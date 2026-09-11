// ABOUTME: Integration coverage for minimized account-retention tombstones
// ABOUTME: Exercises boundaries, replay safety, holds, audit expiry, and one-connection handlers

#![cfg(feature = "integration-tests")]

mod common;

use axum::{body::Body, extract::State, http::Request, routing::post, Router};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::{
    retention::compact_account_records,
    routes::AuthState,
    service_deletion::delete_account_service,
    service_provisioning::{create_minor_account, CreateMinorAccountResponse},
};
use keycast_core::repositories::{
    AdminAuditEventRecord, AdminAuditEventRepository, RetentionCompactionStatus,
    ServiceAccountDeletionOutcome, ServiceAccountDeletionRecord, ServiceAccountDeletionRepository,
    UserRepository,
};
use keycast_core::retention::RetentionDigestKeyring;
use nostr_sdk::Keys;
use serde_json::Value;
use serial_test::serial;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tower::ServiceExt;

const TENANT_ID: i64 = 1;
const DELETION_TOKEN: &str = "retention-test-deletion-token";
const SERVICE_TOKEN: &str = "retention-test-service-token";
const KEY_CONFIG: &str = "current=v2;v1=1111111111111111111111111111111111111111111111111111111111111111;v2=2222222222222222222222222222222222222222222222222222222222222222";

fn env() {
    unsafe {
        std::env::set_var("KEYCAST_DELETION_SERVICE_TOKEN", DELETION_TOKEN);
        std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN);
        std::env::set_var("KEYCAST_RETENTION_DIGEST_KEYS", KEY_CONFIG);
    }
}

fn tenant() -> keycast_api::api::tenant::TenantExtractor {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};
    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "localhost".to_string(),
        name: "Test".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn retention_app(state: AuthState) -> Router {
    Router::new().route(
        "/admin/retention/compaction",
        post(move |headers, body| {
            let state = state.clone();
            async move { compact_account_records(tenant(), State(state), headers, body).await }
        }),
    )
}

fn provisioning_app(state: AuthState) -> Router {
    Router::new().route(
        "/admin/create-minor-account",
        post(move |headers, body| {
            let state = state.clone();
            async move { create_minor_account(tenant(), State(state), headers, body).await }
        }),
    )
}

fn deletion_app(state: AuthState) -> Router {
    Router::new().route(
        "/admin/users/:pubkey/deletion",
        post(move |axum::extract::Path(pubkey), headers, body| {
            let state = state.clone();
            async move {
                delete_account_service(
                    tenant(),
                    State(state),
                    headers,
                    axum::extract::Path(pubkey),
                    body,
                )
                .await
            }
        }),
    )
}

fn json_request(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn insert_deletion(
    pool: &PgPool,
    request_id: &str,
    pubkey: &str,
    completed_at: chrono::DateTime<Utc>,
) {
    let mut tx = pool.begin().await.unwrap();
    ServiceAccountDeletionRepository::record_in_tx(
        &mut tx,
        ServiceAccountDeletionRecord {
            deletion_request_id: request_id.to_string(),
            tenant_id: TENANT_ID,
            user_pubkey: pubkey.to_string(),
            outcome: ServiceAccountDeletionOutcome::Deleted,
            teams_removed: 0,
            oauth_authorizations_deleted: 0,
            bunkers_notified: 0,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE service_account_deletions SET completed_at = $2 WHERE deletion_request_id = $1",
    )
    .bind(request_id)
    .bind(completed_at)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
#[serial]
async fn deletion_compaction_preserves_exact_replay_and_conflict_at_boundary() {
    env();
    let pool = common::setup_test_db().await;
    let (state, _producer) = common::create_test_auth_state(pool.clone());
    let request_id = uuid::Uuid::new_v4().to_string();
    let pubkey = Keys::generate().public_key().to_hex();
    let other_pubkey = Keys::generate().public_key().to_hex();
    let completed_at = Utc::now() - Duration::days(30);
    insert_deletion(&pool, &request_id, &pubkey, completed_at).await;
    let keys = RetentionDigestKeyring::parse(KEY_CONFIG).unwrap();
    let repository = ServiceAccountDeletionRepository::new(pool.clone());

    assert_eq!(
        repository
            .compact(
                &request_id,
                TENANT_ID,
                &pubkey,
                &keys,
                completed_at + Duration::days(30) - Duration::microseconds(1)
            )
            .await
            .unwrap(),
        RetentionCompactionStatus::Ineligible
    );
    assert_eq!(
        repository
            .compact(
                &request_id,
                TENANT_ID,
                &pubkey,
                &keys,
                completed_at + Duration::days(30)
            )
            .await
            .unwrap(),
        RetentionCompactionStatus::Compacted
    );

    let replay = deletion_app(state.clone())
        .oneshot(json_request(
            &format!("/admin/users/{pubkey}/deletion"),
            DELETION_TOKEN,
            serde_json::json!({"deletion_request_id": request_id}),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), axum::http::StatusCode::OK);
    let replay = json(replay).await;
    assert_eq!(replay["outcome"], "deleted");
    assert_eq!(replay["replayed"], true);

    let conflict = deletion_app(state)
        .oneshot(json_request(
            &format!("/admin/users/{other_pubkey}/deletion"),
            DELETION_TOKEN,
            serde_json::json!({"deletion_request_id": request_id}),
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), axum::http::StatusCode::CONFLICT);
    sqlx::query("DELETE FROM service_account_deletion_tombstones WHERE deletion_request_id = $1")
        .bind(&request_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn provisioning_compaction_uses_local_deletion_clock_and_returns_deleted_terminal_state() {
    env();
    let pool = common::setup_test_db().await;
    let (state, _producer) = common::create_test_auth_state(pool.clone());
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("retention-{}", uuid::Uuid::new_v4().simple());
    let created = provisioning_app(state.clone()).oneshot(json_request(
        "/admin/create-minor-account", SERVICE_TOKEN,
        serde_json::json!({"provisioning_operation_id": operation_id, "username": username, "display_name": "Synthetic"}),
    )).await.unwrap();
    let created: CreateMinorAccountResponse = serde_json::from_value(json(created).await).unwrap();
    let pubkey = created.pubkey.expect("new account has a pubkey");

    UserRepository::new(pool.clone())
        .delete_account(&pubkey, TENANT_ID)
        .await
        .unwrap();
    let deleted_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT deleted_at FROM service_provisioning_operations WHERE provisioning_operation_id = $1",
    ).bind(&operation_id).fetch_one(&pool).await.unwrap();
    assert!(
        deleted_at.is_some(),
        "self-service repository deletion stamps the local clock"
    );
    sqlx::query("UPDATE service_provisioning_operations SET deleted_at = NOW() - INTERVAL '31 days' WHERE provisioning_operation_id = $1")
        .bind(&operation_id).execute(&pool).await.unwrap();

    let compacted = retention_app(state.clone())
        .oneshot(json_request(
            "/admin/retention/compaction",
            DELETION_TOKEN,
            serde_json::json!({"provisioning": {"pubkey": pubkey}}),
        ))
        .await
        .unwrap();
    assert_eq!(compacted.status(), axum::http::StatusCode::OK);
    assert_eq!(
        json(compacted).await["provisioning"][0]["status"],
        "compacted"
    );

    let replay = provisioning_app(state.clone()).oneshot(json_request(
        "/admin/create-minor-account", SERVICE_TOKEN,
        serde_json::json!({"provisioning_operation_id": operation_id, "username": username, "display_name": "Synthetic"}),
    )).await.unwrap();
    let replay = json(replay).await;
    assert_eq!(replay["account_state"], "account_deleted");
    assert!(replay.get("pubkey").is_none());
    assert_eq!(replay["replayed"], true);

    let conflict = provisioning_app(state).oneshot(json_request(
        "/admin/create-minor-account", SERVICE_TOKEN,
        serde_json::json!({"provisioning_operation_id": operation_id, "username": format!("{username}-different"), "display_name": "Synthetic"}),
    )).await.unwrap();
    assert_eq!(conflict.status(), axum::http::StatusCode::CONFLICT);
    sqlx::query("UPDATE service_provisioning_operation_tombstones SET digest_key_version = 99 WHERE provisioning_operation_id = $1")
        .bind(&operation_id).execute(&pool).await.unwrap();
    let (state, _producer) = common::create_test_auth_state(pool.clone());
    let unverifiable = retention_app(state)
        .oneshot(json_request(
            "/admin/retention/compaction",
            DELETION_TOKEN,
            serde_json::json!({"provisioning": {"pubkey": pubkey}}),
        ))
        .await
        .unwrap();
    assert_eq!(
        unverifiable.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "missing historical keys must fail closed instead of acknowledging absence"
    );
    sqlx::query("DELETE FROM service_provisioning_operation_tombstones WHERE provisioning_operation_id = $1")
        .bind(&operation_id).execute(&pool).await.unwrap();
}

#[tokio::test]
#[serial]
async fn holds_audit_expiry_overdue_boundaries_and_one_connection_handler_are_safe() {
    env();
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();
    let (state, _producer) = common::create_test_auth_state(pool.clone());
    let request_id = uuid::Uuid::new_v4().to_string();
    let pubkey = Keys::generate().public_key().to_hex();
    let completed_at = Utc::now() - Duration::days(32);
    insert_deletion(&pool, &request_id, &pubkey, completed_at).await;
    let retention_repo = AdminAuditEventRepository::new(pool.clone());
    assert_eq!(
        retention_repo
            .count_overdue_retention_rows(completed_at + Duration::days(31))
            .await
            .unwrap()
            .0,
        0,
        "a row is not overdue at exactly 24 hours after eligibility"
    );
    assert_eq!(
        retention_repo
            .count_overdue_retention_rows(
                completed_at + Duration::days(31) + Duration::microseconds(1),
            )
            .await
            .unwrap()
            .0,
        1,
        "a row is overdue immediately after the 24-hour lag threshold"
    );
    let hold_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO retention_legal_holds (hold_id, tenant_id, scope_kind, scope_key, authorizing_role, reason_reference, review_at) VALUES ($1, $2, 'deletion_request', $3, 'privacy-legal', 'synthetic-case-ref', NOW() + INTERVAL '1 day')")
        .bind(&hold_id).bind(TENANT_ID).bind(&request_id).execute(&pool).await.unwrap();

    let held = retention_app(state.clone())
        .oneshot(json_request(
            "/admin/retention/compaction",
            DELETION_TOKEN,
            serde_json::json!({"deletion": {"deletion_request_id": request_id, "pubkey": pubkey}}),
        ))
        .await
        .unwrap();
    assert_eq!(json(held).await["deletion"]["status"], "held");
    sqlx::query("UPDATE retention_legal_holds SET released_at = NOW() WHERE hold_id = $1")
        .bind(&hold_id)
        .execute(&pool)
        .await
        .unwrap();
    let released = retention_app(state)
        .oneshot(json_request(
            "/admin/retention/compaction",
            DELETION_TOKEN,
            serde_json::json!({"deletion": {"deletion_request_id": request_id, "pubkey": pubkey}}),
        ))
        .await
        .unwrap();
    assert_eq!(json(released).await["deletion"]["status"], "compacted");

    let audit_repo = retention_repo;
    let old_deletion = audit_repo
        .record(AdminAuditEventRecord {
            tenant_id: TENANT_ID,
            actor_pubkey: "service:account-deletion".to_string(),
            action: "service_account_deletion".to_string(),
            target_resource_type: "user".to_string(),
            target_resource_id: Some(pubkey.clone()),
            target_client_id: None,
            metadata_json: serde_json::json!({"deletion_request_id": request_id}),
        })
        .await
        .unwrap();
    let unrelated = audit_repo
        .record(AdminAuditEventRecord {
            tenant_id: TENANT_ID,
            actor_pubkey: pubkey.clone(),
            action: "set_user_status".to_string(),
            target_resource_type: "user".to_string(),
            target_resource_id: Some(pubkey),
            target_client_id: None,
            metadata_json: serde_json::json!({}),
        })
        .await
        .unwrap();
    let audit_as_of = Utc::now();
    sqlx::query("UPDATE admin_audit_events SET occurred_at = $3 - INTERVAL '1 year' + INTERVAL '1 microsecond' WHERE id = $1 OR id = $2")
        .bind(old_deletion.id).bind(unrelated.id).bind(audit_as_of).execute(&pool).await.unwrap();
    assert_eq!(
        audit_repo
            .delete_expired_deletion_events(audit_as_of, 100)
            .await
            .unwrap(),
        0,
        "deletion audit remains immediately before the one-year boundary"
    );
    sqlx::query("UPDATE admin_audit_events SET occurred_at = $2 - INTERVAL '1 year' WHERE id = $1")
        .bind(old_deletion.id)
        .bind(audit_as_of)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        audit_repo
            .delete_expired_deletion_events(audit_as_of, 100)
            .await
            .unwrap(),
        1
    );
    let unrelated_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM admin_audit_events WHERE id = $1)")
            .bind(unrelated.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(unrelated_exists);

    sqlx::query("DELETE FROM admin_audit_events WHERE id = $1")
        .bind(unrelated.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM service_account_deletion_tombstones WHERE deletion_request_id = $1")
        .bind(&request_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM retention_legal_holds WHERE hold_id = $1")
        .bind(&hold_id)
        .execute(&pool)
        .await
        .unwrap();
}
