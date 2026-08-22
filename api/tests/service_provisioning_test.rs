// ABOUTME: Integration coverage for retry-safe service account provisioning
// ABOUTME: Exercises durable replay, conflicts, deletion, concurrency, and one-connection safety

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use http_body_util::BodyExt;
use keycast_api::api::http::{
    routes::AuthState,
    service_provisioning::{create_minor_account, CreateMinorAccountResponse},
};
use keycast_core::{
    repositories::{
        ClaimTokenRepository, ServiceProvisioningOperationRecord,
        ServiceProvisioningOperationRepository, UserRepository,
    },
    types::claim_token::generate_claim_token,
};
use nostr_sdk::Keys;
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const SERVICE_TOKEN: &str = "test-service-provisioning-token";

fn build_app(auth_state: AuthState, tenant_id: i64) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};
    use std::sync::Arc;

    Router::new().route(
        "/admin/create-minor-account",
        post(move |headers, body| {
            let state = auth_state.clone();
            async move {
                create_minor_account(
                    TenantExtractor(Arc::new(Tenant {
                        id: tenant_id,
                        domain: "localhost".to_string(),
                        name: "Test".to_string(),
                        settings: None,
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                    })),
                    State(state),
                    headers,
                    body,
                )
                .await
            }
        }),
    )
}

fn request(
    operation_id: Option<&str>,
    username: &str,
    display_name: Option<&str>,
) -> Request<Body> {
    let mut body = serde_json::json!({
        "username": username,
        "display_name": display_name,
    });
    if let Some(operation_id) = operation_id {
        body["provisioning_operation_id"] = Value::String(operation_id.to_string());
    }
    Request::post("/admin/create-minor-account")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {SERVICE_TOKEN}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn response_typed(response: axum::response::Response) -> CreateMinorAccountResponse {
    serde_json::from_value(response_json(response).await).unwrap()
}

async fn cleanup(pool: &PgPool, operation_id: &str, usernames: &[&str]) {
    sqlx::query("DELETE FROM service_provisioning_operations WHERE provisioning_operation_id = $1")
        .bind(operation_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE username = ANY($1) AND tenant_id IN (1, 2)")
        .bind(usernames)
        .execute(pool)
        .await
        .unwrap();
}

async fn setup() -> (PgPool, AuthState) {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let (state, _producer) = common::create_test_auth_state(pool.clone());
    (pool, state)
}

#[tokio::test]
async fn replays_before_claim_after_claim_and_after_deletion() {
    let (pool, state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("provision-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&username]).await;

    let first = build_app(state.clone(), 1)
        .oneshot(request(Some(&operation_id), &username, Some("Protected")))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first = response_typed(first).await;
    assert!(!first.replayed);

    let replay = build_app(state.clone(), 1)
        .oneshot(request(Some(&operation_id), &username, Some("Protected")))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = response_typed(replay).await;
    assert_eq!(replay.pubkey, first.pubkey);
    assert_eq!(replay.claim_url, first.claim_url);
    assert!(replay.replayed);

    sqlx::query("UPDATE users SET email = $1, password_hash = 'claimed' WHERE pubkey = $2")
        .bind(format!("{username}@test.local"))
        .bind(&first.pubkey)
        .execute(&pool)
        .await
        .unwrap();
    let claimed = build_app(state.clone(), 1)
        .oneshot(request(Some(&operation_id), &username, Some("Protected")))
        .await
        .unwrap();
    let claimed = response_typed(claimed).await;
    assert_eq!(claimed.pubkey, first.pubkey);
    assert!(claimed.claim_url.is_none());
    assert!(claimed.expires_at.is_none());

    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&first.pubkey)
        .execute(&pool)
        .await
        .unwrap();
    let deleted = build_app(state, 1)
        .oneshot(request(Some(&operation_id), &username, Some("Protected")))
        .await
        .unwrap();
    let deleted = response_typed(deleted).await;
    assert_eq!(deleted.pubkey, first.pubkey);
    assert!(deleted.claim_url.is_none());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "deleted account must never be recreated by replay"
    );
    cleanup(&pool, &operation_id, &[&username]).await;
}

#[tokio::test]
async fn conflicting_reuse_changes_nothing() {
    let (pool, state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let first_name = format!("first-{}", uuid::Uuid::new_v4().simple());
    let other_name = format!("other-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&first_name, &other_name]).await;

    let created = build_app(state.clone(), 1)
        .oneshot(request(Some(&operation_id), &first_name, Some("One")))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    for (tenant, username, display_name) in [
        (1, other_name.as_str(), Some("One")),
        (1, first_name.as_str(), Some("Two")),
        (2, first_name.as_str(), Some("One")),
    ] {
        let conflict = build_app(state.clone(), tenant)
            .oneshot(request(Some(&operation_id), username, display_name))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(conflict).await["code"],
            "provisioning_operation_conflict"
        );
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE username = ANY($1) AND tenant_id IN (1, 2)",
    )
    .bind([first_name.as_str(), other_name.as_str()])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    cleanup(&pool, &operation_id, &[&first_name, &other_name]).await;
}

#[tokio::test]
async fn concurrent_expired_token_replay_returns_one_replacement() {
    let (pool, state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("expiry-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&username]).await;

    let created = build_app(state.clone(), 1)
        .oneshot(request(Some(&operation_id), &username, None))
        .await
        .unwrap();
    let created = response_typed(created).await;
    sqlx::query("UPDATE account_claim_tokens SET expires_at = NOW() - INTERVAL '1 day' WHERE user_pubkey = $1")
        .bind(&created.pubkey)
        .execute(&pool)
        .await
        .unwrap();

    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let state = state.clone();
        let operation_id = operation_id.clone();
        let username = username.clone();
        calls.spawn(async move {
            let response = build_app(state, 1)
                .oneshot(request(Some(&operation_id), &username, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response_typed(response).await.claim_url.unwrap()
        });
    }
    let mut links = Vec::new();
    while let Some(link) = calls.join_next().await {
        links.push(link.unwrap());
    }
    assert!(links.iter().all(|link| link == &links[0]));
    assert_ne!(Some(links[0].clone()), created.claim_url);

    let valid: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_claim_tokens WHERE user_pubkey = $1
         AND expires_at > NOW() AND used_at IS NULL AND invalidated_at IS NULL",
    )
    .bind(&created.pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(valid, 1);
    cleanup(&pool, &operation_id, &[&username]).await;
}

#[tokio::test]
async fn concurrent_conflicting_delivery_creates_at_most_one_account() {
    let (pool, state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let names: Vec<String> = (0..8)
        .map(|_| format!("race-{}", uuid::Uuid::new_v4().simple()))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    cleanup(&pool, &operation_id, &refs).await;

    let mut calls = tokio::task::JoinSet::new();
    for username in names.clone() {
        let state = state.clone();
        let operation_id = operation_id.clone();
        calls.spawn(async move {
            build_app(state, 1)
                .oneshot(request(Some(&operation_id), &username, None))
                .await
                .unwrap()
                .status()
        });
    }
    let mut statuses = Vec::new();
    while let Some(status) = calls.join_next().await {
        statuses.push(status.unwrap());
    }
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::CONFLICT)
            .count(),
        7
    );
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ANY($1)")
        .bind(&refs)
        .fetch_one(&pool)
        .await
        .unwrap();
    let operations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM service_provisioning_operations WHERE provisioning_operation_id = $1",
    )
    .bind(&operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((users, operations), (1, 1));
    cleanup(&pool, &operation_id, &refs).await;
}

#[tokio::test]
async fn concurrent_exact_delivery_returns_one_account_to_every_caller() {
    let (pool, state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("exact-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&username]).await;

    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let state = state.clone();
        let operation_id = operation_id.clone();
        let username = username.clone();
        calls.spawn(async move {
            let response = build_app(state, 1)
                .oneshot(request(Some(&operation_id), &username, Some("Exact")))
                .await
                .unwrap();
            let status = response.status();
            let body = response_typed(response).await;
            (status, body.pubkey)
        });
    }
    let mut results = Vec::new();
    while let Some(result) = calls.join_next().await {
        results.push(result.unwrap());
    }
    assert_eq!(
        results
            .iter()
            .filter(|(status, _)| *status == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(status, _)| *status == StatusCode::OK)
            .count(),
        7
    );
    assert!(results.iter().all(|(_, pubkey)| pubkey == &results[0].1));
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
    cleanup(&pool, &operation_id, &[&username]).await;
}

#[tokio::test]
async fn transaction_path_completes_with_one_pool_connection() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();
    let (state, _producer) = common::create_test_auth_state(pool.clone());
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("single-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&username]).await;

    let created = build_app(state.clone(), 1)
        .oneshot(request(Some(&operation_id), &username, None))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_typed(created).await;
    sqlx::query("UPDATE account_claim_tokens SET expires_at = NOW() - INTERVAL '1 day' WHERE user_pubkey = $1")
        .bind(&created.pubkey)
        .execute(&pool)
        .await
        .unwrap();
    let replay = build_app(state, 1)
        .oneshot(request(Some(&operation_id), &username, None))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    cleanup(&pool, &operation_id, &[&username]).await;
}

#[tokio::test]
async fn operation_lock_timeout_is_retryable_and_releases_the_connection() {
    let (pool, state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("lock-timeout-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&username]).await;

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&operation_id)
        .execute(&mut *blocker)
        .await
        .unwrap();

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        build_app(state, 1).oneshot(request(Some(&operation_id), &username, None)),
    )
    .await
    .expect("provisioning lock wait must be bounded")
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(body["code"], "database_unavailable");
    assert_eq!(body["retryable"], true);

    blocker.rollback().await.unwrap();
    cleanup(&pool, &operation_id, &[&username]).await;
}

#[tokio::test]
async fn invalid_operation_id_and_service_token_are_terminal() {
    let (_pool, state) = setup().await;
    let invalid = build_app(state.clone(), 1)
        .oneshot(request(Some("NOT-A-LOWERCASE-UUID"), "valid-name", None))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid).await["code"],
        "invalid_provisioning_operation_id"
    );

    let unauthorized = Request::post("/admin/create-minor-account")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "provisioning_operation_id": uuid::Uuid::new_v4().to_string(),
                "username": "valid-name"
            })
            .to_string(),
        ))
        .unwrap();
    let unauthorized = build_app(state, 1).oneshot(unauthorized).await.unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_request_remains_username_idempotent() {
    let (pool, state) = setup().await;
    let username = format!("legacy-{}", uuid::Uuid::new_v4().simple());
    let cleanup_id = uuid::Uuid::new_v4().to_string();
    cleanup(&pool, &cleanup_id, &[&username]).await;

    let first = build_app(state.clone(), 1)
        .oneshot(request(None, &username, None))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first = response_json(first).await;
    let replay = build_app(state, 1)
        .oneshot(request(None, &username, None))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = response_json(replay).await;
    assert_eq!(first["pubkey"], replay["pubkey"]);
    cleanup(&pool, &cleanup_id, &[&username]).await;
}

#[tokio::test]
async fn rollback_leaves_neither_account_nor_operation_record() {
    let (pool, _state) = setup().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let username = format!("rollback-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &operation_id, &[&username]).await;
    let pubkey = Keys::generate().public_key().to_hex();

    let mut tx = pool.begin().await.unwrap();
    ServiceProvisioningOperationRepository::lock_in_tx(&mut tx, &operation_id)
        .await
        .unwrap();
    UserRepository::create_minor_account_in_tx(
        &mut tx,
        &pubkey,
        1,
        &username,
        None,
        b"synthetic-encrypted-key",
    )
    .await
    .unwrap();
    ClaimTokenRepository::create_in_tx(&mut tx, &generate_claim_token(), &pubkey, None, 1)
        .await
        .unwrap();
    ServiceProvisioningOperationRepository::record_in_tx(
        &mut tx,
        ServiceProvisioningOperationRecord {
            provisioning_operation_id: operation_id.clone(),
            tenant_id: 1,
            request_fingerprint: "0".repeat(64),
            user_pubkey: pubkey.clone(),
        },
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();

    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    let operations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM service_provisioning_operations WHERE provisioning_operation_id = $1",
    )
    .bind(&operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((users, operations), (0, 0));
}
