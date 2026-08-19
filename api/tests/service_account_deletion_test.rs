// ABOUTME: HTTP-layer tests for the trusted service account-deletion endpoint (keycast#297)
// ABOUTME: Covers auth, deletion, already-absent, replay, request-id rebinding, tenant scoping

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{routes::AuthState, service_deletion::delete_account_service},
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const SERVICE_TOKEN: &str = "test-service-deletion-token";

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }
    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

fn create_test_auth_state(pool: PgPool) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));
    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

fn build_app(auth_state: AuthState) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};
    Router::new().route(
        "/admin/users/:pubkey/deletion",
        post(
            move |axum::extract::Path(pubkey): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  body: axum::Json<
                keycast_api::api::http::service_deletion::ServiceAccountDeletionRequest,
            >| {
                let state = auth_state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    delete_account_service(
                        tenant,
                        State(state),
                        headers,
                        axum::extract::Path(pubkey),
                        body,
                    )
                    .await
                }
            },
        ),
    )
}

fn deletion_request(pubkey: &str, request_id: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/admin/users/{pubkey}/deletion"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(Body::from(
            serde_json::json!({ "deletion_request_id": request_id }).to_string(),
        ))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response must be JSON")
}

async fn create_user(pool: &PgPool, tenant_id: i64) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("create user");
    pubkey
}

async fn create_tenant(pool: &PgPool, label: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("{label}.deletion.test"))
    .bind(format!("Deletion tenant {label}"))
    .fetch_one(pool)
    .await
    .expect("create tenant")
}

async fn add_to_team(pool: &PgPool, pubkey: &str, label: &str) -> i32 {
    let team_id: i32 = sqlx::query_scalar(
        "INSERT INTO teams (name, tenant_id, created_at, updated_at)
         VALUES ($1, 1, NOW(), NOW()) RETURNING id",
    )
    .bind(format!("team-{label}"))
    .fetch_one(pool)
    .await
    .expect("create team");

    sqlx::query(
        "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
         VALUES ($1, $2, 'member', NOW(), NOW())",
    )
    .bind(team_id)
    .bind(pubkey)
    .execute(pool)
    .await
    .expect("add to team");
    team_id
}

async fn user_exists(pool: &PgPool, pubkey: &str) -> bool {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(pool)
        .await
        .expect("count users");
    count > 0
}

fn setup_env() {
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
}

#[tokio::test]
async fn deletes_the_account_and_records_the_request() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, TENANT_ID).await;
    let request_id = format!("req-delete-{pubkey}");

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(deletion_request(&pubkey, &request_id, Some(SERVICE_TOKEN)))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["outcome"], "deleted");
    assert_eq!(body["replayed"], false);
    assert_eq!(
        body["pubkey"], pubkey,
        "full pubkey must be echoed untruncated"
    );
    assert_eq!(body["deletion_request_id"], request_id);

    assert!(!user_exists(&pool, &pubkey).await, "user must be gone");

    // The idempotency row has to outlive the account it names.
    let stored: (String, String) = sqlx::query_as(
        "SELECT user_pubkey, outcome FROM service_account_deletions
         WHERE deletion_request_id = $1",
    )
    .bind(&request_id)
    .fetch_one(&pool)
    .await
    .expect("deletion record must persist after the user is deleted");
    assert_eq!(stored.0.trim(), pubkey);
    assert_eq!(stored.1, "deleted");
}

#[tokio::test]
async fn absent_account_is_reported_as_success() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    // Never inserted: models an account Keycast already lost or never held.
    let pubkey = Keys::generate().public_key().to_hex();
    let request_id = format!("req-absent-{pubkey}");

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(deletion_request(&pubkey, &request_id, Some(SERVICE_TOKEN)))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["outcome"], "already_absent",
        "nothing left to delete is completion, not failure"
    );
    assert_eq!(body["replayed"], false);
}

#[tokio::test]
async fn replaying_a_request_id_returns_the_first_outcome_without_deleting_again() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, TENANT_ID).await;
    let request_id = format!("req-replay-{pubkey}");

    let first = build_app(create_test_auth_state(pool.clone()))
        .oneshot(deletion_request(&pubkey, &request_id, Some(SERVICE_TOKEN)))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = body_json(first).await;
    assert_eq!(first_body["outcome"], "deleted");
    assert_eq!(first_body["replayed"], false);

    let second = build_app(create_test_auth_state(pool.clone()))
        .oneshot(deletion_request(&pubkey, &request_id, Some(SERVICE_TOKEN)))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = body_json(second).await;

    // The replay reports what the original request did, not what a fresh
    // attempt would find now. Reporting `already_absent` here would tell the
    // coordinator the account had never been deleted by this request.
    assert_eq!(second_body["outcome"], "deleted");
    assert_eq!(second_body["replayed"], true);
    assert_eq!(second_body["completed_at"], first_body["completed_at"]);

    let records: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM service_account_deletions WHERE deletion_request_id = $1",
    )
    .bind(&request_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(records, 1, "a replay must not write a second record");
}

#[tokio::test]
async fn a_request_id_cannot_be_reused_for_a_different_account() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let first_pubkey = create_user(&pool, TENANT_ID).await;
    let second_pubkey = create_user(&pool, TENANT_ID).await;
    let request_id = format!("req-rebind-{first_pubkey}");

    let resp = build_app(create_test_auth_state(pool.clone()))
        .oneshot(deletion_request(
            &first_pubkey,
            &request_id,
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = build_app(create_test_auth_state(pool.clone()))
        .oneshot(deletion_request(
            &second_pubkey,
            &request_id,
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a request id already bound to one account must not delete another"
    );
    let body = body_json(resp).await;
    assert_eq!(body["retryable"], false, "rebinding is not retryable");
    assert_eq!(body["code"], "deletion_request_id_reused");
    assert!(
        !body.to_string().contains(&first_pubkey),
        "the conflict must not disclose the account the id is bound to"
    );

    assert!(
        user_exists(&pool, &second_pubkey).await,
        "the second account must survive the rejected request"
    );
}

#[tokio::test]
async fn does_not_touch_an_account_owned_by_another_tenant() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;

    let other_tenant = create_tenant(&pool, &format!("t{}", Utc::now().timestamp_micros())).await;
    let pubkey = create_user(&pool, other_tenant).await;
    let team_id = add_to_team(&pool, &pubkey, &pubkey[..8]).await;
    let request_id = format!("req-tenant-{pubkey}");

    // The harness authenticates as TENANT_ID, which does not own this account.
    let resp = build_app(create_test_auth_state(pool.clone()))
        .oneshot(deletion_request(&pubkey, &request_id, Some(SERVICE_TOKEN)))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["outcome"], "already_absent");

    assert!(
        user_exists(&pool, &pubkey).await,
        "another tenant's account must not be deleted"
    );

    // team_users is keyed on user_pubkey alone, with no tenant column, so a
    // deletion that ran its cleanup before checking ownership would destroy this
    // row and then commit it under an already_absent result.
    let memberships: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2",
    )
    .bind(&pubkey)
    .bind(team_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        memberships, 1,
        "another tenant's team membership must survive"
    );
}

#[tokio::test]
async fn writes_an_audit_row_carrying_no_secrets() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, TENANT_ID).await;
    let request_id = format!("req-audit-{pubkey}");

    let resp = build_app(create_test_auth_state(pool.clone()))
        .oneshot(deletion_request(&pubkey, &request_id, Some(SERVICE_TOKEN)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (action, target, metadata): (String, Option<String>, Value) = sqlx::query_as(
        "SELECT action, target_resource_id, metadata_json
         FROM admin_audit_events
         WHERE action = 'service_account_deletion'
           AND target_resource_id = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .expect("an audit row must be written");

    assert_eq!(action, "service_account_deletion");
    assert_eq!(
        target.as_deref(),
        Some(pubkey.as_str()),
        "audit must carry the full pubkey, untruncated"
    );
    assert_eq!(metadata["deletion_request_id"], request_id);
    assert_eq!(metadata["outcome"], "deleted");

    let serialized = metadata.to_string();
    for forbidden in ["nsec", "secret", "token", "password", SERVICE_TOKEN] {
        assert!(
            !serialized.contains(forbidden),
            "audit metadata must not contain {forbidden}"
        );
    }
}

#[tokio::test]
async fn rejects_a_missing_or_wrong_service_token() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, TENANT_ID).await;

    for token in [None, Some("wrong-token")] {
        let resp = build_app(create_test_auth_state(pool.clone()))
            .oneshot(deletion_request(&pubkey, "req-unauthorized", token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["retryable"], false, "bad credentials are terminal");
    }

    assert!(
        user_exists(&pool, &pubkey).await,
        "an unauthorized request must not delete anything"
    );
}

#[tokio::test]
async fn rejects_malformed_input_as_terminal() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let valid_pubkey = Keys::generate().public_key().to_hex();

    let cases = [
        ("not-a-pubkey", "req-valid", "invalid_pubkey"),
        (valid_pubkey.as_str(), "   ", "invalid_deletion_request_id"),
        (
            valid_pubkey.as_str(),
            "has space",
            "invalid_deletion_request_id",
        ),
    ];

    for (pubkey, request_id, expected_code) in cases {
        let resp = build_app(create_test_auth_state(pool.clone()))
            .oneshot(deletion_request(pubkey, request_id, Some(SERVICE_TOKEN)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{pubkey} / {request_id} should be rejected"
        );
        let body = body_json(resp).await;
        assert_eq!(body["code"], expected_code);
        assert_eq!(body["retryable"], false, "malformed input is not retryable");
    }
}

#[tokio::test]
async fn a_database_failure_is_reported_as_retryable() {
    common::assert_test_database_url();
    setup_env();
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, TENANT_ID).await;

    // Close the pool so every query fails the way a saturated or unreachable
    // database would, and assert the coordinator is told to retry rather than
    // to give up on an account the user asked to have deleted.
    let broken = pool.clone();
    broken.close().await;

    let resp = build_app(create_test_auth_state(broken))
        .oneshot(deletion_request(
            &pubkey,
            "req-db-down",
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();

    assert!(
        resp.status().is_server_error(),
        "a database failure must not be reported as a client error, got {}",
        resp.status()
    );
    let body = body_json(resp).await;
    assert_eq!(body["retryable"], true, "database failures are retryable");
}
