// ABOUTME: HTTP-layer tests for the service-token admin user status endpoints
// ABOUTME: Tests GET/PUT /admin/users/:pubkey/status with auth validation

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{
        admin::{
            get_user_status_admin, set_user_status_admin, SetUserStatusRequest, UserStatusResponse,
        },
        routes::AuthState,
    },
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
    BcryptAdmission,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::UserRepository,
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const SERVICE_TOKEN: &str = "test-service-token-secret";
const DELETION_SERVICE_TOKEN: &str = "test-deletion-service-token-secret";

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
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
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
            bcrypt: bcrypt.clone(),
            redis: None,
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

fn build_app(auth_state: AuthState) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};

    let get_state = auth_state.clone();
    let put_state = auth_state.clone();

    Router::new().route(
        "/admin/users/:pubkey/status",
        get(
            move |axum::extract::Path(pubkey): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap| {
                let state = get_state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    get_user_status_admin(
                        tenant,
                        State(state),
                        headers,
                        axum::extract::Path(pubkey),
                    )
                    .await
                }
            },
        )
        .put(
            move |axum::extract::Path(pubkey): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  Json(body): Json<SetUserStatusRequest>| {
                let state = put_state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    set_user_status_admin(
                        tenant,
                        State(state),
                        headers,
                        axum::extract::Path(pubkey),
                        Json(body),
                    )
                    .await
                }
            },
        ),
    )
}

async fn create_test_user(pool: &PgPool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");
    pubkey
}

#[tokio::test]
async fn test_get_user_status_returns_active_by_default() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::get(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.status, "active");
    assert!(status.suspended_reason.is_none());
    assert!(status.suspended_at.is_none());
}

#[tokio::test]
async fn deletion_service_token_cannot_read_admin_user_status() {
    common::assert_test_database_url();
    unsafe {
        std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN);
        std::env::set_var("KEYCAST_DELETION_SERVICE_TOKEN", DELETION_SERVICE_TOKEN);
    }
    let pool = common::setup_test_db().await;
    let pubkey = create_test_user(&pool).await;

    let response = build_app(create_test_auth_state(pool))
        .oneshot(
            Request::get(format!("/admin/users/{pubkey}/status"))
                .header("authorization", format!("Bearer {DELETION_SERVICE_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_set_user_status_suspended() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "age_review"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.status, "suspended");
    assert_eq!(status.suspended_reason.as_deref(), Some("age_review"));
    assert!(status.suspended_at.is_some());
}

#[tokio::test]
async fn test_set_user_status_unsuspend() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());

    let pubkey = create_test_user(&pool).await;

    // Suspend first
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .set_user_status(
            &pubkey,
            TENANT_ID,
            &keycast_core::types::user::UserStatus::Suspended,
            Some("age_review"),
        )
        .await
        .unwrap();

    // Now unsuspend via HTTP
    let app = build_app(auth_state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "active"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.status, "active");
    assert!(status.suspended_reason.is_none());
    assert!(status.suspended_at.is_none());
}

#[tokio::test]
async fn test_set_user_status_invalid_status() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "invalid_value",
                        "reason": "test"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_set_user_status_missing_reason() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_set_user_status_missing_auth() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "test"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_set_user_status_wrong_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", "Bearer wrong-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "test"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_set_user_status_user_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let fake_pubkey = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", fake_pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "test"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_user_status_user_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let fake_pubkey = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::get(format!("/admin/users/{}/status", fake_pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_escalate_suspended_to_banned_preserves_suspended_at() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());

    let pubkey = create_test_user(&pool).await;

    // Suspend first
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .set_user_status(
            &pubkey,
            TENANT_ID,
            &keycast_core::types::user::UserStatus::Suspended,
            Some("age_review"),
        )
        .await
        .unwrap();

    // Read the original suspended_at
    let (_, _, original_suspended_at) = user_repo
        .get_user_status(&pubkey, TENANT_ID)
        .await
        .unwrap()
        .unwrap();
    let original_ts = original_suspended_at.expect("suspended_at should be set");

    // Small delay so timestamps differ if overwritten
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Escalate to banned via HTTP
    let app = build_app(auth_state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "banned",
                        "reason": "policy_violation"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.status, "banned");
    assert_eq!(status.suspended_reason.as_deref(), Some("policy_violation"));
    // suspended_at should be preserved from the original suspension, not overwritten
    let banned_ts = status
        .suspended_at
        .expect("suspended_at should still be set");
    assert_eq!(banned_ts, original_ts);
}

#[tokio::test]
async fn test_set_user_status_whitespace_only_reason_rejected() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let app = build_app(auth_state);

    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "   "
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_reactivate_from_banned_clears_suspended_at() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());

    let pubkey = create_test_user(&pool).await;

    // Ban user directly
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .set_user_status(
            &pubkey,
            TENANT_ID,
            &keycast_core::types::user::UserStatus::Banned,
            Some("policy_violation"),
        )
        .await
        .unwrap();

    // Reactivate via HTTP
    let app = build_app(auth_state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "active"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.status, "active");
    assert!(status.suspended_reason.is_none());
    assert!(status.suspended_at.is_none());
}

// --- Durable admin_audit_events for status changes (keycast#279) ---

#[derive(sqlx::FromRow)]
struct AuditRow {
    actor_pubkey: String,
    action: String,
    target_resource_type: String,
    target_resource_id: Option<String>,
    metadata_json: serde_json::Value,
}

/// Reads the `set_user_status` audit rows for one target user. Scoping by the
/// (random) target pubkey keeps the read isolated from other tests sharing the DB.
async fn read_status_audit_rows(pool: &PgPool, target_pubkey: &str) -> Vec<AuditRow> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT actor_pubkey, action, target_resource_type, target_resource_id, metadata_json \
         FROM admin_audit_events \
         WHERE tenant_id = $1 AND target_resource_id = $2 AND action = 'set_user_status' \
         ORDER BY id",
    )
    .bind(TENANT_ID)
    .bind(target_pubkey)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Suspend with an actor writes exactly one durable audit row carrying the
/// old/new status and reason, consistent with clear-verified_minor.
#[tokio::test]
async fn test_set_user_status_with_actor_writes_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_test_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "age_review",
                        "actor": actor,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_status_audit_rows(&pool, &pubkey).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "set_user_status");
    assert_eq!(rows[0].actor_pubkey, actor);
    assert_eq!(rows[0].target_resource_type, "user");
    assert_eq!(rows[0].target_resource_id.as_deref(), Some(pubkey.as_str()));
    assert_eq!(rows[0].metadata_json["old_status"], "active");
    assert_eq!(rows[0].metadata_json["new_status"], "suspended");
    assert_eq!(rows[0].metadata_json["reason"], "age_review");
}

/// No actor -> log-only (actor_pubkey is NOT NULL), so no audit row.
#[tokio::test]
async fn test_set_user_status_without_actor_writes_no_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "age_review"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(read_status_audit_rows(&pool, &pubkey).await.is_empty());
}

/// A no-op call (status unchanged) with an actor writes no row: gating on a real
/// transition keeps a relay-manager retry from appending a phantom state change.
#[tokio::test]
async fn test_set_user_status_noop_writes_no_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_test_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    // Pre-suspend directly (no audit row) so the HTTP call is a same-status no-op.
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .set_user_status(
            &pubkey,
            TENANT_ID,
            &keycast_core::types::user::UserStatus::Suspended,
            Some("age_review"),
        )
        .await
        .unwrap();

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "age_review",
                        "actor": actor,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(read_status_audit_rows(&pool, &pubkey).await.is_empty());
}

/// A malformed actor 400s (the T&S action never silently loses its audit trail)
/// and leaves the account status untouched.
#[tokio::test]
async fn test_set_user_status_malformed_actor_rejected() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "age_review",
                        "actor": "not-a-hex-pubkey",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let row: (String,) = sqlx::query_as("SELECT status FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.0, "active");
    assert!(read_status_audit_rows(&pool, &pubkey).await.is_empty());
}

/// The reason is sanitized (control/bidi/zero-width stripped) before it reaches
/// BOTH the persisted `suspended_reason` column and the audit metadata.
#[tokio::test]
async fn test_set_user_status_reason_sanitized_in_audit_and_column() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_test_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    // Bidi override (U+202E) + zero-width space (U+200B) embedded in the reason.
    let dirty_reason = "ban\u{202E}\u{200B}ned";

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "banned",
                        "reason": dirty_reason,
                        "actor": actor,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.suspended_reason.as_deref(), Some("banned"));

    let rows = read_status_audit_rows(&pool, &pubkey).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata_json["reason"], "banned");
}

/// A reason that is entirely control/bidi/zero-width characters sanitizes to
/// nothing, so a suspend/ban with it is rejected as a missing reason.
#[tokio::test]
async fn test_set_user_status_control_only_reason_rejected() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_test_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "suspended",
                        "reason": "\u{202E}\u{200B}\u{0007}",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Unsuspend (suspended -> active) with an actor is a real transition and writes
/// an audit row; the cleared reason is recorded as null.
#[tokio::test]
async fn test_set_user_status_unsuspend_with_actor_writes_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_test_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    // Pre-suspend directly so the HTTP call is a suspended -> active transition.
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .set_user_status(
            &pubkey,
            TENANT_ID,
            &keycast_core::types::user::UserStatus::Suspended,
            Some("age_review"),
        )
        .await
        .unwrap();

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}/status", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "status": "active",
                        "actor": actor,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_status_audit_rows(&pool, &pubkey).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_pubkey, actor);
    assert_eq!(rows[0].metadata_json["old_status"], "suspended");
    assert_eq!(rows[0].metadata_json["new_status"], "active");
    assert!(rows[0].metadata_json["reason"].is_null());
}
