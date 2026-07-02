// ABOUTME: HTTP-layer tests for the service-token clear-verified_minor endpoint
// ABOUTME: Tests DELETE /admin/users/:pubkey/verified-minor auth, clear, audit

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::delete,
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{
        admin::{clear_verified_minor_admin, ClearVerifiedMinorParams, UserStatusResponse},
        routes::AuthState,
    },
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
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const SERVICE_TOKEN: &str = "test-service-token-secret";

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
        }),
        auth_tx: None,
    }
}

fn build_app(auth_state: AuthState) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};
    let del_state = auth_state.clone();
    Router::new().route(
        "/admin/users/:pubkey/verified-minor",
        delete(
            move |axum::extract::Path(pubkey): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  axum::extract::Query(params): axum::extract::Query<ClearVerifiedMinorParams>| {
                let state = del_state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    clear_verified_minor_admin(
                        tenant,
                        State(state),
                        headers,
                        axum::extract::Path(pubkey),
                        axum::extract::Query(params),
                    )
                    .await
                }
            },
        ),
    )
}

async fn create_verified_minor_user(pool: &PgPool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("create verified minor");
    pubkey
}

#[tokio::test]
async fn test_clear_verified_minor_clears_and_returns_status() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert!(!status.verified_minor);
    assert!(status.verified_minor_at.is_none());
}

#[tokio::test]
async fn test_clear_verified_minor_missing_auth() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_clear_verified_minor_wrong_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .header("authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_clear_verified_minor_unknown_pubkey_404() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let fake = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", fake))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    actor_pubkey: String,
    action: String,
    target_resource_type: String,
    target_resource_id: Option<String>,
    metadata_json: serde_json::Value,
}

async fn read_audit_rows(pool: &PgPool, actor_pubkey: &str) -> Vec<AuditRow> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT actor_pubkey, action, target_resource_type, target_resource_id, metadata_json \
         FROM admin_audit_events WHERE tenant_id = $1 AND actor_pubkey = $2",
    )
    .bind(TENANT_ID)
    .bind(actor_pubkey)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn test_clear_with_actor_writes_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/verified-minor?actor={}&reason=re-review%20denied",
                    pubkey, actor
                ))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "clear_verified_minor");
    assert_eq!(rows[0].actor_pubkey, actor);
    assert_eq!(rows[0].target_resource_type, "user");
    assert_eq!(rows[0].target_resource_id.as_deref(), Some(pubkey.as_str()));
    assert_eq!(rows[0].metadata_json["reason"], "re-review denied");
}

#[tokio::test]
async fn test_clear_without_actor_writes_no_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM admin_audit_events WHERE target_resource_id = $1 AND action = 'clear_verified_minor'",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn test_clear_malformed_actor_400_and_flag_intact() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/verified-minor?actor=not-hex",
                    pubkey
                ))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let row: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row.0);
}

#[tokio::test]
async fn test_clear_reason_sanitized_in_audit() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    let long = "x".repeat(600);
    let raw_reason = format!("line1%0Aline2{}", long); // %0A = \n url-encoded
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/verified-minor?actor={}&reason={}",
                    pubkey, actor, raw_reason
                ))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    let reason = rows[0].metadata_json["reason"].as_str().unwrap();
    assert!(!reason.contains('\n'), "control chars must be stripped");
    assert!(
        reason.chars().count() <= 500,
        "reason must be bounded to 500"
    );
}

#[tokio::test]
async fn test_clear_reason_strips_bidi_format_chars() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    // reason with U+202E RIGHT-TO-LEFT OVERRIDE (%E2%80%AE) + U+200B ZERO WIDTH SPACE (%E2%80%8B).
    let raw_reason = "spoof%E2%80%AEdaen%E2%80%8B";
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/verified-minor?actor={}&reason={}",
                    pubkey, actor, raw_reason
                ))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    let reason = rows[0].metadata_json["reason"].as_str().unwrap();
    assert!(
        !reason.contains('\u{202E}') && !reason.contains('\u{200B}'),
        "bidi/zero-width format chars must be stripped, got {:?}",
        reason
    );
}

#[tokio::test]
async fn test_clear_empty_actor_is_400() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    // An empty ?actor= is treated as malformed (fail loud) rather than silently
    // dropping the audit trail. The flag must survive.
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor?actor=", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let row: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row.0);
}
