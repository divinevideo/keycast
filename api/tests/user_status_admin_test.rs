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
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
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
