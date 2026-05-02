#![cfg(feature = "integration-tests")]

// ABOUTME: Integration coverage for server-side new-password policy enforcement
// ABOUTME: Verifies weak legacy password hashes still authenticate on login

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::post,
    Json, Router,
};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use keycast_api::{
    api::{
        http::{
            auth::{
                change_password, login, register, reset_password, ChangePasswordRequest,
                RegisterRequest, ResetPasswordRequest,
            },
            headless::{headless_register, HeadlessRegisterRequest},
        },
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
    ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial},
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
use ucan::builder::UcanBuilder;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

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

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

fn create_test_auth_state(pool: PgPool) -> keycast_api::api::http::routes::AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    keycast_api::api::http::routes::AuthState {
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

fn create_test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn cleanup_user(pool: &PgPool, pubkey: &str, email: &str) {
    let _ = sqlx::query("DELETE FROM auth_events WHERE pubkey = $1 OR email = $2")
        .bind(pubkey)
        .bind(email)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1 OR pending_email = $2")
        .bind(pubkey)
        .bind(email)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1 OR email = $2")
        .bind(pubkey)
        .bind(email)
        .execute(pool)
        .await;
}

async fn assert_weak_password_response(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        body["code"],
        keycast_api::password_policy::WEAK_PASSWORD_CODE
    );
    assert_eq!(
        body["error"],
        keycast_api::password_policy::WEAK_PASSWORD_MESSAGE
    );
}

async fn bearer_token_for(keys: &Keys, tenant_id: i64, email: &str) -> String {
    let user_did = nostr_pubkey_to_did(&keys.public_key());
    let key_material = NostrKeyMaterial::from_keys(keys.clone());
    let facts = serde_json::json!({
        "tenant_id": tenant_id,
        "email": email,
        "redirect_origin": "https://app.example.test"
    });

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap();

    format!("Bearer {}", ucan.encode().unwrap())
}

#[tokio::test]
async fn auth_register_rejects_weak_password_before_user_creation() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone());
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("weak-register-{}@example.com", Uuid::new_v4());
    cleanup_user(&pool, &pubkey, &email).await;

    let app = Router::new().route(
        "/auth/register",
        post(
            move |headers: HeaderMap, Json(req): Json<RegisterRequest>| {
                let auth_state = auth_state.clone();
                async move {
                    register(create_test_tenant(), State(auth_state), headers, Json(req)).await
                }
            },
        ),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "password123",
                        "nsec": keys.secret_key().to_secret_hex()
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_weak_password_response(response).await;
    let user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!user_exists);
}

#[tokio::test]
async fn headless_register_rejects_weak_password_before_pending_registration() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone());
    let email = format!("weak-headless-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    cleanup_user(&pool, &pubkey, &email).await;

    let app =
        Router::new().route(
            "/headless/register",
            post(move |Json(req): Json<HeadlessRegisterRequest>| {
                let auth_state = auth_state.clone();
                async move {
                    headless_register(create_test_tenant(), State(auth_state), Json(req)).await
                }
            }),
        );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/headless/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "1234",
                        "client_id": "TestApp",
                        "redirect_uri": "https://example.com/callback"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_weak_password_response(response).await;
    let pending_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_codes WHERE pending_email = $1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!pending_exists);
}

#[tokio::test]
async fn reset_password_rejects_weak_password_without_updating_hash() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("weak-reset-{}@example.com", Uuid::new_v4());
    let reset_token = format!("reset-{}", Uuid::new_v4());
    let old_password_hash = hash("old-password-123!", 4).unwrap();
    cleanup_user(&pool, &pubkey, &email).await;

    sqlx::query(
        "INSERT INTO users (
            pubkey, tenant_id, email, password_hash, email_verified,
            password_reset_token, password_reset_expires_at, created_at, updated_at
         ) VALUES ($1, 1, $2, $3, false, $4, $5, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&old_password_hash)
    .bind(&reset_token)
    .bind(Utc::now() + Duration::hours(1))
    .execute(&pool)
    .await
    .unwrap();

    let app = {
        let pool = pool.clone();
        Router::new().route(
            "/auth/reset-password",
            post(
                move |headers: HeaderMap, Json(req): Json<ResetPasswordRequest>| {
                    let pool = pool.clone();
                    async move {
                        reset_password(create_test_tenant(), State(pool), headers, Json(req)).await
                    }
                },
            ),
        )
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/reset-password")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "token": reset_token,
                        "new_password": "password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_weak_password_response(response).await;
    let stored_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_hash, old_password_hash);
}

#[tokio::test]
async fn change_password_rejects_weak_password_without_updating_hash() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("weak-change-{}@example.com", Uuid::new_v4());
    let old_password_hash = hash("old-password-123!", 4).unwrap();
    cleanup_user(&pool, &pubkey, &email).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&old_password_hash)
    .execute(&pool)
    .await
    .unwrap();

    let auth_header = bearer_token_for(&keys, 1, &email).await;
    let app = {
        let pool = pool.clone();
        Router::new().route(
            "/user/change-password",
            post(
                move |headers: HeaderMap, Json(req): Json<ChangePasswordRequest>| {
                    let pool = pool.clone();
                    async move {
                        change_password(create_test_tenant(), State(pool), headers, Json(req)).await
                    }
                },
            ),
        )
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/user/change-password")
                .header("content-type", "application/json")
                .header("authorization", auth_header)
                .body(Body::from(
                    serde_json::json!({
                        "current_password": "old-password-123!",
                        "new_password": "password123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_weak_password_response(response).await;
    let stored_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_hash, old_password_hash);
}

#[tokio::test]
async fn legacy_weak_password_login_still_succeeds() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone());
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("legacy-login-{}@example.com", Uuid::new_v4());
    let password_hash = hash("password", 4).unwrap();
    cleanup_user(&pool, &pubkey, &email).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(keys.secret_key().to_secret_bytes().as_slice())
    .execute(&pool)
    .await
    .unwrap();

    let app = Router::new().route(
        "/auth/login",
        post(move |headers: HeaderMap, body: String| {
            let auth_state = auth_state.clone();
            async move { login(create_test_tenant(), State(auth_state), headers, body).await }
        }),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .header("origin", "https://app.example.test")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(verify("password", &password_hash).unwrap());
}
