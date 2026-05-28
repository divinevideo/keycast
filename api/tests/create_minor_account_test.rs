#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{
        admin::{create_minor_account, CreateMinorAccountResponse},
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

    let state = auth_state.clone();

    Router::new().route(
        "/admin/create-minor-account",
        post(
            move |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| {
                let state = state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    create_minor_account(
                        tenant,
                        State(state),
                        headers,
                        Json(serde_json::from_value(body).unwrap()),
                    )
                    .await
                }
            },
        ),
    )
}

fn post_create_minor(username: &str, display_name: Option<&str>, token: &str) -> Request<Body> {
    let mut body = serde_json::json!({ "username": username });
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::json!(dn);
    }
    Request::post("/admin/create-minor-account")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

async fn parse_response(resp: axum::http::Response<Body>) -> CreateMinorAccountResponse {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

async fn cleanup_by_username(pool: &PgPool, username: &str) {
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users WHERE LOWER(username) = LOWER($1) AND tenant_id = $2",
    )
    .bind(username)
    .bind(TENANT_ID)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if let Some((pubkey,)) = result {
        let _ = sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
            .bind(&pubkey)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(&pubkey)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(pool)
            .await;
    }
}

// --- Test 1: Happy path — create minor account, get 201 with claim URL ---

#[tokio::test]
async fn test_create_minor_account_happy_path() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let username = format!("minor-{}", uuid::Uuid::new_v4().simple());
    cleanup_by_username(&pool, &username).await;

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(post_create_minor(
            &username,
            Some("Test Minor"),
            SERVICE_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let result = parse_response(resp).await;
    assert!(!result.pubkey.is_empty());
    assert!(result.claim_url.contains("/api/claim?token="));
    assert!(!result.expires_at.is_empty());

    cleanup_by_username(&pool, &username).await;
}

// --- Test 2: Idempotent retry — same username returns 200 with valid claim token ---

#[tokio::test]
async fn test_create_minor_account_idempotent_retry() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let username = format!("minor-{}", uuid::Uuid::new_v4().simple());
    cleanup_by_username(&pool, &username).await;

    let auth_state = create_test_auth_state(pool.clone());

    // First call — creates account
    let app1 = build_app(auth_state.clone());
    let resp1 = app1
        .oneshot(post_create_minor(&username, None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);
    let result1 = parse_response(resp1).await;

    // Second call — idempotent retry
    let app2 = build_app(auth_state.clone());
    let resp2 = app2
        .oneshot(post_create_minor(&username, None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let result2 = parse_response(resp2).await;

    assert_eq!(result1.pubkey, result2.pubkey);
    assert!(result2.claim_url.contains("/api/claim?token="));

    cleanup_by_username(&pool, &username).await;
}

// --- Test 3: Conflict — username taken by non-minor user ---

#[tokio::test]
async fn test_create_minor_account_conflict_non_minor() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let username = format!("normal-{}", uuid::Uuid::new_v4().simple());

    // Create a normal user with this username
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, email, password_hash, email_verified, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .bind("$2b$10$fakehashfakehashfakehashfakehashfakehashfakehashfake")
    .execute(&pool)
    .await
    .expect("Failed to create normal user");

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(post_create_minor(&username, None, SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Cleanup
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
}

// --- Test 4: Conflict — username taken by claimed minor (has email set) ---

#[tokio::test]
async fn test_create_minor_account_conflict_claimed_minor() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let username = format!("claimed-{}", uuid::Uuid::new_v4().simple());

    // Create a minor who has already claimed (email + password set)
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, email, password_hash, verified_minor, verified_minor_at, email_verified, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, TRUE, NOW(), true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .bind("$2b$10$fakehashfakehashfakehashfakehashfakehashfakehashfake")
    .execute(&pool)
    .await
    .expect("Failed to create claimed minor");

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(post_create_minor(&username, None, SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Cleanup
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
}

// --- Test 5: Invalid username rejected ---

#[tokio::test]
async fn test_create_minor_account_invalid_username() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    // Empty username
    let resp = app
        .oneshot(post_create_minor("", None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Username with spaces
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(post_create_minor("has spaces", None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Username starting with hyphen
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(post_create_minor("-startshyphen", None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- Test 6: Missing auth token rejected ---

#[tokio::test]
async fn test_create_minor_account_missing_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(
            Request::post("/admin/create-minor-account")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({ "username": "test" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Test 7: Wrong auth token rejected ---

#[tokio::test]
async fn test_create_minor_account_wrong_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_create_minor("someuser", None, "wrong-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Test 8: Retry with expired token creates new token ---

#[tokio::test]
async fn test_create_minor_account_retry_expired_token_creates_new() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let username = format!("minor-{}", uuid::Uuid::new_v4().simple());
    cleanup_by_username(&pool, &username).await;

    let auth_state = create_test_auth_state(pool.clone());

    // First call — creates account
    let app1 = build_app(auth_state.clone());
    let resp1 = app1
        .oneshot(post_create_minor(&username, None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);
    let result1 = parse_response(resp1).await;

    // Expire all claim tokens for this user
    sqlx::query(
        "UPDATE account_claim_tokens SET expires_at = NOW() - INTERVAL '1 day' WHERE user_pubkey = $1",
    )
    .bind(&result1.pubkey)
    .execute(&pool)
    .await
    .expect("Failed to expire tokens");

    // Retry — should create a new token
    let app2 = build_app(auth_state.clone());
    let resp2 = app2
        .oneshot(post_create_minor(&username, None, SERVICE_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let result2 = parse_response(resp2).await;

    assert_eq!(result1.pubkey, result2.pubkey);
    assert_ne!(result1.claim_url, result2.claim_url);

    cleanup_by_username(&pool, &username).await;
}
