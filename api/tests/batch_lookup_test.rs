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
        admin::{batch_lookup_users, BatchLookupRequest, BatchLookupResponse},
        routes::AuthState,
    },
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
    BcryptAdmission,
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
            account_status_cache: keycast_api::state::new_account_status_cache(),
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

    let state = auth_state.clone();

    Router::new().route(
        "/admin/users/batch-lookup",
        post(
            move |headers: axum::http::HeaderMap, Json(body): Json<BatchLookupRequest>| {
                let state = state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move { batch_lookup_users(tenant, State(state), headers, Json(body)).await }
            },
        ),
    )
}

async fn create_test_user_with_email(pool: &PgPool, email: &str) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, true, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");
    pubkey
}

async fn create_suspended_user_with_email(pool: &PgPool, email: &str) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, status, suspended_reason, suspended_at, created_at, updated_at) \
         VALUES ($1, $2, true, $3, 'suspended', 'age_review', NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");
    pubkey
}

async fn create_user_with_personal_key(pool: &PgPool, email: &str) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, true, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, tenant_id, encrypted_secret_key, created_at, updated_at) \
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(b"fake-encrypted-key".as_slice())
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    pubkey
}

fn post_batch_lookup(emails: &[&str], token: &str) -> Request<Body> {
    Request::post("/admin/users/batch-lookup")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({ "emails": emails })).unwrap(),
        ))
        .unwrap()
}

fn post_batch_lookup_body(body: Body, token: &str) -> Request<Body> {
    Request::post("/admin/users/batch-lookup")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

async fn parse_response(resp: axum::http::Response<Body>) -> BatchLookupResponse {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

// --- Test 1: Returns matching user with correct fields ---

#[tokio::test]
async fn test_batch_lookup_returns_matching_user() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("lookup-{}@example.com", uuid::Uuid::new_v4());
    let pubkey = create_test_user_with_email(&pool, &email).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    assert!(result.not_found.is_empty());

    let user = result.results.get(&email).unwrap();
    assert_eq!(user.pubkey, pubkey);
    assert_eq!(user.status, "active");
    assert!(user.email_verified);
    assert!(!user.has_personal_key);
    assert!(!user.created_at.is_empty());
}

#[tokio::test]
async fn test_batch_lookup_returns_mixed_case_stored_email() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("mixed-case-{}@example.com", uuid::Uuid::new_v4());
    let stored_email = email.to_uppercase();
    let pubkey = create_test_user_with_email(&pool, &stored_email).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert!(result.not_found.is_empty());
    let user = result.results.get(&email).unwrap();
    assert_eq!(user.pubkey, pubkey);
    assert_eq!(user.email, stored_email);
}

// --- Test 2: Mixed batch — some found, some not_found ---

#[tokio::test]
async fn test_batch_lookup_mixed_found_and_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email_a = format!("mixed-a-{}@example.com", uuid::Uuid::new_v4());
    let email_b = format!("mixed-b-{}@example.com", uuid::Uuid::new_v4());
    let email_missing = format!("mixed-missing-{}@example.com", uuid::Uuid::new_v4());

    let pubkey_a = create_test_user_with_email(&pool, &email_a).await;
    let pubkey_b = create_test_user_with_email(&pool, &email_b).await;

    let resp = app
        .oneshot(post_batch_lookup(
            &[&email_a, &email_missing, &email_b],
            SERVICE_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 2);
    assert_eq!(result.results.get(&email_a).unwrap().pubkey, pubkey_a);
    assert_eq!(result.results.get(&email_b).unwrap().pubkey, pubkey_b);
    assert_eq!(result.not_found, vec![email_missing]);
}

// --- Test 3: All unknown emails ---

#[tokio::test]
async fn test_batch_lookup_all_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_batch_lookup(
            &["nobody-a@example.com", "nobody-b@example.com"],
            SERVICE_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert!(result.results.is_empty());
    assert_eq!(result.not_found.len(), 2);
    assert!(result
        .not_found
        .contains(&"nobody-a@example.com".to_string()));
    assert!(result
        .not_found
        .contains(&"nobody-b@example.com".to_string()));
}

// --- Test 4: Duplicate emails deduplicated ---

#[tokio::test]
async fn test_batch_lookup_deduplicates_emails() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("dedup-{}@example.com", uuid::Uuid::new_v4());
    create_test_user_with_email(&pool, &email).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email, &email, &email], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    assert!(result.not_found.is_empty());
}

// --- Test 5: Over 1000 emails returns 400 ---

#[tokio::test]
async fn test_batch_lookup_rejects_over_1000_emails() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let emails: Vec<String> = (0..1001)
        .map(|i| format!("email-{}@example.com", i))
        .collect();
    let body = serde_json::to_string(&serde_json::json!({ "emails": emails })).unwrap();

    let resp = app
        .oneshot(post_batch_lookup_body(Body::from(body), SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- Test 6: Missing auth header ---

#[tokio::test]
async fn test_batch_lookup_rejects_missing_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(
            Request::post("/admin/users/batch-lookup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({ "emails": ["a@b.com"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Test 7: Wrong token ---

#[tokio::test]
async fn test_batch_lookup_rejects_wrong_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_batch_lookup(&["a@b.com"], "wrong-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Test 8: Empty emails array ---

#[tokio::test]
async fn test_batch_lookup_empty_emails() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_batch_lookup(&[], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert!(result.results.is_empty());
    assert!(result.not_found.is_empty());
}

// --- Test 9: Case-insensitive email matching ---

#[tokio::test]
async fn test_batch_lookup_case_insensitive() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email_lower = format!("casetest-{}@example.com", uuid::Uuid::new_v4());
    let email_mixed = email_lower
        .replace("casetest", "CaseTest")
        .replace("example.com", "Example.COM");
    let pubkey = create_test_user_with_email(&pool, &email_lower).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email_mixed], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    let user = result.results.get(&email_lower).unwrap();
    assert_eq!(user.pubkey, pubkey);
}

// --- Test 10: Suspended user returned with correct status ---

#[tokio::test]
async fn test_batch_lookup_returns_suspended_user() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("suspended-{}@example.com", uuid::Uuid::new_v4());
    let pubkey = create_suspended_user_with_email(&pool, &email).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    let user = result.results.get(&email).unwrap();
    assert_eq!(user.pubkey, pubkey);
    assert_eq!(user.status, "suspended");
}

// --- Test 11: has_personal_key true vs false in same batch ---

#[tokio::test]
async fn test_batch_lookup_has_personal_key_accuracy() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email_with_key = format!("withkey-{}@example.com", uuid::Uuid::new_v4());
    let email_without_key = format!("nokey-{}@example.com", uuid::Uuid::new_v4());

    create_user_with_personal_key(&pool, &email_with_key).await;
    create_test_user_with_email(&pool, &email_without_key).await;

    let resp = app
        .oneshot(post_batch_lookup(
            &[&email_with_key, &email_without_key],
            SERVICE_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 2);
    assert!(
        result
            .results
            .get(&email_with_key)
            .unwrap()
            .has_personal_key
    );
    assert!(
        !result
            .results
            .get(&email_without_key)
            .unwrap()
            .has_personal_key
    );
}
