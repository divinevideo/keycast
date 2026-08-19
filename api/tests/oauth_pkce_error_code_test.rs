#![cfg(feature = "integration-tests")]

// ABOUTME: Integration test pinning the token endpoint's PKCE failure response to RFC 7636 4.6.
// ABOUTME: Drives the real handler so the assertion covers the wire body, not just the error enum.

mod common;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::{Duration, Utc};
use keycast_api::{
    api::{
        http::{oauth, routes::AuthState},
        tenant::{Tenant, TenantExtractor},
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
use tokio::task::JoinHandle;
use uuid::Uuid;
use zeroize::Zeroizing;

const CLIENT_ID: &str = "PKCE Error Code Test";
const REDIRECT_URI: &str = "https://test.example.com/callback";

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
    std::env::set_var("BUNKER_RELAYS", "wss://relay.test.example");
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

fn create_test_auth_state(pool: PgPool) -> (AuthState, JoinHandle<()>) {
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = SecretPool::new(1);
    let producer_handle = secret_pool.spawn_producer(bcrypt.clone());
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    let auth_state = AuthState {
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
    };

    (auth_state, producer_handle)
}

fn test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

/// S256 transform from RFC 7636 section 4.2.
fn s256_challenge(verifier: &str) -> String {
    let hash = sha256::digest(verifier);
    let bytes = hex::decode(hash).expect("sha256 digest is hex");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn insert_code(pool: &PgPool, code: &str, challenge: &str, method: &str) -> Vec<u8> {
    let keys = Keys::generate();
    let secret = keys.secret_key().to_secret_bytes().to_vec();

    sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
            code_challenge, code_challenge_method, pending_email, pending_password_hash,
            pending_email_verification_token, pending_encrypted_secret, is_headless
         ) VALUES (
            $1, $2, $3, $4, 'policy:social', $5, 1, NOW(), $6, $7, $8, 'test-password-hash',
            $9, $10, false
         )",
    )
    .bind(code)
    .bind(keys.public_key().to_hex())
    .bind(CLIENT_ID)
    .bind(REDIRECT_URI)
    .bind(Utc::now() + Duration::minutes(10))
    .bind(challenge)
    .bind(method)
    .bind(format!("pkce-error-{}@example.com", Uuid::new_v4()))
    .bind(format!("verify-{code}"))
    .bind(&secret)
    .execute(pool)
    .await
    .expect("Should insert OAuth code");

    secret
}

/// Exchange a code and render the outcome exactly as axum would, so the assertions
/// below see the real response body rather than the internal error enum.
async fn exchange(pool: &PgPool, code: &str, verifier: &str) -> Response {
    let (auth_state, producer_handle) = create_test_auth_state(pool.clone());

    let result = oauth::token(
        test_tenant(),
        State(auth_state),
        oauth::TokenRequestBody(oauth::TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(code.to_string()),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: Some(REDIRECT_URI.to_string()),
            code_verifier: Some(verifier.to_string()),
            refresh_token: None,
        }),
    )
    .await;

    producer_handle.abort();
    result.into_response()
}

async fn body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&bytes).expect("response body should be JSON")
}

#[tokio::test]
async fn token_endpoint_returns_invalid_grant_when_the_s256_verifier_does_not_match() {
    let pool = setup_pool().await;
    let verifier = format!("correct-verifier-{}", Uuid::new_v4());
    let code = format!("pkce-mismatch-{}", Uuid::new_v4());
    insert_code(&pool, &code, &s256_challenge(&verifier), "S256").await;

    let response = exchange(&pool, &code, "a-verifier-that-does-not-match").await;
    let status = response.status();
    let body = body_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    // RFC 7636 section 4.6 requires invalid_grant, and RFC 6749 section 5.2 requires the
    // registered code to be the value of `error` rather than free-text prose.
    assert_eq!(body["error"], "invalid_grant", "body was {body}");
}

#[tokio::test]
async fn token_endpoint_accepts_a_matching_s256_verifier() {
    // Control for the test above: without this, an implementation that rejected every
    // exchange with invalid_grant would still pass.
    let pool = setup_pool().await;
    let verifier = format!("correct-verifier-{}", Uuid::new_v4());
    let code = format!("pkce-match-{}", Uuid::new_v4());
    insert_code(&pool, &code, &s256_challenge(&verifier), "S256").await;

    let response = exchange(&pool, &code, &verifier).await;

    assert_eq!(response.status(), StatusCode::OK);
}
