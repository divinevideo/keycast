#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for scoping verifier-embedded nsec handling to browser BYOK registration.
// ABOUTME: Verifies headless registration keeps its stored key while browser BYOK stores the verifier key.

mod common;

use axum::{extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use keycast_api::{
    api::{
        http::{oauth, routes::AuthState},
        tenant::{Tenant, TenantExtractor},
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
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::task::JoinHandle;
use uuid::Uuid;
use zeroize::Zeroizing;

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
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let producer_handle = secret_pool.spawn_producer();
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
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
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

async fn insert_pending_registration(
    pool: &PgPool,
    code: &str,
    user_pubkey: &str,
    email: &str,
    verifier: &str,
    pending_encrypted_secret: Option<&[u8]>,
    is_headless: bool,
) {
    sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
            code_challenge, code_challenge_method, pending_email, pending_password_hash,
            pending_email_verification_token, pending_encrypted_secret, is_headless
         ) VALUES (
            $1, $2, 'Verifier Scope Test', 'https://test.example.com/callback', 'policy:social',
            $3, 1, NOW(), $4, 'plain', $5, 'test-password-hash', $6, $7, $8
         )",
    )
    .bind(code)
    .bind(user_pubkey)
    .bind(Utc::now() + Duration::minutes(10))
    .bind(verifier)
    .bind(email)
    .bind(format!("verify-{code}"))
    .bind(pending_encrypted_secret)
    .bind(is_headless)
    .execute(pool)
    .await
    .expect("Should insert pending OAuth registration");
}

async fn exchange_code(pool: &PgPool, code: &str, verifier: &str) -> StatusCode {
    let (auth_state, producer_handle) = create_test_auth_state(pool.clone());

    let result = oauth::token(
        test_tenant(),
        State(auth_state),
        oauth::TokenRequestBody(oauth::TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(code.to_string()),
            client_id: "Verifier Scope Test".to_string(),
            redirect_uri: Some("https://test.example.com/callback".to_string()),
            code_verifier: Some(verifier.to_string()),
            refresh_token: None,
        }),
    )
    .await;

    producer_handle.abort();
    result.expect("Token exchange should succeed").status()
}

#[tokio::test]
async fn headless_exchange_ignores_mismatching_verifier_nsec_and_uses_stored_secret() {
    let pool = setup_pool().await;
    let registration_keys = Keys::generate();
    let unrelated_keys = Keys::generate();
    let registration_pubkey = registration_keys.public_key().to_hex();
    let registration_secret = registration_keys.secret_key().to_secret_bytes();
    let verifier = format!(
        "headless-verifier.{}",
        unrelated_keys.secret_key().to_bech32().expect("nsec")
    );
    let code = format!("headless-code-{}", Uuid::new_v4());
    let email = format!("headless-verifier-scope-{}@example.com", Uuid::new_v4());

    insert_pending_registration(
        &pool,
        &code,
        &registration_pubkey,
        &email,
        &verifier,
        Some(&registration_secret),
        true,
    )
    .await;

    assert_eq!(exchange_code(&pool, &code, &verifier).await, StatusCode::OK);

    let stored_user_pubkey: String =
        sqlx::query_scalar("SELECT pubkey FROM users WHERE tenant_id = 1 AND email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Registration should create the user");
    let stored_secret: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = 1 AND user_pubkey = $1",
    )
    .bind(&registration_pubkey)
    .fetch_one(&pool)
    .await
    .expect("Registration should create personal keys");

    assert_eq!(stored_user_pubkey, registration_pubkey);
    assert_eq!(stored_secret, registration_secret);
}

#[tokio::test]
async fn browser_byok_exchange_extracts_validates_and_stores_verifier_nsec() {
    let pool = setup_pool().await;
    let browser_keys = Keys::generate();
    let browser_pubkey = browser_keys.public_key().to_hex();
    let browser_secret = browser_keys.secret_key().to_secret_bytes();
    let verifier = format!(
        "browser-verifier.{}",
        browser_keys.secret_key().to_bech32().expect("nsec")
    );
    let code = format!("browser-code-{}", Uuid::new_v4());
    let email = format!("browser-verifier-scope-{}@example.com", Uuid::new_v4());

    insert_pending_registration(
        &pool,
        &code,
        &browser_pubkey,
        &email,
        &verifier,
        None,
        false,
    )
    .await;

    assert_eq!(exchange_code(&pool, &code, &verifier).await, StatusCode::OK);

    let stored_secret: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = 1 AND user_pubkey = $1",
    )
    .bind(&browser_pubkey)
    .fetch_one(&pool)
    .await
    .expect("BYOK registration should store personal keys");

    assert_eq!(stored_secret, browser_secret);
}
