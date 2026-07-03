#![cfg(feature = "integration-tests")]

// ABOUTME: Integration coverage for exchanging standard OAuth codes for existing users.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use chrono::{Duration, Utc};
use keycast_api::{
    api::{
        http::{
            oauth::{token, TokenRequest, TokenRequestBody},
            routes::AuthState,
        },
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::{OAuthCodeRepository, StoreOAuthCodeParams},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::Arc;
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
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

fn create_auth_state(pool: PgPool) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = Box::leak(Box::new(SecretPool::new(1)));
    let _secret_pool_producer = secret_pool.spawn_producer();
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

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&body).expect("response body should be JSON")
}

async fn cleanup_user(pool: &PgPool, user_pubkey: &str, code: &str) {
    let _ = sqlx::query(
        "DELETE FROM oauth_refresh_tokens
         WHERE authorization_id IN (
             SELECT id FROM oauth_authorizations WHERE user_pubkey = $1 AND tenant_id = 1
         )",
    )
    .bind(user_pubkey)
    .execute(pool)
    .await;
    let _ =
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1 AND tenant_id = 1")
            .bind(user_pubkey)
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = 1")
        .bind(user_pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE code = $1 OR user_pubkey = $2")
        .bind(code)
        .bind(user_pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = 1")
        .bind(user_pubkey)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn oauth_token_exchanges_plain_existing_user_code() {
    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.test");
    let pool = setup_pool().await;
    let auth_state = create_auth_state(pool.clone());
    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let nsec = keys.secret_key().to_bech32().unwrap();
    let email = format!("oauth-token-existing-{}@example.com", Uuid::new_v4());
    let code = format!("oauth_token_existing_{}", Uuid::new_v4());
    let client_id = format!("client_{}", Uuid::new_v4());
    let redirect_uri = "http://localhost:3000/callback";

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
         VALUES ($1, 1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    OAuthCodeRepository::new(pool.clone())
        .store(StoreOAuthCodeParams {
            tenant_id: 1,
            code: &code,
            user_pubkey: &user_pubkey,
            client_id: &client_id,
            redirect_uri,
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at: Utc::now() + Duration::minutes(10),
            previous_auth_id: None,
            state: None,
            is_headless: false,
        })
        .await
        .unwrap();

    let response = match token(
        create_test_tenant(),
        State(auth_state),
        TokenRequestBody(TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(code.clone()),
            client_id,
            redirect_uri: Some(redirect_uri.to_string()),
            code_verifier: Some(format!("verifier.{}", nsec)),
            refresh_token: None,
        }),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    let status = response.status();
    let body = response_json(response).await;

    cleanup_user(&pool, &user_pubkey, &code).await;

    assert_eq!(status, StatusCode::OK, "unexpected token response: {body}");
    assert!(body["access_token"].is_string(), "token response: {body}");
    assert!(body["bunker_url"].is_string(), "token response: {body}");
}
