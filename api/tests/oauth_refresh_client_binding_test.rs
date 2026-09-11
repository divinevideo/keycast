#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the refresh-token grant's client binding at /api/oauth/token.
// ABOUTME: Covers rejection of a mismatched client_id and continued success for the bound client.

mod common;

use axum::{extract::State, http::StatusCode, response::IntoResponse};
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
    repositories::RefreshTokenRepository,
    secret_pool::SecretPool,
    types::refresh_token::hash_refresh_token,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::task::JoinHandle;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const BOUND_CLIENT_ID: &str = "bound-client";
const OTHER_CLIENT_ID: &str = "other-client";

/// Identity key manager: `personal_keys.encrypted_secret_key` holds the raw
/// secret bytes, matching the other OAuth integration tests.
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
            account_status_cache: keycast_api::state::new_account_status_cache(),
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

fn test_tenant_with_id(id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

/// An authorization owned by `BOUND_CLIENT_ID` plus a live refresh token for it.
/// Returns the user pubkey and the raw refresh token.
async fn seed_authorization_with_refresh_token(pool: &PgPool) -> (String, String) {
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_secret = user_keys.secret_key().to_secret_bytes();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Should insert test user");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(user_secret.as_ref())
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Should insert personal keys");

    let authorization_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays,
          tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret-hash', '[]', $5,
                 NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(format!(
        "https://refresh-binding-{}.example",
        Uuid::new_v4()
    ))
    .bind(BOUND_CLIENT_ID)
    .bind(Keys::generate().public_key().to_hex())
    .bind(TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("Should insert OAuth authorization");

    let refresh_token = format!("refresh-token-{}", Uuid::new_v4());
    RefreshTokenRepository::new(pool.clone())
        .create(&refresh_token, authorization_id, TENANT_ID)
        .await
        .expect("Should insert refresh token");

    (user_pubkey, refresh_token)
}

async fn refresh(
    pool: &PgPool,
    refresh_token: &str,
    client_id: &str,
) -> Result<axum::response::Response, oauth::OAuthError> {
    refresh_for_tenant(pool, refresh_token, client_id, TENANT_ID).await
}

async fn refresh_for_tenant(
    pool: &PgPool,
    refresh_token: &str,
    client_id: &str,
    tenant_id: i64,
) -> Result<axum::response::Response, oauth::OAuthError> {
    let (auth_state, producer_handle) = create_test_auth_state(pool.clone());

    let result = oauth::token(
        test_tenant_with_id(tenant_id),
        State(auth_state),
        oauth::TokenRequestBody(oauth::TokenRequest {
            grant_type: Some("refresh_token".to_string()),
            code: None,
            client_id: client_id.to_string(),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(refresh_token.to_string()),
        }),
    )
    .await;

    producer_handle.abort();
    result
}

async fn consumed_at(pool: &PgPool, refresh_token: &str) -> Option<chrono::DateTime<Utc>> {
    sqlx::query_scalar("SELECT consumed_at FROM oauth_refresh_tokens WHERE token_hash = $1")
        .bind(hash_refresh_token(refresh_token))
        .fetch_one(pool)
        .await
        .expect("Refresh token row should exist")
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Response body should be readable");
    serde_json::from_slice(&body).expect("Response body should be JSON")
}

async fn cleanup(pool: &PgPool, user_pubkey: &str) {
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(user_pubkey)
        .execute(pool)
        .await
        .expect("Should clean up test user");
}

#[tokio::test]
async fn refresh_grant_rejects_a_client_id_other_than_the_one_the_token_was_issued_to() {
    let pool = setup_pool().await;
    let (user_pubkey, refresh_token) = seed_authorization_with_refresh_token(&pool).await;

    let response = refresh(&pool, &refresh_token, OTHER_CLIENT_ID)
        .await
        .expect_err("A client_id other than the bound one must be rejected")
        .into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Refresh token was not issued to this client"
        })
    );

    // The rejection happens before rotation, so the bound client's token survives.
    assert_eq!(consumed_at(&pool, &refresh_token).await, None);

    cleanup(&pool, &user_pubkey).await;
}

#[tokio::test]
async fn refresh_grant_still_succeeds_for_the_client_the_token_was_issued_to() {
    let pool = setup_pool().await;
    let (user_pubkey, refresh_token) = seed_authorization_with_refresh_token(&pool).await;

    let response = refresh(&pool, &refresh_token, BOUND_CLIENT_ID)
        .await
        .expect("The bound client must still be able to refresh");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let rotated = body["refresh_token"]
        .as_str()
        .expect("Successful refresh returns a rotated refresh token");
    assert_ne!(rotated, refresh_token);
    assert!(body["access_token"].as_str().is_some());

    // The presented token is spent and the rotated one is live.
    assert!(consumed_at(&pool, &refresh_token).await.is_some());
    assert_eq!(consumed_at(&pool, rotated).await, None);

    cleanup(&pool, &user_pubkey).await;
}

#[tokio::test]
async fn refresh_grant_rejects_a_mismatched_client_before_disclosing_token_state() {
    let pool = setup_pool().await;
    let (user_pubkey, refresh_token) = seed_authorization_with_refresh_token(&pool).await;

    sqlx::query("UPDATE oauth_refresh_tokens SET expires_at = $1 WHERE token_hash = $2")
        .bind(Utc::now() - Duration::days(1))
        .bind(hash_refresh_token(&refresh_token))
        .execute(&pool)
        .await
        .expect("Should expire the refresh token");

    let response = refresh(&pool, &refresh_token, OTHER_CLIENT_ID)
        .await
        .expect_err("An expired token presented by another client must be rejected")
        .into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Refresh token was not issued to this client"
        })
    );

    cleanup(&pool, &user_pubkey).await;
}

#[tokio::test]
async fn refresh_grant_rejects_a_cross_tenant_request_without_consuming_the_token() {
    let pool = setup_pool().await;
    let (user_pubkey, refresh_token) = seed_authorization_with_refresh_token(&pool).await;

    let response = refresh_for_tenant(&pool, &refresh_token, BOUND_CLIENT_ID, TENANT_ID + 1)
        .await
        .expect_err("A refresh token must not be accepted from another tenant")
        .into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Invalid or expired refresh token"
        })
    );

    assert_eq!(consumed_at(&pool, &refresh_token).await, None);

    cleanup(&pool, &user_pubkey).await;
}
