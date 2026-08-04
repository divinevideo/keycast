#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for refresh-token rotation preserving first-party deletion authority
// ABOUTME: Guards DELETE /user/account authorization against silently losing the first_party UCAN fact

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::{Duration, Utc};
use keycast_api::{
    api::{
        http::oauth::{token, TokenRequest},
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::{
        CreateOAuthAuthorizationParams, OAuthAuthorizationRepository, RefreshTokenRepository,
    },
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::{Arc, Once};
use tower::ServiceExt;
use ucan::Ucan;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

const TENANT_ID: i64 = 1;

static BUNKER_RELAYS_INIT: Once = Once::new();

/// The refresh response reconstructs a bunker URL, which reads the deployment-wide
/// relay configuration. Set it once so parallel tests never race on the write.
fn configure_bunker_relays() {
    BUNKER_RELAYS_INIT.call_once(|| {
        std::env::set_var("BUNKER_RELAYS", "wss://relay.test.example");
    });
}

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    configure_bunker_relays();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

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
        id: TENANT_ID,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

struct SeededAuthorization {
    user_pubkey: String,
    refresh_token: String,
}

/// Seed a user, their stored key, an OAuth authorization with the requested
/// first-party status, and a live refresh token bound to that authorization.
async fn seed_authorization(pool: &PgPool, is_first_party: bool) -> SeededAuthorization {
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let email = format!("refresh-first-party-{}@example.test", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(TENANT_ID)
    .bind(&email)
    .execute(pool)
    .await
    .expect("Failed to create test user");

    // TestKeyManager is the identity transform, so the stored ciphertext is the raw secret.
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(&user_pubkey)
    .bind(user_keys.secret_key().secret_bytes().to_vec())
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    let secret_hash = format!("connection-secret-{}", Uuid::new_v4());
    let bunker_public_key =
        keycast_core::bunker_key::derive_bunker_keys(user_keys.secret_key(), &secret_hash)
            .public_key()
            .to_hex();

    let authorization_id = OAuthAuthorizationRepository::new(pool.clone())
        .create(CreateOAuthAuthorizationParams {
            tenant_id: TENANT_ID,
            user_pubkey: user_pubkey.clone(),
            redirect_origin: format!("https://refresh-{}.example.test", Uuid::new_v4()),
            client_id: "Refresh Test Client".to_string(),
            bunker_public_key,
            secret_hash,
            relays: "[]".to_string(),
            policy_id: None,
            is_first_party,
            client_pubkey: None,
            authorization_handle: Some(Uuid::new_v4().to_string()),
            handle_expires_at: Utc::now() + Duration::days(30),
        })
        .await
        .expect("Failed to create OAuth authorization");

    let refresh_token = format!("refresh-token-{}", Uuid::new_v4());
    RefreshTokenRepository::new(pool.clone())
        .create(&refresh_token, authorization_id, TENANT_ID)
        .await
        .expect("Failed to create refresh token");

    SeededAuthorization {
        user_pubkey,
        refresh_token,
    }
}

async fn cleanup(pool: &PgPool, user_pubkey: &str) {
    let _ = sqlx::query(
        "DELETE FROM oauth_refresh_tokens WHERE authorization_id IN
         (SELECT id FROM oauth_authorizations WHERE user_pubkey = $1)",
    )
    .bind(user_pubkey)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
        .bind(user_pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
        .bind(user_pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(user_pubkey)
        .execute(pool)
        .await;
}

/// Exchange a refresh token through the real `/oauth/token` route and return the
/// `first_party` fact carried by the rotated access token.
async fn refreshed_access_token_is_first_party(pool: &PgPool, refresh_token: &str) -> bool {
    let auth_state = create_test_auth_state(pool.clone());
    let app = Router::new().route(
        "/oauth/token",
        post(move |Json(req): Json<TokenRequest>| {
            let auth_state = auth_state.clone();
            async move { token(create_test_tenant(), State(auth_state), Json(req)).await }
        }),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "grant_type": "refresh_token",
                        "client_id": "Refresh Test Client",
                        "refresh_token": refresh_token,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("refresh grant request should complete");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "refresh grant should succeed"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let payload: serde_json::Value =
        serde_json::from_slice(&body).expect("response body should be JSON");
    let access_token = payload["access_token"]
        .as_str()
        .expect("refresh response should carry an access_token");

    Ucan::try_from_token_string(access_token)
        .expect("rotated access token should decode as a UCAN")
        .facts()
        .iter()
        .any(|fact| fact.get("first_party").and_then(|v| v.as_bool()) == Some(true))
}

/// The regression this guards: a first-party session that refreshes immediately
/// before deleting its account must keep the fact `delete_account` requires.
#[tokio::test]
async fn refresh_grant_preserves_first_party_fact() {
    let pool = setup_pool().await;
    let seeded = seed_authorization(&pool, true).await;

    let is_first_party = refreshed_access_token_is_first_party(&pool, &seeded.refresh_token).await;

    cleanup(&pool, &seeded.user_pubkey).await;

    assert!(
        is_first_party,
        "refreshing a first-party authorization must keep account-deletion authority"
    );
}

/// Third-party apps must not gain deletion authority by refreshing.
#[tokio::test]
async fn refresh_grant_withholds_first_party_fact_from_third_party_authorization() {
    let pool = setup_pool().await;
    let seeded = seed_authorization(&pool, false).await;

    let is_first_party = refreshed_access_token_is_first_party(&pool, &seeded.refresh_token).await;

    cleanup(&pool, &seeded.user_pubkey).await;

    assert!(
        !is_first_party,
        "third-party authorizations must never gain account-deletion authority via refresh"
    );
}
