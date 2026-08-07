#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for refresh-token rotation preserving first-party deletion authority
// ABOUTME: Guards DELETE /user/account authorization against silently losing the first_party UCAN fact

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use keycast_api::{
    api::{
        http::oauth::{authorize_get, AuthorizeRequest},
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
use nostr_sdk::{Keys, Url};
use sqlx::PgPool;
use std::sync::{Arc, Once};
use tower::ServiceExt;
use ucan::{builder::UcanBuilder, Ucan};
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};

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
    let _producer_handle = secret_pool.spawn_producer();
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

struct SeededReauthAuthorization {
    user_keys: Keys,
    user_pubkey: String,
    email: String,
    redirect_uri: String,
    authorization_handle: String,
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

async fn seed_reauth_authorization(pool: &PgPool) -> SeededReauthAuthorization {
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let email = format!("reauth-first-party-{}@example.test", Uuid::new_v4());
    let redirect_uri = format!("https://reauth-{}.example.test/callback", Uuid::new_v4());
    let redirect_origin = redirect_uri
        .strip_suffix("/callback")
        .expect("test redirect URI should have callback suffix")
        .to_string();

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

    let secret_hash = format!("reauth-connection-secret-{}", Uuid::new_v4());
    let bunker_public_key =
        keycast_core::bunker_key::derive_bunker_keys(user_keys.secret_key(), &secret_hash)
            .public_key()
            .to_hex();
    let authorization_handle = Uuid::new_v4().to_string();

    OAuthAuthorizationRepository::new(pool.clone())
        .create(CreateOAuthAuthorizationParams {
            tenant_id: TENANT_ID,
            user_pubkey: user_pubkey.clone(),
            redirect_origin,
            client_id: "Reauth Test Client".to_string(),
            bunker_public_key,
            secret_hash,
            relays: "[]".to_string(),
            policy_id: None,
            is_first_party: true,
            client_pubkey: None,
            authorization_handle: Some(authorization_handle.clone()),
            handle_expires_at: Utc::now() + Duration::days(30),
        })
        .await
        .expect("Failed to create OAuth authorization");

    SeededReauthAuthorization {
        user_keys,
        user_pubkey,
        email,
        redirect_uri,
        authorization_handle,
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

async fn user_signed_session_token(keys: &Keys, email: &str, redirect_origin: &str) -> String {
    let key_material = NostrKeyMaterial::from_keys(keys.clone());
    let user_did = nostr_pubkey_to_did(&keys.public_key());
    let facts = serde_json::json!({
        "tenant_id": TENANT_ID,
        "email": email,
        "redirect_origin": redirect_origin,
    });

    UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("session UCAN should build")
        .sign()
        .await
        .expect("session UCAN should sign")
        .encode()
        .expect("session UCAN should encode")
}

fn build_oauth_app(pool: PgPool) -> Router {
    let auth_state = create_test_auth_state(pool);
    let authorize_state = auth_state.clone();
    let token_state = auth_state;

    Router::new()
        .route(
            "/oauth/authorize",
            get(
                move |headers: HeaderMap, Query(req): Query<AuthorizeRequest>| {
                    let auth_state = authorize_state.clone();
                    async move {
                        authorize_get(create_test_tenant(), State(auth_state), headers, Query(req))
                            .await
                    }
                },
            ),
        )
        .route(
            "/oauth/token",
            post(move |Json(req): Json<TokenRequest>| {
                let auth_state = token_state.clone();
                async move { token(create_test_tenant(), State(auth_state), Json(req)).await }
            }),
        )
}

/// Exchange a refresh token through the real `/oauth/token` route and return the
/// `first_party` fact carried by the rotated access token.
async fn refreshed_access_token_is_first_party(
    pool: &PgPool,
    refresh_token: &str,
) -> Result<bool, String> {
    let app = build_oauth_app(pool.clone());

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
        .map_err(|error| format!("refresh grant request should complete: {}", error))?;

    if response.status() != StatusCode::OK {
        return Err(format!(
            "refresh grant should succeed: {}",
            response.status()
        ));
    }

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|error| format!("response body should be readable: {}", error))?;
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|error| format!("response body should be JSON: {}", error))?;
    let access_token = payload["access_token"]
        .as_str()
        .ok_or_else(|| "refresh response should carry an access_token".to_string())?;

    Ok(Ucan::try_from_token_string(access_token)
        .map_err(|error| format!("rotated access token should decode as a UCAN: {}", error))?
        .facts()
        .iter()
        .any(|fact| fact.get("first_party").and_then(|v| v.as_bool()) == Some(true)))
}

#[tokio::test]
async fn silent_reauth_preserves_first_party_authorization() {
    let pool = setup_pool().await;
    let seeded = seed_reauth_authorization(&pool).await;
    let session_token = user_signed_session_token(
        &seeded.user_keys,
        &seeded.email,
        "https://keycast.example.test",
    )
    .await;

    let app = build_oauth_app(pool.clone());
    let authorize_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/oauth/authorize?client_id={}&redirect_uri={}&scope=policy:full&authorization_handle={}",
                    urlencoding::encode("Reauth Test Client"),
                    urlencoding::encode(&seeded.redirect_uri),
                    urlencoding::encode(&seeded.authorization_handle),
                ))
                .header(
                    "cookie",
                    format!("keycast_session={}", session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("silent reauth request should complete");

    let authorize_status = authorize_response.status();
    if authorize_status != StatusCode::SEE_OTHER {
        cleanup(&pool, &seeded.user_pubkey).await;
        assert_eq!(authorize_status, StatusCode::SEE_OTHER);
    }
    let location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("silent reauth should redirect with a code");
    let redirect = Url::parse(location).expect("redirect location should be a valid URL");
    let code = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .expect("redirect should carry authorization code");

    let token_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "grant_type": "authorization_code",
                        "client_id": "Reauth Test Client",
                        "redirect_uri": seeded.redirect_uri,
                        "code": code,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("token exchange should complete");

    let token_status = token_response.status();
    if token_status != StatusCode::OK {
        cleanup(&pool, &seeded.user_pubkey).await;
        assert_eq!(token_status, StatusCode::OK);
    }

    let active_is_first_party: bool = sqlx::query_scalar(
        "SELECT is_first_party FROM oauth_authorizations
         WHERE user_pubkey = $1 AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&seeded.user_pubkey)
    .fetch_one(&pool)
    .await
    .expect("replacement authorization should exist");
    let old_revoked_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT revoked_at FROM oauth_authorizations
         WHERE user_pubkey = $1 AND authorization_handle = $2",
    )
    .bind(&seeded.user_pubkey)
    .bind(&seeded.authorization_handle)
    .fetch_one(&pool)
    .await
    .expect("old authorization should exist");

    cleanup(&pool, &seeded.user_pubkey).await;

    assert!(
        active_is_first_party,
        "silent reauth replacement must preserve first-party deletion authority"
    );
    assert!(
        old_revoked_at.is_some(),
        "silent reauth should still revoke the replaced authorization"
    );
}

/// The regression this guards: a first-party session that refreshes immediately
/// before deleting its account must keep the fact `delete_account` requires.
#[tokio::test]
async fn refresh_grant_preserves_first_party_fact() {
    let pool = setup_pool().await;
    let seeded = seed_authorization(&pool, true).await;

    let result = refreshed_access_token_is_first_party(&pool, &seeded.refresh_token).await;

    cleanup(&pool, &seeded.user_pubkey).await;

    let is_first_party = result.expect("refresh grant should return a decodable access token");

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

    let result = refreshed_access_token_is_first_party(&pool, &seeded.refresh_token).await;

    cleanup(&pool, &seeded.user_pubkey).await;

    let is_first_party = result.expect("refresh grant should return a decodable access token");

    assert!(
        !is_first_party,
        "third-party authorizations must never gain account-deletion authority via refresh"
    );
}
