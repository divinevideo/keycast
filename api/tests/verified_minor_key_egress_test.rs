#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the verified_minor raw-key egress gate (support-trust-safety#188)
// ABOUTME: over POST /user/export-key and POST /user/change-key.

mod common;

use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use keycast_api::api::{
    http::{
        auth::{change_key, export_key, AuthError, ChangeKeyRequest},
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

const TENANT_ID: i64 = 1;

/// The uniform, non-specific message every minor-egress refusal surfaces.
const DENIED_MSG: &str = "Operation denied by policy";

/// The uniform machine-readable code that accompanies it.
const DENIED_CODE: &str = "KEY_EGRESS_DENIED";

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&body).expect("response body should be JSON")
}

/// Pin the refusal as a client sees it: 403, the uniform message, and a code that
/// is the *same* for every denial reason. A per-reason code here would re-leak the
/// account state the uniform message exists to hide.
async fn assert_key_egress_denied_wire_shape() {
    let response = axum::response::IntoResponse::into_response(AuthError::KeyEgressDenied);
    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_eq!(body["error"], DENIED_MSG);
    assert_eq!(body["code"], DENIED_CODE);
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

fn create_test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "login.divine.video".to_string(),
        name: "Key Egress Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn create_test_auth_state(pool: PgPool, key_manager: Arc<Box<dyn KeyManager>>) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
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

/// Insert a user (optionally verified_minor) with an email + bcrypt password
/// hash and email verified, so both export-key and change-key can authenticate.
async fn insert_user(
    pool: &PgPool,
    pubkey: &str,
    email: &str,
    password: &str,
    verified_minor: bool,
) {
    let password_hash = bcrypt::hash(password, 4).expect("hash password");
    sqlx::query(
        "INSERT INTO users
            (pubkey, tenant_id, email, password_hash, email_verified, verified_minor, verified_minor_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, true, $5, CASE WHEN $5 THEN NOW() ELSE NULL END, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .bind(&password_hash)
    .bind(verified_minor)
    .execute(pool)
    .await
    .expect("insert user");
}

async fn create_personal_key(
    pool: &PgPool,
    user_pubkey: &str,
    user_keys: &Keys,
    km: &dyn KeyManager,
) {
    let encrypted = km
        .encrypt(&user_keys.secret_key().secret_bytes())
        .await
        .expect("encrypt user secret");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(user_pubkey)
    .bind(&encrypted)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("create personal key");
}

async fn bearer_for(keys: &Keys) -> String {
    let key_material = NostrKeyMaterial::from_keys(keys.clone());
    let user_did = nostr_pubkey_to_did(&keys.public_key());
    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(json!({
            "tenant_id": TENANT_ID,
            "email": "key-egress-test@example.com",
            "redirect_origin": "https://login.divine.video",
        }))
        .build()
        .expect("build UCAN")
        .sign()
        .await
        .expect("sign UCAN");
    format!("Bearer {}", ucan.encode().expect("encode UCAN"))
}

fn auth_headers(bearer: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", bearer.parse().expect("valid header"));
    headers.insert("host", "login.divine.video".parse().expect("valid host"));
    headers.insert("x-forwarded-proto", "https".parse().expect("valid proto"));
    // change-key requires a first-party (HTTPS) Origin header; export-key ignores it.
    headers.insert(
        "origin",
        "https://login.divine.video".parse().expect("valid origin"),
    );
    headers
}

async fn user_exists(pool: &PgPool, pubkey: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE pubkey = $1 AND tenant_id = $2")
        .bind(pubkey)
        .bind(TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("count users")
        > 0
}

fn unique_email() -> String {
    format!("ke-{}@example.com", Uuid::new_v4())
}

fn km_arc(km: FileKeyManager) -> Arc<Box<dyn KeyManager>> {
    Arc::new(Box::new(km) as Box<dyn KeyManager>)
}

// ============================================================================
// export-key
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_export_key_refused() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), "correct-horse", true).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let err = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": "correct-horse", "format": "nsec" })),
    )
    .await
    .expect_err("verified_minor export-key must be refused");

    match err {
        AuthError::KeyEgressDenied => assert_key_egress_denied_wire_shape().await,
        other => panic!("expected KeyEgressDenied, got: {other:?}"),
    }
}

#[tokio::test]
#[serial]
async fn minor_export_key_refused_before_password_check() {
    // Placement: the gate precedes the password check, so a verified_minor is
    // refused with the uniform message even on a WRONG password (never reaching
    // InvalidCredentials). This keeps the least code between auth and refusal.
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), "correct-horse", true).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let err = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": "WRONG-password", "format": "nsec" })),
    )
    .await
    .expect_err("verified_minor export-key must be refused regardless of password");

    match err {
        AuthError::KeyEgressDenied => assert_key_egress_denied_wire_shape().await,
        other => panic!("expected KeyEgressDenied before password check, got: {other:?}"),
    }
}

#[tokio::test]
#[serial]
async fn non_minor_export_key_returns_nsec() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), "correct-horse", false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let Json(resp) = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": "correct-horse", "format": "nsec" })),
    )
    .await
    .expect("non-minor export-key must succeed");

    assert!(
        resp.key.starts_with("nsec1"),
        "expected an nsec, got: {}",
        resp.key
    );
}

#[tokio::test]
#[serial]
async fn export_key_missing_user_row_fails_closed() {
    // Fail closed: a valid token whose account row cannot be resolved (so minor
    // status is unknown) must be refused, not fall through.
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate(); // no user row inserted
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let err = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": "whatever", "format": "nsec" })),
    )
    .await
    .expect_err("unresolvable account must fail closed");

    match err {
        AuthError::KeyEgressDenied => assert_key_egress_denied_wire_shape().await,
        other => panic!("expected KeyEgressDenied fail-closed, got: {other:?}"),
    }
}

// ============================================================================
// change-key
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_change_key_refused_and_key_unchanged() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), "correct-horse", true).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();

    let err = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: "correct-horse".to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("nsec")),
        }),
    )
    .await
    .expect_err("verified_minor change-key must be refused");

    match err {
        AuthError::KeyEgressDenied => assert_key_egress_denied_wire_shape().await,
        other => panic!("expected KeyEgressDenied, got: {other:?}"),
    }
    // No key swap happened: the original identity still exists, the new one was
    // never created.
    assert!(
        user_exists(&pool, &pubkey).await,
        "old identity must survive a refused change-key"
    );
    assert!(
        !user_exists(&pool, &new_pubkey).await,
        "refused change-key must not create the new identity"
    );
}

#[tokio::test]
#[serial]
async fn non_minor_change_key_succeeds() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), "correct-horse", false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();

    change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: "correct-horse".to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("nsec")),
        }),
    )
    .await
    .expect("non-minor change-key must succeed");

    assert!(
        user_exists(&pool, &new_pubkey).await,
        "non-minor change-key must migrate to the new identity"
    );
}

#[tokio::test]
#[serial]
async fn change_key_missing_user_row_fails_closed() {
    // Symmetric to export_key_missing_user_row_fails_closed: an unresolvable
    // account (valid token, no row) must be refused, not fall through.
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate(); // no user row inserted
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km));

    let new_keys = Keys::generate();
    let err = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: "whatever".to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("nsec")),
        }),
    )
    .await
    .expect_err("unresolvable account must fail closed");

    match err {
        AuthError::KeyEgressDenied => assert_key_egress_denied_wire_shape().await,
        other => panic!("expected KeyEgressDenied fail-closed, got: {other:?}"),
    }
}
