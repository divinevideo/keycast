#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the unconfirmed-email DM gate over the HTTP RPC
// ABOUTME: (/api/nostr) and fast-sign (/api/user/sign) paths.

mod common;

use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use chrono::Utc;
use keycast_api::api::{
    http::{
        auth::{sign_event, AuthError, SignEventRequest},
        nostr_rpc::{nostr_rpc, NostrRpcRequest, NostrRpcResponse, RpcError},
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_api::BcryptAdmission;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::secret_pool::SecretPool;
use keycast_core::verified_minor_dm::PINNED_MINOR_CONTACTABLE_PUBKEYS;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

async fn setup_db() -> PgPool {
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

async fn create_test_tenant(pool: &PgPool) -> i64 {
    let domain = format!("test-unconfirmed-dm-{}.example.com", Uuid::new_v4());
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(&domain)
    .bind("Unconfirmed DM Gate Test Tenant")
    .fetch_one(pool)
    .await
    .expect("Failed to create test tenant")
}

fn tenant_extractor(tenant_id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: tenant_id,
        domain: "login.divine.video".to_string(),
        name: "Unconfirmed DM Gate Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn create_test_auth_state(pool: PgPool, key_manager: Arc<Box<dyn KeyManager>>) -> AuthState {
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();

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

async fn create_personal_key(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    user_keys: &Keys,
    key_manager: &dyn KeyManager,
) {
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(user_pubkey)
    .bind(&encrypted_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");
}

/// Create oauth_authorization and return its bunker_public_key.
async fn create_oauth_authorization(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
) -> String {
    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();
    let auth_handle = hex::encode(rand::random::<[u8; 32]>());

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, policy_id, tenant_id, expires_at, revoked_at, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'test_hash', $4, NULL, $5, NULL, NULL, $6, NOW() + INTERVAL '30 days', NOW(), NOW())"
    )
    .bind(user_pubkey)
    .bind(redirect_origin)
    .bind(&bunker_pubkey)
    .bind(json!(["wss://relay.example.com"]).to_string())
    .bind(tenant_id)
    .bind(&auth_handle)
    .execute(pool)
    .await
    .expect("Failed to create oauth authorization");

    bunker_pubkey
}

async fn build_self_signed_ucan(
    user_keys: &Keys,
    tenant_id: i64,
    redirect_origin: &str,
    bunker_pubkey: Option<&str>,
) -> String {
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());
    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let mut facts = json!({
        "tenant_id": tenant_id,
        "email": "unconfirmed-dm-test@example.com",
        "redirect_origin": redirect_origin,
    });
    if let Some(bpk) = bunker_pubkey {
        facts["bunker_pubkey"] = json!(bpk);
    }

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("Failed to build UCAN")
        .sign()
        .await
        .expect("Failed to sign UCAN");

    ucan.encode().expect("Failed to encode UCAN")
}

/// How the test account's users row looks.
#[derive(Clone, Copy)]
enum EmailState {
    /// An email that was never confirmed: the gated case.
    Unconfirmed,
    /// A confirmed email.
    Confirmed,
    /// No email at all (preloaded, imported, released by a handover).
    None,
}

async fn insert_user(
    pool: &PgPool,
    tenant_id: i64,
    pubkey: &str,
    email_state: EmailState,
    verified_minor: bool,
) {
    let (email, verified) = match email_state {
        EmailState::Unconfirmed => (Some(format!("{pubkey}@example.com")), false),
        EmailState::Confirmed => (Some(format!("{pubkey}@example.com")), true),
        EmailState::None => (None, false),
    };
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, verified_minor, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(tenant_id)
    .bind(email)
    .bind(verified)
    .bind(verified_minor)
    .execute(pool)
    .await
    .expect("Failed to insert user");
}

struct TestAccount {
    keys: Keys,
    token: String,
}

async fn setup_account(
    pool: &PgPool,
    tenant_id: i64,
    key_manager: &dyn KeyManager,
    email_state: EmailState,
    verified_minor: bool,
) -> TestAccount {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(pool, tenant_id, &pubkey, email_state, verified_minor).await;
    create_personal_key(pool, tenant_id, &pubkey, &keys, key_manager).await;
    let redirect_origin = format!("https://unconfirmed-dm-{}.example.com", Uuid::new_v4());
    let bunker_pubkey =
        create_oauth_authorization(pool, tenant_id, &pubkey, &redirect_origin).await;
    let token =
        build_self_signed_ucan(&keys, tenant_id, &redirect_origin, Some(&bunker_pubkey)).await;
    TestAccount { keys, token }
}

async fn invoke_rpc(
    tenant_id: i64,
    auth_state: AuthState,
    token: &str,
    method: &str,
    params: Vec<Value>,
) -> Result<NostrRpcResponse, RpcError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", token).parse().expect("valid header"),
    );
    headers.insert("host", "login.divine.video".parse().expect("valid host"));
    headers.insert("x-forwarded-proto", "https".parse().expect("valid proto"));

    let Json(response) = nostr_rpc(
        tenant_extractor(tenant_id),
        State(auth_state),
        headers,
        Json(NostrRpcRequest {
            method: method.to_string(),
            params,
        }),
    )
    .await?;
    Ok(response)
}

fn hq_pubkey() -> PublicKey {
    PublicKey::from_hex(PINNED_MINOR_CONTACTABLE_PUBKEYS[0]).unwrap()
}

fn unsigned_json(kind: u16, author: &Keys, recipients: &[PublicKey]) -> Value {
    let tags: Vec<Tag> = recipients.iter().map(|pk| Tag::public_key(*pk)).collect();
    let unsigned = EventBuilder::new(Kind::from(kind), "unconfirmed gate test")
        .tags(tags)
        .build(author.public_key());
    serde_json::to_value(&unsigned).expect("serialize unsigned event")
}

async fn account(email_state: EmailState, verified_minor: bool) -> (i64, AuthState, TestAccount) {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let account = setup_account(&pool, tenant_id, &key_manager, email_state, verified_minor).await;
    let auth_state =
        create_test_auth_state(pool, Arc::new(Box::new(key_manager) as Box<dyn KeyManager>));
    (tenant_id, auth_state, account)
}

async fn rpc_error_body(err: RpcError) -> (axum::http::StatusCode, Value) {
    let response = err.into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

// ============================================================================
// HTTP RPC (/api/nostr)
// ============================================================================

#[tokio::test]
#[serial]
async fn unconfirmed_rpc_dm_to_a_stranger_is_refused_with_its_own_code() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, false).await;
    let stranger = Keys::generate();

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &account.token,
        "sign_event",
        vec![unsigned_json(4, &account.keys, &[stranger.public_key()])],
    )
    .await
    .expect_err("an unconfirmed account must not DM a stranger");

    assert!(matches!(err, RpcError::EmailNotConfirmed), "{err:?}");
    let (status, body) = rpc_error_body(err).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "EMAIL_NOT_CONFIRMED");
    assert_eq!(body["error"], "Confirm your email to send direct messages.");
}

#[tokio::test]
#[serial]
async fn unconfirmed_rpc_gift_wrap_and_rumor_are_refused() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, false).await;
    let stranger = Keys::generate();

    for kind in [14u16, 15, 1059] {
        let err = invoke_rpc(
            tenant_id,
            auth_state.clone(),
            &account.token,
            "sign_event",
            vec![unsigned_json(kind, &account.keys, &[stranger.public_key()])],
        )
        .await
        .expect_err("DM carrier kinds must be refused");
        assert!(
            matches!(err, RpcError::EmailNotConfirmed),
            "kind {kind}: {err:?}"
        );
    }
}

#[tokio::test]
#[serial]
async fn unconfirmed_rpc_encrypt_reaches_only_itself_and_the_officials() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, false).await;
    let stranger = Keys::generate();

    for method in ["nip44_encrypt", "nip04_encrypt"] {
        let err = invoke_rpc(
            tenant_id,
            auth_state.clone(),
            &account.token,
            method,
            vec![json!(stranger.public_key().to_hex()), json!("hello")],
        )
        .await
        .expect_err("encrypting to a stranger must be refused");
        assert!(
            matches!(err, RpcError::EmailNotConfirmed),
            "{method}: {err:?}"
        );

        for recipient in [account.keys.public_key(), hq_pubkey()] {
            invoke_rpc(
                tenant_id,
                auth_state.clone(),
                &account.token,
                method,
                vec![json!(recipient.to_hex()), json!("hello")],
            )
            .await
            .unwrap_or_else(|err| panic!("{method} to {recipient} must work: {err:?}"));
        }
    }
}

#[tokio::test]
#[serial]
async fn unconfirmed_rpc_public_events_still_sign() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, false).await;
    let stranger = Keys::generate();

    for kind in [1u16, 7, 1111, 34236] {
        let signed = invoke_rpc(
            tenant_id,
            auth_state.clone(),
            &account.token,
            "sign_event",
            vec![unsigned_json(kind, &account.keys, &[stranger.public_key()])],
        )
        .await
        .unwrap_or_else(|err| panic!("kind {kind} must sign: {err:?}"));
        assert!(signed.result.is_some());
    }
}

#[tokio::test]
#[serial]
async fn confirmed_and_email_less_accounts_dm_as_before() {
    for email_state in [EmailState::Confirmed, EmailState::None] {
        let (tenant_id, auth_state, account) = account(email_state, false).await;
        let stranger = Keys::generate();
        invoke_rpc(
            tenant_id,
            auth_state,
            &account.token,
            "sign_event",
            vec![unsigned_json(4, &account.keys, &[stranger.public_key()])],
        )
        .await
        .expect("an account with nothing to confirm DMs normally");
    }
}

#[tokio::test]
#[serial]
async fn an_unconfirmed_minor_keeps_the_uniform_minor_refusal() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, true).await;
    let stranger = Keys::generate();

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &account.token,
        "sign_event",
        vec![unsigned_json(4, &account.keys, &[stranger.public_key()])],
    )
    .await
    .expect_err("refused");
    match err {
        RpcError::Auth(AuthError::Forbidden(msg)) => {
            assert_eq!(msg, "Operation denied by policy");
        }
        other => panic!("a minor's refusal must not reveal more: {other:?}"),
    }
}

// ============================================================================
// Fast sign (/api/user/sign)
// ============================================================================

async fn invoke_user_sign(
    tenant_id: i64,
    auth_state: AuthState,
    token: &str,
    event_json: Value,
) -> Result<Value, AuthError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", token).parse().expect("valid header"),
    );
    headers.insert("host", "login.divine.video".parse().expect("valid host"));
    headers.insert("x-forwarded-proto", "https".parse().expect("valid proto"));

    let Json(response) = sign_event(
        tenant_extractor(tenant_id),
        State(auth_state),
        headers,
        Json(SignEventRequest { event: event_json }),
    )
    .await?;
    Ok(response.signed_event)
}

#[tokio::test]
#[serial]
async fn unconfirmed_user_sign_refuses_a_dm_with_its_own_code() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, false).await;
    let stranger = Keys::generate();

    let err = invoke_user_sign(
        tenant_id,
        auth_state,
        &account.token,
        unsigned_json(4, &account.keys, &[stranger.public_key()]),
    )
    .await
    .expect_err("refused");
    assert!(matches!(err, AuthError::EmailNotConfirmed), "{err:?}");
    let response = err.into_response();
    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "EMAIL_NOT_CONFIRMED");
}

#[tokio::test]
#[serial]
async fn unconfirmed_user_sign_still_signs_public_events() {
    let (tenant_id, auth_state, account) = account(EmailState::Unconfirmed, false).await;

    invoke_user_sign(
        tenant_id,
        auth_state,
        &account.token,
        unsigned_json(1, &account.keys, &[]),
    )
    .await
    .expect("a public note signs");
}
