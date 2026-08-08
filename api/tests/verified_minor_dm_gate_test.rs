#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the verified_minor DM containment gate (support-trust-safety#183)
// ABOUTME: over the HTTP RPC (/api/nostr) and fast-sign (/api/user/sign) paths.

mod common;

use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use keycast_api::api::{
    http::{
        auth::{sign_event, AuthError, SignEventRequest},
        nostr_rpc::{nostr_rpc, NostrRpcRequest, NostrRpcResponse, RpcError},
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
use keycast_core::signing_handler::{SignerHandlersCache, SigningHandler};
use keycast_core::verified_minor_dm::PINNED_MINOR_CONTACTABLE_PUBKEYS;
use moka::future::Cache;
use nostr_sdk::nips::nip44;
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

// ============================================================================
// Test helpers (mirroring nostr_rpc_integration_test.rs)
// ============================================================================

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
    let domain = format!("test-minor-dm-{}.example.com", Uuid::new_v4());
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(&domain)
    .bind("Minor DM Gate Test Tenant")
    .fetch_one(pool)
    .await
    .expect("Failed to create test tenant")
}

fn tenant_extractor(tenant_id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: tenant_id,
        domain: "login.divine.video".to_string(),
        name: "Minor DM Gate Test Tenant".to_string(),
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
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

async fn insert_user(pool: &PgPool, tenant_id: i64, pubkey: &str, verified_minor: bool) {
    if verified_minor {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at)
             VALUES ($1, $2, TRUE, NOW(), NOW(), NOW())",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("Failed to insert verified_minor user");
    } else {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("Failed to insert user");
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
        "email": "minor-dm-test@example.com",
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

/// Full test account: user row (+ optional verified_minor), personal key,
/// OAuth authorization, and a Bearer token routing through the OAuth handler.
struct TestAccount {
    keys: Keys,
    pubkey: String,
    token: String,
    bunker_pubkey: String,
}

async fn setup_account(
    pool: &PgPool,
    tenant_id: i64,
    key_manager: &dyn KeyManager,
    verified_minor: bool,
) -> TestAccount {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(pool, tenant_id, &pubkey, verified_minor).await;
    create_personal_key(pool, tenant_id, &pubkey, &keys, key_manager).await;
    let redirect_origin = format!("https://minor-dm-{}.example.com", Uuid::new_v4());
    let bunker_pubkey =
        create_oauth_authorization(pool, tenant_id, &pubkey, &redirect_origin).await;
    let token =
        build_self_signed_ucan(&keys, tenant_id, &redirect_origin, Some(&bunker_pubkey)).await;
    TestAccount {
        keys,
        pubkey,
        token,
        bunker_pubkey,
    }
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

fn unsigned_dm_json(kind: u16, author: &Keys, recipients: &[PublicKey]) -> Value {
    let tags: Vec<Tag> = recipients.iter().map(|pk| Tag::public_key(*pk)).collect();
    let unsigned = EventBuilder::new(Kind::from(kind), "gate test message")
        .tags(tags)
        .build(author.public_key());
    serde_json::to_value(&unsigned).expect("serialize unsigned event")
}

/// The uniform, non-specific message every minor-gate refusal surfaces.
const DENIED_MSG: &str = "Operation denied by policy";

fn assert_rpc_denied(err: RpcError) {
    match err {
        RpcError::Auth(AuthError::Forbidden(msg)) => {
            assert_eq!(
                msg, DENIED_MSG,
                "denial must use the uniform policy message"
            );
        }
        other => panic!("expected Forbidden({DENIED_MSG}), got: {other:?}"),
    }
}

// ============================================================================
// HTTP RPC (/api/nostr) — sign_event
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_rpc_sign_rumor_to_arbitrary_recipient_refused() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(14, &minor.keys, &[mallory.public_key()])],
    )
    .await
    .expect_err("minor DM rumor to arbitrary recipient must be refused");
    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_sign_rumor_kind_14_refused_outright_even_to_official() {
    // A conformant NIP-17 client never signs a kind-14 rumor via a remote
    // signer (rumors are unsigned); signing one only serves a covert channel,
    // so it is refused regardless of recipient. The legit DM-to-official path
    // is nip44_encrypt + the kind-13 seal (see minor_rpc_seal_flow_...).
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(14, &minor.keys, &[hq_pubkey()])],
    )
    .await
    .expect_err("minor kind-14 rumor must be refused even to an official");
    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_sign_gift_wrap_with_decoy_official_p_tag_refused() {
    // The bypass the adversarial review found: a kind-1059 whose content is
    // ciphertext readable by a colluding non-approved party, hidden behind a
    // decoy approved `p` tag. Refusing 1059 outright closes it.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(1059, &minor.keys, &[hq_pubkey()])],
    )
    .await
    .expect_err("minor gift wrap with a decoy official p-tag must be refused");
    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_sign_nip04_kind_4_gated_by_p_tag() {
    // NIP-04 kind-4 DM is a real send path (video share, dm NIP-04 helper): the
    // recipient IS the p tag, so it stays p-tag-gated — allowed to an official,
    // refused to an arbitrary recipient.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let signed = invoke_rpc(
        tenant_id,
        auth_state.clone(),
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(4, &minor.keys, &[hq_pubkey()])],
    )
    .await
    .expect("minor kind-4 DM to an official must sign");
    assert!(signed.result.is_some());

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(4, &minor.keys, &[mallory.public_key()])],
    )
    .await
    .expect_err("minor kind-4 DM to an arbitrary recipient must be refused");
    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_sign_public_note_unaffected() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    // Kind 1 with a mention p-tag: public posting is not DM-shaped.
    let response = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(1, &minor.keys, &[mallory.public_key()])],
    )
    .await
    .expect("minor public note must sign normally");
    assert!(response.result.is_some());
}

#[tokio::test]
#[serial]
async fn minor_rpc_sign_gift_wrap_to_arbitrary_recipient_refused() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(1059, &minor.keys, &[mallory.public_key()])],
    )
    .await
    .expect_err("minor gift wrap to arbitrary recipient must be refused");
    assert_rpc_denied(err);
}

// ============================================================================
// HTTP RPC (/api/nostr) — encrypt primitives
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_rpc_nip44_encrypt_to_arbitrary_recipient_refused() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip44_encrypt",
        vec![json!(mallory.public_key().to_hex()), json!("hello")],
    )
    .await
    .expect_err("minor nip44_encrypt to arbitrary recipient must be refused");
    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_nip44_encrypt_to_official_and_self_allowed() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );

    let to_official = invoke_rpc(
        tenant_id,
        auth_state.clone(),
        &minor.token,
        "nip44_encrypt",
        vec![json!(hq_pubkey().to_hex()), json!("hello hq")],
    )
    .await
    .expect("minor nip44_encrypt to pinned official must succeed");
    assert!(to_official.result.is_some());

    let to_self = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip44_encrypt",
        vec![json!(minor.pubkey), json!("note to self")],
    )
    .await
    .expect("minor nip44_encrypt to self must succeed");
    assert!(to_self.result.is_some());
}

// ============================================================================
// HTTP RPC (/api/nostr) — nip17_wrap_batch
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_rpc_nip17_wrap_batch_to_official_and_self_allowed() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let rumor = unsigned_dm_json(14, &minor.keys, &[hq_pubkey()]);

    let response = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip17_wrap_batch",
        vec![
            rumor,
            json!([hq_pubkey().to_hex(), minor.keys.public_key().to_hex()]),
        ],
    )
    .await
    .expect("minor may wrap the same approved rumor to official and self");

    let slots = response
        .result
        .as_ref()
        .and_then(Value::as_array)
        .expect("ordered result slots");
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0]["gift_wrap"]["kind"].as_u64(), Some(1059));

    let self_wrap: Event = serde_json::from_value(slots[1]["gift_wrap"].clone())
        .expect("self slot contains gift wrap");
    let unwrapped = UnwrappedGift::from_gift_wrap(&minor.keys, &self_wrap)
        .await
        .expect("minor can unwrap own history copy");
    assert_eq!(unwrapped.sender, minor.keys.public_key());
    assert_eq!(unwrapped.rumor.content, "gate test message");
}

#[tokio::test]
#[serial]
async fn minor_rpc_nip17_wrap_batch_to_arbitrary_slot_refused() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();
    let rumor = unsigned_dm_json(14, &minor.keys, &[hq_pubkey()]);

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip17_wrap_batch",
        vec![rumor, json!([mallory.public_key().to_hex()])],
    )
    .await
    .expect_err("minor may not add an arbitrary encryption recipient slot");

    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_nip17_wrap_batch_embedded_arbitrary_recipient_refused() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();
    let rumor = unsigned_dm_json(14, &minor.keys, &[hq_pubkey(), mallory.public_key()]);

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip17_wrap_batch",
        vec![rumor, json!([minor.keys.public_key().to_hex()])],
    )
    .await
    .expect_err("approved self slot cannot smuggle an arbitrary rumor p-tag");

    assert_rpc_denied(err);
}

#[tokio::test]
#[serial]
async fn minor_rpc_nip04_encrypt_to_arbitrary_recipient_refused() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip04_encrypt",
        vec![json!(mallory.public_key().to_hex()), json!("hello")],
    )
    .await
    .expect_err("minor nip04_encrypt to arbitrary recipient must be refused");
    assert_rpc_denied(err);
}

// ============================================================================
// HTTP RPC (/api/nostr) — kind-13 seal
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_rpc_seal_flow_to_official_allowed_end_to_end() {
    // The real custodial client flow: nip44_encrypt the rumor to the official
    // via RPC, then sign the kind-13 seal via RPC. Both legs must pass.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );

    let rumor = json!({
        "id": "0000000000000000000000000000000000000000000000000000000000000000",
        "pubkey": minor.pubkey,
        "created_at": 1_700_000_000,
        "kind": 14,
        "tags": [["p", hq_pubkey().to_hex()]],
        "content": "hello hq, sealed",
    })
    .to_string();

    let encrypted = invoke_rpc(
        tenant_id,
        auth_state.clone(),
        &minor.token,
        "nip44_encrypt",
        vec![json!(hq_pubkey().to_hex()), json!(rumor)],
    )
    .await
    .expect("sealing rumor to official must encrypt");
    let ciphertext = encrypted
        .result
        .expect("ciphertext present")
        .as_str()
        .expect("ciphertext is string")
        .to_string();

    let seal = EventBuilder::new(Kind::from(13u16), ciphertext).build(minor.keys.public_key());
    let response = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![serde_json::to_value(&seal).expect("serialize seal")],
    )
    .await
    .expect("seal to pinned official must sign");
    assert!(response.result.is_some());
}

#[tokio::test]
#[serial]
async fn minor_rpc_seal_to_arbitrary_recipient_refused() {
    // Seal ciphertext produced OUTSIDE the gated encrypt primitive, under the
    // user<->mallory conversation key (derivable by mallory alone). Keycast
    // must refuse to sign it: it does not decrypt under any approved key.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let rumor = json!({
        "id": "0000000000000000000000000000000000000000000000000000000000000000",
        "pubkey": minor.pubkey,
        "created_at": 1_700_000_000,
        "kind": 14,
        "tags": [["p", mallory.public_key().to_hex()]],
        "content": "smuggled",
    })
    .to_string();
    let ciphertext = nip44::encrypt(
        mallory.secret_key(),
        &minor.keys.public_key(),
        &rumor,
        nip44::Version::V2,
    )
    .expect("mallory-side encryption");

    let seal = EventBuilder::new(Kind::from(13u16), ciphertext).build(minor.keys.public_key());
    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![serde_json::to_value(&seal).expect("serialize seal")],
    )
    .await
    .expect_err("seal to arbitrary recipient must be refused");
    assert_rpc_denied(err);
}

// ============================================================================
// HTTP RPC (/api/nostr) — ingress (decrypt) stays open, non-minors unaffected
// ============================================================================

#[tokio::test]
#[serial]
async fn minor_rpc_decrypt_from_arbitrary_sender_still_allowed() {
    // #183 scopes containment to egress; decrypt (ingress) is out of scope.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();
    let ciphertext = nip44::encrypt(
        mallory.secret_key(),
        &minor.keys.public_key(),
        "inbound message",
        nip44::Version::V2,
    )
    .expect("mallory encrypts to minor");

    let response = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "nip44_decrypt",
        vec![json!(mallory.public_key().to_hex()), json!(ciphertext)],
    )
    .await
    .expect("minor decrypt of inbound message stays allowed (egress-only gate)");
    assert_eq!(
        response.result.expect("plaintext present").as_str(),
        Some("inbound message")
    );
}

#[tokio::test]
#[serial]
async fn non_minor_rpc_dm_signing_and_encryption_unaffected() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let adult = setup_account(&pool, tenant_id, &key_manager, false).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let signed = invoke_rpc(
        tenant_id,
        auth_state.clone(),
        &adult.token,
        "sign_event",
        vec![unsigned_dm_json(14, &adult.keys, &[mallory.public_key()])],
    )
    .await
    .expect("non-minor DM rumor to anyone must sign");
    assert!(signed.result.is_some());

    let encrypted = invoke_rpc(
        tenant_id,
        auth_state,
        &adult.token,
        "nip44_encrypt",
        vec![json!(mallory.public_key().to_hex()), json!("hello")],
    )
    .await
    .expect("non-minor nip44_encrypt to anyone must succeed");
    assert!(encrypted.result.is_some());
}

#[tokio::test]
#[serial]
async fn rpc_sign_refused_when_user_row_missing_fail_closed() {
    // Handler cached, then the user row disappears: minor status (and account
    // status) are unresolvable, so signing must refuse rather than pass.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );

    // Warm the handler cache with an allowed call.
    invoke_rpc(
        tenant_id,
        auth_state.clone(),
        &minor.token,
        "get_public_key",
        vec![],
    )
    .await
    .expect("get_public_key warms the handler cache");

    sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = $2")
        .bind(&minor.pubkey)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("delete user row");

    let err = invoke_rpc(
        tenant_id,
        auth_state,
        &minor.token,
        "sign_event",
        vec![unsigned_dm_json(14, &minor.keys, &[hq_pubkey()])],
    )
    .await
    .expect_err("unresolvable account must refuse signing");
    assert!(
        matches!(err, RpcError::Auth(_)),
        "expected auth refusal, got: {err:?}"
    );
}

// ============================================================================
// /api/user/sign (slow path — signer_handlers: None)
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
async fn minor_user_sign_endpoint_refuses_dm_to_arbitrary_recipient() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let err = invoke_user_sign(
        tenant_id,
        auth_state,
        &minor.token,
        unsigned_dm_json(14, &minor.keys, &[mallory.public_key()]),
    )
    .await
    .expect_err("minor DM via /user/sign must be refused");
    match err {
        AuthError::Forbidden(msg) => assert_eq!(msg, DENIED_MSG),
        other => panic!("expected Forbidden({DENIED_MSG}), got: {other:?}"),
    }
}

#[tokio::test]
#[serial]
async fn minor_user_sign_endpoint_allows_nip04_dm_to_pinned_official() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );

    let signed = invoke_user_sign(
        tenant_id,
        auth_state,
        &minor.token,
        unsigned_dm_json(4, &minor.keys, &[hq_pubkey()]),
    )
    .await
    .expect("minor NIP-04 DM to pinned official via /user/sign must sign");
    let signed: Event = serde_json::from_value(signed).expect("valid event");
    signed.verify().expect("valid signature");
}

#[tokio::test]
#[serial]
async fn non_minor_user_sign_endpoint_dm_unaffected() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let adult = setup_account(&pool, tenant_id, &key_manager, false).await;
    let auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    let mallory = Keys::generate();

    let signed = invoke_user_sign(
        tenant_id,
        auth_state,
        &adult.token,
        unsigned_dm_json(14, &adult.keys, &[mallory.public_key()]),
    )
    .await
    .expect("non-minor DM via /user/sign must sign");
    assert!(signed.is_object());
}

// ============================================================================
// /api/user/sign fast path (signer_handlers: Some) — denial must be a clean 403
// ============================================================================

/// A cached signing handler that records whether it was invoked. If the fast
/// path's minor gate fires correctly, `sign_event_direct` is never reached.
struct RecordingSignerHandler {
    keys: Keys,
    signed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl SigningHandler for RecordingSignerHandler {
    async fn sign_event_direct(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<Event, Box<dyn std::error::Error + Send + Sync>> {
        self.signed.store(true, Ordering::SeqCst);
        unsigned_event
            .sign(&self.keys)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
    fn authorization_id(&self) -> i64 {
        1
    }
    fn user_pubkey(&self) -> String {
        self.keys.public_key().to_hex()
    }
    fn get_keys(&self) -> Keys {
        self.keys.clone()
    }
}

#[tokio::test]
#[serial]
async fn minor_user_sign_fast_path_denial_is_forbidden_not_503() {
    // I1: on the hot fast path (cached signer handler present), a minor-gate
    // denial must return a clean 403 Forbidden with the uniform message, not
    // the 503 the handler's error mapping would produce — and must refuse
    // BEFORE the handler signs anything.
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let minor = setup_account(&pool, tenant_id, &key_manager, true).await;

    // Install a cached handler keyed by this account's bunker pubkey so the
    // fast path is taken.
    let signed_flag = Arc::new(AtomicBool::new(false));
    let handlers: SignerHandlersCache = Cache::builder().max_capacity(10).build();
    handlers
        .insert(
            minor.bunker_pubkey.clone(),
            Arc::new(RecordingSignerHandler {
                keys: minor.keys.clone(),
                signed: signed_flag.clone(),
            }),
        )
        .await;

    let mut auth_state = create_test_auth_state(
        pool.clone(),
        Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
    );
    // Rebuild state with signer_handlers present (fast path enabled).
    auth_state.state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager: auth_state.state.key_manager.clone(),
        signer_handlers: Some(handlers),
        http_handler_cache: new_http_handler_cache(),
        server_keys: Keys::generate(),
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt_sender: BcryptQueue::new().sender(),
        redis: None,
        secret_pool: SecretPool::new(1).receiver(),
        activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
    });
    let mallory = Keys::generate();

    let err = invoke_user_sign(
        tenant_id,
        auth_state,
        &minor.token,
        unsigned_dm_json(4, &minor.keys, &[mallory.public_key()]),
    )
    .await
    .expect_err("fast-path minor DM to arbitrary recipient must be refused");

    match err {
        AuthError::Forbidden(msg) => assert_eq!(msg, DENIED_MSG),
        other => panic!("expected Forbidden({DENIED_MSG}) on the fast path, got: {other:?}"),
    }
    assert!(
        !signed_flag.load(Ordering::SeqCst),
        "fast-path gate must refuse BEFORE the handler signs"
    );
}
