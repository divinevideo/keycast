// ABOUTME: `<local>@<domain>` reads as both a mailbox and a NIP-05 handle; when those belong to
// ABOUTME: different accounts, both must survive the live name-server promotion path (#49)

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::{
            admin::{get_user_lookup, UserLookupQuery, UserLookupResponse},
            routes::AuthState,
        },
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
use once_cell::sync::Lazy;
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::OnceCell;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

/// How the mock name server should answer a given handle: which pubkey it resolves to, and how
/// long it takes. Registered per test so one shared server can serve every case in this binary
/// without tests racing over `DIVINE_NAME_SERVER_URL`.
static REGISTRY: Lazy<Mutex<HashMap<String, (String, u64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static NAME_SERVER: OnceCell<()> = OnceCell::const_new();

async fn nostr_json(Query(params): Query<HashMap<String, String>>) -> Json<serde_json::Value> {
    let name = params.get("name").cloned().unwrap_or_default();
    // Copy out before any await so the lock is never held across a suspension point.
    let registered = REGISTRY
        .lock()
        .expect("registry lock")
        .get(&name)
        .map(|(pubkey, delay_ms)| (pubkey.clone(), *delay_ms));

    match registered {
        Some((pubkey, delay_ms)) => {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Json(json!({ "names": { name: pubkey } }))
        }
        None => Json(json!({ "names": {} })),
    }
}

/// Start the mock name server once per binary and point the resolver at it.
async fn ensure_name_server() {
    NAME_SERVER
        .get_or_init(|| async {
            let app = Router::new().route("/.well-known/nostr.json", get(nostr_json));
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            std::env::set_var("DIVINE_NAME_SERVER_URL", format!("http://{address}"));
            std::env::set_var("ENABLE_DIVINE_NAMES", "1");

            // The first `reqwest::Client` built in a process pays a one-time global init
            // (measured at ~335ms locally; a second client builds in ~0.1ms). That is longer
            // than `ADMIN_NAME_PROMOTION_TIMEOUT`, so without warming it here the first
            // confirmation in this binary would time out and the test would assert on cold-start
            // latency instead of on merge behavior. This is a real production characteristic of
            // `divine_names`, which builds a client per call: the first handle lookup on a fresh
            // instance can exceed the promotion budget and demote a legitimate match. It predates
            // this PR (the budget and the per-call clients are both on `main`) and is being
            // tracked in #324 rather than widened into this change.
            let _ = reqwest::Client::builder().build();
        })
        .await;
}

fn register_name(handle: &str, pubkey: &str, delay_ms: u64) {
    REGISTRY
        .lock()
        .expect("registry lock")
        .insert(handle.to_string(), (pubkey.to_string(), delay_ms));
}

#[derive(Clone)]
struct AuthConfig {
    pubkey: String,
    admin_role: Option<String>,
}

impl AuthConfig {
    fn full_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("full".to_string()),
        }
    }

    fn into_auth(self) -> UcanAuth {
        UcanAuth {
            pubkey: self.pubkey,
            admin_role: self.admin_role,
        }
    }
}

// Production-shaped: the login host is `login.divine.video`, public handles live at `divine.video`.
fn create_test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "login.divine.video".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
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

async fn lookup(pool: &PgPool, q: &str) -> UserLookupResponse {
    get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery { q: q.to_string() }),
    )
    .await
    .expect("full admin lookup should succeed")
    .0
}

fn authoritative_pubkeys(resp: &UserLookupResponse) -> Vec<String> {
    resp.results
        .iter()
        .filter(|u| u.authoritative)
        .map(|u| u.pubkey.clone())
        .collect()
}

async fn insert_user(pool: &PgPool, pubkey: &str, username: &str, email: Option<&str>) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, email, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .bind(username)
    .bind(email)
    .execute(pool)
    .await
    .unwrap();
}

async fn cleanup_user(pool: &PgPool, pubkey: &str) {
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .unwrap();
}

/// Seed a handle owner and a different mailbox owner, and register the handle with the mock name
/// server. Returns `(handle, mailbox, handle_owner, mailbox_owner)`.
async fn seed_collision(pool: &PgPool, delay_ms: u64) -> (String, String, String, String) {
    // Simple (hyphen-free) suffix keeps the handle unambiguous under the query's normalization.
    let handle = format!("lele{}", Uuid::new_v4().simple());
    let mailbox = format!("{handle}@divine.video");

    let handle_owner = Keys::generate().public_key().to_hex();
    insert_user(pool, &handle_owner, &handle, None).await;

    // A different account owns the mailbox; nothing but its exact address ties it to the query.
    let mailbox_owner = Keys::generate().public_key().to_hex();
    let unrelated_username = format!("mailbox{}", Uuid::new_v4().simple());
    insert_user(pool, &mailbox_owner, &unrelated_username, Some(&mailbox)).await;

    register_name(&handle, &handle_owner, delay_ms);

    (handle, mailbox, handle_owner, mailbox_owner)
}

/// With the name server live and confirming the handle, the mailbox owner must still be confirmed
/// for its own address. This is the production shape of the collision: the earlier tests run with
/// the name server disabled, so they never exercise `apply_name_promotion` demoting local rows
/// before the email reading is merged back in.
#[tokio::test]
async fn confirmed_handle_and_mailbox_owner_are_both_reported() {
    ensure_name_server().await;
    let pool = common::setup_test_db().await;
    let (_handle, mailbox, handle_owner, mailbox_owner) = seed_collision(&pool, 0).await;

    let resp = lookup(&pool, &mailbox).await;
    let confirmed = authoritative_pubkeys(&resp);

    assert!(
        confirmed.contains(&mailbox_owner),
        "name-server confirmation of the handle must not strip the mailbox owner's authority; \
         confirmed: {confirmed:?}"
    );
    assert!(
        confirmed.contains(&handle_owner),
        "the name server confirmed the handle, so its owner must stay confirmed; \
         confirmed: {confirmed:?}"
    );
    assert_eq!(
        resp.authoritative_count, 2,
        "two confirmed identities must suppress auto-expansion"
    );

    cleanup_user(&pool, &handle_owner).await;
    cleanup_user(&pool, &mailbox_owner).await;
}

/// A name-server timeout demotes the *handle* reading only. The mailbox reading is a local exact
/// match on an address the name server has no say over, so it stays confirmed and remains
/// auto-expandable. This deliberately narrows the invariant from #313's first review round
/// ("a timeout must not leave an authoritative match") to the reading the name server owns.
#[tokio::test]
async fn name_server_timeout_demotes_the_handle_but_not_the_mailbox_owner() {
    ensure_name_server().await;
    let pool = common::setup_test_db().await;
    // Well over the 250ms promotion budget, so the handle reading cannot be confirmed.
    let (_handle, mailbox, handle_owner, mailbox_owner) = seed_collision(&pool, 600).await;

    let resp = lookup(&pool, &mailbox).await;

    assert_eq!(
        authoritative_pubkeys(&resp),
        vec![mailbox_owner.clone()],
        "only the mailbox owner is confirmed by a local fact the name server does not own"
    );
    assert_eq!(resp.authoritative_count, 1);

    let handle_row = resp
        .results
        .iter()
        .find(|u| u.pubkey == handle_owner)
        .expect("the unconfirmed handle owner should still be visible as a candidate");
    assert!(
        !handle_row.authoritative,
        "a slow name server must not leave the handle owner confirmed"
    );

    cleanup_user(&pool, &handle_owner).await;
    cleanup_user(&pool, &mailbox_owner).await;
}
