// ABOUTME: A slow name-server response must not let a stale local username stay authoritative (#49)
// ABOUTME: Own binary so it can enable the name server via env vars without racing other tests

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
            admin::{get_user_lookup, UserLookupQuery},
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
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

// A nostr.json handler that responds only after well over the 250ms promotion budget, so the
// support lookup times out waiting for it. It "resolves" the handle to a disagreeing owner.
async fn slow_nostr_json(Query(params): Query<HashMap<String, String>>) -> Json<serde_json::Value> {
    tokio::time::sleep(Duration::from_millis(600)).await;
    let name = params.get("name").cloned().unwrap_or_default();
    let disagreeing_owner = "1".repeat(64);
    Json(json!({ "names": { name: disagreeing_owner } }))
}

async fn start_slow_name_server() -> String {
    let app = Router::new().route("/.well-known/nostr.json", get(slow_nostr_json));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{}", address)
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
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
    let bcrypt_queue = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
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
            bcrypt: bcrypt_queue.clone(),
            redis: None,
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

async fn cleanup_user(pool: &PgPool, pubkey: &str) {
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn slow_name_server_demotes_a_stale_local_username() {
    let base_url = start_slow_name_server().await;
    let _server = EnvGuard::set("DIVINE_NAME_SERVER_URL", &base_url);
    let _enable = EnvGuard::set("ENABLE_DIVINE_NAMES", "1");

    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    let handle = format!("mjb{}", Uuid::new_v4().simple());

    // A local account whose username exactly matches the handle — an authoritative local match.
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at) \
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&handle)
    .execute(&pool)
    .await
    .unwrap();

    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery { q: handle.clone() }),
    )
    .await
    .expect("full admin lookup should succeed")
    .0;

    // The name server was too slow to confirm the handle, so the stale local row stays visible but
    // must NOT be presented as the authoritative identity match.
    let row = resp
        .results
        .iter()
        .find(|u| u.pubkey == pubkey)
        .expect("stale local row should still be visible as a candidate");
    assert!(
        !row.authoritative,
        "a slow name server must not leave a stale local username authoritative"
    );
    assert!(!resp.authoritative_match);

    cleanup_user(&pool, &pubkey).await;
}
