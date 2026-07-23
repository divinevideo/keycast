// ABOUTME: Integration coverage that the support lookup resolves the several Divine-handle forms
// ABOUTME: (@mjb, mjb.<domain>, mjb@<domain>) through get_user_lookup's canonicalization (#49)

#![cfg(feature = "integration-tests")]

mod common;

use axum::extract::{Query, State};
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
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

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

// The tenant host is "localhost", so resolve_nip05_domain falls back to NIP05_DOMAIN / the default
// "divine.video" — which is the domain the handle forms below are canonicalized against.
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
    let bcrypt_queue = BcryptQueue::new();
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
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
        }),
        auth_tx: None,
    }
}

async fn lookup_pubkeys(pool: &PgPool, q: &str) -> Vec<String> {
    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery { q: q.to_string() }),
    )
    .await
    .expect("full admin lookup should succeed")
    .0;
    resp.results.into_iter().map(|u| u.pubkey).collect()
}

async fn cleanup_user(pool: &PgPool, pubkey: &str) {
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn lookup_resolves_divine_handle_forms_to_the_same_account() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    // Simple (hyphen-free) suffix keeps the handle unambiguous under the query's normalization.
    let handle = format!("mjb{}", Uuid::new_v4().simple());

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

    // Every way support/users write the handle must resolve to the same account. The name server
    // is disabled in the test env, so these exercise the canonicalization -> local-username path.
    for form in [
        handle.clone(),                    // bare
        format!("@{handle}"),              // @handle
        format!("{handle}.divine.video"),  // profile-URL / subdomain
        format!("@{handle}.divine.video"), // @handle.domain
        format!("{handle}@divine.video"),  // NIP-05 email form
    ] {
        let pubkeys = lookup_pubkeys(&pool, &form).await;
        assert!(
            pubkeys.contains(&pubkey),
            "handle form `{form}` should resolve to the seeded account"
        );
    }

    cleanup_user(&pool, &pubkey).await;
}
