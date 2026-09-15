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

// Production-shaped: the login/tenant host is `login.divine.video`, but public handles live at
// `divine.video`. Canonicalization must use the public handle domain, NOT the tenant host, or
// `mjb@divine.video` / `mjb.divine.video` would never reduce to `mjb`. This test fails if the
// lookup canonicalizes against the tenant host.
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

async fn lookup_pubkeys(pool: &PgPool, q: &str) -> Vec<String> {
    lookup(pool, q)
        .await
        .results
        .into_iter()
        .map(|u| u.pubkey)
        .collect()
}

/// Pubkeys the lookup reports as confirmed identities, in rank order.
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

#[tokio::test]
async fn lookup_resolves_divine_handle_forms_to_the_same_account() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    // Simple (hyphen-free) suffix keeps the handle unambiguous under the query's normalization.
    let handle = format!("mjb{}", Uuid::new_v4().simple());

    insert_user(&pool, &pubkey, &handle, None).await;

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

    // An unrelated email at another domain must stay on the email path, not resolve to the handle.
    let unrelated = lookup_pubkeys(&pool, "someone-else@example.com").await;
    assert!(
        !unrelated.contains(&pubkey),
        "an unrelated email must not resolve to the seeded handle account"
    );

    cleanup_user(&pool, &pubkey).await;
}

/// `<local>@divine.video` has two honest readings: a mailbox address, and the NIP-05 form of the
/// handle `<local>`. When those belong to *different* accounts, reducing the query to the handle
/// alone drops the exact-email path, so the handle owner becomes the sole confirmed match and the
/// support UI auto-expands it in place of the person who actually owns the address. Both readings
/// must survive, and two confirmed identities must suppress auto-expansion so support chooses.
#[tokio::test]
async fn qualified_email_keeps_mailbox_owner_confirmed_alongside_handle_owner() {
    let pool = common::setup_test_db().await;
    // Simple (hyphen-free) suffix keeps the handle unambiguous under the query's normalization.
    let handle = format!("lele{}", Uuid::new_v4().simple());
    let mailbox = format!("{handle}@divine.video");

    let handle_owner = Keys::generate().public_key().to_hex();
    insert_user(&pool, &handle_owner, &handle, None).await;

    // A different account owns the mailbox. Its username deliberately does not match the handle,
    // so the only thing tying it to the query is its exact email address.
    let mailbox_owner = Keys::generate().public_key().to_hex();
    let unrelated_username = format!("mailbox{}", Uuid::new_v4().simple());
    insert_user(&pool, &mailbox_owner, &unrelated_username, Some(&mailbox)).await;

    let resp = lookup(&pool, &mailbox).await;
    let confirmed = authoritative_pubkeys(&resp);
    assert!(
        confirmed.contains(&mailbox_owner),
        "the mailbox owner must stay confirmed for its own address; confirmed: {confirmed:?}"
    );
    assert!(
        confirmed.contains(&handle_owner),
        "the handle owner must stay confirmed for the NIP-05 reading; confirmed: {confirmed:?}"
    );
    // `selectAutoExpandedPubkey` (web/src/routes/support-admin/lookup-view.ts) only auto-expands
    // when exactly one row is confirmed, so two confirmed identities is what stops the UI from
    // silently picking the wrong person.
    assert_eq!(
        resp.authoritative_count, 2,
        "an ambiguous address must report both identities, not auto-expand one"
    );
    // The literal reading of what support typed ranks first.
    assert_eq!(confirmed.first(), Some(&mailbox_owner));

    // The pure-handle forms are unchanged: the handle owner is the only confirmed identity and
    // stays auto-expandable, even though the mailbox contains the handle as a substring.
    for form in [
        handle.clone(),
        format!("@{handle}"),
        format!("{handle}.divine.video"),
        format!("@{handle}.divine.video"),
    ] {
        let resp = lookup(&pool, &form).await;
        assert_eq!(
            authoritative_pubkeys(&resp),
            vec![handle_owner.clone()],
            "`{form}` must confirm only the handle owner"
        );
        assert_eq!(
            resp.authoritative_count, 1,
            "`{form}` must stay auto-expandable"
        );
    }

    cleanup_user(&pool, &handle_owner).await;
    cleanup_user(&pool, &mailbox_owner).await;
}

/// The common case for a Divine mailbox: one account owns both the address and the handle. Both
/// readings find the same account, so it must merge to a single confirmed row — searching the
/// address twice must not split one person into two results and suppress auto-expansion.
#[tokio::test]
async fn qualified_email_owned_by_the_handle_owner_stays_a_single_confirmed_row() {
    let pool = common::setup_test_db().await;
    let handle = format!("lele{}", Uuid::new_v4().simple());
    let mailbox = format!("{handle}@divine.video");

    let pubkey = Keys::generate().public_key().to_hex();
    insert_user(&pool, &pubkey, &handle, Some(&mailbox)).await;

    let resp = lookup(&pool, &mailbox).await;

    assert_eq!(authoritative_pubkeys(&resp), vec![pubkey.clone()]);
    assert_eq!(
        resp.authoritative_count, 1,
        "one owner of both readings must stay auto-expandable"
    );
    assert_eq!(
        resp.results.len(),
        1,
        "the two readings must merge, not duplicate the account"
    );

    cleanup_user(&pool, &pubkey).await;
}
