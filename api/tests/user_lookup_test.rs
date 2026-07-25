// ABOUTME: HTTP-handler tests for the support-admin user-lookup endpoint (get_user_lookup)
// ABOUTME: Locks the response contract for minor/age-review terminal status + the auth gate (#309)

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
    repositories::AdminUserMatchKind,
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

// -----------------------------------------------------------------------------
// Fixtures (mirror registered_clients_admin_http_test: inject tenant + UcanAuth
// directly instead of resolving them from request headers + global state).
// -----------------------------------------------------------------------------

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

    fn support_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("support".to_string()),
        }
    }

    fn non_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: None,
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

async fn cleanup_user(pool: &PgPool, pubkey: &str) {
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .unwrap();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn lookup_surfaces_verified_minor() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    let username = format!("minoruser{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, $3, TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&username)
    .execute(&pool)
    .await
    .unwrap();

    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery {
            q: username.clone(),
        }),
    )
    .await
    .expect("full admin lookup should succeed")
    .0;

    assert_eq!(
        resp.results.len(),
        1,
        "should find the seeded minor account"
    );
    let user = &resp.results[0];
    assert_eq!(user.pubkey, pubkey);
    assert!(
        user.verified_minor,
        "verified_minor must be surfaced in the lookup response (#309)"
    );
    assert!(user.verified_minor_at.is_some());
    assert_eq!(user.status, "active");

    cleanup_user(&pool, &pubkey).await;
}

#[tokio::test]
async fn lookup_surfaces_suspended_status_and_reason() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    let username = format!("suspended{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, status, suspended_reason, suspended_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'suspended', 'age_review', NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&username)
    .execute(&pool)
    .await
    .unwrap();

    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery {
            q: username.clone(),
        }),
    )
    .await
    .expect("full admin lookup should succeed")
    .0;

    assert_eq!(resp.results.len(), 1);
    let user = &resp.results[0];
    assert_eq!(user.status, "suspended");
    assert_eq!(user.suspended_reason.as_deref(), Some("age_review"));
    assert!(!user.verified_minor);

    cleanup_user(&pool, &pubkey).await;
}

#[tokio::test]
async fn lookup_suggestions_carry_verified_minor() {
    // verified_minor must ride the shared enrich helper onto the "did you mean" suggestion
    // path too, not only exact results. Relies on pg_trgm (created by the email-trgm migration).
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    let unique = Uuid::new_v4().simple().to_string();
    let email = format!("verifiedminor-{}@example.com", unique);
    // A one-char typo (.com -> .con): no exact/substring match, but trigram-close, so the
    // account can only come back through the suggestion path.
    let typo = format!("verifiedminor-{}@example.con", unique);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, $3, TRUE, TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery { q: typo }),
    )
    .await
    .expect("full admin lookup should succeed")
    .0;

    assert!(
        resp.results.iter().all(|u| u.pubkey != pubkey),
        "the typo email should not be an exact/substring result"
    );
    let suggestion = resp
        .suggestions
        .iter()
        .find(|u| u.pubkey == pubkey)
        .expect("verified-minor account should surface as a did-you-mean suggestion");
    assert!(
        suggestion.verified_minor,
        "verified_minor must be carried on the suggestion path, not only exact results"
    );

    cleanup_user(&pool, &pubkey).await;
}

#[tokio::test]
async fn lookup_returns_literal_and_fuzzy_email_matches_together() {
    let pool = common::setup_test_db().await;
    let suffix = Uuid::new_v4().simple().to_string()[..8].to_string();
    let query = format!("publish{suffix}");
    let partial_pubkey = Keys::generate().public_key().to_hex();
    let fuzzy_pubkey = Keys::generate().public_key().to_hex();

    sqlx::query(
        "INSERT INTO users
            (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, TRUE, NOW(), NOW())",
    )
    .bind(&partial_pubkey)
    .bind(TENANT_ID)
    .bind(format!("social{query}llc@gmail.com"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO users
            (pubkey, tenant_id, email, email_verified, status, suspended_reason,
             suspended_at, verified_minor, verified_minor_at, created_at, updated_at)
         VALUES ($1, $2, $3, TRUE, 'suspended', 'age_review', NOW(), TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&fuzzy_pubkey)
    .bind(TENANT_ID)
    .bind(format!("socialpulish{suffix}llc@gmail.com"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO oauth_authorizations
            (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays,
             tenant_id, handle_expires_at, last_activity, activity_count, created_at, updated_at)
         VALUES ($1, 'https://lookup.test', 'Lookup test', $2, 'hash', '[]',
                 $3, NOW() + INTERVAL '30 days', NOW(), 2, NOW(), NOW())",
    )
    .bind(&fuzzy_pubkey)
    .bind(Keys::generate().public_key().to_hex())
    .bind(TENANT_ID)
    .execute(&pool)
    .await
    .unwrap();

    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::full_admin().into_auth(),
        Query(UserLookupQuery { q: query }),
    )
    .await
    .expect("full admin lookup should return mixed match tiers")
    .0;

    let partial = resp
        .results
        .iter()
        .find(|user| user.pubkey == partial_pubkey)
        .expect("literal email fragment should remain a primary result");
    assert_eq!(partial.match_kind, AdminUserMatchKind::Partial);
    assert!(!partial.authoritative);

    let fuzzy = resp
        .suggestions
        .iter()
        .find(|user| user.pubkey == fuzzy_pubkey)
        .expect("typo-near email fragment should accompany the literal result");
    assert_eq!(fuzzy.match_kind, AdminUserMatchKind::Fuzzy);
    assert!(!fuzzy.authoritative);
    assert!(fuzzy.verified_minor);
    assert_eq!(fuzzy.status, "suspended");
    assert_eq!(fuzzy.suspended_reason.as_deref(), Some("age_review"));
    assert_eq!(fuzzy.active_sessions, 1);
    assert!(fuzzy.last_active.is_some());

    assert!(!resp.authoritative_match);
    assert_eq!(resp.authoritative_count, 0);
    assert_eq!(resp.total, resp.results.len());
    assert!(!resp.suggestions.iter().any(|user| resp
        .results
        .iter()
        .any(|result| result.pubkey == user.pubkey)));

    cleanup_user(&pool, &partial_pubkey).await;
    cleanup_user(&pool, &fuzzy_pubkey).await;
}

#[tokio::test]
async fn lookup_keeps_identity_matches_authoritative_and_first() {
    let pool = common::setup_test_db().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let npub = keys.public_key().to_bech32().unwrap();
    let email = format!("authoritative-{suffix}@lookup.test");
    let username = format!("authoritative{suffix}");
    let vine_id = format!("vine-{suffix}");

    sqlx::query(
        "INSERT INTO users
            (pubkey, tenant_id, email, email_verified, username, vine_id, created_at, updated_at)
         VALUES ($1, $2, $3, TRUE, $4, $5, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(&email)
    .bind(&username)
    .bind(&vine_id)
    .execute(&pool)
    .await
    .unwrap();

    for query in [&email, &username, &vine_id, &pubkey, &npub] {
        let resp = get_user_lookup(
            create_test_tenant(),
            State(create_test_auth_state(pool.clone())),
            AuthConfig::full_admin().into_auth(),
            Query(UserLookupQuery {
                q: query.to_string(),
            }),
        )
        .await
        .expect("identity lookup should remain authoritative")
        .0;

        assert_eq!(resp.results[0].pubkey, pubkey);
        assert!(resp.results[0].authoritative);
        assert_eq!(
            resp.results[0].match_kind,
            AdminUserMatchKind::Authoritative
        );
        assert!(resp.authoritative_match);
        assert_eq!(resp.authoritative_count, 1);
        assert_eq!(resp.total, 1);
        assert!(resp.suggestions.is_empty());
    }

    cleanup_user(&pool, &pubkey).await;
}

#[tokio::test]
async fn support_admin_lookup_remains_tenant_scoped() {
    let pool = common::setup_test_db().await;
    let suffix = Uuid::new_v4().simple().to_string()[..8].to_string();
    let query = format!("tenantlookup{suffix}");
    let local_pubkey = Keys::generate().public_key().to_hex();
    let foreign_pubkey = Keys::generate().public_key().to_hex();
    let foreign_tenant_id: i64 = sqlx::query_scalar(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("admin-lookup-{suffix}.test"))
    .bind(format!("Admin lookup {suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO users
            (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, TRUE, NOW(), NOW()),
                ($4, $5, $6, TRUE, NOW(), NOW())",
    )
    .bind(&local_pubkey)
    .bind(TENANT_ID)
    .bind(format!("local-{query}@lookup.test"))
    .bind(&foreign_pubkey)
    .bind(foreign_tenant_id)
    .bind(format!("foreign-{query}@lookup.test"))
    .execute(&pool)
    .await
    .unwrap();

    let resp = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::support_admin().into_auth(),
        Query(UserLookupQuery { q: query }),
    )
    .await
    .expect("support admin lookup should succeed")
    .0;

    assert!(resp.results.iter().any(|user| user.pubkey == local_pubkey));
    assert!(!resp
        .results
        .iter()
        .chain(&resp.suggestions)
        .any(|user| user.pubkey == foreign_pubkey));

    cleanup_user(&pool, &local_pubkey).await;
    cleanup_user(&pool, &foreign_pubkey).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(foreign_tenant_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn lookup_rejects_non_admin() {
    let pool = common::setup_test_db().await;

    let result = get_user_lookup(
        create_test_tenant(),
        State(create_test_auth_state(pool.clone())),
        AuthConfig::non_admin().into_auth(),
        Query(UserLookupQuery {
            q: "anyone".to_string(),
        }),
    )
    .await;

    assert!(result.is_err(), "non-admin must be denied the user lookup");
}
