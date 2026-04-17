#![cfg(feature = "integration-tests")]

use bcrypt::hash;
use chrono::Utc;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::admin::{get_auth_debug, AuthDebugQuery},
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::{AuthEventRecord, AuthEventRepository},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

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
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn cleanup_by_email(pool: &PgPool, email: &str) {
    let _ = sqlx::query("DELETE FROM auth_events WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn test_auth_debug_returns_account_state_and_recent_events_for_email() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone());
    let email = format!("auth-debug-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    let request_id = format!("req-{}", Uuid::new_v4());
    let password_hash = hash("secret-password", 4).unwrap();

    cleanup_by_email(&pool, &email).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, false, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("Should create test user");

    let auth_event_repo = AuthEventRepository::new(pool.clone());
    auth_event_repo
        .record(AuthEventRecord {
            tenant_id: 1,
            request_id,
            endpoint: "/api/headless/login".to_string(),
            event_type: "login".to_string(),
            outcome: "failure".to_string(),
            reason_code: Some("email_not_verified".to_string()),
            http_status: Some(403),
            email: Some(email.clone()),
            email_hash: keycast_api::api::http::auth_observability::hash_email(Some(&email)),
            pubkey: Some(pubkey.clone()),
            pubkey_prefix: Some(pubkey.chars().take(12).collect()),
            client_id: Some("DivineMobileTest".to_string()),
            redirect_origin: Some("https://app.divine.video".to_string()),
            user_agent: Some("integration-test".to_string()),
            metadata_json: serde_json::json!({}),
        })
        .await
        .expect("Should create auth event");

    let response = get_auth_debug(
        create_test_tenant(),
        axum::extract::State(auth_state),
        UcanAuth {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("support".to_string()),
        },
        axum::extract::Query(AuthDebugQuery {
            email: Some(email.clone()),
            pubkey: None,
            npub: None,
            request_id: None,
        }),
    )
    .await
    .expect("auth debug should succeed")
    .0;

    assert_eq!(response.diagnosis, "email_not_verified");
    assert_eq!(
        response
            .account
            .as_ref()
            .and_then(|account| account.email.as_deref()),
        Some(email.as_str())
    );
    assert_eq!(
        response
            .account
            .as_ref()
            .map(|account| account.email_verified),
        Some(Some(false))
    );
    assert_eq!(
        response
            .account
            .as_ref()
            .map(|account| account.password_hash_present),
        Some(true)
    );
    assert_eq!(response.events.len(), 1);
    assert_eq!(
        response.events[0].reason_code.as_deref(),
        Some("email_not_verified")
    );

    cleanup_by_email(&pool, &email).await;
}
