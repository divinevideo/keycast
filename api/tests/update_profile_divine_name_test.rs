mod common;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use http_body_util::BodyExt;
use keycast_api::api::http::{auth, routes::AuthState};
use keycast_api::api::tenant::{Tenant, TenantExtractor};
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::UserRepository;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::Keys;
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use ucan::builder::UcanBuilder;
use zeroize::Zeroizing;

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

fn create_test_tenant(tenant_id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: tenant_id,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

async fn build_test_ucan(keys: &Keys, tenant_id: i64) -> String {
    let key_material = NostrKeyMaterial::from_keys(keys.clone());
    let user_did = nostr_pubkey_to_did(&keys.public_key());
    let facts = json!({
        "tenant_id": tenant_id,
        "redirect_origin": "https://example.test"
    });

    UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("failed to build test UCAN")
        .sign()
        .await
        .expect("failed to sign test UCAN")
        .encode()
        .expect("failed to encode test UCAN")
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
        if let Some(ref value) = self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

async fn mock_name_check(Path(username): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "available": false,
        "reason": format!("{username} is reserved"),
    }))
}

async fn start_name_check_server() -> (String, JoinHandle<()>) {
    let app = Router::new().route("/api/username/check/:username", get(mock_name_check));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve divine name check app");
    });

    (format!("http://{}", address), handle)
}

#[tokio::test]
async fn update_profile_claims_name_without_enabling_atproto() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let tenant_id = 1_i64;
    let username = format!("alice-update-profile-{}", &pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    repo.update_username(&pubkey, &username, tenant_id)
        .await
        .unwrap();

    let state = repo
        .get_atproto_state(&pubkey, tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!state.enabled);
    assert_eq!(state.state, None);
}

#[tokio::test]
async fn username_conflict_is_detected_in_local_repository_check() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let first_user = Keys::generate().public_key().to_hex();
    let second_user = Keys::generate().public_key().to_hex();
    let tenant_id = 1_i64;
    let username = format!("nip05-conflict-{}", &first_user[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&first_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert first user");

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&second_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert second user");

    repo.update_username(&first_user, &username, tenant_id)
        .await
        .expect("failed to set first username");

    let available_for_second = repo
        .check_username_available(&username, &second_user, tenant_id)
        .await
        .expect("failed to check username availability");
    assert!(
        !available_for_second,
        "username should be marked unavailable"
    );
}

#[tokio::test]
#[serial]
async fn update_profile_username_conflict_returns_conflict_status() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let first_keys = Keys::generate();
    let second_keys = Keys::generate();
    let first_user = first_keys.public_key().to_hex();
    let second_user = second_keys.public_key().to_hex();
    let tenant_id = 1_i64;
    let username = format!("profile-conflict-{}", &first_user[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&first_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert first user");

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&second_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert second user");

    repo.update_username(&first_user, &username, tenant_id)
        .await
        .expect("failed to set first username");

    let token = build_test_ucan(&second_keys, tenant_id).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("authorization header should parse"),
    );

    let response = auth::update_profile(
        create_test_tenant(tenant_id),
        State(create_test_auth_state(pool)),
        headers,
        Json(auth::ProfileData {
            username: Some(username),
            name: None,
            about: None,
            picture: None,
            banner: None,
            nip05: None,
            website: None,
            lud16: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["error"],
        "Username is not available. Please choose another username."
    );
}

#[tokio::test]
#[serial]
async fn update_profile_divine_name_conflict_returns_conflict_status() {
    let pool = common::setup_test_db().await;

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let tenant_id = 1_i64;
    let username = "reserved-handle".to_string();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let token = build_test_ucan(&user_keys, tenant_id).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("authorization header should parse"),
    );

    let (base_url, server_handle) = start_name_check_server().await;
    let _divine_name_server = EnvGuard::set("DIVINE_NAME_SERVER_URL", &base_url);
    let _enable_divine_names = EnvGuard::set("ENABLE_DIVINE_NAMES", "1");

    let response = auth::update_profile(
        create_test_tenant(tenant_id),
        State(create_test_auth_state(pool)),
        headers,
        Json(auth::ProfileData {
            username: Some(username.clone()),
            name: None,
            about: None,
            picture: None,
            banner: None,
            nip05: None,
            website: None,
            lud16: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["error"],
        "Username is not available. Please choose another username."
    );

    server_handle.abort();
}

#[tokio::test]
async fn mixed_case_username_blocks_lowercase_claim() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let first_user = Keys::generate().public_key().to_hex();
    let second_user = Keys::generate().public_key().to_hex();
    let tenant_id = 1_i64;
    let mixed_case = format!("AliceCi{}", &first_user[..8]);
    let lower_claim = mixed_case.to_lowercase();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&first_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert first user");

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&second_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert second user");

    repo.update_username(&first_user, &mixed_case, tenant_id)
        .await
        .expect("failed to set mixed-case username");

    let available_for_second = repo
        .check_username_available(&lower_claim, &second_user, tenant_id)
        .await
        .expect("failed to check username availability");
    assert!(
        !available_for_second,
        "lowercase claim should conflict with existing mixed-case row"
    );

    let found = repo
        .find_pubkey_by_username(&lower_claim, tenant_id)
        .await
        .expect("lookup failed");
    assert_eq!(found.as_deref(), Some(first_user.as_str()));
}
