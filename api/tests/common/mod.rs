// ABOUTME: Shared test utilities and safety guards
// ABOUTME: Ensures tests never accidentally connect to production database

use chrono::Utc;
use keycast_api::{
    api::{
        http::routes::AuthState,
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
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

#[allow(dead_code)]
pub type AuthEventRow = (String, String, String, Option<String>, String, Option<i32>);

/// CRITICAL: Validates that DATABASE_URL points to a local/dev database only.
/// This prevents accidental execution of tests against production databases.
///
/// # Panics
/// Panics if DATABASE_URL:
/// - Does not match any known local pattern (localhost, 127.0.0.1, Docker hostnames)
/// - Contains known production identifiers like "keycast-db", "cloud", or GCP IP addresses
pub fn assert_test_database_url() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    // Extract host portion for checking (don't log full URL with credentials)
    let host_info = url
        .split('@')
        .nth(1)
        .unwrap_or(&url)
        .split('/')
        .next()
        .unwrap_or("unknown");

    // Known production indicators - check these FIRST
    let production_indicators = [
        "keycast-db",    // Cloud SQL instance name
        "cloudsql",      // Cloud SQL indicator
        "prod",          // Production indicator
        "130.211.",      // GCP IP range
        "35.192.",       // GCP IP range
        "35.188.",       // GCP IP range
        "35.193.",       // GCP IP range
        "34.66.",        // GCP IP range
        "34.67.",        // GCP IP range
        ".gcp.",         // GCP indicator
        ".cloud.",       // Cloud indicator
        "rds.amazonaws", // AWS RDS
        "azure",         // Azure
    ];

    let url_lower = url.to_lowercase();
    for indicator in production_indicators {
        assert!(
            !url_lower.contains(indicator),
            "\n\n\
            ╔══════════════════════════════════════════════════════════════════╗\n\
            ║  REFUSING TO RUN: DATABASE_URL appears to be a production DB     ║\n\
            ║                                                                  ║\n\
            ║  Detected production indicator: {:<32} ║\n\
            ║                                                                  ║\n\
            ║  Tests must NEVER run against production databases.              ║\n\
            ║  Please use a local database for testing.                        ║\n\
            ╚══════════════════════════════════════════════════════════════════╝\n\n",
            indicator
        );
    }

    // Allowed local patterns:
    // - localhost / 127.0.0.1 (direct local)
    // - Docker Compose hostnames (contain "postgres" but not production indicators)
    // - host.docker.internal (Docker Desktop)
    let is_local = url_lower.contains("localhost")
        || url_lower.contains("127.0.0.1")
        || url_lower.contains("host.docker.internal")
        || (host_info.contains("postgres") && !host_info.contains(".")); // Docker hostname like "keycast-postgres"

    assert!(
        is_local,
        "\n\n\
        ╔══════════════════════════════════════════════════════════════════╗\n\
        ║  REFUSING TO RUN: DATABASE_URL must point to local database      ║\n\
        ║                                                                  ║\n\
        ║  Tests detected a non-local database connection:                 ║\n\
        ║  Host: {:<55} ║\n\
        ║                                                                  ║\n\
        ║  Allowed: localhost, 127.0.0.1, Docker hostnames (e.g. postgres) ║\n\
        ║                                                                  ║\n\
        ║  To fix:                                                         ║\n\
        ║  1. Use local postgres or Docker Compose                         ║\n\
        ║  2. Set DATABASE_URL=postgres://user:pass@localhost/test         ║\n\
        ╚══════════════════════════════════════════════════════════════════╝\n\n",
        host_info
    );
}

/// Connect to test database with safety checks.
/// This is the preferred way to get a database pool in tests.
///
/// # Panics
/// Panics if DATABASE_URL is not a localhost database.
#[allow(dead_code)]
pub async fn setup_test_db() -> PgPool {
    // CRITICAL: Check database URL before connecting
    assert_test_database_url();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

pub struct TestKeyManager;

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

#[allow(dead_code)]
pub async fn setup_oauth_test_db() -> PgPool {
    std::env::set_var("BUNKER_RELAYS", "wss://relay.test.example");
    setup_test_db().await
}

#[allow(dead_code)]
pub fn create_test_auth_state(pool: PgPool) -> (AuthState, JoinHandle<()>) {
    let (state, producer_handle) = create_test_keycast_state(pool, None);
    (
        AuthState {
            state,
            auth_tx: None,
        },
        producer_handle,
    )
}

fn create_test_keycast_state(
    pool: PgPool,
    redis: Option<keycast_api::redis::PrefixedRedis>,
) -> (Arc<KeycastState>, JoinHandle<()>) {
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = SecretPool::new(1);
    let producer_handle = secret_pool.spawn_producer(bcrypt.clone());
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    (
        Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            account_status_cache: keycast_api::state::new_account_status_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt: bcrypt.clone(),
            redis,
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        producer_handle,
    )
}

/// Build the shared test Redis handle on a dedicated runtime.
///
/// The global `KEYCAST_STATE` outlives every `#[tokio::test]` runtime in the
/// same process, and a `ConnectionManager` created on a runtime that has shut
/// down breaks intermittently for later tests. This thread's runtime never
/// shuts down, so the shared connection stays healthy for the whole process.
fn build_shared_store_redis(prefix: String, failing: bool) -> keycast_api::redis::PrefixedRedis {
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".into());
    let (sender, receiver) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build dedicated test Redis runtime");
        let manager = runtime.block_on(async {
            let client = redis::Client::open(redis_url.as_str()).expect("valid test Redis URL");
            redis::aio::ConnectionManager::new(client)
                .await
                .expect("connect to test Redis")
        });
        #[cfg(feature = "integration-tests")]
        let redis = if failing {
            keycast_api::redis::PrefixedRedis::new_failing(manager, Some(prefix))
        } else {
            keycast_api::redis::PrefixedRedis::new(manager, Some(prefix))
        };
        #[cfg(not(feature = "integration-tests"))]
        let redis = {
            let _ = failing;
            keycast_api::redis::PrefixedRedis::new(manager, Some(prefix))
        };
        sender
            .send(redis)
            .expect("deliver shared test Redis handle");
        runtime.block_on(std::future::pending::<()>());
    });

    receiver
        .recv()
        .expect("receive shared test Redis handle from dedicated runtime")
}

/// Install the process-global `KEYCAST_STATE` backed by the dedicated test
/// Redis, so handlers that resolve shared state (for example the ATProto
/// OAuth replay-reservation store) exercise the real shared-store path in
/// tests. Idempotent: the first installation wins for the process.
#[allow(dead_code)]
pub fn install_global_test_state_with_redis(pool: PgPool) {
    use keycast_api::state::KEYCAST_STATE;

    if KEYCAST_STATE.get().is_some() {
        return;
    }

    let prefix = format!("test-atproto-replay:{}", uuid::Uuid::new_v4());
    let redis = build_shared_store_redis(prefix, false);
    let state = create_global_test_keycast_state(pool, redis);
    let _ = KEYCAST_STATE.set(state);
}

/// Install the process-global `KEYCAST_STATE` whose Redis wrapper fails every
/// write, so shared-store outage behavior (fail-closed responses) can be
/// exercised end to end.
#[cfg(feature = "integration-tests")]
#[allow(dead_code)]
pub fn install_global_test_state_with_failing_redis(pool: PgPool) {
    use keycast_api::state::KEYCAST_STATE;

    if KEYCAST_STATE.get().is_some() {
        return;
    }

    let prefix = format!("test-atproto-replay-fail:{}", uuid::Uuid::new_v4());
    let redis = build_shared_store_redis(prefix, true);
    let state = create_global_test_keycast_state(pool, redis);
    let _ = KEYCAST_STATE.set(state);
}

/// Build process-global state without attaching background work to a
/// short-lived `#[tokio::test]` runtime. These replay tests never consume the
/// secret pool; an intentionally closed receiver fails explicitly if a future
/// test starts exercising a handler that does.
fn create_global_test_keycast_state(
    pool: PgPool,
    redis: keycast_api::redis::PrefixedRedis,
) -> Arc<KeycastState> {
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = SecretPool::new(1);
    let secret_pool_receiver = secret_pool.receiver();
    drop(secret_pool);

    Arc::new(KeycastState {
        db: pool,
        key_manager: Arc::new(Box::new(TestKeyManager)),
        signer_handlers: None,
        http_handler_cache: new_http_handler_cache(),
        account_status_cache: keycast_api::state::new_account_status_cache(),
        server_keys: Keys::generate(),
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt,
        redis: Some(redis),
        secret_pool: secret_pool_receiver,
        activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
    })
}

/// Shared ATProto OAuth endpoint environment for integration tests.
///
/// # Panics
/// Panics when the test signing key cannot be parsed.
#[allow(dead_code)]
pub fn configure_atproto_env() -> Keys {
    const TEST_ATPROTO_JWT_KEY_HEX: &str =
        "8f2a55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d078d";
    const TEST_ATPROTO_PDS_DID: &str = "did:web:pds.divine.test";
    const TEST_SERVER_SECRET_HEX: &str =
        "7a1f55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d0123";

    unsafe {
        std::env::set_var("APP_URL", "https://login.divine.video");
        std::env::set_var("ALLOWED_TENANT_DOMAINS", "login.divine.video");
        std::env::remove_var("ENABLE_TENANT_AUTO_PROVISIONING");
        std::env::set_var(
            "ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX",
            TEST_ATPROTO_JWT_KEY_HEX,
        );
        std::env::set_var("ATPROTO_OAUTH_PDS_DID", TEST_ATPROTO_PDS_DID);
        std::env::set_var("BUNKER_RELAYS", "wss://relay.test.example");
        std::env::remove_var("ATPROTO_OAUTH_REPLAY_FAIL_OPEN");
    }

    let server_keys = Keys::parse(TEST_SERVER_SECRET_HEX).unwrap();
    unsafe {
        std::env::set_var("SERVER_NSEC", server_keys.secret_key().to_bech32().unwrap());
    }

    server_keys
}

/// Signing material for a confidential client's private_key_jwt key.
#[allow(dead_code)] // individual test binaries use different subsets of the fields
pub struct ClientAuthKeyMaterial {
    pub signing_key: p256::ecdsa::SigningKey,
    pub jwk: serde_json::Value,
    pub jkt: String,
    pub kid: String,
}

/// Generate fresh private_key_jwt signing material.
///
/// # Panics
/// Panics only on key-generation failure, which does not happen with `OsRng`.
#[allow(dead_code)]
pub fn client_auth_key_material() -> ClientAuthKeyMaterial {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::elliptic_curve::rand_core::OsRng;
    use sha2::{Digest, Sha256};

    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());
    let kid = format!("kid-{}", uuid::Uuid::new_v4());
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
    });
    let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint_input.as_bytes()));

    ClientAuthKeyMaterial {
        signing_key,
        jwk,
        jkt,
        kid,
    }
}

/// Start a local confidential-client metadata server and return its client_id
/// (the metadata URL).
///
/// # Panics
/// Panics when the local listener cannot be bound.
#[allow(dead_code)]
pub async fn start_confidential_client_metadata_server(
    redirect_uri: &str,
    key_material: &ClientAuthKeyMaterial,
    dpop_bound_access_tokens: bool,
) -> String {
    use axum::{routing::get, Json, Router};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_id = format!("http://{addr}/client-metadata.json");
    let metadata = serde_json::json!({
        "client_id": client_id,
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "dpop_bound_access_tokens": dpop_bound_access_tokens,
        "jwks": {
            "keys": [key_material.jwk.clone()]
        }
    });

    async fn confidential_metadata_handler(
        axum::extract::State(state): axum::extract::State<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        Json(state)
    }

    let app = Router::new()
        .route("/client-metadata.json", get(confidential_metadata_handler))
        .with_state(metadata);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    client_id
}

/// Build a signed private_key_jwt client assertion with a fresh jti.
///
/// # Panics
/// Panics only on serialization or signing failure.
#[allow(dead_code)]
pub fn private_key_jwt_assertion(
    key_material: &ClientAuthKeyMaterial,
    client_id: &str,
    aud: &str,
) -> String {
    private_key_jwt_assertion_with_jti(
        key_material,
        client_id,
        aud,
        &format!("client-assertion-{}", uuid::Uuid::new_v4()),
        chrono::Utc::now().timestamp() + 240,
    )
}

/// Build a signed private_key_jwt client assertion with a chosen jti and exp.
///
/// # Panics
/// Panics only on serialization or signing failure.
#[allow(dead_code)]
pub fn private_key_jwt_assertion_with_jti(
    key_material: &ClientAuthKeyMaterial,
    client_id: &str,
    aud: &str,
    jti: &str,
    exp: i64,
) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::signature::Signer;

    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": key_material.kid,
    });
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "exp": exp,
        "iat": now,
        "jti": jti,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key_material.signing_key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[allow(dead_code)]
pub fn test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

// Unit tests for the safety guard moved to a separate test file
// to avoid race conditions with set_var affecting parallel tests.
// The safety guard is tested implicitly when running integration tests.
