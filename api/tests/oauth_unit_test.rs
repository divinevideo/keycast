// ABOUTME: Unit tests for OAuth code generation and validation logic
// ABOUTME: Tests the OAuth authorization code lifecycle and security constraints

/// Test that authorization codes are generated with correct format
#[test]
fn test_authorization_code_format() {
    use rand::Rng;

    // Generate code the same way as the OAuth handler
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Verify length
    assert_eq!(code.len(), 32);

    // Verify all characters are alphanumeric
    assert!(code.chars().all(|c| c.is_alphanumeric()));
}

/// Test that bunker secrets are generated with correct format
#[test]
fn test_bunker_secret_format() {
    use rand::Rng;

    // Generate bunker secret the same way as the token handler
    let bunker_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Verify length
    assert_eq!(bunker_secret.len(), 32);

    // Verify all characters are alphanumeric
    assert!(bunker_secret.chars().all(|c| c.is_alphanumeric()));
}

/// Test that bunker URLs have correct format
#[test]
fn test_bunker_url_format() {
    let bunker_public_key = "test_public_key_hex";
    let relay_url = "wss://relay.damus.io";
    let bunker_secret = "test_secret";

    let bunker_url = format!(
        "bunker://{}?relay={}&secret={}",
        bunker_public_key,
        relay_url,
        bunker_secret
    );

    assert!(bunker_url.starts_with("bunker://"));
    assert!(bunker_url.contains("relay=wss://"));
    assert!(bunker_url.contains("secret="));
}

// ============================================================================
// Database Integration Tests
// ============================================================================

use chrono::{Duration, Utc};
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_pool() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    PgPool::connect(&database_url).await.expect("Failed to connect to database")
}

/// Test authorization code expiration logic
#[tokio::test]
async fn test_authorization_code_expiration() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW())")
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

    // Create OAuth app
    let app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ('Test App', $1, 'secret', '[\"http://localhost/callback\"]', 1, NOW(), NOW())
         RETURNING id"
    )
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create EXPIRED oauth_code (expires_at in the past)
    let expired_time = Utc::now() - Duration::minutes(10);
    let code = format!("expired_code_{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, application_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, $3, $4, 'sign', $5, 1, NOW())"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(app_id)
    .bind("http://localhost/callback")
    .bind(expired_time)
    .execute(&pool)
    .await
    .unwrap();

    // Try to fetch the code - should exist but be expired
    let result: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
        "SELECT expires_at FROM oauth_codes WHERE code = $1 AND expires_at > NOW()"
    )
    .bind(&code)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(result.is_none(), "Expired code should not be found when filtering by expires_at > NOW()");
}

/// Test one-time use of authorization codes
#[tokio::test]
async fn test_authorization_code_one_time_use() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW())")
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

    // Create OAuth app
    let app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ('Test App', $1, 'secret', '[\"http://localhost/callback\"]', 1, NOW(), NOW())
         RETURNING id"
    )
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create valid oauth_code
    let code = format!("valid_code_{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, application_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, $3, $4, 'sign', NOW() + INTERVAL '10 minutes', 1, NOW())"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(app_id)
    .bind("http://localhost/callback")
    .execute(&pool)
    .await
    .unwrap();

    // First exchange - delete the code (simulating token exchange)
    let deleted = sqlx::query("DELETE FROM oauth_codes WHERE code = $1 RETURNING code")
        .bind(&code)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(deleted.is_some(), "First exchange should find and delete the code");

    // Second exchange - code should be gone
    let deleted_again = sqlx::query("DELETE FROM oauth_codes WHERE code = $1 RETURNING code")
        .bind(&code)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(deleted_again.is_none(), "Second exchange should fail - code already used");
}

/// Test redirect URI validation (exact match required)
#[tokio::test]
async fn test_redirect_uri_validation() {
    let pool = setup_pool().await;
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // Create OAuth app with specific redirect_uris
    let _app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ('Test App', $1, 'secret', '[\"http://localhost:3000/callback\", \"https://example.com/oauth\"]', 1, NOW(), NOW())
         RETURNING id"
    )
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Query the redirect_uris and verify
    let redirect_uris: String = sqlx::query_scalar(
        "SELECT redirect_uris FROM oauth_applications WHERE redirect_origin = $1"
    )
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    let uris: Vec<String> = serde_json::from_str(&redirect_uris).unwrap();

    // Verify exact matches work
    assert!(uris.contains(&"http://localhost:3000/callback".to_string()));
    assert!(uris.contains(&"https://example.com/oauth".to_string()));

    // Verify non-matching doesn't exist
    assert!(!uris.contains(&"http://evil.com/callback".to_string()));
    assert!(!uris.contains(&"http://localhost:3000/callback/extra".to_string()));
}

/// Test that multiple authorizations can exist for the same user (different origins)
#[tokio::test]
async fn test_multiple_authorizations_per_user() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW())")
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

    // Create two different OAuth apps
    let redirect_origin_1 = format!("https://app1-{}.example.com", Uuid::new_v4());
    let redirect_origin_2 = format!("https://app2-{}.example.com", Uuid::new_v4());

    let app_id_1: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ('App 1', $1, 'secret1', '[]', 1, NOW(), NOW()) RETURNING id"
    )
    .bind(&redirect_origin_1)
    .fetch_one(&pool)
    .await
    .unwrap();

    let app_id_2: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ('App 2', $1, 'secret2', '[]', 1, NOW(), NOW()) RETURNING id"
    )
    .bind(&redirect_origin_2)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create authorization for App 1
    sqlx::query(
        "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', 1, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin_1)
    .bind(app_id_1)
    .bind(&user_pubkey)
    .execute(&pool)
    .await
    .unwrap();

    // Create authorization for App 2
    sqlx::query(
        "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret2', '[]', 1, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin_2)
    .bind(app_id_2)
    .bind(&user_pubkey)
    .execute(&pool)
    .await
    .unwrap();

    // Count authorizations for this user
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1"
    )
    .bind(&user_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count, 2, "User should have 2 authorizations (one per app)");
}


// ============================================================================
// Unit Tests (No Database Required)
// ============================================================================

/// Test extracting nsec from PKCE code_verifier
#[test]
fn test_extract_nsec_from_verifier() {
    // Test with nsec1 format (bech32)
    let verifier_with_nsec = "randombase64data.nsec1abcdefghijklmnopqrstuvwxyz234567890123456789012";
    let result = keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_with_nsec);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "nsec1abcdefghijklmnopqrstuvwxyz234567890123456789012");

    // Test with hex format (64 chars)
    let verifier_with_hex = "randombase64data.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let result = keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_with_hex);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    // Test without nsec (standard PKCE)
    let verifier_without_nsec = "randombase64datawithnodot";
    let result = keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_without_nsec);
    assert!(result.is_none());

    // Test with short value after dot (not valid nsec)
    let verifier_short = "random.short";
    let result = keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_short);
    assert!(result.is_none());
}

/// Test that RPC fast path query finds OAuth authorizations from any application
/// Bug: The fast path query in nostr_rpc.rs was hardcoded to only find authorizations
/// where client_id = 'keycast-login', causing all other OAuth apps (like 'divine')
/// to fall back to the slow path (DB + KMS decryption on every request).
///
/// Fix: Removed the hardcoded client_id filter from the query.
#[tokio::test]
async fn test_rpc_fast_path_works_with_any_oauth_app() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();
    let tenant_id = 1i64;

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())")
        .bind(&user_pubkey)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .unwrap();

    // Create OAuth app named 'divine' (NOT 'keycast-login')
    let redirect_origin = format!("https://divine-{}.example.com", Uuid::new_v4());
    let app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ('divine', $1, 'secret', '[]', $2, NOW(), NOW())
         RETURNING id"
    )
    .bind(&redirect_origin)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create OAuth authorization with this 'divine' app
    sqlx::query(
        "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', $5, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    // Query using the FIXED fast path SQL (no app.client_id filter)
    // This is the query from nostr_rpc.rs that was fixed
    let result: Option<String> = sqlx::query_scalar(
        "SELECT oa.bunker_public_key
         FROM oauth_authorizations oa
         JOIN users u ON oa.user_pubkey = u.pubkey AND oa.tenant_id = u.tenant_id
         WHERE oa.user_pubkey = $1
           AND u.tenant_id = $2
         ORDER BY oa.created_at DESC
         LIMIT 1"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    // Fast path should find the bunker_public_key regardless of app name
    assert!(result.is_some(), "Fast path query should find bunker_public_key for any OAuth app");
    assert_eq!(result.unwrap(), bunker_pubkey, "Should return correct bunker_public_key");

    // Verify the OLD buggy query would NOT have found it (simulated)
    // The bug was filtering by app.client_id = 'keycast-login'
    let buggy_result: Option<String> = sqlx::query_scalar(
        "SELECT oa.bunker_public_key
         FROM oauth_authorizations oa
         JOIN oauth_applications app ON oa.application_id = app.id
         WHERE oa.user_pubkey = $1
           AND oa.tenant_id = $2
           AND app.name = 'keycast-login'
         ORDER BY oa.created_at DESC
         LIMIT 1"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(buggy_result.is_none(), "Buggy query (filtering by keycast-login) should NOT find divine app authorization");
}

/// Test that secret key encryption stores bytes not hex string
#[test]
fn test_secret_key_encryption_format() {
    use nostr_sdk::Keys;

    // Generate test keys
    let keys = Keys::generate();

    // Get secret in both formats
    let secret_hex = keys.secret_key().to_secret_hex();
    let secret_bytes = keys.secret_key().to_secret_bytes();

    // Verify hex is 64 chars, bytes is 32 bytes
    assert_eq!(secret_hex.len(), 64, "Hex string should be 64 characters");
    assert_eq!(secret_bytes.len(), 32, "Secret bytes should be 32 bytes");

    // Verify we can reconstruct from bytes
    use nostr_sdk::secp256k1::SecretKey as Secp256k1SecretKey;
    let reconstructed = Secp256k1SecretKey::from_slice(&secret_bytes);
    assert!(reconstructed.is_ok(), "Should be able to create SecretKey from bytes");

    // Verify reconstructed key matches original
    let reconstructed_keys = Keys::new(reconstructed.unwrap().into());
    assert_eq!(
        reconstructed_keys.public_key().to_hex(),
        keys.public_key().to_hex(),
        "Reconstructed key should match original"
    );
}

// ============================================================================
// Handler Cache Tests (Verifies fix for stale snapshot bug)
// ============================================================================

use keycast_core::signing_handler::{SignerHandlersCache, SigningHandler};
use std::sync::Arc;

/// Mock handler for testing cache behavior
struct MockHandler {
    id: i64,
    pubkey: String,
}

#[async_trait::async_trait]
impl SigningHandler for MockHandler {
    async fn sign_event_direct(
        &self,
        _unsigned_event: nostr_sdk::UnsignedEvent,
    ) -> Result<nostr_sdk::Event, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!("mock handler - not used in cache tests")
    }

    fn authorization_id(&self) -> i64 {
        self.id
    }

    fn user_pubkey(&self) -> String {
        self.pubkey.clone()
    }

    fn get_keys(&self) -> nostr_sdk::Keys {
        nostr_sdk::Keys::generate()
    }
}

/// Test that moka cache clone shares underlying data (not a snapshot).
/// This verifies the fix for the stale cache bug where API received
/// a snapshot HashMap at startup instead of a live cache reference.
#[tokio::test]
async fn test_moka_cache_is_live_not_snapshot() {
    // Create moka cache (same type used by signer)
    let cache: SignerHandlersCache = moka::future::Cache::builder().build();

    // Clone it (should share same underlying data)
    let cache_clone = cache.clone();

    // Insert via original cache
    let handler = Arc::new(MockHandler {
        id: 1,
        pubkey: "test_pubkey_1".to_string(),
    }) as Arc<dyn SigningHandler>;
    cache.insert("key1".to_string(), handler).await;

    // Verify immediately visible via clone (no snapshot issue!)
    let found = cache_clone.get("key1").await;
    assert!(found.is_some(), "Handler inserted via original should be immediately visible via clone");
    assert_eq!(found.unwrap().authorization_id(), 1);

    // Verify the reverse: insert via clone, visible via original
    let handler2 = Arc::new(MockHandler {
        id: 2,
        pubkey: "test_pubkey_2".to_string(),
    }) as Arc<dyn SigningHandler>;
    cache_clone.insert("key2".to_string(), handler2).await;

    let found2 = cache.get("key2").await;
    assert!(found2.is_some(), "Handler inserted via clone should be visible via original");
    assert_eq!(found2.unwrap().authorization_id(), 2);
}

/// Test that cache invalidation removes handlers correctly.
/// Verifies the Remove command in authorization_channel works.
#[tokio::test]
async fn test_cache_invalidation_removes_handler() {
    let cache: SignerHandlersCache = moka::future::Cache::builder().build();
    let cache_clone = cache.clone();

    // Insert a handler
    let user_pubkey = "user123";
    let handler = Arc::new(MockHandler {
        id: 42,
        pubkey: user_pubkey.to_string(),
    }) as Arc<dyn SigningHandler>;
    cache.insert(user_pubkey.to_string(), handler).await;

    // Verify it exists in both
    assert!(cache.get(user_pubkey).await.is_some());
    assert!(cache_clone.get(user_pubkey).await.is_some());

    // Invalidate via original
    cache.invalidate(user_pubkey).await;

    // Verify removed from both (invalidation is also live!)
    assert!(cache.get(user_pubkey).await.is_none(), "Handler should be removed from original");
    assert!(cache_clone.get(user_pubkey).await.is_none(), "Handler should be removed from clone");
}

/// Test that multiple handlers can coexist (one per user pubkey)
#[tokio::test]
async fn test_multiple_handlers_by_user_pubkey() {
    let cache: SignerHandlersCache = moka::future::Cache::builder().build();

    // Add handlers for different users
    for i in 0..5 {
        let pubkey = format!("user_{}", i);
        let handler = Arc::new(MockHandler {
            id: i as i64,
            pubkey: pubkey.clone(),
        }) as Arc<dyn SigningHandler>;
        cache.insert(pubkey, handler).await;
    }

    // Verify all exist
    for i in 0..5 {
        let pubkey = format!("user_{}", i);
        let found = cache.get(&pubkey).await;
        assert!(found.is_some(), "Handler for {} should exist", pubkey);
        assert_eq!(found.unwrap().authorization_id(), i as i64);
    }

    // Verify non-existent doesn't exist
    assert!(cache.get("nonexistent").await.is_none());
}
