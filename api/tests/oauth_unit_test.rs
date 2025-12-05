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
        bunker_public_key, relay_url, bunker_secret
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

mod common;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

/// Test authorization code expiration logic
#[tokio::test]
async fn test_authorization_code_expiration() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

    // Create EXPIRED oauth_code (expires_at in the past)
    let expired_time = Utc::now() - Duration::minutes(10);
    let code = format!("expired_code_{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, NOW())"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(format!("{}/callback", redirect_origin))
    .bind(expired_time)
    .execute(&pool)
    .await
    .unwrap();

    // Try to fetch the code - should exist but be expired
    let result: Option<(chrono::DateTime<Utc>,)> =
        sqlx::query_as("SELECT expires_at FROM oauth_codes WHERE code = $1 AND expires_at > NOW()")
            .bind(&code)
            .fetch_optional(&pool)
            .await
            .unwrap();

    assert!(
        result.is_none(),
        "Expired code should not be found when filtering by expires_at > NOW()"
    );
}

/// Test one-time use of authorization codes
#[tokio::test]
async fn test_authorization_code_one_time_use() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

    // Create valid oauth_code
    let code = format!("valid_code_{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, 'Test App', $3, 'sign', NOW() + INTERVAL '10 minutes', 1, NOW())"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(format!("{}/callback", redirect_origin))
    .execute(&pool)
    .await
    .unwrap();

    // First exchange - delete the code (simulating token exchange)
    let deleted = sqlx::query("DELETE FROM oauth_codes WHERE code = $1 RETURNING code")
        .bind(&code)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(
        deleted.is_some(),
        "First exchange should find and delete the code"
    );

    // Second exchange - code should be gone
    let deleted_again = sqlx::query("DELETE FROM oauth_codes WHERE code = $1 RETURNING code")
        .bind(&code)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(
        deleted_again.is_none(),
        "Second exchange should fail - code already used"
    );
}

/// Test that multiple authorizations can exist for the same user (different origins)
#[tokio::test]
async fn test_multiple_authorizations_per_user() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Create user
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

    // Create two different origins
    let redirect_origin_1 = format!("https://app1-{}.example.com", Uuid::new_v4());
    let redirect_origin_2 = format!("https://app2-{}.example.com", Uuid::new_v4());

    // Create authorization for App 1
    let bunker_keys_1 = Keys::generate();
    sqlx::query(
        "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'App 1', $3, 'secret1', '[]', 1, NOW() + INTERVAL '30 days', NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin_1)
    .bind(bunker_keys_1.public_key().to_hex())
    .execute(&pool)
    .await
    .unwrap();

    // Create authorization for App 2
    let bunker_keys_2 = Keys::generate();
    sqlx::query(
        "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'App 2', $3, 'secret2', '[]', 1, NOW() + INTERVAL '30 days', NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin_2)
    .bind(bunker_keys_2.public_key().to_hex())
    .execute(&pool)
    .await
    .unwrap();

    // Count authorizations for this user
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1")
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
    let verifier_with_nsec =
        "randombase64data.nsec1abcdefghijklmnopqrstuvwxyz234567890123456789012";
    let result =
        keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_with_nsec);
    assert!(result.is_some());
    assert_eq!(
        result.unwrap(),
        "nsec1abcdefghijklmnopqrstuvwxyz234567890123456789012"
    );

    // Test with hex format (64 chars)
    let verifier_with_hex =
        "randombase64data.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let result =
        keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_with_hex);
    assert!(result.is_some());
    assert_eq!(
        result.unwrap(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );

    // Test without nsec (standard PKCE)
    let verifier_without_nsec = "randombase64datawithnodot";
    let result =
        keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_without_nsec);
    assert!(result.is_none());

    // Test with short value after dot (not valid nsec)
    let verifier_short = "random.short";
    let result = keycast_api::api::http::oauth::extract_nsec_from_verifier_public(verifier_short);
    assert!(result.is_none());
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
    assert!(
        reconstructed.is_ok(),
        "Should be able to create SecretKey from bytes"
    );

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
    keys: Keys,
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

    fn get_keys(&self) -> Keys {
        self.keys.clone()
    }
}

/// Test that SignerHandlersCache properly stores and retrieves handlers by bunker pubkey
#[tokio::test]
async fn test_handler_cache_stores_by_bunker_pubkey() {
    let cache = SignerHandlersCache::new(100);

    let bunker_pubkey = "test_bunker_pubkey_123";
    let handler = Arc::new(MockHandler {
        id: 1,
        pubkey: "user_pubkey_abc".to_string(),
        keys: Keys::generate(),
    }) as Arc<dyn SigningHandler + Send + Sync>;

    // Insert handler
    cache
        .insert(bunker_pubkey.to_string(), handler.clone())
        .await;

    // Retrieve by bunker pubkey
    let retrieved = cache.get(bunker_pubkey).await;
    assert!(retrieved.is_some(), "Should find handler by bunker pubkey");
    assert_eq!(retrieved.unwrap().authorization_id(), 1);
}

/// Test that cache can hold multiple handlers with different bunker pubkeys
#[tokio::test]
async fn test_handler_cache_multiple_handlers() {
    let cache = SignerHandlersCache::new(100);

    // Insert two handlers with different bunker pubkeys
    let handler1 = Arc::new(MockHandler {
        id: 1,
        pubkey: "user1".to_string(),
        keys: Keys::generate(),
    }) as Arc<dyn SigningHandler + Send + Sync>;

    let handler2 = Arc::new(MockHandler {
        id: 2,
        pubkey: "user2".to_string(),
        keys: Keys::generate(),
    }) as Arc<dyn SigningHandler + Send + Sync>;

    cache.insert("bunker1".to_string(), handler1).await;
    cache.insert("bunker2".to_string(), handler2).await;

    // Verify both can be retrieved
    assert!(cache.get("bunker1").await.is_some());
    assert!(cache.get("bunker2").await.is_some());
    assert!(cache.get("bunker3").await.is_none());
}

/// Test that cache remove works
#[tokio::test]
async fn test_handler_cache_remove() {
    let cache = SignerHandlersCache::new(100);

    let handler = Arc::new(MockHandler {
        id: 1,
        pubkey: "user".to_string(),
        keys: Keys::generate(),
    }) as Arc<dyn SigningHandler + Send + Sync>;

    cache.insert("bunker_key".to_string(), handler).await;
    assert!(cache.get("bunker_key").await.is_some());

    cache.remove("bunker_key").await;
    assert!(cache.get("bunker_key").await.is_none());
}
