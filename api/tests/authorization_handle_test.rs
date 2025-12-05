// ABOUTME: Tests for authorization_handle feature (TDD)
// ABOUTME: Implements silent re-authentication for OAuth public clients

mod common;

use chrono::{Duration, Utc};
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// Test Helpers
// ============================================================================

async fn setup_db() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

/// Create a test user and return pubkey
async fn create_test_user(pool: &PgPool, tenant_id: i64) -> String {
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create user");

    user_pubkey
}

// ============================================================================
// Phase 1: Schema Tests
// ============================================================================

#[tokio::test]
async fn test_schema_has_authorization_handle_column() {
    let pool = setup_db().await;

    // Test that oauth_authorizations has authorization_handle column
    let result: Result<Option<(Option<String>,)>, _> =
        sqlx::query_as("SELECT authorization_handle FROM oauth_authorizations LIMIT 1")
            .fetch_optional(&pool)
            .await;

    assert!(
        result.is_ok(),
        "oauth_authorizations should have authorization_handle column"
    );
}

#[tokio::test]
async fn test_schema_has_previous_auth_id_column() {
    let pool = setup_db().await;

    // Test that oauth_codes has previous_auth_id column
    let result: Result<Option<(Option<i32>,)>, _> =
        sqlx::query_as("SELECT previous_auth_id FROM oauth_codes LIMIT 1")
            .fetch_optional(&pool)
            .await;

    assert!(
        result.is_ok(),
        "oauth_codes should have previous_auth_id column"
    );
}

#[tokio::test]
async fn test_authorization_handle_can_be_stored_and_retrieved() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    // Generate a test handle (64 hex chars = 32 bytes)
    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys = Keys::generate();
    let redirect_origin = format!("https://handle-test-{}.example.com", Uuid::new_v4());

    // Insert authorization with handle
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&handle)
    .fetch_one(&pool)
    .await
    .expect("Failed to insert authorization with handle");

    // Retrieve and verify
    let stored_handle: Option<String> =
        sqlx::query_scalar("SELECT authorization_handle FROM oauth_authorizations WHERE id = $1")
            .bind(auth_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch authorization");

    assert_eq!(
        stored_handle,
        Some(handle),
        "Stored handle should match inserted handle"
    );
}

#[tokio::test]
async fn test_authorization_handle_unique_index_on_active() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys1 = Keys::generate();
    let bunker_keys2 = Keys::generate();
    let redirect_origin1 = format!("https://unique-test-1-{}.example.com", Uuid::new_v4());
    let redirect_origin2 = format!("https://unique-test-2-{}.example.com", Uuid::new_v4());

    // First insert should succeed
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret1', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin1)
    .bind(bunker_keys1.public_key().to_hex())
    .bind(&handle)
    .execute(&pool)
    .await
    .expect("First insert should succeed");

    // Second insert with same handle should fail (unique constraint)
    let result = sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret2', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin2)
    .bind(bunker_keys2.public_key().to_hex())
    .bind(&handle)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "Duplicate active handle should violate unique constraint"
    );
}

#[tokio::test]
async fn test_authorization_handle_allows_duplicate_if_revoked() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys1 = Keys::generate();
    let bunker_keys2 = Keys::generate();
    let redirect_origin1 = format!("https://revoke-test-1-{}.example.com", Uuid::new_v4());
    let redirect_origin2 = format!("https://revoke-test-2-{}.example.com", Uuid::new_v4());

    // First insert
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret1', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin1)
    .bind(bunker_keys1.public_key().to_hex())
    .bind(&handle)
    .fetch_one(&pool)
    .await
    .expect("First insert should succeed");

    // Revoke it
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
        .bind(auth_id)
        .execute(&pool)
        .await
        .expect("Failed to revoke");

    // Second insert with same handle should succeed (first is revoked)
    let result = sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret2', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin2)
    .bind(bunker_keys2.public_key().to_hex())
    .bind(&handle)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "Same handle should be allowed when previous is revoked (partial unique index)"
    );
}

#[tokio::test]
async fn test_previous_auth_id_can_be_stored_in_oauth_codes() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let code = format!("code_{}", Uuid::new_v4());
    let redirect_uri = format!("https://code-test-{}.example.com/callback", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::minutes(10);

    // Insert oauth_code with previous_auth_id
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, previous_auth_id, created_at)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, $5, NOW())",
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(&redirect_uri)
    .bind(expires_at)
    .bind(Some(42i32)) // previous_auth_id
    .execute(&pool)
    .await
    .expect("Failed to insert oauth_code with previous_auth_id");

    // Retrieve and verify
    let stored_previous_auth_id: Option<i32> =
        sqlx::query_scalar("SELECT previous_auth_id FROM oauth_codes WHERE code = $1")
            .bind(&code)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch oauth_code");

    assert_eq!(
        stored_previous_auth_id,
        Some(42),
        "Stored previous_auth_id should match"
    );

    // Cleanup
    sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&code)
        .execute(&pool)
        .await
        .expect("Failed to cleanup");
}

// ============================================================================
// Phase 2: Handle Generation Tests
// ============================================================================

#[test]
fn test_authorization_handle_format() {
    // Test the helper function directly
    let handle = keycast_api::api::http::oauth::generate_authorization_handle();

    // Should be 64 hex characters (32 bytes = 256 bits)
    assert_eq!(handle.len(), 64, "Handle should be 64 hex characters");
    assert!(
        handle.chars().all(|c| c.is_ascii_hexdigit()),
        "Handle should contain only hex characters"
    );
}

#[test]
fn test_authorization_handle_is_unique() {
    // Generate multiple handles and verify they're all different
    let handles: Vec<String> = (0..100)
        .map(|_| keycast_api::api::http::oauth::generate_authorization_handle())
        .collect();

    let unique_handles: std::collections::HashSet<_> = handles.iter().collect();
    assert_eq!(
        unique_handles.len(),
        handles.len(),
        "All generated handles should be unique"
    );
}

#[tokio::test]
async fn test_token_response_includes_authorization_handle() {
    // This test verifies the TokenResponse struct has the authorization_handle field
    // by creating a response and checking it serializes correctly
    let response = keycast_api::api::http::oauth::TokenResponse {
        bunker_url: "bunker://test?relay=wss://test&secret=test".to_string(),
        access_token: Some("test_token".to_string()),
        token_type: "Bearer".to_string(),
        expires_in: 86400,
        scope: Some("sign".to_string()),
        policy: None,
        authorization_handle: Some("a".repeat(64)),
    };

    // Serialize to JSON and verify authorization_handle is present
    let json = serde_json::to_string(&response).expect("Failed to serialize TokenResponse");
    assert!(
        json.contains("authorization_handle"),
        "TokenResponse JSON should include authorization_handle"
    );
}

// ============================================================================
// Phase 3: Handle Validation Tests
// ============================================================================

/// Helper function that mimics the authorization handle lookup query
/// Returns the authorization ID if the handle is valid, active, not expired, and handle not past absolute expiration
async fn lookup_authorization_by_handle(pool: &PgPool, handle: &str) -> Option<i32> {
    sqlx::query_scalar(
        "SELECT id FROM oauth_authorizations
         WHERE authorization_handle = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())
           AND handle_expires_at > NOW()",
    )
    .bind(handle)
    .fetch_optional(pool)
    .await
    .expect("Query should not fail")
}

#[tokio::test]
async fn test_valid_handle_enables_auto_approve() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys = Keys::generate();
    let redirect_origin = format!("https://valid-handle-test-{}.example.com", Uuid::new_v4());

    // Create authorization with handle (no expiry, not revoked)
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&handle)
    .fetch_one(&pool)
    .await
    .expect("Failed to insert authorization");

    // Lookup should find the authorization
    let found_id = lookup_authorization_by_handle(&pool, &handle).await;
    assert_eq!(
        found_id,
        Some(auth_id),
        "Valid handle should return authorization ID for auto-approve"
    );
}

#[tokio::test]
async fn test_revoked_handle_requires_consent() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys = Keys::generate();
    let redirect_origin = format!("https://revoked-handle-test-{}.example.com", Uuid::new_v4());

    // Create authorization with handle
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&handle)
    .fetch_one(&pool)
    .await
    .expect("Failed to insert authorization");

    // Revoke it
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
        .bind(auth_id)
        .execute(&pool)
        .await
        .expect("Failed to revoke");

    // Lookup should NOT find the revoked authorization
    let found_id = lookup_authorization_by_handle(&pool, &handle).await;
    assert_eq!(
        found_id, None,
        "Revoked handle should require consent (return None)"
    );
}

#[tokio::test]
async fn test_expired_handle_requires_consent() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys = Keys::generate();
    let redirect_origin = format!("https://expired-handle-test-{}.example.com", Uuid::new_v4());
    let expired_at = Utc::now() - Duration::hours(1); // Expired 1 hour ago

    // Create authorization with handle that's expired
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, expires_at, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret', '[]', 1, $4, $5, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&handle)
    .bind(expired_at)
    .execute(&pool)
    .await
    .expect("Failed to insert authorization");

    // Lookup should NOT find the expired authorization
    let found_id = lookup_authorization_by_handle(&pool, &handle).await;
    assert_eq!(
        found_id, None,
        "Expired handle should require consent (return None)"
    );
}

#[tokio::test]
async fn test_invalid_handle_requires_consent() {
    let pool = setup_db().await;

    // Lookup with a handle that doesn't exist
    let nonexistent_handle = format!("{:064x}", rand::random::<u128>());
    let found_id = lookup_authorization_by_handle(&pool, &nonexistent_handle).await;
    assert_eq!(
        found_id, None,
        "Invalid/nonexistent handle should require consent (return None)"
    );
}

#[tokio::test]
async fn test_handle_lookup_ignores_null_handles() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let bunker_keys = Keys::generate();
    let redirect_origin = format!("https://null-handle-test-{}.example.com", Uuid::new_v4());

    // Create authorization WITHOUT a handle (NULL)
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret', '[]', 1, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .execute(&pool)
    .await
    .expect("Failed to insert authorization");

    // Lookup with empty string should not match NULL
    let found_id = lookup_authorization_by_handle(&pool, "").await;
    assert_eq!(
        found_id, None,
        "Empty handle should not match NULL authorization_handle"
    );
}

// ============================================================================
// Phase 4: Cleanup Tests
// ============================================================================

#[tokio::test]
async fn test_previous_auth_id_passed_through_oauth_code() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let code = format!("code_with_prev_{}", Uuid::new_v4());
    let redirect_uri = format!(
        "https://prev-auth-test-{}.example.com/callback",
        Uuid::new_v4()
    );
    let expires_at = Utc::now() + Duration::minutes(10);
    let previous_auth_id = 42i32;

    // Insert oauth_code with previous_auth_id
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, previous_auth_id, created_at)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, $5, NOW())",
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(&redirect_uri)
    .bind(expires_at)
    .bind(previous_auth_id)
    .execute(&pool)
    .await
    .expect("Failed to insert oauth_code");

    // Fetch and verify previous_auth_id
    let fetched_previous_auth_id: Option<i32> =
        sqlx::query_scalar("SELECT previous_auth_id FROM oauth_codes WHERE code = $1")
            .bind(&code)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch oauth_code");

    assert_eq!(
        fetched_previous_auth_id,
        Some(previous_auth_id),
        "previous_auth_id should be stored and retrievable"
    );

    // Cleanup
    sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&code)
        .execute(&pool)
        .await
        .expect("Failed to cleanup");
}

#[tokio::test]
async fn test_revoke_old_authorization_query() {
    let pool = setup_db().await;
    let user_pubkey = create_test_user(&pool, 1).await;

    let handle = format!("{:064x}", rand::random::<u128>());
    let bunker_keys = Keys::generate();
    let redirect_origin = format!("https://revoke-old-test-{}.example.com", Uuid::new_v4());

    // Create authorization that will be "old"
    let old_auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, 'secret', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&handle)
    .fetch_one(&pool)
    .await
    .expect("Failed to insert authorization");

    // Verify it's not revoked
    let revoked_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM oauth_authorizations WHERE id = $1")
            .bind(old_auth_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch");

    assert!(revoked_at.is_none(), "Should not be revoked initially");

    // Simulate what token exchange should do: revoke old auth
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
        .bind(old_auth_id)
        .execute(&pool)
        .await
        .expect("Failed to revoke");

    // Verify it's now revoked
    let revoked_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM oauth_authorizations WHERE id = $1")
            .bind(old_auth_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch");

    assert!(revoked_at.is_some(), "Should be revoked after UPDATE");

    // Verify old handle no longer works for auto-approve
    let found_id = lookup_authorization_by_handle(&pool, &handle).await;
    assert_eq!(
        found_id, None,
        "Revoked authorization should not be found by handle"
    );
}
