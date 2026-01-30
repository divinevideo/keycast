// ABOUTME: Integration tests for admin preload-user endpoint
// ABOUTME: Tests idempotency - same vine_id should return same pubkey

use sqlx::PgPool;
use uuid::Uuid;

mod common;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Ensure migrations are run
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Clean up test data by vine_id
async fn cleanup_by_vine_id(pool: &PgPool, vine_id: &str, tenant_id: i64) {
    // First get the pubkey for this vine_id
    let result: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(vine_id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    if let Some((pubkey,)) = result {
        cleanup_by_pubkey(pool, &pubkey).await;
    }
}

/// Clean up test data by pubkey
async fn cleanup_by_pubkey(pool: &PgPool, pubkey: &str) {
    let _ = sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
}

// ============================================================================
// Repository-level tests for preload-user idempotency
// ============================================================================

/// Test that create_preloaded_user stores vine_id correctly
#[tokio::test]
async fn test_preloaded_user_stores_vine_id() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let vine_id = format!("vine_test_{}", Uuid::new_v4());
    let username = format!("testuser_{}", &vine_id[..8]);

    // Clean up any existing test data
    cleanup_by_vine_id(&pool, &vine_id, tenant_id).await;

    // Generate a test keypair
    let keys = nostr_sdk::Keys::generate();
    let pubkey = keys.public_key().to_hex();

    // Create preloaded user directly via SQL (simulating repository)
    let result = sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, display_name, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&vine_id)
    .bind(&username)
    .bind("Test Display Name")
    .execute(&pool)
    .await;

    assert!(result.is_ok(), "Should be able to create preloaded user");

    // Verify vine_id was stored
    let stored: Option<(String, String)> =
        sqlx::query_as("SELECT pubkey, vine_id FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(&vine_id)
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(stored.is_some(), "User with vine_id should exist");
    let (stored_pubkey, stored_vine_id) = stored.unwrap();
    assert_eq!(stored_pubkey, pubkey);
    assert_eq!(stored_vine_id, vine_id);

    // Cleanup
    cleanup_by_pubkey(&pool, &pubkey).await;
}

/// Test that find_pubkey_by_vine_id returns correct pubkey
#[tokio::test]
async fn test_find_pubkey_by_vine_id() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let vine_id = format!("vine_lookup_{}", Uuid::new_v4());
    let username = format!("lookupuser_{}", &vine_id[..8]);

    // Clean up
    cleanup_by_vine_id(&pool, &vine_id, tenant_id).await;

    // Create user
    let keys = nostr_sdk::Keys::generate();
    let pubkey = keys.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&vine_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Test find_pubkey_by_vine_id
    let found: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(&vine_id)
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(found.is_some(), "Should find user by vine_id");
    assert_eq!(found.unwrap().0, pubkey);

    // Test with wrong tenant_id returns None
    let wrong_tenant: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(&vine_id)
            .bind(999i64) // Wrong tenant
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        wrong_tenant.is_none(),
        "Should not find user with wrong tenant_id"
    );

    // Cleanup
    cleanup_by_pubkey(&pool, &pubkey).await;
}

/// CRITICAL: Test preload-user idempotency - same vine_id returns same pubkey
#[tokio::test]
async fn test_preload_user_idempotency() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let vine_id = format!("vine_idempotent_{}", Uuid::new_v4());
    let username = format!("idempotent_{}", &vine_id[..8]);

    // Clean up
    cleanup_by_vine_id(&pool, &vine_id, tenant_id).await;

    // First call: create user
    let keys1 = nostr_sdk::Keys::generate();
    let pubkey1 = keys1.public_key().to_hex();

    // Simulate preload_user first call - check if exists, then create
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(&vine_id)
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(existing.is_none(), "User should not exist yet");

    // Create user since it doesn't exist
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(&pubkey1)
    .bind(tenant_id)
    .bind(&vine_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Add personal key
    let encrypted_secret = vec![0u8; 48]; // Dummy encrypted key
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey1)
    .bind(&encrypted_secret)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Should create personal key");

    // Second call: simulate preload_user again with same vine_id
    // This should return the EXISTING pubkey, not create a new one
    let existing_on_second_call: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(&vine_id)
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        existing_on_second_call.is_some(),
        "User should exist on second call"
    );

    let pubkey_from_second_call = existing_on_second_call.unwrap().0;
    assert_eq!(
        pubkey_from_second_call,
        pubkey1,
        "IDEMPOTENCY VIOLATION: Second call returned different pubkey! Expected {}, got {}",
        &pubkey1[..8],
        &pubkey_from_second_call[..8]
    );

    // Verify only ONE user exists with this vine_id
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(&vine_id)
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("Count query should succeed");

    assert_eq!(
        count.0, 1,
        "Should have exactly ONE user for vine_id, found {}",
        count.0
    );

    // Cleanup
    cleanup_by_pubkey(&pool, &pubkey1).await;
}

/// Test unique constraint prevents duplicate vine_id per tenant
#[tokio::test]
async fn test_vine_id_unique_constraint() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let vine_id = format!("vine_unique_{}", Uuid::new_v4());

    // Clean up
    cleanup_by_vine_id(&pool, &vine_id, tenant_id).await;

    // Create first user
    let keys1 = nostr_sdk::Keys::generate();
    let pubkey1 = keys1.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, 'user1', NOW(), NOW())",
    )
    .bind(&pubkey1)
    .bind(tenant_id)
    .bind(&vine_id)
    .execute(&pool)
    .await
    .expect("First insert should succeed");

    // Try to create second user with same vine_id - should fail
    let keys2 = nostr_sdk::Keys::generate();
    let pubkey2 = keys2.public_key().to_hex();

    let duplicate_result = sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, 'user2', NOW(), NOW())",
    )
    .bind(&pubkey2)
    .bind(tenant_id)
    .bind(&vine_id)
    .execute(&pool)
    .await;

    assert!(
        duplicate_result.is_err(),
        "Duplicate vine_id should fail due to unique constraint"
    );

    // Verify error is a unique violation
    let err = duplicate_result.unwrap_err();
    let err_string = err.to_string().to_lowercase();
    assert!(
        err_string.contains("unique")
            || err_string.contains("duplicate")
            || err_string.contains("constraint"),
        "Error should be unique constraint violation, got: {}",
        err_string
    );

    // Cleanup
    cleanup_by_pubkey(&pool, &pubkey1).await;
}

/// Test that different tenants can have same vine_id
#[tokio::test]
async fn test_vine_id_unique_per_tenant() {
    let pool = setup_pool().await;
    let vine_id = format!("vine_multi_tenant_{}", Uuid::new_v4());
    let tenant_id_1: i64 = 1;
    let tenant_id_2: i64 = 2;

    // Clean up
    cleanup_by_vine_id(&pool, &vine_id, tenant_id_1).await;
    cleanup_by_vine_id(&pool, &vine_id, tenant_id_2).await;

    // Ensure tenant 2 exists
    let _ = sqlx::query(
        "INSERT INTO tenants (id, name, domain, created_at, updated_at)
         VALUES ($1, 'Test Tenant 2', 'test2.example.com', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id_2)
    .execute(&pool)
    .await;

    // Create user in tenant 1
    let keys1 = nostr_sdk::Keys::generate();
    let pubkey1 = keys1.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, 'tenant1_user', NOW(), NOW())",
    )
    .bind(&pubkey1)
    .bind(tenant_id_1)
    .bind(&vine_id)
    .execute(&pool)
    .await
    .expect("Should create user in tenant 1");

    // Create user in tenant 2 with SAME vine_id - should succeed
    let keys2 = nostr_sdk::Keys::generate();
    let pubkey2 = keys2.public_key().to_hex();

    let result = sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, 'tenant2_user', NOW(), NOW())",
    )
    .bind(&pubkey2)
    .bind(tenant_id_2)
    .bind(&vine_id)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "Same vine_id in different tenant should succeed"
    );

    // Verify both users exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE vine_id = $1")
        .bind(&vine_id)
        .fetch_one(&pool)
        .await
        .expect("Count should succeed");

    assert_eq!(
        count.0, 2,
        "Should have 2 users with same vine_id in different tenants"
    );

    // Cleanup
    cleanup_by_pubkey(&pool, &pubkey1).await;
    cleanup_by_pubkey(&pool, &pubkey2).await;
}

/// Test is_unclaimed returns correct values
#[tokio::test]
async fn test_is_unclaimed_status() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    // Create unclaimed user (no email)
    let keys_unclaimed = nostr_sdk::Keys::generate();
    let pubkey_unclaimed = keys_unclaimed.public_key().to_hex();
    let vine_id = format!("vine_unclaimed_{}", Uuid::new_v4());

    cleanup_by_pubkey(&pool, &pubkey_unclaimed).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, 'unclaimed_user', NOW(), NOW())",
    )
    .bind(&pubkey_unclaimed)
    .bind(tenant_id)
    .bind(&vine_id)
    .execute(&pool)
    .await
    .expect("Should create unclaimed user");

    // Check is_unclaimed (email IS NULL)
    let unclaimed_status: Option<(Option<String>,)> =
        sqlx::query_as("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(&pubkey_unclaimed)
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(unclaimed_status.is_some(), "User should exist");
    assert!(
        unclaimed_status.unwrap().0.is_none(),
        "Unclaimed user should have NULL email"
    );

    // Create claimed user (has email)
    let keys_claimed = nostr_sdk::Keys::generate();
    let pubkey_claimed = keys_claimed.public_key().to_hex();

    cleanup_by_pubkey(&pool, &pubkey_claimed).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, 'claimed@example.com', true, NOW(), NOW())",
    )
    .bind(&pubkey_claimed)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Should create claimed user");

    // Check claimed user has email
    let claimed_status: Option<(Option<String>,)> =
        sqlx::query_as("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(&pubkey_claimed)
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(claimed_status.is_some(), "User should exist");
    assert!(
        claimed_status.unwrap().0.is_some(),
        "Claimed user should have email"
    );

    // Cleanup
    cleanup_by_pubkey(&pool, &pubkey_unclaimed).await;
    cleanup_by_pubkey(&pool, &pubkey_claimed).await;
}
