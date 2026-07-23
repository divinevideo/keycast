#![cfg(feature = "integration-tests")]

// ABOUTME: Tests for the change_key handler
// ABOUTME: Verifies that key change transaction correctly migrates user identity

mod common;

use chrono::Utc;
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Create a test user with email, password, and personal key
async fn create_test_user(
    pool: &PgPool,
    pubkey: &str,
    email: &str,
    password_hash: &str,
    encrypted_secret: &[u8],
) {
    let now = Utc::now();

    // Clean up any existing data first
    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .ok();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, $4, $5)",
    )
    .bind(pubkey)
    .bind(email)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .expect("Should create test user");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, $3, $4)",
    )
    .bind(pubkey)
    .bind(encrypted_secret)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .expect("Should create personal key");
}

/// Create a test OAuth authorization for a user
async fn create_test_oauth_authorization(pool: &PgPool, user_pubkey: &str, app_name: &str) -> i32 {
    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();
    let now = Utc::now();

    let (id,): (i32,) = sqlx::query_as(
        "INSERT INTO oauth_authorizations
         (user_pubkey, bunker_public_key, secret_hash, relays, redirect_origin, tenant_id, created_at, updated_at, handle_expires_at)
         VALUES ($1, $2, 'test_hash', 'wss://relay.example.com', $3, 1, $4, $5, $6)
         RETURNING id",
    )
    .bind(user_pubkey)
    .bind(&bunker_pubkey)
    .bind(format!("https://{}.example.com", app_name.to_lowercase().replace(' ', "-")))
    .bind(now)
    .bind(now)
    .bind(now + chrono::Duration::days(30))
    .fetch_one(pool)
    .await
    .expect("Should create OAuth authorization");

    id
}

// ============================================================================
// Test: change_key_transaction correctly migrates identity
// ============================================================================

#[tokio::test]
async fn test_change_key_transaction_migrates_identity() {
    let pool = setup_pool().await;

    // Setup: Create old user with personal key
    let old_keys = Keys::generate();
    let old_pubkey = old_keys.public_key().to_hex();
    let email = format!("changekey-{}@example.com", Uuid::new_v4());
    let password_hash = "$2b$12$K4Iczl3gkZmIq7WxVbJbNepLNnDOXhF2wZvLZOKCqwCmHPHkKZedi"; // "testpass"
    let encrypted_secret = vec![0u8; 48]; // Dummy encrypted key

    create_test_user(&pool, &old_pubkey, &email, password_hash, &encrypted_secret).await;

    // Setup: Create OAuth authorizations for old user
    let _auth1_id = create_test_oauth_authorization(&pool, &old_pubkey, "Test App 1").await;
    let _auth2_id = create_test_oauth_authorization(&pool, &old_pubkey, "Test App 2").await;

    // Verify setup
    let oauth_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1")
            .bind(&old_pubkey)
            .fetch_one(&pool)
            .await
            .expect("Should count OAuth authorizations");
    assert_eq!(oauth_count, 2, "Should have 2 OAuth authorizations");

    // Execute: Call the repository method directly (simulating handler behavior)
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    let new_encrypted_secret = vec![1u8; 48]; // Different dummy encrypted key

    let user_repo = keycast_core::repositories::UserRepository::new(pool.clone());
    let deleted_count = user_repo
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            1, // tenant_id
            &email,
            password_hash,
            &new_encrypted_secret,
        )
        .await
        .expect("change_key_transaction should succeed");

    // Verify: Correct number of OAuth authorizations deleted
    assert_eq!(
        deleted_count, 2,
        "Should report 2 deleted OAuth authorizations"
    );

    // Verify: Old user is orphaned (email/password cleared)
    let old_user: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT email, password_hash FROM users WHERE pubkey = $1")
            .bind(&old_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(old_user.is_some(), "Old user record should still exist");
    let (old_email, old_pass) = old_user.unwrap();
    assert!(
        old_email.is_none(),
        "Old user's email should be NULL (orphaned)"
    );
    assert!(
        old_pass.is_none(),
        "Old user's password should be NULL (orphaned)"
    );

    // Verify: New user has email/password
    let new_user: Option<(String, String, bool)> =
        sqlx::query_as("SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1")
            .bind(&new_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(new_user.is_some(), "New user should exist");
    let (new_email, new_pass, verified) = new_user.unwrap();
    assert_eq!(new_email, email, "New user should have migrated email");
    assert_eq!(
        new_pass, password_hash,
        "New user should have migrated password hash"
    );
    assert!(verified, "New user should be email verified");

    // Verify: Old personal_keys deleted
    let old_key_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM personal_keys WHERE user_pubkey = $1)")
            .bind(&old_pubkey)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");
    assert!(!old_key_exists, "Old personal_keys should be deleted");

    // Verify: New personal_keys created
    let new_key: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(&new_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(new_key.is_some(), "New personal_keys should exist");
    assert_eq!(
        new_key.unwrap().0,
        new_encrypted_secret,
        "New key should match"
    );

    // Verify: OAuth authorizations deleted
    let remaining_oauth: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1")
            .bind(&old_pubkey)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");
    assert_eq!(
        remaining_oauth, 0,
        "All OAuth authorizations should be deleted"
    );

    // Cleanup
    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
}

// ============================================================================
// Test: change_key_transaction is atomic (rolls back on failure)
// ============================================================================

#[tokio::test]
async fn test_change_key_transaction_atomic_on_duplicate() {
    let pool = setup_pool().await;

    // Setup: Create old user
    let old_keys = Keys::generate();
    let old_pubkey = old_keys.public_key().to_hex();
    let email = format!("atomic-{}@example.com", Uuid::new_v4());
    let password_hash = "$2b$12$K4Iczl3gkZmIq7WxVbJbNepLNnDOXhF2wZvLZOKCqwCmHPHkKZedi";
    let encrypted_secret = vec![0u8; 48];

    create_test_user(&pool, &old_pubkey, &email, password_hash, &encrypted_secret).await;

    // Setup: Create new user that already exists (will cause conflict)
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    let other_email = format!("other-{}@example.com", Uuid::new_v4());
    create_test_user(
        &pool,
        &new_pubkey,
        &other_email,
        password_hash,
        &encrypted_secret,
    )
    .await;

    // Execute: Try to change to existing pubkey (should fail)
    let user_repo = keycast_core::repositories::UserRepository::new(pool.clone());
    let result = user_repo
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            1,
            &email,
            password_hash,
            &[1u8; 48],
        )
        .await;

    // Verify: Transaction failed
    assert!(
        result.is_err(),
        "Should fail when new pubkey already exists"
    );

    // Verify: Old user is NOT orphaned (rollback worked)
    let old_user: Option<(Option<String>,)> =
        sqlx::query_as("SELECT email FROM users WHERE pubkey = $1")
            .bind(&old_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(old_user.is_some(), "Old user should still exist");
    let (old_email,) = old_user.unwrap();
    assert!(
        old_email.is_some(),
        "Old user's email should NOT be orphaned on failure"
    );

    // Cleanup
    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
}

// ============================================================================
// Test: change_key works with no OAuth authorizations
// ============================================================================

#[tokio::test]
async fn test_change_key_transaction_no_oauth_authorizations() {
    let pool = setup_pool().await;

    // Setup: Create user without any OAuth authorizations
    let old_keys = Keys::generate();
    let old_pubkey = old_keys.public_key().to_hex();
    let email = format!("noauth-{}@example.com", Uuid::new_v4());
    let password_hash = "$2b$12$K4Iczl3gkZmIq7WxVbJbNepLNnDOXhF2wZvLZOKCqwCmHPHkKZedi";
    let encrypted_secret = vec![0u8; 48];

    create_test_user(&pool, &old_pubkey, &email, password_hash, &encrypted_secret).await;

    // Execute
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();

    let user_repo = keycast_core::repositories::UserRepository::new(pool.clone());
    let deleted_count = user_repo
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            1,
            &email,
            password_hash,
            &[1u8; 48],
        )
        .await
        .expect("Should succeed with no OAuth authorizations");

    // Verify
    assert_eq!(
        deleted_count, 0,
        "Should report 0 deleted OAuth authorizations"
    );

    // Verify new user exists
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE pubkey = $1)")
        .bind(&new_pubkey)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");
    assert!(exists, "New user should be created");

    // Cleanup
    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
}

// ============================================================================
// Test: rotation carries account restrictions to the replacement identity
// ============================================================================

/// Account-restriction columns as stored, for comparing the old row to the
/// replacement row after rotation.
#[derive(sqlx::FromRow)]
struct RestrictionsRow {
    status: String,
    suspended_reason: Option<String>,
    suspended_at: Option<chrono::DateTime<Utc>>,
    verified_minor: bool,
    verified_minor_at: Option<chrono::DateTime<Utc>>,
}

#[tokio::test]
async fn test_change_key_transaction_preserves_account_restrictions() {
    let pool = setup_pool().await;

    let old_pubkey = Keys::generate().public_key().to_hex();
    let email = format!("restricted-{}@example.com", Uuid::new_v4());
    let password_hash = "$2b$12$K4Iczl3gkZmIq7WxVbJbNepLNnDOXhF2wZvLZOKCqwCmHPHkKZedi";

    create_test_user(&pool, &old_pubkey, &email, password_hash, &[0u8; 48]).await;

    sqlx::query(
        "UPDATE users SET status = 'banned', suspended_reason = $1, suspended_at = NOW(), \
                          verified_minor = TRUE, verified_minor_at = NOW() \
         WHERE pubkey = $2",
    )
    .bind("policy violation")
    .bind(&old_pubkey)
    .execute(&pool)
    .await
    .expect("Should restrict test user");

    // Read the stored timestamps back so the comparison below is against what
    // Postgres actually holds, not a client-side value it rounds on write.
    let (suspended_at, verified_minor_at): (
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
    ) = sqlx::query_as("SELECT suspended_at, verified_minor_at FROM users WHERE pubkey = $1")
        .bind(&old_pubkey)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

    let new_pubkey = Keys::generate().public_key().to_hex();
    keycast_core::repositories::UserRepository::new(pool.clone())
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            1,
            &email,
            password_hash,
            &[1u8; 48],
        )
        .await
        .expect("change_key_transaction should succeed");

    let carried: RestrictionsRow = sqlx::query_as(
        "SELECT status, suspended_reason, suspended_at, verified_minor, verified_minor_at \
         FROM users WHERE pubkey = $1",
    )
    .bind(&new_pubkey)
    .fetch_one(&pool)
    .await
    .expect("Query should succeed");

    assert_eq!(
        carried.status, "banned",
        "Replacement identity must stay banned, not default to active"
    );
    assert_eq!(
        carried.suspended_reason.as_deref(),
        Some("policy violation")
    );
    assert_eq!(carried.suspended_at, suspended_at);
    assert!(
        carried.verified_minor,
        "verified_minor designation must follow the identity"
    );
    assert_eq!(carried.verified_minor_at, verified_minor_at);

    // Cleanup
    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey IN ($1, $2)")
        .bind(&old_pubkey)
        .bind(&new_pubkey)
        .execute(&pool)
        .await
        .ok();
}
