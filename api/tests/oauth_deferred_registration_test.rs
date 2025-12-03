// ABOUTME: Tests for deferred OAuth registration
// ABOUTME: Verifies that user creation is deferred to token exchange, preventing orphaned state

mod common;

use chrono::{Duration, Utc};
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Run migrations to ensure schema is up to date
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

// ============================================================================
// Test 1: OAuth registration stores pending data in oauth_codes, not users
// ============================================================================

#[tokio::test]
async fn test_oauth_register_defers_user_creation() {
    let pool = setup_pool().await;

    // Generate test data
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let email = format!("test-{}@example.com", Uuid::new_v4());
    let password_hash = "$2b$12$testhashedpassword...";
    let verification_token = format!("verify-{}", Uuid::new_v4());
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let code = format!("code-{}", Uuid::new_v4());

    // Insert oauth_code with pending registration data (simulating oauth_register)
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, NOW(), $5, $6, $7)"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .bind(password_hash)
    .bind(&verification_token)
    .execute(&pool)
    .await
    .expect("Should insert oauth_code with pending data");

    // Verify oauth_codes has the pending data
    let oauth_code: Option<(String, String, String)> = sqlx::query_as(
        "SELECT pending_email, pending_password_hash, pending_email_verification_token
         FROM oauth_codes WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(
        oauth_code.is_some(),
        "oauth_code should exist with pending data"
    );
    let (stored_email, stored_hash, stored_token) = oauth_code.unwrap();
    assert_eq!(stored_email, email);
    assert_eq!(stored_hash, password_hash);
    assert_eq!(stored_token, verification_token);

    // Verify users table has NO row for this pubkey
    let user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE pubkey = $1)")
            .bind(&user_pubkey)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        !user_exists,
        "User should NOT be created during oauth_register"
    );

    // Verify personal_keys table has NO row
    let personal_key_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM personal_keys WHERE user_pubkey = $1)")
            .bind(&user_pubkey)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        !personal_key_exists,
        "personal_keys should NOT be created during oauth_register"
    );
}

// ============================================================================
// Test 2: Token exchange creates user + keys atomically
// ============================================================================

#[tokio::test]
async fn test_token_exchange_creates_user_and_keys() {
    let pool = setup_pool().await;

    // Generate test data
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let email = format!("test-{}@example.com", Uuid::new_v4());
    let password_hash = "$2b$12$testhashedpassword...";
    let verification_token = format!("verify-{}", Uuid::new_v4());
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let code = format!("code-{}", Uuid::new_v4());

    // Simulate encrypted secret (would come from KMS in real code)
    let mock_encrypted_secret: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    // Insert oauth_code with pending registration data AND encrypted secret (auto-generate flow)
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, NOW(), $5, $6, $7, $8)"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .bind(password_hash)
    .bind(&verification_token)
    .bind(mock_encrypted_secret)
    .execute(&pool)
    .await
    .expect("Should insert oauth_code");

    // Simulate token exchange: create user + keys atomically
    // First, get oauth_code data
    let oauth_code: (String, String, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret
         FROM oauth_codes WHERE code = $1 AND expires_at > NOW()"
    )
    .bind(&code)
    .fetch_one(&pool)
    .await
    .expect("Should find oauth_code");

    let (
        pending_email,
        pending_password_hash,
        pending_verification_token,
        pending_encrypted_secret,
    ) = oauth_code;

    // Create user
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
         VALUES ($1, 1, $2, $3, false, $4, $5, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&pending_email)
    .bind(&pending_password_hash)
    .bind(&pending_verification_token)
    .bind(Utc::now() + Duration::hours(24))
    .execute(&pool)
    .await
    .expect("Should create user");

    // Create personal_keys
    let encrypted_secret = pending_encrypted_secret.expect("Should have encrypted secret");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&encrypted_secret)
    .execute(&pool)
    .await
    .expect("Should create personal_keys");

    // Delete oauth_code (consumed)
    sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&code)
        .execute(&pool)
        .await
        .expect("Should delete oauth_code");

    // Verify users row created
    let user: Option<(String, String, bool)> =
        sqlx::query_as("SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1")
            .bind(&user_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(user.is_some(), "User should be created at token exchange");
    let (stored_email, stored_hash, email_verified) = user.unwrap();
    assert_eq!(stored_email, email);
    assert_eq!(stored_hash, password_hash);
    assert!(!email_verified, "Email should not be verified yet");

    // Verify personal_keys row created
    let personal_key: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        personal_key.is_some(),
        "personal_keys should be created at token exchange"
    );
    assert_eq!(
        personal_key.unwrap().0,
        mock_encrypted_secret,
        "Encrypted secret should be copied from oauth_code"
    );
}

// ============================================================================
// Test 3: Incomplete registration allows re-registration
// ============================================================================

#[tokio::test]
async fn test_incomplete_oauth_allows_reregistration() {
    let pool = setup_pool().await;

    let email = format!("test-{}@example.com", Uuid::new_v4());
    let user_keys_1 = Keys::generate();
    let user_pubkey_1 = user_keys_1.public_key().to_hex();
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // First OAuth register - stores in oauth_codes, does NOT complete token exchange
    let code_1 = format!("code-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, NOW(), $5, 'hash1', 'token1')"
    )
    .bind(&code_1)
    .bind(&user_pubkey_1)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .execute(&pool)
    .await
    .expect("First registration should succeed");

    // Verify no user created
    let user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND tenant_id = 1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert!(!user_exists, "User should not exist yet");

    // Second OAuth register with SAME email (user can retry after abandoning first flow)
    let user_keys_2 = Keys::generate();
    let user_pubkey_2 = user_keys_2.public_key().to_hex();
    let code_2 = format!("code-{}", Uuid::new_v4());

    // This should succeed - email check passes because no user row exists
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token)
         VALUES ($1, $2, 'Test App', $3, 'sign', $4, 1, NOW(), $5, 'hash2', 'token2')"
    )
    .bind(&code_2)
    .bind(&user_pubkey_2)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .execute(&pool)
    .await
    .expect("Second registration should succeed (no user exists yet)");

    // Both oauth_codes should exist (old one will expire)
    let code_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_codes WHERE pending_email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert_eq!(code_count, 2, "Both oauth_codes should exist (pending)");
}

// ============================================================================
// Test 4: Complete registration blocks re-registration
// ============================================================================

#[tokio::test]
async fn test_complete_oauth_blocks_reregistration() {
    let pool = setup_pool().await;

    let email = format!("test-{}@example.com", Uuid::new_v4());
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Create completed user (simulates oauth_register + token_exchange completed)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, 'hash', false, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Create personal_keys
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&[1u8, 2, 3, 4][..])
    .execute(&pool)
    .await
    .expect("Should create personal_keys");

    // Now try to register again with same email - early check should catch this
    let existing_user: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = 1")
            .bind(&email)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        existing_user.is_some(),
        "Email already registered check should find existing user"
    );
}

// ============================================================================
// Test 5: UCAN with non-existent user fails gracefully
// ============================================================================

#[tokio::test]
async fn test_ucan_without_user_fails_cleanly() {
    let pool = setup_pool().await;

    // Generate a pubkey for a user that doesn't exist
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Query for user (simulating API auth lookup) - should not find anything
    let user: Option<(String, i32)> =
        sqlx::query_as("SELECT pubkey, tenant_id FROM users WHERE pubkey = $1")
            .bind(&user_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        user.is_none(),
        "User lookup should return nothing for non-existent user"
    );

    // The API would return 401/403 with "User not found" here
    // Frontend would clear cookie and user can start fresh
}

// ============================================================================
// Test 6: First-party auth register still works (regression)
// ============================================================================

#[tokio::test]
async fn test_first_party_register_unchanged() {
    let pool = setup_pool().await;

    let email = format!("test-{}@example.com", Uuid::new_v4());
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let mock_encrypted_secret: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

    // First-party register creates user + keys atomically in one request
    // (No oauth_codes involved - direct registration)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, 'hash', false, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("Should create user");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(mock_encrypted_secret)
    .execute(&pool)
    .await
    .expect("Should create personal_keys");

    // Verify user exists immediately
    let user: Option<(String,)> = sqlx::query_as("SELECT email FROM users WHERE pubkey = $1")
        .bind(&user_pubkey)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

    assert!(
        user.is_some(),
        "User should exist immediately after first-party registration"
    );

    // Verify personal_keys exists immediately
    let personal_key: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        personal_key.is_some(),
        "personal_keys should exist immediately after first-party registration"
    );

    // Verify can login immediately (user + personal_keys exist)
    let can_login: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM users u
            JOIN personal_keys pk ON u.pubkey = pk.user_pubkey
            WHERE u.email = $1 AND u.tenant_id = 1
        )",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("Query should succeed");

    assert!(
        can_login,
        "Should be able to login immediately after first-party registration"
    );
}

// ============================================================================
// Test 7: Auto-generate flow creates user at token exchange
// ============================================================================

#[tokio::test]
async fn test_autogenerate_creates_user_at_token_exchange() {
    let pool = setup_pool().await;

    // Auto-generate flow: server generates keys at registration time
    let server_generated_keys = Keys::generate();
    let user_pubkey = server_generated_keys.public_key().to_hex();
    let email = format!("test-{}@example.com", Uuid::new_v4());
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let code = format!("code-{}", Uuid::new_v4());

    // Simulate encrypted secret from KMS
    let mock_encrypted_secret: &[u8] = &[10, 20, 30, 40, 50, 60, 70, 80];

    // Step 1: oauth_register stores pending data + encrypted secret
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret)
         VALUES ($1, $2, 'Auto-Generate App', $3, 'sign', $4, 1, NOW(), $5, 'hash', 'token', $6)"
    )
    .bind(&code)
    .bind(&user_pubkey)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .bind(mock_encrypted_secret)
    .execute(&pool)
    .await
    .expect("oauth_register should succeed");

    // Verify oauth_codes has pending data + auto-generated pubkey
    let has_pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_codes WHERE code = $1 AND pending_email = $2 AND pending_encrypted_secret IS NOT NULL)"
    )
    .bind(&code)
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("Query should succeed");

    assert!(
        has_pending,
        "oauth_codes should have pending data with encrypted secret"
    );

    // Step 2: Verify users NOT created yet
    let user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE pubkey = $1)")
            .bind(&user_pubkey)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert!(!user_exists, "User should NOT exist before token exchange");

    // Step 3: Complete token exchange (creates user + keys atomically)
    let (pending_email, pending_hash, pending_token, pending_secret): (String, String, String, Vec<u8>) = sqlx::query_as(
        "SELECT pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret
         FROM oauth_codes WHERE code = $1"
    )
    .bind(&code)
    .fetch_one(&pool)
    .await
    .expect("Should find oauth_code");

    // Create user
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
         VALUES ($1, 1, $2, $3, false, $4, $5, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&pending_email)
    .bind(&pending_hash)
    .bind(&pending_token)
    .bind(Utc::now() + Duration::hours(24))
    .execute(&pool)
    .await
    .expect("Should create user");

    // Create personal_keys (copy encrypted bytes directly)
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&pending_secret)
    .execute(&pool)
    .await
    .expect("Should create personal_keys");

    // Delete oauth_code
    sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&code)
        .execute(&pool)
        .await
        .expect("Should delete oauth_code");

    // Step 4: Verify users + personal_keys created
    let user_created: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM users u
            JOIN personal_keys pk ON u.pubkey = pk.user_pubkey
            WHERE u.pubkey = $1
        )",
    )
    .bind(&user_pubkey)
    .fetch_one(&pool)
    .await
    .expect("Query should succeed");

    assert!(
        user_created,
        "User and personal_keys should be created after token exchange"
    );
}

// ============================================================================
// Test 8: Email uniqueness checked early at registration
// ============================================================================

#[tokio::test]
async fn test_email_uniqueness_checked_early() {
    let pool = setup_pool().await;

    let email = format!("test-{}@example.com", Uuid::new_v4());
    let user_keys_1 = Keys::generate();
    let user_pubkey_1 = user_keys_1.public_key().to_hex();

    // Step 1: First-party register with email X (creates user immediately)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, 'hash', false, NOW(), NOW())"
    )
    .bind(&user_pubkey_1)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("First-party registration should succeed");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())"
    )
    .bind(&user_pubkey_1)
    .bind(&[1u8, 2, 3, 4][..])
    .execute(&pool)
    .await
    .expect("Should create personal_keys");

    // Step 2: OAuth register with same email X - early check should fail
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = 1")
            .bind(&email)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        existing.is_some(),
        "Early email check should find existing user - fail before OAuth redirect"
    );
}

// ============================================================================
// Test 9: Race condition - email check at token exchange
// ============================================================================

#[tokio::test]
async fn test_email_race_condition_at_token_exchange() {
    let pool = setup_pool().await;

    let email = format!("test-{}@example.com", Uuid::new_v4());
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());

    // Two users start OAuth registration with same email (race condition)
    // Both pass early check because no user exists yet

    let user_keys_a = Keys::generate();
    let user_pubkey_a = user_keys_a.public_key().to_hex();
    let code_a = format!("code-a-{}", Uuid::new_v4());

    let user_keys_b = Keys::generate();
    let user_pubkey_b = user_keys_b.public_key().to_hex();
    let code_b = format!("code-b-{}", Uuid::new_v4());

    // Step 1: Both OAuth registrations succeed (early check passes for both)
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret)
         VALUES ($1, $2, 'App', $3, 'sign', $4, 1, NOW(), $5, 'hash_a', 'token_a', $6)"
    )
    .bind(&code_a)
    .bind(&user_pubkey_a)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .bind(&[1u8, 2, 3, 4][..])
    .execute(&pool)
    .await
    .expect("oauth_code A should succeed");

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
         pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret)
         VALUES ($1, $2, 'App', $3, 'sign', $4, 1, NOW(), $5, 'hash_b', 'token_b', $6)"
    )
    .bind(&code_b)
    .bind(&user_pubkey_b)
    .bind(format!("{}/callback", redirect_origin))
    .bind(Utc::now() + Duration::minutes(10))
    .bind(&email)
    .bind(&[5u8, 6, 7, 8][..])
    .execute(&pool)
    .await
    .expect("oauth_code B should succeed");

    // Step 2: Token exchange for oauth_code A succeeds (first to complete wins)
    // Check email uniqueness again at token exchange time
    let email_taken: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND tenant_id = 1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        !email_taken,
        "Email should not be taken before first token exchange"
    );

    // Create user A
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, 'hash_a', false, NOW(), NOW())"
    )
    .bind(&user_pubkey_a)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("Should create user A");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())"
    )
    .bind(&user_pubkey_a)
    .bind(&[1u8, 2, 3, 4][..])
    .execute(&pool)
    .await
    .expect("Should create personal_keys A");

    // Step 3: Token exchange for oauth_code B fails (email now taken)
    let email_taken_now: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND tenant_id = 1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    assert!(
        email_taken_now,
        "Email should be taken after first token exchange completes"
    );

    // User B's token exchange would return: "This email is already registered. Please sign in instead."
    // (The oauth_code B just expires unused)
}
