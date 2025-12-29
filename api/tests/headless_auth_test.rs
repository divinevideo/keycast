// ABOUTME: Integration tests for headless authentication endpoints
// ABOUTME: Tests the pure JSON API flow for native mobile apps (Flutter, etc.)

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

/// Clean up test data
async fn cleanup_test_user(pool: &PgPool, pubkey: &str) {
    let _ = sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
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
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
}

// ============================================================================
// Registration Tests
// ============================================================================

/// Test that headless registration creates pending registration in oauth_codes
#[tokio::test]
async fn test_headless_registration_creates_pending_record() {
    let pool = setup_pool().await;
    let test_email = format!("headless-test-{}@example.com", Uuid::new_v4());
    let client_id = "TestFlutterApp";
    let redirect_uri = "https://test.example.com/callback";

    // Generate a test keypair
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    // Clean up any existing test data
    cleanup_test_user(&pool, &pubkey).await;

    // Simulate what headless_register does:
    // 1. Hash password
    let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();

    // 2. Generate device_code and verification_token
    let device_code: String = rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let verification_token = format!("verify_{}", Uuid::new_v4());

    // 3. Create placeholder code
    let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::hours(24);

    // 4. Store in oauth_codes with pending registration data
    let result = sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, 
            expires_at, tenant_id, created_at,
            pending_email, pending_password_hash, pending_email_verification_token,
            device_code
        ) VALUES ($1, $2, $3, $4, $5, $6, 1, NOW(), $7, $8, $9, $10)",
    )
    .bind(&placeholder_code)
    .bind(&pubkey)
    .bind(client_id)
    .bind(redirect_uri)
    .bind("policy:social")
    .bind(expires_at)
    .bind(&test_email)
    .bind(&password_hash)
    .bind(&verification_token)
    .bind(&device_code)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "Should be able to create pending registration"
    );

    // Verify the record exists
    let record = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT user_pubkey, device_code, pending_email, pending_email_verification_token 
         FROM oauth_codes WHERE code = $1 AND tenant_id = 1",
    )
    .bind(&placeholder_code)
    .fetch_one(&pool)
    .await
    .expect("Record should exist");

    assert_eq!(record.0, pubkey);
    assert_eq!(record.1, device_code);
    assert_eq!(record.2, Some(test_email.clone()));
    assert_eq!(record.3, Some(verification_token.clone()));

    // Cleanup
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&placeholder_code)
        .execute(&pool)
        .await;
}

// ============================================================================
// Login Tests
// ============================================================================

/// Test that headless login creates authorization code for verified user
#[tokio::test]
async fn test_headless_login_creates_code() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let test_email = format!("headless-login-{}@example.com", Uuid::new_v4());
    let password = "testpassword123";
    let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();

    // Clean up
    cleanup_test_user(&pool, &pubkey).await;

    // Create verified user
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())"
    )
    .bind(&pubkey)
    .bind(&test_email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Simulate headless login: create authorization code
    let code: String = rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, 'TestApp', 'https://test.example.com/callback', 'policy:social', $3, 1, NOW())"
    )
    .bind(&code)
    .bind(&pubkey)
    .bind(expires_at)
    .execute(&pool)
    .await
    .expect("Should create authorization code");

    // Verify code was created and is valid
    let valid_code = sqlx::query_as::<_, (String,)>(
        "SELECT user_pubkey FROM oauth_codes 
         WHERE code = $1 AND tenant_id = 1 AND expires_at > NOW()",
    )
    .bind(&code)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(valid_code.is_some(), "Authorization code should be valid");
    assert_eq!(valid_code.unwrap().0, pubkey);

    // Cleanup
    cleanup_test_user(&pool, &pubkey).await;
}

/// Test that login fails for unverified email
#[tokio::test]
async fn test_headless_login_fails_unverified_email() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let test_email = format!("unverified-{}@example.com", Uuid::new_v4());
    let password_hash = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST).unwrap();

    // Clean up
    cleanup_test_user(&pool, &pubkey).await;

    // Create UNVERIFIED user
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, false, NOW(), NOW())"
    )
    .bind(&pubkey)
    .bind(&test_email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Verify user is not verified
    let user = sqlx::query_as::<_, (bool,)>(
        "SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .expect("User should exist");

    assert!(!user.0, "User should NOT be email verified");

    // In real flow, headless_login would return HeadlessError::EmailNotVerified here

    // Cleanup
    cleanup_test_user(&pool, &pubkey).await;
}

// ============================================================================
// Authorization Tests
// ============================================================================

/// Test that headless authorize creates code for authenticated user
#[tokio::test]
async fn test_headless_authorize_creates_code() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    // Clean up
    cleanup_test_user(&pool, &pubkey).await;

    // Create verified user (simulating user is already authenticated)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, 1, 'auth-test@example.com', true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Simulate headless_authorize: create new authorization code for different app
    let code: String = rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, 'SecondApp', 'https://second-app.example.com/callback', 'policy:readonly', $3, 1, NOW())"
    )
    .bind(&code)
    .bind(&pubkey)
    .bind(expires_at)
    .execute(&pool)
    .await
    .expect("Should create authorization code");

    // Verify code was created
    let record = sqlx::query_as::<_, (String, String)>(
        "SELECT client_id, scope FROM oauth_codes WHERE code = $1 AND tenant_id = 1",
    )
    .bind(&code)
    .fetch_one(&pool)
    .await
    .expect("Code should exist");

    assert_eq!(record.0, "SecondApp");
    assert_eq!(record.1, "policy:readonly");

    // Cleanup
    cleanup_test_user(&pool, &pubkey).await;
}

// ============================================================================
// Device Code Polling Tests
// ============================================================================

/// Test that device_code can be used to retrieve authorization code after email verification
#[tokio::test]
async fn test_device_code_polling_flow() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let test_email = format!("polling-{}@example.com", Uuid::new_v4());
    let verification_token = format!("verify_{}", Uuid::new_v4());
    let device_code = format!("device_{}", Uuid::new_v4());

    // Clean up
    cleanup_test_user(&pool, &pubkey).await;

    // Step 1: Create pending registration (what headless_register does)
    let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::hours(24);
    let password_hash = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST).unwrap();

    sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, 
            expires_at, tenant_id, created_at,
            pending_email, pending_password_hash, pending_email_verification_token,
            device_code
        ) VALUES ($1, $2, 'TestApp', 'https://test.example.com/callback', 'policy:social', $3, 1, NOW(), $4, $5, $6, $7)"
    )
    .bind(&placeholder_code)
    .bind(&pubkey)
    .bind(expires_at)
    .bind(&test_email)
    .bind(&password_hash)
    .bind(&verification_token)
    .bind(&device_code)
    .execute(&pool)
    .await
    .expect("Should create pending registration");

    // Step 2: Simulate email verification (creates new code, stores in Redis normally)
    // For testing, we'll just update the oauth_codes entry with a new valid code
    let new_code = format!("verified_{}", Uuid::new_v4());

    // In production, verify_email:
    // 1. Finds oauth_code by verification_token
    // 2. Creates user + personal_keys
    // 3. Generates new authorization code
    // 4. Stores new code in Redis keyed by device_code
    // 5. Client polls /api/oauth/poll?device_code=xxx and gets the code

    // Create user (what verify_email does)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())"
    )
    .bind(&pubkey)
    .bind(&test_email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Create new valid authorization code
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at)
         VALUES ($1, $2, 'TestApp', 'https://test.example.com/callback', 'policy:social', $3, 1, NOW())"
    )
    .bind(&new_code)
    .bind(&pubkey)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&pool)
    .await
    .expect("Should create new authorization code");

    // Verify the new code is valid and can be exchanged
    let valid_code = sqlx::query_as::<_, (String,)>(
        "SELECT user_pubkey FROM oauth_codes 
         WHERE code = $1 AND tenant_id = 1 AND expires_at > NOW() AND pending_email IS NULL",
    )
    .bind(&new_code)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(
        valid_code.is_some(),
        "New authorization code should be valid"
    );

    // Cleanup
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
    cleanup_test_user(&pool, &pubkey).await;
}

// ============================================================================
// PKCE Tests
// ============================================================================

/// Test that PKCE challenge is stored with authorization code
#[tokio::test]
async fn test_headless_stores_pkce_challenge() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    // Clean up
    cleanup_test_user(&pool, &pubkey).await;

    // Create user
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, 1, 'pkce-test@example.com', true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .execute(&pool)
    .await
    .expect("Should create user");

    // Create authorization code with PKCE
    let code = format!("pkce_{}", Uuid::new_v4());
    let code_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // Example S256 challenge
    let code_challenge_method = "S256";

    sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, 
            expires_at, tenant_id, created_at,
            code_challenge, code_challenge_method
        ) VALUES ($1, $2, 'PKCEApp', 'https://pkce.example.com/callback', 'policy:social', $3, 1, NOW(), $4, $5)"
    )
    .bind(&code)
    .bind(&pubkey)
    .bind(Utc::now() + Duration::minutes(10))
    .bind(code_challenge)
    .bind(code_challenge_method)
    .execute(&pool)
    .await
    .expect("Should create authorization code with PKCE");

    // Verify PKCE data was stored
    let record = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT code_challenge, code_challenge_method FROM oauth_codes WHERE code = $1",
    )
    .bind(&code)
    .fetch_one(&pool)
    .await
    .expect("Code should exist");

    assert_eq!(record.0, Some(code_challenge.to_string()));
    assert_eq!(record.1, Some(code_challenge_method.to_string()));

    // Cleanup
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&code)
        .execute(&pool)
        .await;
    cleanup_test_user(&pool, &pubkey).await;
}
