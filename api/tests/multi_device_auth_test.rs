// ABOUTME: Tests for multi-device OAuth authorization support
// ABOUTME: Verifies that multiple authorizations can exist per app and revoked_at filtering works

mod common;

use chrono::Utc;
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

/// Helper to create a test user
async fn create_test_user(pool: &PgPool) -> String {
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, 1, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(&user_pubkey)
    .execute(pool)
    .await
    .unwrap();

    user_pubkey
}

/// Helper to create a test OAuth app
async fn create_test_app(pool: &PgPool, name: &str) -> (i32, String) {
    let redirect_origin = format!("https://{}-{}.example.com", name, Uuid::new_v4());

    let app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 'secret', '[]', 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(name)
    .bind(&redirect_origin)
    .fetch_one(pool)
    .await
    .unwrap();

    (app_id, redirect_origin)
}

/// Test that multiple authorizations can exist for the same user+app combination.
/// This is the core multi-device feature - each "Accept" creates a NEW authorization.
#[tokio::test]
async fn test_multiple_authorizations_per_app_allowed() {
    let pool = setup_pool().await;
    let user_pubkey = create_test_user(&pool).await;
    let (app_id, redirect_origin) = create_test_app(&pool, "multi-device-test").await;

    // Create first authorization (Device A)
    let bunker_keys_1 = Keys::generate();
    let bunker_pubkey_1 = bunker_keys_1.public_key().to_hex();

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', 1, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_1)
    .execute(&pool)
    .await
    .expect("First authorization should be created");

    // Create second authorization for SAME user+app (Device B)
    // This should NOT conflict - we want multiple auths per app
    let bunker_keys_2 = Keys::generate();
    let bunker_pubkey_2 = bunker_keys_2.public_key().to_hex();

    let result = sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret2', '[]', 1, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_2)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "Second authorization for same user+app should succeed (multi-device support)"
    );

    // Verify both authorizations exist
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations
         WHERE user_pubkey = $1 AND redirect_origin = $2",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        count, 2,
        "User should have 2 authorizations for the same app (one per device)"
    );
}

/// Test that revoked_at filtering excludes revoked authorizations
#[tokio::test]
async fn test_revoked_at_filtering() {
    let pool = setup_pool().await;
    let user_pubkey = create_test_user(&pool).await;
    let (app_id, redirect_origin) = create_test_app(&pool, "revoke-test").await;

    // Create two authorizations
    let bunker_keys_1 = Keys::generate();
    let bunker_pubkey_1 = bunker_keys_1.public_key().to_hex();
    let bunker_keys_2 = Keys::generate();
    let bunker_pubkey_2 = bunker_keys_2.public_key().to_hex();

    // First auth - will be revoked
    let auth_id_1: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_1)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Second auth - will remain active
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret2', '[]', 1, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_2)
    .execute(&pool)
    .await
    .unwrap();

    // Revoke first authorization (soft-delete)
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
        .bind(auth_id_1)
        .execute(&pool)
        .await
        .unwrap();

    // Count ACTIVE authorizations (revoked_at IS NULL)
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations
         WHERE user_pubkey = $1 AND redirect_origin = $2 AND revoked_at IS NULL",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        active_count, 1,
        "Only 1 authorization should be active after revoking one"
    );

    // Count ALL authorizations (including revoked)
    let total_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations
         WHERE user_pubkey = $1 AND redirect_origin = $2",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        total_count, 2,
        "Both authorizations should still exist in database (soft-delete)"
    );
}

/// Test that the signer daemon query filters out revoked authorizations
#[tokio::test]
async fn test_signer_daemon_filters_revoked() {
    let pool = setup_pool().await;
    let user_pubkey = create_test_user(&pool).await;
    let (app_id, redirect_origin) = create_test_app(&pool, "signer-filter-test").await;

    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();

    // Create and immediately revoke an authorization
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at, revoked_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', 1, NOW(), NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Query like signer daemon does - should NOT find revoked auth
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM oauth_authorizations
         WHERE bunker_public_key = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        found.is_none(),
        "Signer daemon query should NOT find revoked authorization"
    );

    // Verify the auth exists when not filtering
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_authorizations WHERE id = $1)",
    )
    .bind(auth_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(exists, "Authorization should still exist in database");
}

/// Test that OAuth authorization type has revoked_at field
#[tokio::test]
async fn test_oauth_authorization_has_revoked_at_field() {
    let pool = setup_pool().await;

    // Check if revoked_at column exists
    let column_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'oauth_authorizations'
            AND column_name = 'revoked_at'
        )",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        column_exists,
        "oauth_authorizations table should have revoked_at column"
    );
}

/// Test that unique constraint on (tenant_id, user_pubkey, redirect_origin) is removed
#[tokio::test]
async fn test_unique_constraint_removed() {
    let pool = setup_pool().await;

    // Check if the unique constraint exists
    let constraint_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM pg_constraint
            WHERE conname = 'oauth_auth_user_origin_unique'
        )",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        !constraint_exists,
        "oauth_auth_user_origin_unique constraint should be removed for multi-device support"
    );
}

/// Test soft-delete revoke: authorization should have revoked_at set, not be deleted
#[tokio::test]
async fn test_soft_delete_revoke() {
    let pool = setup_pool().await;
    let user_pubkey = create_test_user(&pool).await;
    let (app_id, redirect_origin) = create_test_app(&pool, "soft-delete-test").await;

    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();

    // Create authorization
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Soft-delete (revoke)
    let before_revoke = Utc::now();
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
        .bind(auth_id)
        .execute(&pool)
        .await
        .unwrap();

    // Verify it still exists
    let (exists, revoked_at): (bool, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT true, revoked_at FROM oauth_authorizations WHERE id = $1",
    )
    .bind(auth_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(exists, "Authorization should still exist after soft-delete");
    assert!(
        revoked_at.is_some(),
        "revoked_at should be set after revoke"
    );
    assert!(
        revoked_at.unwrap() >= before_revoke,
        "revoked_at should be recent"
    );
}

/// Test auto-revoke: re-login should only revoke the SPECIFIC auth identified by auth_id in UCAN
/// This preserves multi-device support - other devices keep their authorizations
#[tokio::test]
async fn test_auto_revoke_specific_auth_from_ucan() {
    let pool = setup_pool().await;
    let user_pubkey = create_test_user(&pool).await;
    let (app_id, redirect_origin) = create_test_app(&pool, "auto-revoke-test").await;

    // Create first authorization (Device A)
    let bunker_keys_1 = Keys::generate();
    let bunker_pubkey_1 = bunker_keys_1.public_key().to_hex();

    let auth_id_1: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret1', '[]', 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_1)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create second authorization (Device B) - this should NOT be affected
    let bunker_keys_2 = Keys::generate();
    let bunker_pubkey_2 = bunker_keys_2.public_key().to_hex();

    let auth_id_2: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret2', '[]', 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_2)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Simulate auto-revoke: ONLY revoke the specific auth_id from UCAN (Device A re-logging in)
    // The auth_id comes from the UCAN facts during re-login
    sqlx::query(
        "UPDATE oauth_authorizations
         SET revoked_at = NOW()
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(auth_id_1)
    .execute(&pool)
    .await
    .unwrap();

    // Create third authorization (Device A re-login)
    let bunker_keys_3 = Keys::generate();
    let bunker_pubkey_3 = bunker_keys_3.public_key().to_hex();

    let _auth_id_3: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, application_id, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'secret3', '[]', 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(&bunker_pubkey_3)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Verify first auth (Device A old) is revoked
    let revoked_at_1: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT revoked_at FROM oauth_authorizations WHERE id = $1",
    )
    .bind(auth_id_1)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        revoked_at_1.is_some(),
        "First authorization (Device A) should be auto-revoked"
    );

    // Verify second auth (Device B) is still active - NOT affected by Device A re-login
    let revoked_at_2: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT revoked_at FROM oauth_authorizations WHERE id = $1",
    )
    .bind(auth_id_2)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        revoked_at_2.is_none(),
        "Second authorization (Device B) should NOT be revoked - multi-device preserved"
    );

    // Verify we now have 2 active authorizations (Device B + Device A new)
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations
         WHERE user_pubkey = $1 AND redirect_origin = $2 AND revoked_at IS NULL",
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        active_count, 2,
        "Should have 2 active authorizations (Device B + Device A new)"
    );
}

