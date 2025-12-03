// Permission validation tests for signer daemon
// Tests that the signer properly enforces policy permissions before signing/encrypting/decrypting

use chrono::{Duration, Utc};
use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use keycast_core::signing_handler::SigningHandler;
use keycast_core::types::authorization::Authorization;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use keycast_signer::AuthorizationHandler;
use nostr_sdk::prelude::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Helper to create test database with schema
async fn setup_test_db() -> PgPool {
    // Use development database for tests
    // TODO: Use test-specific database with isolation
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

    let pool = PgPool::connect(&database_url).await.expect(
        "Failed to connect to database. Make sure PostgreSQL is running and DATABASE_URL is set.",
    );

    pool
}

/// Helper to create policy with specified permissions
async fn create_policy_with_permissions(
    pool: &PgPool,
    tenant_id: i64,
    team_id: i32,
    permission_configs: Vec<(&str, serde_json::Value)>,
) -> i32 {
    // Ensure team exists first (check if exists, create if not)
    let team_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND tenant_id = $2)")
            .bind(team_id)
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("Failed to check team existence");

    if !team_exists {
        sqlx::query(
            "INSERT INTO teams (name, tenant_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind("Test Team")
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("Failed to create team");
    }

    // Create policy (policies table doesn't have tenant_id)
    let policy_id: i32 = sqlx::query_scalar(
        "INSERT INTO policies (name, team_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("Test Policy {}", Uuid::new_v4()))
    .bind(team_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create policy");

    // Create and link permissions (permissions table doesn't have tenant_id)
    for (identifier, config) in permission_configs {
        let permission_id: i32 = sqlx::query_scalar(
            "INSERT INTO permissions (identifier, config, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id",
        )
        .bind(identifier)
        .bind(config)
        .fetch_one(pool)
        .await
        .expect("Failed to create permission");

        // Link to policy
        sqlx::query(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(policy_id)
        .bind(permission_id)
        .execute(pool)
        .await
        .expect("Failed to link permission to policy");
    }

    policy_id
}

/// Helper to create test authorization with policy
async fn create_test_authorization(
    pool: &PgPool,
    tenant_id: i64,
    team_id: i32,
    policy_id: i32,
    key_manager: &dyn KeyManager,
) -> (Authorization, Keys, Keys) {
    // Generate bunker and user keys
    let bunker_keys = Keys::generate();
    let user_keys = Keys::generate();

    // Encrypt user secret
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    // Create stored key
    let stored_key_id: i32 = sqlx::query_scalar(
        "INSERT INTO stored_keys (name, pubkey, secret_key, team_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         RETURNING id"
    )
    .bind("Test Key")
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(team_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create stored key");

    // Encrypt bunker secret
    let bunker_secret = bunker_keys.secret_key().secret_bytes();
    let encrypted_bunker_secret = key_manager
        .encrypt(&bunker_secret)
        .await
        .expect("Failed to encrypt bunker secret");

    // Generate unique secret for this test
    let unique_secret = format!("test_secret_{}", Uuid::new_v4());

    // Create authorization
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO authorizations
         (stored_key_id, secret, bunker_public_key, bunker_secret, relays, policy_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
         RETURNING id"
    )
    .bind(stored_key_id)
    .bind(&unique_secret)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&encrypted_bunker_secret)
    .bind(json!(["wss://relay.damus.io"]))
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create authorization");

    // Load authorization
    let auth = Authorization::find(pool, tenant_id, auth_id)
        .await
        .expect("Failed to load authorization");

    (auth, bunker_keys, user_keys)
}

/// Helper to create OAuth authorization with optional policy
async fn create_oauth_authorization(
    pool: &PgPool,
    tenant_id: i64,
    policy_id: Option<i32>,
    key_manager: &dyn KeyManager,
) -> (OAuthAuthorization, Keys) {
    // Generate user keys (used for both bunker and signing in OAuth)
    let user_keys = Keys::generate();

    // Generate unique secret for this test
    let unique_secret = format!("oauth_secret_{}", Uuid::new_v4());

    // Create user first
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(user_keys.public_key().to_hex())
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create user");

    // Encrypt user secret for personal_keys
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    // Create OAuth authorization (bunker key derived via HKDF, not stored)
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let oauth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, policy_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, $4, $5, $6, $7, NOW(), NOW())
         RETURNING id"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&redirect_origin)
    .bind(user_keys.public_key().to_hex())
    .bind(&unique_secret)
    .bind(json!(["wss://relay.damus.io"]))
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create OAuth authorization");

    // Load OAuth authorization
    let oauth_auth = OAuthAuthorization::find(pool, tenant_id, oauth_id)
        .await
        .expect("Failed to load OAuth authorization");

    (oauth_auth, user_keys)
}

// ============================================================================
// TESTS START HERE
// ============================================================================

#[tokio::test]
async fn test_1_no_policy_allows_all() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create empty policy (no permissions)
    let policy_id = create_policy_with_permissions(&pool, 1, 1, vec![]).await;

    let (auth, bunker_keys, user_keys) =
        create_test_authorization(&pool, 1, 1, policy_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        auth.secret.clone(),
        auth.id,
        1,
        false,
        pool.clone(),
    );

    // Try signing kind 1 event
    let unsigned = EventBuilder::text_note("Hello world").build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should succeed - empty policy means no restrictions
    if let Err(e) = &result {
        eprintln!("Test 1 failed with error: {:?}", e);
    }
    assert!(result.is_ok(), "Empty policy should allow all events");
}

#[tokio::test]
async fn test_2_allowed_kinds_permits_matching_kind() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create policy allowing only kind 1
    let config = json!({ "allowed_kinds": [1] });
    let policy_id =
        create_policy_with_permissions(&pool, 1, 1, vec![("allowed_kinds", config)]).await;

    let (auth, bunker_keys, user_keys) =
        create_test_authorization(&pool, 1, 1, policy_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        auth.secret.clone(),
        auth.id,
        1,
        false,
        pool.clone(),
    );

    // Try signing kind 1 event
    let unsigned = EventBuilder::text_note("Hello world").build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should succeed - kind 1 is in allowed list
    if let Err(e) = &result {
        eprintln!("Test 2 failed with error: {:?}", e);
    }
    assert!(result.is_ok(), "Kind 1 should be allowed by policy");
}

#[tokio::test]
async fn test_3_allowed_kinds_denies_non_matching_kind() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create policy allowing only kind 1
    let config = json!({ "allowed_kinds": [1] });
    let policy_id =
        create_policy_with_permissions(&pool, 1, 1, vec![("allowed_kinds", config)]).await;

    let (auth, bunker_keys, user_keys) =
        create_test_authorization(&pool, 1, 1, policy_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        auth.secret.clone(),
        auth.id,
        1,
        false,
        pool.clone(),
    );

    // Try signing kind 4 (encrypted DM) - NOT in allowed list
    let unsigned = EventBuilder::new(Kind::EncryptedDirectMessage, "Secret message")
        .build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should fail - kind 4 not allowed
    assert!(result.is_err(), "Kind 4 should be denied by policy");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("permission")
            || err_msg.contains("Unauthorized")
            || err_msg.contains("denied"),
        "Error should mention permission denial, got: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_4_content_filter_allows_clean_content() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Block words containing "spam"
    let config = json!({ "blocked_words": ["spam", "scam"] });
    let policy_id =
        create_policy_with_permissions(&pool, 1, 1, vec![("content_filter", config)]).await;

    let (auth, bunker_keys, user_keys) =
        create_test_authorization(&pool, 1, 1, policy_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        auth.secret.clone(),
        auth.id,
        1,
        false,
        pool.clone(),
    );

    // Clean content
    let unsigned = EventBuilder::text_note("This is a legitimate message about good things")
        .build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should succeed - no blocked words
    assert!(result.is_ok(), "Clean content should be allowed");
}

#[tokio::test]
async fn test_5_content_filter_denies_blocked_words() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Block words containing "spam"
    let config = json!({ "blocked_words": ["spam", "scam"] });
    let policy_id =
        create_policy_with_permissions(&pool, 1, 1, vec![("content_filter", config)]).await;

    let (auth, bunker_keys, user_keys) =
        create_test_authorization(&pool, 1, 1, policy_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        auth.secret.clone(),
        auth.id,
        1,
        false,
        pool.clone(),
    );

    // Content with blocked word
    let unsigned =
        EventBuilder::text_note("Buy my spam product now!").build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should fail - contains "spam"
    assert!(
        result.is_err(),
        "Content with blocked words should be denied"
    );
}

#[tokio::test]
async fn test_6_multiple_permissions_all_must_pass() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Policy with TWO permissions (AND logic):
    // 1. Only allow kind 1
    // 2. Block word "spam"
    let policy_id = create_policy_with_permissions(
        &pool,
        1,
        1,
        vec![
            ("allowed_kinds", json!({ "allowed_kinds": [1] })),
            ("content_filter", json!({ "blocked_words": ["spam"] })),
        ],
    )
    .await;

    let (auth, bunker_keys, user_keys) =
        create_test_authorization(&pool, 1, 1, policy_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        auth.secret.clone(),
        auth.id,
        1,
        false,
        pool.clone(),
    );

    // Test A: Kind 1 with clean content - BOTH permissions pass
    let unsigned = EventBuilder::text_note("Hello world").build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(
        result.is_ok(),
        "Kind 1 + clean content should pass both permissions"
    );

    // Test B: Kind 1 with spam - allowed_kinds passes, content_filter fails
    let unsigned = EventBuilder::text_note("Buy spam products").build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(
        result.is_err(),
        "Content filter should deny even if kind is allowed"
    );

    // Test C: Kind 4 with clean content - allowed_kinds fails, content_filter passes
    let unsigned = EventBuilder::new(Kind::EncryptedDirectMessage, "Clean message")
        .build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(
        result.is_err(),
        "Wrong kind should deny even if content is clean"
    );
}

#[tokio::test]
async fn test_7_oauth_no_policy_allows_all() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // OAuth auth with NULL policy_id
    let (oauth_auth, user_keys) = create_oauth_authorization(&pool, 1, None, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret.clone(),
        oauth_auth.id,
        1,
        true,
        pool.clone(),
    );

    // Try signing any kind - should succeed
    let unsigned = EventBuilder::new(Kind::EncryptedDirectMessage, "Test message")
        .build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should succeed - no policy means allow all
    assert!(
        result.is_ok(),
        "OAuth with no policy should allow all operations"
    );
}

#[tokio::test]
async fn test_8_oauth_with_policy_enforces_restrictions() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create policy only allowing kind 1
    let config = json!({ "allowed_kinds": [1] });
    let policy_id =
        create_policy_with_permissions(&pool, 1, 1, vec![("allowed_kinds", config)]).await;

    // OAuth auth WITH policy_id
    let (oauth_auth, user_keys) =
        create_oauth_authorization(&pool, 1, Some(policy_id), &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret.clone(),
        oauth_auth.id,
        1,
        true,
        pool.clone(),
    );

    // Test A: Kind 1 - SHOULD PASS
    let unsigned = EventBuilder::text_note("Hello").build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_ok(), "OAuth with policy should allow kind 1");

    // Test B: Kind 4 - SHOULD FAIL
    let unsigned =
        EventBuilder::new(Kind::EncryptedDirectMessage, "Secret").build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_err(), "OAuth with policy should deny kind 4");
}

// ============================================================================
// EXPIRY TESTS
// ============================================================================

/// Helper to create OAuth authorization with expiry date for testing
async fn create_oauth_authorization_with_expiry(
    pool: &PgPool,
    tenant_id: i64,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    key_manager: &dyn KeyManager,
) -> (String, Keys) {
    // Generate user keys
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Generate unique secret for this test
    let unique_secret = format!("oauth_secret_{}", Uuid::new_v4());

    // Derive bunker keys using HKDF (same as production)
    let bunker_keys =
        keycast_core::bunker_key::derive_bunker_keys(user_keys.secret_key(), &unique_secret);
    let bunker_pubkey = bunker_keys.public_key().to_hex();

    // Create user first
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

    // Encrypt user secret for personal_keys
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(&user_pubkey)
    .bind(&encrypted_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    // Create OAuth authorization with specified expiry
    let redirect_origin = format!("https://expiry-test-{}.example.com", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret, relays, policy_id, tenant_id, expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Test App', $3, $4, $5, NULL, $6, $7, NOW(), NOW())"
    )
    .bind(&user_pubkey)
    .bind(&redirect_origin)
    .bind(&bunker_pubkey)
    .bind(&unique_secret)
    .bind(json!(["wss://relay.damus.io"]).to_string())
    .bind(tenant_id)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("Failed to create OAuth authorization");

    (bunker_pubkey, user_keys)
}

#[tokio::test]
async fn test_9_expired_oauth_authorization_not_loaded() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create OAuth authorization that expired 1 hour ago
    let expired_at = Utc::now() - Duration::hours(1);
    let (bunker_pubkey, _user_keys) =
        create_oauth_authorization_with_expiry(&pool, 1, Some(expired_at), &key_manager).await;

    // Query using the same SQL the signer uses (lines 761-771 in signer_daemon.rs)
    let auth_opt: Option<OAuthAuthorization> = sqlx::query_as(
        r#"
        SELECT * FROM oauth_authorizations
        WHERE bunker_public_key = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should NOT find the expired authorization
    assert!(
        auth_opt.is_none(),
        "Expired OAuth authorization should not be loaded by signer"
    );
}

#[tokio::test]
async fn test_10_non_expired_oauth_authorization_loads() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create OAuth authorization that expires in 1 hour (still valid)
    let expires_at = Utc::now() + Duration::hours(1);
    let (bunker_pubkey, _user_keys) =
        create_oauth_authorization_with_expiry(&pool, 1, Some(expires_at), &key_manager).await;

    // Query using the same SQL the signer uses
    let auth_opt: Option<OAuthAuthorization> = sqlx::query_as(
        r#"
        SELECT * FROM oauth_authorizations
        WHERE bunker_public_key = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should find the non-expired authorization
    assert!(
        auth_opt.is_some(),
        "Non-expired OAuth authorization should be loaded by signer"
    );
}

#[tokio::test]
async fn test_11_null_expiry_oauth_authorization_loads() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create OAuth authorization with NULL expires_at (never expires)
    let (bunker_pubkey, _user_keys) =
        create_oauth_authorization_with_expiry(&pool, 1, None, &key_manager).await;

    // Query using the same SQL the signer uses
    let auth_opt: Option<OAuthAuthorization> = sqlx::query_as(
        r#"
        SELECT * FROM oauth_authorizations
        WHERE bunker_public_key = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should find the authorization (NULL expiry means never expires)
    assert!(
        auth_opt.is_some(),
        "OAuth authorization with NULL expiry should be loaded by signer"
    );
}

#[tokio::test]
async fn test_12_revoked_oauth_authorization_not_loaded() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create OAuth authorization (not expired)
    let expires_at = Utc::now() + Duration::hours(1);
    let (bunker_pubkey, _user_keys) =
        create_oauth_authorization_with_expiry(&pool, 1, Some(expires_at), &key_manager).await;

    // Revoke the authorization
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE bunker_public_key = $1")
        .bind(&bunker_pubkey)
        .execute(&pool)
        .await
        .expect("Failed to revoke authorization");

    // Query using the same SQL the signer uses
    let auth_opt: Option<OAuthAuthorization> = sqlx::query_as(
        r#"
        SELECT * FROM oauth_authorizations
        WHERE bunker_public_key = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should NOT find the revoked authorization
    assert!(
        auth_opt.is_none(),
        "Revoked OAuth authorization should not be loaded by signer"
    );
}

// ============================================================================
// TEAM AUTHORIZATION EXPIRY TESTS
// ============================================================================

/// Helper to create team authorization with expiry date for testing
async fn create_team_authorization_with_expiry(
    pool: &PgPool,
    tenant_id: i64,
    team_id: i32,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    key_manager: &dyn KeyManager,
) -> (String, Keys, Keys) {
    // Ensure team exists first
    let team_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND tenant_id = $2)")
            .bind(team_id)
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("Failed to check team existence");

    if !team_exists {
        sqlx::query(
            "INSERT INTO teams (name, tenant_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind("Test Team for Expiry")
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("Failed to create team");
    }

    // Generate bunker and user keys
    let bunker_keys = Keys::generate();
    let user_keys = Keys::generate();

    // Encrypt user secret
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    // Create stored key
    let stored_key_id: i32 = sqlx::query_scalar(
        "INSERT INTO stored_keys (name, pubkey, secret_key, team_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         RETURNING id"
    )
    .bind(format!("Test Key {}", Uuid::new_v4()))
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(team_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create stored key");

    // Encrypt bunker secret
    let bunker_secret = bunker_keys.secret_key().secret_bytes();
    let encrypted_bunker_secret = key_manager
        .encrypt(&bunker_secret)
        .await
        .expect("Failed to encrypt bunker secret");

    let unique_secret = format!("test_secret_{}", Uuid::new_v4());
    let bunker_pubkey = bunker_keys.public_key().to_hex();

    // Create authorization with specified expiry
    sqlx::query(
        "INSERT INTO authorizations
         (stored_key_id, secret, bunker_public_key, bunker_secret, relays, policy_id, tenant_id, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, NOW(), NOW())"
    )
    .bind(stored_key_id)
    .bind(&unique_secret)
    .bind(&bunker_pubkey)
    .bind(&encrypted_bunker_secret)
    .bind(json!(["wss://relay.damus.io"]).to_string())
    .bind(tenant_id)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("Failed to create authorization");

    (bunker_pubkey, bunker_keys, user_keys)
}

#[tokio::test]
async fn test_13_expired_team_authorization_not_loaded() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create team authorization that expired 1 hour ago
    let expired_at = Utc::now() - Duration::hours(1);
    let (bunker_pubkey, _bunker_keys, _user_keys) =
        create_team_authorization_with_expiry(&pool, 1, 1, Some(expired_at), &key_manager).await;

    // Query using the same SQL the signer uses (lines 843-851 in signer_daemon.rs)
    let auth_opt: Option<(i32, Vec<u8>, String, i32, i64)> = sqlx::query_as(
        r#"SELECT id, bunker_secret, secret, stored_key_id, tenant_id
           FROM authorizations
           WHERE bunker_public_key = $1
             AND (expires_at IS NULL OR expires_at > NOW())"#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should NOT find the expired authorization
    assert!(
        auth_opt.is_none(),
        "Expired team authorization should not be loaded by signer"
    );
}

#[tokio::test]
async fn test_14_non_expired_team_authorization_loads() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create team authorization that expires in 1 hour (still valid)
    let expires_at = Utc::now() + Duration::hours(1);
    let (bunker_pubkey, _bunker_keys, _user_keys) =
        create_team_authorization_with_expiry(&pool, 1, 1, Some(expires_at), &key_manager).await;

    // Query using the same SQL the signer uses
    let auth_opt: Option<(i32, Vec<u8>, String, i32, i64)> = sqlx::query_as(
        r#"SELECT id, bunker_secret, secret, stored_key_id, tenant_id
           FROM authorizations
           WHERE bunker_public_key = $1
             AND (expires_at IS NULL OR expires_at > NOW())"#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should find the non-expired authorization
    assert!(
        auth_opt.is_some(),
        "Non-expired team authorization should be loaded by signer"
    );
}

#[tokio::test]
async fn test_15_null_expiry_team_authorization_loads() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create team authorization with NULL expires_at (never expires)
    let (bunker_pubkey, _bunker_keys, _user_keys) =
        create_team_authorization_with_expiry(&pool, 1, 1, None, &key_manager).await;

    // Query using the same SQL the signer uses
    let auth_opt: Option<(i32, Vec<u8>, String, i32, i64)> = sqlx::query_as(
        r#"SELECT id, bunker_secret, secret, stored_key_id, tenant_id
           FROM authorizations
           WHERE bunker_public_key = $1
             AND (expires_at IS NULL OR expires_at > NOW())"#,
    )
    .bind(&bunker_pubkey)
    .fetch_optional(&pool)
    .await
    .expect("Query failed");

    // Should find the authorization (NULL expiry means never expires)
    assert!(
        auth_opt.is_some(),
        "Team authorization with NULL expiry should be loaded by signer"
    );
}

// TODO: Add tests for encrypt/decrypt validation
// TODO: Add test for invalid policy_id handling
// TODO: Add test for permission loading failure
