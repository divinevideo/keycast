// Permission validation tests for signer daemon
// Tests that the signer properly enforces policy permissions before signing/encrypting/decrypting

use keycast_core::encryption::{KeyManager, file_key_manager::FileKeyManager};
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

    let pool = PgPool::connect(&database_url).await
        .expect("Failed to connect to database. Make sure PostgreSQL is running and DATABASE_URL is set.");

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
    let team_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND tenant_id = $2)"
    )
    .bind(team_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to check team existence");

    if !team_exists {
        sqlx::query(
            "INSERT INTO teams (name, tenant_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())"
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
         RETURNING id"
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
             RETURNING id"
        )
        .bind(identifier)
        .bind(config)
        .fetch_one(pool)
        .await
        .expect("Failed to create permission");

        // Link to policy
        sqlx::query(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())"
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
    let encrypted_secret = key_manager.encrypt(&user_secret).await
        .expect("Failed to encrypt user secret");

    // Create stored key
    let stored_key_id: i32 = sqlx::query_scalar(
        "INSERT INTO stored_keys (name, public_key, secret_key, team_id, tenant_id, created_at, updated_at)
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
    let encrypted_bunker_secret = key_manager.encrypt(&bunker_secret).await
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
    let auth = Authorization::find(pool, tenant_id, auth_id).await
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
        "INSERT INTO users (public_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (public_key) DO NOTHING"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create user");

    // Encrypt user secret for personal_keys
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager.encrypt(&user_secret).await
        .expect("Failed to encrypt user secret");

    sqlx::query(
        "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, bunker_secret, tenant_id)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(&unique_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    // Create OAuth application (required foreign key)
    let client_secret = format!("client_secret_{}", Uuid::new_v4());
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (redirect_origin, tenant_id) DO UPDATE SET id = oauth_applications.id
         RETURNING id"
    )
    .bind("Test App")
    .bind(&redirect_origin)
    .bind(&client_secret)
    .bind(json!(["http://localhost/callback"]))
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create OAuth application");

    // Create OAuth authorization
    let oauth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_public_key, redirect_origin, application_id, bunker_public_key, bunker_secret, secret, relays, policy_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
         RETURNING id"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(&unique_secret)
    .bind(json!(["wss://relay.damus.io"]))
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create OAuth authorization");

    // Load OAuth authorization
    let oauth_auth = OAuthAuthorization::find(pool, tenant_id, oauth_id).await
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
    let unsigned = EventBuilder::text_note("Hello world")
        .build(user_keys.public_key());

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
    let policy_id = create_policy_with_permissions(
        &pool, 1, 1,
        vec![("allowed_kinds", config)]
    ).await;

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
    let unsigned = EventBuilder::text_note("Hello world")
        .build(user_keys.public_key());

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
    let policy_id = create_policy_with_permissions(
        &pool, 1, 1,
        vec![("allowed_kinds", config)]
    ).await;

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
        err_msg.contains("permission") || err_msg.contains("Unauthorized") || err_msg.contains("denied"),
        "Error should mention permission denial, got: {}", err_msg
    );
}

#[tokio::test]
async fn test_4_content_filter_allows_clean_content() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Block words containing "spam"
    let config = json!({ "blocked_words": ["spam", "scam"] });
    let policy_id = create_policy_with_permissions(
        &pool, 1, 1,
        vec![("content_filter", config)]
    ).await;

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
    let policy_id = create_policy_with_permissions(
        &pool, 1, 1,
        vec![("content_filter", config)]
    ).await;

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
    let unsigned = EventBuilder::text_note("Buy my spam product now!")
        .build(user_keys.public_key());

    let result = handler.sign_event_direct(unsigned).await;

    // Should fail - contains "spam"
    assert!(result.is_err(), "Content with blocked words should be denied");
}

#[tokio::test]
async fn test_6_multiple_permissions_all_must_pass() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Policy with TWO permissions (AND logic):
    // 1. Only allow kind 1
    // 2. Block word "spam"
    let policy_id = create_policy_with_permissions(
        &pool, 1, 1,
        vec![
            ("allowed_kinds", json!({ "allowed_kinds": [1] })),
            ("content_filter", json!({ "blocked_words": ["spam"] })),
        ]
    ).await;

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
    let unsigned = EventBuilder::text_note("Hello world")
        .build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_ok(), "Kind 1 + clean content should pass both permissions");

    // Test B: Kind 1 with spam - allowed_kinds passes, content_filter fails
    let unsigned = EventBuilder::text_note("Buy spam products")
        .build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_err(), "Content filter should deny even if kind is allowed");

    // Test C: Kind 4 with clean content - allowed_kinds fails, content_filter passes
    let unsigned = EventBuilder::new(Kind::EncryptedDirectMessage, "Clean message")
        .build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_err(), "Wrong kind should deny even if content is clean");
}

#[tokio::test]
async fn test_7_oauth_no_policy_allows_all() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // OAuth auth with NULL policy_id
    let (oauth_auth, user_keys) =
        create_oauth_authorization(&pool, 1, None, &key_manager).await;

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
    assert!(result.is_ok(), "OAuth with no policy should allow all operations");
}

#[tokio::test]
async fn test_8_oauth_with_policy_enforces_restrictions() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Create policy only allowing kind 1
    let config = json!({ "allowed_kinds": [1] });
    let policy_id = create_policy_with_permissions(
        &pool, 1, 1,
        vec![("allowed_kinds", config)]
    ).await;

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
    let unsigned = EventBuilder::text_note("Hello")
        .build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_ok(), "OAuth with policy should allow kind 1");

    // Test B: Kind 4 - SHOULD FAIL
    let unsigned = EventBuilder::new(Kind::EncryptedDirectMessage, "Secret")
        .build(user_keys.public_key());
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_err(), "OAuth with policy should deny kind 4");
}

// TODO: Add tests for encrypt/decrypt validation
// TODO: Add test for invalid policy_id handling
// TODO: Add test for permission loading failure
