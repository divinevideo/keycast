// NIP-46 Client Pubkey Tracking Tests
// Tests that the signer properly tracks client pubkeys after connect and validates subsequent requests
//
// TDD: These tests are written BEFORE the implementation. They should fail initially.

use keycast_core::encryption::{KeyManager, file_key_manager::FileKeyManager};
use keycast_core::signing_handler::SigningHandler;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use keycast_signer::AuthorizationHandler;
use nostr_sdk::prelude::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Helper to create test database with schema
async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

    let pool = PgPool::connect(&database_url).await
        .expect("Failed to connect to database. Make sure PostgreSQL is running.");

    pool
}

/// Helper to create OAuth authorization for testing client pubkey tracking
async fn create_oauth_authorization_for_client_test(
    pool: &PgPool,
    tenant_id: i64,
    key_manager: &dyn KeyManager,
) -> (OAuthAuthorization, Keys, String) {
    // Generate user keys (used for both bunker and signing in OAuth)
    let user_keys = Keys::generate();

    // Generate unique secret for this test
    let unique_secret = format!("client_test_secret_{}", Uuid::new_v4());

    // Create user first
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING"
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
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, bunker_secret, tenant_id)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(&unique_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    // Create OAuth application
    let client_secret = format!("client_secret_{}", Uuid::new_v4());
    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let app_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (name, redirect_origin, client_secret, redirect_uris, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (redirect_origin, tenant_id) DO UPDATE SET id = oauth_applications.id
         RETURNING id"
    )
    .bind("Client Test App")
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
         (user_pubkey, redirect_origin, application_id, bunker_public_key, bunker_secret, secret, relays, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
         RETURNING id"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&redirect_origin)
    .bind(app_id)
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(&unique_secret)
    .bind(json!(["wss://relay.damus.io"]))
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create OAuth authorization");

    // Load OAuth authorization
    let oauth_auth = OAuthAuthorization::find(pool, tenant_id, oauth_id).await
        .expect("Failed to load OAuth authorization");

    (oauth_auth, user_keys, unique_secret)
}

// ============================================================================
// TEST 1: Successful connect stores client pubkey in database
// ============================================================================
#[tokio::test]
async fn test_connect_stores_client_pubkey() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    // Create OAuth authorization
    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    // Create handler
    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Simulate client connecting - client generates ephemeral keypair
    let client_keys = Keys::generate();
    let client_pubkey = client_keys.public_key().to_hex();

    // Process connect request (this method needs to be implemented)
    let result = handler.process_connect(&client_pubkey, &secret).await;
    assert!(result.is_ok(), "Connect should succeed with valid secret");
    assert_eq!(result.unwrap(), "ack", "Connect should return 'ack'");

    // Verify client pubkey was stored in database
    let stored_client: Option<String> = sqlx::query_scalar(
        "SELECT connected_client_pubkey FROM oauth_authorizations WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");

    assert!(stored_client.is_some(), "connected_client_pubkey should be stored");
    assert_eq!(stored_client.unwrap(), client_pubkey, "Stored client pubkey should match");
}

// ============================================================================
// TEST 2: Second connect with same secret from different client is rejected
// ============================================================================
#[tokio::test]
async fn test_connect_rejects_reused_secret() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    // Create OAuth authorization
    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // First client connects successfully
    let client_a = Keys::generate();
    let result = handler.process_connect(&client_a.public_key().to_hex(), &secret).await;
    assert!(result.is_ok(), "First connect should succeed");

    // Second client tries to use same secret
    let client_b = Keys::generate();
    let result = handler.process_connect(&client_b.public_key().to_hex(), &secret).await;

    // Should be rejected - secret already used by client_a
    assert!(result.is_err(), "Second connect with same secret should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("already used") || err_msg.contains("Secret"),
        "Error should indicate secret was already used, got: {}", err_msg
    );
}

// ============================================================================
// TEST 3: Same client reconnecting with same secret succeeds
// ============================================================================
#[tokio::test]
async fn test_same_client_can_reconnect() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();

    let result = handler.process_connect(&client_pubkey, &secret).await;
    assert!(result.is_ok(), "First connect should succeed");

    // Same client reconnects (e.g., after app restart)
    let result = handler.process_connect(&client_pubkey, &secret).await;
    assert!(result.is_ok(), "Reconnect from same client should succeed");
}

// ============================================================================
// TEST 4: Request from connected client succeeds
// ============================================================================
#[tokio::test]
async fn test_request_from_connected_client_succeeds() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects first
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();
    handler.process_connect(&client_pubkey, &secret).await
        .expect("Connect should succeed");

    // Now client makes a sign request
    let unsigned = EventBuilder::text_note("Hello world")
        .build(user_keys.public_key());

    // validate_client should pass for this client
    let validation = handler.validate_client(&client_pubkey).await;
    assert!(validation.is_ok(), "Request from connected client should be validated");

    // Actually sign the event
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_ok(), "Sign should succeed from connected client");
}

// ============================================================================
// TEST 5: Request from unknown client is rejected
// ============================================================================
#[tokio::test]
async fn test_request_from_unknown_client_rejected() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client A connects
    let client_a = Keys::generate();
    handler.process_connect(&client_a.public_key().to_hex(), &secret).await
        .expect("Connect should succeed");

    // Client B (never connected) tries to make a request
    let client_b = Keys::generate();
    let validation = handler.validate_client(&client_b.public_key().to_hex()).await;

    assert!(validation.is_err(), "Request from unknown client should be rejected");
    let err_msg = validation.unwrap_err().to_string();
    assert!(
        err_msg.contains("Unknown client") || err_msg.contains("not connected"),
        "Error should indicate unknown client, got: {}", err_msg
    );
}

// ============================================================================
// TEST 6: First request without connect stores client pubkey (graceful upgrade)
// ============================================================================
#[tokio::test]
async fn test_first_request_without_connect_allowed() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Verify no client is connected yet
    let stored_client: Option<String> = sqlx::query_scalar(
        "SELECT connected_client_pubkey FROM oauth_authorizations WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");
    assert!(stored_client.is_none(), "No client should be connected initially");

    // Client makes request without explicit connect (NULL means accept first client)
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();

    // validate_and_store_client should store the client on first request
    let validation = handler.validate_and_store_client(&client_pubkey).await;
    assert!(validation.is_ok(), "First request should be allowed when no client connected");

    // Verify client was stored
    let stored_client: Option<String> = sqlx::query_scalar(
        "SELECT connected_client_pubkey FROM oauth_authorizations WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");
    assert!(stored_client.is_some(), "Client should be stored after first request");
    assert_eq!(stored_client.unwrap(), client_pubkey);
}

// ============================================================================
// TEST 7: Revocation clears client pubkey
// ============================================================================
#[tokio::test]
async fn test_revocation_clears_client_pubkey() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();
    handler.process_connect(&client_pubkey, &secret).await
        .expect("Connect should succeed");

    // Verify client is stored
    let stored_client: Option<String> = sqlx::query_scalar(
        "SELECT connected_client_pubkey FROM oauth_authorizations WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");
    assert!(stored_client.is_some(), "Client should be stored");

    // Simulate revocation (directly update DB - API would call this)
    sqlx::query(
        "UPDATE oauth_authorizations SET connected_client_pubkey = NULL, connected_at = NULL WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .execute(&pool)
    .await
    .expect("Failed to revoke");

    // Request from previously-connected client should now fail
    let validation = handler.validate_client(&client_pubkey).await;

    // After revocation, client must reconnect
    assert!(validation.is_err(), "Request after revocation should require reconnect");
}

// ============================================================================
// TEST 8: connected_at timestamp is set on connect
// ============================================================================
#[tokio::test]
async fn test_connected_at_timestamp_set() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = AuthorizationHandler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        secret.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects
    let client = Keys::generate();
    handler.process_connect(&client.public_key().to_hex(), &secret).await
        .expect("Connect should succeed");

    // Verify connected_at is set
    let connected_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT connected_at FROM oauth_authorizations WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");

    assert!(connected_at.is_some(), "connected_at should be set after connect");
}
