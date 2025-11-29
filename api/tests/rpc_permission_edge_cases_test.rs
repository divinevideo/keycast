// ABOUTME: Tests for RPC permission validation edge cases
// ABOUTME: Covers UCAN validation, authorization lookup, and policy enforcement

use chrono::{Duration, Utc};
use keycast_api::ucan_auth::{NostrKeyMaterial, nostr_pubkey_to_did, validate_ucan_token};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use nostr_sdk::prelude::*;
use serde_json::json;
use sqlx::PgPool;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

// ============================================================================
// Test Helpers
// ============================================================================

/// Connect to test database
async fn setup_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

/// Create an isolated test tenant
async fn create_test_tenant(pool: &PgPool) -> i64 {
    let domain = format!("test-{}.example.com", Uuid::new_v4());
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id"
    )
    .bind(&domain)
    .bind("Test Tenant")
    .fetch_one(pool)
    .await
    .expect("Failed to create test tenant")
}

/// Create a test user and return (Keys, pubkey_hex)
fn create_test_user() -> (Keys, String) {
    let keys = Keys::generate();
    let pubkey_hex = keys.public_key().to_hex();
    (keys, pubkey_hex)
}

/// Insert user into database
async fn insert_user(pool: &PgPool, tenant_id: i64, pubkey: &str) {
    sqlx::query(
        "INSERT INTO users (public_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (public_key) DO NOTHING"
    )
    .bind(pubkey)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to insert user");
}

/// Create personal_keys entry (required for oauth_authorizations)
async fn create_personal_key(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    user_keys: &Keys,
    key_manager: &dyn KeyManager,
) {
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    let bunker_secret = format!("bunker_secret_{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, bunker_secret, tenant_id)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(user_pubkey)
    .bind(&encrypted_secret)
    .bind(&bunker_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");
}

/// Create oauth_authorization with specific settings
#[allow(clippy::too_many_arguments)]
async fn create_test_authorization(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    policy_id: Option<i32>,
    expires_at: Option<chrono::DateTime<Utc>>,
    key_manager: &dyn KeyManager,
) -> i32 {
    // Generate bunker keys
    let bunker_keys = Keys::generate();
    let bunker_secret = bunker_keys.secret_key().secret_bytes();
    let encrypted_bunker_secret = key_manager
        .encrypt(&bunker_secret)
        .await
        .expect("Failed to encrypt bunker secret");

    let secret = format!("auth_secret_{}", Uuid::new_v4());

    sqlx::query_scalar::<_, i32>(
        "INSERT INTO oauth_authorizations
         (user_public_key, redirect_origin, bunker_public_key, bunker_secret, secret, relays, policy_id, tenant_id, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
         RETURNING id"
    )
    .bind(user_pubkey)
    .bind(redirect_origin)
    .bind(bunker_keys.public_key().to_hex())
    .bind(&encrypted_bunker_secret)
    .bind(&secret)
    .bind(json!(["wss://relay.damus.io"]).to_string())
    .bind(policy_id)
    .bind(tenant_id)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .expect("Failed to create oauth authorization")
}

/// Create a policy with permissions
/// Note: policies are associated with teams, not tenants directly
async fn create_test_policy(
    pool: &PgPool,
    _tenant_id: i64,  // Keep for API consistency, but policies don't have tenant_id
    permissions: Vec<(&str, serde_json::Value)>,
) -> i32 {
    // Create policy (no tenant_id - policies belong to teams)
    let policy_id: i32 = sqlx::query_scalar(
        "INSERT INTO policies (name, created_at, updated_at)
         VALUES ($1, NOW(), NOW())
         RETURNING id"
    )
    .bind(format!("Test Policy {}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("Failed to create policy");

    // Create and link permissions (permissions also don't have tenant_id)
    for (identifier, config) in permissions {
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

/// Build a UCAN with specific facts
async fn build_test_ucan(
    keys: &Keys,
    tenant_id: i64,
    redirect_origin: Option<&str>,
) -> String {
    let pubkey = keys.public_key();
    let user_did = nostr_pubkey_to_did(&pubkey);
    let key_material = NostrKeyMaterial::from_keys(keys.clone());

    let mut facts = json!({
        "tenant_id": tenant_id,
        "email": "test@example.com"
    });

    if let Some(origin) = redirect_origin {
        facts["redirect_origin"] = json!(origin);
    }

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap();

    ucan.encode().unwrap()
}

// ============================================================================
// Test 1: UCAN Missing redirect_origin
// ============================================================================

#[tokio::test]
async fn test_ucan_without_redirect_origin_rejected() {
    let (keys, _pubkey) = create_test_user();

    // Build UCAN without redirect_origin
    let token = build_test_ucan(&keys, 1, None).await;
    let auth_header = format!("Bearer {}", token);

    // Validation should fail
    let result = validate_ucan_token(&auth_header, 1);

    assert!(result.is_err(), "UCAN without redirect_origin should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("redirect_origin"),
        "Error should mention redirect_origin, got: {}", err
    );
}

// ============================================================================
// Test 2: No Authorization for Origin
// ============================================================================

#[tokio::test]
async fn test_no_authorization_for_origin_returns_forbidden() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Insert user but don't create authorization
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &keys, &key_manager).await;

    // Call get_authorization_for_origin directly
    let redirect_origin = format!("https://no-auth-{}.example.com", Uuid::new_v4());

    let result = keycast_api::api::http::auth::get_authorization_for_origin(
        &pool,
        &pubkey,
        &redirect_origin,
        tenant_id,
    ).await;

    assert!(result.is_err(), "Should return error when no authorization exists");

    // Check it's a Forbidden error
    match result {
        Err(keycast_api::api::http::auth::AuthError::Forbidden(msg)) => {
            assert!(msg.contains("No authorization"), "Should mention no authorization: {}", msg);
        }
        other => panic!("Expected Forbidden error, got: {:?}", other),
    }
}

// ============================================================================
// Test 3: NULL policy_id Grants Full Access
// ============================================================================

#[tokio::test]
async fn test_null_policy_grants_full_access() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user and authorization
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &keys, &key_manager).await;

    let redirect_origin = format!("https://full-access-{}.example.com", Uuid::new_v4());

    // Create authorization with NULL policy_id (full access)
    create_test_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        None,  // NULL policy_id = full access
        None,
        &key_manager,
    ).await;

    // Create any event (kind 4 - encrypted DM, which would normally be restricted)
    let unsigned_event = EventBuilder::new(Kind::EncryptedDirectMessage, "Secret message")
        .build(keys.public_key());

    // Validate permissions - should succeed
    let result = keycast_api::api::http::auth::validate_signing_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        &unsigned_event,
    ).await;

    assert!(result.is_ok(), "NULL policy_id should grant full access, got: {:?}", result);
}

// ============================================================================
// Test 4: Policy Enforces Kind Restrictions
// ============================================================================

#[tokio::test]
async fn test_policy_enforces_kind_restrictions() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &keys, &key_manager).await;

    // Create policy that only allows kind 1 (text notes)
    let policy_id = create_test_policy(
        &pool,
        tenant_id,
        vec![("allowed_kinds", json!({"allowed_kinds": [1]}))],
    ).await;

    let redirect_origin = format!("https://restricted-{}.example.com", Uuid::new_v4());

    // Create authorization with the restrictive policy
    create_test_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        Some(policy_id),
        None,
        &key_manager,
    ).await;

    // Test A: Kind 1 should succeed
    let kind1_event = EventBuilder::text_note("Hello world")
        .build(keys.public_key());

    let result = keycast_api::api::http::auth::validate_signing_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        &kind1_event,
    ).await;
    assert!(result.is_ok(), "Kind 1 should be allowed: {:?}", result);

    // Test B: Kind 4 (encrypted DM) should fail
    let kind4_event = EventBuilder::new(Kind::EncryptedDirectMessage, "Secret")
        .build(keys.public_key());

    let result = keycast_api::api::http::auth::validate_signing_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        &kind4_event,
    ).await;
    assert!(result.is_err(), "Kind 4 should be denied by policy");
}

// ============================================================================
// Test 5: Expired Authorization Rejected
// ============================================================================

#[tokio::test]
async fn test_expired_authorization_rejected() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &keys, &key_manager).await;

    let redirect_origin = format!("https://expired-{}.example.com", Uuid::new_v4());

    // Create authorization that expired 1 hour ago
    let expired_at = Utc::now() - Duration::hours(1);
    create_test_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        None,
        Some(expired_at),
        &key_manager,
    ).await;

    // Lookup should fail
    let result = keycast_api::api::http::auth::get_authorization_for_origin(
        &pool,
        &pubkey,
        &redirect_origin,
        tenant_id,
    ).await;

    assert!(result.is_err(), "Expired authorization should be rejected");
    match result {
        Err(keycast_api::api::http::auth::AuthError::Forbidden(msg)) => {
            assert!(msg.contains("No authorization"), "Should say no authorization: {}", msg);
        }
        other => panic!("Expected Forbidden error, got: {:?}", other),
    }
}

// ============================================================================
// Test 6: Encrypt Requires Authorization
// ============================================================================

#[tokio::test]
async fn test_encrypt_requires_authorization() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user but NO authorization
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &keys, &key_manager).await;

    let redirect_origin = format!("https://no-encrypt-auth-{}.example.com", Uuid::new_v4());
    let recipient = Keys::generate().public_key();

    // Validate encrypt permissions - should fail (no authorization)
    let result = keycast_api::api::http::auth::validate_encrypt_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        "test plaintext",
        &recipient,
    ).await;

    assert!(result.is_err(), "Encrypt should require authorization");
    match result {
        Err(keycast_api::api::http::auth::AuthError::Forbidden(msg)) => {
            assert!(msg.contains("No authorization"), "Should say no authorization: {}", msg);
        }
        other => panic!("Expected Forbidden error, got: {:?}", other),
    }
}

// ============================================================================
// Test 8: Decrypt Requires Authorization
// ============================================================================

#[tokio::test]
async fn test_decrypt_requires_authorization() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user but NO authorization
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &keys, &key_manager).await;

    let redirect_origin = format!("https://no-decrypt-auth-{}.example.com", Uuid::new_v4());
    let sender = Keys::generate().public_key();

    // Validate decrypt permissions - should fail (no authorization)
    let result = keycast_api::api::http::auth::validate_decrypt_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        "encrypted_ciphertext_here",
        &sender,
    ).await;

    assert!(result.is_err(), "Decrypt should require authorization");
    match result {
        Err(keycast_api::api::http::auth::AuthError::Forbidden(msg)) => {
            assert!(msg.contains("No authorization"), "Should say no authorization: {}", msg);
        }
        other => panic!("Expected Forbidden error, got: {:?}", other),
    }
}
