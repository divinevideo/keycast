// ABOUTME: Integration tests for admin token lifecycle
// ABOUTME: Tests UCAN generation/validation, user-token workflow, and claim token operations

use keycast_core::repositories::{ClaimTokenRepository, UserRepository};
use keycast_core::types::claim_token::generate_claim_token;
use nostr_sdk::Keys;
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

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

fn ensure_server_nsec() -> Keys {
    if std::env::var("SERVER_NSEC").is_err() {
        let fake = "0".repeat(63) + "1";
        std::env::set_var("SERVER_NSEC", &fake);
    }
    let nsec = std::env::var("SERVER_NSEC").unwrap();
    Keys::parse(&nsec).expect("SERVER_NSEC must be valid")
}

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

/// Build an admin UCAN (server-signed, admin_role: "full")
async fn build_admin_ucan(
    admin_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    server_keys: &Keys,
) -> String {
    use keycast_api::ucan_auth::nostr_pubkey_to_did;
    use keycast_api::ucan_auth::NostrKeyMaterial;
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let server_key_material = NostrKeyMaterial::from_keys(server_keys.clone());
    let admin_did = nostr_pubkey_to_did(admin_pubkey);

    let facts = json!({
        "tenant_id": tenant_id,
        "redirect_origin": "admin",
        "admin": true,
        "admin_role": "full",
    });

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)
        .for_audience(&admin_did)
        .with_lifetime(30 * 24 * 3600)
        .with_fact(facts)
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap();

    ucan.encode().unwrap()
}

/// Build a preload UCAN (server-signed, redirect_origin: "preload", no bunker_pubkey)
async fn build_preload_ucan(
    user_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    server_keys: &Keys,
    admin_pubkey_hex: &str,
) -> String {
    use keycast_api::ucan_auth::nostr_pubkey_to_did;
    use keycast_api::ucan_auth::NostrKeyMaterial;
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let server_key_material = NostrKeyMaterial::from_keys(server_keys.clone());
    let user_did = nostr_pubkey_to_did(user_pubkey);

    let facts = json!({
        "tenant_id": tenant_id,
        "redirect_origin": "preload",
        "issued_by_admin": admin_pubkey_hex,
    });

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)
        .for_audience(&user_did)
        .with_lifetime(30 * 24 * 3600)
        .with_fact(facts)
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap();

    ucan.encode().unwrap()
}

/// Build a self-issued UCAN (user-signed, not server-signed)
async fn build_self_issued_ucan(user_keys: &Keys) -> String {
    use keycast_api::ucan_auth::nostr_pubkey_to_did;
    use keycast_api::ucan_auth::NostrKeyMaterial;
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());

    let facts = json!({
        "tenant_id": 1,
        "redirect_origin": "https://test.example.com",
    });

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
// 1. Admin UCAN token generation & validation
// ============================================================================

#[tokio::test]
async fn test_admin_ucan_valid() {
    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key();

    let token = build_admin_ucan(&admin_pubkey, 1, &server_keys).await;
    let auth_header = format!("Bearer {}", token);

    let (extracted_pubkey, redirect_origin, _bunker_pubkey, _ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 1)
            .await
            .expect("admin UCAN should validate");

    assert_eq!(extracted_pubkey, admin_pubkey.to_hex());
    assert_eq!(redirect_origin, "admin");
}

#[tokio::test]
async fn test_admin_ucan_has_full_admin_role() {
    use keycast_api::api::extractors::UcanAuth;
    use keycast_api::api::http::admin::is_full_admin;

    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key();

    let token = build_admin_ucan(&admin_pubkey, 1, &server_keys).await;
    let auth_header = format!("Bearer {}", token);

    let (_pubkey, _redirect_origin, _bunker_pubkey, ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 0)
            .await
            .unwrap();

    // Extract admin_role the same way the extractor does
    let admin_role = if keycast_api::ucan_auth::is_server_signed(&ucan) {
        ucan.facts()
            .iter()
            .find_map(|fact| fact.get("admin_role").and_then(|v| v.as_str()))
            .map(String::from)
    } else {
        None
    };

    let auth = UcanAuth {
        pubkey: admin_pubkey.to_hex(),
        admin_role,
    };

    assert!(is_full_admin(&auth));
}

#[tokio::test]
async fn test_regular_ucan_not_admin() {
    use keycast_api::api::extractors::UcanAuth;
    use keycast_api::api::http::admin::is_full_admin;

    let _server_keys = ensure_server_nsec();
    let user_keys = Keys::generate();

    let token = build_self_issued_ucan(&user_keys).await;
    let auth_header = format!("Bearer {}", token);

    let (_pubkey, _redirect_origin, _bunker_pubkey, ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 0)
            .await
            .unwrap();

    // Self-issued → is_server_signed returns false → no admin_role
    assert!(!keycast_api::ucan_auth::is_server_signed(&ucan));

    let auth = UcanAuth {
        pubkey: user_keys.public_key().to_hex(),
        admin_role: None,
    };

    // Clear ALLOWED_PUBKEYS so whitelist fallback doesn't interfere
    std::env::remove_var("ALLOWED_PUBKEYS");
    assert!(!is_full_admin(&auth));
}

#[tokio::test]
async fn test_admin_ucan_expired() {
    use keycast_api::ucan_auth::nostr_pubkey_to_did;
    use keycast_api::ucan_auth::NostrKeyMaterial;
    use ucan::builder::UcanBuilder;

    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key();

    let server_key_material = NostrKeyMaterial::from_keys(server_keys);
    let admin_did = nostr_pubkey_to_did(&admin_pubkey);

    let facts = serde_json::json!({
        "tenant_id": 1,
        "redirect_origin": "admin",
        "admin_role": "full",
    });

    // Build with expiration in the past
    let expired_time = ucan::time::now() - 3600;

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)
        .for_audience(&admin_did)
        .with_expiration(expired_time)
        .with_fact(facts)
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap();

    let token = ucan.encode().unwrap();
    let auth_header = format!("Bearer {}", token);

    let result = keycast_api::ucan_auth::validate_ucan_token(&auth_header, 0).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("expired"),
        "should reject expired admin UCAN"
    );
}

// ============================================================================
// 2. Preload UCAN token generation & validation
// ============================================================================

#[tokio::test]
async fn test_preload_ucan_valid() {
    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key();

    let token = build_preload_ucan(
        &user_pubkey,
        1,
        &server_keys,
        &admin_keys.public_key().to_hex(),
    )
    .await;

    let auth_header = format!("Bearer {}", token);

    let (extracted_pubkey, redirect_origin, bunker_pubkey, _ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 1)
            .await
            .expect("preload UCAN should validate");

    assert_eq!(extracted_pubkey, user_pubkey.to_hex());
    assert_eq!(redirect_origin, "preload");
    assert!(
        bunker_pubkey.is_none(),
        "preload UCAN should have no bunker_pubkey"
    );
}

#[tokio::test]
async fn test_preload_ucan_no_bunker_pubkey() {
    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let user_keys = Keys::generate();

    let token = build_preload_ucan(
        &user_keys.public_key(),
        1,
        &server_keys,
        &admin_keys.public_key().to_hex(),
    )
    .await;

    let auth_header = format!("Bearer {}", token);

    let (_pubkey, _redirect_origin, bunker_pubkey, _ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 0)
            .await
            .unwrap();

    // nostr_rpc.rs detects preload mode by absence of bunker_pubkey
    assert!(
        bunker_pubkey.is_none(),
        "preload UCAN must not have bunker_pubkey (this is how nostr_rpc.rs detects preload mode)"
    );
}

#[tokio::test]
async fn test_preload_ucan_issued_by_admin_fact() {
    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let admin_pubkey_hex = admin_keys.public_key().to_hex();
    let user_keys = Keys::generate();

    let token =
        build_preload_ucan(&user_keys.public_key(), 1, &server_keys, &admin_pubkey_hex).await;

    let auth_header = format!("Bearer {}", token);

    let (_pubkey, _redirect_origin, _bunker_pubkey, ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 0)
            .await
            .unwrap();

    // Verify issued_by_admin fact contains the admin's pubkey
    let issued_by_admin = ucan
        .facts()
        .iter()
        .find_map(|fact| fact.get("issued_by_admin").and_then(|v| v.as_str()))
        .expect("preload UCAN should have issued_by_admin fact");

    assert_eq!(issued_by_admin, admin_pubkey_hex);
}

#[tokio::test]
async fn test_preload_ucan_is_server_signed() {
    let server_keys = ensure_server_nsec();
    let admin_keys = Keys::generate();
    let user_keys = Keys::generate();

    let token = build_preload_ucan(
        &user_keys.public_key(),
        1,
        &server_keys,
        &admin_keys.public_key().to_hex(),
    )
    .await;

    let auth_header = format!("Bearer {}", token);

    let (_pubkey, _redirect_origin, _bunker_pubkey, ucan) =
        keycast_api::ucan_auth::validate_ucan_token(&auth_header, 0)
            .await
            .unwrap();

    assert!(
        keycast_api::ucan_auth::is_server_signed(&ucan),
        "preload UCAN should be server-signed"
    );
}

// ============================================================================
// 3. User-token workflow (DB-level)
// ============================================================================

#[tokio::test]
async fn test_user_token_unclaimed_user() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let vine_id = format!("vine_{}", Uuid::new_v4());
    let username = format!("user_{}", &Uuid::new_v4().to_string()[..8]);

    // Create preloaded user (no email = unclaimed)
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .create_preloaded_user(
            &pubkey,
            tenant_id,
            &vine_id,
            &username,
            None,
            b"fake-encrypted",
        )
        .await
        .expect("create preloaded user");

    let is_unclaimed = user_repo.is_unclaimed(&pubkey, tenant_id).await.unwrap();
    assert_eq!(
        is_unclaimed,
        Some(true),
        "preloaded user should be unclaimed"
    );

    cleanup_by_pubkey(&pool, &pubkey).await;
}

#[tokio::test]
async fn test_user_token_claimed_user_rejected() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("claimed-{}@test.local", &Uuid::new_v4().to_string()[..8]);

    // Create user with email (= claimed)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    let user_repo = UserRepository::new(pool.clone());
    let is_unclaimed = user_repo.is_unclaimed(&pubkey, tenant_id).await.unwrap();
    assert_eq!(
        is_unclaimed,
        Some(false),
        "user with email should be claimed"
    );

    cleanup_by_pubkey(&pool, &pubkey).await;
}

#[tokio::test]
async fn test_user_token_nonexistent_user() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    let user_repo = UserRepository::new(pool.clone());
    let is_unclaimed = user_repo.is_unclaimed(&pubkey, tenant_id).await.unwrap();
    assert_eq!(is_unclaimed, None, "nonexistent user should return None");
}

// ============================================================================
// 4. Claim token lifecycle (DB-level)
// ============================================================================

#[tokio::test]
async fn test_claim_token_create_and_find() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key().to_hex();

    // Create a user first (claim tokens have FK to users)
    let user_repo = UserRepository::new(pool.clone());
    let vine_id = format!("vine_{}", Uuid::new_v4());
    let username = format!("ct_{}", &Uuid::new_v4().to_string()[..8]);
    user_repo
        .create_preloaded_user(
            &pubkey,
            tenant_id,
            &vine_id,
            &username,
            None,
            b"fake-encrypted",
        )
        .await
        .expect("create user for claim token test");

    // Create claim token
    let token = generate_claim_token();
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let created = claim_repo
        .create(&token, &pubkey, Some(&admin_pubkey), tenant_id)
        .await
        .expect("create claim token");

    assert_eq!(created.user_pubkey, pubkey);
    assert_eq!(
        created.created_by_pubkey.as_deref(),
        Some(admin_pubkey.as_str())
    );
    assert!(created.used_at.is_none());

    // Find valid token by user pubkey
    let found = claim_repo
        .find_valid_by_user_pubkey(&pubkey, tenant_id)
        .await
        .expect("find claim token");
    assert!(found.is_some(), "should find valid claim token");
    assert_eq!(found.unwrap().token, token);

    // Also find by token directly
    let found_direct = claim_repo.find_valid(&token).await.expect("find by token");
    assert!(found_direct.is_some());

    cleanup_by_pubkey(&pool, &pubkey).await;
}

#[tokio::test]
async fn test_claim_token_expired_not_returned() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    // Create user
    let user_repo = UserRepository::new(pool.clone());
    let vine_id = format!("vine_{}", Uuid::new_v4());
    let username = format!("cte_{}", &Uuid::new_v4().to_string()[..8]);
    user_repo
        .create_preloaded_user(
            &pubkey,
            tenant_id,
            &vine_id,
            &username,
            None,
            b"fake-encrypted",
        )
        .await
        .expect("create user");

    // Insert claim token with past expiry directly via SQL
    let token = generate_claim_token();
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    sqlx::query(
        "INSERT INTO account_claim_tokens (token, user_pubkey, expires_at, created_at, tenant_id)
         VALUES ($1, $2, $3, NOW(), $4)",
    )
    .bind(&token)
    .bind(&pubkey)
    .bind(past)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert expired claim token");

    let claim_repo = ClaimTokenRepository::new(pool.clone());

    // find_valid should not return expired token
    let found = claim_repo.find_valid(&token).await.unwrap();
    assert!(
        found.is_none(),
        "expired claim token should not be returned by find_valid"
    );

    // find_valid_by_user_pubkey should also not return it
    let found_by_user = claim_repo
        .find_valid_by_user_pubkey(&pubkey, tenant_id)
        .await
        .unwrap();
    assert!(
        found_by_user.is_none(),
        "expired claim token should not be returned by find_valid_by_user_pubkey"
    );

    cleanup_by_pubkey(&pool, &pubkey).await;
}

#[tokio::test]
async fn test_claim_token_used_not_returned() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    // Create user
    let user_repo = UserRepository::new(pool.clone());
    let vine_id = format!("vine_{}", Uuid::new_v4());
    let username = format!("ctu_{}", &Uuid::new_v4().to_string()[..8]);
    user_repo
        .create_preloaded_user(
            &pubkey,
            tenant_id,
            &vine_id,
            &username,
            None,
            b"fake-encrypted",
        )
        .await
        .expect("create user");

    // Create valid claim token
    let token = generate_claim_token();
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    claim_repo
        .create(&token, &pubkey, None, tenant_id)
        .await
        .expect("create claim token");

    // Mark as used
    let marked = claim_repo.mark_used(&token).await.expect("mark used");
    assert!(marked.is_some(), "mark_used should return the token");
    assert!(marked.unwrap().used_at.is_some());

    // find_valid should not return used token
    let found = claim_repo.find_valid(&token).await.unwrap();
    assert!(
        found.is_none(),
        "used claim token should not be returned by find_valid"
    );

    // find_valid_by_user_pubkey should also not return it
    let found_by_user = claim_repo
        .find_valid_by_user_pubkey(&pubkey, tenant_id)
        .await
        .unwrap();
    assert!(
        found_by_user.is_none(),
        "used claim token should not be returned by find_valid_by_user_pubkey"
    );

    cleanup_by_pubkey(&pool, &pubkey).await;
}
