// ABOUTME: Integration tests for batch claim token generation and stats
// ABOUTME: Tests batch logic, skip behavior for claimed/missing users, and stats aggregation

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

/// Create a preloaded (unclaimed) user and return their pubkey and vine_id
async fn create_unclaimed_user(pool: &PgPool, tenant_id: i64) -> (String, String) {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let vine_id = format!("vine_batch_{}", Uuid::new_v4());
    let username = format!("batchuser_{}", &Uuid::new_v4().to_string()[..8]);

    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .create_preloaded_user(
            &pubkey,
            tenant_id,
            &vine_id,
            &username,
            None,
            b"fake-encrypted-key",
        )
        .await
        .expect("create preloaded user");

    (pubkey, vine_id)
}

/// Create a claimed user (has email set) and return their pubkey and vine_id
async fn create_claimed_user(pool: &PgPool, tenant_id: i64) -> (String, String) {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let vine_id = format!("vine_claimed_{}", Uuid::new_v4());
    let username = format!("claimeduser_{}", &Uuid::new_v4().to_string()[..8]);
    let email = format!("claimed-{}@test.local", &Uuid::new_v4().to_string()[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&vine_id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("create claimed user");

    (pubkey, vine_id)
}

// ============================================================================
// Batch claim token generation - repository-level logic
// ============================================================================

/// Simulate the core batch loop logic at the repository level.
/// Returns (tokens_created, skipped_vine_ids) for verification.
async fn run_batch_logic(
    pool: &PgPool,
    vine_ids: &[&str],
    admin_pubkey: &str,
    tenant_id: i64,
) -> (Vec<String>, Vec<String>) {
    let user_repo = UserRepository::new(pool.clone());
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let mut created = Vec::new();
    let mut skipped = Vec::new();

    for vine_id in vine_ids {
        let user_pubkey = match user_repo.find_pubkey_by_vine_id(vine_id, tenant_id).await {
            Ok(Some(pk)) => pk,
            Ok(None) => {
                skipped.push(vine_id.to_string());
                continue;
            }
            Err(_) => {
                skipped.push(vine_id.to_string());
                continue;
            }
        };

        match user_repo.is_unclaimed(&user_pubkey, tenant_id).await {
            Ok(Some(true)) => {}
            _ => {
                skipped.push(vine_id.to_string());
                continue;
            }
        }

        let token = generate_claim_token();
        claim_token_repo
            .create(&token, &user_pubkey, Some(admin_pubkey), tenant_id)
            .await
            .expect("create claim token");

        created.push(vine_id.to_string());
    }

    (created, skipped)
}

#[tokio::test]
async fn test_batch_all_valid_users() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key().to_hex();

    let (pubkey1, vine_id1) = create_unclaimed_user(&pool, tenant_id).await;
    let (pubkey2, vine_id2) = create_unclaimed_user(&pool, tenant_id).await;
    let (pubkey3, vine_id3) = create_unclaimed_user(&pool, tenant_id).await;

    let vine_ids: Vec<&str> = vec![&vine_id1, &vine_id2, &vine_id3];
    let (created, skipped) = run_batch_logic(&pool, &vine_ids, &admin_pubkey, tenant_id).await;

    assert_eq!(created.len(), 3, "all three users should get tokens");
    assert_eq!(skipped.len(), 0, "no users should be skipped");

    // Verify tokens exist in DB
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    for pubkey in [&pubkey1, &pubkey2, &pubkey3] {
        let token = claim_repo
            .find_valid_by_user_pubkey(pubkey, tenant_id)
            .await
            .expect("query should succeed");
        assert!(
            token.is_some(),
            "token should exist for pubkey {}",
            &pubkey[..8]
        );
    }

    cleanup_by_pubkey(&pool, &pubkey1).await;
    cleanup_by_pubkey(&pool, &pubkey2).await;
    cleanup_by_pubkey(&pool, &pubkey3).await;
}

#[tokio::test]
async fn test_batch_skips_already_claimed_users() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key().to_hex();

    let (pubkey_unclaimed, vine_id_unclaimed) = create_unclaimed_user(&pool, tenant_id).await;
    let (pubkey_claimed, vine_id_claimed) = create_claimed_user(&pool, tenant_id).await;

    let vine_ids: Vec<&str> = vec![&vine_id_unclaimed, &vine_id_claimed];
    let (created, skipped) = run_batch_logic(&pool, &vine_ids, &admin_pubkey, tenant_id).await;

    assert_eq!(created.len(), 1, "only unclaimed user should get a token");
    assert_eq!(skipped.len(), 1, "claimed user should be skipped");
    assert_eq!(skipped[0], vine_id_claimed);

    // Verify the unclaimed user got a token
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let token = claim_repo
        .find_valid_by_user_pubkey(&pubkey_unclaimed, tenant_id)
        .await
        .unwrap();
    assert!(token.is_some(), "unclaimed user should have a token");

    // Claimed user must not have gotten a token
    let no_token = claim_repo
        .find_valid_by_user_pubkey(&pubkey_claimed, tenant_id)
        .await
        .unwrap();
    assert!(no_token.is_none(), "claimed user should not have a token");

    cleanup_by_pubkey(&pool, &pubkey_unclaimed).await;
    cleanup_by_pubkey(&pool, &pubkey_claimed).await;
}

#[tokio::test]
async fn test_batch_skips_nonexistent_vine_ids() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key().to_hex();

    let (pubkey_valid, vine_id_valid) = create_unclaimed_user(&pool, tenant_id).await;
    let fake_vine_id = format!("vine_nonexistent_{}", Uuid::new_v4());

    let vine_ids: Vec<&str> = vec![&vine_id_valid, &fake_vine_id];
    let (created, skipped) = run_batch_logic(&pool, &vine_ids, &admin_pubkey, tenant_id).await;

    assert_eq!(created.len(), 1, "only the valid user should get a token");
    assert_eq!(skipped.len(), 1, "nonexistent vine_id should be skipped");
    assert_eq!(skipped[0], fake_vine_id);

    cleanup_by_pubkey(&pool, &pubkey_valid).await;
}

#[tokio::test]
async fn test_batch_empty_input_no_tokens_created() {
    let pool = setup_pool().await;
    let tenant_id: i64 = 1;
    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key().to_hex();

    let (created, skipped) = run_batch_logic(&pool, &[], &admin_pubkey, tenant_id).await;

    assert_eq!(created.len(), 0);
    assert_eq!(skipped.len(), 0);
}

// ============================================================================
// Claim token stats - repository-level
// ============================================================================

#[tokio::test]
async fn test_claim_token_stats_counts_correctly() {
    let pool = setup_pool().await;
    // Use a distinct tenant_id to avoid collisions with other tests
    let tenant_id: i64 = 999_001;

    // Clean up any leftover tokens from previous runs
    let _ = sqlx::query("DELETE FROM account_claim_tokens WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM personal_keys WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;

    let admin_keys = Keys::generate();
    let admin_pubkey = admin_keys.public_key().to_hex();
    let claim_repo = ClaimTokenRepository::new(pool.clone());

    // Create a user for "pending" token
    let (pubkey_pending, vine_id_pending) = create_unclaimed_user_in_tenant(&pool, tenant_id).await;

    // Create a user for "claimed" token
    let (pubkey_claimed_token, _vine_id_claimed_token) =
        create_unclaimed_user_in_tenant(&pool, tenant_id).await;

    // Create a user for "expired" token
    let (pubkey_expired, _) = create_unclaimed_user_in_tenant(&pool, tenant_id).await;

    // 1. Create a pending (valid, not used) token
    let pending_token = generate_claim_token();
    claim_repo
        .create(
            &pending_token,
            &pubkey_pending,
            Some(&admin_pubkey),
            tenant_id,
        )
        .await
        .expect("create pending token");

    // 2. Create a used/claimed token
    let used_token = generate_claim_token();
    claim_repo
        .create(
            &used_token,
            &pubkey_claimed_token,
            Some(&admin_pubkey),
            tenant_id,
        )
        .await
        .expect("create used token");
    claim_repo
        .mark_used(&used_token)
        .await
        .expect("mark token as used");

    // 3. Insert an expired token directly via SQL
    let expired_token = generate_claim_token();
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    sqlx::query(
        "INSERT INTO account_claim_tokens (token, user_pubkey, expires_at, created_at, tenant_id)
         VALUES ($1, $2, $3, NOW(), $4)",
    )
    .bind(&expired_token)
    .bind(&pubkey_expired)
    .bind(past)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert expired token");

    let stats = claim_repo
        .get_stats(tenant_id)
        .await
        .expect("get stats should succeed");

    assert_eq!(stats.total_generated, 3, "should count all 3 tokens");
    assert_eq!(stats.total_claimed, 1, "one token was used");
    assert_eq!(stats.total_expired, 1, "one token is expired");
    assert_eq!(stats.total_pending, 1, "one token is pending");

    // Cleanup
    let _ = sqlx::query("DELETE FROM account_claim_tokens WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM personal_keys WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;

    // Suppress unused variable warning for vine_id_pending
    let _ = vine_id_pending;
}

#[tokio::test]
async fn test_claim_token_stats_empty_tenant() {
    let pool = setup_pool().await;
    // Use a tenant_id guaranteed to have no data
    let tenant_id: i64 = 999_002;

    let _ = sqlx::query("DELETE FROM account_claim_tokens WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await;

    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let stats = claim_repo.get_stats(tenant_id).await.expect("get stats");

    assert_eq!(stats.total_generated, 0);
    assert_eq!(stats.total_claimed, 0);
    assert_eq!(stats.total_expired, 0);
    assert_eq!(stats.total_pending, 0);
}

/// Create an unclaimed user in a specific tenant (for isolation in stats tests)
async fn create_unclaimed_user_in_tenant(pool: &PgPool, tenant_id: i64) -> (String, String) {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let vine_id = format!("vine_stats_{}", Uuid::new_v4());
    let username = format!("statsuser_{}", &Uuid::new_v4().to_string()[..8]);

    // Ensure the tenant exists (idempotent)
    sqlx::query(
        "INSERT INTO tenants (id, name, domain, created_at, updated_at)
         VALUES ($1, 'Stats Test Tenant', 'stats-test.example.com', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("ensure tenant exists for stats test");

    // Use direct SQL because create_preloaded_user may require tenant to exist
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&vine_id)
    .bind(&username)
    .execute(pool)
    .await
    .expect("create stats test user");

    // Insert a fake encrypted key to satisfy FK constraints if any
    let _ = sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(b"fake-key".as_ref())
    .bind(tenant_id)
    .execute(pool)
    .await;

    (pubkey, vine_id)
}
