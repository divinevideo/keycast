// ABOUTME: Integration tests for bcrypt cleanup task
// ABOUTME: Verifies that cleanup only removes stale signups, not preloaded users

use chrono::Utc;
use sqlx::PgPool;

/// Helper to create a test database pool
async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

/// Cleanup test data by pubkey
async fn cleanup_test_data(pool: &PgPool, pubkeys: &[&str]) {
    for pubkey in pubkeys {
        let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await;
    }
}

/// The cleanup query that should be tested - mirrors bcrypt_queue.rs
/// This version is scoped to specific pubkeys for safe testing
const CLEANUP_QUERY_SCOPED: &str = "DELETE FROM users WHERE password_hash IS NULL
                                    AND vine_id IS NULL
                                    AND email IS NOT NULL
                                    AND created_at < NOW() - INTERVAL '10 minutes'
                                    AND pubkey = ANY($1)";

#[tokio::test]
async fn test_cleanup_does_not_delete_preloaded_users() {
    let pool = setup_test_db().await;

    let preloaded_pubkey = "cleanup_test_preloaded_user_001";
    let vine_id = "cleanup_test_vine_id_001";
    let test_pubkeys = vec![preloaded_pubkey];

    // Cleanup any existing test data
    cleanup_test_data(&pool, &[preloaded_pubkey]).await;

    // Create a preloaded user with vine_id but no password_hash
    // Use a timestamp 15 minutes in the past to simulate an "old" user
    let old_timestamp = Utc::now() - chrono::Duration::minutes(15);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(preloaded_pubkey)
    .bind(vine_id)
    .bind("test_preloaded_user")
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create preloaded user");

    // Verify user exists
    let count_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(preloaded_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_before.0, 1,
        "Preloaded user should exist before cleanup"
    );

    // Run the scoped cleanup query
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(&test_pubkeys)
        .execute(&pool)
        .await
        .expect("Cleanup query failed");

    // Preloaded user should NOT be deleted (has vine_id)
    let count_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(preloaded_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_after.0, 1,
        "Preloaded user should NOT be deleted by cleanup"
    );
    assert_eq!(
        result.rows_affected(),
        0,
        "No rows should be deleted for preloaded user"
    );

    // Cleanup
    cleanup_test_data(&pool, &[preloaded_pubkey]).await;

    println!("✅ Preloaded user preserved by cleanup (vine_id protects it)");
}

#[tokio::test]
async fn test_cleanup_deletes_stale_signups() {
    let pool = setup_test_db().await;

    let stale_pubkey = "cleanup_test_stale_signup_001";
    let test_pubkeys = vec![stale_pubkey];

    // Cleanup any existing test data
    cleanup_test_data(&pool, &[stale_pubkey]).await;

    // Create a stale signup: no password_hash, no vine_id, old timestamp
    let old_timestamp = Utc::now() - chrono::Duration::minutes(15);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verification_token, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(stale_pubkey)
    .bind("stale_test@example.com")
    .bind("stale_verification_token_123")
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create stale signup");

    // Verify user exists
    let count_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(stale_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_before.0, 1,
        "Stale signup should exist before cleanup"
    );

    // Run the scoped cleanup query
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(&test_pubkeys)
        .execute(&pool)
        .await
        .expect("Cleanup query failed");

    // Stale signup SHOULD be deleted (no vine_id, no password_hash, old)
    let count_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(stale_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_after.0, 0,
        "Stale signup SHOULD be deleted by cleanup"
    );
    assert_eq!(
        result.rows_affected(),
        1,
        "One row should be deleted for stale signup"
    );

    // Cleanup (in case assertion failed)
    cleanup_test_data(&pool, &[stale_pubkey]).await;

    println!("✅ Stale signup correctly deleted");
}

#[tokio::test]
async fn test_cleanup_preserves_recent_signups() {
    let pool = setup_test_db().await;

    let recent_pubkey = "cleanup_test_recent_signup_001";
    let test_pubkeys = vec![recent_pubkey];

    // Cleanup any existing test data
    cleanup_test_data(&pool, &[recent_pubkey]).await;

    // Create a recent signup: no password_hash, no vine_id, but recent timestamp
    let recent_timestamp = Utc::now() - chrono::Duration::minutes(5); // Only 5 min old

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verification_token, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(recent_pubkey)
    .bind("recent_test@example.com")
    .bind("recent_verification_token_123")
    .bind(recent_timestamp)
    .bind(recent_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create recent signup");

    // Run the scoped cleanup query
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(&test_pubkeys)
        .execute(&pool)
        .await
        .expect("Cleanup query failed");

    // Recent signup should NOT be deleted (less than 10 minutes old)
    let count_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(recent_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_after.0, 1,
        "Recent signup should NOT be deleted (too new)"
    );
    assert_eq!(
        result.rows_affected(),
        0,
        "No rows should be deleted for recent signup"
    );

    // Cleanup
    cleanup_test_data(&pool, &[recent_pubkey]).await;

    println!("✅ Recent signup preserved (not old enough for cleanup)");
}

#[tokio::test]
async fn test_cleanup_preserves_users_with_password() {
    let pool = setup_test_db().await;

    let normal_pubkey = "cleanup_test_normal_user_001";
    let test_pubkeys = vec![normal_pubkey];

    // Cleanup any existing test data
    cleanup_test_data(&pool, &[normal_pubkey]).await;

    // Create a normal user: has password_hash, old timestamp
    let old_timestamp = Utc::now() - chrono::Duration::minutes(15);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, $4, $5)",
    )
    .bind(normal_pubkey)
    .bind("normal_test@example.com")
    .bind("$2b$12$somehashvalue") // Has password
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create normal user");

    // Run the scoped cleanup query
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(&test_pubkeys)
        .execute(&pool)
        .await
        .expect("Cleanup query failed");

    // Normal user should NOT be deleted (has password_hash)
    let count_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(normal_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_after.0, 1,
        "Normal user should NOT be deleted (has password)"
    );
    assert_eq!(
        result.rows_affected(),
        0,
        "No rows should be deleted for user with password"
    );

    // Cleanup
    cleanup_test_data(&pool, &[normal_pubkey]).await;

    println!("✅ Normal user with password preserved");
}

#[tokio::test]
async fn test_cleanup_mixed_scenario() {
    let pool = setup_test_db().await;

    let preloaded_pubkey = "cleanup_test_mixed_preloaded";
    let stale_pubkey = "cleanup_test_mixed_stale";
    let normal_pubkey = "cleanup_test_mixed_normal";
    let vine_id = "cleanup_test_mixed_vine_id";

    let all_pubkeys = vec![preloaded_pubkey, stale_pubkey, normal_pubkey];

    // Cleanup any existing test data
    cleanup_test_data(&pool, &all_pubkeys.to_vec()).await;

    let old_timestamp = Utc::now() - chrono::Duration::minutes(15);

    // Create preloaded user (should survive)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, vine_id, username, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(preloaded_pubkey)
    .bind(vine_id)
    .bind("preloaded_mixed")
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create preloaded user");

    // Create stale signup (should be deleted)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4)",
    )
    .bind(stale_pubkey)
    .bind("stale_mixed@example.com")
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create stale signup");

    // Create normal user (should survive)
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, $4, $5)",
    )
    .bind(normal_pubkey)
    .bind("normal_mixed@example.com")
    .bind("$2b$12$somehashvalue")
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create normal user");

    // Count before
    let count_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = ANY($1)")
        .bind(&all_pubkeys)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_before.0, 3, "Should have 3 users before cleanup");

    // Run scoped cleanup
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(&all_pubkeys)
        .execute(&pool)
        .await
        .expect("Cleanup query failed");

    // Check results
    let preloaded_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(preloaded_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    let stale_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(stale_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    let normal_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(normal_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(
        preloaded_exists.0, 1,
        "Preloaded user should survive cleanup"
    );
    assert_eq!(stale_exists.0, 0, "Stale signup should be deleted");
    assert_eq!(normal_exists.0, 1, "Normal user should survive cleanup");
    assert_eq!(
        result.rows_affected(),
        1,
        "Only one row (stale signup) should be deleted"
    );

    // Cleanup
    cleanup_test_data(&pool, &all_pubkeys.to_vec()).await;

    println!(
        "✅ Mixed scenario: cleanup deleted {} rows (stale signup only)",
        result.rows_affected()
    );
}

/// Test that verifies the actual cleanup query in bcrypt_queue.rs matches our expectations
/// This is a documentation test that ensures the query includes the vine_id check
#[tokio::test]
async fn test_cleanup_query_includes_vine_id_check() {
    // The cleanup query in bcrypt_queue.rs should contain these conditions
    let expected_conditions = vec![
        "password_hash IS NULL", // Must have no password
        "vine_id IS NULL",       // Must NOT be a preloaded user
        "email IS NOT NULL",     // Must be an email signup, not a pubkey-only user
        "created_at < NOW()",    // Must be older than threshold
    ];

    let source = include_str!("../src/bcrypt_queue.rs");

    for condition in expected_conditions {
        assert!(
            source.contains(condition),
            "bcrypt_queue.rs cleanup query should contain: {}",
            condition
        );
    }

    println!("✅ Cleanup query in bcrypt_queue.rs contains all required conditions");
}

// ---------------------------------------------------------------------------
// Bug reproduction: cleanup query is overbroad — matches pubkey-only users
// ---------------------------------------------------------------------------
//
// When a user is added to a team by pubkey (via find_or_create), they get a
// users row with NULL email, NULL password_hash, NULL vine_id. The cleanup
// query matches them because it only checks password_hash and vine_id.
//
// The missing ON DELETE CASCADE on team_users_user_pubkey_fkey accidentally
// prevents deletion when they have team memberships, but the query is still
// wrong and produces errors in the log.

/// Cleanup helper that also removes team_users rows
async fn cleanup_test_data_with_teams(pool: &PgPool, pubkeys: &[&str]) {
    for pubkey in pubkeys {
        let _ = sqlx::query("DELETE FROM team_users WHERE user_pubkey = $1")
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
}

async fn cleanup_teams(pool: &PgPool, names: &[&str]) {
    for name in names {
        let _ = sqlx::query("DELETE FROM teams WHERE name = $1")
            .bind(name)
            .execute(pool)
            .await;
    }
}

/// Cleanup must NOT match pubkey-only users (created via find_or_create for teams).
///
/// These users have no email, no password_hash, no vine_id — they were added
/// to teams by pubkey alone. The `email IS NOT NULL` condition excludes them.
#[tokio::test]
async fn test_cleanup_preserves_pubkey_only_user() {
    let pool = setup_test_db().await;

    let pubkey = "cleanup_bug_pubkey_only_user_001_";
    let test_pubkeys = vec![pubkey];

    cleanup_test_data_with_teams(&pool, &[pubkey]).await;

    // Simulate find_or_create: pubkey-only user, no email, no password, no vine_id
    let old_timestamp = Utc::now() - chrono::Duration::minutes(15);
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, 1, $2, $3)",
    )
    .bind(pubkey)
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create pubkey-only user");

    // Cleanup query with email IS NOT NULL should skip this user
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(&test_pubkeys)
        .execute(&pool)
        .await
        .expect("Cleanup query failed");

    assert_eq!(
        result.rows_affected(),
        0,
        "Pubkey-only user should NOT be deleted (no email = not a stale signup)"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "Pubkey-only user should still exist");

    cleanup_test_data_with_teams(&pool, &[pubkey]).await;
    println!("✅ Pubkey-only user correctly preserved by cleanup");
}

/// Cleanup must NOT match pubkey-only users even when they have team memberships.
///
/// Previously the cleanup query would match these users and then fail with:
/// "violates foreign key constraint team_users_user_pubkey_fkey"
/// The `email IS NOT NULL` fix prevents matching them in the first place.
#[tokio::test]
async fn test_cleanup_preserves_team_member() {
    let pool = setup_test_db().await;

    let pubkey = "cleanup_bug_team_member_001______";
    let team_name = "cleanup_bug_test_team_001";

    cleanup_test_data_with_teams(&pool, &[pubkey]).await;
    cleanup_teams(&pool, &[team_name]).await;

    // Create pubkey-only user (simulating find_or_create)
    let old_timestamp = Utc::now() - chrono::Duration::minutes(15);
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, 1, $2, $3)",
    )
    .bind(pubkey)
    .bind(old_timestamp)
    .bind(old_timestamp)
    .execute(&pool)
    .await
    .expect("Failed to create user");

    // Create team and add user as member
    let team_id: (i32,) = sqlx::query_as(
        "INSERT INTO teams (tenant_id, name, created_at, updated_at)
         VALUES (1, $1, NOW(), NOW()) RETURNING id",
    )
    .bind(team_name)
    .fetch_one(&pool)
    .await
    .expect("Failed to create team");

    sqlx::query(
        "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
         VALUES ($1, $2, 'member', NOW(), NOW())",
    )
    .bind(team_id.0)
    .bind(pubkey)
    .execute(&pool)
    .await
    .expect("Failed to add team member");

    // Cleanup should not even try to delete this user (no email = not a stale signup)
    let result = sqlx::query(CLEANUP_QUERY_SCOPED)
        .bind(vec![pubkey])
        .execute(&pool)
        .await
        .expect("Cleanup should succeed without errors");

    assert_eq!(
        result.rows_affected(),
        0,
        "Team member should NOT be matched by cleanup (no email)"
    );

    // User and team membership should both still exist
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    let team_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1")
            .bind(pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(user_count.0, 1, "User should still exist");
    assert_eq!(team_count.0, 1, "Team membership should still exist");

    cleanup_test_data_with_teams(&pool, &[pubkey]).await;
    cleanup_teams(&pool, &[team_name]).await;
    println!("✅ Team member correctly preserved by cleanup");
}
