// ABOUTME: Integration tests for tenant isolation across all tables
// ABOUTME: Verifies that tenant_id filtering prevents cross-tenant data leakage
// TODO: Migrate from SQLite to PostgreSQL - these tests are temporarily disabled
#![cfg(feature = "sqlite-tests")]

use keycast_core::database::Database;
use keycast_core::tenant_query::TenantId;
use sqlx::{Row, SqlitePool};
use std::path::PathBuf;

async fn setup_test_db(test_name: &str) -> SqlitePool {
    let db_filename = format!("test_tenant_isolation_{}.db", test_name);
    let db_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("database")
        .join(db_filename);

    // Remove if exists
    let _ = std::fs::remove_file(&db_path);

    let migrations_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("database/migrations");

    let database = Database::new(db_path.clone(), migrations_path)
        .await
        .expect("Failed to create test database");

    database.pool
}

/// Helper to create a test tenant
async fn create_test_tenant(pool: &SqlitePool, domain: &str, name: &str) -> i64 {
    let result = sqlx::query(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
         RETURNING id"
    )
    .bind(domain)
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("Failed to create tenant");

    result.get(0)
}

#[tokio::test]
async fn test_tenant_isolation_users() {
    let pool = setup_test_db("users").await;

    // Create two tenants
    let tenant1_id = create_test_tenant(&pool, "tenant1.test", "Tenant 1").await;
    let tenant2_id = create_test_tenant(&pool, "tenant2.test", "Tenant 2").await;

    // Create user in tenant 1
    sqlx::query(
        "INSERT INTO users (tenant_id, public_key, created_at, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant1_id)
    .bind("user1_pubkey_abc123")
    .execute(&pool)
    .await
    .expect("Failed to create user in tenant 1");

    // Create user in tenant 2
    sqlx::query(
        "INSERT INTO users (tenant_id, public_key, created_at, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant2_id)
    .bind("user2_pubkey_xyz789")
    .execute(&pool)
    .await
    .expect("Failed to create user in tenant 2");

    // Test: Query for tenant 1 users should ONLY return tenant 1 users
    let tenant1_users: Vec<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE tenant_id = ?"
    )
    .bind(tenant1_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to query tenant 1 users");

    assert_eq!(tenant1_users.len(), 1);
    assert_eq!(tenant1_users[0], "user1_pubkey_abc123");

    // Test: Query for tenant 2 users should ONLY return tenant 2 users
    let tenant2_users: Vec<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE tenant_id = ?"
    )
    .bind(tenant2_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to query tenant 2 users");

    assert_eq!(tenant2_users.len(), 1);
    assert_eq!(tenant2_users[0], "user2_pubkey_xyz789");

    // Test: Query without tenant_id filtering should return BOTH users
    let all_users: Vec<String> = sqlx::query_scalar(
        "SELECT public_key FROM users ORDER BY public_key"
    )
    .fetch_all(&pool)
    .await
    .expect("Failed to query all users");

    assert_eq!(all_users.len(), 2);
}

#[tokio::test]
async fn test_tenant_isolation_oauth_applications() {
    let pool = setup_test_db("oauth_applications").await;

    let tenant1_id = create_test_tenant(&pool, "tenant1.test", "Tenant 1").await;
    let tenant2_id = create_test_tenant(&pool, "tenant2.test", "Tenant 2").await;

    // Create OAuth app in tenant 1
    sqlx::query(
        "INSERT INTO oauth_applications (tenant_id, display_name, redirect_origin, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant1_id)
    .bind("client1")
    .bind("https://app1.test")  // redirect_origin is the secure identifier
    .bind("secret1")
    .bind("App 1")
    .bind(r#"["https://app1.test/callback"]"#)
    .execute(&pool)
    .await
    .expect("Failed to create OAuth app in tenant 1");

    // Create OAuth app in tenant 2 with SAME redirect_origin (should work due to tenant scoping)
    sqlx::query(
        "INSERT INTO oauth_applications (tenant_id, display_name, redirect_origin, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant2_id)
    .bind("client1")
    .bind("https://app1.test")  // Same redirect_origin as tenant 1 - allowed because different tenant
    .bind("secret2")
    .bind("App 2")
    .bind(r#"["https://app1.test/callback"]"#)
    .execute(&pool)
    .await
    .expect("Failed to create OAuth app in tenant 2");

    // Test: Query tenant 1 apps
    let tenant1_apps: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM oauth_applications WHERE tenant_id = ?"
    )
    .bind(tenant1_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to query tenant 1 apps");

    assert_eq!(tenant1_apps.len(), 1);
    assert_eq!(tenant1_apps[0], "App 1");

    // Test: Query tenant 2 apps
    let tenant2_apps: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM oauth_applications WHERE tenant_id = ?"
    )
    .bind(tenant2_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to query tenant 2 apps");

    assert_eq!(tenant2_apps.len(), 1);
    assert_eq!(tenant2_apps[0], "App 2");
}

#[tokio::test]
async fn test_email_uniqueness_per_tenant() {
    let pool = setup_test_db("email_uniqueness").await;

    let tenant1_id = create_test_tenant(&pool, "tenant1.test", "Tenant 1").await;
    let tenant2_id = create_test_tenant(&pool, "tenant2.test", "Tenant 2").await;

    // Create user with email alice@example.com in tenant 1
    sqlx::query(
        "INSERT INTO users (tenant_id, public_key, email, created_at, updated_at)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant1_id)
    .bind("pubkey1")
    .bind("alice@example.com")
    .execute(&pool)
    .await
    .expect("Failed to create user in tenant 1");

    // Create user with SAME email in tenant 2 (should succeed due to tenant scoping)
    let result = sqlx::query(
        "INSERT INTO users (tenant_id, public_key, email, created_at, updated_at)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant2_id)
    .bind("pubkey2")
    .bind("alice@example.com")
    .execute(&pool)
    .await;

    assert!(result.is_ok(), "Should allow same email in different tenants");

    // Verify both users exist with same email
    let emails: Vec<String> = sqlx::query_scalar(
        "SELECT email FROM users WHERE email = ? ORDER BY tenant_id"
    )
    .bind("alice@example.com")
    .fetch_all(&pool)
    .await
    .expect("Failed to query users by email");

    assert_eq!(emails.len(), 2);
}

#[tokio::test]
async fn test_username_uniqueness_per_tenant() {
    let pool = setup_test_db("username_uniqueness").await;

    let tenant1_id = create_test_tenant(&pool, "tenant1.test", "Tenant 1").await;
    let tenant2_id = create_test_tenant(&pool, "tenant2.test", "Tenant 2").await;

    // Create user with username "alice" in tenant 1
    sqlx::query(
        "INSERT INTO users (tenant_id, public_key, username, created_at, updated_at)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant1_id)
    .bind("pubkey1")
    .bind("alice")
    .execute(&pool)
    .await
    .expect("Failed to create user in tenant 1");

    // Create user with SAME username in tenant 2 (should succeed)
    let result = sqlx::query(
        "INSERT INTO users (tenant_id, public_key, username, created_at, updated_at)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant2_id)
    .bind("pubkey2")
    .bind("alice")
    .execute(&pool)
    .await;

    assert!(result.is_ok(), "Should allow same username in different tenants");

    // This means: alice@tenant1.test and alice@tenant2.test are different users
    let usernames: Vec<String> = sqlx::query_scalar(
        "SELECT username FROM users WHERE username = ? ORDER BY tenant_id"
    )
    .bind("alice")
    .fetch_all(&pool)
    .await
    .expect("Failed to query users by username");

    assert_eq!(usernames.len(), 2);
}

#[tokio::test]
async fn test_cross_tenant_data_leakage_prevention() {
    let pool = setup_test_db("data_leakage_prevention").await;

    let tenant1_id = create_test_tenant(&pool, "tenant1.test", "Tenant 1").await;
    let tenant2_id = create_test_tenant(&pool, "tenant2.test", "Tenant 2").await;

    // Create user in tenant 1
    sqlx::query(
        "INSERT INTO users (tenant_id, public_key, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .bind(tenant1_id)
    .bind("secret_pubkey")
    .bind("secret@tenant1.test")
    .bind("$2b$12$fakehash")
    .execute(&pool)
    .await
    .expect("Failed to create user in tenant 1");

    // Attempt to query this user from tenant 2 context (simulating bug or attack)
    let leaked_users: Vec<String> = sqlx::query_scalar(
        "SELECT email FROM users WHERE tenant_id = ? AND email = ?"
    )
    .bind(tenant2_id)  // Wrong tenant
    .bind("secret@tenant1.test")
    .fetch_all(&pool)
    .await
    .expect("Failed to query users");

    // Should return ZERO results (data not leaked)
    assert_eq!(leaked_users.len(), 0, "Cross-tenant data leakage detected!");
}
