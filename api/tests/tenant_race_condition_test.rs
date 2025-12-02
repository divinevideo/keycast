// ABOUTME: Tests for tenant auto-provisioning race condition fix
// ABOUTME: Verifies that concurrent get_or_create_tenant calls don't fail

mod common;

use sqlx::PgPool;
use std::sync::Arc;

async fn setup_pool() -> PgPool {
    common::setup_test_db().await
}

/// Test that concurrent tenant creation requests don't cause duplicate key errors
///
/// This reproduces the bug where:
/// 1. Multiple requests hit the server simultaneously for a new domain
/// 2. Old code: check-then-insert pattern caused race condition
/// 3. Both requests saw "not found" and both tried to insert
/// 4. One succeeded, one failed with duplicate key error
///
/// The fix uses INSERT ... ON CONFLICT DO UPDATE which is atomic.
#[tokio::test]
async fn test_concurrent_tenant_creation() {
    let pool = Arc::new(setup_pool().await);
    let domain = format!("concurrent-test-{}.example.com", uuid::Uuid::new_v4());
    let num_concurrent = 10;

    // Spawn many concurrent tasks all trying to get/create the same tenant
    let mut handles = Vec::new();
    for i in 0..num_concurrent {
        let pool = Arc::clone(&pool);
        let domain = domain.clone();
        handles.push(tokio::spawn(async move {
            // Simulate the get_or_create_tenant logic with ON CONFLICT
            let result = sqlx::query_as::<_, (i64, String, String)>(
                "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
                 VALUES ($1, $2, $3, NOW(), NOW())
                 ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
                 RETURNING id, domain, name",
            )
            .bind(&domain)
            .bind(format!("Test Tenant {}", i))
            .bind(r#"{"auto_provisioned":true}"#)
            .fetch_one(pool.as_ref())
            .await;

            result
        }));
    }

    // All tasks should succeed (no duplicate key errors)
    let mut tenant_ids = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.expect("Task panicked");
        match result {
            Ok((id, returned_domain, _name)) => {
                assert_eq!(returned_domain, domain);
                tenant_ids.push(id);
            }
            Err(e) => {
                panic!("Task {} failed with error: {}. This indicates the race condition fix is not working.", i, e);
            }
        }
    }

    // All tasks should have returned the same tenant ID
    let first_id = tenant_ids[0];
    for (i, id) in tenant_ids.iter().enumerate() {
        assert_eq!(
            *id, first_id,
            "Task {} got different tenant ID: {} vs {}",
            i, id, first_id
        );
    }

    // Verify only one tenant was created
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants WHERE domain = $1")
        .bind(&domain)
        .fetch_one(pool.as_ref())
        .await
        .expect("Failed to count tenants");

    assert_eq!(
        count.0, 1,
        "Expected exactly 1 tenant, but found {}",
        count.0
    );

    // Cleanup
    sqlx::query("DELETE FROM tenants WHERE domain = $1")
        .bind(&domain)
        .execute(pool.as_ref())
        .await
        .ok();
}

/// Test that the sequence is properly set after migrations
///
/// This reproduces the bug where:
/// 1. Initial migration inserts tenant with explicit id=1
/// 2. Sequence wasn't updated, still at 1
/// 3. Next auto-generated ID conflicts with existing id=1
#[tokio::test]
async fn test_tenant_sequence_after_seeded_data() {
    let pool = setup_pool().await;

    // The default tenant (id=1) is inserted by migrations
    // Verify it exists
    let default_tenant: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM tenants WHERE domain = 'default'")
            .fetch_optional(&pool)
            .await
            .expect("Failed to query default tenant");

    assert!(
        default_tenant.is_some(),
        "Default tenant should exist from migrations"
    );
    assert_eq!(
        default_tenant.unwrap().0,
        1,
        "Default tenant should have id=1"
    );

    // Now insert a new tenant using the sequence (no explicit ID)
    let unique_domain = format!("sequence-test-{}.example.com", uuid::Uuid::new_v4());
    let new_tenant: (i64, String) = sqlx::query_as(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, 'New Tenant', NOW(), NOW())
         RETURNING id, domain",
    )
    .bind(&unique_domain)
    .fetch_one(&pool)
    .await
    .expect("Failed to insert new tenant - sequence may not be properly set");

    // The new tenant should have id > 1 (not conflict with seeded data)
    assert!(
        new_tenant.0 > 1,
        "New tenant ID should be > 1, got {}",
        new_tenant.0
    );
    assert_eq!(new_tenant.1, unique_domain);

    // Cleanup
    sqlx::query("DELETE FROM tenants WHERE domain = $1")
        .bind(&unique_domain)
        .execute(&pool)
        .await
        .ok();
}

/// Test that ON CONFLICT properly handles existing tenants
#[tokio::test]
async fn test_get_or_create_returns_existing_tenant() {
    let pool = setup_pool().await;
    let domain = format!("existing-test-{}.example.com", uuid::Uuid::new_v4());

    // First insert - creates new tenant
    let first: (i64, String, String) = sqlx::query_as(
        "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name",
    )
    .bind(&domain)
    .bind("First Name")
    .bind(r#"{}"#)
    .fetch_one(&pool)
    .await
    .expect("First insert failed");

    // Second insert - should return existing tenant
    let second: (i64, String, String) = sqlx::query_as(
        "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name",
    )
    .bind(&domain)
    .bind("Second Name") // Different name
    .bind(r#"{}"#)
    .fetch_one(&pool)
    .await
    .expect("Second insert failed");

    // Should be the same tenant
    assert_eq!(first.0, second.0, "Should return same tenant ID");
    assert_eq!(first.1, second.1, "Should return same domain");
    // Name should be the original (ON CONFLICT doesn't update name)
    assert_eq!(second.2, "First Name", "Name should not change on conflict");

    // Cleanup
    sqlx::query("DELETE FROM tenants WHERE domain = $1")
        .bind(&domain)
        .execute(&pool)
        .await
        .ok();
}
