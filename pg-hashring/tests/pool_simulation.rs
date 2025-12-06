//! Pool simulation tests for cluster-aware connection pooling.
//!
//! These tests verify that ClusterAwarePool correctly adjusts limits
//! based on cluster membership changes.
//!
//! Run with: cargo test -p pg-hashring --features pool --test pool_simulation -- --test-threads=1

#![cfg(feature = "pool")]

use pg_hashring::{ClusterAwarePool, ClusterCoordinator};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

async fn get_test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());
    PgPool::connect(&url).await.unwrap()
}

async fn cleanup_test_instances(pool: &PgPool) {
    sqlx::query("DELETE FROM signer_instances")
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn test_pool_single_instance_gets_full_share() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    let coord = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord.wait_for_established().await;

    let cluster_pool = ClusterAwarePool::new(pool.clone(), Arc::new(coord), 100);

    // Single instance should get full 100 connections
    assert_eq!(cluster_pool.current_limit(), 100);
    assert_eq!(cluster_pool.active_connections(), 0);
    assert_eq!(cluster_pool.max_total(), 100);
}

#[tokio::test]
#[serial]
async fn test_pool_limit_decreases_on_join() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start first coordinator
    let coord1 = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord1.wait_for_established().await;
    let pool1 = ClusterAwarePool::new(pool.clone(), coord1.clone(), 100);

    assert_eq!(pool1.current_limit(), 100);

    // Start second coordinator
    let coord2 = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord2.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    // Trigger membership change callback
    pool1.on_membership_change();

    // Each should now get 50
    assert_eq!(pool1.current_limit(), 50);

    let pool2 = ClusterAwarePool::new(pool.clone(), coord2.clone(), 100);
    assert_eq!(pool2.current_limit(), 50);

    // Cleanup
    drop(pool1);
    drop(pool2);
    // coord1 is wrapped in Arc used by pool1, so we can't shutdown directly
    // coord2 is wrapped in Arc used by pool2
}

#[tokio::test]
#[serial]
async fn test_pool_limit_increases_on_leave() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start two coordinators
    let coord1 = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord1.wait_for_established().await;

    let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord2.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    let pool1 = ClusterAwarePool::new(pool.clone(), coord1.clone(), 100);
    assert_eq!(pool1.current_limit(), 50);

    // Shutdown coord2
    coord2.shutdown().await.unwrap();
    sleep(Duration::from_millis(200)).await;

    // Trigger membership change
    pool1.on_membership_change();

    // coord1 should now get full 100
    assert_eq!(pool1.current_limit(), 100);
}

#[tokio::test]
#[serial]
async fn test_pool_acquire_respects_limit() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    let coord = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord.wait_for_established().await;

    // Create pool with low limit for testing
    let cluster_pool = ClusterAwarePool::new(pool.clone(), coord, 3);
    assert_eq!(cluster_pool.current_limit(), 3);

    // Acquire 3 connections
    let conn1 = cluster_pool.acquire().await.unwrap();
    let conn2 = cluster_pool.acquire().await.unwrap();
    let conn3 = cluster_pool.acquire().await.unwrap();

    assert_eq!(cluster_pool.active_connections(), 3);

    // try_acquire should return None when at limit
    let result = cluster_pool.try_acquire().await.unwrap();
    assert!(
        result.is_none(),
        "try_acquire should return None when at limit"
    );

    // Drop one connection
    drop(conn1);
    sleep(Duration::from_millis(20)).await;

    assert_eq!(cluster_pool.active_connections(), 2);

    // Now try_acquire should succeed
    let conn4 = cluster_pool.try_acquire().await.unwrap();
    assert!(
        conn4.is_some(),
        "try_acquire should succeed after releasing a connection"
    );
    assert_eq!(cluster_pool.active_connections(), 3);

    drop(conn2);
    drop(conn3);
    drop(conn4);
}

#[tokio::test]
#[serial]
async fn test_pool_minimum_connections() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    let coord = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord.wait_for_established().await;

    // Even with low max_total, minimum is enforced
    let cluster_pool = ClusterAwarePool::new(pool.clone(), coord, 1);

    // Minimum is 2, not 1
    assert_eq!(cluster_pool.current_limit(), 2);
}

#[tokio::test]
#[serial]
async fn test_pool_concurrent_acquire() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    let coord = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord.wait_for_established().await;

    let cluster_pool = Arc::new(ClusterAwarePool::new(pool.clone(), coord, 5));

    // Spawn 10 tasks trying to acquire connections
    let mut handles = vec![];
    for i in 0..10 {
        let pool_clone = cluster_pool.clone();
        handles.push(tokio::spawn(async move {
            let conn = pool_clone.acquire().await;
            // Hold for a bit
            sleep(Duration::from_millis(50)).await;
            drop(conn);
            i
        }));
    }

    // All should eventually succeed (they'll queue)
    for handle in handles {
        let _ = handle.await.unwrap();
    }

    // After all tasks complete, active should be 0
    sleep(Duration::from_millis(100)).await;
    assert_eq!(cluster_pool.active_connections(), 0);
}

#[tokio::test]
#[serial]
async fn test_pool_scale_up_to_5_instances() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start with 1 instance
    let coord1 = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord1.wait_for_established().await;
    let pool1 = ClusterAwarePool::new(pool.clone(), coord1.clone(), 100);
    assert_eq!(pool1.current_limit(), 100);

    // Scale up to 5 instances
    let mut coordinators = vec![];
    for _ in 1..5 {
        let coord = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
        coord.wait_for_established().await;
        coordinators.push(coord);
        sleep(Duration::from_millis(100)).await;
    }

    sleep(Duration::from_millis(200)).await;

    // Trigger membership change
    pool1.on_membership_change();

    // Each of 5 instances should get 20 (100/5)
    assert_eq!(pool1.current_limit(), 20);

    // Verify a new pool sees the same
    let pool5 = ClusterAwarePool::new(pool.clone(), coordinators[3].clone(), 100);
    assert_eq!(pool5.current_limit(), 20);
}

#[tokio::test]
#[serial]
async fn test_pool_natural_convergence_on_shrink() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start 2 coordinators
    let coord1 = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord1.wait_for_established().await;

    let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord2.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    let cluster_pool = ClusterAwarePool::new(pool.clone(), coord1.clone(), 100);
    assert_eq!(cluster_pool.current_limit(), 50);

    // Acquire some connections
    let conn1 = cluster_pool.acquire().await.unwrap();
    let conn2 = cluster_pool.acquire().await.unwrap();
    let conn3 = cluster_pool.acquire().await.unwrap();

    assert_eq!(cluster_pool.active_connections(), 3);

    // Now add a third coordinator
    let coord3 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord3.wait_for_established().await;
    sleep(Duration::from_millis(200)).await;

    // Trigger membership change - limit drops to 33
    cluster_pool.on_membership_change();
    assert_eq!(cluster_pool.current_limit(), 33);

    // We're still holding 3 connections, which is under 33, so try_acquire should work
    let conn4 = cluster_pool.try_acquire().await.unwrap();
    assert!(conn4.is_some());

    drop(conn1);
    drop(conn2);
    drop(conn3);
    drop(conn4);

    coord2.shutdown().await.unwrap();
    coord3.shutdown().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_pool_connection_tracking() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    let coord = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord.wait_for_established().await;

    let cluster_pool = ClusterAwarePool::new(pool.clone(), coord, 10);

    // Acquire a connection
    let conn = cluster_pool.acquire().await.unwrap();
    assert_eq!(cluster_pool.active_connections(), 1);

    // Acquire another
    let conn2 = cluster_pool.acquire().await.unwrap();
    assert_eq!(cluster_pool.active_connections(), 2);

    // Drop first connection
    drop(conn);
    sleep(Duration::from_millis(10)).await;
    assert_eq!(cluster_pool.active_connections(), 1);

    // Drop second
    drop(conn2);
    sleep(Duration::from_millis(10)).await;
    assert_eq!(cluster_pool.active_connections(), 0);
}

#[tokio::test]
#[serial]
async fn test_pool_inner_access() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    let coord = Arc::new(ClusterCoordinator::start(pool.clone()).await.unwrap());
    coord.wait_for_established().await;

    let cluster_pool = ClusterAwarePool::new(pool.clone(), coord, 100);

    // Can access inner pool directly for operations that don't need limiting
    let inner = cluster_pool.inner();
    let result: (i32,) = sqlx::query_as("SELECT 1").fetch_one(inner).await.unwrap();
    assert_eq!(result.0, 1);
}
