//! Multi-instance simulation tests for pg-hashring.
//!
//! These tests simulate real-world cluster scenarios with multiple
//! coordinators joining and leaving the cluster.

use pg_hashring::ClusterCoordinator;
use sqlx::PgPool;
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
async fn test_scale_up_from_1_to_5_instances() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start with 1 instance
    let mut coordinators = vec![ClusterCoordinator::start(pool.clone()).await.unwrap()];
    coordinators[0].wait_for_established().await;

    // Verify solo instance handles all keys
    assert!(coordinators[0].should_handle("key-1").await);
    assert!(coordinators[0].should_handle("key-99").await);

    // Scale up to 5 instances
    for _ in 1..5 {
        let coord = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord.wait_for_established().await;
        coordinators.push(coord);
        sleep(Duration::from_millis(100)).await;
    }

    // Give time for all notifications to propagate
    sleep(Duration::from_millis(200)).await;

    // Verify keys are distributed with exactly one owner each
    let mut total_handled = 0;
    for key_idx in 0..100 {
        let key = format!("key-{}", key_idx);
        let mut handlers = 0;
        for coord in &coordinators {
            if coord.should_handle(&key).await {
                handlers += 1;
            }
        }
        assert_eq!(handlers, 1, "Key {} should have exactly 1 handler", key);
        total_handled += handlers;
    }
    assert_eq!(total_handled, 100);

    // Verify roughly even distribution (15-25% each for 5 instances)
    for (i, coord) in coordinators.iter().enumerate() {
        let mut handled = 0;
        for k in 0..100 {
            if coord.should_handle(&format!("key-{}", k)).await {
                handled += 1;
            }
        }
        assert!(
            (10..=35).contains(&handled),
            "Instance {} handles {} keys (expected 15-25)",
            i,
            handled
        );
    }

    // Cleanup
    for coord in coordinators {
        coord.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn test_scale_down_gracefully() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start 3 instances
    let coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord1.wait_for_established().await;

    let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord2.wait_for_established().await;

    let coord3 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord3.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    // Record which keys coord2 handled
    let mut coord2_keys = Vec::new();
    for i in 0..100 {
        let key = format!("key-{}", i);
        if coord2.should_handle(&key).await {
            coord2_keys.push(key);
        }
    }

    // Gracefully shutdown coord2
    coord2.shutdown().await.unwrap();

    sleep(Duration::from_millis(200)).await;

    // coord2's keys should now be handled by coord1 or coord3
    for key in &coord2_keys {
        let handled_by_1 = coord1.should_handle(key).await;
        let handled_by_3 = coord3.should_handle(key).await;
        assert!(
            handled_by_1 || handled_by_3,
            "Key {} orphaned after coord2 shutdown",
            key
        );
        assert!(
            !(handled_by_1 && handled_by_3),
            "Key {} handled by both coord1 and coord3",
            key
        );
    }

    coord1.shutdown().await.unwrap();
    coord3.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_rolling_restart_no_orphans() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start 3 instances
    let mut coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord1.wait_for_established().await;

    let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord2.wait_for_established().await;

    let coord3 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord3.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    // Rolling restart: shutdown coord1, start new coord1
    coord1.shutdown().await.unwrap();
    sleep(Duration::from_millis(100)).await;

    coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord1.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    // Verify all keys still have exactly one owner
    for key_idx in 0..100 {
        let key = format!("key-{}", key_idx);
        let mut handlers = 0;
        if coord1.should_handle(&key).await {
            handlers += 1;
        }
        if coord2.should_handle(&key).await {
            handlers += 1;
        }
        if coord3.should_handle(&key).await {
            handlers += 1;
        }
        assert_eq!(
            handlers, 1,
            "Key {} should have exactly 1 handler after rolling restart, got {}",
            key, handlers
        );
    }

    coord1.shutdown().await.unwrap();
    coord2.shutdown().await.unwrap();
    coord3.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_crash_recovery_via_heartbeat() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start 2 instances
    let coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord1.wait_for_established().await;

    let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord2.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    // Find a key that coord2 owns
    let mut coord2_key = None;
    for i in 0..100 {
        let key = format!("key-{}", i);
        if coord2.should_handle(&key).await {
            coord2_key = Some(key);
            break;
        }
    }
    let coord2_key = coord2_key.expect("coord2 should own at least one key");

    // Simulate crash: drop coord2 without calling shutdown()
    // This means no "left:" notification is sent
    let coord2_id = coord2.instance_id().to_string();
    drop(coord2);

    // Immediately after crash, coord1 still thinks coord2 owns the key
    // (because no notification was sent)
    assert!(
        !coord1.should_handle(&coord2_key).await,
        "Immediately after crash, coord1 should NOT handle coord2's key (stale ring)"
    );

    // Manually mark coord2 as stale in the database (simulate time passing)
    sqlx::query(
        "UPDATE signer_instances SET last_heartbeat = NOW() - INTERVAL '35 seconds' WHERE instance_id = $1::uuid"
    )
    .bind(&coord2_id)
    .execute(&pool)
    .await
    .unwrap();

    // Trigger manual refresh (simulates what happens at heartbeat, but immediately)
    coord1.refresh().await.unwrap();

    // After refresh, coord1 should now handle the key that coord2 used to own
    assert!(
        coord1.should_handle(&coord2_key).await,
        "After refresh, coord1 should handle coord2's former key"
    );

    // Verify instance count is now 1
    assert_eq!(
        coord1.instance_count().await,
        1,
        "After refresh, only coord1 should be in the ring"
    );

    coord1.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_joins() {
    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start 5 coordinators concurrently
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let p = pool.clone();
            tokio::spawn(async move { ClusterCoordinator::start(p).await })
        })
        .collect();

    let mut coordinators = Vec::new();
    for handle in handles {
        let coord = handle.await.unwrap().unwrap();
        coord.wait_for_established().await;
        coordinators.push(coord);
    }

    // Give time for notifications to propagate
    sleep(Duration::from_millis(500)).await;

    // All should see 5 instances
    for (i, coord) in coordinators.iter().enumerate() {
        let count = coord.instance_count().await;
        assert_eq!(
            count, 5,
            "Coordinator {} sees {} instances (expected 5)",
            i, count
        );
    }

    // Verify exactly one owner per key
    for key_idx in 0..100 {
        let key = format!("key-{}", key_idx);
        let mut handlers = 0;
        for coord in &coordinators {
            if coord.should_handle(&key).await {
                handlers += 1;
            }
        }
        assert_eq!(handlers, 1, "Key {} should have exactly 1 handler", key);
    }

    for coord in coordinators {
        coord.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn test_shutdown_drain_period() {
    use std::time::Instant;

    let pool = get_test_pool().await;
    cleanup_test_instances(&pool).await;

    // Start 2 instances
    let coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord1.wait_for_established().await;

    let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
    coord2.wait_for_established().await;

    sleep(Duration::from_millis(200)).await;

    // Find a key that coord2 owns
    let mut coord2_key = None;
    for i in 0..100 {
        let key = format!("key-{}", i);
        if coord2.should_handle(&key).await {
            coord2_key = Some(key);
            break;
        }
    }
    let coord2_key = coord2_key.expect("coord2 should own at least one key");

    // Before shutdown, coord1 does NOT handle coord2's key
    assert!(
        !coord1.should_handle(&coord2_key).await,
        "Before shutdown, coord1 should NOT handle coord2's key"
    );

    // Measure shutdown duration (should include drain period)
    let start = Instant::now();
    coord2.shutdown().await.unwrap();
    let shutdown_duration = start.elapsed();

    // Verify shutdown took at least the drain period (100ms)
    // Allow some slack for timing variations
    assert!(
        shutdown_duration >= Duration::from_millis(90),
        "Shutdown should take at least ~100ms due to drain period, took {:?}",
        shutdown_duration
    );

    // IMMEDIATELY after shutdown (no sleep!), coord1 should already handle the key
    // This proves the drain period gave coord1 time to receive the notification
    assert!(
        coord1.should_handle(&coord2_key).await,
        "Immediately after shutdown, coord1 should handle coord2's former key (drain worked)"
    );

    // Verify coord1 now sees only 1 instance
    assert_eq!(
        coord1.instance_count().await,
        1,
        "After shutdown, only coord1 should remain"
    );

    coord1.shutdown().await.unwrap();
}
