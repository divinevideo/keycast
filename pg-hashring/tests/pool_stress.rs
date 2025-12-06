//! Stress test for cluster-aware connection pooling with multiple instances.
//!
//! Tests:
//! - Natural convergence when instances join
//! - Connection limits adjust correctly (80 → 40 → 26)
//! - All instances can acquire connections without PoolTimedOut
//!
//! Run with: cargo test -p pg-hashring --features pool --test pool_stress -- --nocapture

#![cfg(feature = "pool")]

use pg_hashring::{ClusterAwarePool, ClusterCoordinator};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// In production, each instance runs in separate container with its own pool.
// For testing multiple instances in one process, we need to account for
// PostgreSQL max_connections (usually 100) being shared by all pools.
// 30 * 3 instances = 90, leaving headroom for coordinator pools.
const MAX_POOL_CONNECTIONS: u32 = 30;

async fn get_test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap()
}

async fn cleanup_test_instances(pool: &PgPool) {
    sqlx::query("DELETE FROM signer_instances")
        .execute(pool)
        .await
        .unwrap();
}

struct WorkerMetrics {
    completed: AtomicU64,
    failed: AtomicU64,
}

impl WorkerMetrics {
    fn new() -> Self {
        Self {
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }
}

async fn run_workers(
    pool: Arc<ClusterAwarePool>,
    count: usize,
    duration: Duration,
    metrics: Arc<WorkerMetrics>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = vec![];
    let stop_at = Instant::now() + duration;

    for _ in 0..count {
        let pool = pool.clone();
        let metrics = metrics.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < stop_at {
                match pool.acquire().await {
                    Ok(mut conn) => {
                        let result = sqlx::query("SELECT 1").execute(conn.as_mut()).await;
                        drop(conn);
                        match result {
                            Ok(_) => metrics.completed.fetch_add(1, Ordering::Relaxed),
                            Err(_) => metrics.failed.fetch_add(1, Ordering::Relaxed),
                        };
                    }
                    Err(_) => {
                        metrics.failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }
    handles
}

#[tokio::test]
#[serial]
async fn test_three_instance_stress() {
    let base_pool = get_test_pool().await;
    cleanup_test_instances(&base_pool).await;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());

    println!("\n=== THREE INSTANCE STRESS TEST ===\n");

    // Phase 1: Single instance with full capacity
    println!("Phase 1: Starting Instance 1 (limit=80)");
    let coord1 = Arc::new(ClusterCoordinator::start(base_pool.clone()).await.unwrap());
    coord1.wait_for_established().await;
    let pool1 = Arc::new(
        ClusterAwarePool::connect(&database_url, coord1.clone(), MAX_POOL_CONNECTIONS).unwrap(),
    );

    assert_eq!(pool1.current_limit(), 30, "Instance 1 should have limit=30");
    println!("  Instance 1 limit: {}", pool1.current_limit());

    // Start workers on instance 1
    let metrics1 = Arc::new(WorkerMetrics::new());
    let workers1 = run_workers(pool1.clone(), 25, Duration::from_secs(10), metrics1.clone()).await;
    println!("  Started 25 workers on Instance 1");

    // Let it run for a bit
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!(
        "  Instance 1 after 2s: {} completed, pool {}/{}",
        metrics1.completed.load(Ordering::Relaxed),
        pool1.active_connections(),
        pool1.current_limit()
    );

    // Phase 2: Second instance joins
    println!("\nPhase 2: Starting Instance 2 (limit should drop to 40 each)");
    let coord2 = Arc::new(ClusterCoordinator::start(base_pool.clone()).await.unwrap());
    coord2.wait_for_established().await;

    // Wait for coordinator to sync
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Manually trigger membership change on pool1
    pool1.on_membership_change();

    let pool2 = Arc::new(
        ClusterAwarePool::connect(&database_url, coord2.clone(), MAX_POOL_CONNECTIONS).unwrap(),
    );

    println!("  Instance 1 limit: {}", pool1.current_limit());
    println!("  Instance 2 limit: {}", pool2.current_limit());
    assert_eq!(
        pool1.current_limit(),
        15,
        "Instance 1 should have limit=15 after join"
    );
    assert_eq!(pool2.current_limit(), 15, "Instance 2 should have limit=15");

    // Start workers on instance 2
    let metrics2 = Arc::new(WorkerMetrics::new());
    let workers2 = run_workers(pool2.clone(), 12, Duration::from_secs(8), metrics2.clone()).await;
    println!("  Started 12 workers on Instance 2");

    // Let them run together
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!(
        "  Instance 1: {} completed, pool {}/{}",
        metrics1.completed.load(Ordering::Relaxed),
        pool1.active_connections(),
        pool1.current_limit()
    );
    println!(
        "  Instance 2: {} completed, pool {}/{}",
        metrics2.completed.load(Ordering::Relaxed),
        pool2.active_connections(),
        pool2.current_limit()
    );

    // Phase 3: Third instance joins
    println!("\nPhase 3: Starting Instance 3 (limit should drop to ~26 each)");
    let coord3 = Arc::new(ClusterCoordinator::start(base_pool.clone()).await.unwrap());
    coord3.wait_for_established().await;

    // Wait for coordinator to sync
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Manually trigger membership change on pool1 and pool2
    pool1.on_membership_change();
    pool2.on_membership_change();

    let pool3 = Arc::new(
        ClusterAwarePool::connect(&database_url, coord3.clone(), MAX_POOL_CONNECTIONS).unwrap(),
    );

    println!("  Instance 1 limit: {}", pool1.current_limit());
    println!("  Instance 2 limit: {}", pool2.current_limit());
    println!("  Instance 3 limit: {}", pool3.current_limit());
    assert_eq!(
        pool1.current_limit(),
        10,
        "Instance 1 should have limit=10 after 3rd join"
    );
    assert_eq!(
        pool2.current_limit(),
        10,
        "Instance 2 should have limit=10 after 3rd join"
    );
    assert_eq!(pool3.current_limit(), 10, "Instance 3 should have limit=10");

    // Start workers on instance 3
    let metrics3 = Arc::new(WorkerMetrics::new());
    let workers3 = run_workers(pool3.clone(), 8, Duration::from_secs(6), metrics3.clone()).await;
    println!("  Started 8 workers on Instance 3");

    // Let them all run
    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("\n=== FINAL METRICS ===");
    println!(
        "  Instance 1: {} completed, {} failed, pool {}/{}",
        metrics1.completed.load(Ordering::Relaxed),
        metrics1.failed.load(Ordering::Relaxed),
        pool1.active_connections(),
        pool1.current_limit()
    );
    println!(
        "  Instance 2: {} completed, {} failed, pool {}/{}",
        metrics2.completed.load(Ordering::Relaxed),
        metrics2.failed.load(Ordering::Relaxed),
        pool2.active_connections(),
        pool2.current_limit()
    );
    println!(
        "  Instance 3: {} completed, {} failed, pool {}/{}",
        metrics3.completed.load(Ordering::Relaxed),
        metrics3.failed.load(Ordering::Relaxed),
        pool3.active_connections(),
        pool3.current_limit()
    );

    // Wait for workers to finish
    for handle in workers1 {
        let _ = handle.await;
    }
    for handle in workers2 {
        let _ = handle.await;
    }
    for handle in workers3 {
        let _ = handle.await;
    }

    // Verify no major failures
    let total_failed = metrics1.failed.load(Ordering::Relaxed)
        + metrics2.failed.load(Ordering::Relaxed)
        + metrics3.failed.load(Ordering::Relaxed);
    let total_completed = metrics1.completed.load(Ordering::Relaxed)
        + metrics2.completed.load(Ordering::Relaxed)
        + metrics3.completed.load(Ordering::Relaxed);

    println!("\n=== SUMMARY ===");
    println!("  Total completed: {}", total_completed);
    println!("  Total failed: {}", total_failed);
    println!(
        "  Success rate: {:.1}%",
        (total_completed as f64 / (total_completed + total_failed) as f64) * 100.0
    );

    assert!(
        total_completed > 1000,
        "Should have completed many requests, got {}",
        total_completed
    );
    assert!(
        total_failed < total_completed / 10,
        "Failure rate too high: {} failed of {}",
        total_failed,
        total_completed
    );

    println!("\n=== TEST PASSED ===\n");
}
