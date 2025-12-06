//! Test binary for multiprocess pool testing.
//!
//! Spawns a cluster node that reports status via JSON on stdout and accepts
//! commands on stdin. Used by integration tests to verify cross-process behavior.
//!
//! Run: cargo run -p pg-hashring --features pool --bin pool_node

use pg_hashring::{ClusterAwarePool, ClusterCoordinator};
use sqlx::postgres::PgPoolOptions;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// Match demo's connection budget - see examples/demo.rs for explanation
const MAX_POOL_CONNECTIONS: u32 = 60;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());

    // Lazy pool - no connections until first use
    let coord_pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(60))
        .connect_lazy(&database_url)?;

    // Ensure schema exists
    pg_hashring::setup(&coord_pool).await?;

    // Start coordinator - this registers us with the cluster
    let coordinator = Arc::new(ClusterCoordinator::start(coord_pool.clone()).await?);
    coordinator.wait_for_established().await;

    // Create cluster-aware pool
    let cluster_pool = Arc::new(ClusterAwarePool::connect(
        &database_url,
        coordinator.clone(),
        MAX_POOL_CONNECTIONS,
    )?);

    let instance_id = coordinator.instance_id().to_string();
    let short_id = instance_id[..8].to_string();

    // Signal ready with initial status
    print_status("ready", &short_id, &coordinator, &cluster_pool);

    let shutdown = Arc::new(AtomicBool::new(false));

    // Subscribe to membership events
    let mut membership_rx = coordinator.subscribe();
    let event_pool = cluster_pool.clone();
    let event_coord = coordinator.clone();
    let event_short_id = short_id.clone();
    let event_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            if event_shutdown.load(Ordering::Acquire) {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(100), membership_rx.recv()).await {
                Ok(Ok(event)) => {
                    event_pool.on_membership_change();
                    let event_type = match event {
                        pg_hashring::MembershipEvent::Joined(id) => format!("joined:{}", &id[..8]),
                        pg_hashring::MembershipEvent::Left(id) => format!("left:{}", &id[..8]),
                    };
                    print_status(&event_type, &event_short_id, &event_coord, &event_pool);
                }
                Ok(Err(_)) => break,
                Err(_) => {} // timeout
            }
        }
    });

    // Process stdin commands
    let stdin = io::stdin();
    let mut held_connections = Vec::new();

    for line in stdin.lock().lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "status" => {
                print_status("status", &short_id, &coordinator, &cluster_pool);
            }
            "acquire" => {
                let count: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                let mut acquired = 0;
                let mut capped = false;
                for _ in 0..count {
                    match cluster_pool.acquire_timeout(Duration::from_secs(5)).await {
                        Ok(conn) => {
                            held_connections.push(conn);
                            acquired += 1;
                        }
                        Err(_) => {
                            capped = true;
                            break;
                        }
                    }
                }
                println!(
                    r#"{{"event":"acquired","count":{},"held":{},"limit":{},"capped":{}}}"#,
                    acquired,
                    held_connections.len(),
                    cluster_pool.current_limit(),
                    capped
                );
                let _ = io::stdout().flush();
            }
            "release" => {
                let count: usize = parts
                    .get(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(held_connections.len());
                let released = count.min(held_connections.len());
                for _ in 0..released {
                    held_connections.pop();
                }
                println!(
                    r#"{{"event":"released","count":{},"held":{},"active":{}}}"#,
                    released,
                    held_connections.len(),
                    cluster_pool.active_connections()
                );
                let _ = io::stdout().flush();
            }
            "work" => {
                // Acquire, do a query, release - simulates HTTP request
                match cluster_pool.acquire_timeout(Duration::from_secs(5)).await {
                    Ok(mut conn) => {
                        let result: Result<(i32,), _> =
                            sqlx::query_as("SELECT 1").fetch_one(conn.as_mut()).await;
                        match result {
                            Ok(_) => {
                                println!(
                                    r#"{{"event":"work_done","active":{}}}"#,
                                    cluster_pool.active_connections()
                                );
                            }
                            Err(e) => {
                                println!(
                                    r#"{{"event":"work_failed","error":"{}"}}"#,
                                    e.to_string().replace('"', "'")
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            r#"{{"event":"work_failed","error":"{}"}}"#,
                            e.to_string().replace('"', "'")
                        );
                    }
                }
                let _ = io::stdout().flush();
            }
            "quit" | "exit" => {
                break;
            }
            _ => {
                println!(r#"{{"error":"unknown_command","command":"{}"}}"#, parts[0]);
                let _ = io::stdout().flush();
            }
        }
    }

    // Cleanup - must clear connections before dropping the pool they reference
    shutdown.store(true, Ordering::Release);
    drop(held_connections);
    drop(cluster_pool);

    // Give the event handler task time to see the shutdown flag and exit
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Try to gracefully deregister
    match Arc::try_unwrap(coordinator) {
        Ok(coord) => {
            coord.shutdown().await?;
        }
        Err(coord) => {
            // Fallback: force deregister even with remaining references
            // This ensures other instances see us leave via NOTIFY
            coord.force_deregister().await.ok();
        }
    }

    println!(r#"{{"event":"shutdown","id":"{}"}}"#, short_id);
    let _ = io::stdout().flush();
    Ok(())
}

fn print_status(
    event: &str,
    short_id: &str,
    coordinator: &ClusterCoordinator,
    pool: &ClusterAwarePool,
) {
    let metrics = pool.metrics();
    println!(
        r#"{{"event":"{}","id":"{}","instances":{},"limit":{},"active":{},"max_total":{},"evicted":{}}}"#,
        event,
        short_id,
        coordinator.instance_count(),
        metrics.soft_limit,
        metrics.active_connections,
        metrics.max_total,
        metrics.evicted_connections
    );
    let _ = io::stdout().flush();
}
