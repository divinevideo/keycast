//! Interactive demo of pg-hashring cluster coordination with ClusterAwarePool.
//!
//! Run multiple instances in separate terminals:
//!   cargo run -p pg-hashring --features pool --example demo
//!
//! Simulates HTTP server behavior: acquire connection, do work, release, repeat.
//!
//! Try:
//! 1. Start one instance, run `/work 50` to simulate 50 concurrent HTTP handlers
//! 2. Run `/metrics` to see throughput and latency
//! 3. Start a second instance - watch acquire latency spike then recover
//! 4. Kill an instance with Ctrl+C to see throughput increase

use pg_hashring::{ClusterAwarePool, ClusterCoordinator, MembershipEvent};
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::PgPool;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};

const DEMO_CHANNEL: &str = "demo_messages";

// Connection budget for PostgreSQL (default max_connections=100):
// - cluster_pool: MAX_POOL_CONNECTIONS total shared across all instances
// - coord_pool: up to 5 per instance (for LISTEN/NOTIFY, heartbeats)
// - external: ~10 reserved for psql, migrations, monitoring
//
// Example with 5 instances: 60 + (5×5) + 10 = 95 < 100
const MAX_POOL_CONNECTIONS: u32 = 60;

const DEMO_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS demo_counters (
    key TEXT PRIMARY KEY,
    count BIGINT NOT NULL DEFAULT 0,
    owner_instance TEXT,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"#;

/// Metrics for workload tracking
struct WorkMetrics {
    requests_completed: AtomicU64,
    requests_failed: AtomicU64,
    total_acquire_us: AtomicU64,
    total_work_us: AtomicU64,
    max_acquire_us: AtomicU64,
    started_at: Mutex<Option<Instant>>,
}

impl WorkMetrics {
    fn new() -> Self {
        Self {
            requests_completed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            total_acquire_us: AtomicU64::new(0),
            total_work_us: AtomicU64::new(0),
            max_acquire_us: AtomicU64::new(0),
            started_at: Mutex::new(None),
        }
    }

    fn record_success(&self, acquire_us: u64, work_us: u64) {
        self.requests_completed.fetch_add(1, Ordering::Relaxed);
        self.total_acquire_us
            .fetch_add(acquire_us, Ordering::Relaxed);
        self.total_work_us.fetch_add(work_us, Ordering::Relaxed);

        // Update max acquire time
        let mut current_max = self.max_acquire_us.load(Ordering::Relaxed);
        while acquire_us > current_max {
            match self.max_acquire_us.compare_exchange_weak(
                current_max,
                acquire_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }
    }

    fn record_failure(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
    }

    async fn reset(&self) {
        self.requests_completed.store(0, Ordering::Relaxed);
        self.requests_failed.store(0, Ordering::Relaxed);
        self.total_acquire_us.store(0, Ordering::Relaxed);
        self.total_work_us.store(0, Ordering::Relaxed);
        self.max_acquire_us.store(0, Ordering::Relaxed);
        *self.started_at.lock().await = Some(Instant::now());
    }

    async fn snapshot(&self) -> MetricsSnapshot {
        let completed = self.requests_completed.load(Ordering::Relaxed);
        let failed = self.requests_failed.load(Ordering::Relaxed);
        let total_acquire = self.total_acquire_us.load(Ordering::Relaxed);
        let total_work = self.total_work_us.load(Ordering::Relaxed);
        let max_acquire = self.max_acquire_us.load(Ordering::Relaxed);
        let elapsed = self
            .started_at
            .lock()
            .await
            .map(|s| s.elapsed())
            .unwrap_or_default();

        MetricsSnapshot {
            completed,
            failed,
            avg_acquire_us: if completed > 0 {
                total_acquire / completed
            } else {
                0
            },
            avg_work_us: if completed > 0 {
                total_work / completed
            } else {
                0
            },
            max_acquire_us: max_acquire,
            elapsed,
            rps: if elapsed.as_secs_f64() > 0.0 {
                completed as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            },
        }
    }
}

struct MetricsSnapshot {
    completed: u64,
    failed: u64,
    avg_acquire_us: u64,
    avg_work_us: u64,
    max_acquire_us: u64,
    elapsed: Duration,
    rps: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());

    // Small pool for coordinator (LISTEN/NOTIFY, heartbeats, registration).
    // Uses connect_lazy() to avoid blocking on startup when PostgreSQL is near
    // its connection limit - connections are established on first acquire.
    // min_connections(1) ensures at least one connection stays warm after first use.
    // idle_timeout cleans up if process crashes without graceful shutdown.
    let coord_pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(60))
        .connect_lazy(&database_url)?;

    // Ensure schemas exist
    pg_hashring::setup(&coord_pool).await?;
    sqlx::query(DEMO_SCHEMA).execute(&coord_pool).await?;

    // Start the cluster coordinator
    let coordinator = Arc::new(ClusterCoordinator::start(coord_pool.clone()).await?);
    coordinator.wait_for_established().await;

    // Create cluster-aware pool with correct capacity (lazy - no connections until first acquire)
    let cluster_pool = Arc::new(ClusterAwarePool::connect(
        &database_url,
        coordinator.clone(),
        MAX_POOL_CONNECTIONS,
    )?);

    let instance_id = coordinator.instance_id().to_string();
    let short_id = instance_id[..8].to_string();

    // Shutdown signals
    let shutdown = Arc::new(AtomicBool::new(false));
    let work_running = Arc::new(AtomicBool::new(false));
    let work_workers = Arc::new(AtomicUsize::new(0));
    let metrics = Arc::new(WorkMetrics::new());

    // Set up signal handler for graceful shutdown
    let (ctrlc_tx, ctrlc_rx) = oneshot::channel::<()>();
    let ctrlc_tx = std::sync::Mutex::new(Some(ctrlc_tx));
    ctrlc::set_handler(move || {
        if let Some(tx) = ctrlc_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    })?;

    print_banner(
        &short_id,
        coordinator.instance_count(),
        cluster_pool.current_limit(),
    );

    // Spawn membership event handler (uses coordinator subscription for race-free updates)
    let membership_handle = {
        let mut membership_rx = coordinator.subscribe();
        let cluster_pool = cluster_pool.clone();
        let coordinator = coordinator.clone();
        let short_id = short_id.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }

                // Use timeout to allow checking shutdown flag periodically
                match tokio::time::timeout(Duration::from_millis(100), membership_rx.recv()).await {
                    Ok(Ok(event)) => {
                        // Events are only received AFTER the ring is updated,
                        // so instance_count() is guaranteed to be consistent
                        cluster_pool.on_membership_change();
                        let count = coordinator.instance_count();
                        let limit = cluster_pool.current_limit();
                        let active = cluster_pool.active_connections();

                        match event {
                            MembershipEvent::Joined(id) => {
                                println!(
                                    "\n  [+] Instance {} joined! Cluster: {}, Limit: {} (active: {})",
                                    &id[..8.min(id.len())], count, limit, active
                                );
                                if active > limit {
                                    println!("      Over limit! Acquire latency will increase until convergence.");
                                }
                            }
                            MembershipEvent::Left(id) => {
                                println!(
                                    "\n  [-] Instance {} left. Cluster: {}, Limit: {}",
                                    &id[..8.min(id.len())],
                                    count,
                                    limit
                                );
                            }
                        }

                        print!("[{}] > ", short_id);
                        let _ = io::stdout().flush();
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                        eprintln!("  Warning: Missed {} membership events", n);
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                        break;
                    }
                    Err(_) => {} // timeout, continue to check shutdown
                }
            }
        })
    };

    // Spawn listener for demo messages only (not membership - that's handled above)
    let listener_handle = {
        let coord = coordinator.clone();
        let listener_pool = coord_pool.clone();
        let cluster_pool = cluster_pool.clone();
        let short_id = short_id.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_demo_listener(listener_pool, coord, cluster_pool, short_id, shutdown).await
            {
                eprintln!("Listener error: {}", e);
            }
        })
    };

    // Spawn stdin reader
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<String>(10);
    let prompt_id = short_id.clone();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        loop {
            print!("[{}] > ", prompt_id);
            let _ = stdout.flush();
            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if input_tx.blocking_send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Main event loop
    let mut ctrlc_rx = ctrlc_rx;
    loop {
        tokio::select! {
            _ = &mut ctrlc_rx => {
                println!("\n  Shutting down gracefully...");
                break;
            }
            Some(line) = input_rx.recv() => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                match input {
                    "/quit" | "/exit" | "/q" => {
                        println!("  Shutting down...");
                        break;
                    }
                    "/status" | "/s" => {
                        cmd_status(&coordinator).await;
                    }
                    "/pool" | "/p" => {
                        cmd_pool(&cluster_pool);
                    }
                    "/metrics" | "/m" => {
                        cmd_metrics(&metrics, &cluster_pool).await;
                    }
                    "/stats" => {
                        cmd_stats(&coord_pool, &short_id).await;
                    }
                    "/refresh" | "/r" => {
                        cmd_refresh(&coordinator, &cluster_pool).await;
                    }
                    s if s.starts_with("/work") => {
                        let arg = s.split_whitespace().nth(1).unwrap_or("50");
                        if arg == "stop" {
                            cmd_work_stop(&work_running, &work_workers);
                        } else {
                            let n = arg.parse().unwrap_or(50);
                            cmd_work_start(n, &work_running, &work_workers, &cluster_pool, &metrics, &short_id).await;
                        }
                    }
                    _ => {
                        // Broadcast the message
                        if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)")
                            .bind(DEMO_CHANNEL)
                            .bind(input)
                            .execute(&coord_pool)
                            .await
                        {
                            println!("  Error: {}", e);
                        }
                    }
                }
            }
        }
    }

    // Cleanup
    shutdown.store(true, Ordering::Release);
    work_running.store(false, Ordering::Release);

    // Wait for workers to finish
    let start = Instant::now();
    while work_workers.load(Ordering::Acquire) > 0 && start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = listener_handle.await;
    let _ = membership_handle.await;

    // Drop cluster_pool before unwrapping coordinator (it holds an Arc<ClusterCoordinator>)
    drop(cluster_pool);

    match Arc::try_unwrap(coordinator) {
        Ok(coord) => coord.shutdown().await?,
        Err(_) => eprintln!("  Warning: Could not gracefully deregister"),
    }

    println!("  Goodbye!");

    // Force exit because the stdin reader thread blocks on read_line()
    // and won't notice shutdown until user presses Enter
    std::process::exit(0);
}

fn print_banner(short_id: &str, instances: usize, limit: usize) {
    println!();
    println!("+-----------------------------------------------------------------+");
    println!("|           pg-hashring Pool Demo                                 |");
    println!("+-----------------------------------------------------------------+");
    println!(
        "|  Instance: {}   Cluster: {} instance(s)   Limit: {} conns  |",
        short_id, instances, limit
    );
    println!("+-----------------------------------------------------------------+");
    println!("|  Commands:                                                      |");
    println!("|    /work N     - Start N workers (simulates HTTP handlers)      |");
    println!("|    /work stop  - Stop workers                                   |");
    println!("|    /metrics    - Show throughput and latency stats              |");
    println!("|    /pool       - Connection pool stats (limit/active/max)       |");
    println!("|    /status     - Cluster status and key ownership               |");
    println!("|    /stats      - Show demo_counters table                       |");
    println!("|    /refresh    - Force-sync hashring from database              |");
    println!("|    /quit       - Exit gracefully                                |");
    println!("|                                                                 |");
    println!("|  Type any text to broadcast - owner will bump counter in DB     |");
    println!("+-----------------------------------------------------------------+");
    println!();
}

async fn cmd_status(coordinator: &ClusterCoordinator) {
    let count = coordinator.instance_count();
    println!("  Cluster: {} instance(s)", count);
    let mut my_keys = 0;
    for i in 0..10 {
        if coordinator.should_handle(&format!("test-key-{}", i)) {
            my_keys += 1;
        }
    }
    println!(
        "  I own {}/10 sample keys ({:.0}%)",
        my_keys,
        my_keys as f64 * 10.0
    );
}

fn cmd_pool(cluster_pool: &ClusterAwarePool) {
    let limit = cluster_pool.current_limit();
    let active = cluster_pool.active_connections();
    let max = cluster_pool.max_total();
    let bar_len = 30;
    let filled = (active * bar_len) / limit.max(1);
    let bar: String = (0..bar_len)
        .map(|i| if i < filled { '#' } else { '-' })
        .collect();
    println!("  Pool: [{bar}] {active}/{limit} (max cluster: {max})");
    if active > limit {
        println!("  ** OVER LIMIT ** - new acquires blocked until convergence");
    }
}

async fn cmd_metrics(metrics: &WorkMetrics, pool: &ClusterAwarePool) {
    let snap = metrics.snapshot().await;
    let limit = pool.current_limit();
    let active = pool.active_connections();

    println!("  ---- Workload Metrics ----");
    println!(
        "  Completed: {} requests ({} failed)",
        snap.completed, snap.failed
    );
    println!("  Throughput: {:.1} req/s", snap.rps);
    println!(
        "  Acquire latency: avg {:.2}ms, max {:.2}ms",
        snap.avg_acquire_us as f64 / 1000.0,
        snap.max_acquire_us as f64 / 1000.0
    );
    println!(
        "  Work latency: avg {:.2}ms",
        snap.avg_work_us as f64 / 1000.0
    );
    println!("  Pool: {}/{} connections", active, limit);
    println!("  Elapsed: {:.1}s", snap.elapsed.as_secs_f64());
}

async fn cmd_stats(pool: &PgPool, short_id: &str) {
    match sqlx::query_as::<_, (String, i64, Option<String>)>(
        "SELECT key, count, owner_instance FROM demo_counters ORDER BY count DESC LIMIT 10",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => {
            if rows.is_empty() {
                println!("  No counters yet. Broadcast some messages!");
            } else {
                println!("  Top counters:");
                for (key, count, owner) in rows {
                    let marker = if owner
                        .as_ref()
                        .map(|o| o.starts_with(short_id))
                        .unwrap_or(false)
                    {
                        " <- me"
                    } else {
                        ""
                    };
                    println!(
                        "    {} = {} (owner: {}){}",
                        key,
                        count,
                        owner.unwrap_or_default(),
                        marker
                    );
                }
            }
        }
        Err(e) => println!("  Error: {}", e),
    }
}

async fn cmd_refresh(coordinator: &ClusterCoordinator, cluster_pool: &ClusterAwarePool) {
    println!("  Refreshing hashring...");
    match coordinator.refresh().await {
        Ok(()) => {
            cluster_pool.on_membership_change();
            println!(
                "  Done. Cluster: {} instances, Limit: {}",
                coordinator.instance_count(),
                cluster_pool.current_limit()
            );
        }
        Err(e) => println!("  Error: {}", e),
    }
}

async fn cmd_work_start(
    n: usize,
    work_running: &Arc<AtomicBool>,
    work_workers: &Arc<AtomicUsize>,
    cluster_pool: &Arc<ClusterAwarePool>,
    metrics: &Arc<WorkMetrics>,
    short_id: &str,
) {
    if work_running.swap(true, Ordering::AcqRel) {
        println!("  Work already running. Use /work stop first.");
        return;
    }

    metrics.reset().await;
    println!(
        "  Starting {} workers (acquire -> query -> release -> repeat)...",
        n
    );

    for _ in 0..n {
        let pool = cluster_pool.clone();
        let running = work_running.clone();
        let workers = work_workers.clone();
        let metrics = metrics.clone();
        let id = short_id.to_string();

        workers.fetch_add(1, Ordering::AcqRel);

        tokio::spawn(async move {
            while running.load(Ordering::Acquire) {
                let start = Instant::now();

                // Acquire connection (may block if at limit)
                let mut conn = match pool.acquire().await {
                    Ok(c) => c,
                    Err(_) => {
                        metrics.record_failure();
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };

                let acquire_time = start.elapsed();

                // Do some work - increment a counter
                let work_start = Instant::now();
                let result = sqlx::query(
                    "INSERT INTO demo_counters (key, count, owner_instance, last_updated)
                     VALUES ('work', 1, $1, NOW())
                     ON CONFLICT (key) DO UPDATE SET
                       count = demo_counters.count + 1,
                       owner_instance = $1,
                       last_updated = NOW()",
                )
                .bind(&id)
                .execute(conn.as_mut())
                .await;

                let work_time = work_start.elapsed();

                // Release connection immediately (drop)
                drop(conn);

                match result {
                    Ok(_) => {
                        metrics.record_success(
                            acquire_time.as_micros() as u64,
                            work_time.as_micros() as u64,
                        );
                    }
                    Err(_) => {
                        metrics.record_failure();
                    }
                }

                // Small delay to simulate "think time" between requests
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            let remaining = workers.fetch_sub(1, Ordering::AcqRel) - 1;
            if remaining == 0 {
                println!("\n  All workers stopped");
                print!("[{}] > ", id);
                let _ = io::stdout().flush();
            }
        });
    }

    println!(
        "  {} workers started. Use /metrics to monitor, /work stop to end.",
        n
    );
}

fn cmd_work_stop(work_running: &Arc<AtomicBool>, work_workers: &Arc<AtomicUsize>) {
    if !work_running.swap(false, Ordering::AcqRel) {
        println!("  No work running.");
        return;
    }
    let workers = work_workers.load(Ordering::Acquire);
    println!("  Stopping {} workers...", workers);
}

async fn run_demo_listener(
    pool: PgPool,
    coordinator: Arc<ClusterCoordinator>,
    cluster_pool: Arc<ClusterAwarePool>,
    short_id: String,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut listener = PgListener::connect_with(&pool).await?;
    listener.listen(DEMO_CHANNEL).await?;

    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        match tokio::time::timeout(Duration::from_millis(100), listener.recv()).await {
            Ok(Ok(notification)) => {
                if notification.channel() == DEMO_CHANNEL {
                    handle_demo_message(
                        notification.payload(),
                        &short_id,
                        &coordinator,
                        &cluster_pool,
                    )
                    .await;
                }
            }
            Ok(Err(e)) => {
                eprintln!("  Listener error: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {} // timeout, continue
        }
    }

    Ok(())
}

async fn handle_demo_message(
    payload: &str,
    short_id: &str,
    coordinator: &ClusterCoordinator,
    cluster_pool: &ClusterAwarePool,
) {
    let is_mine = coordinator.should_handle(payload);

    if is_mine {
        // We own this key - bump the counter using the pool
        match cluster_pool.acquire().await {
            Ok(mut conn) => {
                let result = sqlx::query(
                    "INSERT INTO demo_counters (key, count, owner_instance, last_updated)
                     VALUES ($1, 1, $2, NOW())
                     ON CONFLICT (key) DO UPDATE SET
                       count = demo_counters.count + 1,
                       owner_instance = $2,
                       last_updated = NOW()
                     RETURNING count",
                )
                .bind(payload)
                .bind(short_id)
                .fetch_one(conn.as_mut())
                .await;

                match result {
                    Ok(row) => {
                        let count: i64 = sqlx::Row::get(&row, 0);
                        println!(
                            "\n  [*] I own \"{}\" -> count = {} (pool: {}/{})",
                            payload,
                            count,
                            cluster_pool.active_connections(),
                            cluster_pool.current_limit()
                        );
                    }
                    Err(e) => {
                        println!("\n  [*] I own \"{}\" but DB error: {}", payload, e);
                    }
                }
            }
            Err(e) => {
                println!("\n  [*] I own \"{}\" but pool error: {}", payload, e);
            }
        }
    } else {
        println!("\n  [ ] Another instance owns: \"{}\"", payload);
    }

    print!("[{}] > ", short_id);
    let _ = io::stdout().flush();
}
