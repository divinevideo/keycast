//! Interactive demo of pg-hashring cluster coordination.
//!
//! Run multiple instances in separate terminals:
//!   cargo run -p pg-hashring --example demo
//!
//! Type any message and press Enter. The message will be broadcast to all
//! instances, but only one instance (determined by consistent hashing) will
//! claim ownership. Try adding/killing instances to see key redistribution.

use pg_hashring::ClusterCoordinator;
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

const DEMO_CHANNEL: &str = "demo_messages";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to PostgreSQL
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());

    let pool = PgPool::connect(&database_url).await?;

    // Ensure schema exists
    pg_hashring::setup(&pool).await?;

    // Start the cluster coordinator
    let coordinator = Arc::new(ClusterCoordinator::start(pool.clone()).await?);
    coordinator.wait_for_established().await;

    let instance_id = coordinator.instance_id().to_string();
    let short_id = &instance_id[..8];

    // Shutdown signal for listener task
    let shutdown = Arc::new(AtomicBool::new(false));

    // Set up signal handler for graceful shutdown (SIGINT/SIGTERM)
    let (ctrlc_tx, ctrlc_rx) = oneshot::channel::<()>();
    let ctrlc_tx = std::sync::Mutex::new(Some(ctrlc_tx));
    ctrlc::set_handler(move || {
        if let Some(tx) = ctrlc_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    })?;

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              pg-hashring Interactive Demo                    ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Instance: {}                                        ║", short_id);
    println!("║  Cluster:  {} instance(s)                                    ║", coordinator.instance_count());
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Type any text and press Enter to broadcast.                 ║");
    println!("║  Only the owning instance will claim the message.            ║");
    println!("║  Try running multiple instances and killing some!            ║");
    println!("║                                                              ║");
    println!("║  Commands:                                                   ║");
    println!("║    /status  - Show cluster status                            ║");
    println!("║    /refresh - Force-sync ring (use after crash/Ctrl+C)       ║");
    println!("║    /quit    - Exit gracefully                                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Spawn listener for incoming messages
    let coord_clone = coordinator.clone();
    let pool_clone = pool.clone();
    let short_id_clone = short_id.to_string();
    let shutdown_clone = shutdown.clone();

    let listener_handle = tokio::spawn(async move {
        if let Err(e) = run_listener(pool_clone, coord_clone, short_id_clone, shutdown_clone).await
        {
            eprintln!("Listener error: {}", e);
        }
    });

    // Spawn stdin reader task
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<String>(10);
    let short_id_for_prompt = short_id.to_string();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        loop {
            print!("[{}] > ", short_id_for_prompt);
            let _ = stdout.flush();

            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if input_tx.blocking_send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Main event loop - handle both input and shutdown signals
    let mut ctrlc_rx = ctrlc_rx;
    loop {
        tokio::select! {
            _ = &mut ctrlc_rx => {
                println!("\n  Received shutdown signal (SIGINT/SIGTERM), shutting down gracefully...");
                break;
            }
            Some(line) = input_rx.recv() => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                match input {
                    "/quit" | "/exit" | "/q" => {
                        println!("Shutting down gracefully...");
                        break;
                    }
                    "/status" | "/s" => {
                        let count = coordinator.instance_count();
                        println!("  Cluster has {} instance(s)", count);

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
                    "/refresh" | "/r" => {
                        println!("  Refreshing hashring from database...");
                        match coordinator.refresh().await {
                            Ok(()) => {
                                let count = coordinator.instance_count();
                                println!("  ✓ Refreshed. Cluster now has {} instance(s)", count);
                            }
                            Err(e) => {
                                println!("  ✗ Refresh failed: {}", e);
                            }
                        }
                    }
                    _ => {
                        // Broadcast the message
                        if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)")
                            .bind(DEMO_CHANNEL)
                            .bind(input)
                            .execute(&pool)
                            .await
                        {
                            println!("  Error broadcasting: {}", e);
                        }
                    }
                }
            }
        }
    }

    // Signal listener to stop
    shutdown.store(true, Ordering::Release);

    // Wait for listener to finish
    let _ = listener_handle.await;

    // Graceful shutdown - this notifies other instances
    // Note: We need to wait for the listener task to finish before we can unwrap the Arc
    match Arc::try_unwrap(coordinator) {
        Ok(coord) => coord.shutdown().await?,
        Err(_) => {
            // If we can't unwrap, the listener might still be running
            // Just exit - the instance will be cleaned up by heartbeat timeout
            eprintln!("Warning: Could not gracefully deregister");
        }
    }

    println!("Goodbye!");
    Ok(())
}

async fn run_listener(
    pool: PgPool,
    coordinator: Arc<ClusterCoordinator>,
    short_id: String,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut listener = PgListener::connect_with(&pool).await?;
    listener.listen(DEMO_CHANNEL).await?;
    listener.listen("cluster_membership").await?;

    loop {
        // Check shutdown signal
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        // Use timeout so we can periodically check shutdown
        match tokio::time::timeout(Duration::from_millis(100), listener.recv()).await {
            Ok(Ok(notification)) => {
                let channel = notification.channel();
                let payload = notification.payload();

                if channel == "cluster_membership" {
                    // Membership change
                    if payload.starts_with("joined:") {
                        let new_id = &payload[7..];
                        if !new_id.starts_with(&short_id) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            let count = coordinator.instance_count();
                            println!("\n  📥 Instance joined! Cluster now has {} instance(s)", count);
                            print!("[{}] > ", short_id);
                            let _ = io::stdout().flush();
                        }
                    } else if payload.starts_with("left:") {
                        let left_id = &payload[5..];
                        if !left_id.starts_with(&short_id) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            let count = coordinator.instance_count();
                            println!("\n  📤 Instance left. Cluster now has {} instance(s)", count);
                            print!("[{}] > ", short_id);
                            let _ = io::stdout().flush();
                        }
                    }
                } else if channel == DEMO_CHANNEL {
                    // Demo message - check if we should handle it
                    let is_mine = coordinator.should_handle(payload);

                    if is_mine {
                        println!("\n  ✅ I own this key: \"{}\"", payload);
                    } else {
                        println!("\n  ⬚  Another instance owns: \"{}\"", payload);
                    }
                    print!("[{}] > ", short_id);
                    let _ = io::stdout().flush();
                }
            }
            Ok(Err(e)) => {
                eprintln!("Listener error: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {
                // Timeout - continue
            }
        }
    }

    Ok(())
}
