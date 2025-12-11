use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::env;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

// Pool configuration - PgBouncer transaction mode allows high client:backend ratios
// Client connections are multiplexed to fewer backend connections via the pooler.
// Example: 100 instances × 10 connections = 1000 client connections → 200 backend connections
// Override with SQLX_POOL_SIZE env var (higher = better throughput per instance)
const DEFAULT_MAX_CONNECTIONS_PER_INSTANCE: u32 = 10;
const ACQUIRE_TIMEOUT_SECS: u64 = 60;
const MAX_CONNECTION_ATTEMPTS: u32 = 5;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database not initialized")]
    NotInitialized,
    #[error("FS error: {0}")]
    FsError(#[from] std::io::Error),
    #[error("SQLx error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Migrate error: {0}")]
    MigrateError(#[from] sqlx::migrate::MigrateError),
}

#[derive(Clone)]
pub struct Database {
    /// Main pool for queries - goes through connection pooler (transaction mode)
    pub pool: PgPool,
}

impl Database {
    pub async fn new() -> Result<Self, DatabaseError> {
        let database_url =
            env::var("DATABASE_URL").expect("DATABASE_URL must be set for PostgreSQL");

        let instance_id = env::var("K_REVISION").unwrap_or_else(|_| "local".to_string());

        // Statement cache size - parse early for logging
        let statement_cache_size: usize = env::var("SQLX_STATEMENT_CACHE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Pool size per instance - configurable via SQLX_POOL_SIZE env var
        // PgBouncer multiplexes these client connections to fewer backend connections.
        // More connections per instance = higher throughput but more memory usage.
        let max_connections: u32 = env::var("SQLX_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_INSTANCE);

        eprintln!("🐘 Database pool config:");
        eprintln!("   Instance: {}", instance_id);
        eprintln!("   Max connections per instance: {}", max_connections);
        eprintln!(
            "   Statement cache: {}",
            if statement_cache_size > 0 {
                format!(
                    "{} (requires PgBouncer max_prepared_statements)",
                    statement_cache_size
                )
            } else {
                "disabled".to_string()
            }
        );
        eprintln!("   Acquire timeout: {}s", ACQUIRE_TIMEOUT_SECS);
        eprintln!("   ⚠️  If PoolTimedOut errors occur, check:");
        eprintln!("      - Cloud SQL max_connections (db-f1-micro ≈ 25)");
        eprintln!(
            "      - Number of Cloud Run instances × {} = total connections",
            max_connections
        );
        eprintln!("      - Total must be < Cloud SQL max_connections");

        // Main pool options - may go through connection pooler
        let pool_options = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(ACQUIRE_TIMEOUT_SECS))
            .max_connections(max_connections);

        // Statement cache size - configurable for PgBouncer with max_prepared_statements
        // Set SQLX_STATEMENT_CACHE=100 when Cloud SQL pooler has max_prepared_statements configured
        // Default 0 for backward compatibility with transaction-mode poolers without prepared statement support
        // See: https://github.com/launchbadge/sqlx/issues/67
        let connect_options = PgConnectOptions::from_str(&database_url)
            .expect("Invalid DATABASE_URL")
            .statement_cache_capacity(statement_cache_size);

        // Retry connection with exponential backoff for Cloud SQL proxy startup race
        let mut connection_attempts = 0;
        let pool = loop {
            connection_attempts += 1;
            match pool_options
                .clone()
                .connect_with(connect_options.clone())
                .await
            {
                Ok(pool) => break pool,
                Err(e) if connection_attempts < MAX_CONNECTION_ATTEMPTS => {
                    let delay = Duration::from_millis(500 * (1 << connection_attempts));
                    eprintln!(
                        "⏳ Database connection attempt {}/{} failed: {}",
                        connection_attempts, MAX_CONNECTION_ATTEMPTS, e
                    );
                    eprintln!("   Retrying in {:?}...", delay);
                    sleep(delay).await;
                }
                Err(e) => {
                    eprintln!(
                        "❌ Database connection failed after {} attempts",
                        MAX_CONNECTION_ATTEMPTS
                    );
                    eprintln!("   Error: {}", e);
                    if e.to_string().contains("PoolTimedOut") {
                        eprintln!(
                            "   🔍 DIAGNOSIS: PoolTimedOut usually means connection exhaustion."
                        );
                        eprintln!("      Cloud SQL db-f1-micro has ~25 max connections.");
                        eprintln!(
                            "      With {} conn/instance, max {} instances can connect.",
                            max_connections,
                            250 / max_connections
                        );
                        eprintln!("      Solutions:");
                        eprintln!("        1. Reduce min-instances in Cloud Run");
                        eprintln!(
                            "        2. Upgrade Cloud SQL tier (db-g1-small has ~100 connections)"
                        );
                        eprintln!("        3. Set SQLX_POOL_SIZE env var to reduce per-instance connections");
                    }
                    return Err(e.into());
                }
            }
        };

        // Migrations are run manually via tools/run-migrations.sh before deployment
        // This avoids pg_advisory_lock thundering herd when many instances start simultaneously

        eprintln!("✅ PostgreSQL database initialized successfully");

        Ok(Self { pool })
    }
}
