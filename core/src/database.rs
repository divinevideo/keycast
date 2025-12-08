use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::env;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

// Pool configuration constants - tune these based on Cloud SQL tier
// db-f1-micro: ~25 max connections (0.6GB RAM)
// db-g1-small: ~100 max connections (1.7GB RAM)
// db-n1-standard-1: ~250 max connections (3.75GB RAM)
const MAX_CONNECTIONS_PER_INSTANCE: u32 = 2;
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
    /// Main pool for queries - may go through connection pooler (transaction mode)
    pub pool: PgPool,
    /// Direct pool for LISTEN/NOTIFY - bypasses connection pooler
    /// Uses same URL as main pool if DATABASE_DIRECT_URL is not set
    pub direct_pool: PgPool,
}

impl Database {
    pub async fn new(_db_path: PathBuf, migrations_path: PathBuf) -> Result<Self, DatabaseError> {
        let database_url =
            env::var("DATABASE_URL").expect("DATABASE_URL must be set for PostgreSQL");

        // Optional direct URL for LISTEN/NOTIFY (bypasses connection pooler)
        // Falls back to DATABASE_URL if not set
        let direct_url = env::var("DATABASE_DIRECT_URL").unwrap_or_else(|_| database_url.clone());
        let using_separate_direct = env::var("DATABASE_DIRECT_URL").is_ok();

        let instance_id = env::var("K_REVISION").unwrap_or_else(|_| "local".to_string());

        eprintln!("🐘 Database pool config:");
        eprintln!("   Instance: {}", instance_id);
        eprintln!(
            "   Max connections per instance: {}",
            MAX_CONNECTIONS_PER_INSTANCE
        );
        eprintln!("   Acquire timeout: {}s", ACQUIRE_TIMEOUT_SECS);
        if using_separate_direct {
            eprintln!("   Using separate DATABASE_DIRECT_URL for LISTEN/NOTIFY");
        }
        eprintln!("   ⚠️  If PoolTimedOut errors occur, check:");
        eprintln!("      - Cloud SQL max_connections (db-f1-micro ≈ 25)");
        eprintln!(
            "      - Number of Cloud Run instances × {} = total connections",
            MAX_CONNECTIONS_PER_INSTANCE
        );
        eprintln!("      - Total must be < Cloud SQL max_connections");

        // Main pool options - may go through connection pooler
        let pool_options = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(ACQUIRE_TIMEOUT_SECS))
            .max_connections(MAX_CONNECTIONS_PER_INSTANCE);

        // Disable statement cache for PgBouncer/Cloud SQL connection pooling compatibility
        // See: https://github.com/launchbadge/sqlx/issues/67
        let connect_options = PgConnectOptions::from_str(&database_url)
            .expect("Invalid DATABASE_URL")
            .statement_cache_capacity(0);

        // Retry connection with exponential backoff for Cloud SQL proxy startup race
        let mut connection_attempts = 0;
        let pool = loop {
            connection_attempts += 1;
            match pool_options.clone().connect_with(connect_options.clone()).await {
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
                            MAX_CONNECTIONS_PER_INSTANCE,
                            25 / MAX_CONNECTIONS_PER_INSTANCE
                        );
                        eprintln!("      Solutions:");
                        eprintln!("        1. Reduce min-instances in Cloud Run");
                        eprintln!(
                            "        2. Upgrade Cloud SQL tier (db-g1-small has ~100 connections)"
                        );
                        eprintln!("        3. Reduce MAX_CONNECTIONS_PER_INSTANCE in database.rs");
                    }
                    return Err(e.into());
                }
            }
        };

        // Direct pool for LISTEN/NOTIFY - only needs 1 connection per instance
        // No statement_cache_capacity(0) needed since it bypasses pooler
        let direct_pool_options = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(ACQUIRE_TIMEOUT_SECS))
            .max_connections(1); // LISTEN only needs 1 persistent connection

        let mut direct_connect_options = PgConnectOptions::from_str(&direct_url)
            .expect("Invalid DATABASE_DIRECT_URL");
        // If using managed pool for direct connections (no DATABASE_DIRECT_URL set),
        // we still need to disable statement cache due to PgBouncer transaction mode
        if !using_separate_direct {
            direct_connect_options = direct_connect_options.statement_cache_capacity(0);
        }

        let direct_pool = direct_pool_options
            .connect_with(direct_connect_options)
            .await?;

        // Run migrations - with graceful handling for multi-instance startup
        // When many instances start simultaneously with Cloud SQL Managed Pool, they may
        // hit "prepared statement already exists" conflicts (error code 42P05).
        // This is safe to ignore - it means another instance is running migrations.
        eprintln!("Running migrations...");
        let mut attempts = 0;
        while attempts < 3 {
            match sqlx::migrate::Migrator::new(migrations_path.clone())
                .await?
                .run(&direct_pool)
                .await
            {
                Ok(_) => {
                    eprintln!("   Migrations completed successfully");
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    // Check for PgBouncer/managed pool prepared statement conflict
                    if error_str.contains("42P05") || error_str.contains("already exists") {
                        eprintln!("   ⚠️  Migration conflict (42P05): another instance likely running migrations");
                        eprintln!("   Continuing startup - migrations will be applied by another instance");
                        break;
                    }
                    if attempts < 2 {
                        eprintln!("   Migration attempt {} failed: {}", attempts + 1, e);
                        sleep(Duration::from_millis(500)).await;
                        attempts += 1;
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }

        eprintln!("✅ PostgreSQL database initialized successfully");

        Ok(Self { pool, direct_pool })
    }
}
