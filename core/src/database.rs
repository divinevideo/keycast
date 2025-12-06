use crate::config::PoolMode;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

// Pool configuration constants - tune these based on Cloud SQL tier
// db-f1-micro: ~25 max connections (0.6GB RAM)
// db-g1-small: ~100 max connections (1.7GB RAM)
// db-n1-standard-1: ~250 max connections (3.75GB RAM)
const QUERY_POOL_CONNECTIONS: u32 = 2;
const COORD_POOL_CONNECTIONS: u32 = 3; // For LISTEN/NOTIFY + heartbeats
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
    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Clone)]
pub struct Database {
    /// Pool for application queries (direct in Direct mode, MCP in Hybrid mode)
    query_pool: PgPool,

    /// Pool for cluster coordination (always direct - LISTEN/NOTIFY requires it)
    coord_pool: PgPool,

    /// Current pool mode
    mode: PoolMode,
}

impl Database {
    /// Create a new database connection with the specified pool mode.
    ///
    /// In `Direct` mode: Both query_pool and coord_pool connect to DATABASE_URL.
    /// In `Hybrid` mode: coord_pool connects to DATABASE_URL (direct), query_pool
    /// connects to DATABASE_URL_POOLED (PgBouncer/MCP).
    pub async fn new(
        _db_path: PathBuf,
        migrations_path: PathBuf,
        mode: PoolMode,
    ) -> Result<Self, DatabaseError> {
        let database_url =
            env::var("DATABASE_URL").expect("DATABASE_URL must be set for PostgreSQL");

        let instance_id = env::var("K_REVISION").unwrap_or_else(|_| "local".to_string());

        eprintln!("🐘 Database pool config (mode: {}):", mode);
        eprintln!("   Instance: {}", instance_id);
        eprintln!("   Query pool connections: {}", QUERY_POOL_CONNECTIONS);
        eprintln!("   Coord pool connections: {}", COORD_POOL_CONNECTIONS);
        eprintln!("   Acquire timeout: {}s", ACQUIRE_TIMEOUT_SECS);

        // Coordination pool is always direct (LISTEN/NOTIFY requires it)
        let coord_pool = create_pool(&database_url, COORD_POOL_CONNECTIONS).await?;

        // Query pool depends on mode
        let query_pool = match mode {
            PoolMode::Direct => {
                eprintln!("   Query pool: direct connection (DATABASE_URL)");
                create_pool(&database_url, QUERY_POOL_CONNECTIONS).await?
            }
            PoolMode::Hybrid => {
                let pooled_url = env::var("DATABASE_URL_POOLED").map_err(|_| {
                    DatabaseError::Config(
                        "DATABASE_URL_POOLED must be set when POOL_MODE=hybrid".to_string(),
                    )
                })?;
                eprintln!("   Query pool: PgBouncer/MCP (DATABASE_URL_POOLED)");
                create_pool(&pooled_url, QUERY_POOL_CONNECTIONS).await?
            }
        };

        // Run migrations using coord_pool (direct connection)
        eprintln!("Running migrations...");
        let mut attempts = 0;
        while attempts < 3 {
            match sqlx::migrate::Migrator::new(migrations_path.clone())
                .await?
                .run(&coord_pool)
                .await
            {
                Ok(_) => break,
                Err(_e) if attempts < 2 => {
                    sleep(Duration::from_millis(500)).await;
                    attempts += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }

        eprintln!(
            "✅ PostgreSQL database initialized successfully (mode: {})",
            mode
        );

        Ok(Self {
            query_pool,
            coord_pool,
            mode,
        })
    }

    /// Get the query pool (for application queries).
    ///
    /// In Direct mode: connects directly to PostgreSQL.
    /// In Hybrid mode: connects via PgBouncer/MCP.
    pub fn query_pool(&self) -> &PgPool {
        &self.query_pool
    }

    /// Get the coordination pool (for LISTEN/NOTIFY and heartbeats).
    ///
    /// Always connects directly to PostgreSQL (required for LISTEN/NOTIFY).
    pub fn coord_pool(&self) -> &PgPool {
        &self.coord_pool
    }

    /// Get the current pool mode.
    pub fn mode(&self) -> PoolMode {
        self.mode
    }

    /// Backwards-compatible accessor - returns query_pool.
    ///
    /// New code should use `query_pool()` or `coord_pool()` explicitly.
    #[deprecated(since = "0.1.0", note = "Use query_pool() or coord_pool() instead")]
    pub fn pool(&self) -> &PgPool {
        &self.query_pool
    }
}

/// Create a connection pool with retry logic.
async fn create_pool(url: &str, max_connections: u32) -> Result<PgPool, DatabaseError> {
    let pool_options = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(ACQUIRE_TIMEOUT_SECS))
        .max_connections(max_connections);

    let mut connection_attempts = 0;
    loop {
        connection_attempts += 1;
        match pool_options.clone().connect(url).await {
            Ok(pool) => return Ok(pool),
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
                    eprintln!("   🔍 DIAGNOSIS: PoolTimedOut usually means connection exhaustion.");
                    eprintln!("      Cloud SQL db-f1-micro has ~25 max connections.");
                    eprintln!("      Solutions:");
                    eprintln!("        1. Reduce min-instances in Cloud Run");
                    eprintln!(
                        "        2. Upgrade Cloud SQL tier (db-g1-small has ~100 connections)"
                    );
                    eprintln!("        3. Use POOL_MODE=hybrid with Cloud SQL MCP");
                }
                return Err(e.into());
            }
        }
    }
}
