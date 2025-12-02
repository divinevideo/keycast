use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

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
    pub pool: PgPool,
}

impl Database {
    pub async fn new(_db_path: PathBuf, migrations_path: PathBuf) -> Result<Self, DatabaseError> {
        let database_url =
            env::var("DATABASE_URL").expect("DATABASE_URL must be set for PostgreSQL");

        eprintln!("🐘 Using PostgreSQL database");
        eprintln!("Connecting to database...");

        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(10))
            .max_connections(20)
            .connect(&database_url)
            .await?;

        // Run migrations
        eprintln!("Running migrations...");
        let mut attempts = 0;
        while attempts < 3 {
            match sqlx::migrate::Migrator::new(migrations_path.clone())
                .await?
                .run(&pool)
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

        eprintln!("✅ PostgreSQL database initialized successfully");

        Ok(Self { pool })
    }
}
