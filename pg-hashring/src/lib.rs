//! PostgreSQL-backed cluster membership with consistent hashing.
//!
//! This crate provides:
//! - Consistent hashing via AnchorHash (optimal minimal disruption)
//! - PostgreSQL polling for membership changes (~2.5s average detection)
//! - Heartbeat-based liveness (configurable interval, default 5s)
//! - Graceful deregistration on shutdown
//!
//! **Compatible with managed connection poolers** (PgBouncer transaction mode,
//! Cloud SQL Managed Connection Pooling) because it doesn't use LISTEN/NOTIFY.
//!
//! # Example
//!
//! ```rust,ignore
//! use pg_hashring::ClusterCoordinator;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let pool = sqlx::PgPool::connect("postgres://...").await?;
//!
//!     // Ensure schema exists (safe to call multiple times)
//!     pg_hashring::setup(&pool).await?;
//!
//!     // Start coordinator - registers with cluster, begins polling
//!     let coordinator = ClusterCoordinator::start(pool).await?;
//!
//!     // Check if we should handle a key
//!     if coordinator.should_handle("some-bunker-pubkey") {
//!         // Process the request
//!     }
//!
//!     // Graceful shutdown - deregisters from cluster
//!     coordinator.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Scale and Performance
//!
//! With 300 instances polling every 5 seconds = 60 queries/second (negligible load).
//!
//! Appropriate for:
//! - Small to medium clusters (3-300 instances)
//! - Infrequent membership changes (nodes join/leave rarely)
//! - Environments using managed connection poolers
//! - Serverless environments (Cloud Run, Lambda)
//!
//! Not suitable for:
//! - Very large clusters (1000+ nodes)
//! - High-frequency membership churn
//! - Sub-second membership detection requirements
//!
//! # Failure Detection
//!
//! - **Graceful shutdown**: Other instances detect within poll interval (default 5s)
//! - **Crash/kill -9**: Other instances detect within 30-60s (via stale heartbeat cleanup)

mod coordinator;
mod error;
mod registry;
mod ring;

pub use coordinator::{ClusterCoordinator, MembershipEvent};
pub use error::Error;
pub use registry::InstanceRegistry;
pub use ring::HashRing;

use sqlx::PgPool;

/// SQL schema required by pg-hashring (table creation).
pub const SCHEMA_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS signer_instances (
    instance_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"#;

/// SQL schema required by pg-hashring (index creation).
pub const SCHEMA_INDEX_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS idx_signer_instances_heartbeat
ON signer_instances(last_heartbeat)"#;

/// Create the required table if it doesn't exist.
///
/// Safe to call multiple times (uses IF NOT EXISTS).
///
/// # Example
///
/// ```rust,ignore
/// pg_hashring::setup(&pool).await?;
/// let coordinator = ClusterCoordinator::start(pool).await?;
/// ```
pub async fn setup(pool: &PgPool) -> Result<(), Error> {
    sqlx::query(SCHEMA_TABLE_SQL).execute(pool).await?;
    sqlx::query(SCHEMA_INDEX_SQL).execute(pool).await?;
    Ok(())
}
