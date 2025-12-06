//! PostgreSQL-backed cluster membership with consistent hashing.
//!
//! This crate provides:
//! - Consistent hashing via AnchorHash (optimal minimal disruption)
//! - PostgreSQL LISTEN/NOTIFY for near-instant membership changes (~100ms)
//! - Heartbeat fallback for crash detection (30s)
//! - Graceful deregistration on shutdown
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
//!     // Start coordinator - registers with cluster, begins listening
//!     let coordinator = ClusterCoordinator::start(pool).await?;
//!
//!     // Wait for LISTEN to be established (useful for tests)
//!     coordinator.wait_for_established().await;
//!
//!     // Check if we should handle a key
//!     if coordinator.should_handle("some-bunker-pubkey").await {
//!         // Process the request
//!     }
//!
//!     // Graceful shutdown - deregisters and notifies other instances
//!     coordinator.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Scale and Limitations
//!
//! Appropriate for:
//! - Small to medium clusters (3-100 instances)
//! - Infrequent membership changes (nodes join/leave rarely)
//! - Environments where instances share a database but can't form UDP mesh
//!
//! Not suitable for:
//! - Very large clusters (1000+ nodes)
//! - High-frequency membership churn
//!
//! # Failure Detection
//!
//! - **Graceful shutdown**: Other instances know within ~100ms (via NOTIFY)
//! - **Crash/kill -9**: Other instances know within 30-60s (via heartbeat)

mod coordinator;
mod error;
mod registry;
mod ring;

#[cfg(feature = "pool")]
mod cluster_pool;

pub use coordinator::{ClusterCoordinator, MembershipEvent};
pub use error::Error;
pub use registry::InstanceRegistry;
pub use ring::HashRing;

#[cfg(feature = "pool")]
pub use cluster_pool::{ClusterAwarePool, ClusterPoolConnection, PoolMetrics};

use sqlx::PgPool;

/// Duration (in milliseconds) to continue processing after sending "left:" notification.
///
/// This "drain period" allows peers to receive the notification and update their rings
/// before we stop processing. During this overlap, both the departing instance and its
/// successors may handle the same keys (idempotent operations are safe).
///
/// Without this, there's a brief window (~5-20ms of LISTEN/NOTIFY latency) where
/// events could be dropped because the departing instance has stopped but peers
/// haven't yet learned they should take over.
pub const SHUTDOWN_DRAIN_MS: u64 = 100;

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
