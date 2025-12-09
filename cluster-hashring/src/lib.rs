//! Redis-backed cluster membership with consistent hashing.
//!
//! This crate provides:
//! - Consistent hashing via AnchorHash (optimal minimal disruption)
//! - Redis Pub/Sub for instant membership detection
//! - Heartbeat-based liveness (5s interval, 30s stale threshold)
//! - Graceful deregistration on shutdown
//!
//! **Requires Google Memorystore or Redis 6+** for production use.
//!
//! # Example
//!
//! ```rust,ignore
//! use cluster_hashring::ClusterCoordinator;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let redis_url = std::env::var("REDIS_URL")?;
//!
//!     // Start coordinator - registers with cluster, begins Pub/Sub + heartbeat
//!     let coordinator = ClusterCoordinator::start(&redis_url).await?;
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
//! - Pub/Sub: Instant membership detection (<10ms)
//! - Heartbeat: 5s interval (negligible Redis load even at 1000+ instances)
//! - Full sync: Every 30s as backup for missed Pub/Sub messages
//!
//! Appropriate for:
//! - Small to very large clusters (1-10,000+ instances)
//! - High-frequency membership changes
//! - Sub-second membership detection requirements
//! - Serverless environments (Cloud Run, Lambda)
//!
//! # Failure Detection
//!
//! - **Graceful shutdown**: Other instances detect instantly via Pub/Sub
//! - **Crash/kill -9**: Other instances detect within 30s via stale heartbeat cleanup

mod coordinator;
mod error;
mod registry;
mod ring;

pub use coordinator::{ClusterCoordinator, MembershipEvent};
pub use error::Error;
pub use registry::RedisRegistry;
pub use ring::HashRing;
