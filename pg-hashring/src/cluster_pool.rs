//! Cluster-aware connection pool for pg-hashring.
//!
//! Dynamically adjusts connection limits based on cluster size:
//! - Small cluster (1-2 instances): Each instance uses more postgres connections
//! - Large cluster (10+ instances): Connections distributed evenly
//!
//! Uses `ClusterCoordinator::instance_count()` for dynamic adjustment.
//! No NOTIFY overhead - just recalculates on membership change.
//!
//! # Example
//!
//! ```rust,ignore
//! use pg_hashring::{ClusterAwarePool, ClusterCoordinator};
//! use std::sync::Arc;
//!
//! // Create coordinator (uses a small pool internally)
//! let coordinator = Arc::new(ClusterCoordinator::start(coord_pool).await?);
//!
//! // Create cluster-aware pool (lazy - no connections until first acquire)
//! let cluster_pool = ClusterAwarePool::connect(
//!     "postgres://localhost/mydb",
//!     coordinator.clone(),
//!     100,  // Total connections shared across all cluster instances
//! )?;
//!
//! // Acquire respects cluster-aware limits
//! let conn = cluster_pool.acquire().await?;
//!
//! // When membership changes, call:
//! cluster_pool.on_membership_change();
//! ```

use crate::{ClusterCoordinator, Error};
use rand::Rng;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Pool metrics for observability.
///
/// Use with Prometheus, OpenTelemetry, or other metrics systems.
#[derive(Debug, Clone)]
pub struct PoolMetrics {
    /// Currently held connections by this instance.
    pub active_connections: usize,
    /// Current soft limit for this instance.
    pub soft_limit: usize,
    /// Total connections configured for the cluster.
    pub max_total: u32,
    /// Number of instances in the cluster.
    pub instance_count: usize,
    /// Pool utilization as percentage (0.0 - 100.0).
    pub utilization_percent: f32,
    /// Connections evicted due to cluster shrink (cumulative).
    pub evicted_connections: usize,
}

/// A connection pool wrapper that enforces cluster-aware connection limits.
///
/// Each instance gets `max_total / instance_count()` connections.
/// The soft_limit is recalculated when `on_membership_change()` is called.
///
/// # Thread Safety
///
/// This type is `Sync` and can be safely shared across threads via `Arc`.
/// All internal state uses atomic operations.
pub struct ClusterAwarePool {
    pool: PgPool,
    coordinator: Arc<ClusterCoordinator>,
    max_total: u32,
    soft_limit: AtomicUsize,
    active_count: AtomicUsize,
    evicted_count: AtomicUsize,
}

/// A pooled connection that decrements active_count on drop.
///
/// This type implements `Deref` and `DerefMut` to the underlying
/// `PoolConnection<Postgres>`, so it can be used like a regular connection.
///
/// When dropped, if the pool is over its soft limit, the connection is closed
/// instead of being returned to the pool. This enables cooperative eviction
/// when new instances join the cluster.
pub struct ClusterPoolConnection<'a> {
    conn: Option<PoolConnection<Postgres>>,
    active_count: &'a AtomicUsize,
    soft_limit: &'a AtomicUsize,
    evicted_count: &'a AtomicUsize,
}

impl ClusterAwarePool {
    /// Connect to the database and create a cluster-aware pool.
    ///
    /// Uses `connect_lazy()` internally - no connections are established until
    /// first `acquire()`. This is important for cluster scenarios where multiple
    /// instances might start simultaneously; we don't want to fight for connections
    /// during startup.
    ///
    /// The pool has capacity for `max_total` connections, allowing a single
    /// surviving instance to scale up to full capacity if others die.
    ///
    /// # Arguments
    ///
    /// - `database_url`: PostgreSQL connection string
    /// - `coordinator`: ClusterCoordinator for instance_count()
    /// - `max_total`: Total connections to share across all cluster instances
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] if the connection string is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let cluster_pool = ClusterAwarePool::connect(
    ///     "postgres://localhost/mydb",
    ///     coordinator,
    ///     100,
    /// )?;
    /// ```
    pub fn connect(
        database_url: &str,
        coordinator: Arc<ClusterCoordinator>,
        max_total: u32,
    ) -> Result<Self, Error> {
        // Use connect_lazy so we don't establish connections at startup.
        // This allows multiple instances to create pools without racing for
        // PostgreSQL connections. Connections are established on first acquire(),
        // which goes through our soft-limit-respecting path.
        //
        // idle_timeout closes connections that sit unused in the pool,
        // reducing connection count during low activity periods.
        // Note: This won't help with crashed processes - use PostgreSQL's
        // idle_session_timeout (PG14+) or tcp_keepalives_* for that.
        let pool = PgPoolOptions::new()
            .max_connections(max_total)
            .min_connections(0)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(60))
            .connect_lazy(database_url)?;

        Ok(Self::new(pool, coordinator, max_total))
    }

    /// Create a cluster-aware pool from an existing SQLx pool.
    ///
    /// **Important**: The underlying pool must have `max_connections >= max_total`,
    /// otherwise you'll get timeout errors when trying to acquire connections.
    /// Prefer [`connect()`](Self::connect) which configures this automatically.
    ///
    /// # Arguments
    ///
    /// - `pool`: Underlying SQLx pool (must have max_connections >= max_total)
    /// - `coordinator`: ClusterCoordinator for instance_count()
    /// - `max_total`: Total connections to share across all instances
    pub fn new(pool: PgPool, coordinator: Arc<ClusterCoordinator>, max_total: u32) -> Self {
        let instances = coordinator.instance_count().max(1);
        let limit = (max_total as usize / instances).max(2);

        tracing::info!(max_total, instances, limit, "ClusterAwarePool initialized");

        Self {
            pool,
            coordinator,
            max_total,
            soft_limit: AtomicUsize::new(limit),
            active_count: AtomicUsize::new(0),
            evicted_count: AtomicUsize::new(0),
        }
    }

    /// Call this when cluster membership changes.
    ///
    /// Typically hooked into pg-hashring's MembershipEvent::Joined/Left.
    /// Recalculates soft_limit based on current instance_count().
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // In your membership event handler:
    /// match event {
    ///     MembershipEvent::Joined(_) | MembershipEvent::Left(_) => {
    ///         cluster_pool.on_membership_change();
    ///     }
    /// }
    /// ```
    pub fn on_membership_change(&self) {
        let instances = self.coordinator.instance_count().max(1);
        let new_limit = (self.max_total as usize / instances).max(2);
        let old_limit = self.soft_limit.swap(new_limit, Ordering::AcqRel);

        if old_limit != new_limit {
            tracing::info!(
                old_limit,
                new_limit,
                instances,
                active = self.active_count.load(Ordering::Relaxed),
                "Pool limit adjusted"
            );
        }
    }

    /// Acquire a connection, respecting the cluster-aware soft limit.
    ///
    /// If at limit, waits until a connection is released.
    /// The soft limit may change during waiting (cluster shrink/grow).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pool`] if the underlying pool fails to provide a connection.
    ///
    /// # Backpressure Behavior
    ///
    /// When the cluster grows (more instances join), the soft_limit decreases.
    /// If this instance is holding more connections than its new share,
    /// new acquires will block until existing connections are released.
    /// This provides natural backpressure without forcibly closing connections.
    pub async fn acquire(&self) -> Result<ClusterPoolConnection<'_>, Error> {
        loop {
            let limit = self.soft_limit.load(Ordering::Acquire);
            let active = self.active_count.load(Ordering::Acquire);

            if active < limit {
                // Optimistically increment
                let prev = self.active_count.fetch_add(1, Ordering::AcqRel);

                // Double-check we didn't race past the limit
                if prev >= limit {
                    self.active_count.fetch_sub(1, Ordering::AcqRel);
                    // Jitter prevents thundering herd when multiple tasks wake
                    let jitter = rand::thread_rng().gen_range(5..15);
                    tokio::time::sleep(Duration::from_millis(jitter)).await;
                    continue;
                }

                match self.pool.acquire().await {
                    Ok(conn) => {
                        return Ok(ClusterPoolConnection {
                            conn: Some(conn),
                            active_count: &self.active_count,
                            soft_limit: &self.soft_limit,
                            evicted_count: &self.evicted_count,
                        });
                    }
                    Err(e) => {
                        self.active_count.fetch_sub(1, Ordering::AcqRel);
                        return Err(Error::Pool(e.to_string()));
                    }
                }
            }

            // At limit - wait for a release or limit increase
            // Jitter prevents thundering herd when multiple tasks wake
            let jitter = rand::thread_rng().gen_range(5..15);
            tokio::time::sleep(Duration::from_millis(jitter)).await;
        }
    }

    /// Acquire a connection with a timeout.
    ///
    /// Returns an error if the timeout expires before a connection is available.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pool`] with "acquire timeout" if the deadline is exceeded.
    pub async fn acquire_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ClusterPoolConnection<'_>, Error> {
        tokio::time::timeout(timeout, self.acquire())
            .await
            .map_err(|_| Error::Pool("acquire timeout".to_string()))?
    }

    /// Try to acquire a connection without blocking.
    ///
    /// Returns `Ok(None)` if at the soft limit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pool`] if the underlying pool fails to provide a connection.
    pub async fn try_acquire(&self) -> Result<Option<ClusterPoolConnection<'_>>, Error> {
        let limit = self.soft_limit.load(Ordering::Acquire);
        let prev = self.active_count.fetch_add(1, Ordering::AcqRel);

        if prev >= limit {
            self.active_count.fetch_sub(1, Ordering::AcqRel);
            return Ok(None);
        }

        match self.pool.acquire().await {
            Ok(conn) => Ok(Some(ClusterPoolConnection {
                conn: Some(conn),
                active_count: &self.active_count,
                soft_limit: &self.soft_limit,
                evicted_count: &self.evicted_count,
            })),
            Err(e) => {
                self.active_count.fetch_sub(1, Ordering::AcqRel);
                Err(Error::Pool(e.to_string()))
            }
        }
    }

    /// Get current connection limit for this instance.
    pub fn current_limit(&self) -> usize {
        self.soft_limit.load(Ordering::Relaxed)
    }

    /// Get current active connections for this instance.
    pub fn active_connections(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Get the max_total configured for the cluster.
    pub fn max_total(&self) -> u32 {
        self.max_total
    }

    /// Get a reference to the underlying pool.
    pub fn inner(&self) -> &PgPool {
        &self.pool
    }

    /// Check if the pool is healthy and can accept new work.
    ///
    /// Returns `true` if utilization is below 90% of the soft limit.
    /// Use for health checks and load balancer probes.
    pub fn is_healthy(&self) -> bool {
        let active = self.active_connections();
        let limit = self.current_limit();
        // Healthy if under 90% utilization
        active < (limit * 9 / 10).max(1)
    }

    /// Get current pool metrics for observability.
    ///
    /// Returns a snapshot of pool state that can be exported to
    /// Prometheus, OpenTelemetry, or other metrics systems.
    pub fn metrics(&self) -> PoolMetrics {
        let active = self.active_connections();
        let limit = self.current_limit();
        PoolMetrics {
            active_connections: active,
            soft_limit: limit,
            max_total: self.max_total,
            instance_count: self.coordinator.instance_count(),
            utilization_percent: if limit > 0 {
                (active as f32 / limit as f32) * 100.0
            } else {
                0.0
            },
            evicted_connections: self.evicted_count.load(Ordering::Relaxed),
        }
    }

    /// Get cumulative evicted connection count.
    pub fn evicted_connections(&self) -> usize {
        self.evicted_count.load(Ordering::Relaxed)
    }
}

impl Drop for ClusterPoolConnection<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // prev_active is the count BEFORE subtraction (i.e., including this connection)
            let prev_active = self.active_count.fetch_sub(1, Ordering::AcqRel);
            // Floor of 1 defends against degenerate limit=0 scenarios
            let limit = self.soft_limit.load(Ordering::Acquire).max(1);

            if prev_active > limit {
                // Over limit: close connection instead of returning to pool.
                // detach() prevents SQLx from returning it to the pool on drop.
                let _closing = conn.detach();
                self.evicted_count.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(prev_active, limit, "Dropped excess connection for eviction");
            }
            // Under limit: conn drops normally, PoolConnection::drop returns to pool
        }
    }
}

impl std::ops::Deref for ClusterPoolConnection<'_> {
    type Target = PoolConnection<Postgres>;
    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("connection already dropped")
    }
}

impl std::ops::DerefMut for ClusterPoolConnection<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("connection already dropped")
    }
}

#[cfg(test)]
mod tests {
    /// Calculate connection limit using the same formula as production code.
    fn calc_limit(max_total: usize, instances: usize) -> usize {
        (max_total / instances.max(1)).max(2)
    }

    #[test]
    fn test_limit_calculation() {
        // Single instance gets full capacity
        assert_eq!(calc_limit(100, 1), 100);
        // Two instances split evenly
        assert_eq!(calc_limit(100, 2), 50);
        // Three instances: 100/3 = 33
        assert_eq!(calc_limit(100, 3), 33);
        // 100 instances: minimum of 2 enforced
        assert_eq!(calc_limit(100, 100), 2);
        // 200 instances: minimum of 2 enforced
        assert_eq!(calc_limit(100, 200), 2);
        // Zero instances treated as 1
        assert_eq!(calc_limit(100, 0), 100);
    }
}
