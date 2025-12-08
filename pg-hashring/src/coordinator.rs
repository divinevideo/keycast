use crate::{Error, HashRing, InstanceRegistry};
use arc_swap::ArcSwap;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Default poll interval for membership updates (seconds).
/// With 300 instances polling every 5 seconds = 60 QPS (negligible load).
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Membership change event.
#[derive(Debug, Clone, PartialEq)]
pub enum MembershipEvent {
    Joined(String),
    Left(String),
}

/// Orchestrates HashRing + PostgreSQL membership with polling.
///
/// Compatible with managed connection pooling (PgBouncer transaction mode)
/// because it doesn't use LISTEN/NOTIFY which requires persistent connections.
///
/// Membership changes are detected via periodic polling with configurable interval.
/// Default: 5 seconds (avg 2.5 second detection latency).
pub struct ClusterCoordinator {
    ring: Arc<ArcSwap<HashRing>>,
    registry: Arc<InstanceRegistry>,
    pool: sqlx::PgPool,
    cancel_token: CancellationToken,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    event_tx: broadcast::Sender<MembershipEvent>,
}

impl ClusterCoordinator {
    /// Start a new coordinator, registering with the cluster.
    ///
    /// Uses default poll interval (5 seconds).
    ///
    /// # Errors
    ///
    /// Returns an error if registration or initial sync fails.
    pub async fn start(pool: PgPool) -> Result<Self, Error> {
        Self::start_with_interval(pool, Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS)).await
    }

    /// Start with custom poll interval.
    ///
    /// Lower intervals mean faster membership detection but more DB queries.
    /// - 1 second: ~300 QPS with 300 instances
    /// - 5 seconds: ~60 QPS with 300 instances (recommended)
    /// - 10 seconds: ~30 QPS with 300 instances
    pub async fn start_with_interval(pool: PgPool, poll_interval: Duration) -> Result<Self, Error> {
        let registry = Arc::new(InstanceRegistry::register(pool.clone()).await?);
        let instance_id = registry.instance_id().to_string();

        // Create initial ring and sync from database
        let mut initial_ring = HashRing::new(&instance_id);
        let instances = InstanceRegistry::get_active_instances(&pool).await?;
        initial_ring.rebuild(instances);

        let ring = Arc::new(ArcSwap::from_pointee(initial_ring));
        let cancel_token = CancellationToken::new();

        // Broadcast channel for membership events (16 capacity is enough for bursts)
        let (event_tx, _) = broadcast::channel(16);

        // Spawn coordination task
        let task_handle = Self::spawn_coordination_task(
            pool.clone(),
            ring.clone(),
            registry.clone(),
            cancel_token.clone(),
            event_tx.clone(),
            poll_interval,
        );

        Ok(Self {
            ring,
            registry,
            pool,
            cancel_token,
            task_handle: Some(task_handle),
            event_tx,
        })
    }

    fn spawn_coordination_task(
        pool: PgPool,
        ring: Arc<ArcSwap<HashRing>>,
        registry: Arc<InstanceRegistry>,
        cancel_token: CancellationToken,
        event_tx: broadcast::Sender<MembershipEvent>,
        poll_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut poll_interval_timer = tokio::time::interval(poll_interval);
            let mut consecutive_failures: u32 = 0;

            // Track previous membership to detect changes
            let mut previous_members: HashSet<String> = ring
                .load()
                .instances()
                .iter()
                .cloned()
                .collect();

            loop {
                tokio::select! {
                    // Cancellation - immediate response
                    _ = cancel_token.cancelled() => {
                        tracing::debug!("Coordinator shutting down");
                        break;
                    }

                    _ = poll_interval_timer.tick() => {
                        // 1. Send heartbeat
                        if let Err(e) = registry.heartbeat().await {
                            consecutive_failures += 1;
                            let backoff_ms = 100 * 2u64.pow(consecutive_failures.min(6));
                            tracing::error!(
                                failures = consecutive_failures,
                                backoff_ms,
                                "Heartbeat failed: {}, backing off",
                                e
                            );
                            tokio::select! {
                                _ = cancel_token.cancelled() => break,
                                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                            }
                            continue;
                        }

                        // 2. Cleanup stale instances
                        if let Err(e) = InstanceRegistry::cleanup_stale(&pool).await {
                            tracing::warn!("Cleanup failed: {}", e);
                        }

                        // 3. Get current membership
                        match InstanceRegistry::get_active_instances(&pool).await {
                            Ok(instances) => {
                                consecutive_failures = 0;

                                let current_members: HashSet<String> = instances.iter().cloned().collect();

                                // Detect joins
                                for id in current_members.difference(&previous_members) {
                                    tracing::debug!(id = %id, "Instance joined (detected via poll)");
                                    let _ = event_tx.send(MembershipEvent::Joined(id.clone()));
                                }

                                // Detect leaves
                                for id in previous_members.difference(&current_members) {
                                    tracing::debug!(id = %id, "Instance left (detected via poll)");
                                    let _ = event_tx.send(MembershipEvent::Left(id.clone()));
                                }

                                // Update ring if membership changed
                                if current_members != previous_members {
                                    let mut new_ring = (**ring.load()).clone();
                                    new_ring.rebuild(instances);
                                    tracing::debug!(
                                        count = new_ring.instance_count(),
                                        "Membership changed, hashring updated"
                                    );
                                    ring.store(Arc::new(new_ring));
                                    previous_members = current_members;
                                } else {
                                    tracing::trace!(
                                        count = current_members.len(),
                                        "Poll: no membership changes"
                                    );
                                }
                            }
                            Err(e) => {
                                consecutive_failures += 1;
                                let backoff_ms = 100 * 2u64.pow(consecutive_failures.min(6));
                                tracing::error!(
                                    failures = consecutive_failures,
                                    backoff_ms,
                                    "Failed to get instances: {}, backing off",
                                    e
                                );
                                tokio::select! {
                                    _ = cancel_token.cancelled() => break,
                                    _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Check if this coordinator should handle the given key.
    ///
    /// This is a lock-free operation using atomic pointer loading.
    pub fn should_handle(&self, key: &str) -> bool {
        self.ring.load().should_handle(key)
    }

    /// Get the instance ID of this coordinator.
    pub fn instance_id(&self) -> &str {
        self.registry.instance_id()
    }

    /// Get current instance count in the ring.
    ///
    /// This is a lock-free operation using atomic pointer loading.
    pub fn instance_count(&self) -> usize {
        self.ring.load().instance_count()
    }

    /// Subscribe to membership change events.
    ///
    /// Events are broadcast AFTER the ring has been updated, so subscribers
    /// can safely call `instance_count()` and get the new value.
    pub fn subscribe(&self) -> broadcast::Receiver<MembershipEvent> {
        self.event_tx.subscribe()
    }

    /// Manually refresh the hashring from the database.
    ///
    /// Useful when you don't want to wait for the next poll interval.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup or database query fails.
    pub async fn refresh(&self) -> Result<(), Error> {
        InstanceRegistry::cleanup_stale(&self.pool).await?;
        let instances = InstanceRegistry::get_active_instances(&self.pool).await?;

        let mut new_ring = (**self.ring.load()).clone();
        new_ring.rebuild(instances);

        tracing::debug!(count = new_ring.instance_count(), "Manual hashring refresh");
        self.ring.store(Arc::new(new_ring));
        Ok(())
    }

    /// Deregister from the cluster without consuming self.
    ///
    /// Use when you can't take ownership (e.g., Arc::try_unwrap fails).
    pub async fn force_deregister(&self) -> Result<(), Error> {
        self.registry.deregister().await
    }

    /// Graceful shutdown - deregisters from cluster and stops task.
    ///
    /// # Errors
    ///
    /// Returns an error if deregistration fails.
    pub async fn shutdown(mut self) -> Result<(), Error> {
        // 1. Notify peers we're leaving via database (they'll detect on next poll)
        self.registry.deregister().await?;

        // 2. Brief drain period for in-flight requests
        //    With polling, peers won't see the change until their next poll (up to 5s)
        //    but that's acceptable - NIP-46 signing is idempotent
        let drain_ms = (100_usize * self.instance_count().max(1)).min(2000);
        tokio::time::sleep(Duration::from_millis(drain_ms as u64)).await;

        // 3. Cancel the background task
        self.cancel_token.cancel();

        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }

        tracing::debug!(
            drain_ms,
            instance_count = self.instance_count(),
            "Shutdown complete"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    async fn get_test_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());
        PgPool::connect(&url).await.unwrap()
    }

    async fn cleanup_test_instances(pool: &PgPool) {
        sqlx::query("DELETE FROM signer_instances")
            .execute(pool)
            .await
            .unwrap();
    }

    #[test]
    fn test_membership_event_variants() {
        let joined = MembershipEvent::Joined("abc-123".to_string());
        let left = MembershipEvent::Left("xyz-789".to_string());
        assert_eq!(joined, MembershipEvent::Joined("abc-123".to_string()));
        assert_eq!(left, MembershipEvent::Left("xyz-789".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_coordinator_starts_and_handles_keys() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        // Use fast poll for testing
        let coordinator = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        // Solo instance should handle everything
        assert!(coordinator.should_handle("any-key"));
        assert!(coordinator.should_handle("another-key"));

        coordinator.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_two_coordinators_split_keys() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coord1 = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        let coord2 = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        // Wait for poll to detect each other (up to 200ms with 100ms interval)
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Trigger manual refresh to ensure both see each other
        coord1.refresh().await.unwrap();
        coord2.refresh().await.unwrap();

        // Keys should be split between them
        let mut handled_by_1 = 0;
        let mut handled_by_2 = 0;
        for i in 0..100 {
            let key = format!("key-{}", i);
            if coord1.should_handle(&key) {
                handled_by_1 += 1;
            }
            if coord2.should_handle(&key) {
                handled_by_2 += 1;
            }
        }

        assert_eq!(
            handled_by_1 + handled_by_2,
            100,
            "Each key should have exactly one handler"
        );
        assert!(
            handled_by_1 > 35 && handled_by_1 < 65,
            "coord1 should handle ~50% of keys, got {}",
            handled_by_1
        );
        assert!(
            handled_by_2 > 35 && handled_by_2 < 65,
            "coord2 should handle ~50% of keys, got {}",
            handled_by_2
        );

        coord1.shutdown().await.unwrap();
        coord2.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_graceful_shutdown_redistributes_keys() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coord1 = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        let coord2 = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        // Wait for sync
        tokio::time::sleep(Duration::from_millis(250)).await;
        coord1.refresh().await.unwrap();
        coord2.refresh().await.unwrap();

        // Count how many keys coord1 handles with 2 instances
        let mut before = 0;
        for i in 0..100 {
            let key = format!("key-{}", i);
            if coord1.should_handle(&key) {
                before += 1;
            }
        }

        assert!(
            before < 70,
            "coord1 should handle ~50% before, got {}",
            before
        );

        // Shutdown coord2
        coord2.shutdown().await.unwrap();

        // Wait for coord1 to detect coord2 left
        tokio::time::sleep(Duration::from_millis(250)).await;
        coord1.refresh().await.unwrap();

        // coord1 now handles all keys
        let mut after = 0;
        for i in 0..100 {
            let key = format!("key-{}", i);
            if coord1.should_handle(&key) {
                after += 1;
            }
        }

        assert_eq!(
            after, 100,
            "coord1 should handle all keys after coord2 leaves"
        );

        coord1.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_poll_detects_membership_change() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coord1 = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(50), // Fast poll for testing
        )
        .await
        .unwrap();

        assert_eq!(coord1.instance_count(), 1);

        // Start coord2
        let coord2 = ClusterCoordinator::start_with_interval(
            pool.clone(),
            Duration::from_millis(50),
        )
        .await
        .unwrap();

        // Wait for coord1 to detect coord2 via polling
        let start = std::time::Instant::now();
        loop {
            if coord1.instance_count() == 2 {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!(
                    "coord1 didn't detect coord2 after 2s, count={}",
                    coord1.instance_count()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let latency = start.elapsed();
        println!("Poll detection latency: {:?}", latency);
        assert!(
            latency < Duration::from_millis(500),
            "Detection too slow: {:?}",
            latency
        );

        coord1.shutdown().await.unwrap();
        coord2.shutdown().await.unwrap();
    }
}
