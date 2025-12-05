use crate::{Error, HashRing, InstanceRegistry};
use arc_swap::ArcSwap;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Membership change event from PostgreSQL LISTEN/NOTIFY.
#[derive(Debug, Clone, PartialEq)]
pub enum MembershipEvent {
    Joined(String),
    Left(String),
}

impl MembershipEvent {
    pub fn parse(payload: &str) -> Option<Self> {
        if let Some(id) = payload.strip_prefix("joined:") {
            Some(Self::Joined(id.to_string()))
        } else {
            payload
                .strip_prefix("left:")
                .map(|id| Self::Left(id.to_string()))
        }
    }
}

/// Orchestrates HashRing + PostgreSQL membership with LISTEN/NOTIFY.
pub struct ClusterCoordinator {
    ring: Arc<ArcSwap<HashRing>>,
    registry: Arc<InstanceRegistry>,
    pool: sqlx::PgPool,
    shutdown: Arc<AtomicBool>,
    established: Arc<AtomicBool>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ClusterCoordinator {
    /// Start a new coordinator, registering with the cluster.
    pub async fn start(pool: PgPool) -> Result<Self, Error> {
        let registry = Arc::new(InstanceRegistry::register(pool.clone()).await?);
        let instance_id = registry.instance_id().to_string();

        // Create initial ring and sync from database
        let mut initial_ring = HashRing::new(&instance_id);
        let instances = InstanceRegistry::get_active_instances(&pool).await?;
        initial_ring.rebuild(instances);

        let ring = Arc::new(ArcSwap::from_pointee(initial_ring));
        let shutdown = Arc::new(AtomicBool::new(false));
        let established = Arc::new(AtomicBool::new(false));

        // Spawn coordination task
        let task_handle = Self::spawn_coordination_task(
            pool.clone(),
            ring.clone(),
            registry.clone(),
            shutdown.clone(),
            established.clone(),
        );

        Ok(Self {
            ring,
            registry,
            pool,
            shutdown,
            established,
            task_handle: Some(task_handle),
        })
    }

    fn spawn_coordination_task(
        pool: PgPool,
        ring: Arc<ArcSwap<HashRing>>,
        registry: Arc<InstanceRegistry>,
        shutdown: Arc<AtomicBool>,
        established: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut listener = match InstanceRegistry::create_listener(&pool).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Failed to create listener: {}", e);
                    return;
                }
            };

            // Signal that LISTEN is active
            established.store(true, Ordering::Release);

            let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                // Check shutdown flag
                if shutdown.load(Ordering::Acquire) {
                    tracing::debug!("Coordinator shutting down");
                    break;
                }

                tokio::select! {
                    // Timeout to check shutdown flag
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        continue;
                    }

                    result = listener.recv() => {
                        match result {
                            Ok(notification) => {
                                if let Some(event) = MembershipEvent::parse(notification.payload()) {
                                    // Clone current ring, modify, and swap atomically
                                    let mut new_ring = (**ring.load()).clone();
                                    match event {
                                        MembershipEvent::Joined(id) => {
                                            new_ring.add_instance(id.clone());
                                            tracing::debug!(
                                                id = %id,
                                                count = new_ring.instance_count(),
                                                "Instance joined"
                                            );
                                        }
                                        MembershipEvent::Left(id) => {
                                            new_ring.remove_instance(&id);
                                            tracing::debug!(
                                                id = %id,
                                                count = new_ring.instance_count(),
                                                "Instance left"
                                            );
                                        }
                                    }
                                    ring.store(Arc::new(new_ring));
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Listener error: {}, will recover on heartbeat", e);
                            }
                        }
                    }

                    _ = heartbeat_interval.tick() => {
                        if let Err(e) = registry.heartbeat().await {
                            tracing::error!("Heartbeat failed: {}", e);
                            continue;
                        }

                        if let Err(e) = InstanceRegistry::cleanup_stale(&pool).await {
                            tracing::warn!("Cleanup failed: {}", e);
                        }

                        match InstanceRegistry::get_active_instances(&pool).await {
                            Ok(instances) => {
                                // Clone current ring, rebuild, and swap atomically
                                let mut new_ring = (**ring.load()).clone();
                                new_ring.rebuild(instances);
                                tracing::trace!(
                                    count = new_ring.instance_count(),
                                    "Heartbeat: hashring synced"
                                );
                                ring.store(Arc::new(new_ring));
                            }
                            Err(e) => {
                                tracing::error!("Failed to get instances: {}", e);
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

    /// Wait until LISTEN is established.
    pub async fn wait_for_established(&self) {
        while !self.established.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
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

    /// Manually refresh the hashring from the database.
    ///
    /// Useful after a crash when you don't want to wait for the heartbeat.
    /// In normal operation, the ring is updated automatically via LISTEN/NOTIFY
    /// for graceful shutdowns, and via heartbeat (30s) for crash detection.
    pub async fn refresh(&self) -> Result<(), Error> {
        // Clean up stale instances first
        InstanceRegistry::cleanup_stale(&self.pool).await?;

        // Get fresh list of active instances
        let instances = InstanceRegistry::get_active_instances(&self.pool).await?;

        // Clone current ring, rebuild, and swap atomically
        let mut new_ring = (**self.ring.load()).clone();
        new_ring.rebuild(instances);

        tracing::debug!(count = new_ring.instance_count(), "Manual hashring refresh");
        self.ring.store(Arc::new(new_ring));
        Ok(())
    }

    /// Graceful shutdown - deregisters from cluster and stops task.
    ///
    /// The shutdown sequence includes a "drain period" to prevent dropped events:
    /// 1. Deregister and send "left:" notification to peers
    /// 2. Continue processing for SHUTDOWN_DRAIN_MS (peers update their rings)
    /// 3. Stop the background task
    ///
    /// During the drain period, both this instance and its successors may handle
    /// the same keys. This is safe for idempotent operations like NIP-46 signing.
    pub async fn shutdown(mut self) -> Result<(), Error> {
        // 1. Notify peers we're leaving (they start accepting our keys)
        self.registry.deregister().await?;

        // 2. Keep processing during drain period (overlap with peers)
        //    Our local ring still thinks we own our keys, so we keep handling them
        tokio::time::sleep(Duration::from_millis(crate::SHUTDOWN_DRAIN_MS)).await;

        // 3. Now signal background task to stop
        self.shutdown.store(true, Ordering::Release);

        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }

        tracing::debug!(drain_ms = crate::SHUTDOWN_DRAIN_MS, "Shutdown complete with drain");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_membership_event_parse_joined() {
        let event = MembershipEvent::parse("joined:abc-123");
        assert_eq!(event, Some(MembershipEvent::Joined("abc-123".to_string())));
    }

    #[test]
    fn test_membership_event_parse_left() {
        let event = MembershipEvent::parse("left:xyz-789");
        assert_eq!(event, Some(MembershipEvent::Left("xyz-789".to_string())));
    }

    #[test]
    fn test_membership_event_parse_invalid() {
        let event = MembershipEvent::parse("unknown:foo");
        assert_eq!(event, None);
    }

    #[tokio::test]
    async fn test_coordinator_starts_and_handles_keys() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coordinator = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coordinator.wait_for_established().await;

        // Solo instance should handle everything
        assert!(coordinator.should_handle("any-key"));
        assert!(coordinator.should_handle("another-key"));

        coordinator.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_two_coordinators_split_keys() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord1.wait_for_established().await;

        let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord2.wait_for_established().await;

        // Give time for notifications to propagate
        tokio::time::sleep(Duration::from_millis(200)).await;

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
    async fn test_graceful_shutdown_redistributes_keys() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord1.wait_for_established().await;

        let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord2.wait_for_established().await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Count how many keys coord1 handles with 2 instances
        let mut before = 0;
        for i in 0..100 {
            let key = format!("key-{}", i);
            if coord1.should_handle(&key) {
                before += 1;
            }
        }

        assert!(before < 70, "coord1 should handle ~50% before, got {}", before);

        // Shutdown coord2
        coord2.shutdown().await.unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;

        // coord1 now handles all keys
        let mut after = 0;
        for i in 0..100 {
            let key = format!("key-{}", i);
            if coord1.should_handle(&key) {
                after += 1;
            }
        }

        assert_eq!(after, 100, "coord1 should handle all keys after coord2 leaves");

        coord1.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_notification_latency() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let coord1 = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord1.wait_for_established().await;

        let start = std::time::Instant::now();

        let coord2 = ClusterCoordinator::start(pool.clone()).await.unwrap();
        coord2.wait_for_established().await;

        // Poll until coord1 sees coord2
        let mut attempts = 0;
        loop {
            let count = coord1.instance_count();
            if count == 2 {
                break;
            }
            attempts += 1;
            if attempts > 50 {
                panic!("coord1 didn't see coord2 after 500ms, count={}", count);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let latency = start.elapsed();
        println!("Notification latency: {:?}", latency);
        assert!(
            latency < Duration::from_millis(500),
            "Latency too high: {:?}",
            latency
        );

        coord1.shutdown().await.unwrap();
        coord2.shutdown().await.unwrap();
    }
}
