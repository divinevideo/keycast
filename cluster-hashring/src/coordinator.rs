use crate::{Error, HashRing, RedisRegistry};
use arc_swap::ArcSwap;
use redis::aio::PubSub;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;
const FULL_SYNC_INTERVAL_SECS: u64 = 30;
const CLEANUP_PROBABILITY_PERCENT: u32 = 10;

/// Membership change event.
#[derive(Debug, Clone, PartialEq)]
pub enum MembershipEvent {
    Joined(String),
    Left(String),
}

/// JSON message format for Pub/Sub
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct PubSubMessage {
    event: String, // "join" or "leave"
    instance_id: String,
}

/// Orchestrates HashRing + Redis membership with Pub/Sub.
///
/// Real-time membership detection via Redis Pub/Sub with periodic
/// full sync as backup. Compatible with Google Memorystore.
pub struct ClusterCoordinator {
    ring: Arc<ArcSwap<HashRing>>,
    registry: Arc<tokio::sync::Mutex<RedisRegistry>>,
    cancel_token: CancellationToken,
    heartbeat_handle: Option<tokio::task::JoinHandle<()>>,
    pubsub_handle: Option<tokio::task::JoinHandle<()>>,
    event_tx: broadcast::Sender<MembershipEvent>,
}

impl ClusterCoordinator {
    /// Start a new coordinator, registering with the cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if registration or initial sync fails.
    pub async fn start(redis_url: &str) -> Result<Self, Error> {
        Self::start_with_prefix(redis_url, None).await
    }

    /// Start a coordinator with an optional key prefix (for test isolation).
    ///
    /// # Errors
    ///
    /// Returns an error if registration or initial sync fails.
    pub async fn start_with_prefix(redis_url: &str, prefix: Option<&str>) -> Result<Self, Error> {
        let mut registry = RedisRegistry::register_with_prefix(redis_url, prefix).await?;
        let instance_id = registry.instance_id().to_string();
        let channel = registry.channel().to_string();

        // Create initial ring and sync from Redis
        let mut initial_ring = HashRing::new(&instance_id);
        let instances = registry.get_active_instances().await?;
        initial_ring.rebuild(instances.clone());

        let ring = Arc::new(ArcSwap::from_pointee(initial_ring));
        let cancel_token = CancellationToken::new();

        // Broadcast channel for membership events
        let (event_tx, _) = broadcast::channel(16);

        // Publish join event
        Self::publish_event(&mut registry, "join", &instance_id).await?;

        let registry = Arc::new(tokio::sync::Mutex::new(registry));

        // Spawn heartbeat task
        let heartbeat_handle = Self::spawn_heartbeat_task(
            registry.clone(),
            ring.clone(),
            cancel_token.clone(),
            event_tx.clone(),
        );

        // Spawn Pub/Sub listener task
        let pubsub_handle = Self::spawn_pubsub_task(
            redis_url.to_string(),
            instance_id.clone(),
            channel,
            ring.clone(),
            cancel_token.clone(),
            event_tx.clone(),
        );

        Ok(Self {
            ring,
            registry,
            cancel_token,
            heartbeat_handle: Some(heartbeat_handle),
            pubsub_handle: Some(pubsub_handle),
            event_tx,
        })
    }

    async fn publish_event(
        registry: &mut RedisRegistry,
        event: &str,
        instance_id: &str,
    ) -> Result<(), Error> {
        let msg = PubSubMessage {
            event: event.to_string(),
            instance_id: instance_id.to_string(),
        };
        let payload = serde_json::to_string(&msg).map_err(|e| Error::Config(e.to_string()))?;

        let mut conn = registry.connection();
        let channel = registry.channel();
        redis::cmd("PUBLISH")
            .arg(channel)
            .arg(&payload)
            .query_async::<()>(&mut conn)
            .await?;

        tracing::debug!(event, instance_id, channel, "Published membership event");
        Ok(())
    }

    fn spawn_heartbeat_task(
        registry: Arc<tokio::sync::Mutex<RedisRegistry>>,
        ring: Arc<ArcSwap<HashRing>>,
        cancel_token: CancellationToken,
        event_tx: broadcast::Sender<MembershipEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut heartbeat_interval =
                tokio::time::interval(Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS));
            let mut sync_interval =
                tokio::time::interval(Duration::from_secs(FULL_SYNC_INTERVAL_SECS));
            let mut consecutive_failures: u32 = 0;

            // Track previous membership for change detection
            let mut previous_members: HashSet<String> =
                ring.load().instances().iter().cloned().collect();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::debug!("Heartbeat task shutting down");
                        break;
                    }

                    _ = heartbeat_interval.tick() => {
                        let mut reg = registry.lock().await;

                        // Send heartbeat
                        if let Err(e) = reg.heartbeat().await {
                            consecutive_failures += 1;
                            let backoff_ms = 100 * 2u64.pow(consecutive_failures.min(6));
                            tracing::error!(
                                failures = consecutive_failures,
                                backoff_ms,
                                "Heartbeat failed: {}, backing off",
                                e
                            );
                            drop(reg);
                            tokio::select! {
                                _ = cancel_token.cancelled() => break,
                                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                            }
                            continue;
                        }
                        consecutive_failures = 0;

                        // Probabilistic cleanup (10% chance)
                        if rand::random::<u32>() % 100 < CLEANUP_PROBABILITY_PERCENT {
                            if let Err(e) = reg.cleanup_stale().await {
                                tracing::warn!("Cleanup failed: {}", e);
                            }
                        }
                    }

                    _ = sync_interval.tick() => {
                        // Periodic full sync as backup
                        let mut reg = registry.lock().await;
                        match reg.get_active_instances().await {
                            Ok(instances) => {
                                let current_members: HashSet<String> = instances.iter().cloned().collect();

                                // Detect changes
                                for id in current_members.difference(&previous_members) {
                                    tracing::debug!(id = %id, "Instance joined (detected via sync)");
                                    let _ = event_tx.send(MembershipEvent::Joined(id.clone()));
                                }
                                for id in previous_members.difference(&current_members) {
                                    tracing::debug!(id = %id, "Instance left (detected via sync)");
                                    let _ = event_tx.send(MembershipEvent::Left(id.clone()));
                                }

                                if current_members != previous_members {
                                    let mut new_ring = (**ring.load()).clone();
                                    new_ring.rebuild(instances);
                                    tracing::debug!(
                                        count = new_ring.instance_count(),
                                        "Full sync: membership changed"
                                    );
                                    ring.store(Arc::new(new_ring));
                                    previous_members = current_members;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Full sync failed: {}", e);
                            }
                        }
                    }
                }
            }
        })
    }

    fn spawn_pubsub_task(
        redis_url: String,
        my_instance_id: String,
        channel: String,
        ring: Arc<ArcSwap<HashRing>>,
        cancel_token: CancellationToken,
        event_tx: broadcast::Sender<MembershipEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                if cancel_token.is_cancelled() {
                    break;
                }

                // Connect to Redis for Pub/Sub
                let client = match redis::Client::open(redis_url.as_str()) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Failed to create Redis client for Pub/Sub: {}", e);
                        tokio::select! {
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        }
                    }
                };

                let conn = match client.get_async_pubsub().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Failed to get Pub/Sub connection: {}", e);
                        tokio::select! {
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        }
                    }
                };

                if let Err(e) = Self::run_pubsub_loop(
                    conn,
                    &my_instance_id,
                    &channel,
                    &ring,
                    &cancel_token,
                    &event_tx,
                )
                .await
                {
                    if !cancel_token.is_cancelled() {
                        tracing::warn!("Pub/Sub loop error, reconnecting: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            tracing::debug!("Pub/Sub task shutting down");
        })
    }

    async fn run_pubsub_loop(
        mut pubsub: PubSub,
        my_instance_id: &str,
        channel: &str,
        ring: &Arc<ArcSwap<HashRing>>,
        cancel_token: &CancellationToken,
        event_tx: &broadcast::Sender<MembershipEvent>,
    ) -> Result<(), Error> {
        pubsub.subscribe(channel).await?;
        tracing::debug!("Subscribed to {}", channel);

        let mut stream = pubsub.on_message();

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break;
                }
                msg = stream.next() => {
                    match msg {
                        Some(msg) => {
                            let payload: String = match msg.get_payload() {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!("Failed to get Pub/Sub payload: {}", e);
                                    continue;
                                }
                            };

                            let parsed: PubSubMessage = match serde_json::from_str(&payload) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!("Failed to parse Pub/Sub message: {}", e);
                                    continue;
                                }
                            };

                            // Ignore our own events
                            if parsed.instance_id == my_instance_id {
                                continue;
                            }

                            match parsed.event.as_str() {
                                "join" => {
                                    tracing::debug!(
                                        instance_id = %parsed.instance_id,
                                        "Instance joined (via Pub/Sub)"
                                    );
                                    let mut new_ring = (**ring.load()).clone();
                                    new_ring.add_instance(parsed.instance_id.clone());
                                    ring.store(Arc::new(new_ring));
                                    let _ = event_tx.send(MembershipEvent::Joined(parsed.instance_id));
                                }
                                "leave" => {
                                    tracing::debug!(
                                        instance_id = %parsed.instance_id,
                                        "Instance left (via Pub/Sub)"
                                    );
                                    let mut new_ring = (**ring.load()).clone();
                                    new_ring.remove_instance(&parsed.instance_id);
                                    ring.store(Arc::new(new_ring));
                                    let _ = event_tx.send(MembershipEvent::Left(parsed.instance_id));
                                }
                                other => {
                                    tracing::warn!("Unknown Pub/Sub event: {}", other);
                                }
                            }
                        }
                        None => {
                            // Stream ended, reconnect
                            return Err(Error::Connection("Pub/Sub stream ended".to_string()));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if this coordinator should handle the given key.
    ///
    /// This is a lock-free operation using atomic pointer loading.
    pub fn should_handle(&self, key: &str) -> bool {
        self.ring.load().should_handle(key)
    }

    /// Get the instance ID of this coordinator.
    pub fn instance_id(&self) -> String {
        self.ring.load().instance_id().to_string()
    }

    /// Get current instance count in the ring.
    ///
    /// This is a lock-free operation using atomic pointer loading.
    pub fn instance_count(&self) -> usize {
        self.ring.load().instance_count()
    }

    /// Subscribe to membership change events.
    ///
    /// Events are broadcast AFTER the ring has been updated.
    pub fn subscribe(&self) -> broadcast::Receiver<MembershipEvent> {
        self.event_tx.subscribe()
    }

    /// Manually refresh the hashring from Redis.
    ///
    /// # Errors
    ///
    /// Returns an error if Redis query fails.
    pub async fn refresh(&self) -> Result<(), Error> {
        let mut reg = self.registry.lock().await;
        reg.cleanup_stale().await?;
        let instances = reg.get_active_instances().await?;

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
        let mut reg = self.registry.lock().await;

        // Publish leave event
        let instance_id = reg.instance_id().to_string();
        Self::publish_event(&mut reg, "leave", &instance_id).await?;

        reg.deregister().await
    }

    /// Graceful shutdown - deregisters from cluster and stops tasks.
    ///
    /// # Errors
    ///
    /// Returns an error if deregistration fails.
    pub async fn shutdown(mut self) -> Result<(), Error> {
        // 1. Cancel background tasks FIRST to prevent heartbeat from re-registering
        self.cancel_token.cancel();

        if let Some(handle) = self.heartbeat_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.pubsub_handle.take() {
            let _ = handle.await;
        }

        // 2. Now deregister from cluster (tasks are stopped, so no race)
        {
            let mut reg = self.registry.lock().await;
            let instance_id = reg.instance_id().to_string();
            if let Err(e) = Self::publish_event(&mut reg, "leave", &instance_id).await {
                tracing::warn!("Failed to publish leave event: {}", e);
            }
            reg.deregister().await?;
        }

        // 3. Brief drain period for in-flight requests
        let drain_ms = (100_usize * self.instance_count().max(1)).min(2000);
        tokio::time::sleep(Duration::from_millis(drain_ms as u64)).await;

        tracing::debug!(drain_ms, "Shutdown complete");
        Ok(())
    }
}

use futures_util::StreamExt;

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn get_redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    /// Generate unique test prefix to isolate test data
    fn test_prefix() -> String {
        format!("test:{}", Uuid::new_v4())
    }

    #[test]
    fn test_membership_event_variants() {
        let joined = MembershipEvent::Joined("abc-123".to_string());
        let left = MembershipEvent::Left("xyz-789".to_string());
        assert_eq!(joined, MembershipEvent::Joined("abc-123".to_string()));
        assert_eq!(left, MembershipEvent::Left("xyz-789".to_string()));
    }

    #[tokio::test]
    async fn test_coordinator_starts_and_handles_keys() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let coordinator = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        // Solo instance should handle everything
        assert!(coordinator.should_handle("any-key"));
        assert!(coordinator.should_handle("another-key"));
        assert_eq!(coordinator.instance_count(), 1);

        coordinator.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_two_coordinators_split_keys() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let coord1 = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let coord2 = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        // Wait for Pub/Sub to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Trigger manual refresh to ensure both see each other
        coord1.refresh().await.unwrap();
        coord2.refresh().await.unwrap();

        assert_eq!(coord1.instance_count(), 2, "coord1 should see 2 instances");
        assert_eq!(coord2.instance_count(), 2, "coord2 should see 2 instances");

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
    async fn test_pubsub_detects_join() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let coord1 = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let mut rx = coord1.subscribe();

        assert_eq!(coord1.instance_count(), 1);

        // Start coord2 - coord1 should detect via Pub/Sub
        let coord2 = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        // Wait for Pub/Sub event
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Timeout waiting for join event")
            .expect("Channel closed");

        match event {
            MembershipEvent::Joined(id) => {
                assert_eq!(id, coord2.instance_id());
            }
            MembershipEvent::Left(_) => panic!("Expected join, got leave"),
        }

        coord1.shutdown().await.unwrap();
        coord2.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_graceful_shutdown_redistributes_keys() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let coord1 = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let coord2 = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        // Wait for both coordinators to see exactly 2 instances
        for _ in 0..20 {
            coord1.refresh().await.unwrap();
            coord2.refresh().await.unwrap();
            if coord1.instance_count() == 2 && coord2.instance_count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(coord1.instance_count(), 2, "coord1 should see 2 instances");
        assert_eq!(coord2.instance_count(), 2, "coord2 should see 2 instances");

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

        // Poll until coord1 sees only 1 instance (itself)
        for _ in 0..40 {
            coord1.refresh().await.unwrap();
            if coord1.instance_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            coord1.instance_count(),
            1,
            "coord1 should see only itself after coord2 leaves"
        );

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
}
