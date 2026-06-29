use crate::valkey_auth::{ValkeyConnectionFactory, TOKEN_REFRESH_BUFFER_SECS};
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
/// full sync as backup. Compatible with Google Memorystore and Valkey.
pub struct ClusterCoordinator {
    ring: Arc<ArcSwap<HashRing>>,
    registry: Arc<tokio::sync::Mutex<RedisRegistry>>,
    factory: Arc<ValkeyConnectionFactory>,
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
        Self::start_with_config(redis_url, prefix, false).await
    }

    /// Start a coordinator with full configuration options.
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis/Valkey connection URL
    /// * `prefix` - Optional key prefix for namespace isolation
    /// * `use_iam_auth` - Enable GCP IAM authentication for Memorystore Valkey
    ///
    /// # Errors
    ///
    /// Returns an error if registration or initial sync fails.
    pub async fn start_with_config(
        redis_url: &str,
        prefix: Option<&str>,
        use_iam_auth: bool,
    ) -> Result<Self, Error> {
        let factory = Arc::new(ValkeyConnectionFactory::new(redis_url, use_iam_auth).await?);
        let mut registry = RedisRegistry::register_with_factory(factory.clone(), prefix).await?;
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

        // Establish Pub/Sub subscription BEFORE publishing join event.
        // This guarantees we're listening before other coordinators can see our join.
        let mut pubsub = factory.get_pubsub_connection().await?;
        pubsub.subscribe(&channel).await?;
        tracing::debug!(channel = %channel, "Pub/Sub subscription established");

        // NOW publish join event (other instances will receive it)
        Self::publish_event(&mut registry, "join", &instance_id).await?;

        let registry = Arc::new(tokio::sync::Mutex::new(registry));

        // Spawn heartbeat task (with token refresh for IAM)
        let heartbeat_handle = Self::spawn_heartbeat_task(
            registry.clone(),
            ring.clone(),
            factory.clone(),
            cancel_token.clone(),
            event_tx.clone(),
        );

        // Spawn Pub/Sub listener task with already-subscribed connection
        let pubsub_handle = Self::spawn_pubsub_listener(
            pubsub,
            factory.clone(),
            instance_id.clone(),
            channel,
            ring.clone(),
            cancel_token.clone(),
            event_tx.clone(),
        );

        Ok(Self {
            ring,
            registry,
            factory,
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
        factory: Arc<ValkeyConnectionFactory>,
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

                        // Shutdown race guard: if the cancel token fired while
                        // we were waiting on the registry lock, a concurrent
                        // `deregister_and_stop_heartbeat` may have already
                        // removed this instance under this same lock. Sending a
                        // heartbeat now would re-register us (ZADD) and the
                        // instance would linger in the ring for a full heartbeat
                        // interval after we meant to leave. The select! arm for
                        // `cancel_token.cancelled()` does not protect us here:
                        // when both arms are ready select! may pick this one.
                        // We MUST check while holding the lock so the check is
                        // serialized against the deregister's DEL.
                        if cancel_token.is_cancelled() {
                            tracing::debug!("Heartbeat task observed cancellation under lock; not re-registering");
                            break;
                        }

                        // Check if IAM token needs refresh (before it expires)
                        if factory.uses_iam_auth() {
                            let ttl = factory.token_ttl_secs().await;
                            if ttl < TOKEN_REFRESH_BUFFER_SECS {
                                tracing::debug!(
                                    ttl_secs = ttl,
                                    "IAM token expiring soon, refreshing connection"
                                );
                                if let Err(e) = reg.refresh_connection().await {
                                    tracing::error!("Failed to refresh connection for IAM: {}", e);
                                    // Continue with existing connection, it may still work
                                }
                            }
                        }

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

    /// Spawn a Pub/Sub listener task with an already-subscribed connection.
    /// If the connection drops, the task will reconnect and resubscribe.
    fn spawn_pubsub_listener(
        initial_pubsub: PubSub,
        factory: Arc<ValkeyConnectionFactory>,
        my_instance_id: String,
        channel: String,
        ring: Arc<ArcSwap<HashRing>>,
        cancel_token: CancellationToken,
        event_tx: broadcast::Sender<MembershipEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // First iteration: use the already-subscribed connection
            let mut first_run = true;
            let mut current_pubsub: Option<PubSub> = Some(initial_pubsub);

            loop {
                if cancel_token.is_cancelled() {
                    break;
                }

                // Get connection: use initial on first run, reconnect on subsequent runs
                let pubsub = if first_run {
                    first_run = false;
                    current_pubsub.take().unwrap()
                } else {
                    // Reconnect using factory (supports IAM auth)
                    let mut conn = match factory.get_pubsub_connection().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("Failed to get Pub/Sub connection: {}", e);
                            tokio::select! {
                                _ = cancel_token.cancelled() => break,
                                _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                            }
                        }
                    };

                    // Resubscribe after reconnect
                    if let Err(e) = conn.subscribe(&channel).await {
                        tracing::error!("Failed to resubscribe to Pub/Sub channel: {}", e);
                        tokio::select! {
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        }
                    }
                    tracing::debug!(channel = %channel, "Pub/Sub resubscribed after reconnect");
                    conn
                };

                if let Err(e) = Self::run_pubsub_loop(
                    pubsub,
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

    /// Process messages on an already-subscribed Pub/Sub connection.
    async fn run_pubsub_loop(
        mut pubsub: PubSub,
        my_instance_id: &str,
        _channel: &str,
        ring: &Arc<ArcSwap<HashRing>>,
        cancel_token: &CancellationToken,
        event_tx: &broadcast::Sender<MembershipEvent>,
    ) -> Result<(), Error> {
        // Connection is already subscribed by caller
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

    /// Get the connection factory (for creating additional connections).
    pub fn factory(&self) -> Arc<ValkeyConnectionFactory> {
        self.factory.clone()
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

    /// Gracefully deregister from the cluster without consuming `self`.
    ///
    /// Use during process shutdown when the coordinator is shared behind an
    /// `Arc` (with the signer and relay workers) and ownership cannot be
    /// reclaimed for [`shutdown`](Self::shutdown).
    ///
    /// Mirrors [`shutdown`](Self::shutdown)'s ordering: the background tasks are
    /// stopped FIRST (by cancelling the shared token) so the heartbeat cannot
    /// re-register, then the `leave` event is published and the instance is
    /// deregistered. Because this takes `&self` it cannot `await` the heartbeat
    /// `JoinHandle` (which lives behind `&mut self`); instead it relies on the
    /// heartbeat loop re-checking the cancel token *while holding the registry
    /// lock* before each re-register. This method holds that same registry lock
    /// for the deregister, so the heartbeat's ZADD and this method's DEL are
    /// serialized and the instance cannot be resurrected after removal.
    ///
    /// # Errors
    ///
    /// Returns an error if deregistration fails. Failure to publish the `leave`
    /// event is logged and swallowed (peers still converge via heartbeat
    /// staleness), matching [`shutdown`](Self::shutdown).
    pub async fn deregister_and_stop_heartbeat(&self) -> Result<(), Error> {
        // 1. Stop background tasks first so the heartbeat cannot re-register.
        self.cancel_token.cancel();

        // 2. Publish leave + deregister under the registry lock (serialized
        //    against any in-flight heartbeat ZADD — see the method docs).
        let mut reg = self.registry.lock().await;
        let instance_id = reg.instance_id().to_string();
        if let Err(e) = Self::publish_event(&mut reg, "leave", &instance_id).await {
            tracing::warn!("Failed to publish leave event: {}", e);
        }
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
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".to_string())
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
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
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
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_deregister_and_stop_heartbeat_does_not_reappear() {
        // Regression for the SIGTERM-time graceful deregister: after
        // `deregister_and_stop_heartbeat` the instance must NOT be resurrected
        // by a surviving heartbeat tick. We wait past one full heartbeat
        // interval — long enough for the race (cancel vs. heartbeat ZADD) to
        // manifest if the token check were not serialized under the registry
        // lock — and assert the instance stays gone in Redis.
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let coordinator = ClusterCoordinator::start_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let instance_id = coordinator.instance_id();

        // Independent registry on the same prefix to read the ground truth in
        // Redis (its own presence is irrelevant; we only check `instance_id`).
        let mut observer = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        let before = observer.get_active_instances().await.unwrap();
        assert!(
            before.contains(&instance_id),
            "coordinator must be registered before deregister, got {before:?}"
        );

        // Graceful deregister via the `&self` (Arc-shared) path.
        coordinator.deregister_and_stop_heartbeat().await.unwrap();

        // Wait well past one heartbeat interval so a surviving heartbeat task
        // would have re-registered (ZADD) if the race were open.
        tokio::time::sleep(Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS + 2)).await;

        let after = observer.get_active_instances().await.unwrap();
        assert!(
            !after.contains(&instance_id),
            "deregistered instance must not reappear after more than one heartbeat interval, got {after:?}"
        );

        observer.deregister().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
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
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
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

        // Wait for Pub/Sub event (subscription guaranteed before coord2 starts)
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
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
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
