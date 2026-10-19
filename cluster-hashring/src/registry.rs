use crate::valkey_auth::{is_read_only_error, ValkeyConnectionFactory};
use crate::Error;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisResult};
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const DEFAULT_INSTANCES_KEY: &str = "signer_instances";
const DEFAULT_CHANNEL: &str = "cluster:membership";
const STALE_THRESHOLD_SECS: u64 = 30;

pub struct RedisRegistry {
    conn: ConnectionManager,
    factory: Arc<ValkeyConnectionFactory>,
    instance_id: String,
    instances_key: String,
    channel: String,
}

impl Drop for RedisRegistry {
    fn drop(&mut self) {
        tracing::debug!(
            instance_id = %self.instance_id,
            "RedisRegistry dropped (deregister should be called explicitly)"
        );
    }
}

impl RedisRegistry {
    /// Register with default key names (production use).
    pub async fn register(redis_url: &str) -> Result<Self, Error> {
        Self::register_with_prefix(redis_url, None).await
    }

    /// Register with optional key prefix (for test isolation).
    pub async fn register_with_prefix(
        redis_url: &str,
        prefix: Option<&str>,
    ) -> Result<Self, Error> {
        let factory = Arc::new(ValkeyConnectionFactory::new(redis_url, false).await?);
        Self::register_with_factory(factory, prefix).await
    }

    /// Register using a ValkeyConnectionFactory (supports IAM auth).
    pub async fn register_with_factory(
        factory: Arc<ValkeyConnectionFactory>,
        prefix: Option<&str>,
    ) -> Result<Self, Error> {
        let mut conn = factory.get_connection_manager().await?;

        let instance_id = Uuid::new_v4().to_string();
        let timestamp = current_timestamp_ms();

        let (instances_key, channel) = match prefix {
            Some(p) => (
                format!("{p}:{DEFAULT_INSTANCES_KEY}"),
                format!("{p}:{DEFAULT_CHANNEL}"),
            ),
            None => (
                DEFAULT_INSTANCES_KEY.to_string(),
                DEFAULT_CHANNEL.to_string(),
            ),
        };

        // ZADD signer_instances <timestamp> <instance_id>
        conn.zadd::<_, _, _, ()>(&instances_key, &instance_id, timestamp)
            .await?;

        tracing::info!(%instance_id, %instances_key, "Registered instance in Redis");
        Ok(Self {
            conn,
            factory,
            instance_id,
            instances_key,
            channel,
        })
    }

    pub async fn deregister(&mut self) -> Result<(), Error> {
        // ZREM signer_instances <instance_id>
        let instances_key = self.instances_key.clone();
        let instance_id = self.instance_id.clone();
        self.write_with_reconnect(|mut conn| {
            let instances_key = instances_key.clone();
            let instance_id = instance_id.clone();
            async move { conn.zrem::<_, _, ()>(instances_key, instance_id).await }
        })
        .await?;

        tracing::info!(instance_id = %self.instance_id, "Deregistered instance from Redis");
        Ok(())
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub async fn heartbeat(&mut self) -> Result<(), Error> {
        let timestamp = current_timestamp_ms();

        // ZADD signer_instances <timestamp> <instance_id> (updates score)
        let instances_key = self.instances_key.clone();
        let instance_id = self.instance_id.clone();
        self.write_with_reconnect(|mut conn| {
            let instances_key = instances_key.clone();
            let instance_id = instance_id.clone();
            async move {
                conn.zadd::<_, _, _, ()>(instances_key, instance_id, timestamp)
                    .await
            }
        })
        .await?;

        Ok(())
    }

    pub async fn get_active_instances(&mut self) -> Result<Vec<String>, Error> {
        let cutoff = current_timestamp_ms() - (STALE_THRESHOLD_SECS * 1000);

        // ZRANGEBYSCORE signer_instances <cutoff> +inf
        let instances: Vec<String> = self
            .conn
            .zrangebyscore(&self.instances_key, cutoff, "+inf")
            .await?;

        Ok(instances)
    }

    pub async fn cleanup_stale(&mut self) -> Result<u64, Error> {
        let cutoff = current_timestamp_ms() - (STALE_THRESHOLD_SECS * 1000);

        // ZREMRANGEBYSCORE signer_instances -inf <cutoff>
        let instances_key = self.instances_key.clone();
        let count: u64 = self
            .write_with_reconnect(|mut conn| {
                let instances_key = instances_key.clone();
                async move { conn.zrembyscore(instances_key, "-inf", cutoff).await }
            })
            .await?;

        if count > 0 {
            tracing::info!(count, "Cleaned up stale instances from Redis");
        }
        Ok(count)
    }

    /// Get the channel name for pub/sub operations.
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Get the instances key name (for test cleanup).
    pub fn instances_key(&self) -> &str {
        &self.instances_key
    }

    /// Get the Redis command connection for operations like `PUBLISH`.
    pub fn connection(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// Get the connection factory.
    pub fn factory(&self) -> Arc<ValkeyConnectionFactory> {
        self.factory.clone()
    }

    /// Refresh the Redis connection (for IAM token rotation).
    /// This creates a new connection with fresh credentials.
    pub async fn refresh_connection(&mut self) -> Result<(), Error> {
        self.conn = self.factory.get_connection_manager().await?;
        tracing::debug!(instance_id = %self.instance_id, "Refreshed Redis connection");
        Ok(())
    }

    /// Run a write, reconnecting and retrying once if Redis answers `READONLY`.
    ///
    /// The heartbeat must reach the current primary after a failover; otherwise
    /// this instance ages out of every other instance's ring while its socket
    /// stays open to the demoted node.
    async fn write_with_reconnect<T, F, Fut>(&mut self, op: F) -> Result<T, Error>
    where
        F: Fn(ConnectionManager) -> Fut,
        Fut: Future<Output = RedisResult<T>>,
    {
        match op(self.conn.clone()).await {
            Err(error) if is_read_only_error(&error) => {
                tracing::warn!(
                    instance_id = %self.instance_id,
                    "Redis rejected a write as READONLY; reconnecting to reach the current primary"
                );
                self.refresh_connection().await?;
                Ok(op(self.conn.clone()).await?)
            }
            result => Ok(result?),
        }
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn get_redis_url() -> String {
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".to_string())
    }

    /// Generate unique test prefix to isolate test data
    fn test_prefix() -> String {
        format!("test:{}", Uuid::new_v4())
    }

    async fn registry_client_id(registry: &mut RedisRegistry) -> u64 {
        redis::cmd("CLIENT")
            .arg("ID")
            .query_async(&mut registry.conn)
            .await
            .unwrap()
    }

    async fn kill_client(redis_url: &str, client_id: u64) {
        let client = redis::Client::open(redis_url).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        redis::cmd("CLIENT")
            .arg("KILL")
            .arg("ID")
            .arg(client_id)
            .query_async::<()>(&mut conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_register_creates_instance() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        let instances = registry.get_active_instances().await.unwrap();
        assert_eq!(instances.len(), 1);
        assert!(instances.contains(&registry.instance_id().to_string()));

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_deregister_removes_instance() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let id = registry.instance_id().to_string();

        let instances = registry.get_active_instances().await.unwrap();
        assert!(instances.contains(&id));

        registry.deregister().await.unwrap();

        let instances = registry.get_active_instances().await.unwrap();
        assert!(!instances.contains(&id));
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_heartbeat_updates_timestamp() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        registry.heartbeat().await.unwrap();

        // Instance should still be active
        let instances = registry.get_active_instances().await.unwrap();
        assert!(instances.contains(&registry.instance_id().to_string()));

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_recovers_after_connection_killed() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        let client_id = registry_client_id(&mut registry).await;
        kill_client(&redis_url, client_id).await;

        let first_result = registry.heartbeat().await;
        assert!(
            first_result.is_err(),
            "the command that discovers the killed socket should fail"
        );

        registry.heartbeat().await.unwrap();
        let instances = registry.get_active_instances().await.unwrap();
        assert!(instances.contains(&registry.instance_id().to_string()));

        registry.deregister().await.unwrap();
    }

    fn read_only_error() -> redis::RedisError {
        redis::RedisError::from((
            redis::ErrorKind::ReadOnly,
            "You can't write against a read only replica.",
        ))
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_reconnects_and_retries_after_read_only() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let original_client_id = registry_client_id(&mut registry).await;

        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let client_id: u64 = registry
            .write_with_reconnect(|mut conn| {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        return Err(read_only_error());
                    }
                    redis::cmd("CLIENT").arg("ID").query_async(&mut conn).await
                }
            })
            .await
            .unwrap();

        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_ne!(
            client_id, original_client_id,
            "the retry should run on a new connection"
        );
        assert_eq!(registry_client_id(&mut registry).await, client_id);

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_keeps_connection_on_other_errors() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let original_client_id = registry_client_id(&mut registry).await;

        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), Error> = registry
            .write_with_reconnect(|_conn| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    Err(redis::RedisError::from((
                        redis::ErrorKind::ResponseError,
                        "ERR unknown command",
                    )))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(registry_client_id(&mut registry).await, original_client_id);

        registry.deregister().await.unwrap();
    }

    /// Demotes the server, so it runs only against a dedicated instance named by
    /// `REDIS_FAILOVER_TEST_URL`, never the shared test Redis.
    #[tokio::test]
    #[ignore = "demotes the server: requires a dedicated Redis via REDIS_FAILOVER_TEST_URL"]
    async fn test_heartbeat_reconnects_after_read_only() {
        let Ok(redis_url) = std::env::var("REDIS_FAILOVER_TEST_URL") else {
            eprintln!("skipping: REDIS_FAILOVER_TEST_URL is not set");
            return;
        };
        let mut registry = RedisRegistry::register_with_prefix(&redis_url, Some(&test_prefix()))
            .await
            .unwrap();
        let before = registry_client_id(&mut registry).await;
        let mut admin = redis::Client::open(redis_url.as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();

        // Port 1 never answers, so the node stays a replica until promoted.
        redis::cmd("REPLICAOF")
            .arg("127.0.0.1")
            .arg(1)
            .query_async::<()>(&mut admin)
            .await
            .unwrap();
        let while_replica = registry.heartbeat().await;
        redis::cmd("REPLICAOF")
            .arg("NO")
            .arg("ONE")
            .query_async::<()>(&mut admin)
            .await
            .unwrap();

        assert!(while_replica.is_err(), "a replica refuses the heartbeat");
        assert_ne!(
            registry_client_id(&mut registry).await,
            before,
            "the heartbeat should reconnect after READONLY"
        );
        registry.heartbeat().await.unwrap();

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_multiple_instances_unique_ids() {
        let redis_url = get_redis_url();
        let prefix = test_prefix();

        let mut r1 = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let mut r2 = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();
        let mut r3 = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix))
            .await
            .unwrap();

        let ids = [r1.instance_id(), r2.instance_id(), r3.instance_id()];
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 3, "All instance IDs should be unique");

        let instances = r1.get_active_instances().await.unwrap();
        assert_eq!(instances.len(), 3);

        r1.deregister().await.unwrap();
        r2.deregister().await.unwrap();
        r3.deregister().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis via TEST_REDIS_URL or local Redis on localhost:16379"]
    async fn test_registry_prefix_isolation() {
        let redis_url = get_redis_url();
        let prefix1 = test_prefix();
        let prefix2 = test_prefix();

        // Create registries with different prefixes
        let mut r1 = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix1))
            .await
            .unwrap();
        let mut r2 = RedisRegistry::register_with_prefix(&redis_url, Some(&prefix2))
            .await
            .unwrap();

        // Each should only see itself
        let instances1 = r1.get_active_instances().await.unwrap();
        let instances2 = r2.get_active_instances().await.unwrap();

        assert_eq!(instances1.len(), 1);
        assert_eq!(instances2.len(), 1);
        assert!(instances1.contains(&r1.instance_id().to_string()));
        assert!(instances2.contains(&r2.instance_id().to_string()));
        assert!(!instances1.contains(&r2.instance_id().to_string()));
        assert!(!instances2.contains(&r1.instance_id().to_string()));

        r1.deregister().await.unwrap();
        r2.deregister().await.unwrap();
    }
}
