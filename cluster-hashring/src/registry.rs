use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::Error;

const DEFAULT_INSTANCES_KEY: &str = "signer_instances";
const DEFAULT_CHANNEL: &str = "cluster:membership";
const STALE_THRESHOLD_SECS: u64 = 30;

pub struct RedisRegistry {
    conn: MultiplexedConnection,
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
        let client = redis::Client::open(redis_url)?;
        let mut conn = client.get_multiplexed_async_connection().await?;

        let instance_id = Uuid::new_v4().to_string();
        let timestamp = current_timestamp_ms();

        let (instances_key, channel) = match prefix {
            Some(p) => (format!("{p}:{DEFAULT_INSTANCES_KEY}"), format!("{p}:{DEFAULT_CHANNEL}")),
            None => (DEFAULT_INSTANCES_KEY.to_string(), DEFAULT_CHANNEL.to_string()),
        };

        // ZADD signer_instances <timestamp> <instance_id>
        conn.zadd::<_, _, _, ()>(&instances_key, &instance_id, timestamp)
            .await?;

        tracing::info!(%instance_id, %instances_key, "Registered instance in Redis");
        Ok(Self {
            conn,
            instance_id,
            instances_key,
            channel,
        })
    }

    pub async fn deregister(&mut self) -> Result<(), Error> {
        // ZREM signer_instances <instance_id>
        self.conn
            .zrem::<_, _, ()>(&self.instances_key, &self.instance_id)
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
        self.conn
            .zadd::<_, _, _, ()>(&self.instances_key, &self.instance_id, timestamp)
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
        let count: u64 = self
            .conn
            .zrembyscore(&self.instances_key, "-inf", cutoff)
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

    /// Get the Redis connection for Pub/Sub operations
    pub fn connection(&self) -> MultiplexedConnection {
        self.conn.clone()
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
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    /// Generate unique test prefix to isolate test data
    fn test_prefix() -> String {
        format!("test:{}", Uuid::new_v4())
    }

    #[tokio::test]
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
