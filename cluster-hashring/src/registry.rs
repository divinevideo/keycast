use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::Error;

const INSTANCES_KEY: &str = "signer_instances";
const STALE_THRESHOLD_SECS: u64 = 30;

pub struct RedisRegistry {
    conn: MultiplexedConnection,
    instance_id: String,
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
    pub async fn register(redis_url: &str) -> Result<Self, Error> {
        let client = redis::Client::open(redis_url)?;
        let mut conn = client.get_multiplexed_async_connection().await?;

        let instance_id = Uuid::new_v4().to_string();
        let timestamp = current_timestamp_ms();

        // ZADD signer_instances <timestamp> <instance_id>
        conn.zadd::<_, _, _, ()>(INSTANCES_KEY, &instance_id, timestamp)
            .await?;

        tracing::info!(%instance_id, "Registered instance in Redis");
        Ok(Self { conn, instance_id })
    }

    pub async fn deregister(&mut self) -> Result<(), Error> {
        // ZREM signer_instances <instance_id>
        self.conn
            .zrem::<_, _, ()>(INSTANCES_KEY, &self.instance_id)
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
            .zadd::<_, _, _, ()>(INSTANCES_KEY, &self.instance_id, timestamp)
            .await?;

        Ok(())
    }

    pub async fn get_active_instances(&mut self) -> Result<Vec<String>, Error> {
        let cutoff = current_timestamp_ms() - (STALE_THRESHOLD_SECS * 1000);

        // ZRANGEBYSCORE signer_instances <cutoff> +inf
        let instances: Vec<String> = self
            .conn
            .zrangebyscore(INSTANCES_KEY, cutoff, "+inf")
            .await?;

        Ok(instances)
    }

    pub async fn cleanup_stale(&mut self) -> Result<u64, Error> {
        let cutoff = current_timestamp_ms() - (STALE_THRESHOLD_SECS * 1000);

        // ZREMRANGEBYSCORE signer_instances -inf <cutoff>
        let count: u64 = self
            .conn
            .zrembyscore(INSTANCES_KEY, "-inf", cutoff)
            .await?;

        if count > 0 {
            tracing::info!(count, "Cleaned up stale instances from Redis");
        }
        Ok(count)
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
    use serial_test::serial;
    use std::time::Duration;

    async fn get_redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    async fn cleanup_test_instances(redis_url: &str) {
        let client = redis::Client::open(redis_url).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: () = redis::cmd("DEL")
            .arg(INSTANCES_KEY)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_register_creates_instance() {
        let redis_url = get_redis_url().await;
        cleanup_test_instances(&redis_url).await;

        let mut registry = RedisRegistry::register(&redis_url).await.unwrap();

        let instances = registry.get_active_instances().await.unwrap();
        assert!(instances.contains(&registry.instance_id().to_string()));

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_deregister_removes_instance() {
        let redis_url = get_redis_url().await;
        cleanup_test_instances(&redis_url).await;

        let mut registry = RedisRegistry::register(&redis_url).await.unwrap();
        let id = registry.instance_id().to_string();

        let instances = registry.get_active_instances().await.unwrap();
        assert!(instances.contains(&id));

        registry.deregister().await.unwrap();

        let instances = registry.get_active_instances().await.unwrap();
        assert!(!instances.contains(&id));
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_heartbeat_updates_timestamp() {
        let redis_url = get_redis_url().await;
        cleanup_test_instances(&redis_url).await;

        let mut registry = RedisRegistry::register(&redis_url).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        registry.heartbeat().await.unwrap();

        // Instance should still be active
        let instances = registry.get_active_instances().await.unwrap();
        assert!(instances.contains(&registry.instance_id().to_string()));

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_multiple_instances_unique_ids() {
        let redis_url = get_redis_url().await;
        cleanup_test_instances(&redis_url).await;

        let mut r1 = RedisRegistry::register(&redis_url).await.unwrap();
        let mut r2 = RedisRegistry::register(&redis_url).await.unwrap();
        let mut r3 = RedisRegistry::register(&redis_url).await.unwrap();

        let ids = [r1.instance_id(), r2.instance_id(), r3.instance_id()];
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 3, "All instance IDs should be unique");

        let instances = r1.get_active_instances().await.unwrap();
        assert_eq!(instances.len(), 3);

        r1.deregister().await.unwrap();
        r2.deregister().await.unwrap();
        r3.deregister().await.unwrap();
    }
}
