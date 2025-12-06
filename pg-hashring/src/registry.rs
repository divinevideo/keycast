use sqlx::postgres::PgListener;
use sqlx::PgPool;
use uuid::Uuid;

use crate::Error;

pub struct InstanceRegistry {
    pool: PgPool,
    instance_id: String,
}

impl Drop for InstanceRegistry {
    fn drop(&mut self) {
        tracing::debug!(
            instance_id = %self.instance_id,
            "InstanceRegistry dropped (deregister should be called explicitly)"
        );
    }
}

const DEFAULT_TABLE: &str = "signer_instances";
const DEFAULT_CHANNEL: &str = "cluster_membership";

impl InstanceRegistry {
    pub async fn register(pool: PgPool) -> Result<Self, Error> {
        let instance_id = Uuid::new_v4().to_string();

        sqlx::query(&format!(
            "INSERT INTO {} (instance_id) VALUES ($1::uuid)",
            DEFAULT_TABLE
        ))
        .bind(&instance_id)
        .execute(&pool)
        .await?;

        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(DEFAULT_CHANNEL)
            .bind(format!("joined:{}", instance_id))
            .execute(&pool)
            .await?;

        tracing::info!(%instance_id, "Registered instance");
        Ok(Self { pool, instance_id })
    }

    pub async fn deregister(&self) -> Result<(), Error> {
        sqlx::query(&format!(
            "DELETE FROM {} WHERE instance_id = $1::uuid",
            DEFAULT_TABLE
        ))
        .bind(&self.instance_id)
        .execute(&self.pool)
        .await?;

        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(DEFAULT_CHANNEL)
            .bind(format!("left:{}", self.instance_id))
            .execute(&self.pool)
            .await?;

        tracing::info!(instance_id = %self.instance_id, "Deregistered instance");
        Ok(())
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub async fn create_listener(pool: &PgPool) -> Result<PgListener, Error> {
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen(DEFAULT_CHANNEL).await?;
        Ok(listener)
    }

    pub async fn heartbeat(&self) -> Result<(), Error> {
        sqlx::query(&format!(
            "UPDATE {} SET last_heartbeat = NOW() WHERE instance_id = $1::uuid",
            DEFAULT_TABLE
        ))
        .bind(&self.instance_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_active_instances(pool: &PgPool) -> Result<Vec<String>, Error> {
        let rows: Vec<(String,)> = sqlx::query_as(&format!(
            "SELECT instance_id::text FROM {} \
             WHERE last_heartbeat > NOW() - INTERVAL '30 seconds' \
             ORDER BY instance_id",
            DEFAULT_TABLE
        ))
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    pub async fn cleanup_stale(pool: &PgPool) -> Result<u64, Error> {
        let result = sqlx::query(&format!(
            "DELETE FROM {} WHERE last_heartbeat < NOW() - INTERVAL '30 seconds'",
            DEFAULT_TABLE
        ))
        .execute(pool)
        .await?;
        let count = result.rows_affected();
        if count > 0 {
            tracing::info!(count, "Cleaned up stale instances");
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::time::Duration;

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

    #[tokio::test]
    #[serial]
    async fn test_registry_register_creates_instance() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM signer_instances WHERE instance_id = $1::uuid")
                .bind(registry.instance_id())
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(count.0, 1);

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_notify_on_register() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let mut listener = InstanceRegistry::create_listener(&pool).await.unwrap();

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();

        let notification = tokio::time::timeout(Duration::from_millis(500), listener.recv())
            .await
            .expect("timeout waiting for notification")
            .unwrap();

        assert!(
            notification.payload().starts_with("joined:"),
            "Expected 'joined:' prefix, got: {}",
            notification.payload()
        );
        assert!(
            notification.payload().contains(registry.instance_id()),
            "Notification should contain instance_id"
        );

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_notify_on_deregister() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();
        let instance_id = registry.instance_id().to_string();

        let mut listener = InstanceRegistry::create_listener(&pool).await.unwrap();

        // Drain any pending notifications from register
        let _ = tokio::time::timeout(Duration::from_millis(50), listener.recv()).await;

        registry.deregister().await.unwrap();

        let notification = tokio::time::timeout(Duration::from_millis(500), listener.recv())
            .await
            .expect("timeout waiting for notification")
            .unwrap();

        assert_eq!(
            notification.payload(),
            format!("left:{}", instance_id),
            "Expected 'left:<id>' notification"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_graceful_shutdown_removes_from_active() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();
        let id = registry.instance_id().to_string();

        let active = InstanceRegistry::get_active_instances(&pool).await.unwrap();
        assert!(active.contains(&id), "Instance should be in active list");

        registry.deregister().await.unwrap();

        let active = InstanceRegistry::get_active_instances(&pool).await.unwrap();
        assert!(
            !active.contains(&id),
            "Instance should NOT be in active list after deregister"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_heartbeat_updates_timestamp() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();

        let initial: (chrono::DateTime<chrono::Utc>,) = sqlx::query_as(
            "SELECT last_heartbeat FROM signer_instances WHERE instance_id = $1::uuid",
        )
        .bind(registry.instance_id())
        .fetch_one(&pool)
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        registry.heartbeat().await.unwrap();

        let updated: (chrono::DateTime<chrono::Utc>,) = sqlx::query_as(
            "SELECT last_heartbeat FROM signer_instances WHERE instance_id = $1::uuid",
        )
        .bind(registry.instance_id())
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(updated.0 >= initial.0, "Heartbeat should update timestamp");

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_registry_multiple_instances_unique_ids() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let r1 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let r2 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let r3 = InstanceRegistry::register(pool.clone()).await.unwrap();

        let ids = [r1.instance_id(), r2.instance_id(), r3.instance_id()];
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 3, "All instance IDs should be unique");

        r1.deregister().await.unwrap();
        r2.deregister().await.unwrap();
        r3.deregister().await.unwrap();
    }
}
