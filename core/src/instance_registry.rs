use sqlx::PgPool;
use uuid::Uuid;

pub struct InstanceRegistry {
    pool: PgPool,
    instance_id: String,
}

impl Drop for InstanceRegistry {
    fn drop(&mut self) {
        tracing::debug!(instance_id = %self.instance_id, "InstanceRegistry dropped (deregister should be called explicitly)");
    }
}

impl InstanceRegistry {
    pub async fn register(pool: PgPool) -> Result<Self, sqlx::Error> {
        let instance_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO signer_instances (instance_id) VALUES ($1::uuid)")
            .bind(&instance_id)
            .execute(&pool)
            .await?;
        tracing::info!(%instance_id, "Registered signer instance");
        Ok(Self { pool, instance_id })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub async fn heartbeat(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE signer_instances SET last_heartbeat = NOW() WHERE instance_id = $1::uuid",
        )
        .bind(&self.instance_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_active_instances(&self) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT instance_id::text FROM signer_instances WHERE last_heartbeat > NOW() - INTERVAL '30 seconds' ORDER BY instance_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    pub async fn deregister(&self) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM signer_instances WHERE instance_id = $1::uuid")
            .bind(&self.instance_id)
            .execute(&self.pool)
            .await?;
        tracing::info!(instance_id = %self.instance_id, "Deregistered signer instance");
        Ok(())
    }

    pub async fn cleanup_stale(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM signer_instances WHERE last_heartbeat < NOW() - INTERVAL '60 seconds'",
        )
        .execute(&self.pool)
        .await?;
        let count = result.rows_affected();
        if count > 0 {
            tracing::info!(count, "Cleaned up stale signer instances");
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());
        PgPool::connect(&database_url).await.unwrap()
    }

    async fn cleanup_test_instances(pool: &PgPool) {
        sqlx::query("DELETE FROM signer_instances")
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_register_creates_instance() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();

        // Verify instance exists in database
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM signer_instances WHERE instance_id = $1::uuid")
            .bind(registry.instance_id())
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(count.0, 1);

        // Cleanup
        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    async fn test_instance_id_is_valid_uuid() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();
        let id = registry.instance_id();

        // Should be a valid UUID
        assert!(Uuid::parse_str(id).is_ok(), "instance_id should be a valid UUID");

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    async fn test_heartbeat_updates_timestamp() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();

        // Get initial heartbeat
        let initial: (chrono::DateTime<chrono::Utc>,) = sqlx::query_as(
            "SELECT last_heartbeat FROM signer_instances WHERE instance_id = $1::uuid"
        )
        .bind(registry.instance_id())
        .fetch_one(&pool)
        .await
        .unwrap();

        // Small delay
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Send heartbeat
        registry.heartbeat().await.unwrap();

        // Get updated heartbeat
        let updated: (chrono::DateTime<chrono::Utc>,) = sqlx::query_as(
            "SELECT last_heartbeat FROM signer_instances WHERE instance_id = $1::uuid"
        )
        .bind(registry.instance_id())
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(updated.0 >= initial.0, "Heartbeat should update timestamp");

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    async fn test_get_active_instances_returns_fresh() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry1 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let registry2 = InstanceRegistry::register(pool.clone()).await.unwrap();

        let active = registry1.get_active_instances().await.unwrap();

        // Check that both our instances are in the active list
        // (may have more from parallel tests, so just check contains)
        assert!(active.contains(&registry1.instance_id().to_string()));
        assert!(active.contains(&registry2.instance_id().to_string()));

        registry1.deregister().await.unwrap();
        registry2.deregister().await.unwrap();
    }

    #[tokio::test]
    async fn test_deregister_removes_instance() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();
        let instance_id = registry.instance_id().to_string();

        registry.deregister().await.unwrap();

        // Verify instance no longer exists
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM signer_instances WHERE instance_id = $1::uuid")
            .bind(&instance_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn test_multiple_instances_have_unique_ids() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry1 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let registry2 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let registry3 = InstanceRegistry::register(pool.clone()).await.unwrap();

        let ids = [
            registry1.instance_id(),
            registry2.instance_id(),
            registry3.instance_id(),
        ];

        // All IDs should be unique
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 3, "All instance IDs should be unique");

        registry1.deregister().await.unwrap();
        registry2.deregister().await.unwrap();
        registry3.deregister().await.unwrap();
    }

    #[tokio::test]
    async fn test_cleanup_stale_removes_old_instances() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        // Insert a stale instance (heartbeat > 60 seconds ago)
        let stale_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO signer_instances (instance_id, last_heartbeat) VALUES ($1::uuid, NOW() - INTERVAL '2 minutes')"
        )
        .bind(&stale_id)
        .execute(&pool)
        .await
        .unwrap();

        // Register a fresh instance
        let registry = InstanceRegistry::register(pool.clone()).await.unwrap();

        // Cleanup should remove at least the stale one we created
        let removed = registry.cleanup_stale().await.unwrap();
        assert!(removed >= 1, "Should remove at least 1 stale instance");

        // Our fresh instance should be in active list
        let active = registry.get_active_instances().await.unwrap();
        assert!(active.contains(&registry.instance_id().to_string()));

        // The stale one should NOT be in active list
        assert!(!active.contains(&stale_id));

        registry.deregister().await.unwrap();
    }

    #[tokio::test]
    async fn test_active_instances_ordered_by_id() {
        let pool = get_test_pool().await;
        cleanup_test_instances(&pool).await;

        let registry1 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let registry2 = InstanceRegistry::register(pool.clone()).await.unwrap();
        let registry3 = InstanceRegistry::register(pool.clone()).await.unwrap();

        let active = registry1.get_active_instances().await.unwrap();

        // Should be sorted (for deterministic hashring)
        let mut sorted = active.clone();
        sorted.sort();
        assert_eq!(active, sorted, "Active instances should be sorted by ID");

        registry1.deregister().await.unwrap();
        registry2.deregister().await.unwrap();
        registry3.deregister().await.unwrap();
    }
}
