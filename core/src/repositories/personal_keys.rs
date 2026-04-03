// ABOUTME: Repository for personal_keys table operations
// ABOUTME: Manages encrypted user secret keys for personal OAuth authorizations

use crate::repositories::RepositoryError;
use chrono::Utc;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct PersonalKeysRepository {
    pool: PgPool,
}

impl PersonalKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find encrypted secret key by user pubkey.
    /// Returns None if user has no personal keys.
    pub async fn find_encrypted_key(
        &self,
        user_pubkey: &str,
    ) -> Result<Option<Vec<u8>>, RepositoryError> {
        sqlx::query_scalar("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(user_pubkey)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Find encrypted secret key with tenant isolation.
    /// Joins with users table to verify tenant membership.
    pub async fn find_encrypted_key_for_tenant(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<Vec<u8>>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT pk.encrypted_secret_key
             FROM personal_keys pk
             JOIN users u ON pk.user_pubkey = u.pubkey
             WHERE pk.user_pubkey = $1 AND u.tenant_id = $2",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find encrypted secret key by tenant_id directly on personal_keys table.
    /// Use when you need to check personal_keys.tenant_id without user JOIN.
    pub async fn find_encrypted_key_by_tenant(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Option<Vec<u8>>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create personal keys for a user.
    pub async fn create(
        &self,
        user_pubkey: &str,
        encrypted_secret_key: &[u8],
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(user_pubkey)
        .bind(encrypted_secret_key)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete all personal keys for a user.
    /// Used when user changes their key identity.
    ///
    /// WARNING: Not tenant-scoped. Prefer `delete_by_user_for_tenant` for request paths.
    pub async fn delete_by_user(&self, user_pubkey: &str) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(user_pubkey)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete personal keys for a user within a specific tenant.
    /// Ensures tenant isolation by joining with users table.
    pub async fn delete_by_user_for_tenant(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "DELETE FROM personal_keys
             WHERE user_pubkey = $1
               AND tenant_id = $2",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;

    fn assert_localhost_db() {
        let url = std::env::var("DATABASE_URL").unwrap_or_default();
        assert!(
            url.contains("localhost") || url.contains("127.0.0.1") || url.is_empty(),
            "Tests must run against localhost database"
        );
    }

    async fn setup_pool() -> PgPool {
        assert_localhost_db();
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database")
    }

    #[tokio::test]
    async fn test_find_encrypted_key_not_found() {
        let pool = setup_pool().await;
        let repo = PersonalKeysRepository::new(pool);

        let result = repo
            .find_encrypted_key("nonexistent_pubkey_12345")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_create_and_find() {
        use nostr_sdk::Keys;
        use uuid::Uuid;

        let pool = setup_pool().await;
        let repo = PersonalKeysRepository::new(pool.clone());

        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let encrypted_key = vec![1, 2, 3, 4, 5, 6, 7, 8]; // Mock encrypted data

        // Create user first (foreign key constraint)
        sqlx::query("INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at) VALUES ($1, 1, $2, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .bind(format!("test-{}@example.com", Uuid::new_v4()))
            .execute(&pool)
            .await
            .unwrap();

        // Create personal keys
        repo.create(&user_pubkey, &encrypted_key, 1).await.unwrap();

        // Find should return the key
        let found = repo.find_encrypted_key(&user_pubkey).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap(), encrypted_key);

        // Cleanup
        repo.delete_by_user(&user_pubkey).await.unwrap();

        // Should be gone
        let found = repo.find_encrypted_key(&user_pubkey).await.unwrap();
        assert!(found.is_none());
    }
}
