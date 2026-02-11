// ABOUTME: Repository for OAuth authorization database operations
// ABOUTME: Handles OAuth-based remote signing authorizations

use crate::repositories::RepositoryError;
use crate::types::oauth_authorization::OAuthAuthorization;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Parameters for creating a new OAuth authorization.
#[derive(Debug, Clone)]
pub struct CreateOAuthAuthorizationParams {
    pub tenant_id: i64,
    pub user_pubkey: String,
    pub redirect_origin: String,
    pub client_id: String,
    pub bunker_public_key: String,
    /// The bcrypt hash of the connection secret (verified during NIP-46 connect)
    pub secret_hash: String,
    pub relays: String,
    pub policy_id: Option<i32>,
    pub client_pubkey: Option<String>,
    pub authorization_handle: Option<String>,
    pub handle_expires_at: DateTime<Utc>,
}

/// Repository for OAuth authorization database operations.
#[derive(Debug, Clone)]
pub struct OAuthAuthorizationRepository {
    pool: PgPool,
}

impl OAuthAuthorizationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find(
        &self,
        tenant_id: i64,
        authorization_id: i32,
    ) -> Result<OAuthAuthorization, RepositoryError> {
        sqlx::query_as::<_, OAuthAuthorization>(
            "SELECT id, user_pubkey, redirect_origin, client_id, bunker_public_key,
                    secret_hash, relays, policy_id, tenant_id, client_pubkey, connected_client_pubkey,
                    connected_at, created_at, updated_at, revoked_at, expires_at,
                    handle_expires_at, authorization_handle
             FROM oauth_authorizations WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(authorization_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn all_ids(&self) -> Result<Vec<i32>, RepositoryError> {
        sqlx::query_scalar::<_, i32>(
            r#"
            SELECT id FROM oauth_authorizations
            WHERE revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > NOW())
              AND handle_expires_at > NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn all_ids_for_all_tenants(&self) -> Result<Vec<(i64, i32)>, RepositoryError> {
        sqlx::query_as::<_, (i64, i32)>(
            r#"
            SELECT tenant_id, id FROM oauth_authorizations
            WHERE revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > NOW())
              AND handle_expires_at > NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find an active authorization by handle, scoped to a specific user.
    /// Returns None if handle doesn't exist, is expired, revoked, or belongs to a different user.
    pub async fn find_id_by_handle(
        &self,
        authorization_handle: &str,
        user_pubkey: &str,
    ) -> Result<Option<i32>, RepositoryError> {
        sqlx::query_scalar::<_, i32>(
            "SELECT id FROM oauth_authorizations
             WHERE authorization_handle = $1
               AND user_pubkey = $2
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > NOW())
               AND handle_expires_at > NOW()",
        )
        .bind(authorization_handle)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create a new OAuth authorization and return its ID.
    pub async fn create(
        &self,
        params: CreateOAuthAuthorizationParams,
    ) -> Result<i32, RepositoryError> {
        let now = Utc::now();
        sqlx::query_scalar::<_, i32>(
            "INSERT INTO oauth_authorizations
             (tenant_id, user_pubkey, redirect_origin, client_id, bunker_public_key,
              secret_hash, relays, policy_id, client_pubkey, authorization_handle, handle_expires_at,
              created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING id",
        )
        .bind(params.tenant_id)
        .bind(&params.user_pubkey)
        .bind(&params.redirect_origin)
        .bind(&params.client_id)
        .bind(&params.bunker_public_key)
        .bind(&params.secret_hash)
        .bind(&params.relays)
        .bind(params.policy_id)
        .bind(&params.client_pubkey)
        .bind(&params.authorization_handle)
        .bind(params.handle_expires_at)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Revoke an authorization by setting revoked_at to now.
    pub async fn revoke(&self, id: i32) -> Result<(), RepositoryError> {
        sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List active OAuth sessions for a user.
    /// Returns (name, redirect_origin, bunker_public_key, client_pubkey, created_at, last_activity, activity_count).
    pub async fn list_active_sessions(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<
        Vec<(
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            i32,
        )>,
        RepositoryError,
    > {
        sqlx::query_as(
            "SELECT
                COALESCE(oa.client_id, oa.redirect_origin) as name,
                oa.redirect_origin,
                oa.bunker_public_key,
                oa.client_pubkey,
                oa.created_at::text,
                oa.last_activity::text,
                oa.activity_count
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_pubkey = u.pubkey
             WHERE oa.user_pubkey = $1
               AND u.tenant_id = $2
               AND oa.revoked_at IS NULL
             ORDER BY oa.created_at DESC",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Verify session ownership by bunker pubkey, returning the user pubkey if valid.
    pub async fn verify_session_ownership(
        &self,
        bunker_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT oa.user_pubkey FROM oauth_authorizations oa
             JOIN users u ON oa.user_pubkey = u.pubkey
             WHERE oa.bunker_public_key = $1 AND u.tenant_id = $2",
        )
        .bind(bunker_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.map(|r| r.0))
    }

    /// Check if an active authorization exists for a bunker pubkey and user.
    pub async fn exists_active_for_bunker(
        &self,
        bunker_pubkey: &str,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let exists: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM oauth_authorizations
             WHERE bunker_public_key = $1 AND user_pubkey = $2
               AND revoked_at IS NULL
               AND user_pubkey IN (SELECT pubkey FROM users WHERE tenant_id = $3)",
        )
        .bind(bunker_pubkey)
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }

    /// Revoke an authorization by bunker pubkey.
    pub async fn revoke_by_bunker_pubkey(
        &self,
        bunker_pubkey: &str,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE oauth_authorizations
             SET revoked_at = NOW(), updated_at = NOW()
             WHERE bunker_public_key = $1 AND user_pubkey = $2
               AND revoked_at IS NULL
               AND user_pubkey IN (SELECT pubkey FROM users WHERE tenant_id = $3)",
        )
        .bind(bunker_pubkey)
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find bunker pubkey by redirect origin.
    pub async fn find_bunker_pubkey_by_redirect_origin(
        &self,
        user_pubkey: &str,
        redirect_origin: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT oa.bunker_public_key FROM oauth_authorizations oa
             WHERE oa.user_pubkey = $1
             AND oa.redirect_origin = $2
             AND oa.tenant_id = $3",
        )
        .bind(user_pubkey)
        .bind(redirect_origin)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Disconnect a NIP-46 client by clearing connected client pubkey.
    /// Returns the number of rows affected (0 if no matching authorization found).
    pub async fn disconnect_client(
        &self,
        bunker_pubkey: &str,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "UPDATE oauth_authorizations
             SET connected_client_pubkey = NULL, connected_at = NULL, updated_at = NOW()
             WHERE bunker_public_key = $1 AND user_pubkey = $2
               AND revoked_at IS NULL
               AND user_pubkey IN (SELECT pubkey FROM users WHERE tenant_id = $3)",
        )
        .bind(bunker_pubkey)
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Find policy_id for an active authorization by user and redirect origin.
    /// Returns None if no authorization found, Some(None) if no policy set.
    pub async fn find_policy_id_by_origin(
        &self,
        user_pubkey: &str,
        redirect_origin: &str,
        tenant_id: i64,
    ) -> Result<Option<Option<i32>>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT policy_id
             FROM oauth_authorizations
             WHERE user_pubkey = $1
             AND redirect_origin = $2
             AND tenant_id = $3
             AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .bind(user_pubkey)
        .bind(redirect_origin)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if any active (non-revoked) authorization exists for a user+origin.
    pub async fn has_active_for_origin(
        &self,
        user_pubkey: &str,
        redirect_origin: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let exists: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM oauth_authorizations
             WHERE user_pubkey = $1
               AND redirect_origin = $2
               AND tenant_id = $3
               AND revoked_at IS NULL
             LIMIT 1",
        )
        .bind(user_pubkey)
        .bind(redirect_origin)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }

    /// Find the most recent bunker pubkey for a user.
    pub async fn find_latest_bunker_pubkey(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_pubkey = u.pubkey
             WHERE oa.user_pubkey = $1 AND u.tenant_id = $2
             ORDER BY oa.created_at DESC
             LIMIT 1",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find authorization details by bunker public key.
    /// Returns (id, user_pubkey, authorization_handle, expires_at, revoked_at, policy_id).
    #[allow(clippy::type_complexity)]
    pub async fn find_by_bunker_pubkey(
        &self,
        bunker_pubkey: &str,
    ) -> Result<
        Option<(
            i32,
            String,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<i32>,
        )>,
        RepositoryError,
    > {
        sqlx::query_as(
            "SELECT id, user_pubkey, authorization_handle, expires_at, revoked_at, policy_id
             FROM oauth_authorizations
             WHERE bunker_public_key = $1",
        )
        .bind(bunker_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// List active authorizations with policy info for a user.
    /// Returns tuples of (app_name, policy_id, policy_name, policy_slug, policy_display_name,
    /// policy_description, created_at, bunker_public_key, last_activity, activity_count).
    #[allow(clippy::type_complexity)]
    pub async fn list_with_policy_info(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<
        Vec<(
            String,         // app_name
            i32,            // policy_id (0 if none)
            String,         // policy_name
            Option<String>, // policy_slug
            Option<String>, // policy_display_name
            Option<String>, // policy_description
            String,         // created_at
            String,         // bunker_public_key
            Option<String>, // last_activity
            Option<i64>,    // activity_count
        )>,
        RepositoryError,
    > {
        sqlx::query_as(
            "SELECT
                COALESCE(oa.client_id, oa.redirect_origin, 'Personal Bunker') as app_name,
                COALESCE(oa.policy_id, 0) as policy_id,
                COALESCE(p.name, 'No Policy') as policy_name,
                p.slug as policy_slug,
                p.display_name as policy_display_name,
                p.description as policy_description,
                oa.created_at::text,
                oa.bunker_public_key,
                oa.last_activity::text,
                oa.activity_count::bigint
             FROM oauth_authorizations oa
             LEFT JOIN policies p ON oa.policy_id = p.id
             JOIN users u ON oa.user_pubkey = u.pubkey
             WHERE oa.user_pubkey = $1
               AND u.tenant_id = $2
               AND oa.revoked_at IS NULL
             ORDER BY oa.created_at DESC",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}

#[cfg(test)]
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
    async fn test_all_ids_returns_active_authorizations() {
        let pool = setup_pool().await;
        let repo = OAuthAuthorizationRepository::new(pool);

        // Should not error even if no authorizations exist
        let result = repo.all_ids().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_find_not_found() {
        let pool = setup_pool().await;
        let repo = OAuthAuthorizationRepository::new(pool);

        let result = repo.find(1, 999999).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_find_by_handle_requires_matching_user() {
        use nostr_sdk::Keys;
        use uuid::Uuid;

        let pool = setup_pool().await;
        let repo = OAuthAuthorizationRepository::new(pool.clone());

        let user_a = Keys::generate().public_key().to_hex();
        let user_b = Keys::generate().public_key().to_hex();
        let bunker_pubkey = Keys::generate().public_key().to_hex();
        let handle = format!("{:064x}", rand::random::<u128>());
        let origin = format!("https://test-{}.example.com", Uuid::new_v4());

        // Create users
        for pubkey in [&user_a, &user_b] {
            sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
                .bind(pubkey)
                .execute(&pool)
                .await
                .unwrap();
        }

        // Create authorization for user_b
        sqlx::query(
            "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays, tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
             VALUES ($1, $2, 'Test', $3, '$2b$10$test_hash', '[]', 1, $4, NOW() + INTERVAL '30 days', NOW(), NOW())"
        )
        .bind(&user_b)
        .bind(&origin)
        .bind(&bunker_pubkey)
        .bind(&handle)
        .execute(&pool)
        .await
        .unwrap();

        // user_a cannot find user_b's handle
        let result = repo.find_id_by_handle(&handle, &user_a).await.unwrap();
        assert!(result.is_none());

        // user_b can find their own handle
        let result = repo.find_id_by_handle(&handle, &user_b).await.unwrap();
        assert!(result.is_some());
    }
}
