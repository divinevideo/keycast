use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::repositories::RepositoryError;
use crate::types::refresh_token::{hash_refresh_token, RefreshToken, REFRESH_TOKEN_EXPIRY_DAYS};

/// The client a refresh token is bound to, resolved without consuming the token.
///
/// `client_id` mirrors the column on `oauth_authorizations`, which is nullable,
/// so an absent value means the binding is not recorded rather than that it is
/// empty.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RefreshTokenBinding {
    pub client_id: Option<String>,
}

/// Repository for OAuth refresh token operations.
/// Implements token rotation per RFC 9700 - each token is one-time use.
#[derive(Debug)]
pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new refresh token (stores the hash, not the plaintext).
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database insert fails.
    pub async fn create(
        &self,
        token: &str,
        authorization_id: i32,
        tenant_id: i64,
    ) -> Result<RefreshToken, RepositoryError> {
        let token_hash = hash_refresh_token(token);
        let now = Utc::now();
        let expires_at = now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

        sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth_refresh_tokens
             (token_hash, authorization_id, tenant_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *",
        )
        .bind(&token_hash)
        .bind(authorization_id)
        .bind(tenant_id)
        .bind(now)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Consume a refresh token atomically (validates + marks as consumed).
    ///
    /// Returns `None` if token is invalid, expired, or already consumed.
    /// Implements one-time use per RFC 9700 token rotation.
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database query fails.
    pub async fn consume(&self, token: &str) -> Result<Option<RefreshToken>, RepositoryError> {
        let token_hash = hash_refresh_token(token);

        let result = sqlx::query_as::<_, RefreshToken>(
            "UPDATE oauth_refresh_tokens
             SET consumed_at = NOW()
             WHERE token_hash = $1
               AND consumed_at IS NULL
               AND expires_at > NOW()
             RETURNING *",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Look up a refresh-token record by its SHA-256 hash without changing it.
    ///
    /// This is intended for rejection diagnostics after [`Self::consume`] returns `None`.
    /// It deliberately includes expired and consumed records.
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if the database query fails.
    pub async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        sqlx::query_as::<_, RefreshToken>(
            "SELECT id, token_hash, authorization_id, tenant_id, created_at, expires_at, consumed_at
             FROM oauth_refresh_tokens
             WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Resolve the client a refresh token is bound to, without consuming it.
    ///
    /// Returns `None` when no token with this hash exists in the tenant, which
    /// keeps the caller's existing handling of unknown tokens intact. Expired
    /// and already-consumed tokens are included, because the binding they carry
    /// is what decides whether the caller is entitled to learn their state.
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if the database query fails.
    pub async fn find_binding(
        &self,
        token_hash: &str,
        tenant_id: i64,
    ) -> Result<Option<RefreshTokenBinding>, RepositoryError> {
        sqlx::query_as::<_, RefreshTokenBinding>(
            "SELECT oa.client_id
             FROM oauth_refresh_tokens AS rt
             JOIN oauth_authorizations AS oa
               ON oa.id = rt.authorization_id
              AND oa.tenant_id = rt.tenant_id
             WHERE rt.token_hash = $1
               AND rt.tenant_id = $2",
        )
        .bind(token_hash)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Revoke all refresh tokens for an authorization.
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database update fails.
    pub async fn revoke_for_authorization(
        &self,
        authorization_id: i32,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "UPDATE oauth_refresh_tokens
             SET consumed_at = NOW()
             WHERE authorization_id = $1
               AND consumed_at IS NULL",
        )
        .bind(authorization_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clean up expired and consumed tokens (for maintenance).
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database delete fails.
    pub async fn cleanup_old_tokens(&self, days_old: i64) -> Result<u64, RepositoryError> {
        let cutoff = Utc::now() - Duration::days(days_old);

        let result = sqlx::query(
            "DELETE FROM oauth_refresh_tokens
             WHERE (consumed_at IS NOT NULL AND consumed_at < $1)
                OR (expires_at < $1)",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_consistency() {
        let token = "test_token_12345";
        let hash1 = hash_refresh_token(token);
        let hash2 = hash_refresh_token(token);
        assert_eq!(hash1, hash2);
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod integration_tests {
    use super::*;
    use crate::types::refresh_token::{generate_refresh_token, hash_refresh_token};
    use nostr_sdk::Keys;
    use uuid::Uuid;

    fn assert_localhost_db() {
        let url = std::env::var("DATABASE_URL").unwrap_or_default();
        assert!(
            url.contains("localhost") || url.contains("127.0.0.1") || url.is_empty(),
            "Tests must run against localhost"
        );
    }

    async fn setup_pool() -> PgPool {
        assert_localhost_db();
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("failed to connect to test database");
        pool
    }

    #[tokio::test]
    async fn lookup_by_hash_returns_existing_state_without_mutating_it() {
        let pool = setup_pool().await;
        let repo = RefreshTokenRepository::new(pool.clone());
        let user_pubkey = Keys::generate().public_key().to_hex();
        let origin = format!("https://refresh-test-{}.example", Uuid::new_v4());

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .expect("create test user");
        let authorization_id: i32 = sqlx::query_scalar(
            "INSERT INTO oauth_authorizations
             (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays,
              tenant_id, handle_expires_at, created_at, updated_at)
             VALUES ($1, $2, 'stored-client', $3, 'secret-hash', '[]', 1,
                     NOW() + INTERVAL '30 days', NOW(), NOW())
             RETURNING id",
        )
        .bind(&user_pubkey)
        .bind(&origin)
        .bind(Keys::generate().public_key().to_hex())
        .fetch_one(&pool)
        .await
        .expect("create test authorization");

        let raw_token = generate_refresh_token();
        let token_hash = hash_refresh_token(&raw_token);
        repo.create(&raw_token, authorization_id, 1)
            .await
            .expect("create refresh token");

        let active = repo
            .find_by_token_hash(&token_hash)
            .await
            .expect("lookup active refresh token")
            .expect("active refresh token should exist");
        assert!(active.consumed_at.is_none());
        assert!(repo
            .find_by_token_hash(&raw_token)
            .await
            .expect("raw-token lookup should execute")
            .is_none());

        repo.consume(&raw_token)
            .await
            .expect("consume refresh token")
            .expect("refresh token should be consumable");
        let consumed = repo
            .find_by_token_hash(&token_hash)
            .await
            .expect("lookup consumed refresh token")
            .expect("consumed refresh token should remain diagnosable");
        assert!(consumed.consumed_at.is_some());
        assert!(repo
            .find_by_token_hash(&"0".repeat(64))
            .await
            .expect("unknown-token lookup should execute")
            .is_none());

        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .expect("clean up test user");
    }

    #[tokio::test]
    async fn binding_lookup_resolves_the_owning_client_within_the_tenant_only() {
        let pool = setup_pool().await;
        let repo = RefreshTokenRepository::new(pool.clone());
        let user_pubkey = Keys::generate().public_key().to_hex();
        let origin = format!("https://binding-test-{}.example", Uuid::new_v4());

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .expect("create test user");
        let authorization_id: i32 = sqlx::query_scalar(
            "INSERT INTO oauth_authorizations
             (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays,
              tenant_id, handle_expires_at, created_at, updated_at)
             VALUES ($1, $2, 'stored-client', $3, 'secret-hash', '[]', 1,
                     NOW() + INTERVAL '30 days', NOW(), NOW())
             RETURNING id",
        )
        .bind(&user_pubkey)
        .bind(&origin)
        .bind(Keys::generate().public_key().to_hex())
        .fetch_one(&pool)
        .await
        .expect("create test authorization");

        let raw_token = generate_refresh_token();
        let token_hash = hash_refresh_token(&raw_token);
        repo.create(&raw_token, authorization_id, 1)
            .await
            .expect("create refresh token");

        assert_eq!(
            repo.find_binding(&token_hash, 1)
                .await
                .expect("binding lookup should execute"),
            Some(RefreshTokenBinding {
                client_id: Some("stored-client".to_string()),
            })
        );
        assert!(repo
            .find_binding(&token_hash, 2)
            .await
            .expect("cross-tenant lookup should execute")
            .is_none());
        assert!(repo
            .find_binding(&"0".repeat(64), 1)
            .await
            .expect("unknown-token lookup should execute")
            .is_none());

        // The lookup must not consume or otherwise disturb the token.
        assert!(repo
            .find_by_token_hash(&token_hash)
            .await
            .expect("state lookup should execute")
            .expect("token should still exist")
            .consumed_at
            .is_none());

        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .expect("clean up test user");
    }
}
