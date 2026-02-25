use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::repositories::RepositoryError;
use crate::types::claim_token::{ClaimToken, ClaimTokenStats, CLAIM_TOKEN_EXPIRY_DAYS};

/// Repository for account claim token operations.
/// Used for preloaded users to claim their accounts by setting email/password.
#[derive(Debug)]
pub struct ClaimTokenRepository {
    pool: PgPool,
}

impl ClaimTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new claim token for a preloaded user.
    pub async fn create(
        &self,
        token: &str,
        user_pubkey: &str,
        created_by_pubkey: Option<&str>,
        tenant_id: i64,
    ) -> Result<ClaimToken, RepositoryError> {
        let now = Utc::now();
        let expires_at = now + Duration::days(CLAIM_TOKEN_EXPIRY_DAYS);

        sqlx::query_as::<_, ClaimToken>(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, expires_at, created_at, created_by_pubkey, tenant_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *",
        )
        .bind(token)
        .bind(user_pubkey)
        .bind(expires_at)
        .bind(now)
        .bind(created_by_pubkey)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a valid (not expired, not used) claim token.
    /// Returns None if token doesn't exist, is expired, or already used.
    pub async fn find_valid(&self, token: &str) -> Result<Option<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(
            "SELECT * FROM account_claim_tokens
             WHERE token = $1
               AND expires_at > NOW()
               AND used_at IS NULL",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark a claim token as used.
    /// Returns the updated token, or None if token not found or already used.
    pub async fn mark_used(&self, token: &str) -> Result<Option<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(
            "UPDATE account_claim_tokens
             SET used_at = NOW()
             WHERE token = $1
               AND used_at IS NULL
             RETURNING *",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a valid (not expired, not used) claim token for a specific user.
    /// Returns the most recently created valid token, if any.
    pub async fn find_valid_by_user_pubkey(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(
            "SELECT * FROM account_claim_tokens
             WHERE user_pubkey = $1
               AND tenant_id = $2
               AND expires_at > NOW()
               AND used_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find all claim tokens for a user (for admin viewing).
    pub async fn find_by_user_pubkey(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Vec<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(
            "SELECT * FROM account_claim_tokens
             WHERE user_pubkey = $1 AND tenant_id = $2
             ORDER BY created_at DESC",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get aggregate statistics for claim tokens in a tenant.
    pub async fn get_stats(&self, tenant_id: i64) -> Result<ClaimTokenStats, RepositoryError> {
        let row: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
               COUNT(*)::bigint AS total_generated,
               COUNT(*) FILTER (WHERE used_at IS NOT NULL)::bigint AS total_claimed,
               COUNT(*) FILTER (WHERE expires_at < NOW() AND used_at IS NULL)::bigint AS total_expired,
               COUNT(*) FILTER (WHERE expires_at >= NOW() AND used_at IS NULL)::bigint AS total_pending
             FROM account_claim_tokens
             WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ClaimTokenStats {
            total_generated: row.0,
            total_claimed: row.1,
            total_expired: row.2,
            total_pending: row.3,
        })
    }

    /// Clean up expired and used tokens (for maintenance).
    pub async fn cleanup_old_tokens(&self, days_old: i64) -> Result<u64, RepositoryError> {
        let cutoff = Utc::now() - Duration::days(days_old);

        let result = sqlx::query(
            "DELETE FROM account_claim_tokens
             WHERE (used_at IS NOT NULL AND used_at < $1)
                OR (expires_at < $1)",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
