use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::repositories::RepositoryError;
use crate::types::claim_token::{
    ClaimToken, ClaimTokenState, ClaimTokenStats, CLAIM_TOKEN_EXPIRY_DAYS,
};

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

    /// Find a valid (not expired, not used, not admin-invalidated) claim token.
    /// Returns None if token doesn't exist, is expired, already used, or has
    /// been administratively invalidated.
    ///
    /// Note: this filters on `invalidated_at IS NULL` as defense-in-depth even
    /// though `invalidate_valid_for_user` and `create_with_prior_invalidation`
    /// both also set `expires_at = NOW()` (which the `expires_at > NOW()`
    /// predicate would catch). The explicit `invalidated_at IS NULL` check
    /// prevents a future code path that sets `invalidated_at` without also
    /// clamping `expires_at` from surfacing invalidated tokens.
    pub async fn find_valid(&self, token: &str) -> Result<Option<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(
            "SELECT * FROM account_claim_tokens
             WHERE token = $1
               AND expires_at > NOW()
               AND used_at IS NULL
               AND invalidated_at IS NULL",
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

    /// Find a valid (not expired, not used, not admin-invalidated) claim token
    /// for a specific user. Returns the most recently created valid token, if
    /// any. Same defense-in-depth filter as `find_valid`.
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
               AND invalidated_at IS NULL
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

    /// Create a new claim token and, in the same transaction, invalidate any
    /// prior valid token for the same user. Used by the Regenerate admin
    /// action. Returns (new_token, count_of_priors_invalidated).
    ///
    /// The invalidation UPDATE's WHERE clause (`used_at IS NULL AND
    /// invalidated_at IS NULL AND expires_at > NOW()`) is the safety guard:
    /// it won't clobber an already-claimed, already-invalidated, or
    /// already-expired row's timestamps. Wrapping the UPDATE and the INSERT
    /// in one transaction means a Regenerate either swaps both (old dead,
    /// new alive) or neither — no "neither valid" window.
    pub async fn create_with_prior_invalidation(
        &self,
        token: &str,
        user_pubkey: &str,
        created_by_pubkey: Option<&str>,
        tenant_id: i64,
    ) -> Result<(ClaimToken, u64), RepositoryError> {
        let now = Utc::now();
        let expires_at = now + Duration::days(CLAIM_TOKEN_EXPIRY_DAYS);

        let mut tx = self.pool.begin().await?;

        let invalidated_count = sqlx::query(
            "UPDATE account_claim_tokens
             SET expires_at = NOW(),
                 invalidated_at = NOW(),
                 invalidated_by = $1,
                 invalidation_reason = 'replaced_by_regenerate'
             WHERE user_pubkey = $2
               AND tenant_id = $3
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(created_by_pubkey)
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let new_token = sqlx::query_as::<_, ClaimToken>(
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
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((new_token, invalidated_count))
    }

    /// Invalidate all valid (unused, unexpired, not-already-invalidated) claim
    /// tokens for a user. Sets expires_at = NOW() and invalidated_at = NOW(),
    /// records admin pubkey and optional reason. Returns the count of rows
    /// updated. Idempotent: returns 0 when nothing valid exists.
    ///
    /// The WHERE clause (`used_at IS NULL AND invalidated_at IS NULL AND
    /// expires_at > NOW()`) is the safety guard: it atomically excludes
    /// already-claimed, already-invalidated, and already-expired rows.
    /// Callers do not need a separate pre-flight check against races with
    /// concurrent claim / invalidate / expiry transitions — the update either
    /// matches a valid row or is a no-op.
    pub async fn invalidate_valid_for_user(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
        invalidated_by: &str,
        reason: Option<&str>,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "UPDATE account_claim_tokens
             SET expires_at = NOW(),
                 invalidated_at = NOW(),
                 invalidated_by = $3,
                 invalidation_reason = $4
             WHERE user_pubkey = $1
               AND tenant_id = $2
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .bind(invalidated_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Classify a token string into one of the ClaimTokenState variants by
    /// inspecting the row and, for expired rows, checking for a newer valid
    /// replacement. Used by the `/claim` HTTP handler to pick the right
    /// error page.
    pub async fn classify(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<ClaimTokenState, RepositoryError> {
        let ct = sqlx::query_as::<_, ClaimToken>(
            "SELECT * FROM account_claim_tokens
             WHERE token = $1 AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let ct = match ct {
            None => return Ok(ClaimTokenState::Unrecognized),
            Some(t) => t,
        };

        if ct.used_at.is_some() {
            return Ok(ClaimTokenState::AlreadyClaimed(ct));
        }
        if ct.invalidated_at.is_some() {
            return Ok(ClaimTokenState::AdminInvalidated(ct));
        }
        if ct.expires_at > Utc::now() {
            return Ok(ClaimTokenState::Valid(ct));
        }

        // Expired, not admin-invalidated; check for newer valid token for same user.
        let newer = sqlx::query_as::<_, ClaimToken>(
            "SELECT * FROM account_claim_tokens
             WHERE user_pubkey = $1
               AND tenant_id = $2
               AND created_at > $3
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(&ct.user_pubkey)
        .bind(tenant_id)
        .bind(ct.created_at)
        .fetch_optional(&self.pool)
        .await?;

        Ok(match newer {
            Some(n) => ClaimTokenState::Replaced {
                current: ct,
                newer: n,
            },
            None => ClaimTokenState::Expired(ct),
        })
    }
}
