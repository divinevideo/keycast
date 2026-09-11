use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};

use crate::repositories::RepositoryError;
use crate::types::claim_token::{
    ClaimToken, ClaimTokenState, ClaimTokenStats, CLAIM_CONFIRMATION_SEND_LIMIT,
    CLAIM_TOKEN_EXPIRY_DAYS,
};

macro_rules! claim_token_columns {
    () => {
        "id, token, user_pubkey, expires_at, used_at, created_at, created_by_pubkey, \
         tenant_id, invalidated_at, invalidated_by, invalidation_reason"
    };
}

/// Outcome of staging a pending claim against a claim-token row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagePendingOutcome {
    /// Pending email/password/confirmation-token written to the row.
    Staged,
    /// Token was used, admin-invalidated, expired, or unknown — nothing staged.
    TokenNotStageable,
    /// Token is still valid, but it has already sent
    /// `CLAIM_CONFIRMATION_SEND_LIMIT` confirmation emails, so nothing was
    /// staged and nothing may be sent. Distinct from `TokenNotStageable` so the
    /// claimer gets a page that explains the budget rather than a generic
    /// "link no longer valid".
    SendLimitReached,
}

/// Send-related state for a staged pending claim, read by the resend endpoint
/// to decide whether a resend is due and which confirmation token to (re)send.
/// `confirmation_token` and `confirmation_expired` are non-optional because
/// `stage_pending_claim` always writes `pending_email`, `confirmation_token`,
/// and `confirmation_expires_at` together, and `confirm_claim_consuming_token`
/// always clears them together — so a row with `pending_email IS NOT NULL`
/// (this query's guard) is guaranteed to also carry a confirmation token and
/// expiry.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingClaimSendState {
    pub to_email: String,
    pub confirmation_sent_at: Option<DateTime<Utc>>,
    pub confirmation_token: String,
    pub confirmation_expired: bool,
}

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

        sqlx::query_as::<_, ClaimToken>(concat!(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, expires_at, created_at, created_by_pubkey, tenant_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING ",
            claim_token_columns!()
        ))
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
        sqlx::query_as::<_, ClaimToken>(concat!(
            "SELECT ",
            claim_token_columns!(),
            " FROM account_claim_tokens
             WHERE token = $1
               AND expires_at > NOW()
               AND used_at IS NULL
               AND invalidated_at IS NULL"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark a claim token as used.
    /// Returns the updated token, or None if token not found or already used.
    ///
    /// NOTE: the claim flow itself must NOT use this — it re-checks only
    /// `used_at`, not `invalidated_at`/`expires_at`. `claim_confirm_get`
    /// consumes tokens via `UserRepository::confirm_claim_consuming_token`,
    /// which is atomic with full validity (#280 review). Kept for
    /// tests/fixtures.
    pub async fn mark_used(&self, token: &str) -> Result<Option<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(concat!(
            "UPDATE account_claim_tokens
             SET used_at = NOW()
             WHERE token = $1
               AND used_at IS NULL
             RETURNING ",
            claim_token_columns!()
        ))
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
        sqlx::query_as::<_, ClaimToken>(concat!(
            "SELECT ",
            claim_token_columns!(),
            " FROM account_claim_tokens
             WHERE user_pubkey = $1
               AND tenant_id = $2
               AND expires_at > NOW()
               AND used_at IS NULL
               AND invalidated_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1"
        ))
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn find_valid_by_user_pubkey_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(concat!(
            "SELECT ",
            claim_token_columns!(),
            " FROM account_claim_tokens
             WHERE user_pubkey = $1
               AND tenant_id = $2
               AND expires_at > NOW()
               AND used_at IS NULL
               AND invalidated_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1"
        ))
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into)
    }

    /// Lock this account's claim-token rows before checking account state.
    /// The claim flow consumes a token before updating the user, so replay uses
    /// the same lock order to avoid minting across a concurrent claim.
    pub async fn lock_for_user_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "SELECT id FROM account_claim_tokens
             WHERE user_pubkey = $1 AND tenant_id = $2
             FOR UPDATE",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .fetch_all(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn create_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        token: &str,
        user_pubkey: &str,
        created_by_pubkey: Option<&str>,
        tenant_id: i64,
    ) -> Result<ClaimToken, RepositoryError> {
        let now = Utc::now();
        let expires_at = now + Duration::days(CLAIM_TOKEN_EXPIRY_DAYS);
        sqlx::query_as::<_, ClaimToken>(concat!(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, expires_at, created_at, created_by_pubkey, tenant_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING ",
            claim_token_columns!()
        ))
        .bind(token)
        .bind(user_pubkey)
        .bind(expires_at)
        .bind(now)
        .bind(created_by_pubkey)
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
    }

    /// Return the current token or mint one replacement while the caller holds
    /// the provisioning operation lock in this same transaction.
    pub async fn find_or_replace_for_provisioning_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        user_pubkey: &str,
        tenant_id: i64,
        replacement_token: &str,
    ) -> Result<ClaimToken, RepositoryError> {
        if let Some(existing) =
            Self::find_valid_by_user_pubkey_in_tx(tx, user_pubkey, tenant_id).await?
        {
            return Ok(existing);
        }

        let now = Utc::now();
        sqlx::query(
            "UPDATE account_claim_tokens
             SET expires_at = NOW(), invalidated_at = NOW(),
                 invalidation_reason = 'replaced_by_provisioning_replay'
             WHERE user_pubkey = $1 AND tenant_id = $2
               AND used_at IS NULL AND invalidated_at IS NULL",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;

        let expires_at = now + Duration::days(CLAIM_TOKEN_EXPIRY_DAYS);
        sqlx::query_as::<_, ClaimToken>(concat!(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, expires_at, created_at, tenant_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING ",
            claim_token_columns!()
        ))
        .bind(replacement_token)
        .bind(user_pubkey)
        .bind(expires_at)
        .bind(now)
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
    }

    /// Find all claim tokens for a user (for admin viewing).
    pub async fn find_by_user_pubkey(
        &self,
        user_pubkey: &str,
        tenant_id: i64,
    ) -> Result<Vec<ClaimToken>, RepositoryError> {
        sqlx::query_as::<_, ClaimToken>(concat!(
            "SELECT ",
            claim_token_columns!(),
            " FROM account_claim_tokens
             WHERE user_pubkey = $1 AND tenant_id = $2
             ORDER BY created_at DESC"
        ))
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

        let new_token = sqlx::query_as::<_, ClaimToken>(concat!(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, expires_at, created_at, created_by_pubkey, tenant_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING ",
            claim_token_columns!()
        ))
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

    /// Stage pending email/password/confirmation-token state on a claim
    /// token, guarded by the same validity predicate as `find_valid`. This
    /// mirrors `UserRepository::set_pending_email_change`
    /// (`core/src/repositories/user.rs:1007`) but for the claim flow: it is a
    /// sibling write, not a shared method, because the two guards differ
    /// (claim tokens also gate on `used_at`/`invalidated_at`/`expires_at`
    /// together, since an admin can invalidate an outstanding claim token).
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_pending_claim(
        &self,
        token: &str,
        tenant_id: i64,
        pending_email: &str,
        pending_password_hash: &str,
        confirmation_token: &str,
        confirmation_expires_at: DateTime<Utc>,
    ) -> Result<StagePendingOutcome, RepositoryError> {
        // Guarded write: only stage when the token is still valid. Re-checks
        // validity under the row lock so an invalidation cannot be overwritten.
        //
        // `confirmation_send_count` is incremented here, in the same statement
        // that claims the send, and the cap is part of the predicate. That makes
        // the budget check atomic: concurrent submits cannot each read a
        // count below the cap and then both send, because only one of them can
        // win the row update for a given count.
        let updated = sqlx::query(
            "UPDATE account_claim_tokens
             SET pending_email = $1,
                 pending_password_hash = $2,
                 confirmation_token = $3,
                 confirmation_expires_at = $4,
                 confirmation_sent_at = NOW(),
                 confirmation_send_count = confirmation_send_count + 1
             WHERE token = $5
               AND tenant_id = $6
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()
               AND confirmation_send_count < $7",
        )
        .bind(pending_email)
        .bind(pending_password_hash)
        .bind(confirmation_token)
        .bind(confirmation_expires_at)
        .bind(token)
        .bind(tenant_id)
        .bind(CLAIM_CONFIRMATION_SEND_LIMIT)
        .execute(&self.pool)
        .await?;

        if updated.rows_affected() > 0 {
            return Ok(StagePendingOutcome::Staged);
        }

        // Zero rows means either the token is no longer stageable or it is
        // still valid but out of send budget. Only the failure path pays for
        // this second read, and it deliberately drops the cap from the
        // predicate so a still-valid-but-exhausted token is distinguishable.
        let still_valid: Option<(i32,)> = sqlx::query_as(
            "SELECT confirmation_send_count
             FROM account_claim_tokens
             WHERE token = $1
               AND tenant_id = $2
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match still_valid {
            Some((count,)) if count >= CLAIM_CONFIRMATION_SEND_LIMIT => {
                Ok(StagePendingOutcome::SendLimitReached)
            }
            // Either no valid row at all, or it became stageable again between
            // the two statements; treat both as not-stageable so the caller
            // re-classifies the token and shows a state-specific page.
            _ => Ok(StagePendingOutcome::TokenNotStageable),
        }
    }

    /// Look up the claim token string and confirmation expiry for a given
    /// confirmation token, with no validity guard at all.
    ///
    /// Used only to classify a failed confirm into a precise error page, which
    /// is why it deliberately matches rows the other methods exclude (used,
    /// invalidated, expired): the whole point is to tell the claimer *why* the
    /// link did not work. Returns `None` when no row carries this confirmation
    /// token — unknown, already consumed (a successful confirm nulls it), or
    /// superseded by a rotation.
    pub async fn confirmation_classification(
        &self,
        confirmation_token: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT token, confirmation_expires_at
             FROM account_claim_tokens
             WHERE confirmation_token = $1
               AND tenant_id = $2",
        )
        .bind(confirmation_token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Read the send-related state of a staged pending claim, for the resend
    /// endpoint to decide whether a resend is due (cooldown) and whether the
    /// existing confirmation token is still usable or needs rotating.
    /// Explicit columns (no `SELECT *`), guarded by the same still-valid
    /// predicate as `stage_pending_claim`. Returns `None` when no staged,
    /// still-valid pending claim exists for this token (unknown token, no
    /// pending claim staged, or the underlying claim token has been used,
    /// invalidated, or has expired) — the caller (the resend handler) treats
    /// that identically to "in cooldown" so the response stays
    /// enumeration-safe.
    pub async fn pending_claim_send_state(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<PendingClaimSendState>, RepositoryError> {
        sqlx::query_as::<_, PendingClaimSendState>(
            "SELECT pending_email AS to_email,
                    confirmation_sent_at,
                    confirmation_token,
                    (confirmation_expires_at <= NOW()) AS confirmation_expired
             FROM account_claim_tokens
             WHERE token = $1
               AND tenant_id = $2
               AND pending_email IS NOT NULL
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Claim a resend slot for a staged pending claim, returning `true` when
    /// the caller may actually send.
    ///
    /// This is a single atomic check-and-set: the cooldown and the lifetime
    /// send cap are both predicates on the same `UPDATE` that bumps
    /// `confirmation_sent_at` and increments `confirmation_send_count`. An
    /// earlier version read the cooldown and wrote in two statements, which let
    /// concurrent resends each pass the read and each send — bounded only by
    /// how many arrived at once. Doing it in one statement means exactly one
    /// concurrent request can win a given slot.
    ///
    /// When `rotated` is `Some` (because the prior confirmation token had
    /// already expired) the freshly minted token/expiry pair replaces the old
    /// one in the same write.
    ///
    /// Guarded by the same still-valid predicate as
    /// `pending_claim_send_state`/`stage_pending_claim`, so a claim token that
    /// died between the read and this write (e.g. a concurrent admin
    /// invalidation) leaves the row untouched rather than reviving it.
    /// A `false` return therefore covers every reason not to send — in
    /// cooldown, out of budget, or no longer valid — which is what keeps the
    /// resend endpoint's response enumeration-safe.
    pub async fn touch_claim_confirmation(
        &self,
        token: &str,
        tenant_id: i64,
        rotated: Option<(&str, DateTime<Utc>)>,
        cooldown_minutes: i64,
    ) -> Result<bool, RepositoryError> {
        let cooldown_minutes = i32::try_from(cooldown_minutes).unwrap_or(i32::MAX);
        let updated = match rotated {
            Some((new_confirmation_token, new_confirmation_expires_at)) => {
                sqlx::query(
                    "UPDATE account_claim_tokens
                     SET confirmation_sent_at = NOW(),
                         confirmation_send_count = confirmation_send_count + 1,
                         confirmation_token = $1,
                         confirmation_expires_at = $2
                     WHERE token = $3
                       AND tenant_id = $4
                       AND pending_email IS NOT NULL
                       AND used_at IS NULL
                       AND invalidated_at IS NULL
                       AND expires_at > NOW()
                       AND confirmation_send_count < $5
                       AND (confirmation_sent_at IS NULL
                            OR confirmation_sent_at
                               < NOW() - make_interval(mins => $6))",
                )
                .bind(new_confirmation_token)
                .bind(new_confirmation_expires_at)
                .bind(token)
                .bind(tenant_id)
                .bind(CLAIM_CONFIRMATION_SEND_LIMIT)
                .bind(cooldown_minutes)
                .execute(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    "UPDATE account_claim_tokens
                     SET confirmation_sent_at = NOW(),
                         confirmation_send_count = confirmation_send_count + 1
                     WHERE token = $1
                       AND tenant_id = $2
                       AND pending_email IS NOT NULL
                       AND used_at IS NULL
                       AND invalidated_at IS NULL
                       AND expires_at > NOW()
                       AND confirmation_send_count < $3
                       AND (confirmation_sent_at IS NULL
                            OR confirmation_sent_at
                               < NOW() - make_interval(mins => $4))",
                )
                .bind(token)
                .bind(tenant_id)
                .bind(CLAIM_CONFIRMATION_SEND_LIMIT)
                .bind(cooldown_minutes)
                .execute(&self.pool)
                .await?
            }
        };

        Ok(updated.rows_affected() > 0)
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
        let ct = sqlx::query_as::<_, ClaimToken>(concat!(
            "SELECT ",
            claim_token_columns!(),
            " FROM account_claim_tokens
                 WHERE token = $1 AND tenant_id = $2"
        ))
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
        let newer = sqlx::query_as::<_, ClaimToken>(concat!(
            "SELECT ",
            claim_token_columns!(),
            " FROM account_claim_tokens
             WHERE user_pubkey = $1
               AND tenant_id = $2
               AND created_at > $3
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1"
        ))
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
