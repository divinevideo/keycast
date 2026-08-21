// ABOUTME: Repository for durable service-requested account-deletion records
// ABOUTME: Provides the idempotency key that makes a terminal deletion safe to retry

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};

use crate::repositories::RepositoryError;

/// Outcome recorded for a completed service deletion request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccountDeletionOutcome {
    /// The account existed and was deleted by this request.
    Deleted,
    /// The account was already gone when this request ran.
    AlreadyAbsent,
}

impl ServiceAccountDeletionOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::AlreadyAbsent => "already_absent",
        }
    }
}

/// A completed deletion to record.
#[derive(Debug, Clone)]
pub struct ServiceAccountDeletionRecord {
    pub deletion_request_id: String,
    pub tenant_id: i64,
    pub user_pubkey: String,
    pub outcome: ServiceAccountDeletionOutcome,
    pub teams_removed: i32,
    pub oauth_authorizations_deleted: i32,
    pub bunkers_notified: i32,
}

/// A deletion that has already completed.
#[derive(Debug, Clone, FromRow)]
pub struct ServiceAccountDeletionRow {
    pub deletion_request_id: String,
    pub tenant_id: i64,
    pub user_pubkey: String,
    pub outcome: String,
    pub teams_removed: i32,
    pub oauth_authorizations_deleted: i32,
    pub bunkers_notified: i32,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ServiceAccountDeletionRepository {
    pool: PgPool,
}

impl ServiceAccountDeletionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Look up a previously completed request.
    ///
    /// Keyed on the request id alone, deliberately: the caller compares the
    /// stored tenant and pubkey against what it was asked for, so a request id
    /// replayed against a different account is caught rather than silently
    /// missing the record and deleting a second account.
    pub async fn find(
        &self,
        deletion_request_id: &str,
    ) -> Result<Option<ServiceAccountDeletionRow>, RepositoryError> {
        sqlx::query_as::<_, ServiceAccountDeletionRow>(
            "SELECT
                deletion_request_id,
                tenant_id,
                user_pubkey,
                outcome,
                teams_removed,
                oauth_authorizations_deleted,
                bunkers_notified,
                completed_at
             FROM service_account_deletions
             WHERE deletion_request_id = $1",
        )
        .bind(deletion_request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Record a completed deletion inside the caller's transaction.
    ///
    /// This has to share the deletion's transaction. Written separately, a crash
    /// between the two commits would leave an account deleted with no record
    /// that the request completed, and the coordinator's retry would have no way
    /// to tell that from a request that never ran.
    ///
    /// Returns [`RepositoryError::Duplicate`] when the request id is already
    /// recorded, which is how a concurrent replay of the same request loses the
    /// race rather than double-recording.
    pub async fn record_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        record: ServiceAccountDeletionRecord,
    ) -> Result<ServiceAccountDeletionRow, RepositoryError> {
        sqlx::query_as::<_, ServiceAccountDeletionRow>(
            "INSERT INTO service_account_deletions (
                deletion_request_id,
                tenant_id,
                user_pubkey,
                outcome,
                teams_removed,
                oauth_authorizations_deleted,
                bunkers_notified
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING
                deletion_request_id,
                tenant_id,
                user_pubkey,
                outcome,
                teams_removed,
                oauth_authorizations_deleted,
                bunkers_notified,
                completed_at",
        )
        .bind(record.deletion_request_id)
        .bind(record.tenant_id)
        .bind(record.user_pubkey)
        .bind(record.outcome.as_str())
        .bind(record.teams_removed)
        .bind(record.oauth_authorizations_deleted)
        .bind(record.bunkers_notified)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
    }
}
