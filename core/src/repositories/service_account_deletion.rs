// ABOUTME: Repository for durable service-requested account-deletion records
// ABOUTME: Provides the idempotency key that makes a terminal deletion safe to retry

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};

use crate::{
    repositories::RepositoryError,
    retention::{DigestPurpose, RetentionDigestKeyring},
};

const RETENTION_DAYS: i64 = 30;

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

#[derive(Debug, Clone, FromRow)]
pub struct ServiceAccountDeletionTombstone {
    pub deletion_request_id: String,
    pub tenant_id: i64,
    pub outcome: String,
    pub completed_at: DateTime<Utc>,
    pub binding_digest: Vec<u8>,
    pub digest_key_version: i32,
    pub compacted_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ServiceAccountDeletionReplay {
    Complete(ServiceAccountDeletionRow),
    Compacted(ServiceAccountDeletionTombstone),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionCompactionStatus {
    Compacted,
    AlreadyCompacted,
    Ineligible,
    Held,
    NotFound,
    Conflict,
}

#[derive(Debug, FromRow)]
struct DeletionReplayQueryRow {
    representation: String,
    deletion_request_id: String,
    tenant_id: i64,
    user_pubkey: Option<String>,
    outcome: String,
    teams_removed: Option<i32>,
    oauth_authorizations_deleted: Option<i32>,
    bunkers_notified: Option<i32>,
    completed_at: DateTime<Utc>,
    binding_digest: Option<Vec<u8>>,
    digest_key_version: Option<i32>,
    compacted_at: Option<DateTime<Utc>>,
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
    ) -> Result<Option<ServiceAccountDeletionReplay>, RepositoryError> {
        let row = sqlx::query_as::<_, DeletionReplayQueryRow>(
            "SELECT 'complete'::TEXT AS representation,
                    deletion_request_id, tenant_id, user_pubkey, outcome,
                    teams_removed, oauth_authorizations_deleted, bunkers_notified,
                    completed_at, NULL::BYTEA AS binding_digest,
                    NULL::INTEGER AS digest_key_version,
                    NULL::TIMESTAMPTZ AS compacted_at
             FROM service_account_deletions
             WHERE deletion_request_id = $1
             UNION ALL
             SELECT 'compacted'::TEXT AS representation,
                    deletion_request_id, tenant_id, NULL::TEXT AS user_pubkey, outcome,
                    NULL::INTEGER AS teams_removed,
                    NULL::INTEGER AS oauth_authorizations_deleted,
                    NULL::INTEGER AS bunkers_notified,
                    completed_at, binding_digest, digest_key_version, compacted_at
             FROM service_account_deletion_tombstones
             WHERE deletion_request_id = $1
             LIMIT 1",
        )
        .bind(deletion_request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(RepositoryError::from)?;
        row.map(Self::decode_replay).transpose()
    }

    fn decode_replay(
        row: DeletionReplayQueryRow,
    ) -> Result<ServiceAccountDeletionReplay, RepositoryError> {
        match row.representation.as_str() {
            "complete" => Ok(ServiceAccountDeletionReplay::Complete(
                ServiceAccountDeletionRow {
                    deletion_request_id: row.deletion_request_id,
                    tenant_id: row.tenant_id,
                    user_pubkey: row.user_pubkey.ok_or_else(|| {
                        RepositoryError::Integrity("complete deletion missing pubkey".to_string())
                    })?,
                    outcome: row.outcome,
                    teams_removed: row.teams_removed.ok_or_else(|| {
                        RepositoryError::Integrity("complete deletion missing counts".to_string())
                    })?,
                    oauth_authorizations_deleted: row.oauth_authorizations_deleted.ok_or_else(
                        || {
                            RepositoryError::Integrity(
                                "complete deletion missing counts".to_string(),
                            )
                        },
                    )?,
                    bunkers_notified: row.bunkers_notified.ok_or_else(|| {
                        RepositoryError::Integrity("complete deletion missing counts".to_string())
                    })?,
                    completed_at: row.completed_at,
                },
            )),
            "compacted" => Ok(ServiceAccountDeletionReplay::Compacted(
                ServiceAccountDeletionTombstone {
                    deletion_request_id: row.deletion_request_id,
                    tenant_id: row.tenant_id,
                    outcome: row.outcome,
                    completed_at: row.completed_at,
                    binding_digest: row.binding_digest.ok_or_else(|| {
                        RepositoryError::Integrity("deletion tombstone missing digest".to_string())
                    })?,
                    digest_key_version: row.digest_key_version.ok_or_else(|| {
                        RepositoryError::Integrity(
                            "deletion tombstone missing key version".to_string(),
                        )
                    })?,
                    compacted_at: row.compacted_at.ok_or_else(|| {
                        RepositoryError::Integrity(
                            "deletion tombstone missing timestamp".to_string(),
                        )
                    })?,
                },
            )),
            _ => Err(RepositoryError::Integrity(
                "unknown deletion replay representation".to_string(),
            )),
        }
    }

    pub async fn compact(
        &self,
        deletion_request_id: &str,
        tenant_id: i64,
        user_pubkey: &str,
        keys: &RetentionDigestKeyring,
        as_of: DateTime<Utc>,
    ) -> Result<RetentionCompactionStatus, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("deletion:{deletion_request_id}"))
            .execute(&mut *tx)
            .await?;

        if let Some(tombstone) = sqlx::query_as::<_, ServiceAccountDeletionTombstone>(
            "SELECT deletion_request_id, tenant_id, outcome, completed_at,
                    binding_digest, digest_key_version, compacted_at
             FROM service_account_deletion_tombstones
             WHERE deletion_request_id = $1",
        )
        .bind(deletion_request_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let matches = verify_deletion_binding(keys, &tombstone, tenant_id, user_pubkey)?;
            tx.commit().await?;
            return Ok(if matches {
                RetentionCompactionStatus::AlreadyCompacted
            } else {
                RetentionCompactionStatus::Conflict
            });
        }

        let row = sqlx::query_as::<_, ServiceAccountDeletionRow>(
            "SELECT deletion_request_id, tenant_id, user_pubkey, outcome,
                    teams_removed, oauth_authorizations_deleted, bunkers_notified, completed_at
             FROM service_account_deletions
             WHERE deletion_request_id = $1
             FOR UPDATE",
        )
        .bind(deletion_request_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::NotFound);
        };
        if row.tenant_id != tenant_id || row.user_pubkey != user_pubkey {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Conflict);
        }
        if row.completed_at + chrono::Duration::days(RETENTION_DAYS) > as_of {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Ineligible);
        }
        if legal_hold_exists(
            &mut tx,
            tenant_id,
            "deletion_request",
            deletion_request_id,
            as_of,
        )
        .await?
            || legal_hold_exists(&mut tx, tenant_id, "account_binding", user_pubkey, as_of).await?
        {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Held);
        }

        let tenant_bytes = tenant_id.to_be_bytes();
        let digest = keys.digest(
            DigestPurpose::DeletionBinding,
            &[
                &tenant_bytes,
                deletion_request_id.as_bytes(),
                user_pubkey.as_bytes(),
            ],
        );
        sqlx::query(
            "INSERT INTO service_account_deletion_tombstones
                (deletion_request_id, tenant_id, outcome, completed_at,
                 binding_digest, digest_key_version, compacted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&row.deletion_request_id)
        .bind(row.tenant_id)
        .bind(&row.outcome)
        .bind(row.completed_at)
        .bind(digest)
        .bind(keys.current_version())
        .bind(as_of)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM service_account_deletions WHERE deletion_request_id = $1")
            .bind(deletion_request_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(RetentionCompactionStatus::Compacted)
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

pub fn verify_deletion_binding(
    keys: &RetentionDigestKeyring,
    tombstone: &ServiceAccountDeletionTombstone,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<bool, RepositoryError> {
    let tenant_bytes = tenant_id.to_be_bytes();
    keys.verify(
        tombstone.digest_key_version,
        DigestPurpose::DeletionBinding,
        &[
            &tenant_bytes,
            tombstone.deletion_request_id.as_bytes(),
            user_pubkey.as_bytes(),
        ],
        &tombstone.binding_digest,
    )
    .map_err(|error| RepositoryError::Integrity(error.to_string()))
}

async fn legal_hold_exists(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    scope_kind: &str,
    scope_key: &str,
    as_of: DateTime<Utc>,
) -> Result<bool, RepositoryError> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM retention_legal_holds
            WHERE tenant_id = $1 AND scope_kind = $2 AND scope_key = $3
              AND started_at <= $4 AND released_at IS NULL
              AND (expires_at IS NULL OR expires_at > $4)
         )",
    )
    .bind(tenant_id)
    .bind(scope_kind)
    .bind(scope_key)
    .bind(as_of)
    .fetch_one(&mut **tx)
    .await
    .map_err(Into::into)
}
