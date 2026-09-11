// ABOUTME: Durable idempotency records for service-requested account provisioning
// ABOUTME: Preserves replay safety after deleted-account detail is compacted

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};

use crate::{
    repositories::{RepositoryError, RetentionCompactionStatus},
    retention::{DigestPurpose, RetentionDigestKeyring},
};

const RETENTION_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct ServiceProvisioningOperationRecord {
    pub provisioning_operation_id: String,
    pub tenant_id: i64,
    pub request_fingerprint: String,
    pub user_pubkey: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct ServiceProvisioningOperationRow {
    pub provisioning_operation_id: String,
    pub tenant_id: i64,
    pub request_fingerprint: String,
    pub user_pubkey: String,
    pub outcome: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ServiceProvisioningOperationTombstone {
    pub provisioning_operation_id: String,
    pub tenant_id: i64,
    pub request_fingerprint_digest: Vec<u8>,
    pub binding_digest: Vec<u8>,
    pub digest_key_version: i32,
    pub outcome: String,
    pub completed_at: DateTime<Utc>,
    pub compacted_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ServiceProvisioningOperationReplay {
    Complete(ServiceProvisioningOperationRow),
    Compacted(ServiceProvisioningOperationTombstone),
}

#[derive(Debug, Clone)]
pub struct ProvisioningCompactionAcknowledgement {
    pub provisioning_operation_id: String,
    pub status: RetentionCompactionStatus,
}

#[derive(Debug, FromRow)]
struct ReplayQueryRow {
    representation: String,
    provisioning_operation_id: String,
    tenant_id: i64,
    request_fingerprint: Option<String>,
    user_pubkey: Option<String>,
    outcome: String,
    created_at: Option<DateTime<Utc>>,
    deleted_at: Option<DateTime<Utc>>,
    request_fingerprint_digest: Option<Vec<u8>>,
    binding_digest: Option<Vec<u8>>,
    digest_key_version: Option<i32>,
    completed_at: Option<DateTime<Utc>>,
    compacted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ServiceProvisioningOperationRepository {
    pool: PgPool,
}

impl ServiceProvisioningOperationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find(
        &self,
        operation_id: &str,
    ) -> Result<Option<ServiceProvisioningOperationReplay>, RepositoryError> {
        Self::find_with_executor(&self.pool, operation_id).await
    }

    pub async fn find_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        operation_id: &str,
    ) -> Result<Option<ServiceProvisioningOperationReplay>, RepositoryError> {
        Self::find_with_executor(&mut **tx, operation_id).await
    }

    async fn find_with_executor<'e, E>(
        executor: E,
        operation_id: &str,
    ) -> Result<Option<ServiceProvisioningOperationReplay>, RepositoryError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let row = sqlx::query_as::<_, ReplayQueryRow>(
            "SELECT 'complete'::TEXT AS representation,
                    provisioning_operation_id, tenant_id, request_fingerprint,
                    user_pubkey, outcome, created_at, deleted_at,
                    NULL::BYTEA AS request_fingerprint_digest,
                    NULL::BYTEA AS binding_digest,
                    NULL::INTEGER AS digest_key_version,
                    NULL::TIMESTAMPTZ AS completed_at,
                    NULL::TIMESTAMPTZ AS compacted_at
             FROM service_provisioning_operations
             WHERE provisioning_operation_id = $1
             UNION ALL
             SELECT 'compacted'::TEXT AS representation,
                    provisioning_operation_id, tenant_id,
                    NULL::CHAR(64), NULL::CHAR(64), outcome,
                    NULL::TIMESTAMPTZ, NULL::TIMESTAMPTZ,
                    request_fingerprint_digest, binding_digest, digest_key_version,
                    completed_at, compacted_at
             FROM service_provisioning_operation_tombstones
             WHERE provisioning_operation_id = $1
             LIMIT 1",
        )
        .bind(operation_id)
        .fetch_optional(executor)
        .await
        .map_err(RepositoryError::from)?;
        row.map(Self::decode_replay).transpose()
    }

    fn decode_replay(
        row: ReplayQueryRow,
    ) -> Result<ServiceProvisioningOperationReplay, RepositoryError> {
        let missing = |field: &str| {
            RepositoryError::Integrity(format!("provisioning replay missing {field}"))
        };
        match row.representation.as_str() {
            "complete" => Ok(ServiceProvisioningOperationReplay::Complete(
                ServiceProvisioningOperationRow {
                    provisioning_operation_id: row.provisioning_operation_id,
                    tenant_id: row.tenant_id,
                    request_fingerprint: row
                        .request_fingerprint
                        .ok_or_else(|| missing("fingerprint"))?,
                    user_pubkey: row.user_pubkey.ok_or_else(|| missing("pubkey"))?,
                    outcome: row.outcome,
                    created_at: row.created_at.ok_or_else(|| missing("creation time"))?,
                    deleted_at: row.deleted_at,
                },
            )),
            "compacted" => Ok(ServiceProvisioningOperationReplay::Compacted(
                ServiceProvisioningOperationTombstone {
                    provisioning_operation_id: row.provisioning_operation_id,
                    tenant_id: row.tenant_id,
                    request_fingerprint_digest: row
                        .request_fingerprint_digest
                        .ok_or_else(|| missing("fingerprint digest"))?,
                    binding_digest: row
                        .binding_digest
                        .ok_or_else(|| missing("binding digest"))?,
                    digest_key_version: row
                        .digest_key_version
                        .ok_or_else(|| missing("key version"))?,
                    outcome: row.outcome,
                    completed_at: row.completed_at.ok_or_else(|| missing("completion time"))?,
                    compacted_at: row.compacted_at.ok_or_else(|| missing("compaction time"))?,
                },
            )),
            _ => Err(RepositoryError::Integrity(
                "unknown provisioning replay representation".to_string(),
            )),
        }
    }

    pub async fn lock_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        operation_id: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(operation_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub async fn record_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        record: ServiceProvisioningOperationRecord,
    ) -> Result<ServiceProvisioningOperationRow, RepositoryError> {
        sqlx::query_as::<_, ServiceProvisioningOperationRow>(
            "INSERT INTO service_provisioning_operations
                (provisioning_operation_id, tenant_id, request_fingerprint, user_pubkey, outcome)
             VALUES ($1, $2, $3, $4, 'created')
             RETURNING provisioning_operation_id, tenant_id, request_fingerprint,
                       user_pubkey, outcome, created_at, deleted_at",
        )
        .bind(record.provisioning_operation_id)
        .bind(record.tenant_id)
        .bind(record.request_fingerprint)
        .bind(record.user_pubkey)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
    }

    pub async fn mark_account_deleted_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: i64,
        user_pubkey: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<u64, RepositoryError> {
        sqlx::query(
            "UPDATE service_provisioning_operations
             SET deleted_at = COALESCE(deleted_at, $3)
             WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .bind(deleted_at)
        .execute(&mut **tx)
        .await
        .map(|result| result.rows_affected())
        .map_err(Into::into)
    }

    pub async fn compact_for_account(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
        keys: &RetentionDigestKeyring,
        as_of: DateTime<Utc>,
    ) -> Result<Vec<ProvisioningCompactionAcknowledgement>, RepositoryError> {
        let tenant_bytes = tenant_id.to_be_bytes();
        let configured_versions = keys.versions();
        let has_unverifiable_tombstones: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM service_provisioning_operation_tombstones
                WHERE tenant_id = $1 AND NOT (digest_key_version = ANY($2))
             )",
        )
        .bind(tenant_id)
        .bind(&configured_versions)
        .fetch_one(&self.pool)
        .await?;
        if has_unverifiable_tombstones {
            return Err(RepositoryError::Integrity(
                "retention digest keyring cannot verify every provisioning tombstone".to_string(),
            ));
        }
        let binding_digests = keys.digests_for_all_versions(
            DigestPurpose::ProvisioningBinding,
            &[&tenant_bytes, user_pubkey.as_bytes()],
        );
        let already: Vec<String> = sqlx::query_scalar(
            "SELECT provisioning_operation_id
             FROM service_provisioning_operation_tombstones
             WHERE tenant_id = $1 AND binding_digest = ANY($2)
             ORDER BY provisioning_operation_id",
        )
        .bind(tenant_id)
        .bind(&binding_digests)
        .fetch_all(&self.pool)
        .await?;
        let operation_ids: Vec<String> = sqlx::query_scalar(
            "SELECT provisioning_operation_id
             FROM service_provisioning_operations
             WHERE tenant_id = $1 AND user_pubkey = $2
             ORDER BY provisioning_operation_id",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_all(&self.pool)
        .await?;

        let mut acknowledgements = already
            .into_iter()
            .map(|id| ProvisioningCompactionAcknowledgement {
                provisioning_operation_id: id,
                status: RetentionCompactionStatus::AlreadyCompacted,
            })
            .collect::<Vec<_>>();
        for id in operation_ids {
            let status = self
                .compact_one(&id, tenant_id, user_pubkey, keys, as_of)
                .await?;
            acknowledgements.push(ProvisioningCompactionAcknowledgement {
                provisioning_operation_id: id,
                status,
            });
        }
        acknowledgements.sort_by(|a, b| {
            a.provisioning_operation_id
                .cmp(&b.provisioning_operation_id)
        });
        acknowledgements
            .dedup_by(|a, b| a.provisioning_operation_id == b.provisioning_operation_id);
        Ok(acknowledgements)
    }

    async fn compact_one(
        &self,
        operation_id: &str,
        tenant_id: i64,
        user_pubkey: &str,
        keys: &RetentionDigestKeyring,
        as_of: DateTime<Utc>,
    ) -> Result<RetentionCompactionStatus, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_in_tx(&mut tx, operation_id).await?;
        let row = sqlx::query_as::<_, ServiceProvisioningOperationRow>(
            "SELECT provisioning_operation_id, tenant_id, request_fingerprint,
                    user_pubkey, outcome, created_at, deleted_at
             FROM service_provisioning_operations
             WHERE provisioning_operation_id = $1 FOR UPDATE",
        )
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::AlreadyCompacted);
        };
        if row.tenant_id != tenant_id || row.user_pubkey != user_pubkey {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Conflict);
        }
        let Some(deleted_at) = row.deleted_at else {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Ineligible);
        };
        if deleted_at + chrono::Duration::days(RETENTION_DAYS) > as_of {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Ineligible);
        }
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM retention_legal_holds
             WHERE tenant_id = $1 AND scope_kind = 'account_binding'
               AND scope_key = $2 AND started_at <= $3 AND released_at IS NULL
               AND (expires_at IS NULL OR expires_at > $3))",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .bind(as_of)
        .fetch_one(&mut *tx)
        .await?;
        if held {
            tx.commit().await?;
            return Ok(RetentionCompactionStatus::Held);
        }

        let tenant_bytes = tenant_id.to_be_bytes();
        let fingerprint_digest = keys.digest(
            DigestPurpose::ProvisioningFingerprint,
            &[
                &tenant_bytes,
                operation_id.as_bytes(),
                row.request_fingerprint.trim().as_bytes(),
            ],
        );
        let binding_digest = keys.digest(
            DigestPurpose::ProvisioningBinding,
            &[&tenant_bytes, user_pubkey.as_bytes()],
        );
        sqlx::query(
            "INSERT INTO service_provisioning_operation_tombstones
                (provisioning_operation_id, tenant_id, request_fingerprint_digest,
                 binding_digest, digest_key_version, completed_at, compacted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(operation_id)
        .bind(tenant_id)
        .bind(fingerprint_digest)
        .bind(binding_digest)
        .bind(keys.current_version())
        .bind(deleted_at)
        .bind(as_of)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM service_provisioning_operations WHERE provisioning_operation_id = $1",
        )
        .bind(operation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(RetentionCompactionStatus::Compacted)
    }
}

pub fn verify_provisioning_fingerprint(
    keys: &RetentionDigestKeyring,
    tombstone: &ServiceProvisioningOperationTombstone,
    tenant_id: i64,
    fingerprint: &str,
) -> Result<bool, RepositoryError> {
    let tenant_bytes = tenant_id.to_be_bytes();
    keys.verify(
        tombstone.digest_key_version,
        DigestPurpose::ProvisioningFingerprint,
        &[
            &tenant_bytes,
            tombstone.provisioning_operation_id.as_bytes(),
            fingerprint.as_bytes(),
        ],
        &tombstone.request_fingerprint_digest,
    )
    .map_err(|error| RepositoryError::Integrity(error.to_string()))
}
