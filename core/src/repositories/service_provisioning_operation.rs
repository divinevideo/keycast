// ABOUTME: Durable idempotency records for service-requested account provisioning
// ABOUTME: Serializes creation and replay without retaining mutable account attributes

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};

use crate::repositories::RepositoryError;

/// Conservative policy marker only. Production purging remains gated by
/// support-trust-safety#204 because deleting a still-replayable operation could
/// permit a second account to be created.
pub const PROVISIONING_OPERATION_RETENTION_DAYS: i64 = 730;

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
    ) -> Result<Option<ServiceProvisioningOperationRow>, RepositoryError> {
        Self::find_with_executor(&self.pool, operation_id).await
    }

    pub async fn find_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        operation_id: &str,
    ) -> Result<Option<ServiceProvisioningOperationRow>, RepositoryError> {
        Self::find_with_executor(&mut **tx, operation_id).await
    }

    async fn find_with_executor<'e, E>(
        executor: E,
        operation_id: &str,
    ) -> Result<Option<ServiceProvisioningOperationRow>, RepositoryError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query_as::<_, ServiceProvisioningOperationRow>(
            "SELECT provisioning_operation_id, tenant_id, request_fingerprint,
                    user_pubkey, outcome, created_at
             FROM service_provisioning_operations
             WHERE provisioning_operation_id = $1",
        )
        .bind(operation_id)
        .fetch_optional(executor)
        .await
        .map_err(Into::into)
    }

    /// Serialize all work for one operation id using a transaction-scoped lock.
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
                       user_pubkey, outcome, created_at",
        )
        .bind(record.provisioning_operation_id)
        .bind(record.tenant_id)
        .bind(record.request_fingerprint)
        .bind(record.user_pubkey)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
    }
}
