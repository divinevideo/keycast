// ABOUTME: Repository for durable admin-action audit events
// ABOUTME: Append-only forensic log capturing actor, action, target, and metadata

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use crate::repositories::RepositoryError;

#[derive(Debug, Clone)]
pub struct AdminAuditEventRecord {
    pub tenant_id: i64,
    pub actor_pubkey: String,
    pub action: String,
    pub target_resource_type: String,
    pub target_resource_id: Option<String>,
    pub target_client_id: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone, FromRow)]
pub struct AdminAuditEventRow {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub tenant_id: i64,
    pub actor_pubkey: String,
    pub action: String,
    pub target_resource_type: String,
    pub target_resource_id: Option<String>,
    pub target_client_id: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone)]
pub struct AdminAuditEventRepository {
    pool: PgPool,
}

impl AdminAuditEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(
        &self,
        record: AdminAuditEventRecord,
    ) -> Result<AdminAuditEventRow, RepositoryError> {
        sqlx::query_as::<_, AdminAuditEventRow>(
            "INSERT INTO admin_audit_events (
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING
                id,
                occurred_at,
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json",
        )
        .bind(record.tenant_id)
        .bind(record.actor_pubkey)
        .bind(record.action)
        .bind(record.target_resource_type)
        .bind(record.target_resource_id)
        .bind(record.target_client_id)
        .bind(record.metadata_json)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_recent(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<AdminAuditEventRow>, RepositoryError> {
        sqlx::query_as::<_, AdminAuditEventRow>(
            "SELECT
                id,
                occurred_at,
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json
             FROM admin_audit_events
             WHERE tenant_id = $1
             ORDER BY occurred_at DESC, id DESC
             LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Delete one bounded batch of expired service-deletion audit rows.
    /// Hold checks and deletion share one statement and one database snapshot.
    pub async fn delete_expired_deletion_events(
        &self,
        as_of: DateTime<Utc>,
        batch_size: i64,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "WITH expired AS (
                SELECT event.id
                FROM admin_audit_events AS event
                WHERE event.action = 'service_account_deletion'
                  AND event.occurred_at <= $1 - INTERVAL '1 year'
                  AND NOT EXISTS (
                    SELECT 1 FROM retention_legal_holds AS hold
                    WHERE hold.tenant_id = event.tenant_id
                      AND hold.started_at <= $1
                      AND hold.released_at IS NULL
                      AND (hold.expires_at IS NULL OR hold.expires_at > $1)
                      AND (
                        (hold.scope_kind = 'account_binding'
                         AND hold.scope_key = event.target_resource_id)
                        OR
                        (hold.scope_kind = 'deletion_request'
                         AND hold.scope_key = event.metadata_json->>'deletion_request_id')
                      )
                  )
                ORDER BY event.occurred_at, event.id
                LIMIT $2
             )
             DELETE FROM admin_audit_events
             WHERE id IN (SELECT id FROM expired)",
        )
        .bind(as_of)
        .bind(batch_size)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn count_overdue_retention_rows(
        &self,
        as_of: DateTime<Utc>,
    ) -> Result<(i64, i64), RepositoryError> {
        let deletion: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM service_account_deletions AS deletion
             WHERE deletion.completed_at < $1 - INTERVAL '31 days'
               AND NOT EXISTS (
                 SELECT 1 FROM retention_legal_holds AS hold
                 WHERE hold.tenant_id = deletion.tenant_id
                   AND hold.started_at <= $1 AND hold.released_at IS NULL
                   AND (hold.expires_at IS NULL OR hold.expires_at > $1)
                   AND ((hold.scope_kind = 'deletion_request'
                         AND hold.scope_key = deletion.deletion_request_id)
                        OR (hold.scope_kind = 'account_binding'
                            AND hold.scope_key = deletion.user_pubkey))
               )",
        )
        .bind(as_of)
        .fetch_one(&self.pool)
        .await?;
        let provisioning: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM service_provisioning_operations AS operation
             WHERE operation.deleted_at < $1 - INTERVAL '31 days'
               AND NOT EXISTS (
                 SELECT 1 FROM retention_legal_holds AS hold
                 WHERE hold.tenant_id = operation.tenant_id
                   AND hold.scope_kind = 'account_binding'
                   AND hold.scope_key = operation.user_pubkey
                   AND hold.started_at <= $1 AND hold.released_at IS NULL
                   AND (hold.expires_at IS NULL OR hold.expires_at > $1)
               )",
        )
        .bind(as_of)
        .fetch_one(&self.pool)
        .await?;
        Ok((deletion, provisioning))
    }
}
