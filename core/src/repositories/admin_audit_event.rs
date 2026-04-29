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
}
