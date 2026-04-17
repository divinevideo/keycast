// ABOUTME: Repository for engineer-facing authentication audit events
// ABOUTME: Stores append-only auth history for support and debugging workflows

use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone)]
pub struct AuthEventRecord {
    pub tenant_id: i64,
    pub request_id: String,
    pub endpoint: String,
    pub event_type: String,
    pub outcome: String,
    pub reason_code: Option<String>,
    pub http_status: Option<i32>,
    pub email: Option<String>,
    pub email_hash: String,
    pub pubkey: Option<String>,
    pub pubkey_prefix: Option<String>,
    pub client_id: Option<String>,
    pub redirect_origin: Option<String>,
    pub user_agent: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuthEventRow {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub request_id: String,
    pub tenant_id: i64,
    pub endpoint: String,
    pub event_type: String,
    pub outcome: String,
    pub reason_code: Option<String>,
    pub http_status: Option<i32>,
    pub email: Option<String>,
    pub email_hash: String,
    pub pubkey: Option<String>,
    pub pubkey_prefix: Option<String>,
    pub client_id: Option<String>,
    pub redirect_origin: Option<String>,
    pub user_agent: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone)]
pub struct AuthEventRepository {
    pool: PgPool,
}

impl AuthEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(&self, record: AuthEventRecord) -> Result<AuthEventRow, RepositoryError> {
        sqlx::query_as::<_, AuthEventRow>(
            "INSERT INTO auth_events (
                request_id,
                tenant_id,
                endpoint,
                event_type,
                outcome,
                reason_code,
                http_status,
                email,
                email_hash,
                pubkey,
                pubkey_prefix,
                client_id,
                redirect_origin,
                user_agent,
                metadata_json
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
             )
             RETURNING
                id,
                occurred_at,
                request_id,
                tenant_id,
                endpoint,
                event_type,
                outcome,
                reason_code,
                http_status,
                email,
                email_hash,
                pubkey,
                pubkey_prefix,
                client_id,
                redirect_origin,
                user_agent,
                metadata_json",
        )
        .bind(record.request_id)
        .bind(record.tenant_id)
        .bind(record.endpoint)
        .bind(record.event_type)
        .bind(record.outcome)
        .bind(record.reason_code)
        .bind(record.http_status)
        .bind(record.email)
        .bind(record.email_hash)
        .bind(record.pubkey)
        .bind(record.pubkey_prefix)
        .bind(record.client_id)
        .bind(record.redirect_origin)
        .bind(record.user_agent)
        .bind(record.metadata_json)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_recent_by_email(
        &self,
        tenant_id: i64,
        email: &str,
        limit: i64,
    ) -> Result<Vec<AuthEventRow>, RepositoryError> {
        sqlx::query_as::<_, AuthEventRow>(
            "SELECT
                id,
                occurred_at,
                request_id,
                tenant_id,
                endpoint,
                event_type,
                outcome,
                reason_code,
                http_status,
                email,
                email_hash,
                pubkey,
                pubkey_prefix,
                client_id,
                redirect_origin,
                user_agent,
                metadata_json
             FROM auth_events
             WHERE tenant_id = $1 AND email = $2
             ORDER BY occurred_at DESC, id DESC
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_recent_by_pubkey(
        &self,
        tenant_id: i64,
        pubkey: &str,
        limit: i64,
    ) -> Result<Vec<AuthEventRow>, RepositoryError> {
        sqlx::query_as::<_, AuthEventRow>(
            "SELECT
                id,
                occurred_at,
                request_id,
                tenant_id,
                endpoint,
                event_type,
                outcome,
                reason_code,
                http_status,
                email,
                email_hash,
                pubkey,
                pubkey_prefix,
                client_id,
                redirect_origin,
                user_agent,
                metadata_json
             FROM auth_events
             WHERE tenant_id = $1 AND pubkey = $2
             ORDER BY occurred_at DESC, id DESC
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(pubkey)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_recent_by_request_id(
        &self,
        tenant_id: i64,
        request_id: &str,
        limit: i64,
    ) -> Result<Vec<AuthEventRow>, RepositoryError> {
        sqlx::query_as::<_, AuthEventRow>(
            "SELECT
                id,
                occurred_at,
                request_id,
                tenant_id,
                endpoint,
                event_type,
                outcome,
                reason_code,
                http_status,
                email,
                email_hash,
                pubkey,
                pubkey_prefix,
                client_id,
                redirect_origin,
                user_agent,
                metadata_json
             FROM auth_events
             WHERE tenant_id = $1 AND request_id = $2
             ORDER BY occurred_at DESC, id DESC
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn delete_older_than(&self, cutoff: DateTime<Utc>) -> Result<u64, RepositoryError> {
        let result = sqlx::query("DELETE FROM auth_events WHERE occurred_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
