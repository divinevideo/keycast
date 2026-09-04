// ABOUTME: Service-token endpoints letting the marketing sync service read consent, write back the
// ABOUTME: suppression floor, and drain deletion and email-change rows. keycast never calls HubSpot.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admin::authorize_service_token;
use super::routes::AuthState;
use crate::api::error::ApiResult;

/// Upper bound on a page. Matches the documented 1,000-row contract on batch-lookup.
const MAX_LIMIT: i64 = 1000;
const DEFAULT_LIMIT: i64 = 500;

// ---------------------------------------------------------------------------------------------
// Consent reads
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ConsentPageQuery {
    /// Cursor: the last `updated_at` processed. Paired with `since_pubkey` to break ties, because
    /// two accounts can share a timestamp and a timestamp-only cursor would skip or loop.
    pub since: Option<DateTime<Utc>>,
    pub since_pubkey: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ConsentRecord {
    pub pubkey: String,
    pub email: Option<String>,
    pub consent: String,
    pub consent_at: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub app_version: Option<String>,
    /// NULL means never observed. Not the same as "not opted out".
    pub global_optout: Option<bool>,
    pub optout_observed_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ConsentCursor {
    pub since: DateTime<Utc>,
    pub since_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct ConsentPage {
    pub results: Vec<ConsentRecord>,
    /// Absent when the page was not full, meaning the caller has reached the end.
    pub next: Option<ConsentCursor>,
}

pub async fn list_consents(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<ConsentPageQuery>,
) -> ApiResult<Json<ConsentPage>> {
    authorize_service_token(&headers)?;

    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let rows: Vec<ConsentRecord> = sqlx::query_as(
        "SELECT pubkey, email,
                email_marketing_consent             AS consent,
                email_marketing_consent_at          AS consent_at,
                email_marketing_consent_source      AS source,
                email_marketing_consent_app_version AS app_version,
                email_marketing_global_optout       AS global_optout,
                email_marketing_optout_observed_at  AS optout_observed_at,
                updated_at
         FROM users
         WHERE tenant_id = $4
           AND ($1::timestamptz IS NULL OR (updated_at, pubkey) > ($1, $2))
         ORDER BY updated_at, pubkey
         LIMIT $3",
    )
    .bind(query.since)
    .bind(query.since_pubkey.unwrap_or_default())
    .bind(limit)
    .bind(tenant.0.id)
    .fetch_all(&auth_state.state.db)
    .await?;

    let next = if rows.len() as i64 == limit {
        rows.last().map(|r| ConsentCursor {
            since: r.updated_at,
            since_pubkey: r.pubkey.clone(),
        })
    } else {
        None
    };

    Ok(Json(ConsentPage {
        results: rows,
        next,
    }))
}

// ---------------------------------------------------------------------------------------------
// Suppression floor
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Observation {
    pub pubkey: String,
    pub global_optout: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ObservationsRequest {
    pub observations: Vec<Observation>,
}

#[derive(Debug, Serialize)]
pub struct ObservationsResponse {
    pub updated: u64,
}

/// Writes only the suppression floor.
///
/// The consent event columns are deliberately absent from this statement. Immutability is enforced
/// by there being no code path that writes them, rather than by anyone remembering the rule.
pub async fn record_observations(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<ObservationsRequest>,
) -> ApiResult<Json<ObservationsResponse>> {
    authorize_service_token(&headers)?;

    let mut updated = 0u64;
    for obs in req.observations {
        // Idempotent: an identical observation changes nothing, so replaying a batch after a crash
        // does not churn the observation timestamp.
        let result = sqlx::query(
            "UPDATE users
             SET email_marketing_global_optout = $2,
                 email_marketing_optout_observed_at = $3
             WHERE pubkey = $1 AND tenant_id = $4
               AND email_marketing_global_optout IS DISTINCT FROM $2",
        )
        .bind(&obs.pubkey)
        .bind(obs.global_optout)
        .bind(obs.observed_at)
        .bind(tenant.0.id)
        .execute(&auth_state.state.db)
        .await?;
        updated += result.rows_affected();
    }

    Ok(Json(ObservationsResponse { updated }))
}

// ---------------------------------------------------------------------------------------------
// Deletion tombstones and email changes
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IdPageQuery {
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AckRequest {
    pub ids: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct AckResponse {
    pub cleared: u64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DeletionRecord {
    pub id: i64,
    pub email: String,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct DeletionPage {
    pub results: Vec<DeletionRecord>,
}

pub async fn list_deletions(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<IdPageQuery>,
) -> ApiResult<Json<DeletionPage>> {
    authorize_service_token(&headers)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let results: Vec<DeletionRecord> = sqlx::query_as(
        "SELECT id, email, deleted_at FROM email_marketing_deletions
         WHERE tenant_id = $3 AND ($1::bigint IS NULL OR id > $1)
         ORDER BY id LIMIT $2",
    )
    .bind(query.since)
    .bind(limit)
    .bind(tenant.0.id)
    .fetch_all(&auth_state.state.db)
    .await?;

    Ok(Json(DeletionPage { results }))
}

/// Clearing is a separate call from listing so that a sync service which crashes after reading but
/// before acting replays the deletion instead of dropping it. Dropping one means continuing to
/// email somebody who deleted their account.
pub async fn ack_deletions(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> ApiResult<Json<AckResponse>> {
    authorize_service_token(&headers)?;

    let result =
        sqlx::query("DELETE FROM email_marketing_deletions WHERE id = ANY($1) AND tenant_id = $2")
            .bind(&req.ids)
            .bind(tenant.0.id)
            .execute(&auth_state.state.db)
            .await?;

    Ok(Json(AckResponse {
        cleared: result.rows_affected(),
    }))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EmailChangeRecord {
    pub id: i64,
    pub pubkey: String,
    pub old_email: String,
    pub new_email: String,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EmailChangePage {
    pub results: Vec<EmailChangeRecord>,
}

pub async fn list_email_changes(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<IdPageQuery>,
) -> ApiResult<Json<EmailChangePage>> {
    authorize_service_token(&headers)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let results: Vec<EmailChangeRecord> = sqlx::query_as(
        "SELECT id, pubkey, old_email, new_email, changed_at FROM email_marketing_email_changes
         WHERE tenant_id = $3 AND ($1::bigint IS NULL OR id > $1)
         ORDER BY id LIMIT $2",
    )
    .bind(query.since)
    .bind(limit)
    .bind(tenant.0.id)
    .fetch_all(&auth_state.state.db)
    .await?;

    Ok(Json(EmailChangePage { results }))
}

pub async fn ack_email_changes(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> ApiResult<Json<AckResponse>> {
    authorize_service_token(&headers)?;

    let result = sqlx::query(
        "DELETE FROM email_marketing_email_changes WHERE id = ANY($1) AND tenant_id = $2",
    )
    .bind(&req.ids)
    .bind(tenant.0.id)
    .execute(&auth_state.state.db)
    .await?;

    Ok(Json(AckResponse {
        cleared: result.rows_affected(),
    }))
}
