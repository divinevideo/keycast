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
    /// Cursor: the last consent timestamp processed. Paired with `since_pubkey` to break ties,
    /// because two accounts can consent in the same instant and a timestamp-only cursor would skip
    /// or loop.
    ///
    /// Deliberately the CONSENT time, not `updated_at`. A consent answer is immutable, so each one
    /// is read exactly once. Ordering on `updated_at` meant any unrelated account change (a
    /// password reset, a profile edit) re-triggered a subscribe, which silently reversed a granular
    /// unsubscribe the person had made in the meantime.
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

    // Only rows carrying a consent event. An account nobody asked has nothing to sync and would
    // only be pages the caller has to read past.
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
            AND email IS NOT NULL
            AND email_marketing_consent_at IS NOT NULL
           AND ($1::timestamptz IS NULL
                OR (email_marketing_consent_at, pubkey) > ($1, $2))
         ORDER BY email_marketing_consent_at, pubkey
         LIMIT $3",
    )
    .bind(query.since)
    .bind(query.since_pubkey.unwrap_or_default())
    .bind(limit)
    .bind(tenant.0.id)
    .fetch_all(&auth_state.state.db)
    .await?;

    let next = if rows.len() as i64 == limit {
        rows.last().and_then(|r| {
            r.consent_at.map(|since| ConsentCursor {
                since,
                since_pubkey: r.pubkey.clone(),
            })
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
    /// Rows whose floor actually changed.
    pub updated: u64,
    /// Accounts that exist and were left alone. A `false` observation and an identical `true`
    /// replay both land here, and both are expected.
    pub unchanged: Vec<String>,
    /// Pubkeys with no live account in this tenant: rotated away, deleted, or a wrong-tenant
    /// caller. Reported separately because a summed row count cannot distinguish those from an
    /// ordinary no-op, and they mean something is wrong rather than nothing to do.
    pub not_found: Vec<String>,
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

    if req.observations.len() as i64 > MAX_LIMIT {
        return Err(crate::api::error::ApiError::bad_request(format!(
            "observations batch exceeds {MAX_LIMIT}"
        )));
    }
    if req.observations.is_empty() {
        return Ok(Json(ObservationsResponse {
            updated: 0,
            unchanged: Vec::new(),
            not_found: Vec::new(),
        }));
    }

    let pubkeys: Vec<String> = req.observations.iter().map(|o| o.pubkey.clone()).collect();
    let optouts: Vec<bool> = req.observations.iter().map(|o| o.global_optout).collect();
    let observed: Vec<DateTime<Utc>> = req.observations.iter().map(|o| o.observed_at).collect();

    // One set-based statement rather than a row-at-a-time loop. A thousand sequential updates each
    // acquiring from the pool is poor under transaction-mode pooling, and a summed row count cannot
    // tell the caller which input did what.
    //
    // The floor is write-once-true, not a mirror of the email platform's current flag: that platform
    // forgets an opt-out when an address changes, so a later `false` for the new contact must not
    // clear a floor already recorded. An identical `true` is a no-op, so a crash-replayed batch does
    // not churn the observation timestamp.
    //
    // Only the floor columns appear here. The consent event is absent by construction, so its
    // immutability holds because no code path can write it rather than because somebody remembers.
    //
    // An account with no email is an orphaned identity left by a key rotation. It is reported as
    // not-found rather than written to: recording somebody's opt-out against a row nothing reads
    // loses the opt-out.
    let touched: Vec<(String, bool)> = sqlx::query_as(
        "WITH input AS (
             SELECT * FROM UNNEST($1::text[], $2::bool[], $3::timestamptz[])
                 AS t(pubkey, global_optout, observed_at)
         ),
         live AS (
             SELECT i.pubkey, i.global_optout, i.observed_at
             FROM input i
             JOIN users u ON u.pubkey = i.pubkey AND u.tenant_id = $4 AND u.email IS NOT NULL
         ),
         changed AS (
             UPDATE users u
             SET email_marketing_global_optout = TRUE,
                 email_marketing_optout_observed_at = l.observed_at
             FROM live l
             WHERE u.pubkey = l.pubkey AND u.tenant_id = $4
               AND l.global_optout IS TRUE
               AND u.email_marketing_global_optout IS DISTINCT FROM TRUE
             RETURNING u.pubkey
         )
         SELECT l.pubkey, (c.pubkey IS NOT NULL) AS changed
         FROM live l LEFT JOIN changed c ON c.pubkey = l.pubkey",
    )
    .bind(&pubkeys)
    .bind(&optouts)
    .bind(&observed)
    .bind(tenant.0.id)
    .fetch_all(&auth_state.state.db)
    .await?;

    let mut updated = 0u64;
    let mut unchanged = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (pubkey, changed) in touched {
        seen.insert(pubkey.clone());
        if changed {
            updated += 1;
        } else {
            unchanged.push(pubkey);
        }
    }
    let not_found: Vec<String> = pubkeys.into_iter().filter(|p| !seen.contains(p)).collect();

    Ok(Json(ObservationsResponse {
        updated,
        unchanged,
        not_found,
    }))
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

/// Drop rows past their retention window.
///
/// `table` is one of two compile-time literals from this module, never user input, so the
/// interpolation cannot carry anything a caller controls.
async fn purge_expired(
    auth_state: &AuthState,
    table: &'static str,
    tenant_id: i64,
) -> ApiResult<()> {
    let statement = format!("DELETE FROM {table} WHERE tenant_id = $1 AND expires_at <= NOW()");
    sqlx::query(&statement)
        .bind(tenant_id)
        .execute(&auth_state.state.db)
        .await?;
    Ok(())
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

    // Purge past-retention rows before reading. This makes the bound a property of the data rather
    // than of a consumer that may never run: somebody who deleted their account should not have
    // their address kept indefinitely because a worker elsewhere is switched off.
    purge_expired(&auth_state, "email_marketing_deletions", tenant.0.id).await?;

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

    purge_expired(&auth_state, "email_marketing_email_changes", tenant.0.id).await?;

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
