//! UCAN-authenticated optional FROST coordinator. Secret shares/nonces never
//! cross this API; round-two deliveries remain NIP-44 recipient ciphertext.
use crate::api::{
    error::{ApiError, ApiResult},
    extractors::GroupAuth,
    tenant::TenantExtractor,
};
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use keycast_core::groups::frost::{
    DkgState, FrostCoordinator, FrostError, Session, SigningMessage, SigningState,
};
use nostr::{Event, UnsignedEvent};
use serde::Deserialize;
use sqlx::PgPool;

/// Merge under `/api/groups` (or the existing authenticated groups prefix).
pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/:group_id/frost/dkg", post(create_dkg))
        .route("/:group_id/frost/signing", post(create_signing))
        .route("/:group_id/frost/sessions/:session_id", get(session))
        .route(
            "/:group_id/frost/sessions/:session_id/dkg",
            post(dkg_message),
        )
        .route(
            "/:group_id/frost/sessions/:session_id/signing",
            post(signing_message),
        )
        .route("/:group_id/frost/sessions/:session_id/abort", post(abort))
}

fn error(e: FrostError) -> ApiError {
    match e {
        FrostError::Forbidden => ApiError::forbidden("Group access denied"),
        FrostError::NotFound => ApiError::not_found("FROST session not found"),
        FrostError::Database(e) => {
            tracing::error!(error=%e,"FROST storage unavailable");
            ApiError::service_unavailable("FROST storage unavailable")
        }
        FrostError::Json(_) => ApiError::bad_request("Invalid FROST protocol payload"),
        other => ApiError::conflict(other.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDkg {
    pub session_id: String,
    pub threshold: u16,
}
async fn create_dkg(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<CreateDkg>,
) -> ApiResult<Json<DkgState>> {
    FrostCoordinator::new(pool)
        .create_dkg(
            tenant.0.id,
            group,
            &auth.pubkey,
            &request.session_id,
            request.threshold,
        )
        .await
        .map(Json)
        .map_err(error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSigning {
    pub session_id: String,
    pub dkg_session_id: String,
    pub event: UnsignedEvent,
    pub signer_ids: Vec<u16>,
}
async fn create_signing(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<CreateSigning>,
) -> ApiResult<Json<SigningState>> {
    FrostCoordinator::new(pool)
        .create_signing(
            tenant.0.id,
            group,
            &auth.pubkey,
            &request.session_id,
            &request.dkg_session_id,
            request.event,
            request.signer_ids,
        )
        .await
        .map(Json)
        .map_err(error)
}
async fn session(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path((group, id)): Path<(i32, String)>,
) -> ApiResult<Json<Session>> {
    FrostCoordinator::new(pool)
        .get(tenant.0.id, group, &auth.pubkey, &id)
        .await
        .map(Json)
        .map_err(error)
}
async fn dkg_message(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path((group, id)): Path<(i32, String)>,
    Json(event): Json<Event>,
) -> ApiResult<Json<DkgState>> {
    FrostCoordinator::new(pool)
        .dkg_message(tenant.0.id, group, &auth.pubkey, &id, event)
        .await
        .map(Json)
        .map_err(error)
}
async fn signing_message(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path((group, id)): Path<(i32, String)>,
    Json(message): Json<SigningMessage>,
) -> ApiResult<Json<SigningState>> {
    FrostCoordinator::new(pool)
        .signing_message(tenant.0.id, group, &auth.pubkey, &id, message)
        .await
        .map(Json)
        .map_err(error)
}
async fn abort(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path((group, id)): Path<(i32, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    FrostCoordinator::new(pool)
        .abort(tenant.0.id, group, &auth.pubkey, &id)
        .await
        .map_err(error)?;
    Ok(Json(serde_json::json!({"aborted":true})))
}
