//! UCAN-authenticated backup operations. No recovery credential is accepted from clients.
use crate::{
    api::{
        error::{ApiError, ApiResult},
        extractors::GroupAuth,
        tenant::TenantExtractor,
    },
    state::get_key_manager,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue},
    routing::{get, post},
    Json, Router,
};
use keycast_core::groups::backup::{
    BackupError, BackupService, BackupStatus, RestoreBackup, RestoredBackup, UploadBackup,
};
use sqlx::PgPool;

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/groups/:group_id/backups", get(status).put(upload))
        .route("/groups/:group_id/backups/restore", post(restore))
        .layer(DefaultBodyLimit::max(128 * 1024))
}
fn service(pool: PgPool) -> ApiResult<BackupService<'static>> {
    Ok(BackupService::new(
        pool,
        get_key_manager().map_err(|_| {
            ApiError::service_unavailable("Recovery encryption unavailable; retry shortly")
        })?,
    ))
}
fn api_error(error: BackupError) -> ApiError {
    let message = error.to_string();
    match error {
        BackupError::Denied => ApiError::forbidden(message),
        BackupError::Invalid => ApiError::bad_request(message),
        BackupError::Conflict | BackupError::Obsolete => ApiError::conflict(message),
        BackupError::Missing => ApiError::not_found(message),
        BackupError::Unavailable => ApiError::retryable_service_unavailable(message, 2),
    }
}
async fn status(
    TenantExtractor(tenant): TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
) -> ApiResult<Json<BackupStatus>> {
    Ok(Json(
        service(pool)?
            .status(tenant.id, group, &auth.pubkey)
            .await
            .map_err(api_error)?,
    ))
}
async fn upload(
    TenantExtractor(tenant): TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<UploadBackup>,
) -> ApiResult<Json<BackupStatus>> {
    Ok(Json(
        service(pool)?
            .upload(tenant.id, group, &auth.pubkey, request)
            .await
            .map_err(api_error)?,
    ))
}
async fn restore(
    TenantExtractor(tenant): TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<RestoreBackup>,
) -> ApiResult<(HeaderMap, Json<RestoredBackup>)> {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok((
        headers,
        Json(
            service(pool)?
                .restore(tenant.id, group, &auth.pubkey, request)
                .await
                .map_err(api_error)?,
        ),
    ))
}
