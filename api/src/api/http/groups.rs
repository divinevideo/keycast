//! UCAN-authenticated group lifecycle. Legacy team administration remains separate.
use crate::{
    api::{
        error::{ApiError, ApiResult},
        extractors::GroupAuth,
        tenant::TenantExtractor,
    },
    state::{get_key_manager, get_secret_pool},
};
use axum::{
    extract::{Path, State},
    http::header,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use keycast_core::groups::{
    CreateGroup, Group, GroupAccess, GroupError, GroupGrant, GroupMembership, GroupService,
};
use serde::Deserialize;
use sqlx::PgPool;

pub fn map_error(error: GroupError) -> ApiError {
    match error {
        GroupError::Forbidden => ApiError::forbidden("Group access denied"),
        GroupError::Invalid(message) => ApiError::bad_request(message),
        GroupError::Conflict => ApiError::conflict("Group request conflicts with current state"),
        GroupError::Storage(_) | GroupError::Encryption => ApiError::retryable_service_unavailable(
            "Group storage or signing material unavailable; retry the request",
            1,
        ),
    }
}
fn service(pool: PgPool) -> ApiResult<GroupService<'static>> {
    Ok(GroupService::new(
        pool,
        get_key_manager().map_err(|_| ApiError::service_unavailable("Key storage unavailable"))?,
    ))
}

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/groups/capabilities", get(capabilities))
        .route("/groups", get(list).post(create))
        .route("/groups/invitations", get(invitations))
        .route("/groups/:group_id", get(get_group))
        .route("/groups/:group_id/members", get(members).post(invite))
        .route("/groups/:group_id/members/:admin", delete(remove))
        .route("/groups/:group_id/accept", post(accept))
        .route("/groups/:group_id/access", get(grants).post(enroll))
        .route("/groups/:group_id/access/:authorization", delete(revoke))
        .route("/groups/:group_id/recover", post(recover))
}
async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "protocol_versions":[1],"default_mode":"hosted","ordinary_human_approvals":1,
        "custody_modes":["hosted","device","frost"],"server_frost_participant":false,
        "recoverable_backup":true,"frost_suite":"frost-secp256k1-tr@2.2.0",
        "self_managed":{"registration_required":false,"keycast_required":false,"transport":"client-owned authenticated confidential relay delivery","backup":"client-managed"},
        "custody_notice":"Keycast can recover hosted keys and backed-up signing material. Recoverable threshold shares are custodial; they do not authorize server participation."
    }))
}
async fn create(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Json(request): Json<CreateGroup>,
) -> ApiResult<Json<Group>> {
    Ok(Json(
        service(pool)?
            .create(tenant.0.id, &auth.pubkey, &request)
            .await
            .map_err(map_error)?,
    ))
}
async fn list(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
) -> ApiResult<Json<Vec<Group>>> {
    Ok(Json(
        service(pool)?
            .list(tenant.0.id, &auth.pubkey)
            .await
            .map_err(map_error)?,
    ))
}
async fn get_group(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
) -> ApiResult<Json<Group>> {
    Ok(Json(
        service(pool)?
            .get(tenant.0.id, group, &auth.pubkey)
            .await
            .map_err(map_error)?,
    ))
}
async fn invitations(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
) -> ApiResult<Json<Vec<Group>>> {
    Ok(Json(
        service(pool)?
            .invitations(tenant.0.id, &auth.pubkey)
            .await
            .map_err(map_error)?,
    ))
}
async fn members(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
) -> ApiResult<Json<Vec<GroupMembership>>> {
    Ok(Json(
        service(pool)?
            .members(tenant.0.id, group, &auth.pubkey)
            .await
            .map_err(map_error)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    admin_pubkey: String,
}
async fn invite(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<Invite>,
) -> ApiResult<Json<serde_json::Value>> {
    service(pool)?
        .invite(tenant.0.id, group, &auth.pubkey, &request.admin_pubkey)
        .await
        .map_err(map_error)?;
    Ok(Json(serde_json::json!({"status":"invited"})))
}
async fn accept(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
) -> ApiResult<Json<serde_json::Value>> {
    service(pool)?
        .accept(tenant.0.id, group, &auth.pubkey)
        .await
        .map_err(map_error)?;
    Ok(Json(serde_json::json!({"status":"active"})))
}
async fn remove(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path((group, removed)): Path<(i32, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    service(pool)?
        .remove(tenant.0.id, group, &auth.pubkey, &removed)
        .await
        .map_err(map_error)?;
    Ok(Json(serde_json::json!({"status":"removed"})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    client_pubkey: String,
}
async fn access(
    pool: PgPool,
    tenant: i64,
    group: i32,
    admin: &str,
    request: Enrollment,
    recovery: bool,
) -> ApiResult<Response> {
    // Check membership before consuming bounded credential-generation capacity.
    keycast_core::groups::require_admin(&pool, tenant, group, admin)
        .await
        .map_err(map_error)?;
    let pair = get_secret_pool()
        .map_err(|_| ApiError::service_unavailable("Credential service unavailable"))?
        .get()
        .await
        .map_err(|_| {
            ApiError::retryable_service_unavailable(
                "Credential capacity exhausted; retry enrollment",
                1,
            )
        })?;
    let result: GroupAccess = service(pool)?
        .enroll(tenant, group, admin, &request.client_pubkey, pair, recovery)
        .await
        .map_err(map_error)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(result)).into_response())
}
async fn enroll(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<Enrollment>,
) -> ApiResult<Response> {
    access(pool, tenant.0.id, group, &auth.pubkey, request, false).await
}
async fn recover(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
    Json(request): Json<Enrollment>,
) -> ApiResult<Response> {
    access(pool, tenant.0.id, group, &auth.pubkey, request, true).await
}
async fn revoke(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path((group, authorization)): Path<(i32, i32)>,
) -> ApiResult<Json<serde_json::Value>> {
    service(pool)?
        .revoke(tenant.0.id, group, &auth.pubkey, authorization)
        .await
        .map_err(map_error)?;
    Ok(Json(serde_json::json!({"status":"revoked"})))
}

async fn grants(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    auth: GroupAuth,
    Path(group): Path<i32>,
) -> ApiResult<Json<Vec<GroupGrant>>> {
    Ok(Json(
        service(pool)?
            .grants(tenant.0.id, group, &auth.pubkey)
            .await
            .map_err(map_error)?,
    ))
}
