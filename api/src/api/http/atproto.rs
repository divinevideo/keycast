use crate::divine_names::{self, DivineNameError, PubkeyLookupResponse};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use keycast_core::repositories::{
    AtprotoOAuthSessionRepository, ConditionalWrite, RepositoryError, UserRepository,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::future::Future;

use super::auth::{extract_user_from_token, AuthError};

#[derive(Debug, Deserialize)]
pub struct EnableAtprotoRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct SetCrosspostRequest {
    pub enabled: bool,
}

pub struct SetCrosspostContext<'a> {
    pub user_repo: &'a UserRepository,
    pub session_repo: &'a AtprotoOAuthSessionRepository,
    pub tenant_id: i64,
    pub authenticated_user_pubkey: &'a str,
    pub requested_pubkey: &'a str,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct InternalAtprotoSyncRequest {
    pub nostr_pubkey: String,
    pub enabled: bool,
    pub state: Option<String>,
    pub did: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AtprotoStatusResponse {
    pub enabled: bool,
    pub state: Option<String>,
    pub did: Option<String>,
    pub error: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameResolution {
    Resolved(String),
    NotClaimed,
    Unavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum AtprotoControlError {
    #[error("user not found")]
    UserNotFound,
    #[error("username must be claimed before enabling atproto")]
    UsernameNotClaimed,
    #[error("username resolution is temporarily unavailable")]
    UsernameResolutionUnavailable,
    #[error("requested username does not match claimed username")]
    UsernameMismatch,
    #[error("{}", .0.public_message())]
    ProvisioningTrigger(crate::atproto_provisioning::AtprotoProvisioningError),
    #[error("repository error: {0}")]
    Repository(#[from] RepositoryError),
}

fn map_state_to_response(
    username: Option<String>,
    state: keycast_core::types::user::UserAtprotoState,
) -> AtprotoStatusResponse {
    AtprotoStatusResponse {
        enabled: state.enabled,
        state: state.state,
        did: state.did,
        error: state.error,
        username,
    }
}

fn validate_atproto_state(state: Option<&str>) -> Result<(), AuthError> {
    match state {
        Some("pending" | "ready" | "failed" | "disabled") | None => Ok(()),
        Some(_) => Err(AuthError::BadRequest(
            "ATProto state must be one of pending, ready, failed, disabled, or null".to_string(),
        )),
    }
}

pub async fn resolve_username_with_fallback<F, Fut>(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    lookup: F,
) -> Result<UsernameResolution, AtprotoControlError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Option<PubkeyLookupResponse>, DivineNameError>>,
{
    resolve_username_with_fallback_enabled(
        repo,
        tenant_id,
        user_pubkey,
        divine_names::is_enabled(),
        lookup,
    )
    .await
}

pub async fn resolve_username_with_fallback_enabled<F, Fut>(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    divine_names_enabled: bool,
    lookup: F,
) -> Result<UsernameResolution, AtprotoControlError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Option<PubkeyLookupResponse>, DivineNameError>>,
{
    let local_username = repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    if let Some(username) = local_username {
        return Ok(UsernameResolution::Resolved(username));
    }

    if !divine_names_enabled {
        return Ok(UsernameResolution::NotClaimed);
    }

    let lookup_response = match lookup(user_pubkey.to_string()).await {
        Ok(Some(response)) => response,
        Ok(None) => return Ok(UsernameResolution::NotClaimed),
        Err(error) => {
            tracing::warn!(
                "Failed to look up Divine username for ATProto fallback by pubkey {}: {}",
                user_pubkey,
                error
            );
            return Ok(UsernameResolution::Unavailable);
        }
    };

    let Some(ref lookup_pubkey) = lookup_response.pubkey else {
        tracing::warn!(
            "Divine username lookup by pubkey returned no owner for requested_pubkey={}",
            user_pubkey
        );
        return Ok(UsernameResolution::Unavailable);
    };

    if !lookup_pubkey.eq_ignore_ascii_case(user_pubkey) {
        tracing::warn!(
            "Divine username lookup by pubkey returned mismatched owner: requested_pubkey={}, returned_pubkey={}",
            user_pubkey,
            lookup_pubkey
        );
        return Ok(UsernameResolution::NotClaimed);
    }

    let Some(resolved_username) = lookup_response.canonical.or(lookup_response.name) else {
        tracing::warn!(
            "Divine username lookup by pubkey returned no username for pubkey {}",
            user_pubkey
        );
        return Ok(UsernameResolution::NotClaimed);
    };

    let normalized_username = match super::auth::normalize_nip05_username(&resolved_username) {
        Ok(username) => username,
        Err(error) => {
            tracing::warn!(
                "Divine username lookup returned invalid username '{}' for pubkey {}: {:?}",
                resolved_username,
                user_pubkey,
                error
            );
            return Ok(UsernameResolution::NotClaimed);
        }
    };

    if !repo
        .check_username_available(&normalized_username, user_pubkey, tenant_id)
        .await?
    {
        let conflicting_pubkey = repo
            .find_pubkey_by_username(&normalized_username, tenant_id)
            .await?
            .unwrap_or_else(|| "<unknown>".to_string());
        tracing::warn!(
            "Refusing to reconcile Divine username '{}' for pubkey {} because tenant {} already assigns it to pubkey {}",
            normalized_username,
            user_pubkey,
            tenant_id,
            conflicting_pubkey
        );
        return Ok(UsernameResolution::NotClaimed);
    }

    match repo
        .update_username_if_missing(user_pubkey, &normalized_username, tenant_id)
        .await
    {
        Ok(true) => Ok(UsernameResolution::Resolved(normalized_username)),
        Ok(false) => {
            let current_username = repo
                .get_username(user_pubkey, tenant_id)
                .await?
                .ok_or(AtprotoControlError::UserNotFound)?;

            Ok(current_username.map_or(
                UsernameResolution::Unavailable,
                UsernameResolution::Resolved,
            ))
        }
        Err(RepositoryError::Duplicate) => {
            tracing::warn!(
                "Refusing to reconcile Divine username '{}' for pubkey {} because a duplicate local username appeared in tenant {}",
                normalized_username,
                user_pubkey,
                tenant_id
            );
            Ok(UsernameResolution::NotClaimed)
        }
        Err(error) => Err(error.into()),
    }
}

fn require_resolved_username(
    resolution: UsernameResolution,
) -> Result<String, AtprotoControlError> {
    match resolution {
        UsernameResolution::Resolved(username) => Ok(username),
        UsernameResolution::NotClaimed => Err(AtprotoControlError::UsernameNotClaimed),
        UsernameResolution::Unavailable => Err(AtprotoControlError::UsernameResolutionUnavailable),
    }
}

fn authorize_internal_sync(headers: &HeaderMap) -> Result<(), AuthError> {
    let expected = std::env::var("KEYCAST_ATPROTO_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            AuthError::Internal("KEYCAST_ATPROTO_TOKEN must be configured".to_string())
        })?;

    let actual = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    if actual != format!("Bearer {expected}") {
        return Err(AuthError::InvalidToken);
    }

    Ok(())
}

pub async fn enable_user_atproto(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    requested_username: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let claimed_username = require_resolved_username(
        resolve_username_with_fallback(repo, tenant_id, user_pubkey, |pubkey| async move {
            divine_names::lookup_by_pubkey(&pubkey).await
        })
        .await?,
    )?;

    if claimed_username != requested_username {
        return Err(AtprotoControlError::UsernameMismatch);
    }

    let existing_did = current_atproto_did(repo, tenant_id, user_pubkey).await?;

    repo.set_atproto_state(
        user_pubkey,
        tenant_id,
        true,
        Some("pending"),
        existing_did.as_deref(),
        None,
    )
    .await?;

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(Some(claimed_username), state))
}

/// Reads the DID currently on the row so a lifecycle write can carry it
/// forward.
///
/// [`UserRepository::set_atproto_state`] writes `atproto_did` unconditionally,
/// so passing `None` erases the link to a live repo. That column is what
/// [`disable_user_atproto_with_trigger`] reads to decide whether a local-only
/// disable is safe, so an enable that blanks it on its way through would let a
/// later disable silently release a provisioned account.
async fn current_atproto_did(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<Option<String>, AtprotoControlError> {
    Ok(repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?
        .did)
}

pub async fn enable_user_atproto_with_trigger<F, Fut>(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    requested_username: &str,
    trigger: F,
) -> Result<AtprotoStatusResponse, AtprotoControlError>
where
    F: FnOnce(String, String) -> Fut,
    Fut: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
{
    let response = enable_user_atproto(repo, tenant_id, user_pubkey, requested_username).await?;
    let username = response
        .username
        .clone()
        .ok_or(AtprotoControlError::UsernameNotClaimed)?;

    if let Err(error) = trigger(user_pubkey.to_string(), username.clone()).await {
        roll_back_failed_enable(repo, tenant_id, user_pubkey, &error).await?;
        return Err(AtprotoControlError::ProvisioningTrigger(error));
    }

    Ok(response)
}

/// Clears the opt-in that [`enable_user_atproto`] or [`reenable_user_atproto`]
/// wrote ahead of the trigger.
///
/// The enabled flag is set before the control plane is called, so a failed
/// trigger leaves an opt-in that exists nowhere but this row. Keeping it makes
/// the account read as "publishing" while no repo exists, and traps the user:
/// turning it back off needs a control-plane call the same outage is refusing.
/// If the trigger did reach the control plane before failing, provisioning
/// reports back through the internal sync endpoint and the state converges
/// there.
///
/// Any existing DID is carried through the rollback: it records a repo the
/// control plane still owns, and [`disable_user_atproto_with_trigger`] depends
/// on it to keep refusing a local-only disable for a provisioned account.
///
/// The rollback only applies while the row is still `pending`. If the trigger
/// did reach the control plane and provisioning reported back through the
/// internal sync endpoint before the local call failed, that sync has already
/// moved the row and must not be overwritten.
///
/// That guard is a state check and not a claim of request ownership: the row
/// records no operation identity, so a rollback cannot tell its own `pending`
/// write apart from one a later concurrent request left behind, and it can
/// still compensate a newer opt-in.
async fn roll_back_failed_enable(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    error: &crate::atproto_provisioning::AtprotoProvisioningError,
) -> Result<(), AtprotoControlError> {
    match repo
        .roll_back_atproto_enable(user_pubkey, tenant_id, Some(error.public_message()))
        .await?
    {
        ConditionalWrite::Applied => {}
        ConditionalWrite::Ineligible => {
            tracing::info!(
                "Skipped ATProto enable rollback for pubkey {}: the row is no longer pending, so provisioning state took precedence",
                user_pubkey
            );
        }
        // The row disappeared while the trigger was in flight. Report that as
        // the missing user it is, matching what the caller saw before the
        // rollback became conditional.
        ConditionalWrite::NotFound => return Err(AtprotoControlError::UserNotFound),
    }

    Ok(())
}

pub async fn reenable_user_atproto(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let claimed_username = require_resolved_username(
        resolve_username_with_fallback(repo, tenant_id, user_pubkey, |pubkey| async move {
            divine_names::lookup_by_pubkey(&pubkey).await
        })
        .await?,
    )?;

    let existing_did = current_atproto_did(repo, tenant_id, user_pubkey).await?;

    repo.set_atproto_state(
        user_pubkey,
        tenant_id,
        true,
        Some("pending"),
        existing_did.as_deref(),
        None,
    )
    .await?;

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(Some(claimed_username), state))
}

pub async fn reenable_user_atproto_with_trigger<F, Fut>(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    trigger: F,
) -> Result<AtprotoStatusResponse, AtprotoControlError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
{
    let response = reenable_user_atproto(repo, tenant_id, user_pubkey).await?;

    if let Err(error) = trigger(user_pubkey.to_string()).await {
        roll_back_failed_enable(repo, tenant_id, user_pubkey, &error).await?;
        return Err(AtprotoControlError::ProvisioningTrigger(error));
    }

    Ok(response)
}

pub async fn get_user_atproto_status(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let (response, _) =
        get_user_atproto_status_with_resolution(repo, tenant_id, user_pubkey).await?;
    Ok(response)
}

async fn get_user_atproto_status_with_resolution(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<(AtprotoStatusResponse, UsernameResolution), AtprotoControlError> {
    let username_resolution =
        resolve_username_with_fallback(repo, tenant_id, user_pubkey, |pubkey| async move {
            divine_names::lookup_by_pubkey(&pubkey).await
        })
        .await?;
    let username = match &username_resolution {
        UsernameResolution::Resolved(username) => Some(username.clone()),
        UsernameResolution::NotClaimed | UsernameResolution::Unavailable => None,
    };

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok((map_state_to_response(username, state), username_resolution))
}

pub async fn sync_user_atproto_state_by_pubkey(
    repo: &UserRepository,
    user_pubkey: &str,
    enabled: bool,
    state: Option<&str>,
    did: Option<&str>,
    error: Option<&str>,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    repo.set_atproto_state_by_pubkey(user_pubkey, enabled, state, did, error)
        .await?;

    let username = repo
        .get_username_by_pubkey(user_pubkey)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;
    let state = repo
        .get_atproto_state_by_pubkey(user_pubkey)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(username, state))
}

pub async fn disable_user_atproto(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let username = repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    repo.set_atproto_state(user_pubkey, tenant_id, false, Some("disabled"), None, None)
        .await?;

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(username, state))
}

pub async fn disable_user_atproto_and_revoke_sessions(
    user_repo: &UserRepository,
    session_repo: &AtprotoOAuthSessionRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let response = disable_user_atproto(user_repo, tenant_id, user_pubkey).await?;
    session_repo.revoke_sessions_for_pubkey(user_pubkey).await?;
    Ok(response)
}

pub async fn disable_user_atproto_with_trigger<F, Fut>(
    user_repo: &UserRepository,
    session_repo: &AtprotoOAuthSessionRepository,
    tenant_id: i64,
    user_pubkey: &str,
    trigger: F,
) -> Result<AtprotoStatusResponse, AtprotoControlError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
{
    // Resolve the user before calling the control plane so a request for an
    // unknown account still fails as `UserNotFound` rather than reaching the
    // gateway. The DID is deliberately not read here: it is checked inside the
    // conditional write below, because anything read before the trigger await
    // can be stale by the time it would be acted on.
    let username = user_repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    if let Err(error) = trigger(user_pubkey.to_string()).await {
        // A provisioned account has a live repo that can keep publishing, so
        // reporting "off" without the control plane agreeing would be a lie.
        // Without a DID there is nothing to publish from, and refusing there is
        // what strands an account that a failed enable already left switched
        // on: every attempt to switch it back off hits the same outage.
        //
        // The eligibility check is the `atproto_did IS NULL` predicate on this
        // statement rather than an earlier read, so provisioning cannot attach a
        // DID between the check and the write. A `false` result means the
        // account became provisioned, and the request fails closed.
        match user_repo
            .disable_atproto_if_unprovisioned(user_pubkey, tenant_id)
            .await?
        {
            ConditionalWrite::Applied => {}
            ConditionalWrite::Ineligible => {
                return Err(AtprotoControlError::ProvisioningTrigger(error))
            }
            // The account was removed while the trigger was in flight. That is a
            // missing user, not a provisioning outage, and the caller saw it as
            // such before this write became conditional.
            ConditionalWrite::NotFound => return Err(AtprotoControlError::UserNotFound),
        }

        tracing::warn!(
            "Disabling unprovisioned ATProto account for pubkey {} locally after control-plane failure: {}",
            user_pubkey,
            error
        );

        session_repo.revoke_sessions_for_pubkey(user_pubkey).await?;

        let state = user_repo
            .get_atproto_state(user_pubkey, tenant_id)
            .await?
            .ok_or(AtprotoControlError::UserNotFound)?;

        return Ok(map_state_to_response(username, state));
    }

    disable_user_atproto_and_revoke_sessions(user_repo, session_repo, tenant_id, user_pubkey).await
}

pub async fn set_user_atproto_crosspost<
    FOptIn,
    FutOptIn,
    FReenable,
    FutReenable,
    FDisable,
    FutDisable,
>(
    context: SetCrosspostContext<'_>,
    opt_in_trigger: FOptIn,
    reenable_trigger: FReenable,
    disable_trigger: FDisable,
) -> Result<AtprotoStatusResponse, AuthError>
where
    FOptIn: FnOnce(String, String, bool) -> FutOptIn,
    FutOptIn: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
    FReenable: FnOnce(String) -> FutReenable,
    FutReenable: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
    FDisable: FnOnce(String) -> FutDisable,
    FutDisable: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
{
    let SetCrosspostContext {
        user_repo,
        session_repo,
        tenant_id,
        authenticated_user_pubkey,
        requested_pubkey,
        enabled,
    } = context;

    if authenticated_user_pubkey != requested_pubkey {
        return Err(AuthError::Forbidden(
            "You can only manage Bluesky publishing for your own account".to_string(),
        ));
    }

    let (current, username_resolution) =
        get_user_atproto_status_with_resolution(user_repo, tenant_id, authenticated_user_pubkey)
            .await
            .map_err(map_control_error)?;

    if enabled {
        if matches!(&username_resolution, UsernameResolution::Unavailable) {
            return Err(map_control_error(
                AtprotoControlError::UsernameResolutionUnavailable,
            ));
        }

        if current.enabled && matches!(current.state.as_deref(), Some("pending" | "ready")) {
            return Ok(current);
        }

        if current.state.as_deref() == Some("disabled") {
            return reenable_user_atproto_with_trigger(
                user_repo,
                tenant_id,
                authenticated_user_pubkey,
                reenable_trigger,
            )
            .await
            .map_err(map_control_error);
        }

        let username = require_resolved_username(username_resolution).map_err(map_control_error)?;

        return enable_user_atproto_with_trigger(
            user_repo,
            tenant_id,
            authenticated_user_pubkey,
            &username,
            |pubkey, requested_username| async move {
                opt_in_trigger(pubkey, requested_username, true).await
            },
        )
        .await
        .map_err(map_control_error);
    }

    if !current.enabled && matches!(current.state.as_deref(), None | Some("disabled")) {
        return Ok(current);
    }

    disable_user_atproto_with_trigger(
        user_repo,
        session_repo,
        tenant_id,
        authenticated_user_pubkey,
        disable_trigger,
    )
    .await
    .map_err(map_control_error)
}

fn map_control_error(error: AtprotoControlError) -> AuthError {
    match error {
        AtprotoControlError::UserNotFound => AuthError::UserNotFound,
        AtprotoControlError::UsernameNotClaimed => {
            AuthError::BadRequest("Username must be claimed before enabling ATProto".to_string())
        }
        AtprotoControlError::UsernameResolutionUnavailable => AuthError::ServiceUnavailable {
            message:
                "ATProto username lookup is temporarily unavailable. Please try again shortly."
                    .to_string(),
            retry_after: Some(30),
        },
        AtprotoControlError::UsernameMismatch => AuthError::BadRequest(
            "Requested username does not match the claimed username".to_string(),
        ),
        AtprotoControlError::ProvisioningTrigger(err) => {
            tracing::warn!("ATProto provisioning trigger failed: {}", err);
            // Both branches surface as a scoped 503: AuthError::Internal's
            // IntoResponse discards the message and emits a fixed generic body,
            // so a non-dependency provisioning failure must also use
            // ServiceUnavailable to preserve the ATProto-specific text.
            AuthError::ServiceUnavailable {
                message: err.public_message().to_string(),
                retry_after: Some(30),
            }
        }
        AtprotoControlError::Repository(RepositoryError::NotFound(_)) => AuthError::UserNotFound,
        AtprotoControlError::Repository(RepositoryError::Duplicate) => {
            AuthError::Conflict("ATProto state conflicts with an existing record".to_string())
        }
        AtprotoControlError::Repository(RepositoryError::Integrity(err)) => {
            tracing::warn!("ATProto repository integrity error: {}", err);
            AuthError::BadRequest("ATProto state update is invalid".to_string())
        }
        AtprotoControlError::Repository(RepositoryError::Database(err)) => {
            tracing::error!("ATProto repository error: {}", err);
            AuthError::ServiceUnavailable {
                message: "ATProto state is temporarily unavailable. Please try again shortly."
                    .to_string(),
                retry_after: Some(30),
            }
        }
    }
}

pub async fn enable_atproto(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(request): Json<EnableAtprotoRequest>,
) -> Result<(StatusCode, Json<AtprotoStatusResponse>), AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let repo = UserRepository::new(pool);

    let response = enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &request.username,
        |pubkey, username| async move {
            crate::atproto_provisioning::request_enable(&pubkey, &username, true).await
        },
    )
    .await
    .map_err(map_control_error)?;

    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub async fn atproto_status(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let repo = UserRepository::new(pool);

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .map_err(map_control_error)?;

    Ok(Json(response))
}

pub async fn internal_sync_atproto(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(request): Json<InternalAtprotoSyncRequest>,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    authorize_internal_sync(&headers)?;
    validate_atproto_state(request.state.as_deref())?;

    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool);
    let response = sync_user_atproto_state_by_pubkey(
        &repo,
        &request.nostr_pubkey,
        request.enabled,
        request.state.as_deref(),
        request.did.as_deref(),
        request.error.as_deref(),
    )
    .await
    .map_err(map_control_error)?;

    if !request.enabled || request.state.as_deref() == Some("disabled") {
        session_repo
            .revoke_sessions_for_pubkey(&request.nostr_pubkey)
            .await
            .map_err(|error| AuthError::Internal(error.to_string()))?;
    }

    Ok(Json(response))
}

pub async fn disable_atproto(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let user_repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool);

    let response = disable_user_atproto_with_trigger(
        &user_repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        |pubkey| async move { crate::atproto_provisioning::request_disable(&pubkey).await },
    )
    .await
    .map_err(map_control_error)?;

    Ok(Json(response))
}

pub async fn account_crosspost(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(requested_pubkey): Path<String>,
    Json(request): Json<SetCrosspostRequest>,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let authenticated_user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let user_repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool);

    let response = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &user_repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &authenticated_user_pubkey,
            requested_pubkey: &requested_pubkey,
            enabled: request.enabled,
        },
        |pubkey, username, crosspost_enabled| async move {
            crate::atproto_provisioning::request_enable(&pubkey, &username, crosspost_enabled).await
        },
        |pubkey| async move { crate::atproto_provisioning::request_reenable(&pubkey).await },
        |pubkey| async move { crate::atproto_provisioning::request_disable(&pubkey).await },
    )
    .await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::{map_control_error, AtprotoControlError};
    use crate::api::http::auth::AuthError;
    use keycast_core::repositories::RepositoryError;

    #[test]
    fn provisioning_dependency_failure_maps_to_service_unavailable() {
        let error = map_control_error(AtprotoControlError::ProvisioningTrigger(
            crate::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured,
        ));

        assert!(matches!(
            error,
            AuthError::ServiceUnavailable {
                message,
                retry_after: Some(30),
            } if message == "ATProto enablement is temporarily unavailable. Please try again later."
        ));
    }

    #[test]
    fn provisioning_client_error_maps_to_service_unavailable_with_scoped_body() {
        // A control-plane 4xx is not dependency-unavailable, but it must still
        // surface as a scoped 503 carrying the ATProto-specific message rather
        // than AuthError::Internal's fixed generic body.
        let error = map_control_error(AtprotoControlError::ProvisioningTrigger(
            crate::atproto_provisioning::AtprotoProvisioningError::UnexpectedStatus {
                status: reqwest::StatusCode::BAD_REQUEST,
                body: "bad request".to_string(),
            },
        ));

        assert!(matches!(
            error,
            AuthError::ServiceUnavailable {
                message,
                retry_after: Some(30),
            } if message == "ATProto provisioning failed. Please try again later."
        ));
    }

    #[test]
    fn repository_duplicate_maps_to_conflict() {
        let error = map_control_error(AtprotoControlError::Repository(RepositoryError::Duplicate));

        assert!(
            matches!(error, AuthError::Conflict(_)),
            "ATProto duplicate state should be classified as conflict"
        );
    }
}
