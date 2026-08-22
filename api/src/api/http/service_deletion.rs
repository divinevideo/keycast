// ABOUTME: Trusted service-to-service terminal account deletion (keycast#297)
// ABOUTME: Authenticated by a deletion-scoped service token; idempotent on a caller-supplied request id
// ABOUTME: Errors are classified retryable vs terminal so the coordinator can retry safely

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    AccountDeletionOutcome, RepositoryError, ServiceAccountDeletionOutcome,
    ServiceAccountDeletionRecord, ServiceAccountDeletionRepository, ServiceAccountDeletionRow,
    UserRepository,
};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::http::admin::authorize_configured_service_token;
use crate::api::http::routes::AuthState;

/// Upper bound on the caller-supplied request id.
///
/// The id is opaque to Keycast, but it is stored, logged, and used as a primary
/// key, so it is bounded and restricted to printable non-space ASCII. That keeps
/// an id out of log-injection range and keeps the index key small.
const MAX_DELETION_REQUEST_ID_LEN: usize = 200;

/// `admin_audit_events.actor_pubkey` is NOT NULL and there is no human actor on
/// this path -- the caller is a service holding the service token, not a pubkey.
const AUDIT_ACTOR: &str = "service:account-deletion";
const AUDIT_ACTION: &str = "service_account_deletion";

#[derive(Debug, Deserialize)]
pub struct ServiceAccountDeletionRequest {
    /// Stable, opaque id for this deletion request, chosen by the coordinator.
    /// Replaying it returns the original outcome instead of deleting again.
    pub deletion_request_id: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceAccountDeletionResponse {
    pub deletion_request_id: String,
    /// Full 64-character hex pubkey. Never truncated.
    pub pubkey: String,
    /// `deleted` when this request removed the account, `already_absent` when
    /// there was nothing left to remove. Both are success.
    pub outcome: String,
    /// True when this response replays an earlier completed request rather than
    /// reporting work done now.
    pub replayed: bool,
    pub completed_at: DateTime<Utc>,
}

/// Errors for this endpoint, carrying an explicit retry classification.
///
/// The coordinator has to decide whether to retry without parsing prose, and a
/// wrong decision is expensive in both directions: retrying a terminal failure
/// spins forever, and giving up on a transient one strands an account the user
/// asked to have deleted. The status code and the `retryable` field always
/// agree; `code` is the stable identifier to branch on.
#[derive(Debug)]
pub enum ServiceDeletionError {
    Unauthorized(&'static str, String),
    BadRequest(&'static str, String),
    Conflict(&'static str, String),
    Unavailable(&'static str, String),
    Internal(&'static str, String),
}

impl ServiceDeletionError {
    fn parts(&self) -> (StatusCode, &'static str, &str, bool) {
        match self {
            Self::Unauthorized(code, msg) => (StatusCode::UNAUTHORIZED, *code, msg.as_str(), false),
            Self::BadRequest(code, msg) => (StatusCode::BAD_REQUEST, *code, msg.as_str(), false),
            Self::Conflict(code, msg) => (StatusCode::CONFLICT, *code, msg.as_str(), false),
            Self::Unavailable(code, msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, *code, msg.as_str(), true)
            }
            Self::Internal(code, msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, *code, msg.as_str(), true)
            }
        }
    }
}

impl IntoResponse for ServiceDeletionError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable) = self.parts();
        if status.is_server_error() {
            tracing::error!(
                event = "service_account_deletion_error",
                code = code,
                error = message,
                "Service account deletion failed"
            );
        }
        (
            status,
            Json(serde_json::json!({
                "error": message,
                "code": code,
                "retryable": retryable,
            })),
        )
            .into_response()
    }
}

/// A repository failure is retryable unless it is a caller mistake.
///
/// The deletion is idempotent on the request id, so retrying after an ambiguous
/// or transient failure cannot delete twice. That makes "retryable" the safe
/// default for anything the caller cannot fix.
fn map_repo_error(err: RepositoryError) -> ServiceDeletionError {
    match err {
        RepositoryError::Unavailable(msg) => {
            ServiceDeletionError::Unavailable("database_unavailable", msg)
        }
        RepositoryError::Integrity(msg) => {
            ServiceDeletionError::Internal("integrity_violation", msg)
        }
        other => ServiceDeletionError::Internal("database_error", other.to_string()),
    }
}

fn map_service_token_error(err: ApiError) -> ServiceDeletionError {
    match err {
        // The token is absent or wrong. Retrying cannot fix that.
        ApiError::Auth(msg) => ServiceDeletionError::Unauthorized("unauthorized", msg),
        // The server has no token configured. That is an operator fix, and a
        // retry after it is deployed will succeed.
        other => ServiceDeletionError::Unavailable("service_auth_unavailable", other.to_string()),
    }
}

/// Constant-time bearer check against the deletion-only service credential.
///
/// This deliberately does not fall back to `KEYCAST_SERVICE_TOKEN`: that
/// broader credential also authorizes unrelated administration and signing
/// operations, while the coordinator needs authority only to complete an
/// already-committed account deletion.
fn authorize_deletion_service_token(headers: &HeaderMap) -> Result<(), ApiError> {
    authorize_configured_service_token(
        headers,
        "KEYCAST_DELETION_SERVICE_TOKEN",
        "Deletion service credential not configured",
    )
}

/// Canonicalize the path pubkey, rejecting anything that is not a valid
/// 64-character hex Nostr public key.
fn validate_pubkey(raw: &str) -> Result<String, ServiceDeletionError> {
    PublicKey::from_hex(raw.trim())
        .map(|pk| pk.to_hex())
        .map_err(|_| {
            ServiceDeletionError::BadRequest(
                "invalid_pubkey",
                "pubkey must be a 64-character hex Nostr public key".to_string(),
            )
        })
}

fn validate_request_id(raw: &str) -> Result<String, ServiceDeletionError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ServiceDeletionError::BadRequest(
            "invalid_deletion_request_id",
            "deletion_request_id is required".to_string(),
        ));
    }
    if trimmed.len() > MAX_DELETION_REQUEST_ID_LEN {
        return Err(ServiceDeletionError::BadRequest(
            "invalid_deletion_request_id",
            format!("deletion_request_id must be at most {MAX_DELETION_REQUEST_ID_LEN} characters"),
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_graphic()) {
        return Err(ServiceDeletionError::BadRequest(
            "invalid_deletion_request_id",
            "deletion_request_id must be printable ASCII with no spaces".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Turn a stored completion into a response, after checking it describes the
/// account the caller asked about.
///
/// A request id bound to a different account is refused rather than answered.
/// Treating it as success would let a coordinator bug report an account deleted
/// that is still live; deleting the newly named account would honour a request
/// that was never made for it. Neither is recoverable, so this is terminal.
fn replay(
    existing: ServiceAccountDeletionRow,
    tenant_id: i64,
    pubkey: &str,
) -> Result<Json<ServiceAccountDeletionResponse>, ServiceDeletionError> {
    if existing.tenant_id != tenant_id || existing.user_pubkey.trim() != pubkey {
        return Err(ServiceDeletionError::Conflict(
            "deletion_request_id_reused",
            "deletion_request_id is already bound to a different account".to_string(),
        ));
    }

    tracing::info!(
        event = "service_account_deletion_replayed",
        tenant_id = tenant_id,
        user_pubkey = %pubkey,
        deletion_request_id = %existing.deletion_request_id,
        outcome = %existing.outcome,
        "Replayed a completed deletion request"
    );

    Ok(Json(ServiceAccountDeletionResponse {
        deletion_request_id: existing.deletion_request_id,
        pubkey: pubkey.to_string(),
        outcome: existing.outcome,
        replayed: true,
        completed_at: existing.completed_at,
    }))
}

/// POST /api/admin/users/:pubkey/deletion
///
/// Permanently delete a hosted account on behalf of the deletion coordinator.
///
/// Authorization is the deletion-scoped service bearer, deliberately separate
/// from both user UCAN/OAuth and Keycast's broader service credential: by the
/// time this runs the user's signer is gone, so there is no user credential
/// left to present. This is not a general third-party account-deletion API.
pub async fn delete_account_service(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
    Json(req): Json<ServiceAccountDeletionRequest>,
) -> Result<Json<ServiceAccountDeletionResponse>, ServiceDeletionError> {
    authorize_deletion_service_token(&headers).map_err(map_service_token_error)?;

    let tenant_id = tenant.0.id;
    let pubkey = validate_pubkey(&pubkey)?;
    let deletion_request_id = validate_request_id(&req.deletion_request_id)?;

    let pool = auth_state.state.db.clone();
    let deletions = ServiceAccountDeletionRepository::new(pool.clone());

    // A completed request is answered from the record, never re-run.
    if let Some(existing) = deletions
        .find(&deletion_request_id)
        .await
        .map_err(map_repo_error)?
    {
        return replay(existing, tenant_id, &pubkey);
    }

    tracing::info!(
        event = "service_account_deletion_started",
        tenant_id = tenant_id,
        user_pubkey = %pubkey,
        deletion_request_id = %deletion_request_id,
        "Deletion requested by trusted service"
    );

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| map_repo_error(RepositoryError::from(e)))?;

    let outcome = UserRepository::delete_account_in_tx(&mut tx, &pubkey, tenant_id)
        .await
        .map_err(map_repo_error)?;

    let (recorded_outcome, deleted) = match &outcome {
        AccountDeletionOutcome::Deleted(result) => {
            (ServiceAccountDeletionOutcome::Deleted, Some(result))
        }
        AccountDeletionOutcome::AlreadyAbsent => {
            (ServiceAccountDeletionOutcome::AlreadyAbsent, None)
        }
    };

    let record = ServiceAccountDeletionRecord {
        deletion_request_id: deletion_request_id.clone(),
        tenant_id,
        user_pubkey: pubkey.clone(),
        outcome: recorded_outcome,
        teams_removed: deleted.map(|r| r.teams_removed as i32).unwrap_or(0),
        oauth_authorizations_deleted: deleted
            .map(|r| r.oauth_authorizations_deleted as i32)
            .unwrap_or(0),
        bunkers_notified: deleted.map(|r| r.bunker_pubkeys.len() as i32).unwrap_or(0),
    };

    let row = match ServiceAccountDeletionRepository::record_in_tx(&mut tx, record).await {
        Ok(row) => row,
        // A concurrent copy of this same request committed first. Abandon this
        // attempt and answer from the record it wrote, so both callers get the
        // same outcome and only one deletion is ever performed.
        Err(RepositoryError::Duplicate) => {
            tx.rollback()
                .await
                .map_err(|e| map_repo_error(RepositoryError::from(e)))?;
            let existing = deletions
                .find(&deletion_request_id)
                .await
                .map_err(map_repo_error)?
                .ok_or_else(|| {
                    ServiceDeletionError::Internal(
                        "idempotency_record_missing",
                        "deletion request conflicted but no record was found".to_string(),
                    )
                })?;
            return replay(existing, tenant_id, &pubkey);
        }
        Err(other) => return Err(map_repo_error(other)),
    };

    tx.commit()
        .await
        .map_err(|e| map_repo_error(RepositoryError::from(e)))?;

    // Past this point the deletion is committed. Everything below is a
    // best-effort side effect: failing any of it must not turn a completed
    // deletion into an error the coordinator would retry.
    if let AccountDeletionOutcome::Deleted(result) = &outcome {
        if let Some(tx) = &auth_state.auth_tx {
            use keycast_core::authorization_channel::AuthorizationCommand;
            for bunker_pubkey in &result.bunker_pubkeys {
                if let Err(e) = tx
                    .send(AuthorizationCommand::Remove {
                        bunker_pubkey: bunker_pubkey.clone(),
                    })
                    .await
                {
                    tracing::warn!("Failed to notify signer daemon of bunker removal: {}", e);
                }
            }
        }
        METRICS.inc_account_deleted();
    }

    // Audit only the request that did the work. Replays are logged but not
    // written, so `admin_audit_events` holds one row per account actually
    // deleted rather than one per retry. The durable idempotency row committed
    // above is the authoritative record either way, so a failed audit insert
    // does not lose the fact that this happened.
    record_audit(&auth_state, tenant_id, &pubkey, &row).await;

    tracing::info!(
        event = "service_account_deletion_completed",
        tenant_id = tenant_id,
        user_pubkey = %pubkey,
        deletion_request_id = %row.deletion_request_id,
        outcome = %row.outcome,
        teams_removed = row.teams_removed,
        oauth_auths_deleted = row.oauth_authorizations_deleted,
        bunkers_notified = row.bunkers_notified,
        "Account permanently deleted by trusted service"
    );

    Ok(Json(ServiceAccountDeletionResponse {
        deletion_request_id: row.deletion_request_id,
        pubkey,
        outcome: row.outcome,
        replayed: false,
        completed_at: row.completed_at,
    }))
}

/// Append the forensic audit row. Carries no credentials, key material, or
/// signed payloads -- only who acted, on which account, and what it changed.
async fn record_audit(
    auth_state: &AuthState,
    tenant_id: i64,
    pubkey: &str,
    row: &ServiceAccountDeletionRow,
) {
    use keycast_core::repositories::{AdminAuditEventRecord, AdminAuditEventRepository};

    let audit_repo = AdminAuditEventRepository::new(auth_state.state.db.clone());
    if let Err(error) = audit_repo
        .record(AdminAuditEventRecord {
            tenant_id,
            actor_pubkey: AUDIT_ACTOR.to_string(),
            action: AUDIT_ACTION.to_string(),
            target_resource_type: "user".to_string(),
            target_resource_id: Some(pubkey.to_string()),
            target_client_id: None,
            metadata_json: serde_json::json!({
                "deletion_request_id": row.deletion_request_id,
                "outcome": row.outcome,
                "teams_removed": row.teams_removed,
                "oauth_authorizations_deleted": row.oauth_authorizations_deleted,
                "bunkers_notified": row.bunkers_notified,
            }),
        })
        .await
    {
        tracing::error!(
            user_pubkey = %pubkey,
            deletion_request_id = %row.deletion_request_id,
            error = %error,
            "Failed to write admin_audit_events row for service account deletion"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_empty_deletion_credentials_fail_closed() {
        unsafe { std::env::remove_var("KEYCAST_DELETION_SERVICE_TOKEN") };
        let missing = authorize_deletion_service_token(&HeaderMap::new()).unwrap_err();
        assert!(matches!(
            missing,
            ApiError::Internal(ref message)
                if message == "Deletion service credential not configured"
        ));

        unsafe { std::env::set_var("KEYCAST_DELETION_SERVICE_TOKEN", "   ") };
        let empty = authorize_deletion_service_token(&HeaderMap::new()).unwrap_err();
        unsafe { std::env::remove_var("KEYCAST_DELETION_SERVICE_TOKEN") };
        assert!(matches!(
            empty,
            ApiError::Internal(ref message)
                if message == "Deletion service credential not configured"
        ));
    }

    #[test]
    fn request_id_rejects_empty_oversized_and_unprintable() {
        assert!(validate_request_id("   ").is_err());
        assert!(validate_request_id(&"a".repeat(MAX_DELETION_REQUEST_ID_LEN + 1)).is_err());
        assert!(validate_request_id("has space").is_err());
        assert!(validate_request_id("line\nbreak").is_err());
        assert!(validate_request_id("tab\there").is_err());
    }

    #[test]
    fn request_id_accepts_a_uuid_and_trims() {
        let id = validate_request_id("  b8f0c1a2-4d3e-4f5a-9b6c-7d8e9f0a1b2c  ")
            .expect("uuid must be accepted");
        assert_eq!(id, "b8f0c1a2-4d3e-4f5a-9b6c-7d8e9f0a1b2c");
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn pubkey_must_be_a_full_valid_key() {
        let valid = nostr_sdk::Keys::generate().public_key().to_hex();
        assert_eq!(validate_pubkey(&valid).expect("generated key"), valid);
        assert_eq!(
            validate_pubkey(&format!("  {valid}  ")).expect("surrounding space"),
            valid
        );

        assert!(validate_pubkey("not-a-pubkey").is_err());
        assert!(validate_pubkey("").is_err());
        // A truncated identifier is rejected rather than resolved. This endpoint
        // deletes an account permanently; a prefix is not an identity.
        assert!(validate_pubkey(&valid[..63]).is_err());
        assert!(validate_pubkey(&format!("{valid}0")).is_err());
    }

    #[test]
    fn error_status_and_retryable_always_agree() {
        let cases = [
            ServiceDeletionError::Unauthorized("unauthorized", "x".into()),
            ServiceDeletionError::BadRequest("invalid_pubkey", "x".into()),
            ServiceDeletionError::Conflict("deletion_request_id_reused", "x".into()),
            ServiceDeletionError::Unavailable("database_unavailable", "x".into()),
            ServiceDeletionError::Internal("database_error", "x".into()),
        ];
        for case in &cases {
            let (status, _, _, retryable) = case.parts();
            assert_eq!(
                status.is_server_error(),
                retryable,
                "retryable must mean 5xx and 5xx must mean retryable, got {status}"
            );
        }
    }
}
