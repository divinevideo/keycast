// ABOUTME: Authenticated retention compaction requested by the deletion coordinator
// ABOUTME: Returns explicit durable acknowledgements for every requested target

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use keycast_core::{
    repositories::{
        RepositoryError, RetentionCompactionStatus, ServiceAccountDeletionRepository,
        ServiceProvisioningOperationRepository,
    },
    retention::RetentionDigestKeyring,
};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};

use super::{routes::AuthState, service_deletion::authorize_deletion_service_token};
use crate::api::error::ApiError;

#[derive(Debug, Deserialize)]
pub struct RetentionCompactionRequest {
    pub deletion: Option<DeletionCompactionTarget>,
    pub provisioning: Option<ProvisioningCompactionTarget>,
}

#[derive(Debug, Deserialize)]
pub struct DeletionCompactionTarget {
    pub deletion_request_id: String,
    pub pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct ProvisioningCompactionTarget {
    pub pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct RetentionCompactionResponse {
    pub deletion: Option<CompactionAcknowledgement>,
    pub provisioning: Vec<CompactionAcknowledgement>,
}

#[derive(Debug, Serialize)]
pub struct CompactionAcknowledgement {
    pub target_kind: &'static str,
    pub target_id: String,
    pub status: &'static str,
    pub durable: bool,
}

#[derive(Debug)]
pub enum RetentionError {
    Unauthorized(String),
    BadRequest(String),
    Unavailable(String),
    Internal(String),
}

impl IntoResponse for RetentionError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable) = match self {
            Self::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", message, false)
            }
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                "invalid_compaction_request",
                message,
                false,
            ),
            Self::Unavailable(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "retention_unavailable",
                message,
                true,
            ),
            Self::Internal(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "retention_error",
                message,
                true,
            ),
        };
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

fn map_auth(error: ApiError) -> RetentionError {
    match error {
        ApiError::Auth(message) => RetentionError::Unauthorized(message),
        other => RetentionError::Unavailable(other.to_string()),
    }
}

fn map_repo(error: RepositoryError) -> RetentionError {
    match error {
        RepositoryError::Unavailable(message) => RetentionError::Unavailable(message),
        RepositoryError::Integrity(message) => RetentionError::Internal(message),
        other => RetentionError::Internal(other.to_string()),
    }
}

fn valid_pubkey(raw: &str) -> Result<String, RetentionError> {
    PublicKey::from_hex(raw.trim())
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| {
            RetentionError::BadRequest(
                "pubkey must be a full 64-character hexadecimal Nostr public key".to_string(),
            )
        })
}

fn valid_deletion_request_id(raw: &str) -> Result<String, RetentionError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 200
        || !trimmed
            .chars()
            .all(|character| character.is_ascii_graphic())
    {
        return Err(RetentionError::BadRequest(
            "deletion_request_id must be 1-200 printable ASCII characters with no spaces"
                .to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn acknowledgement(
    target_kind: &'static str,
    target_id: String,
    status: RetentionCompactionStatus,
) -> CompactionAcknowledgement {
    let (status, durable) = match status {
        RetentionCompactionStatus::Compacted => ("compacted", true),
        RetentionCompactionStatus::AlreadyCompacted => ("already_compacted", true),
        RetentionCompactionStatus::Ineligible => ("not_yet_eligible", false),
        RetentionCompactionStatus::Held => ("held", false),
        RetentionCompactionStatus::NotFound => ("not_found", false),
        RetentionCompactionStatus::Conflict => ("conflict", false),
    };
    CompactionAcknowledgement {
        target_kind,
        target_id,
        status,
        durable,
    }
}

/// Compact only records explicitly presented by the deletion coordinator.
/// The deletion-scoped bearer is also the coordinator's assertion that its
/// attempt is terminal; Keycast independently enforces its local 30-day clock.
pub async fn compact_account_records(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(request): Json<RetentionCompactionRequest>,
) -> Result<Json<RetentionCompactionResponse>, RetentionError> {
    authorize_deletion_service_token(&headers).map_err(map_auth)?;
    if request.deletion.is_none() && request.provisioning.is_none() {
        return Err(RetentionError::BadRequest(
            "deletion or provisioning target is required".to_string(),
        ));
    }
    let keys = RetentionDigestKeyring::from_env()
        .map_err(|error| RetentionError::Unavailable(error.to_string()))?;
    let tenant_id = tenant.0.id;
    let as_of = Utc::now();

    let deletion = if let Some(target) = request.deletion {
        let deletion_request_id = valid_deletion_request_id(&target.deletion_request_id)?;
        let pubkey = valid_pubkey(&target.pubkey)?;
        let status = ServiceAccountDeletionRepository::new(auth_state.state.db.clone())
            .compact(&deletion_request_id, tenant_id, &pubkey, &keys, as_of)
            .await
            .map_err(map_repo)?;
        Some(acknowledgement(
            "deletion_request",
            deletion_request_id,
            status,
        ))
    } else {
        None
    };

    let provisioning = if let Some(target) = request.provisioning {
        let pubkey = valid_pubkey(&target.pubkey)?;
        let acknowledgements =
            ServiceProvisioningOperationRepository::new(auth_state.state.db.clone())
                .compact_for_account(tenant_id, &pubkey, &keys, as_of)
                .await
                .map_err(map_repo)?;
        if acknowledgements.is_empty() {
            vec![CompactionAcknowledgement {
                target_kind: "provisioning_account",
                target_id: pubkey,
                status: "not_applicable",
                durable: true,
            }]
        } else {
            acknowledgements
                .into_iter()
                .map(|item| {
                    acknowledgement(
                        "provisioning_operation",
                        item.provisioning_operation_id,
                        item.status,
                    )
                })
                .collect()
        }
    } else {
        Vec::new()
    };

    Ok(Json(RetentionCompactionResponse {
        deletion,
        provisioning,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_request_id_rejects_ambiguous_or_unbounded_values() {
        assert!(valid_deletion_request_id("").is_err());
        assert!(valid_deletion_request_id("contains space").is_err());
        assert!(valid_deletion_request_id("contains\nnewline").is_err());
        assert!(valid_deletion_request_id(&"x".repeat(201)).is_err());
    }

    #[test]
    fn deletion_request_id_is_canonicalized() {
        assert_eq!(
            valid_deletion_request_id("  synthetic-request-id  ").unwrap(),
            "synthetic-request-id"
        );
    }
}
