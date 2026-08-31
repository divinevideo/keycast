// ABOUTME: Retry-safe trusted-service provisioning for protected accounts
// ABOUTME: Durable operation ids preserve account identity after claim or deletion

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::{
    repositories::{
        ClaimTokenRepository, RepositoryError, ServiceProvisioningOperationRecord,
        ServiceProvisioningOperationRepository, ServiceProvisioningOperationRow, UserRepository,
    },
    types::claim_token::generate_claim_token,
};
use nostr_sdk::Keys;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::{
    error::ApiError,
    http::{admin, routes::AuthState},
};

const PROVISIONING_LOCK_TIMEOUT: &str = "3s";

#[derive(Debug, Deserialize)]
pub struct CreateMinorAccountRequest {
    pub provisioning_operation_id: Option<String>,
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProvisionedAccountState {
    Unclaimed,
    Claimed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMinorAccountResponse {
    pub pubkey: String,
    pub claim_url: Option<String>,
    pub expires_at: Option<String>,
    pub account_state: ProvisionedAccountState,
    pub replayed: bool,
}

#[derive(Debug)]
enum ProvisioningError {
    Unauthorized(&'static str, String),
    BadRequest(&'static str, String),
    Conflict(&'static str, String),
    Unavailable(&'static str, String),
    Internal(&'static str, String),
}

impl IntoResponse for ProvisioningError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable) = match self {
            Self::Unauthorized(code, message) => (StatusCode::UNAUTHORIZED, code, message, false),
            Self::BadRequest(code, message) => (StatusCode::BAD_REQUEST, code, message, false),
            Self::Conflict(code, message) => (StatusCode::CONFLICT, code, message, false),
            Self::Unavailable(code, message) => {
                (StatusCode::SERVICE_UNAVAILABLE, code, message, true)
            }
            Self::Internal(code, message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, code, message, true)
            }
        };
        (
            status,
            Json(serde_json::json!({
                "error": message, "code": code, "retryable": retryable,
            })),
        )
            .into_response()
    }
}

fn map_repo_error(error: RepositoryError) -> ProvisioningError {
    match error {
        RepositoryError::Unavailable(message) => {
            tracing::warn!(error = %message, "Provisioning database unavailable");
            ProvisioningError::Unavailable(
                "database_unavailable",
                "Service temporarily unavailable. Please try again.".to_string(),
            )
        }
        RepositoryError::Integrity(message) => {
            tracing::error!(error = %message, "Provisioning integrity violation");
            ProvisioningError::Internal(
                "integrity_violation",
                "Something went wrong. Please try again.".to_string(),
            )
        }
        other => {
            tracing::error!(error = %other, "Provisioning database error");
            ProvisioningError::Internal(
                "database_error",
                "Something went wrong. Please try again.".to_string(),
            )
        }
    }
}

fn map_service_token_error(error: ApiError) -> ProvisioningError {
    match error {
        ApiError::Auth(message) => ProvisioningError::Unauthorized("unauthorized", message),
        other => {
            tracing::error!(error = %other, "Provisioning service authentication unavailable");
            ProvisioningError::Unavailable(
                "service_auth_unavailable",
                "Service temporarily unavailable. Please try again.".to_string(),
            )
        }
    }
}

fn map_account_create_error(error: RepositoryError, username: &str) -> ProvisioningError {
    match error {
        RepositoryError::Duplicate => ProvisioningError::Conflict(
            "username_conflict",
            format!("User with username {username} already exists"),
        ),
        other => map_repo_error(other),
    }
}

async fn set_provisioning_lock_timeout(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), ProvisioningError> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(PROVISIONING_LOCK_TIMEOUT)
        .execute(&mut **tx)
        .await
        .map_err(|error| map_repo_error(error.into()))?;
    Ok(())
}

fn normalize_username(raw: &str) -> Result<String, ProvisioningError> {
    let username = raw.trim().to_lowercase();
    if username.is_empty()
        || username.len() > 64
        || !username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        || !username.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !username.ends_with(|c: char| c.is_ascii_alphanumeric())
    {
        return Err(ProvisioningError::BadRequest(
            "invalid_username",
            "username must be 1-64 characters, start and end with alphanumeric, containing only lowercase letters, digits, hyphens, or underscores".to_string(),
        ));
    }
    Ok(username)
}

fn validate_operation_id(raw: &str) -> Result<String, ProvisioningError> {
    let parsed = Uuid::parse_str(raw).map_err(|_| {
        ProvisioningError::BadRequest(
            "invalid_provisioning_operation_id",
            "provisioning_operation_id must be a lowercase UUID".to_string(),
        )
    })?;
    let canonical = parsed.to_string();
    if canonical != raw {
        return Err(ProvisioningError::BadRequest(
            "invalid_provisioning_operation_id",
            "provisioning_operation_id must be a lowercase UUID".to_string(),
        ));
    }
    Ok(canonical)
}

/// Versioned, length-delimited request identity. Length prefixes prevent field
/// boundary ambiguity; the presence byte distinguishes `None` from `Some("")`.
fn request_fingerprint(tenant_id: i64, username: &str, display_name: Option<&str>) -> String {
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keycast-service-provisioning-v1\0");
    hasher.update(&tenant_id.to_be_bytes());
    field(&mut hasher, username.as_bytes());
    match display_name {
        None => {
            hasher.update(&[0]);
        }
        Some(value) => {
            hasher.update(&[1]);
            field(&mut hasher, value.as_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn claim_response(
    pubkey: String,
    token: keycast_core::types::claim_token::ClaimToken,
    replayed: bool,
) -> Response {
    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let claim_url = format!("{app_url}/api/claim?token={}", token.token);
    let status = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (
        status,
        Json(CreateMinorAccountResponse {
            pubkey,
            claim_url: Some(claim_url),
            expires_at: Some(token.expires_at.to_rfc3339()),
            account_state: ProvisionedAccountState::Unclaimed,
            replayed,
        }),
    )
        .into_response()
}

fn claimed_response(pubkey: String) -> Response {
    (
        StatusCode::OK,
        Json(CreateMinorAccountResponse {
            pubkey,
            claim_url: None,
            expires_at: None,
            account_state: ProvisionedAccountState::Claimed,
            replayed: true,
        }),
    )
        .into_response()
}

fn validate_replay(
    row: &ServiceProvisioningOperationRow,
    tenant_id: i64,
    fingerprint: &str,
) -> Result<(), ProvisioningError> {
    if row.tenant_id != tenant_id || row.request_fingerprint.trim() != fingerprint {
        return Err(ProvisioningError::Conflict(
            "provisioning_operation_conflict",
            "provisioning_operation_id is already bound to different request parameters"
                .to_string(),
        ));
    }
    Ok(())
}

async fn replay_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: ServiceProvisioningOperationRow,
    tenant_id: i64,
    fingerprint: &str,
) -> Result<Response, ProvisioningError> {
    validate_replay(&row, tenant_id, fingerprint)?;
    ClaimTokenRepository::lock_for_user_in_tx(tx, row.user_pubkey.trim(), tenant_id)
        .await
        .map_err(map_repo_error)?;
    let claimable = UserRepository::is_unclaimed_minor_in_tx(tx, &row.user_pubkey, tenant_id)
        .await
        .map_err(map_repo_error)?
        .unwrap_or(false);
    if !claimable {
        return Ok(claimed_response(row.user_pubkey.trim().to_string()));
    }
    let replacement = generate_claim_token();
    let token = ClaimTokenRepository::find_or_replace_for_provisioning_in_tx(
        tx,
        row.user_pubkey.trim(),
        tenant_id,
        &replacement,
    )
    .await
    .map_err(map_repo_error)?;
    Ok(claim_response(
        row.user_pubkey.trim().to_string(),
        token,
        true,
    ))
}

async fn provision_with_operation(
    tenant_id: i64,
    auth_state: AuthState,
    operation_id: String,
    username: String,
    display_name: Option<String>,
) -> Result<Response, ProvisioningError> {
    let fingerprint = request_fingerprint(tenant_id, &username, display_name.as_deref());
    let pool = auth_state.state.db.clone();
    let operations = ServiceProvisioningOperationRepository::new(pool.clone());

    // Avoid KMS work for an ordinary replay. Replay itself still takes the
    // operation lock because expired-token replacement is a write.
    if operations
        .find(&operation_id)
        .await
        .map_err(map_repo_error)?
        .is_some()
    {
        let mut tx = pool.begin().await.map_err(|e| map_repo_error(e.into()))?;
        set_provisioning_lock_timeout(&mut tx).await?;
        ServiceProvisioningOperationRepository::lock_in_tx(&mut tx, &operation_id)
            .await
            .map_err(map_repo_error)?;
        let row = ServiceProvisioningOperationRepository::find_in_tx(&mut tx, &operation_id)
            .await
            .map_err(map_repo_error)?
            .ok_or_else(|| {
                ProvisioningError::Internal(
                    "idempotency_record_missing",
                    "provisioning operation disappeared during replay".to_string(),
                )
            })?;
        let response = replay_in_tx(&mut tx, row, tenant_id, &fingerprint).await?;
        tx.commit().await.map_err(|e| map_repo_error(e.into()))?;
        return Ok(response);
    }

    // Key generation and KMS encryption must never hold a database transaction.
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let secret = keys.secret_key().to_secret_bytes();
    let encrypted_secret = auth_state
        .state
        .key_manager
        .encrypt(&secret)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "Provisioning key encryption unavailable");
            ProvisioningError::Unavailable(
                "key_encryption_unavailable",
                "Service temporarily unavailable. Please try again.".to_string(),
            )
        })?;
    let replacement_token = generate_claim_token();

    let mut tx = pool.begin().await.map_err(|e| map_repo_error(e.into()))?;
    set_provisioning_lock_timeout(&mut tx).await?;
    ServiceProvisioningOperationRepository::lock_in_tx(&mut tx, &operation_id)
        .await
        .map_err(map_repo_error)?;
    UserRepository::lock_minor_username_in_tx(&mut tx, &username, tenant_id)
        .await
        .map_err(map_repo_error)?;

    if let Some(row) = ServiceProvisioningOperationRepository::find_in_tx(&mut tx, &operation_id)
        .await
        .map_err(map_repo_error)?
    {
        let response = replay_in_tx(&mut tx, row, tenant_id, &fingerprint).await?;
        tx.commit().await.map_err(|e| map_repo_error(e.into()))?;
        return Ok(response);
    }

    // Bind an upgraded caller to an account created by the transitional
    // no-operation-id path instead of creating a duplicate.
    if let Some((existing_pubkey, _, is_unclaimed)) =
        UserRepository::find_user_minor_status_by_username_in_tx(&mut tx, &username, tenant_id)
            .await
            .map_err(map_repo_error)?
    {
        ClaimTokenRepository::lock_for_user_in_tx(&mut tx, &existing_pubkey, tenant_id)
            .await
            .map_err(map_repo_error)?;
        let still_unclaimed =
            UserRepository::is_unclaimed_minor_in_tx(&mut tx, &existing_pubkey, tenant_id)
                .await
                .map_err(map_repo_error)?
                .unwrap_or(false);
        if !is_unclaimed || !still_unclaimed {
            return Err(ProvisioningError::Conflict(
                "username_conflict",
                format!("User with username {username} already exists"),
            ));
        }
        let token = ClaimTokenRepository::find_or_replace_for_provisioning_in_tx(
            &mut tx,
            &existing_pubkey,
            tenant_id,
            &replacement_token,
        )
        .await
        .map_err(map_repo_error)?;
        ServiceProvisioningOperationRepository::record_in_tx(
            &mut tx,
            ServiceProvisioningOperationRecord {
                provisioning_operation_id: operation_id,
                tenant_id,
                request_fingerprint: fingerprint,
                user_pubkey: existing_pubkey.clone(),
            },
        )
        .await
        .map_err(map_repo_error)?;
        tx.commit().await.map_err(|e| map_repo_error(e.into()))?;
        return Ok(claim_response(existing_pubkey, token, true));
    }

    UserRepository::create_minor_account_in_tx(
        &mut tx,
        &pubkey,
        tenant_id,
        &username,
        display_name.as_deref(),
        &encrypted_secret,
    )
    .await
    .map_err(|error| map_account_create_error(error, &username))?;
    let token =
        ClaimTokenRepository::create_in_tx(&mut tx, &replacement_token, &pubkey, None, tenant_id)
            .await
            .map_err(map_repo_error)?;
    ServiceProvisioningOperationRepository::record_in_tx(
        &mut tx,
        ServiceProvisioningOperationRecord {
            provisioning_operation_id: operation_id,
            tenant_id,
            request_fingerprint: fingerprint,
            user_pubkey: pubkey.clone(),
        },
    )
    .await
    .map_err(map_repo_error)?;
    tx.commit().await.map_err(|e| map_repo_error(e.into()))?;

    if crate::divine_names::is_enabled() {
        match crate::divine_names::claim_username(&keys, &username, None).await {
            Ok(response) if response.ok => {
                tracing::info!("Username '{}' claimed on divine-name-server", username)
            }
            Ok(response) => tracing::warn!(
                "divine-name-server rejected username '{}': {}",
                username,
                response.error.unwrap_or_default()
            ),
            Err(error) => tracing::warn!(
                "divine-name-server unreachable for '{}': {}",
                username,
                error
            ),
        }
    }
    Ok(claim_response(pubkey, token, false))
}

pub async fn create_minor_account(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(request): Json<CreateMinorAccountRequest>,
) -> Response {
    if let Err(error) = admin::authorize_service_token(&headers) {
        return map_service_token_error(error).into_response();
    }
    let username = match normalize_username(&request.username) {
        Ok(username) => username,
        Err(error) => return error.into_response(),
    };
    let Some(raw_operation_id) = request.provisioning_operation_id else {
        let legacy = admin::CreateMinorAccountRequest {
            username,
            display_name: request.display_name,
        };
        return match admin::create_minor_account(tenant, State(auth_state), headers, Json(legacy))
            .await
        {
            Ok(response) => response,
            Err(error) => error.into_response(),
        };
    };
    let operation_id = match validate_operation_id(&raw_operation_id) {
        Ok(operation_id) => operation_id,
        Err(error) => return error.into_response(),
    };
    match provision_with_operation(
        tenant.0.id,
        auth_state,
        operation_id,
        username,
        request.display_name,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use keycast_core::repositories::RepositoryError;

    use super::{map_account_create_error, map_repo_error, request_fingerprint};

    #[test]
    fn fingerprint_is_length_delimited_and_presence_sensitive() {
        assert_ne!(
            request_fingerprint(1, "23", None),
            request_fingerprint(12, "3", None)
        );
        assert_ne!(
            request_fingerprint(1, "name", None),
            request_fingerprint(1, "name", Some(""))
        );
        assert_ne!(
            request_fingerprint(1, "name", Some("a")),
            request_fingerprint(1, "name", Some("b"))
        );
    }

    #[tokio::test]
    async fn repository_errors_do_not_expose_internal_details() {
        let response = map_repo_error(RepositoryError::Database(
            "relation service_provisioning_operations does not exist".to_string(),
        ))
        .into_response();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["code"], "database_error");
        assert_eq!(body["error"], "Something went wrong. Please try again.");
        assert!(!body.to_string().contains("service_provisioning_operations"));
    }

    #[tokio::test]
    async fn account_create_duplicate_is_a_terminal_username_conflict() {
        let response =
            map_account_create_error(RepositoryError::Duplicate, "existing-user").into_response();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_eq!(body["code"], "username_conflict");
        assert_eq!(body["retryable"], false);
    }
}
