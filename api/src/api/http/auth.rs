// ABOUTME: Personal authentication handlers for email/password registration and login
// ABOUTME: Implements UCAN-based authentication and NIP-46 bunker URL generation

use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use bcrypt::DEFAULT_COST;
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretString};

use super::admin::{is_full_admin, is_support_admin};
use crate::api::extractors::UcanAuth;
use crate::brand::BRAND_NAME;
use crate::key_egress_limiter::{
    KeyEgressAdmission, KeyEgressLimiter, KeyEgressReservation, KEY_EGRESS_FINALIZATION_DEADLINE,
    KEY_EGRESS_RESERVED_WORK_DEADLINE,
};
use crate::nip98;
use keycast_core::bcrypt_admission::{
    BcryptAdmission, BcryptAdmissionError, BcryptOperation, BcryptPermit, BcryptWorkload,
};
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    AccountStatusWithMinorRow, AuthEventRepository, CreateOAuthAuthorizationParams,
    MaterializePendingRegistrationOutcome, OAuthAuthorizationRepository, OAuthCodeData,
    OAuthCodeRepository, PersonalKeysRepository, PolicyRepository, UserRepository,
    VerifiedMinorRow,
};
use keycast_core::traits::CustomPermission;
use nostr_sdk::{Keys, PublicKey, ToBech32, UnsignedEvent};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration as StdDuration;

// Registration and login return simple JSON (not OAuth TokenResponse)

const DEFAULT_TOKEN_EXPIRY_HOURS: i64 = 24;
pub const EMAIL_VERIFICATION_EXPIRY_HOURS: i64 = 24;
pub const EMAIL_CHANGE_EXPIRY_HOURS: i64 = 24;
/// Minimum minutes between successive email-change initiations (resend cooldown).
const EMAIL_CHANGE_RESEND_COOLDOWN_MINUTES: i64 = 5;
const PASSWORD_RESET_EXPIRY_HOURS: i64 = 1;
const DEFAULT_NIP05_DOMAIN: &str = "divine.video";
const MAX_NIP05_USERNAME_LENGTH: usize = 64;
const USERS_EMAIL_TENANT_CONSTRAINT: &str = "idx_users_email_tenant";
pub(crate) const INVALID_EMAIL_CODE: &str = "INVALID_EMAIL";
pub(crate) const INVALID_EMAIL_MESSAGE: &str = "Please enter a valid email address.";
pub(crate) const EMAIL_ALREADY_EXISTS_CODE: &str = "EMAIL_ALREADY_EXISTS";
pub(crate) const EMAIL_ALREADY_EXISTS_MESSAGE: &str =
    "This email is already registered. Please log in instead.";
/// A verification link that resolves to nothing: already used, or replaced by a newer
/// verification email (keycast#268). Deliberately distinct from [`AuthError::InvalidToken`], whose
/// "Please log in again." copy is correct for a bad *session* token but is a dead end here — the
/// user has no session to return to, and the actionable advice is to open the newest email or
/// resend from the app.
pub(crate) const VERIFICATION_LINK_SUPERSEDED_CODE: &str = "VERIFICATION_LINK_SUPERSEDED";
pub(crate) const VERIFICATION_LINK_SUPERSEDED_HEADING: &str = "Link no longer valid";
pub(crate) const VERIFICATION_LINK_SUPERSEDED_MESSAGE: &str =
    "This link was already used or replaced by a newer verification email. \
     Check your most recent email, or tap Resend in the app.";
pub(crate) const EMAIL_NOT_VERIFIED_CODE: &str = "EMAIL_NOT_VERIFIED";
pub(crate) const EMAIL_NOT_VERIFIED_MESSAGE: &str =
    "Please verify your email address before continuing. Check your inbox for the verification link.";
/// Uniform refusal for raw-key egress denied by policy. The message deliberately
/// does not say *why*, and the code is deliberately the same for every reason, so
/// neither discloses account state (see `refuse_key_egress_for_verified_minor`).
pub(crate) const KEY_EGRESS_DENIED_CODE: &str = "KEY_EGRESS_DENIED";
pub(crate) const KEY_EGRESS_DENIED_MESSAGE: &str = "Operation denied by policy";
pub(crate) const TOO_MANY_ATTEMPTS_CODE: &str = "TOO_MANY_ATTEMPTS";
/// `auth_events.endpoint` for the two raw-key egress routes.
pub(crate) const EXPORT_KEY_ENDPOINT: &str = "/api/user/export-key";
pub(crate) const CHANGE_KEY_ENDPOINT: &str = "/api/user/change-key";
/// `auth_events.event_type` shared by both raw-key egress routes, so one wrong-password
/// budget covers the whole surface rather than one per endpoint.
pub(crate) const KEY_EGRESS_EVENT_TYPE: &str = "key_egress";
/// `auth_events.reason_code` the lockout counts. Only a wrong password counts: the
/// gates that run before it refuse an account that cannot succeed anyway, so counting
/// them would lock out a user who never guessed at anything.
pub(crate) const KEY_EGRESS_INVALID_PASSWORD_REASON: &str = "invalid_password";
/// Get token expiry in seconds. Uses `TOKEN_EXPIRY_SECONDS` env var if set,
/// otherwise defaults to 24 hours (86400 seconds).
pub fn token_expiry_seconds() -> i64 {
    std::env::var("TOKEN_EXPIRY_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TOKEN_EXPIRY_HOURS * 3600)
}

pub fn generate_secure_token() -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Returns the domain segment of NIP-05 identifiers (`user@domain`).
///
/// `/.well-known/nostr.json` is served for the request's tenant, and the tenant is derived from
/// the Host header—so `nip05` in `/user/profile` must use that same domain. Letting `NIP05_DOMAIN`
/// or `DOMAIN` override a real tenant would make verification fail (profile claims one host while
/// discovery lives on another). Those env vars apply only when the tenant host is `localhost` or
/// `127.0.0.1` (local dev), with `DEFAULT_NIP05_DOMAIN` as the final fallback.
fn resolve_nip05_domain(tenant_domain: &str) -> String {
    if tenant_domain == "localhost" || tenant_domain == "127.0.0.1" {
        return std::env::var("NIP05_DOMAIN")
            .ok()
            .or_else(|| std::env::var("DOMAIN").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_NIP05_DOMAIN.to_string());
    }
    tenant_domain.to_string()
}

/// The public Divine handle domain — what NIP-05 handles and profile URLs use
/// (`<handle>@divine.video`, `<handle>.divine.video`), independent of the per-request tenant/login
/// host. The support lookup resolves *public* handles, so it must canonicalize against this domain,
/// not `resolve_nip05_domain`'s tenant host (which is e.g. `login.divine.video` in production, so a
/// query like `mjb@divine.video` would never be reduced to the handle `mjb`).
pub(crate) fn public_handle_domain() -> String {
    std::env::var("NIP05_DOMAIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_NIP05_DOMAIN.to_string())
}

pub(crate) fn normalize_nip05_username(raw_username: &str) -> Result<String, AuthError> {
    let username = raw_username.trim().to_lowercase();

    if username.is_empty() {
        return Err(AuthError::BadRequest(
            "Username cannot be empty".to_string(),
        ));
    }

    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return Err(AuthError::BadRequest(
            "Username can only contain a-z, 0-9, hyphens, underscores, and dots".to_string(),
        ));
    }

    if username.starts_with('-') || username.ends_with('-') {
        return Err(AuthError::BadRequest(
            "Username cannot start or end with a hyphen".to_string(),
        ));
    }

    if username.len() > MAX_NIP05_USERNAME_LENGTH {
        return Err(AuthError::BadRequest(format!(
            "Username must be at most {} characters",
            MAX_NIP05_USERNAME_LENGTH
        )));
    }

    Ok(username)
}

pub(crate) fn normalize_registration_email(email: &str) -> Result<String, &'static str> {
    let trimmed = email.trim();

    if trimmed.is_empty()
        || trimmed.len() > 254
        || !trimmed.is_ascii()
        || trimmed.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        return Err(INVALID_EMAIL_CODE);
    }

    let normalized = trimmed.to_ascii_lowercase();

    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(INVALID_EMAIL_CODE);
    };

    if local.is_empty()
        || domain.is_empty()
        || local.len() > 64
        || local.contains('@')
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || local.contains("..")
        || domain.contains("..")
        || !domain.contains('.')
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'.'
                )
        })
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(INVALID_EMAIL_CODE);
    }

    Ok(normalized)
}

/// Generate UCAN token signed by user's key (self-signed)
/// redirect_origin identifies which app/authorization this token is for
pub(crate) async fn generate_ucan_token(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
    relays: Option<&[String]>,
    status: Option<&keycast_core::types::user::UserStatus>,
) -> Result<String, AuthError> {
    use crate::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());

    // Create facts - redirect_origin is required to identify the authorization
    let mut facts_obj = json!({
        "tenant_id": tenant_id,
        "email": email,
        "redirect_origin": redirect_origin,
    });

    if let Some(relays) = relays {
        facts_obj["relays"] = json!(relays);
    }
    if let Some(s) = status {
        if !s.is_active() {
            facts_obj["account_status"] = json!(s.as_str());
        }
    }

    let facts = facts_obj;

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did) // Self-issued
        .with_lifetime(token_expiry_seconds() as u64)
        .with_fact(facts)
        .build()
        .map_err(|e| AuthError::Internal(format!("Failed to build UCAN: {}", e)))?
        .sign()
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to sign UCAN: {}", e)))?;

    ucan.encode()
        .map_err(|e| AuthError::Internal(format!("Failed to encode UCAN: {}", e)))
}

/// Generate server-signed UCAN for users without personal keys yet
/// Used during OAuth registration before keys are created
/// redirect_origin identifies which app/authorization this token is for
/// bunker_pubkey uniquely identifies the authorization for direct cache lookup
/// is_first_party: true for headless flow tokens (allows account deletion)
/// admin_role: "full" for NIP-07 admins, "support" for CF Access admins
#[allow(clippy::too_many_arguments)]
pub async fn generate_server_signed_ucan(
    user_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
    bunker_pubkey: Option<&str>,
    server_keys: &Keys,
    is_first_party: bool,
    admin_role: Option<&str>,
    status: Option<&keycast_core::types::user::UserStatus>,
) -> Result<String, AuthError> {
    use crate::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let server_key_material = NostrKeyMaterial::from_keys(server_keys.clone());
    let user_did = nostr_pubkey_to_did(user_pubkey);

    let mut facts = json!({
        "tenant_id": tenant_id,
        "email": email,
        "redirect_origin": redirect_origin,
    });
    if let Some(bpk) = bunker_pubkey {
        facts["bunker_pubkey"] = json!(bpk);
    }
    if is_first_party {
        facts["first_party"] = json!(true);
    }
    if let Some(role) = admin_role {
        facts["admin_role"] = json!(role);
    }
    if let Some(s) = status {
        if !s.is_active() {
            facts["account_status"] = json!(s.as_str());
        }
    }

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material) // Server issues
        .for_audience(&user_did) // For this user
        .with_lifetime(token_expiry_seconds() as u64)
        .with_fact(facts)
        .build()
        .map_err(|e| AuthError::Internal(format!("Failed to build UCAN: {}", e)))?
        .sign()
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to sign UCAN: {}", e)))?;

    ucan.encode()
        .map_err(|e| AuthError::Internal(format!("Failed to encode UCAN: {}", e)))
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>, // Optional: user can provide their own nsec/hex secret key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>, // Optional: user's preferred relays
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct BunkerUrlResponse {
    pub bunker_url: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub success: bool,
    pub message: String,
    /// For OAuth flows: URL to redirect to after verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// For normal flows: indicates user is now authenticated (UCAN cookie set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    /// Status for async operations: "processing" when password hash is pending
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Seconds to wait before retrying when status is "processing"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct AccountStatusResponse {
    pub email: String,
    pub email_verified: bool,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_reason: Option<String>,
    /// True for an approved minor (13-15) account (Keycast `users.verified_minor`).
    /// Returned independently of `account_status`: an approved minor is `active`, so gating
    /// this behind the non-active check (like `account_status`) would hide the protected-minor
    /// state from clients. Always present so a `false` reliably signals "not a protected minor".
    pub verified_minor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_minor_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AccountStatusResponse {
    /// Builds the `GET /user/account` response from a user's account row.
    ///
    /// `verified_minor` / `verified_minor_at` are surfaced **unconditionally** (an
    /// approved minor is `active`), whereas `account_status` / `suspended_reason` are
    /// only populated when the account is *not* active. Extracted so this branching —
    /// the load-bearing behavior of this endpoint — is unit-testable without a DB.
    fn from_account_row(
        public_key: String,
        email: Option<String>,
        email_verified: Option<bool>,
        status: keycast_core::types::user::UserStatus,
        suspended_reason: Option<String>,
        verified_minor: bool,
        verified_minor_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        let active = status.is_active();
        AccountStatusResponse {
            email: email.unwrap_or_default(),
            email_verified: email_verified.unwrap_or(false),
            public_key,
            account_status: if active {
                None
            } else {
                Some(status.as_str().to_string())
            },
            suspended_reason: if active { None } else { suspended_reason },
            verified_minor,
            verified_minor_at,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProfileData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
}

#[derive(Debug)]
pub enum AuthError {
    Database(sqlx::Error),
    PasswordHash(bcrypt::BcryptError),
    InvalidCredentials,
    EmailAlreadyExists,
    EmailNotVerified,
    UserNotFound,
    Encryption(String),
    Internal(String),
    MissingToken,
    InvalidToken,
    /// An email-verification link that no longer resolves: already used, or superseded by a newer
    /// verification email (keycast#268). Distinct from [`AuthError::InvalidToken`] so the dead-link
    /// copy can be actionable instead of telling a logged-out user to log in again.
    VerificationLinkSuperseded,
    TokenExpired,
    EmailSendFailed(String),
    DuplicateKey, // Nostr pubkey already registered (BYOK case)
    InvalidEmail,
    OAuthProtocol {
        status: StatusCode,
        error: &'static str,
        description: String,
    },
    BadRequest(String),
    Forbidden(String),   // User has no authorization for this origin
    KeyEgressDenied,     // Policy refuses raw-key egress for this account
    RegistrationExpired, // Async bcrypt timed out (instance died)
    /// The pending registration already completed token issuance; re-mint is refused
    /// (keycast#262 bounded lifecycle).
    RegistrationAlreadyCompleted,
    ServiceUnavailable {
        // Server at capacity or shutting down
        message: String,
        retry_after: Option<u32>,
    },
    TooManyRequests {
        // Caller is locked out after repeated failures
        message: String,
        retry_after: u32,
    },
    Conflict(String),
}

fn has_database_constraint(error: &sqlx::Error, expected_constraint: &str) -> bool {
    match error {
        sqlx::Error::Database(db_error) => db_error.constraint() == Some(expected_constraint),
        _ => false,
    }
}

fn coded_error_response(status: StatusCode, message: &str, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": message,
            "code": code,
        })),
    )
        .into_response()
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::Database(e)
                if has_database_constraint(&e, USERS_EMAIL_TENANT_CONSTRAINT) =>
            {
                tracing::info!(
                    "Email conflict while verifying registration: constraint {}",
                    USERS_EMAIL_TENANT_CONSTRAINT
                );
                return coded_error_response(
                    StatusCode::CONFLICT,
                    EMAIL_ALREADY_EXISTS_MESSAGE,
                    EMAIL_ALREADY_EXISTS_CODE,
                );
            }
            AuthError::Database(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::PasswordHash(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Password hashing error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password. Please check your credentials and try again.".to_string(),
            ),
            AuthError::EmailAlreadyExists => {
                return coded_error_response(
                    StatusCode::CONFLICT,
                    EMAIL_ALREADY_EXISTS_MESSAGE,
                    EMAIL_ALREADY_EXISTS_CODE,
                );
            }
            AuthError::EmailNotVerified => {
                return coded_error_response(
                    StatusCode::FORBIDDEN,
                    EMAIL_NOT_VERIFIED_MESSAGE,
                    EMAIL_NOT_VERIFIED_CODE,
                );
            }
            AuthError::UserNotFound => (
                StatusCode::NOT_FOUND,
                "No account found with this email. Please register first.".to_string(),
            ),
            AuthError::Encryption(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Encryption error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::Internal(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Internal error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication required. Please provide a valid token.".to_string(),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired token. Please log in again.".to_string(),
            ),
            // Status deliberately unchanged from the InvalidToken it replaced (401): only the copy
            // and the machine-readable code are new, so no client keying off the status breaks.
            AuthError::VerificationLinkSuperseded => {
                return coded_error_response(
                    StatusCode::UNAUTHORIZED,
                    VERIFICATION_LINK_SUPERSEDED_MESSAGE,
                    VERIFICATION_LINK_SUPERSEDED_CODE,
                );
            }
            AuthError::EmailSendFailed(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Email send error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to send email. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::DuplicateKey => (
                StatusCode::CONFLICT,
                "This Nostr key is already registered. Please log in instead or use a different key.".to_string(),
            ),
            AuthError::InvalidEmail => {
                return coded_error_response(
                    StatusCode::BAD_REQUEST,
                    INVALID_EMAIL_MESSAGE,
                    INVALID_EMAIL_CODE,
                );
            },
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "Verification code or token has expired. Please request a new one.".to_string(),
            ),
            AuthError::OAuthProtocol {
                status,
                error,
                description,
            } => {
                return (
                    status,
                    Json(serde_json::json!({
                        "error": error,
                        "error_description": description,
                    })),
                )
                    .into_response();
            }
            AuthError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                msg,
            ),
            AuthError::Conflict(msg) => (
                StatusCode::CONFLICT,
                msg,
            ),
            AuthError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                msg,
            ),
            AuthError::KeyEgressDenied => {
                return coded_error_response(
                    StatusCode::FORBIDDEN,
                    KEY_EGRESS_DENIED_MESSAGE,
                    KEY_EGRESS_DENIED_CODE,
                );
            }
            AuthError::RegistrationExpired => (
                StatusCode::GONE,
                "Registration expired. Please register again.".to_string(),
            ),
            AuthError::RegistrationAlreadyCompleted => (
                StatusCode::CONFLICT,
                "This registration is already complete. Please sign in.".to_string(),
            ),
            AuthError::ServiceUnavailable { message, retry_after } => {
                // Return with Retry-After header if provided
                let response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({ "error": message })),
                );
                if let Some(seconds) = retry_after {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        [("Retry-After", seconds.to_string())],
                        Json(serde_json::json!({ "error": message })),
                    ).into_response();
                }
                return response.into_response();
            }
            AuthError::TooManyRequests { message, retry_after } => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Retry-After", retry_after.to_string())],
                    Json(serde_json::json!({
                        "error": message,
                        "code": TOO_MANY_ATTEMPTS_CODE,
                    })),
                ).into_response();
            }
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn account_incomplete(message: impl Into<String>) -> AuthError {
    AuthError::Conflict(message.into())
}

fn retryable_service_unavailable(
    message: impl Into<String>,
    retry_after: Option<u32>,
) -> AuthError {
    AuthError::ServiceUnavailable {
        message: message.into(),
        retry_after,
    }
}

fn bcrypt_auth_error(error: BcryptAdmissionError) -> AuthError {
    match error {
        BcryptAdmissionError::Bcrypt(error) => AuthError::PasswordHash(error),
        BcryptAdmissionError::AtCapacity
        | BcryptAdmissionError::ShuttingDown
        | BcryptAdmissionError::WorkerFailed => AuthError::ServiceUnavailable {
            message: "Password service is busy. Please try again shortly.".to_string(),
            retry_after: Some(1),
        },
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        AuthError::Database(e)
    }
}

impl From<keycast_core::repositories::RepositoryError> for AuthError {
    fn from(e: keycast_core::repositories::RepositoryError) -> Self {
        use keycast_core::repositories::RepositoryError;
        match e {
            RepositoryError::Duplicate => AuthError::EmailAlreadyExists,
            RepositoryError::NotFound(_) => AuthError::UserNotFound,
            RepositoryError::Unavailable(message) => AuthError::ServiceUnavailable {
                message,
                retry_after: Some(1),
            },
            _ => AuthError::Internal(e.to_string()),
        }
    }
}

impl From<bcrypt::BcryptError> for AuthError {
    fn from(e: bcrypt::BcryptError) -> Self {
        AuthError::PasswordHash(e)
    }
}

/// Map a verification finalize error into the headless API's error type so the in-app PIN path
/// (keycast#262) inherits the link path's behavior — in particular the duplicate-email 409.
impl From<AuthError> for super::headless::HeadlessError {
    fn from(e: AuthError) -> Self {
        use super::headless::HeadlessError;
        match e {
            // Dedicated variant so the response body carries the documented EMAIL_ALREADY_EXISTS
            // code byte-identical to the link path (keycast#198/#236 contract), while the shared
            // Conflict variant keeps emitting the generic CONFLICT code for its other cases.
            AuthError::EmailAlreadyExists => HeadlessError::EmailAlreadyExists,
            AuthError::Database(ref db_err)
                if has_database_constraint(db_err, USERS_EMAIL_TENANT_CONSTRAINT) =>
            {
                HeadlessError::EmailAlreadyExists
            }
            AuthError::Conflict(msg) => HeadlessError::Conflict(msg),
            AuthError::RegistrationAlreadyCompleted => HeadlessError::Conflict(
                "This registration is already complete. Please sign in.".to_string(),
            ),
            AuthError::ServiceUnavailable {
                message,
                retry_after,
            } => HeadlessError::ServiceUnavailable {
                message,
                retry_after,
            },
            other => {
                tracing::error!("PIN verification finalize failed: {:?}", other);
                HeadlessError::Internal("Email verification could not be completed".to_string())
            }
        }
    }
}

/// Extract user public key from UCAN token in Authorization header or cookie
/// tenant_id is required to validate the token was issued for this tenant
pub(crate) async fn extract_user_from_token(
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<String, AuthError> {
    let (pubkey, _redirect_origin, _bunker_pubkey) =
        extract_user_and_origin_from_token(headers, tenant_id).await?;
    Ok(pubkey)
}

/// Extract user public key, redirect_origin, and bunker_pubkey from UCAN token in Authorization header or cookie
/// redirect_origin identifies which app/authorization this token is for
/// bunker_pubkey uniquely identifies the authorization for direct cache lookup (optional)
/// tenant_id is required to validate the token was issued for this tenant
pub(crate) async fn extract_user_and_origin_from_token(
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<(String, String, Option<String>), AuthError> {
    // Try Bearer token first
    if let Some(auth_header) = headers.get("Authorization") {
        let auth_str = auth_header.to_str().map_err(|_| AuthError::InvalidToken)?;

        if auth_str.starts_with("Bearer ") {
            // Validate UCAN token and extract user pubkey, redirect_origin, and bunker_pubkey
            return crate::ucan_auth::extract_user_from_ucan(headers, tenant_id)
                .await
                .map_err(|_| AuthError::InvalidToken);
        }
    }

    // Fall back to cookie-based UCAN
    if let Some(token) = extract_ucan_from_cookie(headers) {
        // Parse UCAN from string using ucan_auth helper with tenant validation
        let (pubkey, redirect_origin, bunker_pubkey, _ucan) =
            crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id)
                .await
                .map_err(|e| {
                    tracing::warn!("UCAN parse error from cookie: {}", e);
                    AuthError::InvalidToken
                })?;

        Ok((pubkey, redirect_origin, bunker_pubkey))
    } else {
        Err(AuthError::MissingToken)
    }
}

/// Extract UCAN token from Cookie header
pub(crate) fn extract_ucan_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;

    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(token) = cookie.strip_prefix("keycast_session=") {
            return Some(token.to_string());
        }
    }

    None
}

/// Extract redirect_origin from HTTP Origin header
/// Required for first-party login/register to identify which app the UCAN is for
pub(crate) fn extract_origin_from_headers(headers: &HeaderMap) -> Result<String, AuthError> {
    headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AuthError::BadRequest("Origin header required".to_string()))
}

/// Get server keys from SERVER_NSEC environment variable
fn get_server_keys() -> Result<Keys, AuthError> {
    let server_nsec = std::env::var("SERVER_NSEC")
        .map_err(|_| AuthError::Internal("SERVER_NSEC not configured".to_string()))?;
    Keys::parse(&server_nsec)
        .map_err(|e| AuthError::Internal(format!("Invalid SERVER_NSEC: {}", e)))
}

/// Build the expected URL from request parts for NIP-98 validation
fn build_expected_url(headers: &HeaderMap, path: &str) -> Result<String, AuthError> {
    // Try to get host from headers (multiple options for proxy compatibility)
    // Cloud Run uses x-forwarded-host, nginx uses host, HTTP/2 uses :authority
    let host_from_headers = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .or_else(|| headers.get(":authority"))
        .and_then(|v| v.to_str().ok());

    // Fall back to APP_URL env var if no host header (common in Cloud Run)
    if let Some(host) = host_from_headers {
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| {
                if host.contains(":443") || !host.contains(":") {
                    "https"
                } else {
                    "http"
                }
            });
        Ok(format!("{}://{}{}", proto, host, path))
    } else if let Ok(app_url) = std::env::var("APP_URL") {
        // Use APP_URL as fallback (strips trailing slash if present)
        let base = app_url.trim_end_matches('/');
        Ok(format!("{}{}", base, path))
    } else {
        Err(AuthError::BadRequest(
            "Host header required (or set APP_URL env var)".to_string(),
        ))
    }
}

/// Handle NIP-98 admin login (admin-only, no user record created)
async fn nostr_auth_login(
    tenant_id: i64,
    headers: &HeaderMap,
    auth_header: &str,
) -> Result<Response, AuthError> {
    // Build expected URL for this endpoint
    let expected_url = build_expected_url(headers, "/api/auth/login")?;

    // Validate NIP-98 event
    let nip98_auth =
        nip98::extract_and_validate(auth_header, &expected_url, "POST").map_err(|e| match e {
            nip98::Nip98Error::InvalidHeaderFormat => {
                AuthError::BadRequest("Invalid NIP-98 header format".to_string())
            }
            nip98::Nip98Error::InvalidSignature => {
                AuthError::BadRequest("Invalid NIP-98 signature".to_string())
            }
            nip98::Nip98Error::EventExpired => AuthError::BadRequest(
                "NIP-98 event expired (must be within 60 seconds)".to_string(),
            ),
            _ => AuthError::BadRequest(format!("NIP-98 validation failed: {}", e)),
        })?;

    let pubkey_hex = nip98_auth.pubkey.to_hex();

    // Check if pubkey is a full admin or support admin (checks ALLOWED_PUBKEYS and Redis)
    let nip98_auth_check = UcanAuth {
        pubkey: pubkey_hex.clone(),
        admin_role: None,
    };
    let admin_role = if is_full_admin(&nip98_auth_check) {
        "full"
    } else if is_support_admin(&nip98_auth_check).await {
        "support"
    } else {
        tracing::warn!(
            "NIP-98 login denied for non-admin pubkey: {}",
            &pubkey_hex[..8]
        );
        return Err(AuthError::Forbidden(
            "Pubkey not authorized for admin access".to_string(),
        ));
    };

    // Get redirect_origin from headers (required for UCAN)
    let redirect_origin = extract_origin_from_headers(headers)?;

    // Generate server-signed UCAN for admin session
    let server_keys = get_server_keys()?;
    let ucan_token = generate_server_signed_ucan(
        &nip98_auth.pubkey,
        tenant_id,
        "admin", // No email for NIP-98 admins
        &redirect_origin,
        None, // No bunker_pubkey for admin sessions
        &server_keys,
        false, // NIP-98 admin login is not first-party OAuth
        Some(admin_role),
        None, // Admin login does not carry user account status
    )
    .await?;

    // Track successful admin login
    METRICS.inc_login();

    tracing::info!(
        event = "nip98_admin_login",
        tenant_id = tenant_id,
        pubkey = &pubkey_hex[..8],
        "Admin logged in via NIP-98"
    );

    // Create response with UCAN session cookie
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    Ok((
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(AuthResponse {
            success: true,
            pubkey: pubkey_hex,
            verification_required: None,
            email: None,
        }),
    )
        .into_response())
}

/// Register a new user with email and password
/// Note: Does NOT issue UCAN - user must verify email first
pub async fn register(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    _headers: HeaderMap,
    Json(mut req): Json<RegisterRequest>,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    req.email = normalize_registration_email(&req.email).map_err(|_| AuthError::InvalidEmail)?;

    let instance_id = keycast_core::instance::instance_id();

    tracing::info!(
        event = "registration_attempt",
        instance_id = %instance_id,
        tenant_id = tenant_id,
        "Registration attempt"
    );

    let user_repo = UserRepository::new(pool.clone());
    if user_repo
        .find_pubkey_by_email(&req.email, tenant_id)
        .await?
        .is_some()
    {
        return Err(AuthError::EmailAlreadyExists);
    }

    let password_hash = auth_state
        .state
        .bcrypt
        .hash(
            BcryptWorkload::Signup,
            SecretString::from(req.password.clone()),
            DEFAULT_COST,
        )
        .await
        .map_err(bcrypt_auth_error)?;

    // Generate email verification token
    // Email uniqueness is enforced by idx_users_email_tenant constraint
    let verification_token = generate_secure_token();
    let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

    // Use provided nsec or generate new Nostr keypair
    let keys = if let Some(ref nsec_str) = req.nsec {
        tracing::info!(
            "User provided their own key (BYOK) for email: {}",
            req.email
        );
        // Try parsing as bech32 nsec first, then as hex
        Keys::parse(nsec_str)
            .map_err(|e| AuthError::Internal(format!("Invalid nsec or secret key: {}. Please provide a valid nsec (bech32) or hex secret key.", e)))?
    } else {
        tracing::info!("Auto-generating new keypair for email: {}", req.email);
        Keys::generate()
    };

    let public_key = keys.public_key();
    let secret_key = keys.secret_key();

    // Check if this public key is already registered in this tenant (for BYOK case)
    if req.nsec.is_some() {
        let user_repo = UserRepository::new(pool.clone());
        if user_repo.exists(&public_key.to_hex(), tenant_id).await? {
            return Err(AuthError::DuplicateKey);
        }
    }

    // Encrypt the secret key (as raw bytes)
    let secret_bytes = secret_key.to_secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&secret_bytes)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Register user with personal key in a single transaction.
    // Returns Err(RepositoryError::Duplicate) if email already exists, which maps to AuthError::EmailAlreadyExists
    user_repo
        .register_with_personal_key(
            &public_key.to_hex(),
            tenant_id,
            &req.email,
            &password_hash,
            &verification_token,
            verification_expires,
            &encrypted_secret,
        )
        .await?;

    // Track successful registration
    METRICS.inc_registration();

    // Send verification email (required - user must verify before login)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_verification_email(&req.email, &verification_token, None)
                .await
            {
                tracing::error!("Failed to send verification email to {}: {}", req.email, e);
                // Continue even if email fails - user can resend later
            } else {
                tracing::info!("Sent verification email to {}", req.email);
            }
        }
        Err(e) => {
            tracing::warn!(
                "Email service unavailable, skipping verification email: {}",
                e
            );
        }
    }

    tracing::info!(
        event = "registration_success",
        instance_id = %instance_id,
        tenant_id = tenant_id,
        "User registered successfully, awaiting email verification"
    );

    // DO NOT issue UCAN or set session cookie - user must verify email first
    // Return verification_required response so frontend shows "check your email" message
    let response = (
        axum::http::StatusCode::OK,
        axum::Json(AuthResponse {
            success: true,
            pubkey: public_key.to_hex(),
            verification_required: Some(true),
            email: Some(req.email.clone()),
        }),
    );

    Ok(response)
}

/// Login with email/password or NIP-98
///
/// Supports two authentication methods:
/// 1. NIP-98 Admin: POST with Authorization: Nostr <base64(kind_27235_event)>
/// 2. Email/Password: POST with JSON body { "email": "...", "password": "..." }
///
/// Returns simple JSON response and sets UCAN cookie
pub async fn login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AuthError> {
    let tenant_id = tenant.0.id;
    let endpoint = "/api/auth/login";

    // Check for NIP-98 Authorization header first
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Nostr ") {
                return nostr_auth_login(tenant_id, &headers, auth_str).await;
            }
        }
    }

    // Parse JSON body for email/password login
    let mut req: LoginRequest = serde_json::from_str(&body)
        .map_err(|e| AuthError::BadRequest(format!("Invalid JSON: {}", e)))?;
    req.email = req.email.to_lowercase();

    let pool = &auth_state.state.db;

    // Extract redirect_origin from HTTP Origin header (required for UCAN)
    let redirect_origin = match extract_origin_from_headers(&headers) {
        Ok(origin) => origin,
        Err(error) => {
            let message = match &error {
                AuthError::BadRequest(message) => message.clone(),
                _ => "Invalid origin".to_string(),
            };
            super::auth_observability::record_auth_event_and_log(
                &auth_state.state.db,
                &headers,
                None,
                super::auth_observability::AuthEvent {
                    tenant_id,
                    endpoint,
                    event_type: "login",
                    outcome: "failure",
                    reason_code: Some("invalid_request"),
                    http_status: 400,
                    email: None,
                    pubkey: None,
                    client_id: None,
                    redirect_origin: None,
                    metadata_json: serde_json::json!({ "error": message }),
                },
            )
            .await;
            return Err(error);
        }
    };

    tracing::info!(
        event = "login_attempt",
        tenant_id = tenant_id,
        redirect_origin = %redirect_origin,
        "Login attempt"
    );

    // Fetch user with password hash and email_verified status from this tenant
    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo.find_with_password(&req.email, tenant_id).await?;

    let (public_key, password_hash, email_verified, user_status) = match user {
        Some(u) => u,
        None => {
            super::auth_observability::record_auth_event_and_log(
                pool,
                &headers,
                None,
                super::auth_observability::AuthEvent {
                    tenant_id,
                    endpoint,
                    event_type: "login",
                    outcome: "failure",
                    reason_code: Some("user_not_found"),
                    http_status: 401,
                    email: Some(&req.email),
                    pubkey: None,
                    client_id: None,
                    redirect_origin: Some(&redirect_origin),
                    metadata_json: serde_json::json!({}),
                },
            )
            .await;
            tracing::warn!(
                event = "login",
                tenant_id = tenant_id,
                success = false,
                reason = "user_not_found",
                "Login failed: user not found"
            );
            return Err(AuthError::InvalidCredentials);
        }
    };

    let valid = auth_state
        .state
        .bcrypt
        .verify(
            BcryptWorkload::Login,
            SecretString::from(req.password.clone()),
            password_hash.clone(),
        )
        .await
        .map_err(bcrypt_auth_error)?;
    if !valid {
        super::auth_observability::record_auth_event_and_log(
            pool,
            &headers,
            None,
            super::auth_observability::AuthEvent {
                tenant_id,
                endpoint,
                event_type: "login",
                outcome: "failure",
                reason_code: Some("invalid_password"),
                http_status: 401,
                email: Some(&req.email),
                pubkey: Some(&public_key),
                client_id: None,
                redirect_origin: Some(&redirect_origin),
                metadata_json: serde_json::json!({}),
            },
        )
        .await;
        tracing::warn!(
            event = "login",
            tenant_id = tenant_id,
            success = false,
            reason = "invalid_password",
            "Login failed: invalid password"
        );
        METRICS.inc_login_failure();
        return Err(AuthError::InvalidCredentials);
    }

    // Check if email is verified
    if !email_verified {
        super::auth_observability::record_auth_event_and_log(
            pool,
            &headers,
            None,
            super::auth_observability::AuthEvent {
                tenant_id,
                endpoint,
                event_type: "login",
                outcome: "failure",
                reason_code: Some("email_not_verified"),
                http_status: 403,
                email: Some(&req.email),
                pubkey: Some(&public_key),
                client_id: None,
                redirect_origin: Some(&redirect_origin),
                metadata_json: serde_json::json!({}),
            },
        )
        .await;
        tracing::warn!(
            event = "login",
            tenant_id = tenant_id,
            success = false,
            reason = "email_not_verified",
            "Login failed: email not verified"
        );
        return Err(AuthError::EmailNotVerified);
    }

    // Get user's Nostr keys from personal_keys (tenant-scoped)
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key_for_tenant(&public_key, tenant_id)
        .await?
        .ok_or_else(|| account_incomplete("Account setup is incomplete. Please register again."))?;

    let key_manager = auth_state.state.key_manager.as_ref();
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Generate UCAN token for session cookie with redirect_origin
    let status_ref = if user_status.is_active() {
        None
    } else {
        Some(&user_status)
    };
    let ucan_token = generate_ucan_token(
        &keys,
        tenant_id,
        &req.email,
        &redirect_origin,
        None,
        status_ref,
    )
    .await?;

    // Track successful login
    METRICS.inc_login();

    tracing::info!(
        event = "login",
        tenant_id = tenant_id,
        success = true,
        "User logged in successfully"
    );

    super::auth_observability::record_auth_event_and_log(
        pool,
        &headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint,
            event_type: "login",
            outcome: "success",
            reason_code: None,
            http_status: 200,
            email: Some(&req.email),
            pubkey: Some(&public_key),
            client_id: None,
            redirect_origin: Some(&redirect_origin),
            metadata_json: serde_json::json!({}),
        },
    )
    .await;

    // Create response with UCAN session cookie
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    Ok((
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(AuthResponse {
            success: true,
            pubkey: public_key,
            verification_required: None,
            email: None,
        }),
    )
        .into_response())
}

/// Logout endpoint - clears the keycast_session cookie
pub async fn logout() -> Result<impl axum::response::IntoResponse, AuthError> {
    tracing::info!("User logging out");

    // Clear the session cookie by setting Max-Age=0
    let cookie = "keycast_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

    let response = (
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        })),
    );

    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct CreateBunkerRequest {
    pub app_name: String,            // Required: friendly display name
    pub origin: Option<String>, // Optional: the app's origin URL (HTTPS, or http://localhost / *.localhost / 127.0.0.1 / [::1] for local dev)
    pub policy_slug: Option<String>, // Optional: null = full access
}

#[derive(Debug, Serialize)]
pub struct CreateBunkerResponse {
    pub bunker_url: String,
    pub origin: Option<String>,
    pub app_name: String,
    pub bunker_pubkey: String,
    pub created_at: String,
}

/// Validate origin is a valid URL (HTTPS required, except localhost for development)
fn validate_origin(origin: &str) -> Result<(), AuthError> {
    let url = nostr::Url::parse(origin)
        .map_err(|_| AuthError::BadRequest("Invalid origin URL".to_string()))?;

    let host = url
        .host_str()
        .ok_or_else(|| AuthError::BadRequest("Origin must have a host".to_string()))?;

    // Allow http:// only for localhost (development). Accepts IPv4, IPv6, and
    // RFC 6761 `.localhost` subdomains so multiple local dev services can
    // coexist on distinct hostnames. The subdomain match requires a non-empty
    // label before `.localhost`. Kept in sync with `extract_origin` in oauth.rs.
    let is_localhost = host == "localhost"
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "::1"
        || (host.ends_with(".localhost") && host.len() > ".localhost".len());
    if url.scheme() != "https" && !is_localhost {
        return Err(AuthError::BadRequest("Origin must be HTTPS".to_string()));
    }

    Ok(())
}

/// POST /user/bunker/create
/// Manually create a new bunker connection for NIP-46 clients
/// User can create multiple bunker connections for different apps
/// If UCAN contains auth_id for the same redirect_origin, that authorization is auto-revoked
pub async fn create_bunker(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<CreateBunkerRequest>,
) -> Result<Json<CreateBunkerResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let pool = &auth_state.state.db;

    // Validate origin if provided (HTTPS, or http:// for localhost variants)
    if let Some(ref origin) = req.origin {
        validate_origin(origin)?;
    }

    // Use provided origin if given, otherwise empty string for manual bunkers
    // Manual bunkers don't need redirect_origin since they're not actually OAuth
    let redirect_origin = req.origin.clone().unwrap_or_default();
    let display_name = &req.app_name;

    tracing::info!(
        "Creating manual bunker for user: {} in tenant: {}, redirect_origin: {}",
        user_pubkey,
        tenant_id,
        redirect_origin
    );

    // Get user's encrypted secret key (tenant-scoped)
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await?
        .ok_or_else(|| account_incomplete("Account setup is incomplete. Please register again."))?;

    // Get pre-computed (secret, hash) from pool - instant, no waiting for bcrypt
    let secret_pair = auth_state.state.secret_pool.get().await.ok_or_else(|| {
        retryable_service_unavailable(
            "Service temporarily unavailable. Please try again in a few minutes.",
            Some(5),
        )
    })?;
    let connection_secret = secret_pair.secret;
    let secret_hash = secret_pair.hash;

    // Look up policy_id from slug if provided
    let policy_repo = PolicyRepository::new(pool.clone());
    let policy_id: Option<i32> = if let Some(ref slug) = req.policy_slug {
        policy_repo.find_id_by_slug(slug).await?
    } else {
        None
    };

    // Derive bunker key using HKDF with secret_hash as entropy (privacy: bunker_pubkey ≠ user_pubkey)
    // The bunker key is derived at runtime - not stored in DB - avoiding extra KMS roundtrips
    let key_manager = auth_state.state.key_manager.as_ref();
    let decrypted_user_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to decrypt user key: {}", e)))?;
    let user_secret_key = nostr_sdk::SecretKey::from_slice(&decrypted_user_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key: {}", e)))?;

    let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &secret_hash);
    let bunker_public_key = bunker_keys.public_key();

    // Use deployment-wide relay list (ignore any client-provided relay)
    let relays = keycast_core::types::authorization::Authorization::get_bunker_relays();
    let relays_json = serde_json::to_string(&relays)
        .map_err(|e| AuthError::Internal(format!("Failed to serialize relays: {}", e)))?;

    // Create OAuth authorization - always INSERT (multi-device support)
    // Each "Accept" creates a NEW authorization, old ones remain valid until revoked
    let created_at = Utc::now();
    let handle_expires_at = created_at + chrono::Duration::days(30);
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let auth_id = oauth_auth_repo
        .create(CreateOAuthAuthorizationParams {
            tenant_id,
            user_pubkey: user_pubkey.clone(),
            redirect_origin: redirect_origin.clone(),
            client_id: display_name.to_string(),
            bunker_public_key: bunker_public_key.to_hex(),
            secret_hash,
            relays: relays_json.clone(),
            policy_id,
            is_first_party: false,
            client_pubkey: None,
            authorization_handle: None,
            handle_expires_at,
        })
        .await?;

    tracing::info!(
        "Created new OAuth authorization {} for user {} app {}",
        auth_id,
        user_pubkey,
        redirect_origin
    );

    // Signal signer daemon to reload via channel (instant notification)
    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx
            .send(AuthorizationCommand::Upsert {
                bunker_pubkey: bunker_public_key.to_hex(),
                tenant_id,
                is_oauth: true,
            })
            .await
        {
            tracing::error!("Failed to send authorization upsert command: {}", e);
        } else {
            tracing::info!("Sent authorization upsert command to signer daemon");
        }
    }

    // Build bunker URL using derived bunker pubkey (not user pubkey for privacy)
    let relay_params: String = relays
        .iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect::<Vec<_>>()
        .join("&");

    let bunker_url = format!(
        "bunker://{}?{}&secret={}",
        bunker_public_key.to_hex(),
        relay_params,
        connection_secret.expose_secret()
    );

    tracing::info!(
        "Created manual bunker connection for user: {}, redirect_origin: {}",
        user_pubkey,
        redirect_origin
    );

    Ok(Json(CreateBunkerResponse {
        bunker_url,
        origin: req.origin,
        app_name: req.app_name,
        bunker_pubkey: user_pubkey.clone(),
        created_at: created_at.to_rfc3339(),
    }))
}

/// Get bunker URL for the authenticated user
/// DEPRECATED: Bunker URLs with secrets are only available at creation time.
/// The connection secret is now hashed (bcrypt) for security and cannot be retrieved.
/// Use /user/bunker/create to create a new authorization if you need a bunker URL.
pub async fn get_bunker_url(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<BunkerUrlResponse>, AuthError> {
    // Extract user pubkey AND redirect_origin from UCAN token
    let tenant_id = tenant.0.id;
    let (user_pubkey, redirect_origin, _bunker_pubkey) =
        extract_user_and_origin_from_token(&headers, tenant_id).await?;
    tracing::info!(
        "get_bunker_url called for user: {} origin: {} in tenant: {}",
        user_pubkey,
        redirect_origin,
        tenant_id
    );

    // Check if authorization exists (but we can't return the secret anymore)
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let bunker_pubkey = oauth_auth_repo
        .find_bunker_pubkey_by_redirect_origin(&user_pubkey, &redirect_origin, tenant_id)
        .await?;

    match bunker_pubkey {
        Some(pubkey) => {
            // Authorization exists but we can't return the secret
            // Return error explaining the new security model
            tracing::info!(
                "Authorization exists for origin: {} with pubkey: {} but secret is hashed",
                redirect_origin,
                pubkey
            );
            Err(AuthError::BadRequest(
                "Bunker URLs with secrets are only available at creation time. \
                 The connection secret is now hashed for security. \
                 Create a new authorization via /user/bunker/create if you need a bunker URL."
                    .to_string(),
            ))
        }
        None => {
            tracing::warn!(
                "No authorization found for user {} origin {} in tenant {}",
                user_pubkey,
                redirect_origin,
                tenant_id
            );
            Err(AuthError::Forbidden(
                "No authorization for this origin. Create one via OAuth or /user/bunker/create"
                    .to_string(),
            ))
        }
    }
}

/// Outcome of completing a pending registration: the freshly minted 10-minute exchange code
/// plus the routing context the caller needs to build its response.
pub struct FinalizedRegistration {
    /// Fresh 10-minute OAuth authorization code the app/browser exchanges for tokens.
    pub new_code: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub is_headless: bool,
}

/// How a freshly minted headless exchange code reaches the waiting app.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HeadlessDelivery {
    /// Email-link path: the app only learns the code via Redis polling, so Redis must be available
    /// and the push must succeed — otherwise the app would be stranded with no code to pick up.
    RedisRequired,
    /// In-app PIN path: the code is returned synchronously in the response body, so the Redis push
    /// is best-effort and a Redis outage must not fail the flow.
    RedisBestEffort,
}

/// Shared completion path for a pending email-verification registration (keycast#262).
///
/// Invoked by both the email-link verification path and the in-app PIN path so they produce
/// identical results: deferred user creation (including duplicate-email handling), a fresh
/// 10-minute exchange code, and the headless Redis polling push.
///
/// The pending `oauth_codes` row is intentionally NOT deleted here. Re-verifying within the 24h
/// window re-arms a fresh exchange code, which is what makes link prefetch/preview harmless: a
/// mail-scanner GET can no longer materialize the user, mint a short-lived code, delete the row,
/// and strand the user's real visit. The row expires on its own at the end of the verify window.
/// The one exception is a duplicate email (#236): that registration can never complete, so the
/// pending row is deleted to make the 409 terminal instead of looping on every retry.
pub async fn finalize_pending_registration(
    pool: &PgPool,
    redis: Option<&crate::redis::PrefixedRedis>,
    tenant_id: i64,
    oauth_data: &OAuthCodeData,
    delivery: HeadlessDelivery,
) -> Result<FinalizedRegistration, AuthError> {
    if oauth_data.consumed_at.is_some() {
        return Err(AuthError::RegistrationAlreadyCompleted);
    }
    let verification_token = oauth_data
        .pending_email_verification_token
        .as_deref()
        .ok_or_else(|| account_incomplete("Registration is incomplete. Please register again."))?;
    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    let headless_retry_error = || AuthError::ServiceUnavailable {
        message: "Email verified, but app sign-in is still finishing. Please retry shortly."
            .to_string(),
        retry_after: Some(5),
    };

    // For the link path (RedisRequired), validate device_code + Redis BEFORE minting so we never
    // mint a code the polling app could never receive.
    let strict_delivery = if oauth_data.is_headless && delivery == HeadlessDelivery::RedisRequired {
        let device_code = oauth_data.device_code.as_ref().ok_or_else(|| {
            tracing::error!(
                event = "headless_poll_delivery_failed",
                tenant_id = tenant_id,
                user_pubkey = %oauth_data.user_pubkey,
                "Headless verification is missing device_code"
            );
            headless_retry_error()
        })?;
        let redis = redis.ok_or_else(|| {
            tracing::error!(
                event = "headless_poll_delivery_failed",
                tenant_id = tenant_id,
                user_pubkey = %oauth_data.user_pubkey,
                "Headless verification requires Redis, but Redis is unavailable"
            );
            headless_retry_error()
        })?;
        Some((device_code, redis))
    } else {
        None
    };

    let candidate: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let finalized = match oauth_code_repo
        .materialize_pending_registration(tenant_id, verification_token, &candidate)
        .await?
    {
        MaterializePendingRegistrationOutcome::Ready(finalized) => *finalized,
        MaterializePendingRegistrationOutcome::Processing => return Err(headless_retry_error()),
        MaterializePendingRegistrationOutcome::DuplicateKey => return Err(AuthError::DuplicateKey),
        MaterializePendingRegistrationOutcome::EmailAlreadyExists => {
            return Err(AuthError::EmailAlreadyExists)
        }
        MaterializePendingRegistrationOutcome::NotFound => {
            return Err(AuthError::ServiceUnavailable {
                message: "Registration changed while it was being finalized. Please retry."
                    .to_string(),
                retry_after: Some(1),
            })
        }
    };
    let oauth_data = finalized.pending;
    let new_code = finalized.exchange_code.code;
    let redis_ttl_seconds = (finalized.exchange_code.expires_at - Utc::now())
        .num_seconds()
        .max(1) as u64;

    if let Some((device_code, redis)) = strict_delivery {
        let key = format!("oauth_poll:{}", device_code);
        if let Err(e) = redis.setex(&key, redis_ttl_seconds, &new_code).await {
            tracing::error!(
                event = "headless_poll_delivery_failed",
                tenant_id = tenant_id,
                user_pubkey = %oauth_data.user_pubkey,
                device_code = %device_code,
                error = %e,
                "Failed to store headless OAuth code in Redis for polling"
            );
            // Keep the code for retry. Another concurrent finalizer may already have reused and
            // delivered it, so even the call that minted it cannot safely delete it here.
            return Err(headless_retry_error());
        }
        tracing::debug!(
            "Stored OAuth code in Redis for headless polling: device_code={}",
            device_code
        );
    } else if let Some(ref device_code) = oauth_data.device_code {
        // Best-effort push: non-headless same-device verification, or the PIN path where the code
        // is also returned synchronously in the response body (so a Redis miss is not fatal).
        if let Some(redis) = redis {
            let key = format!("oauth_poll:{}", device_code);
            if let Err(e) = redis.setex(&key, redis_ttl_seconds, &new_code).await {
                tracing::warn!("Failed to store OAuth code in Redis for polling: {}", e);
                // Continue - redirect flow / synchronous return still works.
            } else {
                tracing::debug!(
                    "Stored OAuth code in Redis for polling: device_code={}",
                    device_code
                );
            }
        }
    }

    Ok(FinalizedRegistration {
        new_code,
        redirect_uri: oauth_data.redirect_uri.clone(),
        state: oauth_data.state.clone(),
        is_headless: oauth_data.is_headless,
    })
}

/// Result of running the interactive POST email-verification logic.
enum VerifyOutcome {
    /// Non-headless OAuth: send the browser to the client callback carrying a fresh code.
    OAuthRedirect { redirect_url: String },
    /// Headless (mobile app): the app polls for the code; the page just shows success.
    Headless,
    /// First-party normal registration: user is logged in; carries the session cookie.
    LoggedIn { cookie: String },
    /// Idempotent re-click on an already-verified first-party account.
    AlreadyVerified,
    /// Async bcrypt hash still running; the caller should retry shortly.
    Processing,
    /// The verification link has expired.
    Expired,
}

/// Outcomes that a server-side GET may produce. This deliberately excludes first-party user
/// verification and session issuance, which require the interactive POST flow.
enum PendingVerifyOutcome {
    OAuthRedirect { redirect_url: String },
    Headless,
    AlreadyVerified,
    Expired,
}

/// Finalize only an OAuth/headless pending registration, if the token belongs to one.
async fn perform_pending_email_verification(
    auth_state: &super::routes::AuthState,
    tenant_id: i64,
    token: &str,
) -> Result<Option<PendingVerifyOutcome>, AuthError> {
    let pool = &auth_state.state.db;
    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    let Some(oauth_data) = oauth_code_repo
        .find_by_verification_token_including_expired(token, tenant_id)
        .await?
    else {
        return Ok(None);
    };
    if oauth_data.expires_at <= Utc::now() {
        return Ok(Some(PendingVerifyOutcome::Expired));
    }

    tracing::info!(
        "Email verification for OAuth registration: pubkey {}, email {:?}",
        oauth_data.user_pubkey,
        oauth_data.pending_email
    );

    // Complete via the shared finalize path. This intentionally does NOT delete the pending row:
    // re-verifying within the 24h window re-arms a fresh 10-minute code, which makes link
    // prefetch/preview harmless. Once token issuance completes, finalize refuses to re-mint.
    let finalized = match finalize_pending_registration(
        pool,
        auth_state.state.redis.as_ref(),
        tenant_id,
        &oauth_data,
        HeadlessDelivery::RedisRequired,
    )
    .await
    {
        Ok(finalized) => finalized,
        Err(AuthError::RegistrationAlreadyCompleted) => {
            return Ok(Some(PendingVerifyOutcome::AlreadyVerified))
        }
        Err(e) => return Err(e),
    };

    if finalized.is_headless {
        tracing::info!(
            event = "email_verification",
            tenant_id = tenant_id,
            flow = "oauth_headless",
            success = true,
            "Email verified (headless), app will pick up code via polling"
        );
        return Ok(Some(PendingVerifyOutcome::Headless));
    }

    let mut redirect_url = format!("{}?code={}", finalized.redirect_uri, finalized.new_code);
    if let Some(ref state) = finalized.state {
        redirect_url = format!("{}&state={}", redirect_url, state);
    }
    tracing::info!(
        event = "email_verification",
        tenant_id = tenant_id,
        flow = "oauth",
        success = true,
        "Email verified, redirecting to OAuth client"
    );
    Ok(Some(PendingVerifyOutcome::OAuthRedirect { redirect_url }))
}

/// Core POST email-verification logic. OAuth/headless pending rows finalize server-side; normal
/// first-party registrations are verified and receive a session only through this interactive POST.
async fn perform_email_verification(
    auth_state: &super::routes::AuthState,
    headers: &HeaderMap,
    tenant_id: i64,
    token: &str,
) -> Result<VerifyOutcome, AuthError> {
    if let Some(outcome) = perform_pending_email_verification(auth_state, tenant_id, token).await? {
        return Ok(match outcome {
            PendingVerifyOutcome::OAuthRedirect { redirect_url } => {
                VerifyOutcome::OAuthRedirect { redirect_url }
            }
            PendingVerifyOutcome::Headless => VerifyOutcome::Headless,
            PendingVerifyOutcome::AlreadyVerified => VerifyOutcome::AlreadyVerified,
            PendingVerifyOutcome::Expired => VerifyOutcome::Expired,
        });
    }

    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let user_repo = UserRepository::new(pool.clone());
    // Matches neither a pending registration nor a users row: the link was already used or a
    // newer verification email replaced it (keycast#268).
    let token_data = user_repo
        .find_by_verification_token(token, tenant_id)
        .await?
        .ok_or(AuthError::VerificationLinkSuperseded)?;

    let public_key = token_data.pubkey;
    let verification_expired = token_data
        .email_verification_expires_at
        .as_ref()
        .is_none_or(|expires| expires < &Utc::now());

    // Keep an already-verified first-party token useful for retrying the interactive POST during
    // its original verification window (for example, if the first response was lost). Once the
    // window expires, the retained token remains a harmless acknowledgement and must not mint a
    // new session.
    if token_data.email_verified {
        if verification_expired {
            return Ok(VerifyOutcome::AlreadyVerified);
        }
    } else {
        // An unverified account cannot complete after the verification window expires.
        if verification_expired {
            return Ok(VerifyOutcome::Expired);
        }

        // TODO(#377): Remove after the bounded-bcrypt rollout no longer has pre-migration
        // first-party registration rows with password_hash IS NULL.
        // Compatibility for registrations persisted by the pre-#366 asynchronous bcrypt flow.
        // New registrations hash before insertion, but rollout can leave older pending rows.
        if token_data.password_hash.is_none() {
            let age = Utc::now().signed_duration_since(token_data.created_at);
            if age.num_seconds() > 120 {
                // Hash should complete in <1s normally. After 2min, assume instance died.
                // User needs to re-register (cleanup job will delete this row)
                tracing::warn!(
                    "Password hash not completed after {}s for token {}..., likely instance died",
                    age.num_seconds(),
                    &token[..std::cmp::min(8, token.len())]
                );
                return Err(AuthError::RegistrationExpired);
            }
            // Still processing - tell caller to retry
            tracing::debug!(
                "Password hash still processing (age: {}s) for token {}...",
                age.num_seconds(),
                &token[..std::cmp::min(8, token.len())]
            );
            return Ok(VerifyOutcome::Processing);
        }

        // Mark email as verified (token kept for idempotent re-verification).
        user_repo.verify_email(&public_key, tenant_id).await?;
    }

    // Get user's email and account status for UCAN
    let email = user_repo.get_email(&public_key, tenant_id).await?;
    // Best-effort: DB errors → None (no status fact). Hard enforcement is at signing time.
    let user_status = user_repo
        .get_user_status(&public_key, tenant_id)
        .await
        .ok()
        .flatten()
        .map(|(s, _, _)| s);

    // Get user's keys to generate UCAN (tenant-scoped)
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret = personal_keys_repo
        .find_encrypted_key_for_tenant(&public_key, tenant_id)
        .await?
        .ok_or_else(|| account_incomplete("Account setup is incomplete. Please register again."))?;

    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Extract redirect_origin from Origin header for UCAN
    let redirect_origin = extract_origin_from_headers(headers)
        .or_else(|_| std::env::var("APP_URL"))
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    // Generate UCAN token for session cookie
    let ucan_token = generate_ucan_token(
        &keys,
        tenant_id,
        &email,
        &redirect_origin,
        None,
        user_status.as_ref(),
    )
    .await?;

    tracing::info!(
        event = "email_verification",
        tenant_id = tenant_id,
        flow = "normal",
        success = true,
        "Email verified successfully, issuing UCAN"
    );

    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );
    Ok(VerifyOutcome::LoggedIn { cookie })
}

/// Verify email address with token (POST, JSON — used by the SPA verify page / clients).
/// Handles two flows:
/// 1. OAuth registration: token in oauth_codes → complete OAuth flow → redirect to client
/// 2. Normal registration: token in users → mark verified → issue UCAN → set cookie
pub async fn verify_email(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let tenant_id = tenant.0.id;
    // Emitted with the same event_type as the GET path so both transports are comparable in the
    // auth-event feed (keycast#262 made the GET primary).
    let outcome =
        match perform_email_verification(&auth_state, &headers, tenant_id, &req.token).await {
            Ok(outcome) => outcome,
            Err(err) => {
                record_verify_email_event(
                    &auth_state.state.db,
                    &headers,
                    tenant_id,
                    "POST",
                    "failure",
                    Some(verify_email_reason_code(&err)),
                    verify_email_error_status(&err),
                )
                .await;
                return Err(err);
            }
        };

    let outcome_reason = match &outcome {
        VerifyOutcome::Headless => "headless",
        VerifyOutcome::OAuthRedirect { .. } => "oauth_redirect",
        VerifyOutcome::AlreadyVerified => "already_verified",
        VerifyOutcome::Processing => "processing",
        VerifyOutcome::Expired => "expired",
        VerifyOutcome::LoggedIn { .. } => "logged_in",
    };
    let event_outcome = if matches!(&outcome, VerifyOutcome::Expired) {
        "failure"
    } else {
        "success"
    };
    record_verify_email_event(
        &auth_state.state.db,
        &headers,
        tenant_id,
        "POST",
        event_outcome,
        Some(outcome_reason),
        200,
    )
    .await;

    let response = match outcome {
        VerifyOutcome::Headless => (
            StatusCode::OK,
            Json(VerifyEmailResponse {
                success: true,
                message: "Email verified! Open the app to continue.".to_string(),
                redirect_to: None,
                authenticated: None,
                status: Some("headless".to_string()),
                retry_after: None,
            }),
        )
            .into_response(),
        VerifyOutcome::OAuthRedirect { redirect_url } => (
            StatusCode::OK,
            Json(VerifyEmailResponse {
                success: true,
                message: "Email verified! Redirecting to app...".to_string(),
                redirect_to: Some(redirect_url),
                authenticated: None,
                status: None,
                retry_after: None,
            }),
        )
            .into_response(),
        VerifyOutcome::AlreadyVerified => (
            StatusCode::OK,
            Json(VerifyEmailResponse {
                success: true,
                message: "Your email is already verified. You can log in.".to_string(),
                redirect_to: None,
                authenticated: None,
                status: None,
                retry_after: None,
            }),
        )
            .into_response(),
        VerifyOutcome::Expired => (
            StatusCode::OK,
            Json(VerifyEmailResponse {
                success: false,
                message: "Verification link has expired. Please request a new one.".to_string(),
                redirect_to: None,
                authenticated: None,
                status: None,
                retry_after: None,
            }),
        )
            .into_response(),
        VerifyOutcome::Processing => (
            StatusCode::OK,
            Json(VerifyEmailResponse {
                success: false,
                message: "Processing your registration, please wait...".to_string(),
                redirect_to: None,
                authenticated: None,
                status: Some("processing".to_string()),
                retry_after: Some(1),
            }),
        )
            .into_response(),
        VerifyOutcome::LoggedIn { cookie } => (
            StatusCode::OK,
            [(axum::http::header::SET_COOKIE, cookie)],
            Json(VerifyEmailResponse {
                success: true,
                message: "Email verified successfully! You are now logged in.".to_string(),
                redirect_to: None,
                authenticated: Some(true),
                status: None,
                retry_after: None,
            }),
        )
            .into_response(),
    };

    Ok(response)
}

/// Query parameters for the GET verify-email link.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: Option<String>,
}

/// Verify email address by GET (the link target in verification emails).
///
/// OAuth/headless pending registrations finalize on this server-side GET so sandboxed in-app
/// browsers do not need JavaScript. First-party tokens are handed to the interactive page without
/// mutating user state or issuing a session; only that page's POST may do so.
pub async fn verify_email_get(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    let tenant_id = tenant.0.id;
    let pool = auth_state.state.db.clone();
    let emit = |outcome: &'static str, reason: Option<&'static str>, status: i32| {
        let pool = pool.clone();
        let headers = headers.clone();
        async move {
            record_verify_email_event(&pool, &headers, tenant_id, "GET", outcome, reason, status)
                .await;
        }
    };

    let Some(token) = query.token.filter(|t| !t.is_empty()) else {
        emit("failure", Some("missing_token"), 400).await;
        return verify_html_page(
            StatusCode::BAD_REQUEST,
            "Invalid link",
            "This verification link is missing its token. Please use the link from your email.",
        );
    };

    match perform_pending_email_verification(&auth_state, tenant_id, &token).await {
        Ok(Some(PendingVerifyOutcome::OAuthRedirect { redirect_url })) => {
            emit("success", Some("oauth_redirect"), 303).await;
            Redirect::to(&redirect_url).into_response()
        }
        Ok(Some(PendingVerifyOutcome::Headless)) => {
            emit("success", Some("headless"), 200).await;
            verify_html_page(
                StatusCode::OK,
                "Email verified!",
                "Your email is verified. You can return to the app to continue.",
            )
        }
        Ok(Some(PendingVerifyOutcome::AlreadyVerified)) => {
            emit("success", Some("already_verified"), 200).await;
            verify_html_page(
                StatusCode::OK,
                "Already verified",
                "Your email is already verified. You can return to the app or log in.",
            )
        }
        Ok(Some(PendingVerifyOutcome::Expired)) => {
            emit("failure", Some("expired"), 410).await;
            verify_html_page(
                StatusCode::GONE,
                "Verification link expired",
                "This verification link has expired. Please sign up again.",
            )
        }
        Ok(None) => {
            // Not a pending registration. Only a token that still resolves to a users row belongs
            // to the first-party interactive flow, which the SPA owns (it POSTs and mints the
            // session). Anything else is a dead link, and bouncing it to the SPA just relays it to
            // a 401 "Please log in again" — the one place this GET would still need client-side
            // JavaScript, which is exactly what verifying on GET exists to avoid (keycast#268).
            let user_repo = UserRepository::new(auth_state.state.db.clone());
            match user_repo
                .find_by_verification_token(&token, tenant_id)
                .await
            {
                Ok(Some(_)) => {
                    // Not an outcome yet: the interactive POST records the terminal one.
                    emit("accepted", Some("interactive_handoff"), 303).await;
                    let interactive_url = format!(
                        "/email-verification/continue?token={}",
                        urlencoding::encode(&token)
                    );
                    Redirect::to(&interactive_url).into_response()
                }
                Ok(None) => {
                    emit("failure", Some("verification_link_superseded"), 200).await;
                    verify_link_superseded_page()
                }
                // Can't tell a dead link from a database blip, so retry rather than declaring the
                // link dead.
                Err(err) => {
                    tracing::error!(
                        tenant_id = tenant_id,
                        error = %err,
                        "Failed to resolve verification token on GET verify"
                    );
                    emit("failure", Some("database_error"), 503).await;
                    verify_html_retry_page(5)
                }
            }
        }
        // Retryable: the link may still be good, so render a non-terminal page that retries
        // itself instead of a success-looking 2xx or terminal invalid-link page.
        Err(AuthError::ServiceUnavailable { retry_after, .. }) => {
            emit("failure", Some("retryable_unavailable"), 503).await;
            verify_html_retry_page(retry_after.unwrap_or(5))
        }
        // Terminal: the email belongs to another account (mirrors the POST path's 409).
        Err(AuthError::EmailAlreadyExists) => {
            emit("failure", Some("email_already_exists"), 409).await;
            verify_html_page(
                StatusCode::CONFLICT,
                "Email already registered",
                "This email is already registered. Please log in instead.",
            )
        }
        Err(err @ AuthError::Database(_)) if matches!(&err, AuthError::Database(e) if has_database_constraint(e, USERS_EMAIL_TENANT_CONSTRAINT)) =>
        {
            emit("failure", Some("email_already_exists"), 409).await;
            verify_html_page(
                StatusCode::CONFLICT,
                "Email already registered",
                "This email is already registered. Please log in instead.",
            )
        }
        // Rate limited: the link is still good, so retry rather than declaring it dead.
        Err(AuthError::TooManyRequests { retry_after, .. }) => {
            emit("failure", Some("rate_limited"), 429).await;
            verify_html_retry_page(retry_after)
        }
        Err(
            err @ (AuthError::Database(_)
            | AuthError::PasswordHash(_)
            | AuthError::Encryption(_)
            | AuthError::Internal(_)
            | AuthError::EmailSendFailed(_)),
        ) => {
            emit("failure", Some(verify_email_reason_code(&err)), 503).await;
            verify_html_retry_page(5)
        }
        // A link that no longer resolves gets the actionable dead-link page, not a generic failure.
        Err(AuthError::VerificationLinkSuperseded) => {
            emit("failure", Some("verification_link_superseded"), 200).await;
            verify_link_superseded_page()
        }
        Err(err) => {
            emit("failure", Some(verify_email_reason_code(&err)), 200).await;
            verify_html_page(
                StatusCode::OK,
                "Verification failed",
                "This verification link is invalid or has expired. If you already verified, you can log in.",
            )
        }
    }
}

/// Low-cardinality `auth_events.endpoint` label shared by all verify-email entry paths.
pub(crate) const VERIFY_EMAIL_ENDPOINT: &str = "/api/auth/verify-email";

/// Record one verify-email attempt to the shared auth-event feed.
///
/// All verify-email entry paths emit this with the same `event_type`, differing only in
/// `metadata_json.method`, so GET and POST outcomes are directly comparable. That matters most
/// right after the switch to verifying on GET (keycast#262): the GET is now the primary path, and the
/// `verification_link_superseded` rate is the signal for whether duplicate signups
/// (keycast#268 Fix A) actually stopped in production.
async fn record_verify_email_event(
    pool: &PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
    method: &'static str,
    outcome: &'static str,
    reason_code: Option<&str>,
    http_status: i32,
) {
    super::auth_observability::record_auth_event_and_log(
        pool,
        headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint: VERIFY_EMAIL_ENDPOINT,
            event_type: "email_verification",
            outcome,
            reason_code,
            http_status,
            email: None,
            pubkey: None,
            client_id: None,
            redirect_origin: None,
            metadata_json: serde_json::json!({ "method": method }),
        },
    )
    .await;
}

/// HTTP status a verify-email failure will answer with, for the auth-event feed.
///
/// Kept in step with `AuthError`'s `IntoResponse`; only the statuses this route can actually
/// produce are enumerated, and anything else records the 503 the catch-all answers with.
fn verify_email_error_status(error: &AuthError) -> i32 {
    match error {
        AuthError::EmailAlreadyExists => 409,
        AuthError::Database(err) if has_database_constraint(err, USERS_EMAIL_TENANT_CONSTRAINT) => {
            409
        }
        AuthError::DuplicateKey
        | AuthError::Conflict(_)
        | AuthError::RegistrationAlreadyCompleted => 409,
        AuthError::VerificationLinkSuperseded | AuthError::InvalidToken => 401,
        AuthError::TooManyRequests { .. } => 429,
        AuthError::RegistrationExpired => 410,
        AuthError::BadRequest(_) | AuthError::InvalidEmail => 400,
        AuthError::Forbidden(_) | AuthError::KeyEgressDenied => 403,
        _ => 503,
    }
}

/// Classify a verify-email failure into a stable `reason_code` for the auth-event feed.
fn verify_email_reason_code(error: &AuthError) -> &'static str {
    match error {
        AuthError::ServiceUnavailable { .. } => "retryable_unavailable",
        AuthError::TooManyRequests { .. } => "rate_limited",
        AuthError::EmailAlreadyExists => "email_already_exists",
        AuthError::Database(err) if has_database_constraint(err, USERS_EMAIL_TENANT_CONSTRAINT) => {
            "email_already_exists"
        }
        AuthError::Database(_) => "database_error",
        AuthError::VerificationLinkSuperseded => "verification_link_superseded",
        AuthError::RegistrationExpired => "registration_expired",
        AuthError::RegistrationAlreadyCompleted => "registration_already_completed",
        AuthError::DuplicateKey => "account_email_conflict",
        AuthError::InvalidToken | AuthError::MissingToken | AuthError::TokenExpired => {
            "invalid_token"
        }
        _ => "other",
    }
}

/// Terminal page for a verification link that no longer resolves — already used, or replaced by a
/// newer verification email (keycast#268).
///
/// Served as 200 like the other terminal outcomes on this route: in-app browsers replace 4xx/5xx
/// bodies with their own error chrome, which would hide the one instruction that resolves this.
fn verify_link_superseded_page() -> Response {
    verify_html_page(
        StatusCode::OK,
        VERIFICATION_LINK_SUPERSEDED_HEADING,
        VERIFICATION_LINK_SUPERSEDED_MESSAGE,
    )
}

/// Render the retryable-failure page for the GET verify flow: 503 + `Retry-After` plus an HTML
/// meta refresh, so both HTTP clients and webview users (who may have no address bar to reload
/// with) retry automatically instead of reading a dead end.
fn verify_html_retry_page(retry_after_secs: u32) -> Response {
    let mut response = verify_html_page_with_refresh(
        StatusCode::SERVICE_UNAVAILABLE,
        "Almost there…",
        "We hit a temporary problem verifying your link. This page will retry automatically in a few seconds.",
        Some(retry_after_secs),
    );
    if let Ok(value) = retry_after_secs.to_string().parse() {
        response.headers_mut().insert("Retry-After", value);
    }
    response
}

/// Render a branded, self-contained HTML status page for the GET verify flow.
fn verify_html_page(status: StatusCode, heading: &str, message: &str) -> Response {
    verify_html_page_with_refresh(status, heading, message, None)
}

/// [`verify_html_page`] with an optional `<meta http-equiv="refresh">` interval in seconds.
fn verify_html_page_with_refresh(
    status: StatusCode,
    heading: &str,
    message: &str,
    refresh_secs: Option<u32>,
) -> Response {
    let refresh_tag = refresh_secs
        .map(|secs| format!("<meta http-equiv=\"refresh\" content=\"{secs}\">"))
        .unwrap_or_default();
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">{refresh_tag}\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"theme-color\" content=\"#072218\"><title>{heading} - {brand}</title>\
         <style>*{{box-sizing:border-box}}body{{font-family:system-ui,-apple-system,sans-serif;\
         background:#072218;color:#f7fffc;display:flex;min-height:100vh;align-items:center;\
         justify-content:center;margin:0;padding:1rem}}.card{{width:100%;max-width:420px;text-align:center;\
         background:#0f2e23;border:1px solid rgba(39,197,139,.25);border-radius:1rem;padding:2rem;\
         box-shadow:0 18px 60px rgba(0,0,0,.22)}}.brand{{display:inline-flex;flex-direction:column;\
         align-items:center;gap:2px;margin-bottom:1.5rem;text-decoration:none}}.brand img{{height:28px;\
         max-width:180px}}.brand span{{color:#27c58b;font-size:11px;font-weight:600;letter-spacing:3px;\
         text-transform:uppercase}}h1{{font-family:system-ui,-apple-system,sans-serif;\
         font-size:1.55rem;line-height:1.2;margin:0 0 .75rem}}p{{color:#b8cbc4;margin:0;\
         font-size:.98rem;line-height:1.55}}</style></head><body><main class=\"card\">\
         <a class=\"brand\" href=\"/\"><img src=\"/divine-logo.svg\" alt=\"{brand}\">\
         <span>Login</span></a><h1>{heading}</h1><p>{message}</p></main></body></html>",
        brand = html_escape(BRAND_NAME),
        heading = html_escape(heading),
        message = html_escape(message),
    );
    (status, Html(body)).into_response()
}

/// Minimal HTML-escaping for the small set of static status strings rendered above.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    /// Email address (optional if using Bearer token auth)
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResendVerificationResponse {
    pub success: bool,
    pub message: String,
}

/// Resend email verification.
///
/// Accepts either:
/// - Bearer token in Authorization header (existing users with session)
/// - Email address in request body (headless flow, no session yet)
///
/// Always returns success to prevent email enumeration attacks.
pub async fn resend_verification(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(mut req): Json<ResendVerificationRequest>,
) -> Json<ResendVerificationResponse> {
    let tenant_id = tenant.0.id;
    if let Some(ref mut email) = req.email {
        *email = email.to_lowercase();
    }

    // Try to get user identity from token first, then fall back to email
    let lookup_result: Option<(String, String, bool, Option<chrono::DateTime<chrono::Utc>>)> =
        if let Ok(user_pubkey) = extract_user_from_token(&headers, tenant_id).await {
            // Authenticated: look up by pubkey
            let user_repo = UserRepository::new(pool.clone());
            match user_repo
                .get_verification_status(&user_pubkey, tenant_id)
                .await
            {
                Ok(Some((email, verified, last_sent))) => {
                    Some((user_pubkey, email, verified, last_sent))
                }
                _ => None,
            }
        } else if let Some(ref email) = req.email {
            // Unauthenticated: look up by email
            let user_repo = UserRepository::new(pool.clone());
            match user_repo
                .get_verification_status_by_email(email, tenant_id)
                .await
            {
                Ok(Some((pubkey, verified, last_sent))) => {
                    Some((pubkey, email.clone(), verified, last_sent))
                }
                _ => None,
            }
        } else {
            None
        };

    // Always return success to prevent enumeration
    let success_response = Json(ResendVerificationResponse {
        success: true,
        message: "If this email is registered, you will receive a verification email shortly."
            .to_string(),
    });

    let Some((pubkey, email, email_verified, last_sent)) = lookup_result else {
        // User not found - return success anyway to prevent enumeration
        tracing::debug!("Resend verification: user not found (not leaking this to client)");
        return success_response;
    };

    // Already verified - return success (don't leak verification status)
    if email_verified {
        tracing::debug!("Resend verification: email already verified for {}", email);
        return success_response;
    }

    // Rate limit: 1 per 5 minutes
    if let Some(sent_at) = last_sent {
        let minutes_since = (Utc::now() - sent_at).num_minutes();
        if minutes_since < 5 {
            tracing::debug!(
                "Resend verification: rate limited for {} ({} minutes since last send)",
                email,
                minutes_since
            );
            // Return success anyway - don't reveal rate limiting to potential attackers
            return success_response;
        }
    }

    // Generate new verification token
    let verification_token = generate_secure_token();
    let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

    let user_repo = UserRepository::new(pool.clone());
    if let Err(e) = user_repo
        .set_verification_token(
            &pubkey,
            tenant_id,
            &verification_token,
            verification_expires,
        )
        .await
    {
        tracing::error!("Failed to set verification token: {}", e);
        return success_response;
    }

    // Send verification email (don't await to prevent timing attacks)
    let email_clone = email.clone();
    let token_clone = verification_token.clone();
    tokio::spawn(async move {
        match crate::email_service::EmailService::new() {
            Ok(email_service) => {
                if let Err(e) = email_service
                    .send_verification_email(&email_clone, &token_clone, None)
                    .await
                {
                    tracing::error!(
                        "Failed to send verification email to {}: {}",
                        email_clone,
                        e
                    );
                } else {
                    tracing::info!("Sent verification email to {}", email_clone);
                }
            }
            Err(e) => {
                tracing::warn!("Email service unavailable: {}", e);
            }
        }
    });

    success_response
}

/// Request password reset email
pub async fn forgot_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(mut req): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let endpoint = "/api/auth/forgot-password";
    req.email = req.email.to_lowercase();
    tracing::info!(
        "Password reset requested for email: {} in tenant: {}",
        req.email,
        tenant_id
    );

    // Check if user exists in this tenant
    let user_repo = UserRepository::new(pool.clone());
    let user_pubkey = user_repo
        .find_pubkey_by_email(&req.email, tenant_id)
        .await?;

    // Always return success even if email doesn't exist (security best practice)
    let public_key = match user_pubkey {
        Some(pubkey) => pubkey,
        None => {
            super::auth_observability::record_auth_event_and_log(
                &pool,
                &headers,
                None,
                super::auth_observability::AuthEvent {
                    tenant_id,
                    endpoint,
                    event_type: "password_reset_request",
                    outcome: "accepted",
                    reason_code: Some("user_not_found"),
                    http_status: 200,
                    email: Some(&req.email),
                    pubkey: None,
                    client_id: None,
                    redirect_origin: None,
                    metadata_json: serde_json::json!({}),
                },
            )
            .await;
            tracing::info!(
                "Password reset requested for non-existent email: {}",
                req.email
            );
            return Ok(Json(ForgotPasswordResponse {
                success: true,
                message:
                    "If an account exists with that email, a password reset link has been sent."
                        .to_string(),
            }));
        }
    };

    let mut reason_code = None;

    // Generate reset token
    let reset_token = generate_secure_token();
    let reset_expires = Utc::now() + Duration::hours(PASSWORD_RESET_EXPIRY_HOURS);

    // Store reset token (reusing user_repo from above)
    user_repo
        .set_password_reset_token(&public_key, tenant_id, &reset_token, reset_expires)
        .await?;

    // Send password reset email (optional - don't fail if email service unavailable)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_password_reset_email(&req.email, &reset_token)
                .await
            {
                METRICS.inc_auth_email_send_failure("password_reset");
                reason_code = Some("email_send_failed");
                tracing::error!(
                    "Failed to send password reset email to {}: {}",
                    req.email,
                    e
                );
            } else {
                tracing::info!("Sent password reset email to {}", req.email);
            }
        }
        Err(e) => {
            METRICS.inc_auth_email_send_failure("password_reset");
            reason_code = Some("email_send_failed");
            tracing::warn!(
                "Email service unavailable, skipping password reset email: {}",
                e
            );
        }
    }

    super::auth_observability::record_auth_event_and_log(
        &pool,
        &headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint,
            event_type: "password_reset_request",
            outcome: "accepted",
            reason_code,
            http_status: 200,
            email: Some(&req.email),
            pubkey: Some(&public_key),
            client_id: None,
            redirect_origin: None,
            metadata_json: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(ForgotPasswordResponse {
        success: true,
        message: "If an account exists with that email, a password reset link has been sent."
            .to_string(),
    }))
}

/// Reset password with token
pub async fn reset_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Extension(bcrypt): Extension<BcryptAdmission>,
    headers: HeaderMap,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let endpoint = "/api/auth/reset-password";
    tracing::info!(
        "Password reset attempt with token: {}... for tenant: {}",
        &req.token[..10],
        tenant_id
    );

    // Find user with this reset token in this tenant
    let user_repo = UserRepository::new(pool.clone());
    let (public_key, expires_at) =
        match user_repo.find_by_reset_token(&req.token, tenant_id).await? {
            Some(data) => data,
            None => {
                super::auth_observability::record_auth_event_and_log(
                    &pool,
                    &headers,
                    None,
                    super::auth_observability::AuthEvent {
                        tenant_id,
                        endpoint,
                        event_type: "password_reset",
                        outcome: "failure",
                        reason_code: Some("invalid_token"),
                        http_status: 401,
                        email: None,
                        pubkey: None,
                        client_id: None,
                        redirect_origin: None,
                        metadata_json: serde_json::json!({}),
                    },
                )
                .await;
                return Err(AuthError::InvalidToken);
            }
        };
    let account_email: Option<String> = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2",
    )
    .bind(&public_key)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    // Check if token is expired
    if let Some(expires) = expires_at {
        if expires < Utc::now() {
            super::auth_observability::record_auth_event_and_log(
                &pool,
                &headers,
                None,
                super::auth_observability::AuthEvent {
                    tenant_id,
                    endpoint,
                    event_type: "password_reset",
                    outcome: "failure",
                    reason_code: Some("token_expired"),
                    http_status: 200,
                    email: account_email.as_deref(),
                    pubkey: Some(&public_key),
                    client_id: None,
                    redirect_origin: None,
                    metadata_json: serde_json::json!({}),
                },
            )
            .await;
            return Ok(Json(ResetPasswordResponse {
                success: false,
                message: "Password reset link has expired. Please request a new one.".to_string(),
            }));
        }
    }

    let password_hash = bcrypt
        .hash(
            BcryptWorkload::Account,
            SecretString::from(req.new_password.clone()),
            DEFAULT_COST,
        )
        .await
        .map_err(bcrypt_auth_error)?;

    // Update password, clear reset token, and mark email as verified
    // (user proved email ownership by receiving and using the reset link)
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .reset_password(&public_key, tenant_id, &password_hash)
        .await?;

    super::auth_observability::record_auth_event_and_log(
        &pool,
        &headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint,
            event_type: "password_reset",
            outcome: "success",
            reason_code: Some("password_hash_updated"),
            http_status: 200,
            email: account_email.as_deref(),
            pubkey: Some(&public_key),
            client_id: None,
            redirect_origin: None,
            metadata_json: serde_json::json!({}),
        },
    )
    .await;

    tracing::info!(
        event = "password_reset",
        tenant_id = tenant_id,
        success = true,
        "Password reset successfully (email now verified)"
    );

    Ok(Json(ResetPasswordResponse {
        success: true,
        message: "Password reset successfully! You can now log in with your new password."
            .to_string(),
    }))
}

/// Get username for NIP-05 - the only profile data we store server-side
pub async fn get_profile(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<ProfileData>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    tracing::info!(
        "Fetching username for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    // Get username from users table - this is the ONLY thing we store
    // The client should fetch actual kind 0 profile data from Nostr relays via bunker
    let user_repo = UserRepository::new(pool.clone());
    let username = user_repo
        .get_username(&user_pubkey, tenant_id)
        .await?
        .flatten();
    let nip05_domain = resolve_nip05_domain(&tenant.0.domain);
    let nip05 = username
        .as_ref()
        .map(|username| format!("{}@{}", username, nip05_domain));

    // Return only username - client fetches rest from relays
    Ok(Json(ProfileData {
        username,
        name: None,
        about: None,
        picture: None,
        banner: None,
        nip05,
        website: None,
        lud16: None,
    }))
}

/// Get account status including email verification state
pub async fn get_account_status(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<AccountStatusResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    tracing::debug!(
        "Fetching account status for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo
        .get_account_status_with_minor(&user_pubkey, tenant_id)
        .await?;

    match user {
        Some(AccountStatusWithMinorRow {
            email,
            email_verified,
            status,
            suspended_reason,
            verified_minor,
            verified_minor_at,
        }) => Ok(Json(AccountStatusResponse::from_account_row(
            user_pubkey,
            email,
            email_verified,
            status,
            suspended_reason,
            verified_minor,
            verified_minor_at,
        ))),
        None => Err(AuthError::UserNotFound),
    }
}

/// Update username (for NIP-05) - the only profile data we store server-side
/// Client should publish kind 0 profile events to relays via bunker URL
/// Also syncs username to divine-name-server for NIP-05 on divine.video
pub async fn update_profile(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(profile): Json<ProfileData>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    tracing::info!(
        "Updating username for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    // Track divine-name-server sync result
    let mut divine_names_result: Option<Result<crate::divine_names::ClaimResponse, String>> = None;

    // Only update username - everything else is stored on Nostr relays
    if let Some(ref username_raw) = profile.username {
        let username = normalize_nip05_username(username_raw)?;

        // Check divine-name-server FIRST (if enabled) - this is the authoritative source
        if crate::divine_names::is_enabled() {
            match crate::divine_names::check_availability(&username).await {
                Ok(response) => {
                    if !response.available {
                        let same_owner_active = response.status.as_deref() == Some("active")
                            && response
                                .pubkey
                                .as_deref()
                                .is_some_and(|pubkey| pubkey.eq_ignore_ascii_case(&user_pubkey));

                        if !same_owner_active {
                            let error_msg = response
                                .reason
                                .unwrap_or_else(|| "Username is not available".to_string());
                            tracing::info!(
                                "Username '{}' not available on divine-name-server: {}",
                                username,
                                error_msg
                            );
                            return Err(AuthError::Conflict(
                                "Username is not available. Please choose another username."
                                    .to_string(),
                            ));
                        }

                        let error_msg = response
                            .reason
                            .unwrap_or_else(|| "already claimed".to_string());
                        tracing::info!(
                            "Username '{}' is already active on divine-name-server for the authenticated user: {}",
                            username,
                            error_msg
                        );
                    }
                }
                Err(e) => {
                    // If we can't reach divine-name-server, log but continue with local check
                    // This prevents divine-name-server outages from blocking all username changes
                    tracing::warn!(
                        "Failed to check divine-name-server availability for '{}': {}. Falling back to local check.",
                        username,
                        e
                    );
                }
            }
        }

        // Check if username is already taken in this tenant (local check)
        let user_repo = UserRepository::new(pool.clone());
        if !user_repo
            .check_username_available(&username, &user_pubkey, tenant_id)
            .await?
        {
            return Err(AuthError::Conflict(
                "Username is not available. Please choose another username.".to_string(),
            ));
        }

        // Sync to divine-name-server (if enabled)
        if crate::divine_names::is_enabled() {
            // Get user's keys for NIP-98 signing
            let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
            if let Ok(Some(encrypted_secret)) = personal_keys_repo
                .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
                .await
            {
                if let Ok(decrypted_secret) = key_manager.decrypt(&encrypted_secret).await {
                    if let Ok(secret_key) =
                        nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
                    {
                        let keys = Keys::new(secret_key.into());

                        // Claim username on divine-name-server
                        match crate::divine_names::claim_username(&keys, &username, None).await {
                            Ok(response) => {
                                tracing::info!(
                                    "Successfully claimed username '{}' on divine-name-server for user: {}",
                                    username,
                                    user_pubkey
                                );
                                divine_names_result = Some(Ok(response));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to claim username on divine-name-server: {}. Continuing with local update.",
                                    e
                                );
                                divine_names_result = Some(Err(e.to_string()));
                            }
                        }
                    }
                }
            }
        }

        // Update username in users table (always do local update)
        if let Err(error) = user_repo
            .update_username(&user_pubkey, &username, tenant_id)
            .await
        {
            if matches!(
                error,
                keycast_core::repositories::RepositoryError::Duplicate
            ) {
                return Err(AuthError::Conflict(
                    "Username is not available. Please choose another username.".to_string(),
                ));
            }
            return Err(error.into());
        }

        tracing::info!(
            "Username updated to '{}' for user: {}",
            username,
            user_pubkey
        );
    }

    // Build response with divine-names sync status
    let mut response = serde_json::json!({
        "success": true,
        "message": "Username saved. Client should publish kind 0 event to relays via bunker."
    });

    if let Some(result) = divine_names_result {
        match result {
            Ok(claim_response) => {
                response["divine_names"] = serde_json::json!({
                    "synced": true,
                    "nip05": claim_response.nip05,
                    "profile_url": claim_response.profile_url
                });
            }
            Err(error) => {
                response["divine_names"] = serde_json::json!({
                    "synced": false,
                    "error": error
                });
            }
        }
    }

    Ok(Json(response))
}

#[derive(Debug, Serialize)]
pub struct BunkerSession {
    pub application_name: String,
    pub redirect_origin: String,
    pub bunker_pubkey: String,
    pub client_pubkey: Option<String>,
    pub created_at: String,
    pub last_activity: Option<String>,
    pub activity_count: i64,
}

#[derive(Debug, Serialize)]
pub struct BunkerSessionsResponse {
    pub sessions: Vec<BunkerSession>,
}

/// List all active bunker sessions for the authenticated user
pub async fn list_sessions(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<BunkerSessionsResponse>, AuthError> {
    // Extract user from UCAN (supports both cookie and Bearer token)
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    tracing::info!(
        "Listing bunker sessions for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    // Get OAuth authorizations - client_id is the display name
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let oauth_sessions = oauth_auth_repo
        .list_active_sessions(&user_pubkey, tenant_id)
        .await?;

    let sessions = oauth_sessions
        .into_iter()
        .map(
            |(
                name,
                redirect_origin,
                bunker_pubkey,
                client_pubkey,
                created_at,
                last_activity,
                activity_count,
            )| {
                BunkerSession {
                    application_name: name,
                    redirect_origin,
                    bunker_pubkey,
                    client_pubkey,
                    created_at,
                    last_activity,
                    activity_count: activity_count as i64,
                }
            },
        )
        .collect();

    Ok(Json(BunkerSessionsResponse { sessions }))
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionRequest {
    pub bunker_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeSessionResponse {
    pub success: bool,
    pub message: String,
}

/// Revoke a bunker session
pub async fn revoke_session(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<RevokeSessionRequest>,
) -> Result<Json<RevokeSessionResponse>, AuthError> {
    let pool = &auth_state.state.db;
    // Extract user from UCAN (supports both cookie and Bearer token)
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    tracing::info!(
        "Revoking bunker session for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    // Verify the authorization exists and belongs to this user
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let exists = oauth_auth_repo
        .exists_active_for_bunker(&req.bunker_pubkey, &user_pubkey, tenant_id)
        .await?;

    if !exists {
        return Err(AuthError::InvalidToken);
    }

    // Soft-delete the authorization (set revoked_at for audit trail)
    oauth_auth_repo
        .revoke_by_bunker_pubkey(&req.bunker_pubkey, &user_pubkey, tenant_id)
        .await?;

    // Track OAuth authorization revoked
    METRICS.inc_oauth_revoked();

    // Signal signer daemon to remove from cache
    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx
            .send(AuthorizationCommand::Remove {
                bunker_pubkey: req.bunker_pubkey.clone(),
            })
            .await
        {
            tracing::error!("Failed to send authorization remove command: {}", e);
        } else {
            tracing::debug!("Signaled signer daemon to remove authorization");
        }
    }

    tracing::info!(
        "Successfully revoked bunker session for user: {}",
        user_pubkey
    );

    Ok(Json(RevokeSessionResponse {
        success: true,
        message: "Session revoked successfully".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DisconnectClientRequest {
    pub bunker_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct DisconnectClientResponse {
    pub success: bool,
    pub message: String,
}

/// Disconnect a NIP-46 client from a bunker session
/// This clears the connected_client_pubkey, requiring the client to reconnect
/// Useful for forcing a client to re-authenticate without fully revoking the session
pub async fn disconnect_client(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<DisconnectClientRequest>,
) -> Result<Json<DisconnectClientResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    tracing::info!(
        "Disconnecting NIP-46 client for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let rows_affected = oauth_auth_repo
        .disconnect_client(&req.bunker_pubkey, &user_pubkey, tenant_id)
        .await?;

    if rows_affected == 0 {
        return Err(AuthError::InvalidToken);
    }

    tracing::info!(
        "Successfully disconnected NIP-46 client for user: {}",
        user_pubkey
    );

    Ok(Json(DisconnectClientResponse {
        success: true,
        message: "Client disconnected - must reconnect to continue".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct PermissionDetail {
    pub application_name: String,
    pub policy_name: String,
    pub policy_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,
    /// User-friendly permission descriptions (new format)
    pub permissions: Vec<keycast_core::custom_permissions::PermissionDisplay>,
    /// Legacy: Raw allowed event kinds
    pub allowed_event_kinds: Vec<i16>,
    /// Legacy: Human-readable event kind names
    pub event_kind_names: Vec<String>,
    pub created_at: String,
    pub last_activity: Option<String>,
    pub activity_count: i64,
    /// Bunker public key - used to identify the session for activity lookups
    pub bunker_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct PermissionsResponse {
    pub permissions: Vec<PermissionDetail>,
}

/// Get detailed permissions for all active authorizations
pub async fn list_permissions(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<PermissionsResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    tracing::info!(
        "Listing permissions for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    // Get OAuth authorizations with policy and permission details
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let auth_data = oauth_auth_repo
        .list_with_policy_info(&user_pubkey, tenant_id)
        .await?;

    let mut permissions = Vec::new();
    let policy_repo = PolicyRepository::new(pool.clone());

    for (
        app_name,
        policy_id,
        policy_name,
        policy_slug,
        policy_display_name,
        policy_description,
        created_at,
        bunker_pubkey,
        last_activity,
        activity_count,
    ) in auth_data
    {
        // Load permission displays using the PolicyRepository (policies are now global)
        let permission_displays = if policy_id > 0 {
            match policy_repo.find(policy_id).await {
                Ok(policy) => policy.permission_displays(&pool).await.unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        // Get allowed event kinds from policy permissions (legacy)
        let event_kinds: Vec<i16> = if policy_id > 0 {
            if let Ok(Some(config_json)) = policy_repo.get_allowed_kinds_config(policy_id).await {
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_json) {
                    if let Some(kinds_array) =
                        config.get("allowed_kinds").and_then(|v| v.as_array())
                    {
                        kinds_array
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as i16))
                            .collect()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Convert event kinds to human-readable names
        let event_kind_names: Vec<String> = event_kinds
            .iter()
            .map(|&kind| match kind {
                0 => "Profile (kind 0)".to_string(),
                1 => "Notes (kind 1)".to_string(),
                3 => "Follows (kind 3)".to_string(),
                4 => "Encrypted DM - NIP-04 (kind 4)".to_string(),
                5 => "Deletion (kind 5)".to_string(),
                6 => "Repost (kind 6)".to_string(),
                7 => "Reaction (kind 7)".to_string(),
                16 => "Generic Repost (kind 16)".to_string(),
                44 => "Encrypted DM - NIP-44 (kind 44)".to_string(),
                1059 => "Gift Wrap (kind 1059)".to_string(),
                1984 => "Report (kind 1984)".to_string(),
                9734 => "Zap Request (kind 9734)".to_string(),
                9735 => "Zap Receipt (kind 9735)".to_string(),
                23194 | 23195 => "Wallet Operation (kind 23194-23195)".to_string(),
                _ if (10000..20000).contains(&kind) => format!("List/Data (kind {})", kind),
                _ if kind >= 30000 => format!("Long-form (kind {})", kind),
                _ => format!("Kind {}", kind),
            })
            .collect();

        permissions.push(PermissionDetail {
            application_name: app_name,
            policy_name,
            policy_id: policy_id.into(),
            policy_slug,
            policy_display_name,
            policy_description,
            permissions: permission_displays,
            allowed_event_kinds: event_kinds,
            event_kind_names,
            created_at,
            last_activity,
            activity_count: activity_count.unwrap_or(0),
            bunker_pubkey,
        });
    }

    Ok(Json(PermissionsResponse { permissions }))
}

#[derive(Debug, Deserialize)]
pub struct SignEventRequest {
    pub event: serde_json::Value, // unsigned event JSON
}

#[derive(Debug, Serialize)]
pub struct SignEventResponse {
    pub signed_event: serde_json::Value,
}

/// Look up authorization by (user_pubkey, redirect_origin, tenant_id)
/// Returns the OAuth authorization if found, None otherwise
pub async fn get_authorization_for_origin(
    pool: &PgPool,
    user_pubkey: &str,
    redirect_origin: &str,
    tenant_id: i64,
) -> Result<Option<i32>, AuthError> {
    // Returns policy_id (or None if full access)
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let policy_id = oauth_auth_repo
        .find_policy_id_by_origin(user_pubkey, redirect_origin, tenant_id)
        .await?;

    match policy_id {
        Some(pid) => Ok(pid), // Authorization exists, returns Option<i32> (None = full access)
        None => Err(AuthError::Forbidden(
            "No authorization for this origin. Create one via OAuth or /user/bunker/create"
                .to_string(),
        )),
    }
}

/// Validate that the user has permission to sign this event
/// Returns () if successful, or an error if unauthorized
pub async fn validate_signing_permissions(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    event: &UnsignedEvent,
) -> Result<(), AuthError> {
    // Get the policy_id from the user's OAuth authorization for this origin
    // NULL policy_id means "full power" - no restrictions
    let policy_id =
        get_authorization_for_origin(pool, user_pubkey, redirect_origin, tenant_id).await?;

    // NULL policy_id means full power - allow everything
    let policy_id = match policy_id {
        Some(id) => id,
        None => {
            tracing::info!(
                "✅ Permission validated for user {} to sign event kind {} in tenant {} (full access - no policy)",
                user_pubkey,
                event.kind.as_u16(),
                tenant_id
            );
            return Ok(());
        }
    };

    // Load permissions for this policy
    let policy_repo = PolicyRepository::new(pool.clone());
    let permissions = policy_repo.get_permissions(policy_id).await?;

    // Convert to custom permissions
    let custom_permissions: Result<Vec<Box<dyn CustomPermission>>, _> = permissions
        .iter()
        .map(|p| p.to_custom_permission())
        .collect();

    let custom_permissions = custom_permissions
        .map_err(|e| AuthError::Internal(format!("Failed to convert permissions: {}", e)))?;

    // Validate event against permissions (AND logic: ALL permissions must allow)
    let event_kind = event.kind.as_u16();

    // If there are no permissions, default to allow (permissive default)
    if custom_permissions.is_empty() {
        tracing::info!(
            "✅ Permission validated for user {} to sign event kind {} in tenant {} (no permission restrictions)",
            user_pubkey,
            event_kind,
            tenant_id
        );
        return Ok(());
    }

    // Check that ALL permissions allow this event (defense-in-depth)
    let allowed = custom_permissions.iter().all(|p| p.can_sign(event));

    if !allowed {
        tracing::warn!(
            "Permission denied for user {} to sign event kind {} in tenant {}",
            user_pubkey,
            event_kind,
            tenant_id
        );
        return Err(AuthError::InvalidCredentials);
    }

    tracing::info!(
        "✅ Permission validated for user {} to sign event kind {} in tenant {}",
        user_pubkey,
        event_kind,
        tenant_id
    );

    Ok(())
}

/// Validate that the user has permission to encrypt for the given pubkey
/// Returns () if successful, or an error if unauthorized
pub async fn validate_encrypt_permissions(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    plaintext: &str,
    recipient_pubkey: &PublicKey,
) -> Result<(), AuthError> {
    let policy_id =
        get_authorization_for_origin(pool, user_pubkey, redirect_origin, tenant_id).await?;

    // Parse sender pubkey
    let sender_pubkey = PublicKey::from_hex(user_pubkey)
        .map_err(|e| AuthError::Internal(format!("Invalid user pubkey: {}", e)))?;

    // NULL policy_id means full power - allow everything
    let policy_id = match policy_id {
        Some(id) => id,
        None => {
            tracing::info!(
                "✅ Encrypt permission validated for user {} to {} in tenant {} (full access - no policy)",
                user_pubkey,
                &recipient_pubkey.to_hex()[..8],
                tenant_id
            );
            return Ok(());
        }
    };

    // Load permissions for this policy
    let policy_repo = PolicyRepository::new(pool.clone());
    let permissions = policy_repo.get_permissions(policy_id).await?;

    let custom_permissions: Result<Vec<Box<dyn CustomPermission>>, _> = permissions
        .iter()
        .map(|p| p.to_custom_permission())
        .collect();

    let custom_permissions = custom_permissions
        .map_err(|e| AuthError::Internal(format!("Failed to convert permissions: {}", e)))?;

    // If there are no permissions, default to allow (permissive default)
    if custom_permissions.is_empty() {
        tracing::info!(
            "✅ Encrypt permission validated for user {} to {} in tenant {} (no permission restrictions)",
            user_pubkey,
            &recipient_pubkey.to_hex()[..8],
            tenant_id
        );
        return Ok(());
    }

    // Check that ALL permissions allow this encryption (defense-in-depth)
    let allowed = custom_permissions
        .iter()
        .all(|p| p.can_encrypt(plaintext, &sender_pubkey, recipient_pubkey));

    if !allowed {
        tracing::warn!(
            "Permission denied for user {} to encrypt to {} in tenant {}",
            user_pubkey,
            &recipient_pubkey.to_hex()[..8],
            tenant_id
        );
        return Err(AuthError::Forbidden(
            "Encryption not permitted by policy".to_string(),
        ));
    }

    tracing::info!(
        "✅ Encrypt permission validated for user {} to {} in tenant {}",
        user_pubkey,
        &recipient_pubkey.to_hex()[..8],
        tenant_id
    );

    Ok(())
}

/// Validate that the user has permission to decrypt from the given pubkey
/// Returns () if successful, or an error if unauthorized
pub async fn validate_decrypt_permissions(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    ciphertext: &str,
    sender_pubkey: &PublicKey,
) -> Result<(), AuthError> {
    let policy_id =
        get_authorization_for_origin(pool, user_pubkey, redirect_origin, tenant_id).await?;

    // Parse recipient pubkey
    let recipient_pubkey = PublicKey::from_hex(user_pubkey)
        .map_err(|e| AuthError::Internal(format!("Invalid user pubkey: {}", e)))?;

    // NULL policy_id means full power - allow everything
    let policy_id = match policy_id {
        Some(id) => id,
        None => {
            tracing::info!(
                "✅ Decrypt permission validated for user {} from {} in tenant {} (full access - no policy)",
                user_pubkey,
                &sender_pubkey.to_hex()[..8],
                tenant_id
            );
            return Ok(());
        }
    };

    // Load permissions for this policy
    let policy_repo = PolicyRepository::new(pool.clone());
    let permissions = policy_repo.get_permissions(policy_id).await?;

    let custom_permissions: Result<Vec<Box<dyn CustomPermission>>, _> = permissions
        .iter()
        .map(|p| p.to_custom_permission())
        .collect();

    let custom_permissions = custom_permissions
        .map_err(|e| AuthError::Internal(format!("Failed to convert permissions: {}", e)))?;

    // If there are no permissions, default to allow (permissive default)
    if custom_permissions.is_empty() {
        tracing::info!(
            "✅ Decrypt permission validated for user {} from {} in tenant {} (no permission restrictions)",
            user_pubkey,
            &sender_pubkey.to_hex()[..8],
            tenant_id
        );
        return Ok(());
    }

    // Check that ALL permissions allow this decryption (defense-in-depth)
    let allowed = custom_permissions
        .iter()
        .all(|p| p.can_decrypt(ciphertext, sender_pubkey, &recipient_pubkey));

    if !allowed {
        tracing::warn!(
            "Permission denied for user {} to decrypt from {} in tenant {}",
            user_pubkey,
            &sender_pubkey.to_hex()[..8],
            tenant_id
        );
        return Err(AuthError::Forbidden(
            "Decryption not permitted by policy".to_string(),
        ));
    }

    tracing::info!(
        "✅ Decrypt permission validated for user {} from {} in tenant {}",
        user_pubkey,
        &sender_pubkey.to_hex()[..8],
        tenant_id
    );

    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PubkeyResponse {
    pub pubkey: String, // hex format
    pub npub: String,   // bech32 format
}

/// Apply the verified_minor DM containment gate (support-trust-safety#183) to a
/// `/user/sign` request, on either the fast or slow path. Refusals surface the
/// uniform policy-denial message (no account-state leak); the specific reason is
/// logged server-side only. `keys` is the user's signing keypair (needed to
/// recover a kind-13 seal's recipient by trial decryption).
fn enforce_minor_dm_sign(
    keys: &Keys,
    unsigned_event: &UnsignedEvent,
    user_pubkey: &str,
) -> Result<(), AuthError> {
    keycast_core::verified_minor_dm::validate_minor_sign(keys, unsigned_event).map_err(|denied| {
        tracing::warn!(
            event = "minor_dm_gate.sign_denied",
            user_pubkey = %user_pubkey,
            kind = unsigned_event.kind.as_u16(),
            reason = %denied,
            "verified_minor DM sign refused (/user/sign)"
        );
        AuthError::Forbidden("Operation denied by policy".to_string())
    })
}

/// Fast HTTP signing endpoint - sign an event without NIP-46 relay overhead
/// This is 10-50x faster than NIP-46 for quick operations
pub async fn sign_event(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<SignEventRequest>,
) -> Result<Json<SignEventResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let (user_pubkey, redirect_origin, _bunker_pubkey) =
        extract_user_and_origin_from_token(&headers, tenant_id).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Check account status before either signing path (fast or slow)
    let user_repo = UserRepository::new(pool.clone());
    if let Some((status, _, _)) = user_repo.get_user_status(&user_pubkey, tenant_id).await? {
        if !status.is_active() {
            return Err(AuthError::Forbidden("Account restricted".to_string()));
        }
    }

    // Parse unsigned event first for validation
    let unsigned_event: UnsignedEvent = serde_json::from_value(req.event.clone())
        .map_err(|e| AuthError::Internal(format!("Invalid event format: {}", e)))?;

    // 🔒 VALIDATE PERMISSIONS BEFORE SIGNING
    validate_signing_permissions(
        pool,
        tenant_id,
        &user_pubkey,
        &redirect_origin,
        &unsigned_event,
    )
    .await?;

    // verified_minor DM containment (support-trust-safety#183) applies to BOTH
    // the fast and slow paths. Fetch the flag once here (only for DM-shaped
    // kinds) so the hot fast path returns a clean 403 too, rather than the
    // signer handler's error mapping to a 503. A missing user row fails closed.
    let verified_minor =
        if keycast_core::verified_minor_dm::is_minor_gated_kind(unsigned_event.kind) {
            user_repo
                .get_verified_minor(&user_pubkey, tenant_id)
                .await?
                .ok_or_else(|| AuthError::Forbidden("Operation denied by policy".to_string()))?
                .verified_minor
        } else {
            false
        };

    // FAST PATH: Try to use cached signer handler if in unified mode
    if let Some(ref handlers) = auth_state.state.signer_handlers {
        tracing::info!(
            "Attempting fast path signing for user: {} in tenant: {}",
            user_pubkey,
            tenant_id
        );

        // Query for user's bunker public key from any OAuth authorization
        let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
        let bunker_pubkey = oauth_auth_repo
            .find_latest_bunker_pubkey(&user_pubkey, tenant_id)
            .await?;

        if let Some(bunker_key) = bunker_pubkey {
            if let Some(handler) = handlers.get(&bunker_key).await {
                tracing::info!("✅ Using cached handler for user {}", user_pubkey);

                // DM containment on the fast path returns a clean 403 here; the
                // signer handler also gates as a backstop, but its error would
                // map to a 503 through the Internal wrapper below.
                if verified_minor {
                    enforce_minor_dm_sign(&handler.get_keys(), &unsigned_event, &user_pubkey)?;
                }

                let signed_event = handler
                    .sign_event_direct(unsigned_event)
                    .await
                    .map_err(|e| AuthError::Internal(format!("Signing failed: {}", e)))?;

                let signed_json = serde_json::to_value(&signed_event).map_err(|e| {
                    AuthError::Internal(format!("JSON serialization failed: {}", e))
                })?;

                tracing::info!(
                    "Fast path: Successfully signed event {} for user: {}",
                    signed_event.id,
                    user_pubkey
                );

                return Ok(Json(SignEventResponse {
                    signed_event: signed_json,
                }));
            }
        }
    }

    // SLOW PATH: Fallback to DB + decryption
    tracing::warn!(
        "⚠️  Handler not cached, using slow path (DB+decrypt) for user {}",
        user_pubkey
    );

    // Get user's encrypted secret key
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret = personal_keys_repo
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Decrypt the secret key (EXPENSIVE DECRYPTION!)
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // verified_minor DM containment on the slow path (support-trust-safety#183);
    // `verified_minor` was resolved once above and shared with the fast path.
    if verified_minor {
        enforce_minor_dm_sign(&keys, &unsigned_event, &user_pubkey)?;
    }

    // Permission validation already done above (before fast path check)
    // Sign the event
    let signed_event = unsigned_event
        .sign(&keys)
        .await
        .map_err(|e| AuthError::Internal(format!("Signing failed: {}", e)))?;

    // Convert to JSON
    let signed_json = serde_json::to_value(&signed_event)
        .map_err(|e| AuthError::Internal(format!("JSON serialization failed: {}", e)))?;

    tracing::info!(
        "Slow path: Successfully signed event {} for user: {}",
        signed_event.id,
        user_pubkey
    );

    Ok(Json(SignEventResponse {
        signed_event: signed_json,
    }))
}

/// Get user's public key in both hex and npub formats
pub async fn get_pubkey(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<PubkeyResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;

    tracing::info!(
        "Fetching pubkey for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    // Verify user exists in this tenant
    let user_repo = UserRepository::new(pool.clone());
    if !user_repo.exists(&user_pubkey, tenant_id).await? {
        return Err(AuthError::UserNotFound);
    }

    // Convert hex pubkey to PublicKey and then to npub
    let pubkey = PublicKey::from_hex(&user_pubkey)
        .map_err(|e| AuthError::Internal(format!("Invalid public key: {}", e)))?;

    let npub = pubkey
        .to_bech32()
        .map_err(|e| AuthError::Internal(format!("Bech32 conversion failed: {}", e)))?;

    Ok(Json(PubkeyResponse {
        pubkey: user_pubkey,
        npub,
    }))
}

// ===== KEY EXPORT ENDPOINTS =====

#[derive(Debug, Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyPasswordResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportKeyResponse {
    pub key: String,
}

/// Verify user's password before allowing key export
pub async fn verify_password_for_export(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Extension(bcrypt): Extension<BcryptAdmission>,
    headers: HeaderMap,
    Json(req): Json<VerifyPasswordRequest>,
) -> Result<Json<VerifyPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;

    // Get user's email and password hash
    let user_repo = UserRepository::new(pool.clone());
    let (_email, password_hash) = user_repo
        .get_credentials(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let valid = bcrypt
        .verify(
            BcryptWorkload::Account,
            SecretString::from(req.password.clone()),
            password_hash.clone(),
        )
        .await
        .map_err(bcrypt_auth_error)?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    Ok(Json(VerifyPasswordResponse { success: true }))
}

// ===== CHANGE PASSWORD ENDPOINT =====

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Change user's password (requires authentication and current password verification)
pub async fn change_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Extension(bcrypt): Extension<BcryptAdmission>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;

    // Validate new password length
    if req.new_password.len() < 8 {
        return Err(AuthError::BadRequest(
            "New password must be at least 8 characters".to_string(),
        ));
    }

    // Get user's current password hash
    let user_repo = UserRepository::new(pool.clone());
    let (_email, password_hash) = user_repo
        .get_credentials(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let valid = bcrypt
        .verify(
            BcryptWorkload::Account,
            SecretString::from(req.current_password.clone()),
            password_hash.clone(),
        )
        .await
        .map_err(bcrypt_auth_error)?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    let new_hash = bcrypt
        .hash(
            BcryptWorkload::Account,
            SecretString::from(req.new_password.clone()),
            DEFAULT_COST,
        )
        .await
        .map_err(bcrypt_auth_error)?;

    // Update password in database
    user_repo
        .update_password(&user_pubkey, tenant_id, &new_hash)
        .await?;

    tracing::info!(pubkey = %user_pubkey, "Password changed successfully");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Password changed successfully"
    })))
}

// ===== SELF-SERVE EMAIL CHANGE ENDPOINTS =====

#[derive(Debug, Deserialize)]
pub struct ChangeEmailRequest {
    pub new_email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ChangeEmailResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmEmailChangeRequest {
    pub token: String,
}

/// Record an auth event for the email-change flow (best-effort).
#[allow(clippy::too_many_arguments)]
async fn record_email_change_event(
    pool: &PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
    endpoint: &'static str,
    event_type: &'static str,
    outcome: &'static str,
    reason_code: Option<&str>,
    http_status: i32,
    email: Option<&str>,
    pubkey: Option<&str>,
) {
    super::auth_observability::record_auth_event_and_log(
        pool,
        headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint,
            event_type,
            outcome,
            reason_code,
            http_status,
            email,
            pubkey,
            client_id: None,
            redirect_origin: None,
            metadata_json: serde_json::json!({}),
        },
    )
    .await;
}

/// Initiate a self-serve email change.
///
/// Authenticated (UCAN) with current-password re-verification. Generates per-address tokens,
/// emails a confirmation link to the new address and a confirm/cancel notification to the old
/// address. Always returns 200 for an authenticated user (anti-enumeration on the new address).
pub async fn change_email(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Extension(bcrypt): Extension<BcryptAdmission>,
    headers: HeaderMap,
    Json(req): Json<ChangeEmailRequest>,
) -> Result<Json<ChangeEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;

    // Validate + normalize the new email (reuse the registration normalizer to prevent
    // case/dot bypass and reject anything malformed).
    let new_email = match normalize_registration_email(&req.new_email) {
        Ok(email) => email,
        Err(_) => {
            record_email_change_event(
                &pool,
                &headers,
                tenant_id,
                "/api/user/change-email",
                "email_change_request",
                "failure",
                Some("invalid_email"),
                400,
                None,
                Some(&user_pubkey),
            )
            .await;
            return Err(AuthError::InvalidEmail);
        }
    };

    let user_repo = UserRepository::new(pool.clone());

    // Re-verify the current password before allowing any change.
    let (current_email, password_hash) = user_repo
        .get_credentials(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let valid = bcrypt
        .verify(
            BcryptWorkload::Account,
            SecretString::from(req.password.clone()),
            password_hash.clone(),
        )
        .await
        .map_err(bcrypt_auth_error)?;
    if !valid {
        // Record the failed attempt — this endpoint re-verifies the password, so failures feed
        // the same abuse/brute-force monitoring as login/forgot-password.
        record_email_change_event(
            &pool,
            &headers,
            tenant_id,
            "/api/user/change-email",
            "email_change_request",
            "failure",
            Some("wrong_password"),
            401,
            Some(&new_email),
            Some(&user_pubkey),
        )
        .await;
        return Err(AuthError::InvalidCredentials);
    }

    // No-op if the address is unchanged.
    if new_email == current_email {
        return Ok(Json(ChangeEmailResponse {
            success: true,
            message: "That is already your email address.".to_string(),
        }));
    }

    let ok_response = Json(ChangeEmailResponse {
        success: true,
        message: "Check both your current and new email to confirm the change.".to_string(),
    });

    // Resend cooldown: rate-limit re-initiations of the *same* target. The prior emails are still
    // valid, so we just tell the user to check their inbox. A change to a *different* address is a
    // new request that supersedes the prior one, so it bypasses the cooldown (otherwise correcting
    // a typo'd address within the window would silently fail). The endpoint is password-gated on
    // every call, so the residual "send to alternating targets" rate is bounded by request auth.
    if let Ok(Some((Some(existing_target), Some(last_sent)))) = user_repo
        .pending_email_send_state(&user_pubkey, tenant_id)
        .await
    {
        if existing_target == new_email
            && Utc::now() - last_sent < Duration::minutes(EMAIL_CHANGE_RESEND_COOLDOWN_MINUTES)
        {
            // Honest message: nothing fresh was sent, the earlier links are still valid.
            return Ok(Json(ChangeEmailResponse {
                success: true,
                message:
                    "We recently sent confirmation links for this change. Please check your inbox."
                        .to_string(),
            }));
        }
    }

    // Anti-enumeration: if the new email is already registered, return success without sending
    // or storing anything, so the endpoint can't be used to probe for registered addresses.
    if user_repo
        .find_pubkey_by_email(&new_email, tenant_id)
        .await?
        .is_some()
    {
        record_email_change_event(
            &pool,
            &headers,
            tenant_id,
            "/api/user/change-email",
            "email_change_request",
            "accepted",
            Some("email_already_registered"),
            200,
            Some(&new_email),
            Some(&user_pubkey),
        )
        .await;
        return Ok(ok_response);
    }

    // Generate per-address tokens and store the pending change (overwrites any prior pending
    // change, naturally cancelling it).
    let old_token = generate_secure_token();
    let new_token = generate_secure_token();
    let expires = Utc::now() + Duration::hours(EMAIL_CHANGE_EXPIRY_HOURS);
    user_repo
        .set_pending_email_change(
            &user_pubkey,
            tenant_id,
            &new_email,
            &old_token,
            &new_token,
            expires,
        )
        .await?;

    // Best-effort sends; don't fail the flow if email delivery is unavailable.
    match crate::email_service::EmailService::new() {
        Ok(svc) => {
            if let Err(e) = svc
                .send_email_change_confirmation(&new_email, &new_token)
                .await
            {
                tracing::error!("Failed to send email-change confirmation: {}", e);
            }
            // The old-address token serves both confirm and cancel; the action is distinguished
            // by endpoint (/confirm-email-change vs /cancel-email-change), not by a separate token.
            if let Err(e) = svc
                .send_email_change_notification(&current_email, &new_email, &old_token, &old_token)
                .await
            {
                tracing::error!("Failed to send email-change notification: {}", e);
            }
        }
        Err(e) => tracing::warn!("Email service unavailable: {}", e),
    }

    record_email_change_event(
        &pool,
        &headers,
        tenant_id,
        "/api/user/change-email",
        "email_change_request",
        "accepted",
        None,
        200,
        Some(&new_email),
        Some(&user_pubkey),
    )
    .await;

    Ok(ok_response)
}

/// Confirm one side of a pending email change. Finalizes atomically once both sides confirm.
/// Token-based, unauthenticated (the token proves control of the address it was sent to).
pub async fn confirm_email_change(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ConfirmEmailChangeRequest>,
) -> Result<Json<ChangeEmailResponse>, AuthError> {
    use keycast_core::repositories::FinalizeEmailOutcome;

    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(pool.clone());

    let (pending, side) = user_repo
        .find_by_pending_email_token(&req.token, tenant_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    // Expiry check (treat a missing expiry as expired).
    if pending
        .pending_email_expires_at
        .is_none_or(|e| e < Utc::now())
    {
        return Err(AuthError::TokenExpired);
    }

    // Token-gated: if a concurrent re-initiation rotated the tokens after we resolved the side,
    // this marks no row and the token belongs to a change that has since been superseded. Surface
    // that distinctly from a bogus token: the link was real, just replaced by a newer request.
    let confirmed = user_repo
        .mark_pending_email_confirmed(&pending.pubkey, tenant_id, side, &req.token)
        .await?;
    if !confirmed {
        return Err(AuthError::Conflict(
            "This email change request was superseded by a newer one. Please use the most recent confirmation link.".to_string(),
        ));
    }

    // Finalize atomically iff both sides have now confirmed. Doing the both-confirmed check and
    // the swap in one UPDATE avoids a race when both links are clicked concurrently (each request
    // marks its own side, and whichever finalize runs after both marks commit applies the swap).
    match user_repo
        .finalize_email_change_if_ready(&pending.pubkey, tenant_id)
        .await?
    {
        FinalizeEmailOutcome::Finalized => {
            record_email_change_event(
                &pool,
                &headers,
                tenant_id,
                "/api/auth/confirm-email-change",
                "email_change",
                "success",
                Some("finalized"),
                200,
                pending.pending_email.as_deref(),
                Some(&pending.pubkey),
            )
            .await;
            Ok(Json(ChangeEmailResponse {
                success: true,
                message: "Your email address has been updated.".to_string(),
            }))
        }
        FinalizeEmailOutcome::EmailTaken => Err(AuthError::Conflict(
            "That email address is no longer available.".to_string(),
        )),
        FinalizeEmailOutcome::NotReady => Ok(Json(ChangeEmailResponse {
            success: true,
            message: "Confirmed. Waiting for the other address to confirm.".to_string(),
        })),
    }
}

/// Cancel a pending email change. Token-bound (old- or new-address token); returns a generic
/// response whether or not a pending change existed, so it leaks nothing.
pub async fn cancel_email_change(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ConfirmEmailChangeRequest>,
) -> Result<Json<ChangeEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(pool.clone());

    if let Some((pending, _side)) = user_repo
        .find_by_pending_email_token(&req.token, tenant_id)
        .await?
    {
        // Token-gated clear: a cancel link whose change was superseded by a concurrent
        // re-initiation must not wipe the fresh change. Only audit an actual cancellation.
        let cleared = user_repo
            .clear_pending_email_change_by_token(&pending.pubkey, tenant_id, &req.token)
            .await?;
        if cleared {
            record_email_change_event(
                &pool,
                &headers,
                tenant_id,
                "/api/auth/cancel-email-change",
                "email_change",
                "success",
                Some("cancelled"),
                200,
                pending.pending_email.as_deref(),
                Some(&pending.pubkey),
            )
            .await;
        }
    }

    Ok(Json(ChangeEmailResponse {
        success: true,
        message: "The email change has been cancelled.".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ChangeKeyRequest {
    pub password: String,
    pub nsec: Option<String>, // If None, auto-generate new key
}

#[derive(Debug, Serialize)]
pub struct ChangeKeyResponse {
    pub success: bool,
    pub new_pubkey: String,
    pub message: String,
}

/// Refuse a raw-key egress operation (export-key / change-key) for a
/// `verified_minor` account (support-trust-safety#188).
///
/// This is the server-side complement to the app-side affordance removal
/// (#182): Keycast holds the key for a custodial minor, so an ungated
/// export/change-key over the headless API would let the minor extract or swap
/// their key with just their password and bypass every other guardrail. Called
/// at the top of the handler, before the password check and before any key
/// material is touched, so the least code runs between authentication and the
/// refusal. The block lifts automatically when `verified_minor` is cleared
/// (age-up / revocation) — the same flag that drives the DM gate.
///
/// Fail closed: only an explicit non-minor status proceeds; `verified_minor` OR
/// an unresolvable account (no row) is refused. The uniform policy-denial
/// message leaks no account state; the specific reason is logged server-side.
async fn refuse_key_egress_for_verified_minor(
    user_repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    operation: &str,
) -> Result<(), AuthError> {
    let is_non_minor = matches!(
        user_repo.get_verified_minor(user_pubkey, tenant_id).await?,
        Some(VerifiedMinorRow {
            verified_minor: false,
            ..
        })
    );
    if !is_non_minor {
        tracing::warn!(
            event = "minor_key_egress_denied",
            user_pubkey = %user_pubkey,
            operation = %operation,
            "verified_minor raw-key egress refused"
        );
        return Err(AuthError::KeyEgressDenied);
    }
    Ok(())
}

/// Build an auth event for one raw-key egress outcome.
#[allow(clippy::too_many_arguments)]
fn key_egress_event_record(
    headers: &HeaderMap,
    tenant_id: i64,
    endpoint: &'static str,
    outcome: &'static str,
    reason_code: Option<&str>,
    http_status: i32,
    pubkey: &str,
    metadata_json: serde_json::Value,
) -> keycast_core::repositories::AuthEventRecord {
    super::auth_observability::auth_event_record_and_log(
        headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint,
            event_type: KEY_EGRESS_EVENT_TYPE,
            outcome,
            reason_code,
            http_status,
            email: None,
            pubkey: Some(pubkey),
            client_id: None,
            redirect_origin: None,
            metadata_json,
        },
    )
}

/// Record one raw-key egress outcome in its own short database operation.
#[allow(clippy::too_many_arguments)]
async fn record_key_egress_event(
    pool: &PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
    endpoint: &'static str,
    outcome: &'static str,
    reason_code: Option<&str>,
    http_status: i32,
    pubkey: &str,
    metadata_json: serde_json::Value,
) -> Result<(), AuthError> {
    let record = key_egress_event_record(
        headers,
        tenant_id,
        endpoint,
        outcome,
        reason_code,
        http_status,
        pubkey,
        metadata_json,
    );
    AuthEventRepository::new(pool.clone())
        .record(record)
        .await?;
    Ok(())
}

/// Record one raw-key egress outcome inside the caller's transaction.
#[allow(clippy::too_many_arguments)]
async fn record_key_egress_event_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    tenant_id: i64,
    endpoint: &'static str,
    outcome: &'static str,
    reason_code: Option<&str>,
    http_status: i32,
    pubkey: &str,
    metadata_json: serde_json::Value,
) -> Result<(), AuthError> {
    let record = key_egress_event_record(
        headers,
        tenant_id,
        endpoint,
        outcome,
        reason_code,
        http_status,
        pubkey,
        metadata_json,
    );
    AuthEventRepository::record_in_transaction(tx, record).await?;
    Ok(())
}

fn key_egress_unavailable(message: &str) -> AuthError {
    AuthError::ServiceUnavailable {
        message: message.to_string(),
        retry_after: Some(1),
    }
}

fn password_verification_error(error: BcryptAdmissionError) -> AuthError {
    tracing::error!(
        error = %error,
        "raw-key egress password verification unavailable"
    );
    key_egress_unavailable("Password verification is temporarily unavailable. Please retry.")
}

async fn reserve_key_egress_attempt(
    redis: Option<&crate::PrefixedRedis>,
    tenant_id: i64,
    current_pubkey: &str,
    endpoint: &'static str,
) -> Result<KeyEgressReservation, AuthError> {
    let redis = redis.ok_or_else(|| {
        key_egress_unavailable("Key egress protection is temporarily unavailable. Please retry.")
    })?;
    match KeyEgressLimiter::new(redis.clone())
        .reserve(tenant_id, current_pubkey)
        .await
    {
        Ok(KeyEgressAdmission::Reserved(reservation)) => Ok(reservation),
        Ok(KeyEgressAdmission::Locked { retry_after }) => {
            // The fifth durable wrong-password audit row records entry into
            // lockout. Preserve aggregate denial volume here without making
            // each subsequent refusal a synchronous database write.
            METRICS.observe_auth_request(
                endpoint,
                "failure",
                Some("rate_limited"),
                StdDuration::ZERO,
            );
            tracing::warn!(
                event = "key_egress_rate_limited",
                endpoint,
                retry_after_seconds = retry_after,
                "raw-key egress refused after repeated wrong passwords"
            );
            Err(AuthError::TooManyRequests {
                message: "Too many incorrect passwords. Please wait before trying again."
                    .to_string(),
                retry_after,
            })
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "raw-key egress Redis admission failed"
            );
            Err(key_egress_unavailable(
                "Key egress protection is temporarily unavailable. Please retry.",
            ))
        }
    }
}

async fn begin_key_egress_attempt(
    bcrypt: &BcryptAdmission,
    redis: Option<&crate::PrefixedRedis>,
    tenant_id: i64,
    current_pubkey: &str,
    endpoint: &'static str,
) -> Result<(BcryptPermit, KeyEgressReservation, tokio::time::Instant), AuthError> {
    // CPU admission must happen before Redis admission: waiting for scarce
    // bcrypt capacity must never consume one of the account's attempt leases.
    let verifier = bcrypt
        .reserve(BcryptWorkload::Account, BcryptOperation::Verify)
        .await
        .map_err(password_verification_error)?;
    let reserved_work_deadline = tokio::time::Instant::now() + KEY_EGRESS_RESERVED_WORK_DEADLINE;
    let reservation =
        reserve_key_egress_attempt(redis, tenant_id, current_pubkey, endpoint).await?;
    Ok((verifier, reservation, reserved_work_deadline))
}

async fn release_key_egress_reservation(
    reservation: KeyEgressReservation,
) -> Result<(), AuthError> {
    match tokio::time::timeout(KEY_EGRESS_FINALIZATION_DEADLINE, reservation.release()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            tracing::error!(
                error = %error,
                "raw-key egress reservation release failed"
            );
            Err(key_egress_unavailable(
                "Key egress protection is temporarily unavailable. Please retry.",
            ))
        }
        Err(_) => Err(key_egress_unavailable(
            "Key egress protection timed out. Please retry.",
        )),
    }
}

async fn record_key_egress_failure(reservation: KeyEgressReservation) -> Result<(), AuthError> {
    match tokio::time::timeout(
        KEY_EGRESS_FINALIZATION_DEADLINE,
        reservation.record_failure(),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            tracing::error!(
                error = %error,
                "raw-key egress failure conversion failed"
            );
            Err(key_egress_unavailable(
                "Key egress protection is temporarily unavailable. Please retry.",
            ))
        }
        Err(_) => Err(key_egress_unavailable(
            "Key egress protection timed out. Please retry.",
        )),
    }
}

/// Enforce the policy gate that must outrank password-attempt state.
async fn enforce_key_egress_policy(
    pool: &PgPool,
    headers: &HeaderMap,
    user_repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    endpoint: &'static str,
    operation: &str,
) -> Result<(), AuthError> {
    match refuse_key_egress_for_verified_minor(user_repo, tenant_id, user_pubkey, operation).await {
        Ok(()) => Ok(()),
        Err(AuthError::KeyEgressDenied) => {
            record_key_egress_event(
                pool,
                headers,
                tenant_id,
                endpoint,
                "failure",
                Some("policy_denied"),
                403,
                user_pubkey,
                serde_json::json!({}),
            )
            .await?;
            Err(AuthError::KeyEgressDenied)
        }
        Err(error) => Err(error),
    }
}

/// Export user's private key (requires password and verified email)
pub async fn export_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ExportKeyResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let user_repo = UserRepository::new(pool.clone());

    enforce_key_egress_policy(
        pool,
        &headers,
        &user_repo,
        tenant_id,
        &user_pubkey,
        EXPORT_KEY_ENDPOINT,
        "export_key",
    )
    .await?;

    let password = match req.get("password").and_then(|v| v.as_str()) {
        Some(password) => password.to_string(),
        None => {
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                EXPORT_KEY_ENDPOINT,
                "failure",
                Some("missing_password"),
                400,
                &user_pubkey,
                serde_json::json!({}),
            )
            .await?;
            return Err(AuthError::BadRequest("Missing password".to_string()));
        }
    };

    let format = req
        .get("format")
        .and_then(|value| value.as_str())
        .unwrap_or("nsec")
        .to_string();

    // CPU admission happens before Redis reservation. Waiting for verifier
    // capacity therefore cannot consume an attempt slot.
    let (verifier, reservation, reserved_work_deadline) = begin_key_egress_attempt(
        &auth_state.state.bcrypt,
        auth_state.state.redis.as_ref(),
        tenant_id,
        &user_pubkey,
        EXPORT_KEY_ENDPOINT,
    )
    .await?;

    enum PasswordOutcome {
        Correct,
        Incorrect,
        EmailNotVerified,
    }

    let password_outcome = tokio::time::timeout_at(reserved_work_deadline, async {
        let result = user_repo
            .find_with_password_and_verified(&user_pubkey, tenant_id)
            .await?;
        let (_email, password_hash, email_verified) = result.ok_or(AuthError::UserNotFound)?;
        if !email_verified {
            return Ok::<PasswordOutcome, AuthError>(PasswordOutcome::EmailNotVerified);
        }
        let valid = verifier
            .verify(SecretString::from(password), password_hash)
            .await
            .map_err(password_verification_error)?;
        Ok(if valid {
            PasswordOutcome::Correct
        } else {
            PasswordOutcome::Incorrect
        })
    })
    .await;

    match password_outcome {
        Err(_) => {
            release_key_egress_reservation(reservation).await?;
            return Err(key_egress_unavailable(
                "Password verification timed out. Please retry.",
            ));
        }
        Ok(Err(error)) => {
            release_key_egress_reservation(reservation).await?;
            return Err(error);
        }
        Ok(Ok(PasswordOutcome::EmailNotVerified)) => {
            release_key_egress_reservation(reservation).await?;
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                EXPORT_KEY_ENDPOINT,
                "failure",
                Some("email_not_verified"),
                403,
                &user_pubkey,
                serde_json::json!({}),
            )
            .await?;
            return Err(AuthError::EmailNotVerified);
        }
        Ok(Ok(PasswordOutcome::Incorrect)) => {
            // Redis is the security counter. Convert before the forensic DB
            // audit so an audit failure cannot refund the attempt.
            record_key_egress_failure(reservation).await?;
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                EXPORT_KEY_ENDPOINT,
                "failure",
                Some(KEY_EGRESS_INVALID_PASSWORD_REASON),
                401,
                &user_pubkey,
                serde_json::json!({}),
            )
            .await?;
            return Err(AuthError::InvalidCredentials);
        }
        Ok(Ok(PasswordOutcome::Correct)) => {
            release_key_egress_reservation(reservation).await?;
        }
    }

    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_key = match personal_keys_repo
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await?
    {
        Some(encrypted_key) => encrypted_key,
        None => {
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                EXPORT_KEY_ENDPOINT,
                "failure",
                Some("missing_personal_key"),
                404,
                &user_pubkey,
                serde_json::json!({}),
            )
            .await?;
            return Err(AuthError::UserNotFound);
        }
    };

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_key)
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to decrypt key: {}", e)))?;

    let keys = Keys::parse(&hex::encode(&decrypted_secret))
        .map_err(|e| AuthError::Internal(format!("Failed to parse key: {}", e)))?;

    let key_string = match format.as_str() {
        "nsec" => keys
            .secret_key()
            .to_bech32()
            .map_err(|e| AuthError::Internal(format!("Failed to encode nsec: {}", e)))?,
        _ => {
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                EXPORT_KEY_ENDPOINT,
                "failure",
                Some("invalid_format"),
                400,
                &user_pubkey,
                serde_json::json!({ "format": format }),
            )
            .await?;
            return Err(AuthError::BadRequest(
                "Invalid format. Must be 'nsec'".to_string(),
            ));
        }
    };

    record_key_egress_event(
        pool,
        &headers,
        tenant_id,
        EXPORT_KEY_ENDPOINT,
        "success",
        None,
        200,
        &user_pubkey,
        serde_json::json!({}),
    )
    .await?;

    Ok(Json(ExportKeyResponse { key: key_string }))
}

/// Change user's private key - transfers email login to new identity
/// WARNING: Deletes all OAuth authorizations (bunker connections)
pub async fn change_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<ChangeKeyRequest>,
) -> Result<Response, AuthError> {
    let tenant_id = tenant.0.id;
    let old_pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let user_repo = UserRepository::new(pool.clone());
    let ChangeKeyRequest { password, nsec } = req;
    let byok = nsec.is_some();

    enforce_key_egress_policy(
        pool,
        &headers,
        &user_repo,
        tenant_id,
        &old_pubkey,
        CHANGE_KEY_ENDPOINT,
        "change_key",
    )
    .await?;

    let (verifier, reservation, reserved_work_deadline) = begin_key_egress_attempt(
        &auth_state.state.bcrypt,
        auth_state.state.redis.as_ref(),
        tenant_id,
        &old_pubkey,
        CHANGE_KEY_ENDPOINT,
    )
    .await?;

    enum ChangePasswordOutcome {
        Correct {
            email: String,
            password_hash: String,
        },
        Incorrect,
    }

    let password_outcome = tokio::time::timeout_at(reserved_work_deadline, async {
        let (email, password_hash) = user_repo
            .get_credentials(&old_pubkey, tenant_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let valid = verifier
            .verify(SecretString::from(password), password_hash.clone())
            .await
            .map_err(password_verification_error)?;
        Ok::<ChangePasswordOutcome, AuthError>(if valid {
            ChangePasswordOutcome::Correct {
                email,
                password_hash,
            }
        } else {
            ChangePasswordOutcome::Incorrect
        })
    })
    .await;

    let (email, password_hash) = match password_outcome {
        Err(_) => {
            release_key_egress_reservation(reservation).await?;
            return Err(key_egress_unavailable(
                "Password verification timed out. Please retry.",
            ));
        }
        Ok(Err(error)) => {
            release_key_egress_reservation(reservation).await?;
            return Err(error);
        }
        Ok(Ok(ChangePasswordOutcome::Incorrect)) => {
            record_key_egress_failure(reservation).await?;
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                CHANGE_KEY_ENDPOINT,
                "failure",
                Some(KEY_EGRESS_INVALID_PASSWORD_REASON),
                401,
                &old_pubkey,
                serde_json::json!({}),
            )
            .await?;
            return Err(AuthError::InvalidCredentials);
        }
        Ok(Ok(ChangePasswordOutcome::Correct {
            email,
            password_hash,
        })) => {
            release_key_egress_reservation(reservation).await?;
            (email, password_hash)
        }
    };

    let new_keys = if let Some(ref nsec_string) = nsec {
        tracing::info!("User provided new key (BYOK) for change");
        match Keys::parse(nsec_string) {
            Ok(keys) => keys,
            Err(error) => {
                record_key_egress_event(
                    pool,
                    &headers,
                    tenant_id,
                    CHANGE_KEY_ENDPOINT,
                    "failure",
                    Some("invalid_nsec"),
                    500,
                    &old_pubkey,
                    serde_json::json!({ "byok": true }),
                )
                .await?;
                return Err(AuthError::Internal(format!(
                    "Invalid nsec or secret key: {error}"
                )));
            }
        }
    } else {
        tracing::info!("Auto-generating new key for change");
        Keys::generate()
    };

    let new_pubkey = new_keys.public_key().to_hex();
    let new_secret_bytes = new_keys.secret_key().to_secret_bytes();

    if user_repo.exists(&new_pubkey, tenant_id).await? {
        record_key_egress_event(
            pool,
            &headers,
            tenant_id,
            CHANGE_KEY_ENDPOINT,
            "failure",
            Some("duplicate_key"),
            409,
            &old_pubkey,
            serde_json::json!({
                "new_pubkey": new_pubkey,
                "byok": byok,
            }),
        )
        .await?;
        return Err(AuthError::DuplicateKey);
    }

    let encrypted_secret = match key_manager.encrypt(&new_secret_bytes).await {
        Ok(encrypted_secret) => encrypted_secret,
        Err(error) => {
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                CHANGE_KEY_ENDPOINT,
                "failure",
                Some("encryption_failed"),
                500,
                &old_pubkey,
                serde_json::json!({
                    "new_pubkey": new_pubkey,
                    "byok": byok,
                }),
            )
            .await?;
            return Err(AuthError::Encryption(error.to_string()));
        }
    };

    // Every fallible response input is ready before custody can mutate.
    let redirect_origin = extract_origin_from_headers(&headers)?;
    let ucan_token =
        generate_ucan_token(&new_keys, tenant_id, &email, &redirect_origin, None, None).await?;
    let cookie = format!(
        "keycast_session={ucan_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400"
    );

    let mutation = async {
        let mut transaction = pool.begin().await?;
        let oauth_count = user_repo
            .change_key_in_transaction(
                &mut transaction,
                &old_pubkey,
                &new_pubkey,
                tenant_id,
                &email,
                &password_hash,
                &encrypted_secret,
            )
            .await?;
        record_key_egress_event_in_transaction(
            &mut transaction,
            &headers,
            tenant_id,
            CHANGE_KEY_ENDPOINT,
            "success",
            None,
            200,
            &old_pubkey,
            serde_json::json!({
                "new_pubkey": new_pubkey,
                "byok": byok,
                "oauth_authorizations_deleted": oauth_count,
            }),
        )
        .await?;
        transaction.commit().await?;
        Ok::<i64, AuthError>(oauth_count)
    }
    .await;

    let oauth_count = match mutation {
        Ok(oauth_count) => oauth_count,
        Err(error) => {
            record_key_egress_event(
                pool,
                &headers,
                tenant_id,
                CHANGE_KEY_ENDPOINT,
                "failure",
                Some("change_key_failed"),
                500,
                &old_pubkey,
                serde_json::json!({
                    "new_pubkey": new_pubkey,
                    "byok": byok,
                }),
            )
            .await?;
            return Err(error);
        }
    };

    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx
            .send(AuthorizationCommand::Remove {
                bunker_pubkey: old_pubkey.clone(),
            })
            .await
        {
            tracing::error!("Failed to send authorization remove command: {}", e);
        }
    }

    tracing::info!(
        "Successfully changed key for user {} → {} (deleted {} OAuth authorizations)",
        old_pubkey,
        new_pubkey,
        oauth_count
    );

    let response = ChangeKeyResponse {
        success: true,
        new_pubkey: new_pubkey.clone(),
        message: format!(
            "Private key changed successfully. Deleted {} connected app(s). Your old identity ({}) still exists in teams if you backed up the old key.",
            oauth_count,
            &old_pubkey[..16]
        ),
    };

    Ok((
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(response),
    )
        .into_response())
}

/// Response for account deletion.
#[derive(Debug, Serialize)]
pub struct DeleteAccountResponse {
    pub success: bool,
    pub message: String,
}

/// DELETE /user/account
/// Permanently delete the user's account and all associated data.
///
/// Authorization: Requires UCAN token that is either:
/// - User-signed (issuer == audience) - proves nsec possession
/// - Server-signed with first_party: true fact - issued via headless flow
///
/// Third-party OAuth apps cannot delete accounts (no first_party fact).
pub async fn delete_account(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
) -> Result<Json<DeleteAccountResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Get Authorization header
    let auth_header = headers
        .get("Authorization")
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidToken)?;

    // Validate UCAN token
    let (user_pubkey, redirect_origin, _, ucan) =
        crate::ucan_auth::validate_ucan_token(auth_header, tenant_id)
            .await
            .map_err(|e| {
                tracing::warn!("Account deletion UCAN validation failed: {}", e);
                AuthError::InvalidToken
            })?;

    // Check authorization: user-signed OR first_party fact
    let issuer = crate::ucan_auth::did_to_nostr_pubkey(ucan.issuer())
        .map_err(|_| AuthError::InvalidToken)?
        .to_hex();
    let is_user_signed = issuer == user_pubkey;

    let is_first_party = ucan
        .facts()
        .iter()
        .find_map(|f| f.get("first_party").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    if !is_user_signed && !is_first_party {
        tracing::warn!(
            event = "account_deletion_denied",
            tenant_id = tenant_id,
            user_pubkey = %user_pubkey,
            redirect_origin = %redirect_origin,
            "Denied: not user-signed and not first-party"
        );
        return Err(AuthError::Forbidden(format!(
            "Account deletion requires the {} app or web login with your private key",
            BRAND_NAME
        )));
    }

    tracing::info!(
        event = "account_deletion_started",
        tenant_id = tenant_id,
        user_pubkey = %user_pubkey,
        is_user_signed = is_user_signed,
        is_first_party = is_first_party,
        redirect_origin = %redirect_origin,
        "Deletion initiated"
    );

    // Execute account deletion
    let user_repo = UserRepository::new(pool.clone());
    let result = user_repo
        .delete_account(&user_pubkey, tenant_id)
        .await
        .map_err(|e| {
            tracing::error!(
                event = "account_deletion_failed",
                tenant_id = tenant_id,
                user_pubkey = %user_pubkey,
                error = %e,
                "Database error during deletion"
            );
            AuthError::Database(sqlx::Error::Protocol(e.to_string()))
        })?;

    // Signal signer daemon to remove bunker connections
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

    // Track metric
    METRICS.inc_account_deleted();

    tracing::info!(
        event = "account_deletion_completed",
        tenant_id = tenant_id,
        user_pubkey = %user_pubkey,
        teams_removed = result.teams_removed,
        oauth_auths_deleted = result.oauth_authorizations_deleted,
        bunkers_notified = result.bunker_pubkeys.len(),
        "Account permanently deleted"
    );

    Ok(Json(DeleteAccountResponse {
        success: true,
        message: "Account permanently deleted".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::generate_server_signed_ucan;
    use super::validate_origin;
    use super::verify_html_page;
    use super::AccountStatusResponse;
    use super::BRAND_NAME;
    use super::{bcrypt_auth_error, BcryptAdmissionError};
    #[cfg(feature = "integration-tests")]
    use super::{VERIFICATION_LINK_SUPERSEDED_CODE, VERIFICATION_LINK_SUPERSEDED_HEADING};
    use axum::response::IntoResponse;
    use ucan::Ucan;

    #[test]
    fn bcrypt_capacity_maps_to_retryable_service_unavailable() {
        let response = bcrypt_auth_error(BcryptAdmissionError::AtCapacity).into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(response.headers()["Retry-After"], "1");
    }

    #[tokio::test]
    async fn verification_status_page_uses_divine_login_branding() {
        let response = verify_html_page(
            axum::http::StatusCode::OK,
            "Email verified!",
            "Return to the app.",
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("status page should be UTF-8");

        assert!(body.contains("/divine-logo.svg"));
        assert!(body.contains(">Login</span>"));
        assert!(body.contains("background:#072218"));
        assert!(body.contains("Email verified!"));
        assert!(body.contains(&format!("Email verified! - {BRAND_NAME}")));
        assert!(!body.contains("Bricolage Grotesque"));
        assert!(!body.contains("font-family:Inter"));
    }

    #[tokio::test]
    async fn server_signed_ucan_includes_first_party_only_when_requested() {
        let user_keys = Keys::generate();
        let server_keys = Keys::generate();

        let first_party_token = generate_server_signed_ucan(
            &user_keys.public_key(),
            1,
            "user@example.test",
            "https://first-party.example.test",
            None,
            &server_keys,
            true,
            None,
            None,
        )
        .await
        .expect("first-party UCAN");
        let first_party_ucan =
            Ucan::try_from_token_string(&first_party_token).expect("decode first-party UCAN");
        assert!(
            first_party_ucan
                .facts()
                .iter()
                .any(|fact| fact.get("first_party").and_then(|v| v.as_bool()) == Some(true)),
            "first-party sessions must carry the deletion authorization fact"
        );

        let third_party_token = generate_server_signed_ucan(
            &user_keys.public_key(),
            1,
            "user@example.test",
            "https://third-party.example.test",
            None,
            &server_keys,
            false,
            None,
            None,
        )
        .await
        .expect("third-party UCAN");
        let third_party_ucan =
            Ucan::try_from_token_string(&third_party_token).expect("decode third-party UCAN");
        assert!(
            third_party_ucan
                .facts()
                .iter()
                .all(|fact| fact.get("first_party").is_none()),
            "third-party sessions must not gain account deletion authority"
        );
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn verifier_capacity_is_acquired_before_a_redis_attempt_lease() {
        use crate::PrefixedRedis;
        use keycast_core::bcrypt_admission::{BcryptAdmission, BcryptOperation, BcryptWorkload};
        use redis::aio::ConnectionManager;
        use std::time::Duration as StdDuration;
        use uuid::Uuid;

        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("TEST_REDIS_URL must name the dedicated test Redis");
        let client = redis::Client::open(redis_url).expect("valid Redis URL");
        let connection = ConnectionManager::new(client.clone())
            .await
            .expect("connect to Redis");
        let prefix = format!("keycast-pr326-independent-review:{}", Uuid::new_v4());
        let redis = PrefixedRedis::new(connection, Some(prefix.clone()));
        let verifier = BcryptAdmission::new(1, StdDuration::from_millis(10));
        let held = verifier
            .reserve(BcryptWorkload::Account, BcryptOperation::Verify)
            .await
            .expect("occupy verifier capacity");

        let error = super::begin_key_egress_attempt(
            &verifier,
            Some(&redis),
            1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            super::EXPORT_KEY_ENDPOINT,
        )
        .await
        .expect_err("occupied verifier must load-shed");
        assert!(
            matches!(error, super::AuthError::ServiceUnavailable { .. }),
            "verifier overload should surface as temporary unavailability: {error:?}"
        );

        let mut raw = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{prefix}:key_egress:*"))
            .query_async(&mut raw)
            .await
            .expect("list limiter keys");
        assert!(
            keys.is_empty(),
            "load shedding before CPU admission must not create an attempt lease: {keys:?}"
        );
        drop(held);
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn registration_waits_for_bcrypt_without_holding_max_one_database_pool() {
        use keycast_core::bcrypt_admission::{BcryptOperation, BcryptWorkload};
        use std::time::Duration as StdDuration;

        let bootstrap = create_test_db().await;
        bootstrap.close().await;
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(StdDuration::from_millis(200))
            .connect(&database_url)
            .await
            .expect("connect max-one pool");
        let bcrypt = BcryptAdmission::new(1, StdDuration::from_secs(1));
        let held = bcrypt
            .reserve(BcryptWorkload::Account, BcryptOperation::Hash)
            .await
            .expect("occupy bcrypt capacity");
        let mut auth_state = create_test_auth_state(pool.clone());
        Arc::get_mut(&mut auth_state.state)
            .expect("test state has one owner")
            .bcrypt = bcrypt;

        let registration = tokio::spawn(super::register(
            create_unit_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(super::RegisterRequest {
                email: format!("bcrypt-pool-order-{}@example.test", Uuid::new_v4()),
                password: "test-password".to_string(),
                nsec: None,
                relays: None,
            }),
        ));
        tokio::task::yield_now().await;
        tokio::time::sleep(StdDuration::from_millis(20)).await;

        let connection = tokio::time::timeout(StdDuration::from_millis(200), pool.acquire())
            .await
            .expect("pool acquisition must not wait behind bcrypt")
            .expect("acquire sole pool connection");
        assert!(!registration.is_finished());

        drop(connection);
        registration.abort();
        drop(held);
        pool.close().await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn registration_rejects_duplicate_email_before_bcrypt_admission() {
        use keycast_core::bcrypt_admission::BcryptAdmission;
        use std::time::Duration as StdDuration;

        let pool = create_test_db().await;
        let email = format!("bcrypt-duplicate-{}@example.test", Uuid::new_v4());
        let pubkey = Keys::generate().public_key().to_hex();
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
             VALUES ($1, 1, $2, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("insert existing user");

        let bcrypt = BcryptAdmission::new(1, StdDuration::from_secs(1));
        bcrypt.shutdown().await;
        let mut auth_state = create_test_auth_state(pool.clone());
        Arc::get_mut(&mut auth_state.state)
            .expect("test state has one owner")
            .bcrypt = bcrypt;

        let result = super::register(
            create_unit_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(super::RegisterRequest {
                email: email.clone(),
                password: "test-password".to_string(),
                nsec: None,
                relays: None,
            }),
        )
        .await;
        assert!(matches!(result, Err(super::AuthError::EmailAlreadyExists)));

        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await
            .expect("delete existing user");
    }

    #[test]
    fn account_status_active_minor_surfaces_flag_without_status() {
        let resp = AccountStatusResponse::from_account_row(
            "pk".to_string(),
            Some("a@b.com".to_string()),
            Some(true),
            keycast_core::types::user::UserStatus::Active,
            None,
            true,
            Some(chrono::Utc::now()),
        );
        // verified_minor surfaces even though the account is active (not gated).
        assert!(resp.verified_minor);
        assert!(resp.verified_minor_at.is_some());
        assert!(resp.account_status.is_none());
        assert!(resp.suspended_reason.is_none());
        assert_eq!(resp.email, "a@b.com");
        assert!(resp.email_verified);
    }

    #[test]
    fn account_status_suspended_minor_still_surfaces_flag() {
        let resp = AccountStatusResponse::from_account_row(
            "pk".to_string(),
            None,
            None,
            keycast_core::types::user::UserStatus::Suspended,
            Some("reason".to_string()),
            true,
            None,
        );
        // Regression guard: verified_minor stays true when suspended, while
        // account_status / suspended_reason now populate.
        assert!(resp.verified_minor);
        assert_eq!(resp.account_status.as_deref(), Some("suspended"));
        assert_eq!(resp.suspended_reason.as_deref(), Some("reason"));
        assert_eq!(resp.email, ""); // None -> default
        assert!(!resp.email_verified);
    }

    #[test]
    fn test_validate_origin_https() {
        assert!(validate_origin("https://example.com").is_ok());
        assert!(validate_origin("https://example.com:8080").is_ok());
    }

    #[test]
    fn test_validate_origin_http_localhost() {
        assert!(validate_origin("http://localhost").is_ok());
        assert!(validate_origin("http://localhost:3000").is_ok());
        assert!(validate_origin("http://127.0.0.1:3000").is_ok());
        // IPv6 loopback, matching extract_origin in oauth.rs
        assert!(validate_origin("http://[::1]").is_ok());
        assert!(validate_origin("http://[::1]:3000").is_ok());
    }

    #[test]
    fn test_validate_origin_http_localhost_subdomain() {
        // RFC 6761 reserves *.localhost as loopback.
        assert!(validate_origin("http://admin.localhost:8787").is_ok());
        assert!(validate_origin("http://api.localhost").is_ok());
        assert!(validate_origin("http://admin.app.localhost:8080").is_ok());
    }

    #[test]
    fn test_validate_origin_http_non_localhost_rejected() {
        assert!(validate_origin("http://example.com").is_err());
        // Hosts that merely contain "localhost" must not be treated as loopback.
        assert!(validate_origin("http://xxxlocalhost").is_err());
        assert!(validate_origin("http://localhost.evil.com").is_err());
    }

    #[tokio::test]
    async fn test_username_conflict_response_uses_canonical_message() {
        let response = super::AuthError::Conflict(
            "Username is not available. Please choose another username.".to_string(),
        )
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body_text = std::str::from_utf8(&body).unwrap();
        assert!(!body_text.contains("dependency diagnostics"));
        assert!(body_text.len() < 200);

        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["error"],
            "Username is not available. Please choose another username."
        );
    }

    #[tokio::test]
    async fn test_register_rejects_malformed_email_with_stable_error() {
        let response = match super::register(
            create_unit_test_tenant(),
            axum::extract::State(create_lazy_auth_state()),
            axum::http::HeaderMap::new(),
            axum::Json(super::RegisterRequest {
                email: "person@gmail..com".to_string(),
                password: "testpassword123".to_string(),
                nsec: None,
                relays: None,
            }),
        )
        .await
        {
            Ok(response) => axum::response::IntoResponse::into_response(response),
            Err(error) => axum::response::IntoResponse::into_response(error),
        };

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = response_json(response).await;
        assert_eq!(body["code"], super::INVALID_EMAIL_CODE);
        assert_eq!(body["error"], "Please enter a valid email address.");
    }

    #[tokio::test]
    async fn test_duplicate_email_response_has_stable_code() {
        let response = super::AuthError::EmailAlreadyExists.into_response();

        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
        let body = response_json(response).await;
        assert_eq!(body["code"], super::EMAIL_ALREADY_EXISTS_CODE);
        assert_eq!(body["error"], super::EMAIL_ALREADY_EXISTS_MESSAGE);
    }

    #[cfg(feature = "integration-tests")]
    use super::{
        generate_ucan_token, login, update_profile, verify_email, verify_email_get, ProfileData,
        VerifyEmailQuery, VerifyEmailRequest,
    };
    #[cfg(feature = "integration-tests")]
    use crate::api::http::routes::{public_verify_email_route, AuthState};
    #[cfg(feature = "integration-tests")]
    use crate::api::tenant::{Tenant, TenantExtractor};
    #[cfg(feature = "integration-tests")]
    use crate::handlers::http_rpc_handler::new_http_handler_cache;
    #[cfg(feature = "integration-tests")]
    use crate::state::KeycastState;
    use crate::BcryptAdmission;
    #[cfg(feature = "integration-tests")]
    use axum::{
        body::Body,
        extract::{Query, State},
        http::{
            header::{AUTHORIZATION, ORIGIN},
            HeaderMap, HeaderValue, Request, StatusCode,
        },
        Json,
    };
    #[cfg(feature = "integration-tests")]
    use chrono::{Duration, Utc};
    #[cfg(feature = "integration-tests")]
    use keycast_core::encryption::file_key_manager::FileKeyManager;
    #[cfg(feature = "integration-tests")]
    use keycast_core::encryption::{KeyManager, KeyManagerError};
    #[cfg(feature = "integration-tests")]
    use keycast_core::secret_pool::SecretPool;
    #[cfg(feature = "integration-tests")]
    use keycast_core::signing_handler::SigningHandler;
    #[cfg(feature = "integration-tests")]
    use moka::future::Cache;
    use nostr_sdk::{Keys, Kind, Timestamp, UnsignedEvent};
    #[cfg(feature = "integration-tests")]
    use sqlx::PgPool;
    #[cfg(feature = "integration-tests")]
    use std::sync::Arc;
    #[cfg(feature = "integration-tests")]
    use tower::ServiceExt;
    #[cfg(feature = "integration-tests")]
    use uuid::Uuid;
    #[cfg(feature = "integration-tests")]
    use zeroize::Zeroizing;

    struct LazyTestKeyManager;

    #[async_trait::async_trait]
    impl keycast_core::encryption::KeyManager for LazyTestKeyManager {
        async fn encrypt(
            &self,
            plaintext_bytes: &[u8],
        ) -> Result<Vec<u8>, keycast_core::encryption::KeyManagerError> {
            Ok(plaintext_bytes.to_vec())
        }

        async fn decrypt(
            &self,
            ciphertext_bytes: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, keycast_core::encryption::KeyManagerError>
        {
            Ok(zeroize::Zeroizing::new(ciphertext_bytes.to_vec()))
        }
    }

    fn create_lazy_auth_state() -> crate::api::http::routes::AuthState {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy(&database_url)
            .expect("lazy pool should be created");
        let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
        let secret_pool = keycast_core::secret_pool::SecretPool::new(1);
        let tenant_cache = moka::future::Cache::builder().max_capacity(10).build();
        let key_manager: std::sync::Arc<Box<dyn keycast_core::encryption::KeyManager>> =
            std::sync::Arc::new(Box::new(LazyTestKeyManager));

        crate::api::http::routes::AuthState {
            state: std::sync::Arc::new(crate::state::KeycastState {
                db: pool,
                key_manager,
                signer_handlers: None,
                http_handler_cache: crate::handlers::http_rpc_handler::new_http_handler_cache(),
                server_keys: Keys::generate(),
                tenant_cache,
                bcrypt,
                redis: None,
                secret_pool: secret_pool.receiver(),
                activity_logger: crate::activity_log::ActivityLogger::disabled(),
            }),
            auth_tx: None,
        }
    }

    fn create_unit_test_tenant() -> crate::api::tenant::TenantExtractor {
        crate::api::tenant::TenantExtractor(std::sync::Arc::new(crate::api::tenant::Tenant {
            id: 1,
            domain: "example.test".to_string(),
            name: "Test Tenant".to_string(),
            settings: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }))
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&body).expect("response body should be JSON")
    }

    /// Helper to create test database connection
    /// Uses DATABASE_URL env var or defaults to localhost
    #[cfg(feature = "integration-tests")]
    async fn create_test_db() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        let pool = PgPool::connect(&database_url).await.expect(
            "\n\n\
            ╔══════════════════════════════════════════════════════════════════╗\n\
            ║  PostgreSQL connection failed - these tests require a database   ║\n\
            ╠══════════════════════════════════════════════════════════════════╣\n\
            ║  To run locally:                                                 ║\n\
            ║    docker run -d --name postgres -p 5432:5432 \\                  ║\n\
            ║      -e POSTGRES_PASSWORD=password \\                             ║\n\
            ║      -e POSTGRES_DB=keycast_test postgres:16                     ║\n\
            ║                                                                  ║\n\
            ║  Or skip these tests:  cargo test -- --skip test_fast_path      ║\n\
            ╚══════════════════════════════════════════════════════════════════╝\n\n",
        );

        // Run migrations
        sqlx::migrate!("../database/migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        pool
    }

    #[cfg(feature = "integration-tests")]
    async fn cleanup_verify_email_test_data(pool: &PgPool, pubkey: &str, token: &str) {
        let _ = sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1 OR pending_email_verification_token = $2")
            .bind(pubkey)
            .bind(token)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await;
    }

    #[cfg(feature = "integration-tests")]
    struct TestKeyManager;

    #[cfg(feature = "integration-tests")]
    #[async_trait::async_trait]
    impl KeyManager for TestKeyManager {
        async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
            Ok(plaintext_bytes.to_vec())
        }

        async fn decrypt(
            &self,
            ciphertext_bytes: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
            Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
        }
    }

    #[cfg(feature = "integration-tests")]
    fn create_test_auth_state(pool: PgPool) -> AuthState {
        let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
        let secret_pool = SecretPool::new(1);
        let tenant_cache = Cache::builder().max_capacity(10).build();
        let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

        AuthState {
            state: Arc::new(KeycastState {
                db: pool,
                key_manager,
                signer_handlers: None,
                http_handler_cache: new_http_handler_cache(),
                server_keys: Keys::generate(),
                tenant_cache,
                bcrypt,
                redis: None,
                secret_pool: secret_pool.receiver(),
                activity_logger: crate::activity_log::ActivityLogger::disabled(),
            }),
            auth_tx: None,
        }
    }

    #[cfg(feature = "integration-tests")]
    fn create_test_tenant() -> TenantExtractor {
        TenantExtractor(Arc::new(Tenant {
            id: 1,
            domain: "example.test".to_string(),
            name: "Test Tenant".to_string(),
            settings: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }))
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_headless_verify_email_requires_redis_and_keeps_pending_registration_for_retry() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let test_email = format!("verify-email-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let device_code = format!("device_{}", Uuid::new_v4());
        let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let expires_at = Utc::now() + Duration::hours(24);

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;

        sqlx::query(
            "INSERT INTO oauth_codes (
                tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                expires_at, created_at, pending_email, pending_password_hash,
                pending_email_verification_token, device_code, is_headless
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11, $12)",
        )
        .bind(1_i64)
        .bind(&placeholder_code)
        .bind(&pubkey)
        .bind("TestMobileApp")
        .bind("https://test.example.com/callback")
        .bind("policy:social")
        .bind(expires_at)
        .bind(&test_email)
        .bind(&password_hash)
        .bind(&verification_token)
        .bind(&device_code)
        .bind(true)
        .execute(&pool)
        .await
        .unwrap();

        for _ in 0..2 {
            let response = match verify_email(
                create_test_tenant(),
                State(auth_state.clone()),
                HeaderMap::new(),
                Json(VerifyEmailRequest {
                    token: verification_token.clone(),
                }),
            )
            .await
            {
                Ok(response) => response.into_response(),
                Err(err) => err.into_response(),
            };

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        let pending_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND pending_email_verification_token = $1",
        )
        .bind(&verification_token)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            pending_count.0, 1,
            "pending registration should remain retryable"
        );

        let usable_code_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND user_pubkey = $1 AND pending_email IS NULL",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            usable_code_count.0, 0,
            "should not mint a pollable code before Redis succeeds"
        );

        let user_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE tenant_id = 1 AND pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            user_count.0, 0,
            "strict Redis validation must run before user materialization"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_duplicate_email_returns_conflict() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let existing_pubkey = Keys::generate().public_key().to_hex();
        let pending_keys = Keys::generate();
        let pending_pubkey = pending_keys.public_key().to_hex();
        let duplicate_email = format!("verify-duplicate-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let expires_at = Utc::now() + Duration::hours(24);
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(&pool, &existing_pubkey, &verification_token).await;
        cleanup_verify_email_test_data(&pool, &pending_pubkey, &verification_token).await;

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, $4, true, NOW(), NOW())",
        )
        .bind(&existing_pubkey)
        .bind(1_i64)
        .bind(&duplicate_email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO oauth_codes (
                tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                expires_at, created_at, pending_email, pending_password_hash,
                pending_email_verification_token, pending_encrypted_secret
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11)",
        )
        .bind(1_i64)
        .bind(&placeholder_code)
        .bind(&pending_pubkey)
        .bind("TestApp")
        .bind("https://test.example.com/callback")
        .bind("policy:social")
        .bind(expires_at)
        .bind(&duplicate_email)
        .bind(&password_hash)
        .bind(&verification_token)
        .bind(&encrypted_secret)
        .execute(&pool)
        .await
        .unwrap();

        let response = match verify_email(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response_json(response).await;
        assert_eq!(body["code"], super::EMAIL_ALREADY_EXISTS_CODE);

        let pending_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND pending_email_verification_token = $1",
        )
        .bind(&verification_token)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            pending_count.0, 0,
            "duplicate-email verification should resolve the pending registration"
        );

        let retry_response = match verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };
        assert_ne!(
            retry_response.status(),
            StatusCode::CONFLICT,
            "retrying the same token should not loop through duplicate-email insertion"
        );

        cleanup_verify_email_test_data(&pool, &existing_pubkey, &verification_token).await;
        cleanup_verify_email_test_data(&pool, &pending_pubkey, &verification_token).await;
    }

    /// Extract the `code` query parameter from a verify redirect URL like `{uri}?code=XXX&state=YYY`.
    #[cfg(feature = "integration-tests")]
    fn extract_code_from_redirect(redirect_to: &str) -> String {
        let after = redirect_to
            .split("code=")
            .nth(1)
            .expect("redirect should carry a code");
        after.split('&').next().unwrap().to_string()
    }

    /// Insert a non-headless OAuth pending registration (browser flow) and return (pubkey, token).
    #[cfg(feature = "integration-tests")]
    async fn insert_oauth_pending_registration(pool: &PgPool, email: &str) -> (String, String) {
        let pending_keys = Keys::generate();
        let pending_pubkey = pending_keys.public_key().to_hex();
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let expires_at = Utc::now() + Duration::hours(24);
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(pool, &pending_pubkey, &verification_token).await;

        sqlx::query(
            "INSERT INTO oauth_codes (
                tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                expires_at, created_at, pending_email, pending_password_hash,
                pending_email_verification_token, pending_encrypted_secret
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11)",
        )
        .bind(1_i64)
        .bind(&placeholder_code)
        .bind(&pending_pubkey)
        .bind("TestApp")
        .bind("https://test.example.com/callback")
        .bind("policy:social")
        .bind(expires_at)
        .bind(email)
        .bind(&password_hash)
        .bind(&verification_token)
        .bind(&encrypted_secret)
        .execute(pool)
        .await
        .unwrap();

        (pending_pubkey, verification_token)
    }

    /// Re-verifying an OAuth registration within the window must re-arm a fresh 10-min code
    /// WITHOUT deleting the pending row (keycast#262 Part A idempotency).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_oauth_idempotent_rearms_without_deleting_pending() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let email = format!("verify-idem-{}@example.com", Uuid::new_v4());
        let (pubkey, token) = insert_oauth_pending_registration(&pool, &email).await;

        let first = verify_email(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: token.clone(),
            }),
        )
        .await
        .map(|r| r.into_response())
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(first.status(), StatusCode::OK);
        let body1 = response_json(first).await;
        let code1 = extract_code_from_redirect(body1["redirect_to"].as_str().unwrap());

        // Pending row must survive the first verify (so prefetch can't strand a later real visit).
        let repo = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
        assert!(
            repo.find_by_verification_token(&token, 1)
                .await
                .unwrap()
                .is_some(),
            "pending row must survive verify (idempotent re-arm)"
        );

        let second = verify_email(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: token.clone(),
            }),
        )
        .await
        .map(|r| r.into_response())
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "re-verify must still succeed, not fail with InvalidToken"
        );
        let body2 = response_json(second).await;
        let code2 = extract_code_from_redirect(body2["redirect_to"].as_str().unwrap());

        assert_eq!(
            code1, code2,
            "idempotent re-arm reuses the same live exchange code"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_concurrent_finalizers_return_the_same_exchange_code() {
        let pool = create_test_db().await;
        let email = format!("verify-concurrent-{}@example.com", Uuid::new_v4());
        let (pubkey, token) = insert_oauth_pending_registration(&pool, &email).await;
        let repo = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
        let pending = repo
            .find_by_verification_token(&token, 1)
            .await
            .unwrap()
            .unwrap();

        let (first, second) = tokio::join!(
            super::finalize_pending_registration(
                &pool,
                None,
                1,
                &pending,
                super::HeadlessDelivery::RedisBestEffort,
            ),
            super::finalize_pending_registration(
                &pool,
                None,
                1,
                &pending,
                super::HeadlessDelivery::RedisBestEffort,
            ),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.new_code, second.new_code);

        let exchange_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND pending_email_verification_token = $1
               AND pending_email IS NULL",
        )
        .bind(&token)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(exchange_count, 1);

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// A prefetch (mail scanner / link preview) of the verify link must not strand the user:
    /// the pending row survives, so the user's later real click still completes.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_prefetch_does_not_strand_user() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());

        // OAuth registrations retain their pending row so a scanner hit cannot consume the
        // redirect/code that the user's later visit needs.
        let email = format!("verify-prefetch-{}@example.com", Uuid::new_v4());
        let (pubkey, token) = insert_oauth_pending_registration(&pool, &email).await;

        // Simulated prefetch hit.
        let prefetch = verify_email(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: token.clone(),
            }),
        )
        .await
        .map(|r| r.into_response())
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(prefetch.status(), StatusCode::OK);

        // The user's real click afterwards must still complete (not InvalidToken / stranded).
        let real = verify_email(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: token.clone(),
            }),
        )
        .await
        .map(|r| r.into_response())
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(
            real.status(),
            StatusCode::OK,
            "user's real click after a prefetch must still verify"
        );
        let body = response_json(real).await;
        assert_eq!(body["success"], true);
        // Must re-arm via the pending-registration path (fresh redirect + code), NOT fall through
        // to the degenerate users-table "already verified" branch that mints no exchange code.
        assert!(
            body["redirect_to"].is_string(),
            "real click after prefetch must re-arm a fresh exchange code, not silently strand"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;

        // First-party registration links hand off to the interactive page. A scanner GET must not
        // verify the user or mint a first-party session; the page's POST performs that transition.
        let first_party_keys = Keys::generate();
        let first_party_pubkey = first_party_keys.public_key().to_hex();
        let first_party_token = format!("verify_first_party_{}", Uuid::new_v4());
        let first_party_email = format!("verify-first-party-{}@example.com", Uuid::new_v4());
        let first_party_password_hash =
            bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let first_party_expires_at = Utc::now() + Duration::hours(24);
        let first_party_secret = first_party_keys.secret_key().to_secret_bytes();
        let user_repo = keycast_core::repositories::UserRepository::new(pool.clone());

        cleanup_verify_email_test_data(&pool, &first_party_pubkey, &first_party_token).await;
        user_repo
            .register_with_personal_key(
                &first_party_pubkey,
                1,
                &first_party_email,
                &first_party_password_hash,
                &first_party_token,
                first_party_expires_at,
                &first_party_secret,
            )
            .await
            .unwrap();

        let scanner_get = verify_email_get(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Query(VerifyEmailQuery {
                token: Some(first_party_token.clone()),
            }),
        )
        .await;
        assert!(scanner_get.status().is_redirection());
        assert!(
            !scanner_get
                .headers()
                .contains_key(axum::http::header::SET_COOKIE),
            "a first-party GET must never issue a session cookie"
        );
        let (verified_after_get,): (bool,) =
            sqlx::query_as("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&first_party_pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !verified_after_get,
            "a first-party GET must not mutate verification state"
        );

        let interactive_post = verify_email(
            create_test_tenant(),
            State(auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: first_party_token.clone(),
            }),
        )
        .await
        .map(|r| r.into_response())
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(interactive_post.status(), StatusCode::OK);
        assert!(
            interactive_post
                .headers()
                .contains_key(axum::http::header::SET_COOKIE),
            "the interactive POST must still issue the first-party session cookie"
        );
        let (verified_after_post,): (bool,) =
            sqlx::query_as("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&first_party_pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            verified_after_post,
            "the interactive POST must complete first-party verification"
        );

        cleanup_verify_email_test_data(&pool, &first_party_pubkey, &first_party_token).await;
    }

    /// Build a Redis-backed AuthState for headless GET tests (the link path requires Redis).
    #[cfg(feature = "integration-tests")]
    async fn create_test_auth_state_with_redis(pool: PgPool) -> AuthState {
        let mut state = create_test_auth_state(pool);
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".into());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let redis = crate::redis::PrefixedRedis::new(conn, Some("test_verify".to_string()));
        let inner = Arc::get_mut(&mut state.state).expect("unique Arc");
        inner.redis = Some(redis);
        state
    }

    /// Build an AuthState whose Redis wrapper deterministically rejects SETEX operations.
    #[cfg(feature = "integration-tests")]
    async fn create_test_auth_state_with_failing_redis(pool: PgPool) -> AuthState {
        let mut state = create_test_auth_state(pool);
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".into());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let redis =
            crate::redis::PrefixedRedis::new_failing(conn, Some("test_verify_fail".to_string()));
        let inner = Arc::get_mut(&mut state.state).expect("unique Arc");
        inner.redis = Some(redis);
        state
    }

    /// Insert a headless pending registration (device_code set) and return (pubkey, token, device_code).
    #[cfg(feature = "integration-tests")]
    async fn insert_headless_pending_registration(
        pool: &PgPool,
        email: &str,
    ) -> (String, String, String) {
        let pending_keys = Keys::generate();
        let pending_pubkey = pending_keys.public_key().to_hex();
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
        let device_code = format!("dc_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let expires_at = Utc::now() + Duration::hours(24);
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(pool, &pending_pubkey, &verification_token).await;

        sqlx::query(
            "INSERT INTO oauth_codes (
                tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                expires_at, created_at, pending_email, pending_password_hash,
                pending_email_verification_token, pending_encrypted_secret, device_code, is_headless
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11, $12, true)",
        )
        .bind(1_i64)
        .bind(&placeholder_code)
        .bind(&pending_pubkey)
        .bind("TestApp")
        .bind("https://test.example.com/callback")
        .bind("policy:social")
        .bind(expires_at)
        .bind(email)
        .bind(&password_hash)
        .bind(&verification_token)
        .bind(&encrypted_secret)
        .bind(&device_code)
        .execute(pool)
        .await
        .unwrap();

        (pending_pubkey, verification_token, device_code)
    }

    /// GET /api/auth/verify-email for a non-headless OAuth registration must verify server-side
    /// (no client JS) and 3xx-redirect the browser to the client callback carrying a fresh code.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_oauth_redirects_with_code() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let email = format!("verify-get-oauth-{}@example.com", Uuid::new_v4());
        let (pubkey, token) = insert_oauth_pending_registration(&pool, &email).await;

        let response = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            axum::extract::Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();

        assert!(
            response.status().is_redirection(),
            "GET verify for OAuth should redirect, got {}",
            response.status()
        );
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("redirect must set Location")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            location.contains("code="),
            "redirect Location must carry an exchange code: {location}"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// GET verify for a headless registration shows an HTML success page (the app polls for the
    /// code) and re-arms a fresh code without deleting the pending row.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_headless_returns_success_page() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state_with_redis(pool.clone()).await;
        let email = format!("verify-get-headless-{}@example.com", Uuid::new_v4());
        let (pubkey, token, _device_code) =
            insert_headless_pending_registration(&pool, &email).await;

        let response = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            axum::extract::Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        assert!(
            content_type.contains("text/html"),
            "headless GET verify should render an HTML page, got {content_type}"
        );

        // Pending row survives (idempotent re-arm).
        let repo = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
        assert!(repo
            .find_by_verification_token(&token, 1)
            .await
            .unwrap()
            .is_some());

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// Insert a first-party (users-table) row carrying a live verification token.
    #[cfg(feature = "integration-tests")]
    async fn insert_first_party_pending_user(pool: &PgPool, email: &str) -> (String, String) {
        let pubkey = Keys::generate().public_key().to_hex();
        let token = format!("verify_first_party_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, 1, $2, $3, false, $4, NOW() + INTERVAL \'24 hours\', NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(email)
        .bind(&password_hash)
        .bind(&token)
        .execute(pool)
        .await
        .expect("first-party user row should insert");

        (pubkey, token)
    }

    /// A token that still resolves to a first-party users row is handed to the interactive page,
    /// which owns that flow (it POSTs and mints the session).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_first_party_token_redirects_to_interactive_page() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let email = format!("verify-get-first-party-{}@example.com", Uuid::new_v4());
        let (pubkey, token) = insert_first_party_pending_user(&pool, &email).await;

        let response = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            axum::extract::Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();

        assert!(response.status().is_redirection());
        assert!(
            !response
                .headers()
                .contains_key(axum::http::header::SET_COOKIE),
            "GET must not issue a first-party session"
        );
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(
            location.starts_with("/email-verification/continue?token="),
            "first-party tokens must be handed to the interactive page, got {location}"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_public_verify_email_route_is_registered_without_cors() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool);
        let app = public_verify_email_route(auth_state.state, auth_state.auth_tx);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/verify-email?token=sensitive")
                    .header(ORIGIN, "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("public verification route response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response
            .headers()
            .contains_key(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("route response body");
        assert_eq!(&body[..], b"Missing Host header");
    }

    /// A token that resolves to nothing - already used, or superseded by a newer verification
    /// email - renders a terminal server-side page saying so (keycast#268).
    ///
    /// It must NOT bounce to the SPA: that path POSTs, 401s, and tells a user with no account and
    /// no session to "log in again", and it is the one place this GET would still need client-side
    /// JavaScript, which is what verifying on GET exists to avoid.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_dead_token_renders_superseded_page() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());

        let response = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            axum::extract::Query(VerifyEmailQuery {
                token: Some(format!("nonexistent_{}", Uuid::new_v4())),
            }),
        )
        .await
        .into_response();

        assert!(
            !response.status().is_redirection(),
            "a dead token must not be relayed to the SPA"
        );
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains(VERIFICATION_LINK_SUPERSEDED_HEADING),
            "dead-link page should carry the superseded heading, got: {body}"
        );
        assert!(
            body.contains("replaced by a newer verification email"),
            "dead-link page should explain the real cause, got: {body}"
        );
        assert!(
            !body.contains("log in again"),
            "dead-link page must not tell a user with no session to log in again, got: {body}"
        );
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_expired_pending_token_is_not_reported_as_superseded_or_successful() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let email = format!("verify-expired-{}@example.com", Uuid::new_v4());
        let (pubkey, token) = insert_oauth_pending_registration(&pool, &email).await;
        sqlx::query(
            "UPDATE oauth_codes SET expires_at = NOW() - INTERVAL '1 second'
             WHERE pending_email_verification_token = $1 AND tenant_id = 1",
        )
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();

        let get_request_id = format!("get_{}", Uuid::new_v4());
        let mut get_headers = HeaderMap::new();
        get_headers.insert(
            crate::api::http::auth_observability::REQUEST_ID_HEADER,
            get_request_id.parse().unwrap(),
        );
        let get_response = verify_email_get(
            create_test_tenant(),
            State(auth_state.clone()),
            get_headers,
            Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();
        assert_eq!(get_response.status(), StatusCode::GONE);

        let post_request_id = format!("post_{}", Uuid::new_v4());
        let mut post_headers = HeaderMap::new();
        post_headers.insert(
            crate::api::http::auth_observability::REQUEST_ID_HEADER,
            post_request_id.parse().unwrap(),
        );
        let post_response = verify_email(
            create_test_tenant(),
            State(auth_state),
            post_headers,
            Json(VerifyEmailRequest {
                token: token.clone(),
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(post_response.status(), StatusCode::OK);

        for (request_id, expected) in [
            (
                &get_request_id,
                "/api/auth/verify-email|email_verification|failure|expired|410",
            ),
            (
                &post_request_id,
                "/api/auth/verify-email|email_verification|failure|expired|200",
            ),
        ] {
            let event: String = sqlx::query_scalar(
                "SELECT concat_ws('|', endpoint, event_type, outcome, reason_code, http_status)
                 FROM auth_events WHERE request_id = $1",
            )
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(event, expected);
        }

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// The GET path records auth events for its outcomes, matching the POST path's event_type so
    /// the two transports are comparable. Post-merge the GET is the primary verification path, and
    /// the `verification_link_superseded` rate is the signal for whether duplicate signups
    /// actually stopped in production (keycast#268).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_records_auth_event_for_dead_link() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let token = format!("nonexistent_{}", Uuid::new_v4());

        let mut headers = HeaderMap::new();
        headers.insert(
            crate::api::http::auth_observability::REQUEST_ID_HEADER,
            token.parse().expect("token is a valid header value"),
        );

        let _ = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            headers,
            axum::extract::Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();

        let event: Option<(String,)> = sqlx::query_as(
            "SELECT concat_ws('|', endpoint, event_type, outcome, reason_code, http_status)
             FROM auth_events WHERE request_id = $1",
        )
        .bind(&token)
        .fetch_optional(&pool)
        .await
        .expect("query should succeed");

        let event = event
            .expect("GET verify must record an auth event, not silently drop the outcome")
            .0;
        assert_eq!(
            event,
            "/api/auth/verify-email|email_verification|failure|verification_link_superseded|200"
        );

        let method: Option<String> = sqlx::query_scalar(
            "SELECT metadata_json->>'method' FROM auth_events WHERE request_id = $1",
        )
        .bind(&token)
        .fetch_one(&pool)
        .await
        .expect("query should succeed");
        assert_eq!(
            method.as_deref(),
            Some("GET"),
            "the transport must be recorded so GET and POST stay comparable"
        );

        let _ = sqlx::query("DELETE FROM auth_events WHERE request_id = $1")
            .bind(&token)
            .execute(&pool)
            .await;
    }

    /// A superseded token reaching the POST/SPA path answers with the same actionable copy and a
    /// machine-readable code, instead of the generic "Please log in again." (keycast#268).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_post_dead_token_does_not_say_log_in_again() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());

        let response = verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: format!("nonexistent_{}", Uuid::new_v4()),
            }),
        )
        .await
        .map(axum::response::IntoResponse::into_response)
        .unwrap_or_else(axum::response::IntoResponse::into_response);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("error body should be JSON");

        assert_eq!(
            body["code"].as_str(),
            Some(VERIFICATION_LINK_SUPERSEDED_CODE),
            "clients need a machine-readable code to branch on, got: {body}"
        );
        let message = body["error"].as_str().unwrap_or_default();
        assert!(
            !message.contains("log in again"),
            "superseded verification links must not say 'log in again', got: {message}"
        );
        assert!(
            message.contains("replaced by a newer verification email"),
            "message should explain the real cause, got: {message}"
        );
    }

    /// GET verify hitting the duplicate-email conflict must render the "log in instead" page with
    /// a 409, not the generic invalid-link page (f4): the registration is terminally dead, and
    /// the page must say why.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_duplicate_email_shows_login_page() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let existing_pubkey = Keys::generate().public_key().to_hex();
        let duplicate_email = format!("verify-get-dup-{}@example.com", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&existing_pubkey)
        .bind(&duplicate_email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        let (pending_pubkey, token) =
            insert_oauth_pending_registration(&pool, &duplicate_email).await;

        let response = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            axum::extract::Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();

        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "duplicate email on GET verify should surface as 409"
        );
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body_bytes);
        assert!(
            body.contains("already registered"),
            "page must tell the user the email is already registered: {body}"
        );

        cleanup_verify_email_test_data(&pool, &existing_pubkey, &token).await;
        cleanup_verify_email_test_data(&pool, &pending_pubkey, &token).await;
    }

    /// GET verify for a headless registration when Redis is unavailable must render a
    /// retry-friendly 503 page (finalize returns ServiceUnavailable), not a terminal
    /// "verification failed" page: the link is still good and a refresh will succeed (f4).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_get_headless_without_redis_returns_retry_page() {
        let pool = create_test_db().await;
        // No Redis on this state: the headless RedisRequired path must fail retryably.
        let auth_state = create_test_auth_state(pool.clone());
        let email = format!("verify-get-noredis-{}@example.com", Uuid::new_v4());
        let (pubkey, token, _device_code) =
            insert_headless_pending_registration(&pool, &email).await;

        let response = verify_email_get(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            axum::extract::Query(VerifyEmailQuery {
                token: Some(token.clone()),
            }),
        )
        .await
        .into_response();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "retryable failure must not render as a 2xx success-looking page"
        );
        assert!(
            response.headers().get("Retry-After").is_some(),
            "retryable page should carry Retry-After"
        );
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body_bytes);
        assert!(
            body.contains("http-equiv=\"refresh\""),
            "retry page should auto-refresh so webview users are not stranded: {body}"
        );
        assert!(
            !body.contains("invalid"),
            "retry page must not read as a terminal failure: {body}"
        );
        assert!(
            !body.contains("Your email is verified"),
            "retry page must not claim verification succeeded before retryable work completes: {body}"
        );
        assert!(
            body.contains("temporary problem verifying your link"),
            "retry page should explain the temporary verification problem neutrally: {body}"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// A failed strict Redis delivery preserves the exchange code for a retry.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_finalize_pending_registration_fresh_code_redis_failure_preserves_code() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state_with_failing_redis(pool.clone()).await;
        let redis = auth_state.state.redis.as_ref().expect("failing Redis");
        let repo = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
        let email = format!("verify-fresh-redis-fail-{}@example.com", Uuid::new_v4());
        let (pubkey, token, _device_code) =
            insert_headless_pending_registration(&pool, &email).await;
        let pending = repo
            .find_by_verification_token(&token, 1)
            .await
            .unwrap()
            .expect("pending registration");

        let result = super::finalize_pending_registration(
            &pool,
            Some(redis),
            1,
            &pending,
            super::HeadlessDelivery::RedisRequired,
        )
        .await;

        assert!(matches!(
            result,
            Err(super::AuthError::ServiceUnavailable { .. })
        ));
        assert!(
            repo.find_by_verification_token(&token, 1)
                .await
                .unwrap()
                .is_some(),
            "Redis failure must preserve the pending registration for retry"
        );
        let (email_verified,): (bool,) =
            sqlx::query_as("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            email_verified,
            "the user must remain materialized and verified"
        );
        assert!(
            repo.find_live_exchange_code_with_expiry_for_pending(1, &pending)
                .await
                .unwrap()
                .is_some(),
            "the live code must remain reusable after a retryable Redis failure"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// A failed strict Redis redelivery must not delete a still-live code owned by a prior
    /// successful finalize, because the polling app may already hold that code.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_finalize_pending_registration_reused_code_redis_failure_preserves_code() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state_with_failing_redis(pool.clone()).await;
        let redis = auth_state.state.redis.as_ref().expect("failing Redis");
        let repo = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
        let email = format!("verify-reused-redis-fail-{}@example.com", Uuid::new_v4());
        let (pubkey, token, _device_code) =
            insert_headless_pending_registration(&pool, &email).await;
        let pending = repo
            .find_by_verification_token(&token, 1)
            .await
            .unwrap()
            .expect("pending registration");

        let first = super::finalize_pending_registration(
            &pool,
            None,
            1,
            &pending,
            super::HeadlessDelivery::RedisBestEffort,
        )
        .await
        .expect("first finalize mints a reusable live code");

        let result = super::finalize_pending_registration(
            &pool,
            Some(redis),
            1,
            &pending,
            super::HeadlessDelivery::RedisRequired,
        )
        .await;

        assert!(matches!(
            result,
            Err(super::AuthError::ServiceUnavailable { .. })
        ));
        let live_code = repo
            .find_live_exchange_code_with_expiry_for_pending(1, &pending)
            .await
            .unwrap()
            .map(|(code, _expires_at)| code);
        assert_eq!(
            live_code.as_deref(),
            Some(first.new_code.as_str()),
            "Redis redelivery failure must leave the reused code intact"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &token).await;
    }

    /// Acceptance: the link path and the PIN path produce identical materialization, because both
    /// funnel through finalize_pending_registration (keycast#262). The only difference is the
    /// headless Redis-delivery strictness, which does not change the user/keys/code outcome.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_link_and_pin_paths_finalize_identically() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state_with_redis(pool.clone()).await;
        let redis = auth_state.state.redis.clone();
        let repo = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());

        let email_a = format!("identical-link-{}@example.com", Uuid::new_v4());
        let email_b = format!("identical-pin-{}@example.com", Uuid::new_v4());
        let (pubkey_a, token_a, _dc_a) =
            insert_headless_pending_registration(&pool, &email_a).await;
        let (pubkey_b, token_b, _dc_b) =
            insert_headless_pending_registration(&pool, &email_b).await;

        let data_a = repo
            .find_by_verification_token(&token_a, 1)
            .await
            .unwrap()
            .unwrap();
        let data_b = repo
            .find_by_verification_token(&token_b, 1)
            .await
            .unwrap()
            .unwrap();

        // A finalizes via the link path's delivery mode; B via the PIN path's.
        let ra = super::finalize_pending_registration(
            &pool,
            redis.as_ref(),
            1,
            &data_a,
            super::HeadlessDelivery::RedisRequired,
        )
        .await
        .expect("link-path finalize succeeds");
        let rb = super::finalize_pending_registration(
            &pool,
            redis.as_ref(),
            1,
            &data_b,
            super::HeadlessDelivery::RedisBestEffort,
        )
        .await
        .expect("pin-path finalize succeeds");

        assert_eq!(ra.is_headless, rb.is_headless);
        assert!(!ra.new_code.is_empty() && !rb.new_code.is_empty());

        // Both paths materialize an identically-shaped result: verified user + 1 personal key +
        // a fresh headless 10-minute exchange code, with the pending row preserved.
        for (pubkey, code) in [(&pubkey_a, &ra.new_code), (&pubkey_b, &rb.new_code)] {
            let (verified,): (bool,) = sqlx::query_as(
                "SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1",
            )
            .bind(pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(verified, "user must be materialized as verified");

            let (key_count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = 1",
            )
            .bind(pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(key_count, 1, "personal_keys must be created exactly once");

            let minted = repo
                .find_valid(1, code)
                .await
                .unwrap()
                .expect("a fresh exchange code must be minted");
            assert!(minted.is_headless);
        }

        assert!(
            repo.find_by_verification_token(&token_a, 1)
                .await
                .unwrap()
                .is_some(),
            "link-path pending row must be preserved"
        );
        assert!(
            repo.find_by_verification_token(&token_b, 1)
                .await
                .unwrap()
                .is_some(),
            "pin-path pending row must be preserved"
        );

        cleanup_verify_email_test_data(&pool, &pubkey_a, &token_a).await;
        cleanup_verify_email_test_data(&pool, &pubkey_b, &token_b).await;
    }

    #[cfg(feature = "integration-tests")]
    async fn insert_pending_oauth_registration(
        pool: &PgPool,
        pubkey: &str,
        email: &str,
        verification_token: &str,
        password_hash: &str,
        encrypted_secret: Option<&[u8]>,
    ) {
        let placeholder_code = format!("placeholder_{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO oauth_codes (
                tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                expires_at, created_at, pending_email, pending_password_hash,
                pending_email_verification_token, pending_encrypted_secret
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11)",
        )
        .bind(1_i64)
        .bind(&placeholder_code)
        .bind(pubkey)
        .bind("TestApp")
        .bind("https://test.example.com/callback")
        .bind("policy:social")
        .bind(Utc::now() + Duration::hours(24))
        .bind(email)
        .bind(password_hash)
        .bind(verification_token)
        .bind(encrypted_secret)
        .execute(pool)
        .await
        .unwrap();
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_applies_pending_registration_to_bare_user_row() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let pending_keys = Keys::generate();
        let pubkey = pending_keys.public_key().to_hex();
        let email = format!("verify-bare-row-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;

        // Bare row pre-created by another path (team add, authorization pre-create)
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        insert_pending_oauth_registration(
            &pool,
            &pubkey,
            &email,
            &verification_token,
            &password_hash,
            Some(&encrypted_secret),
        )
        .await;

        let response = match verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::OK);

        let row: (Option<String>, Option<String>, bool) = sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users
             WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row.0.as_deref(),
            Some(email.as_str()),
            "pending email must be applied to the pre-existing bare row"
        );
        assert_eq!(
            row.1.as_deref(),
            Some(password_hash.as_str()),
            "pending password must be applied to the pre-existing bare row"
        );
        assert!(row.2, "email must be marked verified");

        let key_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(key_count.0, 1, "personal key must be created");

        let usable_code_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND user_pubkey = $1 AND pending_email IS NULL",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(usable_code_count.0, 1, "OAuth code should be minted");

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_retry_backfills_missing_personal_key() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let pending_keys = Keys::generate();
        let pubkey = pending_keys.public_key().to_hex();
        let email = format!("verify-backfill-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let changed_password_hash =
            bcrypt::hash("changedpassword123", bcrypt::DEFAULT_COST).unwrap();
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;

        // Row already carries the pending email (prior retry applied it) but the
        // personal key is missing — e.g. a registration dropped by the old
        // idempotency-by-existence bug.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&email)
        .bind(&changed_password_hash)
        .execute(&pool)
        .await
        .unwrap();

        insert_pending_oauth_registration(
            &pool,
            &pubkey,
            &email,
            &verification_token,
            &password_hash,
            Some(&encrypted_secret),
        )
        .await;

        let response = match verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::OK);

        let stored_secrets: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored_secrets.len(),
            1,
            "retry must backfill exactly one personal key"
        );
        assert_eq!(
            stored_secrets[0].0, encrypted_secret,
            "backfilled key must hold the pending secret"
        );

        let stored_password_hash: (String,) =
            sqlx::query_as("SELECT password_hash FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored_password_hash.0, changed_password_hash,
            "retry key backfill must not rewrite existing credentials"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_completes_same_email_unverified_row_before_minting() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let pending_keys = Keys::generate();
        let pubkey = pending_keys.public_key().to_hex();
        let email = format!("verify-incomplete-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;

        // Standard registration can leave the same pubkey/email row incomplete
        // until this verification link is clicked.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, NULL, false, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();

        insert_pending_oauth_registration(
            &pool,
            &pubkey,
            &email,
            &verification_token,
            &password_hash,
            Some(&encrypted_secret),
        )
        .await;

        let response = match verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::OK);

        let row: (Option<String>, Option<String>, bool) = sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users
             WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some(email.as_str()));
        assert_eq!(
            row.1.as_deref(),
            Some(password_hash.as_str()),
            "pending password must complete the incomplete same-email row"
        );
        assert!(row.2, "OAuth verification must mark the row verified");

        let usable_code_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND user_pubkey = $1 AND pending_email IS NULL",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(usable_code_count.0, 1, "OAuth code should be minted");

        let key_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(key_count.0, 1, "personal key must be created once");

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_conflicting_account_email_returns_conflict_without_minting() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let pending_keys = Keys::generate();
        let pubkey = pending_keys.public_key().to_hex();
        let existing_email = format!("verify-existing-{}@example.com", Uuid::new_v4());
        let pending_email = format!("verify-pending-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;

        // The pubkey is already bound to a different email.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&existing_email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        insert_pending_oauth_registration(
            &pool,
            &pubkey,
            &pending_email,
            &verification_token,
            &password_hash,
            Some(&encrypted_secret),
        )
        .await;

        let response = match verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let row: (Option<String>,) =
            sqlx::query_as("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            row.0.as_deref(),
            Some(existing_email.as_str()),
            "existing account email must not be overwritten"
        );

        let minted_code_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND user_pubkey = $1 AND pending_email IS NULL",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(minted_code_count.0, 0, "no OAuth code may be minted");

        let pending_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND pending_email_verification_token = $1",
        )
        .bind(&verification_token)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            pending_count.0, 0,
            "unresolvable pending registration should be cleaned up"
        );

        cleanup_verify_email_test_data(&pool, &pubkey, &verification_token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_email_bare_row_with_taken_email_returns_email_conflict() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let owner_pubkey = Keys::generate().public_key().to_hex();
        let pending_keys = Keys::generate();
        let pending_pubkey = pending_keys.public_key().to_hex();
        let email = format!("verify-taken-{}@example.com", Uuid::new_v4());
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let encrypted_secret = pending_keys.secret_key().to_secret_bytes().to_vec();

        cleanup_verify_email_test_data(&pool, &owner_pubkey, &verification_token).await;
        cleanup_verify_email_test_data(&pool, &pending_pubkey, &verification_token).await;

        // Another user owns the pending email; the pending pubkey has a bare row.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&owner_pubkey)
        .bind(&email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&pending_pubkey)
        .execute(&pool)
        .await
        .unwrap();

        insert_pending_oauth_registration(
            &pool,
            &pending_pubkey,
            &email,
            &verification_token,
            &password_hash,
            Some(&encrypted_secret),
        )
        .await;

        let response = match verify_email(
            create_test_tenant(),
            State(auth_state),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: verification_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response_json(response).await;
        assert_eq!(body["code"], super::EMAIL_ALREADY_EXISTS_CODE);

        let row: (Option<String>,) =
            sqlx::query_as("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pending_pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, None, "bare row must stay untouched on conflict");

        let minted_code_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE tenant_id = 1 AND user_pubkey = $1 AND pending_email IS NULL",
        )
        .bind(&pending_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(minted_code_count.0, 0, "no OAuth code may be minted");

        cleanup_verify_email_test_data(&pool, &owner_pubkey, &verification_token).await;
        cleanup_verify_email_test_data(&pool, &pending_pubkey, &verification_token).await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_update_profile_username_taken_returns_conflict() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let first_pubkey = Keys::generate().public_key().to_hex();
        let second_keys = Keys::generate();
        let second_pubkey = second_keys.public_key().to_hex();
        let username = format!("profile-conflict-{}", &first_pubkey[..8]);

        cleanup_verify_email_test_data(&pool, &first_pubkey, "unused").await;
        cleanup_verify_email_test_data(&pool, &second_pubkey, "unused").await;

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())",
        )
        .bind(&first_pubkey)
        .bind(1_i64)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(&second_pubkey)
        .bind(1_i64)
        .execute(&pool)
        .await
        .unwrap();

        let token = generate_ucan_token(
            &second_keys,
            1_i64,
            "second@example.com",
            "http://localhost:3000",
            None,
            None,
        )
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let response = match update_profile(
            create_test_tenant(),
            State(auth_state),
            headers,
            Json(ProfileData {
                username: Some(username.clone()),
                name: None,
                picture: None,
                about: None,
                banner: None,
                nip05: None,
                website: None,
                lud16: None,
            }),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);

        cleanup_verify_email_test_data(&pool, &first_pubkey, "unused").await;
        cleanup_verify_email_test_data(&pool, &second_pubkey, "unused").await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_login_missing_personal_keys_returns_conflict() {
        let pool = create_test_db().await;
        let auth_state = create_test_auth_state(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        let email = format!("missing-keys-{}@example.com", Uuid::new_v4());
        let password = "testpassword123";
        let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();

        cleanup_verify_email_test_data(&pool, &pubkey, "unused").await;

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, $4, true, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(1_i64)
        .bind(&email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:3000"));

        let response = match login(
            create_test_tenant(),
            State(auth_state),
            headers,
            format!(r#"{{"email":"{email}","password":"{password}"}}"#),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(err) => err.into_response(),
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);

        cleanup_verify_email_test_data(&pool, &pubkey, "unused").await;
    }

    #[cfg(feature = "integration-tests")]
    /// Mock signing handler for testing
    #[derive(Clone)]
    struct MockSigningHandler {
        user_keys: Keys,
        auth_id: i64,
    }

    #[cfg(feature = "integration-tests")]
    #[async_trait::async_trait]
    impl SigningHandler for MockSigningHandler {
        async fn sign_event_direct(
            &self,
            unsigned_event: UnsignedEvent,
        ) -> Result<nostr_sdk::Event, Box<dyn std::error::Error + Send + Sync>> {
            let signed = unsigned_event
                .sign(&self.user_keys)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(signed)
        }

        fn authorization_id(&self) -> i64 {
            self.auth_id
        }

        fn user_pubkey(&self) -> String {
            self.user_keys.public_key().to_hex()
        }

        fn get_keys(&self) -> Keys {
            self.user_keys.clone()
        }
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_fast_path_components() {
        // Test that all fast path components work correctly
        let pool = create_test_db().await;
        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();

        // Use unique redirect_origin for this test
        let redirect_origin = format!("https://test-{}.app", uuid::Uuid::new_v4());

        // Insert test user
        sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();

        // Insert OAuth authorization (client_id stored directly on oauth_authorizations)
        let bunker_keys = Keys::generate();
        let bunker_pubkey = bunker_keys.public_key().to_hex();

        sqlx::query(
            "INSERT INTO oauth_authorizations (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays, tenant_id, handle_expires_at, created_at, updated_at)
             VALUES ($1, $2, 'Test App', $3, 'test_hash', '[]', 1, NOW() + INTERVAL '30 days', NOW(), NOW())"
        )
        .bind(&user_pubkey)
        .bind(&redirect_origin)
        .bind(&bunker_pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // Verify we can query bunker_public_key (fast path lookup - finds any valid authorization)
        let result: Option<String> = sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_pubkey = u.pubkey
             WHERE oa.user_pubkey = $1 AND u.tenant_id = 1
             ORDER BY oa.created_at DESC
             LIMIT 1",
        )
        .bind(&user_pubkey)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert_eq!(
            result,
            Some(bunker_pubkey),
            "Should find bunker pubkey for fast path"
        );

        // Verify handler can sign
        let mock_handler = MockSigningHandler {
            user_keys: user_keys.clone(),
            auth_id: 1,
        };

        let unsigned = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            "Test fast path",
        );

        let signed = mock_handler.sign_event_direct(unsigned).await.unwrap();
        assert!(signed.verify().is_ok());

        println!("✅ Fast path components test passed");
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_slow_path_components() {
        // Test that slow path (DB + KMS) works correctly
        let pool = create_test_db().await;
        let key_manager = FileKeyManager::new().unwrap();

        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let user_secret_bytes = user_keys.secret_key().to_secret_bytes();

        // Encrypt user secret key (raw 32 bytes, consistent with registration)
        let encrypted_secret = key_manager.encrypt(&user_secret_bytes).await.unwrap();

        // Insert test user
        sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();

        // Insert personal keys
        sqlx::query("INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id) VALUES ($1, $2, 1)")
            .bind(&user_pubkey)
            .bind(&encrypted_secret)
            .execute(&pool)
            .await
            .unwrap();

        // Test slow path: DB query
        let result: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT pk.encrypted_secret_key
             FROM personal_keys pk
             JOIN users u ON pk.user_pubkey = u.pubkey
             WHERE pk.user_pubkey = $1 AND u.tenant_id = 1",
        )
        .bind(&user_pubkey)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(result.is_some(), "Should find encrypted key");

        // Test decryption
        let (encrypted,) = result.unwrap();
        let decrypted = key_manager.decrypt(&encrypted).await.unwrap();
        // Decrypted bytes are raw 32-byte secret key
        let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted).unwrap();
        let recovered_keys = Keys::new(secret_key.into());

        // Test signing
        let unsigned = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            "Test slow path",
        );

        let signed = unsigned.sign(&recovered_keys).await.unwrap();
        assert!(signed.verify().is_ok());

        println!("✅ Slow path components test passed");
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_fallback_when_handler_not_cached() {
        // Test that system falls back to slow path when handler not in cache
        let pool = create_test_db().await;
        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();

        // Insert user but NO OAuth authorization
        sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();

        // Query for bunker_pubkey should return None
        let bunker_pubkey: Option<String> = sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_pubkey = u.pubkey
             WHERE oa.user_pubkey = $1 AND u.tenant_id = 1",
        )
        .bind(&user_pubkey)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(
            bunker_pubkey.is_none(),
            "Should not find OAuth authorization for fallback"
        );

        println!("✅ Fallback detection test passed");
    }

    #[tokio::test]
    async fn test_signature_validation() {
        // Test that signatures are valid
        let user_keys = Keys::generate();

        let unsigned = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            "Test signature",
        );

        let signed = unsigned.sign(&user_keys).await.unwrap();

        assert!(signed.verify().is_ok(), "Signature should be valid");
        assert_eq!(signed.pubkey, user_keys.public_key());
        assert_eq!(signed.content, "Test signature");

        println!("✅ Signature validation test passed");
    }

    #[tokio::test]
    async fn test_permission_validation_allows_text_note() {
        // Test that text notes (kind 1) are allowed by default
        let user_keys = Keys::generate();

        let unsigned = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote, // Kind 1 - should be allowed
            vec![],
            "This is a normal text note",
        );

        let signed = unsigned.sign(&user_keys).await.unwrap();
        assert!(signed.verify().is_ok());

        // Permission validation now implemented in signer daemon (see signer/tests/permission_validation_tests.rs)
        println!("✅ Permission validation allows text notes");
    }

    #[tokio::test]
    async fn test_permission_validation_blocks_restricted_kinds() {
        // Test that certain restricted event kinds could be blocked
        // For now, this is a placeholder - real implementation will have configurable policies

        let user_keys = Keys::generate();

        // Example: Kind 0 (metadata), Kind 3 (contacts), Kind 7 (reaction) should all be allowed
        // But hypothetically we might want to restrict certain kinds in the future

        let test_kinds = vec![
            (Kind::Metadata, "Metadata"),
            (Kind::ContactList, "ContactList"),
            (Kind::Reaction, "Reaction"),
        ];

        for (kind, name) in test_kinds {
            let unsigned = UnsignedEvent::new(
                user_keys.public_key(),
                Timestamp::now(),
                kind,
                vec![],
                format!("Test {}", name),
            );

            let signed = unsigned.sign(&user_keys).await;
            assert!(signed.is_ok(), "{} should be signable", name);
        }

        println!("✅ Permission validation tested for various kinds");
    }

    #[tokio::test]
    async fn test_permission_validation_content_length() {
        // Test that extremely long content could potentially be restricted
        let user_keys = Keys::generate();

        // Test normal length (should pass)
        let normal_content = "This is a normal length message";
        let unsigned_normal = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            normal_content,
        );

        let signed = unsigned_normal.sign(&user_keys).await.unwrap();
        assert!(signed.verify().is_ok());

        // Test very long content (currently no limit, but we might want one)
        let long_content = "x".repeat(100_000); // 100KB of text
        let unsigned_long = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            &long_content,
        );

        let signed_long = unsigned_long.sign(&user_keys).await.unwrap();
        assert!(signed_long.verify().is_ok());

        // NOTE: Content length validation not implemented yet (would need new permission type)
        // Current permissions: allowed_kinds, content_filter (word blocking), encrypt_to_self
        println!("✅ Content length validation tested");
    }

    #[test]
    fn test_normalize_nip05_username_accepts_required_charset_and_lowercases() {
        let normalized = super::normalize_nip05_username("Alice.Name_123")
            .expect("username should normalize successfully");
        assert_eq!(normalized, "alice.name_123");
    }

    #[test]
    fn test_normalize_nip05_username_rejects_invalid_chars() {
        let result = super::normalize_nip05_username("alice+name");
        assert!(
            result.is_err(),
            "plus sign is not allowed in NIP-05 local-part"
        );
    }

    #[test]
    fn test_normalize_nip05_username_rejects_non_ascii() {
        let result = super::normalize_nip05_username("álîce");
        assert!(
            result.is_err(),
            "non-ascii usernames should be rejected for NIP-05 local-part compliance"
        );
    }

    #[test]
    fn test_normalize_nip05_username_rejects_hyphen_edges() {
        assert!(super::normalize_nip05_username("-alice").is_err());
        assert!(super::normalize_nip05_username("alice-").is_err());
    }

    #[test]
    fn resolve_nip05_domain_uses_tenant_for_public_hosts() {
        assert_eq!(
            super::resolve_nip05_domain("login.example.com"),
            "login.example.com"
        );
    }

    #[test]
    fn test_normalize_nip05_username_accepts_max_length_boundary() {
        let username = "a".repeat(super::MAX_NIP05_USERNAME_LENGTH);
        let normalized = super::normalize_nip05_username(&username)
            .expect("username with max allowed length should normalize");
        assert_eq!(normalized, username);
    }

    #[test]
    fn test_normalize_nip05_username_rejects_length_above_boundary() {
        let username = "a".repeat(super::MAX_NIP05_USERNAME_LENGTH + 1);
        let result = super::normalize_nip05_username(&username);
        assert!(
            result.is_err(),
            "username longer than max boundary should be rejected"
        );
    }

    #[test]
    fn test_normalize_registration_email_accepts_common_addresses() {
        for email in [
            "person@example.com",
            "Person+tag@Example.COM",
            "first.last@sub.example.co.uk",
        ] {
            assert!(
                super::normalize_registration_email(email).is_ok(),
                "{email} should be accepted"
            );
        }
    }

    #[test]
    fn test_normalize_registration_email_rejects_malformed_addresses() {
        for email in [
            "person@gmail..com",
            "person@exa_mple.com",
            "person@gm!ail.com",
            "person@-example.com",
            "person@example-.com",
            "person(foo)@example.com",
            "person<evil>@example.com",
            "\u{212a}@example.com",
            "person@\u{212a}.example.com",
            "person@.example.com",
            "person@example.com.",
            ".person@example.com",
            "person.@example.com",
            "personexample.com",
            "person@localhost",
            "person @example.com",
            "",
        ] {
            assert!(
                super::normalize_registration_email(email).is_err(),
                "{email} should be rejected"
            );
        }

        let local_too_long = format!("{}@example.com", "a".repeat(65));
        assert!(
            super::normalize_registration_email(&local_too_long).is_err(),
            "local part longer than 64 bytes should be rejected"
        );

        let domain_label_too_long = format!("person@{}.com", "a".repeat(64));
        assert!(
            super::normalize_registration_email(&domain_label_too_long).is_err(),
            "domain labels longer than 63 bytes should be rejected"
        );
    }
}
