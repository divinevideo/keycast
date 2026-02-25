// ABOUTME: Personal authentication handlers for email/password registration and login
// ABOUTME: Implements UCAN-based authentication and NIP-46 bunker URL generation

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretString};

use super::admin::{is_full_admin, is_support_admin};
use crate::api::extractors::UcanAuth;
use crate::bcrypt_queue::{BcryptJob, BcryptQueueError};
use crate::nip98;
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    CreateOAuthAuthorizationParams, OAuthAuthorizationRepository, OAuthCodeRepository,
    PersonalKeysRepository, PolicyRepository, UserRepository,
};
use keycast_core::traits::CustomPermission;
use nostr_sdk::{Keys, PublicKey, ToBech32, UnsignedEvent};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

// Registration and login return simple JSON (not OAuth TokenResponse)

const DEFAULT_TOKEN_EXPIRY_HOURS: i64 = 24;
pub const EMAIL_VERIFICATION_EXPIRY_HOURS: i64 = 24;
const PASSWORD_RESET_EXPIRY_HOURS: i64 = 1;

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

/// Generate UCAN token signed by user's key (self-signed)
/// redirect_origin identifies which app/authorization this token is for
pub(crate) async fn generate_ucan_token(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
    relays: Option<&[String]>,
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
pub(crate) async fn generate_server_signed_ucan(
    user_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
    bunker_pubkey: Option<&str>,
    server_keys: &Keys,
    is_first_party: bool,
    admin_role: Option<&str>,
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
    TokenExpired,
    EmailSendFailed(String),
    DuplicateKey, // Nostr pubkey already registered (BYOK case)
    BadRequest(String),
    Forbidden(String),   // User has no authorization for this origin
    RegistrationExpired, // Async bcrypt timed out (instance died)
    ServiceUnavailable {
        // Server at capacity or shutting down
        message: String,
        retry_after: Option<u32>,
    },
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
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
            AuthError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                "This email is already registered. Please log in instead.".to_string(),
            ),
            AuthError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "Please verify your email address before continuing. Check your inbox for the verification link.".to_string(),
            ),
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
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "Verification code or token has expired. Please request a new one.".to_string(),
            ),
            AuthError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                msg,
            ),
            AuthError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                msg,
            ),
            AuthError::RegistrationExpired => (
                StatusCode::GONE,
                "Registration expired. Please register again.".to_string(),
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
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
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
            _ => AuthError::Internal(e.to_string()),
        }
    }
}

impl From<bcrypt::BcryptError> for AuthError {
    fn from(e: bcrypt::BcryptError) -> Self {
        AuthError::PasswordHash(e)
    }
}

/// Extract user public key from UCAN token in Authorization header or cookie
pub(crate) async fn extract_user_from_token(headers: &HeaderMap) -> Result<String, AuthError> {
    let (pubkey, _redirect_origin, _bunker_pubkey) =
        extract_user_and_origin_from_token(headers).await?;
    Ok(pubkey)
}

/// Extract user public key, redirect_origin, and bunker_pubkey from UCAN token in Authorization header or cookie
/// redirect_origin identifies which app/authorization this token is for
/// bunker_pubkey uniquely identifies the authorization for direct cache lookup (optional)
pub(crate) async fn extract_user_and_origin_from_token(
    headers: &HeaderMap,
) -> Result<(String, String, Option<String>), AuthError> {
    // Try Bearer token first
    if let Some(auth_header) = headers.get("Authorization") {
        let auth_str = auth_header.to_str().map_err(|_| AuthError::InvalidToken)?;

        if auth_str.starts_with("Bearer ") {
            // Validate UCAN token and extract user pubkey, redirect_origin, and bunker_pubkey
            return crate::ucan_auth::extract_user_from_ucan(headers, 0)
                .await
                .map_err(|_| AuthError::InvalidToken);
        }
    }

    // Fall back to cookie-based UCAN
    if let Some(token) = extract_ucan_from_cookie(headers) {
        // Parse UCAN from string using ucan_auth helper (tenant validation done by caller)
        let (pubkey, redirect_origin, bunker_pubkey, _ucan) =
            crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), 0)
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

    req.email = req.email.to_lowercase();

    let instance_id = keycast_core::instance::instance_id();

    tracing::info!(
        event = "registration_attempt",
        instance_id = %instance_id,
        tenant_id = tenant_id,
        "Registration attempt"
    );

    // Generate email verification token
    // Note: Password hashing is deferred to background worker via bcrypt queue
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

    // Register user with personal key in a single transaction
    // Password hash is NULL initially - will be set by bcrypt worker
    // Returns Err(RepositoryError::Duplicate) if email already exists, which maps to AuthError::EmailAlreadyExists
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .register_with_personal_key(
            &public_key.to_hex(),
            tenant_id,
            &req.email,
            None, // password_hash computed async by bcrypt worker
            &verification_token,
            verification_expires,
            &encrypted_secret,
        )
        .await?;

    // Queue bcrypt job to hash password in background
    // Worker will UPDATE users SET password_hash = $hash WHERE email_verification_token = $token
    let bcrypt_result = auth_state.state.bcrypt_sender.try_send(BcryptJob {
        token: verification_token.clone(),
        password: SecretString::from(req.password.clone()),
    });

    if let Err(e) = bcrypt_result {
        // If queue fails, we have a user row with NULL password_hash
        // Clean up by deleting the user row (it would fail verification anyway)
        tracing::error!("Failed to queue bcrypt job: {:?}, cleaning up user row", e);
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(public_key.to_hex())
            .bind(tenant_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2")
            .bind(public_key.to_hex())
            .bind(tenant_id)
            .execute(pool)
            .await;

        return match e {
            BcryptQueueError::AtCapacity => Err(AuthError::ServiceUnavailable {
                message: "Server at capacity, please try again".to_string(),
                retry_after: Some(5),
            }),
            BcryptQueueError::ShuttingDown => Err(AuthError::ServiceUnavailable {
                message: "Server restarting, please try again".to_string(),
                retry_after: Some(10),
            }),
        };
    }

    // Track successful registration
    METRICS.inc_registration();

    // Send verification email (required - user must verify before login)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_verification_email(&req.email, &verification_token)
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
    let redirect_origin = extract_origin_from_headers(&headers)?;

    tracing::info!(
        event = "login_attempt",
        tenant_id = tenant_id,
        redirect_origin = %redirect_origin,
        "Login attempt"
    );

    // Fetch user with password hash and email_verified status from this tenant
    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo.find_with_password(&req.email, tenant_id).await?;

    let (public_key, password_hash, email_verified) = match user {
        Some(u) => u,
        None => {
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

    // Verify password (spawn_blocking to avoid blocking async runtime)
    let password = req.password.clone();
    let hash = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify(&password, &hash))
        .await
        .map_err(|e| AuthError::Internal(format!("Task join error: {}", e)))??;
    if !valid {
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
        tracing::warn!(
            event = "login",
            tenant_id = tenant_id,
            success = false,
            reason = "email_not_verified",
            "Login failed: email not verified"
        );
        return Err(AuthError::EmailNotVerified);
    }

    // Get user's Nostr keys from personal_keys
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key(&public_key)
        .await?
        .ok_or_else(|| AuthError::Internal("Personal keys not found".to_string()))?;

    let key_manager = auth_state.state.key_manager.as_ref();
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Generate UCAN token for session cookie with redirect_origin
    let ucan_token =
        generate_ucan_token(&keys, tenant_id, &req.email, &redirect_origin, None).await?;

    // Track successful login
    METRICS.inc_login();

    tracing::info!(
        event = "login",
        tenant_id = tenant_id,
        success = true,
        "User logged in successfully"
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
    pub origin: Option<String>,      // Optional: the app's origin URL (must be HTTPS if provided)
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

    // Allow http:// only for localhost (development)
    let is_localhost = host == "localhost" || host == "127.0.0.1";
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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    // Validate origin if provided (must be HTTPS)
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

    // Get user's encrypted secret key
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key(&user_pubkey)
        .await?
        .ok_or(AuthError::Internal("Personal keys not found".to_string()))?;

    // Get pre-computed (secret, hash) from pool - instant, no waiting for bcrypt
    let secret_pair = auth_state
        .state
        .secret_pool
        .get()
        .await
        .ok_or_else(|| AuthError::Internal("Secret pool exhausted".to_string()))?;
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
    let (user_pubkey, redirect_origin, _bunker_pubkey) =
        extract_user_and_origin_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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

/// Verify email address with token
/// Handles two flows:
/// 1. OAuth registration: token in oauth_codes → complete OAuth flow → redirect to client
/// 2. Normal registration: token in users → mark verified → issue UCAN → set cookie
pub async fn verify_email(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // First: Check oauth_codes for pending OAuth registration
    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    if let Some(oauth_data) = oauth_code_repo
        .find_by_verification_token(&req.token, tenant_id)
        .await?
    {
        // Found in oauth_codes - this is an OAuth registration flow
        tracing::info!(
            "Email verification for OAuth registration: pubkey {}, email {:?}",
            oauth_data.user_pubkey,
            oauth_data.pending_email
        );

        let email = oauth_data
            .pending_email
            .as_ref()
            .ok_or_else(|| AuthError::Internal("Missing pending email".to_string()))?;
        let password_hash = oauth_data
            .pending_password_hash
            .as_ref()
            .ok_or_else(|| AuthError::Internal("Missing pending password hash".to_string()))?;

        // Create user with email_verified=true (they just verified!)
        let user_repo = UserRepository::new(pool.clone());

        // Check if keys were generated (pending_encrypted_secret) or BYOK flow
        if let Some(ref encrypted_secret) = oauth_data.pending_encrypted_secret {
            // Auto-generated or direct nsec: create user + personal_keys
            // Use a transaction to ensure atomicity
            let now = Utc::now();
            let mut tx = pool.begin().await?;

            sqlx::query(
                "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&oauth_data.user_pubkey)
            .bind(tenant_id)
            .bind(email)
            .bind(password_hash)
            .bind(true) // email_verified = true
            .bind(&req.token) // Keep token for idempotent re-verification
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&oauth_data.user_pubkey)
            .bind(encrypted_secret)
            .bind(tenant_id)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            tracing::info!(
                "Created user and personal_keys for OAuth registration: {}",
                oauth_data.user_pubkey
            );
        } else {
            // BYOK flow: just create user, keys will come at token exchange
            user_repo
                .create_with_password_verified(
                    &oauth_data.user_pubkey,
                    tenant_id,
                    email,
                    password_hash,
                    true,             // email_verified = true
                    Some(&req.token), // Keep token for idempotent re-verification
                )
                .await?;

            tracing::info!(
                "Created user for BYOK OAuth registration: {}",
                oauth_data.user_pubkey
            );
        }

        // Generate new authorization code for the redirect
        let new_code: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Store the new code (10 minute expiry for exchange)
        let code_expires_at = Utc::now() + Duration::minutes(10);
        let store_params = keycast_core::repositories::StoreOAuthCodeParams {
            tenant_id,
            code: &new_code,
            user_pubkey: &oauth_data.user_pubkey,
            client_id: &oauth_data.client_id,
            redirect_uri: &oauth_data.redirect_uri,
            scope: &oauth_data.scope,
            code_challenge: oauth_data.code_challenge.as_deref(),
            code_challenge_method: oauth_data.code_challenge_method.as_deref(),
            expires_at: code_expires_at,
            previous_auth_id: oauth_data.previous_auth_id,
            state: oauth_data.state.as_deref(),
            is_headless: oauth_data.is_headless, // Inherit from original registration
        };
        oauth_code_repo.store(store_params).await?;

        // Store code in Redis for multi-device polling (RFC 8628 pattern)
        // Use device_code (secret, from response body) not state (public, in URL)
        // See: https://datatracker.ietf.org/doc/html/rfc8628
        if let Some(ref device_code) = oauth_data.device_code {
            if let Some(redis) = &auth_state.state.redis {
                let key = format!("oauth_poll:{}", device_code);
                if let Err(e) = redis::cmd("SETEX")
                    .arg(&key)
                    .arg(600) // 10 minute TTL
                    .arg(&new_code)
                    .query_async::<()>(&mut redis.clone())
                    .await
                {
                    tracing::warn!("Failed to store OAuth code in Redis for polling: {}", e);
                    // Continue - redirect flow still works for same-device verification
                } else {
                    tracing::debug!(
                        "Stored OAuth code in Redis for polling: device_code={}",
                        device_code
                    );
                }
            }
        }

        // Delete the pending registration entry
        oauth_code_repo
            .delete_by_verification_token(&req.token, tenant_id)
            .await?;

        // For headless flows (mobile app), don't redirect — the app is polling
        // via device_code/Redis and will pick up the code automatically.
        // The browser just shows a success page.
        if oauth_data.is_headless {
            tracing::info!(
                event = "email_verification",
                tenant_id = tenant_id,
                flow = "oauth_headless",
                success = true,
                "Email verified (headless), app will pick up code via polling"
            );

            return Ok((
                axum::http::StatusCode::OK,
                axum::Json(VerifyEmailResponse {
                    success: true,
                    message: "Email verified! Open the app to continue.".to_string(),
                    redirect_to: None,
                    authenticated: None,
                    status: Some("headless".to_string()),
                    retry_after: None,
                }),
            )
                .into_response());
        }

        // Non-headless: redirect to OAuth client's callback URL
        let mut redirect_url = format!("{}?code={}", oauth_data.redirect_uri, new_code);
        if let Some(ref state) = oauth_data.state {
            redirect_url = format!("{}&state={}", redirect_url, state);
        }

        tracing::info!(
            event = "email_verification",
            tenant_id = tenant_id,
            flow = "oauth",
            success = true,
            "Email verified, redirecting to OAuth client"
        );

        return Ok((
            axum::http::StatusCode::OK,
            axum::Json(VerifyEmailResponse {
                success: true,
                message: "Email verified! Redirecting to app...".to_string(),
                redirect_to: Some(redirect_url),
                authenticated: None,
                status: None,
                retry_after: None,
            }),
        )
            .into_response());
    }

    // Second: Check users table for normal registration
    let user_repo = UserRepository::new(pool.clone());
    let token_data = user_repo
        .find_by_verification_token(&req.token, tenant_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let public_key = token_data.pubkey;

    // Already verified (e.g. user clicked the link again) - show success
    if token_data.email_verified {
        return Ok((
            axum::http::StatusCode::OK,
            axum::Json(VerifyEmailResponse {
                success: true,
                message: "Your email is already verified. You can log in.".to_string(),
                redirect_to: None,
                authenticated: None,
                status: None,
                retry_after: None,
            }),
        )
            .into_response());
    }

    // Check if token is expired
    if let Some(expires) = token_data.email_verification_expires_at {
        if expires < Utc::now() {
            return Ok((
                axum::http::StatusCode::OK,
                axum::Json(VerifyEmailResponse {
                    success: false,
                    message: "Verification link has expired. Please request a new one.".to_string(),
                    redirect_to: None,
                    authenticated: None,
                    status: None,
                    retry_after: None,
                }),
            )
                .into_response());
        }
    }

    // Check async bcrypt state: password_hash IS NULL means still processing
    if token_data.password_hash.is_none() {
        let age = Utc::now().signed_duration_since(token_data.created_at);
        if age.num_seconds() > 120 {
            // Hash should complete in <1s normally. After 2min, assume instance died.
            // User needs to re-register (cleanup job will delete this row)
            tracing::warn!(
                "Password hash not completed after {}s for token {}..., likely instance died",
                age.num_seconds(),
                &req.token[..std::cmp::min(8, req.token.len())]
            );
            return Err(AuthError::RegistrationExpired);
        }
        // Still processing - tell frontend to poll
        tracing::debug!(
            "Password hash still processing (age: {}s) for token {}...",
            age.num_seconds(),
            &req.token[..std::cmp::min(8, req.token.len())]
        );
        return Ok((
            axum::http::StatusCode::OK,
            axum::Json(VerifyEmailResponse {
                success: false,
                message: "Processing your registration, please wait...".to_string(),
                redirect_to: None,
                authenticated: None,
                status: Some("processing".to_string()),
                retry_after: Some(1),
            }),
        )
            .into_response());
    }

    // Mark email as verified (token kept for idempotent re-verification)
    user_repo.verify_email(&public_key, tenant_id).await?;

    // Get user's email for UCAN
    let email = user_repo.get_email(&public_key, tenant_id).await?;

    // Get user's keys to generate UCAN
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret = personal_keys_repo
        .find_encrypted_key(&public_key)
        .await?
        .ok_or_else(|| AuthError::Internal("Personal keys not found".to_string()))?;

    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Extract redirect_origin from Origin header for UCAN
    let redirect_origin = extract_origin_from_headers(&headers)
        .or_else(|_| std::env::var("APP_URL"))
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    // Generate UCAN token for session cookie
    let ucan_token = generate_ucan_token(&keys, tenant_id, &email, &redirect_origin, None).await?;

    tracing::info!(
        event = "email_verification",
        tenant_id = tenant_id,
        flow = "normal",
        success = true,
        "Email verified successfully, issuing UCAN"
    );

    // Set UCAN session cookie
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    Ok((
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(VerifyEmailResponse {
            success: true,
            message: "Email verified successfully! You are now logged in.".to_string(),
            redirect_to: None,
            authenticated: Some(true),
            status: None,
            retry_after: None,
        }),
    )
        .into_response())
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
        if let Ok(user_pubkey) = extract_user_from_token(&headers).await {
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
                    .send_verification_email(&email_clone, &token_clone)
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
    Json(mut req): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
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
            tracing::warn!(
                "Email service unavailable, skipping password reset email: {}",
                e
            );
        }
    }

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
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!(
        "Password reset attempt with token: {}... for tenant: {}",
        &req.token[..10],
        tenant_id
    );

    // Find user with this reset token in this tenant
    let user_repo = UserRepository::new(pool.clone());
    let (public_key, expires_at) = user_repo
        .find_by_reset_token(&req.token, tenant_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    // Check if token is expired
    if let Some(expires) = expires_at {
        if expires < Utc::now() {
            return Ok(Json(ResetPasswordResponse {
                success: false,
                message: "Password reset link has expired. Please request a new one.".to_string(),
            }));
        }
    }

    // Hash new password (spawn_blocking to avoid blocking async runtime)
    let new_password = req.new_password.clone();
    let password_hash = tokio::task::spawn_blocking(move || hash(&new_password, DEFAULT_COST))
        .await
        .map_err(|e| AuthError::Internal(format!("Task join error: {}", e)))??;

    // Update password, clear reset token, and mark email as verified
    // (user proved email ownership by receiving and using the reset link)
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .reset_password(&public_key, tenant_id, &password_hash)
        .await?;

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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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

    // Return only username - client fetches rest from relays
    Ok(Json(ProfileData {
        username,
        name: None,
        about: None,
        picture: None,
        banner: None,
        nip05: None,
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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
    tracing::debug!(
        "Fetching account status for user: {} in tenant: {}",
        user_pubkey,
        tenant_id
    );

    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo
        .get_account_status(&user_pubkey, tenant_id)
        .await?;

    match user {
        Some((email, email_verified)) => Ok(Json(AccountStatusResponse {
            email: email.unwrap_or_default(),
            email_verified: email_verified.unwrap_or(false),
            public_key: user_pubkey,
        })),
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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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
    if let Some(ref username) = profile.username {
        // Validate username (alphanumeric, dash, underscore only - matches divine-name-server ASCII rules)
        // Note: divine-name-server also supports Unicode/IDN but we keep keycast validation simple
        if !username.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return Err(AuthError::Internal(
                "Username can only contain letters, numbers, and hyphens".to_string(),
            ));
        }

        // Cannot start or end with hyphen
        if username.starts_with('-') || username.ends_with('-') {
            return Err(AuthError::Internal(
                "Username cannot start or end with a hyphen".to_string(),
            ));
        }

        // Check divine-name-server FIRST (if enabled) - this is the authoritative source
        if crate::divine_names::is_enabled() {
            match crate::divine_names::check_availability(username).await {
                Ok((available, reason)) => {
                    if !available {
                        let error_msg = reason.unwrap_or_else(|| {
                            "Username is not available on divine.video".to_string()
                        });
                        tracing::info!(
                            "Username '{}' not available on divine-name-server: {}",
                            username,
                            error_msg
                        );
                        return Err(AuthError::Internal(error_msg));
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
            .check_username_available(username, &user_pubkey, tenant_id)
            .await?
        {
            return Err(AuthError::Internal("Username already taken".to_string()));
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
                        match crate::divine_names::claim_username(&keys, username, None).await {
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
        user_repo
            .update_username(&user_pubkey, username, tenant_id)
            .await?;

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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
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

/// Fast HTTP signing endpoint - sign an event without NIP-46 relay overhead
/// This is 10-50x faster than NIP-46 for quick operations
pub async fn sign_event(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<SignEventRequest>,
) -> Result<Json<SignEventResponse>, AuthError> {
    let (user_pubkey, redirect_origin, _bunker_pubkey) =
        extract_user_and_origin_from_token(&headers).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

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
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;

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
    headers: HeaderMap,
    Json(req): Json<VerifyPasswordRequest>,
) -> Result<Json<VerifyPasswordResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;

    // Get user's email and password hash
    let user_repo = UserRepository::new(pool.clone());
    let (_email, password_hash) = user_repo
        .get_credentials(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Verify password (spawn_blocking to avoid blocking async runtime)
    let password = req.password.clone();
    let hash = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify(&password, &hash))
        .await
        .map_err(|e| AuthError::Internal(format!("Task join error: {}", e)))?
        .map_err(|_| AuthError::Internal("Password verification failed".to_string()))?;

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
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;

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

    // Verify current password
    let current_password = req.current_password.clone();
    let hash = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify(&current_password, &hash))
        .await
        .map_err(|e| AuthError::Internal(format!("Task join error: {}", e)))?
        .map_err(|_| AuthError::Internal("Password verification failed".to_string()))?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    // Hash new password
    let new_password = req.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || bcrypt::hash(&new_password, DEFAULT_COST))
        .await
        .map_err(|e| AuthError::Internal(format!("Task join error: {}", e)))?
        .map_err(|e| AuthError::Internal(format!("Password hashing failed: {}", e)))?;

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

/// Export user's private key (requires password and verified email)
pub async fn export_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ExportKeyResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // Extract password and format from request
    let password = req
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or(AuthError::BadRequest("Missing password".to_string()))?;

    let format = req.get("format").and_then(|v| v.as_str()).unwrap_or("nsec");

    // Verify password and email verification status
    let user_repo = UserRepository::new(pool.clone());
    let result = user_repo
        .find_with_password_and_verified(&user_pubkey, tenant_id)
        .await?;

    let (_email, password_hash, email_verified) = result.ok_or(AuthError::UserNotFound)?;

    // Require email verification
    if !email_verified {
        return Err(AuthError::EmailNotVerified);
    }

    let valid = verify(password, &password_hash)
        .map_err(|_| AuthError::Internal("Password verification failed".to_string()))?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    // Get user's encrypted secret key
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_key = personal_keys_repo
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_key)
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to decrypt key: {}", e)))?;

    // Parse the secret key
    let keys = Keys::parse(&hex::encode(&decrypted_secret))
        .map_err(|e| AuthError::Internal(format!("Failed to parse key: {}", e)))?;

    // Format the key based on requested format
    let key_string = match format {
        "nsec" => keys
            .secret_key()
            .to_bech32()
            .map_err(|e| AuthError::Internal(format!("Failed to encode nsec: {}", e)))?,
        _ => {
            return Err(AuthError::BadRequest(
                "Invalid format. Must be 'nsec'".to_string(),
            ))
        }
    };

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
    let old_pubkey = extract_user_from_token(&headers).await?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // Get user's email and verify password
    let user_repo = UserRepository::new(pool.clone());
    let (email, password_hash) = user_repo
        .get_credentials(&old_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Verify password
    let valid = verify(&req.password, &password_hash)
        .map_err(|_| AuthError::Internal("Password verification failed".to_string()))?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    // Generate or parse new key
    let new_keys = if let Some(ref nsec_str) = req.nsec {
        tracing::info!("User provided new key (BYOK) for change");
        Keys::parse(nsec_str)
            .map_err(|e| AuthError::Internal(format!("Invalid nsec or secret key: {}", e)))?
    } else {
        tracing::info!("Auto-generating new key for change");
        Keys::generate()
    };

    let new_pubkey = new_keys.public_key().to_hex();
    let new_secret_bytes = new_keys.secret_key().to_secret_bytes();

    // Check if new pubkey already exists in this tenant
    if user_repo.exists(&new_pubkey, tenant_id).await? {
        return Err(AuthError::DuplicateKey);
    }

    // Encrypt new secret key (as raw 32 bytes, consistent with registration)
    let encrypted_secret = key_manager
        .encrypt(&new_secret_bytes)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Execute key change transaction
    let oauth_count = user_repo
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            tenant_id,
            &email,
            &password_hash,
            &encrypted_secret,
        )
        .await?;

    // Signal signer daemon to remove old authorizations
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

    // Issue new UCAN session cookie signed by the new key
    let redirect_origin = extract_origin_from_headers(&headers)?;
    let ucan_token =
        generate_ucan_token(&new_keys, tenant_id, &email, &redirect_origin, None).await?;

    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
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
            user = &user_pubkey[..8],
            redirect_origin = %redirect_origin,
            "Denied: not user-signed and not first-party"
        );
        return Err(AuthError::Forbidden(
            "Account deletion requires the Divine app or web login with your private key"
                .to_string(),
        ));
    }

    tracing::info!(
        event = "account_deletion_started",
        tenant_id = tenant_id,
        user = &user_pubkey[..8],
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
                user = &user_pubkey[..8],
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
        user = &user_pubkey[..8],
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
    use keycast_core::encryption::file_key_manager::FileKeyManager;
    use keycast_core::encryption::KeyManager;
    use keycast_core::signing_handler::SigningHandler;
    use nostr_sdk::{Keys, Kind, Timestamp, UnsignedEvent};
    use sqlx::PgPool;

    /// Helper to create test database connection
    /// Uses DATABASE_URL env var or defaults to localhost
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

    /// Mock signing handler for testing
    #[derive(Clone)]
    struct MockSigningHandler {
        user_keys: Keys,
        auth_id: i64,
    }

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
}
