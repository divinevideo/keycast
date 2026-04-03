// ABOUTME: Headless authentication handlers for native mobile apps (Flutter, etc.)
// ABOUTME: Pure JSON API - no cookies, no HTML, returns access_token directly

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::verify;
use chrono::{Duration, Utc};
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    OAuthCodeRepository, PolicyRepository, StoreOAuthCodeWithRegistrationParams, UserRepository,
};
use nostr_sdk::Keys;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::auth::{generate_secure_token, EMAIL_VERIFICATION_EXPIRY_HOURS};
use super::oauth::{extract_origin, parse_policy_scope};

// ============================================================================
// Headless Registration
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct HeadlessRegisterRequest {
    pub email: String,
    pub password: String,
    /// Client app identifier (e.g., "Divine Video", "My Nostr App")
    pub client_id: String,
    /// OAuth redirect URI (used to derive origin for bunker)
    pub redirect_uri: String,
    /// Optional: import existing Nostr key (nsec1... or hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,
    /// OAuth scope (e.g., "policy:social")
    pub scope: Option<String>,
    /// PKCE code challenge (S256)
    pub code_challenge: Option<String>,
    /// PKCE challenge method (should be "S256")
    pub code_challenge_method: Option<String>,
    /// OAuth state parameter for CSRF protection
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeadlessRegisterResponse {
    pub success: bool,
    /// Nostr public key (hex)
    pub pubkey: String,
    /// Email verification is required before login
    pub verification_required: bool,
    /// Device code for polling (RFC 8628 pattern)
    pub device_code: String,
    /// Email address for display
    pub email: String,
}

/// POST /api/headless/register
///
/// Register a new user without web UI. Returns device_code for email verification polling.
///
/// Flow:
/// 1. Client calls this endpoint with email/password
/// 2. Server sends verification email, returns device_code
/// 3. Client polls GET /api/oauth/poll?device_code=xxx
/// 4. When email verified, poll returns authorization code
/// 5. Client exchanges code for bunker_url via POST /api/oauth/token
pub async fn headless_register(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(mut req): Json<HeadlessRegisterRequest>,
) -> Result<impl IntoResponse, HeadlessError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    req.email = req.email.to_lowercase();

    tracing::info!(
        event = "headless_registration_attempt",
        tenant_id = tenant_id,
        client_id = %req.client_id,
        "Headless registration attempt"
    );

    // Validate redirect_uri and extract origin
    let _redirect_origin = extract_origin(&req.redirect_uri)
        .map_err(|e| HeadlessError::InvalidRequest(format!("Invalid redirect_uri: {:?}", e)))?;

    // Validate scope if provided
    let scope = req.scope.as_deref().unwrap_or("policy:full");
    if scope.starts_with("policy:") {
        let policy_slug = parse_policy_scope(scope)
            .map_err(|e| HeadlessError::InvalidRequest(format!("{:?}", e)))?;

        // Verify policy exists
        let policy_repo = PolicyRepository::new(pool.clone());
        policy_repo.find_by_slug(&policy_slug).await.map_err(|_| {
            HeadlessError::InvalidRequest(format!("Unknown policy '{}'", policy_slug))
        })?;
    }

    // Use provided nsec or generate new Nostr keypair
    let keys = if let Some(ref nsec_str) = req.nsec {
        tracing::info!(
            "Headless registration: user provided their own key (BYOK) for email: {}",
            req.email
        );
        Keys::parse(nsec_str).map_err(|e| {
            HeadlessError::InvalidRequest(format!(
                "Invalid nsec or secret key: {}. Please provide a valid nsec (bech32) or hex secret key.",
                e
            ))
        })?
    } else {
        tracing::info!(
            "Headless registration: auto-generating new keypair for email: {}",
            req.email
        );
        Keys::generate()
    };

    let public_key = keys.public_key();
    let secret_key = keys.secret_key();

    // Check if this public key is already registered (for BYOK case)
    if req.nsec.is_some() {
        let user_repo = UserRepository::new(pool.clone());
        if user_repo.exists(&public_key.to_hex(), tenant_id).await? {
            return Err(HeadlessError::Conflict(
                "This Nostr key is already registered. Please log in instead or use a different key.".to_string(),
            ));
        }
    }

    // Check if email is already registered
    let user_repo = UserRepository::new(pool.clone());
    if user_repo
        .find_pubkey_by_email(&req.email, tenant_id)
        .await?
        .is_some()
    {
        return Err(HeadlessError::Conflict(
            "This email is already registered. Please log in instead.".to_string(),
        ));
    }

    // Encrypt the secret key
    let secret_bytes = secret_key.to_secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&secret_bytes)
        .await
        .map_err(|e| HeadlessError::Internal(format!("Encryption error: {}", e)))?;

    // Generate device_code for polling (RFC 8628 pattern)
    let device_code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // Generate email verification token
    let verification_token = generate_secure_token();

    // Hash password synchronously (headless flow can tolerate latency)
    let password = req.password.clone();
    let password_hash =
        tokio::task::spawn_blocking(move || bcrypt::hash(&password, bcrypt::DEFAULT_COST))
            .await
            .map_err(|e| HeadlessError::Internal(format!("Task join error: {}", e)))?
            .map_err(|e| HeadlessError::Internal(format!("Password hash error: {}", e)))?;

    // Generate placeholder authorization code (will be replaced after email verification)
    let placeholder_code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store pending registration in oauth_codes (deferred user creation)
    let expires_at = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);
    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    oauth_code_repo
        .store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id,
            code: &placeholder_code,
            user_pubkey: &public_key.to_hex(),
            client_id: &req.client_id,
            redirect_uri: &req.redirect_uri,
            scope,
            code_challenge: req.code_challenge.as_deref(),
            code_challenge_method: req.code_challenge_method.as_deref(),
            expires_at,
            pending_email: &req.email,
            pending_password_hash: &password_hash,
            pending_email_verification_token: &verification_token,
            pending_encrypted_secret: Some(&encrypted_secret),
            state: req.state.as_deref(),
            device_code: Some(&device_code),
            is_headless: true,
        })
        .await?;

    // Send verification email
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_verification_email(&req.email, &verification_token)
                .await
            {
                tracing::error!("Failed to send verification email to {}: {}", req.email, e);
                // Continue - user can request resend later
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

    // Track successful registration
    METRICS.inc_registration();

    tracing::info!(
        event = "headless_registration_success",
        tenant_id = tenant_id,
        client_id = %req.client_id,
        "Headless registration successful, awaiting email verification"
    );

    Ok(Json(HeadlessRegisterResponse {
        success: true,
        pubkey: public_key.to_hex(),
        verification_required: true,
        device_code,
        email: req.email,
    }))
}

// ============================================================================
// Headless Login
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct HeadlessLoginRequest {
    pub email: String,
    pub password: String,
    /// Client app identifier
    pub client_id: String,
    /// OAuth redirect URI
    pub redirect_uri: String,
    /// OAuth scope (e.g., "policy:social")
    pub scope: Option<String>,
    /// PKCE code challenge (S256)
    pub code_challenge: Option<String>,
    /// PKCE challenge method
    pub code_challenge_method: Option<String>,
    /// OAuth state parameter
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeadlessLoginResponse {
    pub success: bool,
    /// Authorization code to exchange for bunker_url
    pub code: String,
    /// Nostr public key (hex)
    pub pubkey: String,
    /// OAuth state (echoed back)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// POST /api/headless/login
///
/// Login and get authorization code in one step (no approval screen needed).
///
/// Flow:
/// 1. Client calls this with email/password + PKCE
/// 2. Server validates credentials, returns authorization code
/// 3. Client exchanges code for bunker_url via POST /api/oauth/token
pub async fn headless_login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(mut req): Json<HeadlessLoginRequest>,
) -> Result<impl IntoResponse, HeadlessError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    req.email = req.email.to_lowercase();

    tracing::info!(
        event = "headless_login_attempt",
        tenant_id = tenant_id,
        client_id = %req.client_id,
        "Headless login attempt"
    );

    // Validate redirect_uri
    let _redirect_origin = extract_origin(&req.redirect_uri)
        .map_err(|e| HeadlessError::InvalidRequest(format!("Invalid redirect_uri: {:?}", e)))?;

    // Fetch user with password hash
    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo.find_with_password(&req.email, tenant_id).await?;

    let (public_key, password_hash, email_verified) = match user {
        Some(u) => u,
        None => {
            tracing::warn!(
                event = "headless_login",
                tenant_id = tenant_id,
                success = false,
                reason = "user_not_found",
                "Headless login failed: user not found"
            );
            return Err(HeadlessError::Unauthorized);
        }
    };

    // Verify password
    let password = req.password.clone();
    let hash = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify(&password, &hash))
        .await
        .map_err(|e| HeadlessError::Internal(format!("Task join error: {}", e)))?
        .map_err(|_| HeadlessError::Internal("Password verification failed".to_string()))?;

    if !valid {
        tracing::warn!(
            event = "headless_login",
            tenant_id = tenant_id,
            success = false,
            reason = "invalid_password",
            "Headless login failed: invalid password"
        );
        METRICS.inc_login_failure();
        return Err(HeadlessError::Unauthorized);
    }

    // Check if email is verified
    if !email_verified {
        tracing::warn!(
            event = "headless_login",
            tenant_id = tenant_id,
            success = false,
            reason = "email_not_verified",
            "Headless login failed: email not verified"
        );
        return Err(HeadlessError::EmailNotVerified);
    }

    // Generate authorization code
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store authorization code (10 minute expiry)
    let expires_at = Utc::now() + Duration::minutes(10);
    let scope = req.scope.as_deref().unwrap_or("policy:full");

    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    oauth_code_repo
        .store(keycast_core::repositories::StoreOAuthCodeParams {
            tenant_id,
            code: &code,
            user_pubkey: &public_key,
            client_id: &req.client_id,
            redirect_uri: &req.redirect_uri,
            scope,
            code_challenge: req.code_challenge.as_deref(),
            code_challenge_method: req.code_challenge_method.as_deref(),
            expires_at,
            previous_auth_id: None,
            state: req.state.as_deref(),
            is_headless: true,
        })
        .await?;

    // Track successful login
    METRICS.inc_login();

    tracing::info!(
        event = "headless_login",
        tenant_id = tenant_id,
        success = true,
        "Headless login successful"
    );

    Ok(Json(HeadlessLoginResponse {
        success: true,
        code,
        pubkey: public_key,
        state: req.state,
    }))
}

// ============================================================================
// Headless Authorize (for users who already have access_token)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct HeadlessAuthorizeRequest {
    /// Client app identifier
    pub client_id: String,
    /// OAuth redirect URI
    pub redirect_uri: String,
    /// OAuth scope
    pub scope: Option<String>,
    /// PKCE code challenge
    pub code_challenge: Option<String>,
    /// PKCE challenge method
    pub code_challenge_method: Option<String>,
    /// OAuth state parameter
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeadlessAuthorizeResponse {
    pub success: bool,
    /// Authorization code to exchange for bunker_url
    pub code: String,
    /// OAuth state (echoed back)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// POST /api/headless/authorize
///
/// Generate authorization code for an already-authenticated user.
/// Requires Bearer token (from previous login) in Authorization header.
///
/// This is for apps that want to create additional authorizations
/// (e.g., connecting a second app to the same account).
pub async fn headless_authorize(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<HeadlessAuthorizeRequest>,
) -> Result<impl IntoResponse, HeadlessError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    // Extract user from UCAN Bearer token with tenant validation
    let user_pubkey = super::auth::extract_user_from_token(&headers, tenant_id)
        .await
        .map_err(|_| HeadlessError::Unauthorized)?;

    tracing::info!(
        event = "headless_authorize",
        tenant_id = tenant_id,
        client_id = %req.client_id,
        user = %user_pubkey,
        "Headless authorize request"
    );

    // Validate redirect_uri
    let _redirect_origin = extract_origin(&req.redirect_uri)
        .map_err(|e| HeadlessError::InvalidRequest(format!("Invalid redirect_uri: {:?}", e)))?;

    // Generate authorization code
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store authorization code
    let expires_at = Utc::now() + Duration::minutes(10);
    let scope = req.scope.as_deref().unwrap_or("policy:full");

    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    oauth_code_repo
        .store(keycast_core::repositories::StoreOAuthCodeParams {
            tenant_id,
            code: &code,
            user_pubkey: &user_pubkey,
            client_id: &req.client_id,
            redirect_uri: &req.redirect_uri,
            scope,
            code_challenge: req.code_challenge.as_deref(),
            code_challenge_method: req.code_challenge_method.as_deref(),
            expires_at,
            previous_auth_id: None,
            state: req.state.as_deref(),
            is_headless: true,
        })
        .await?;

    Ok(Json(HeadlessAuthorizeResponse {
        success: true,
        code,
        state: req.state,
    }))
}

// ============================================================================
// Error Type
// ============================================================================

#[derive(Debug)]
pub enum HeadlessError {
    Unauthorized,
    EmailNotVerified,
    InvalidRequest(String),
    Conflict(String),
    Internal(String),
    ServiceUnavailable {
        message: String,
        retry_after: Option<u32>,
    },
}

impl IntoResponse for HeadlessError {
    fn into_response(self) -> Response {
        let (status, message, code) = match self {
            HeadlessError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password".to_string(),
                "INVALID_CREDENTIALS",
            ),
            HeadlessError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "Please verify your email address before signing in".to_string(),
                "EMAIL_NOT_VERIFIED",
            ),
            HeadlessError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg, "INVALID_REQUEST"),
            HeadlessError::Conflict(msg) => (StatusCode::CONFLICT, msg, "CONFLICT"),
            HeadlessError::Internal(msg) => {
                tracing::error!("Headless internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "INTERNAL_ERROR",
                )
            }
            HeadlessError::ServiceUnavailable {
                message,
                retry_after,
            } => {
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": message,
                        "code": "SERVICE_UNAVAILABLE"
                    })),
                )
                    .into_response();

                if let Some(seconds) = retry_after {
                    response
                        .headers_mut()
                        .insert("Retry-After", seconds.to_string().parse().unwrap());
                }
                return response;
            }
        };

        (
            status,
            Json(serde_json::json!({
                "error": message,
                "code": code
            })),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for HeadlessError {
    fn from(e: sqlx::Error) -> Self {
        HeadlessError::Internal(format!("Database error: {}", e))
    }
}

impl From<keycast_core::repositories::RepositoryError> for HeadlessError {
    fn from(e: keycast_core::repositories::RepositoryError) -> Self {
        use keycast_core::repositories::RepositoryError;
        match e {
            RepositoryError::Duplicate => {
                HeadlessError::Conflict("Resource already exists".to_string())
            }
            RepositoryError::NotFound(msg) => HeadlessError::InvalidRequest(msg),
            _ => HeadlessError::Internal(e.to_string()),
        }
    }
}
