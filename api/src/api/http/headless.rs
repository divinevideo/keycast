// ABOUTME: Headless authentication handlers for native mobile apps (Flutter, etc.)
// ABOUTME: Pure JSON API - no cookies, no HTML, returns access_token directly

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
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

use super::auth::{
    generate_secure_token, normalize_registration_email, EMAIL_VERIFICATION_EXPIRY_HOURS,
    INVALID_EMAIL_CODE, INVALID_EMAIL_MESSAGE,
};
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
/// Map a policy-lookup error at registration. A genuinely missing policy is a client error
/// reported as "Unknown policy '<slug>'", but any other repository error (e.g. a DB connection
/// failure such as 28P01) must surface as `Internal` rather than being masked as a missing
/// policy — masking a connection error as "Unknown policy" hid a real fault and caused a review
/// mis-triage (keycast#262).
fn map_policy_lookup_error(
    policy_slug: &str,
    err: keycast_core::repositories::RepositoryError,
) -> HeadlessError {
    use keycast_core::repositories::RepositoryError;
    match err {
        RepositoryError::NotFound(_) => {
            HeadlessError::InvalidRequest(format!("Unknown policy '{}'", policy_slug))
        }
        other => {
            HeadlessError::Internal(format!("Failed to look up policy '{policy_slug}': {other}"))
        }
    }
}

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

    req.email =
        normalize_registration_email(&req.email).map_err(|_| HeadlessError::InvalidEmail)?;

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

        // Verify policy exists. A missing policy is a client error, but a DB failure here must
        // surface as-is rather than being masked as "Unknown policy" (keycast#262).
        let policy_repo = PolicyRepository::new(pool.clone());
        policy_repo
            .find_by_slug(&policy_slug)
            .await
            .map_err(|e| map_policy_lookup_error(&policy_slug, e))?;
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

    // Generate a 6-digit in-app verification PIN (keycast#262), emailed alongside the link as a
    // second transport for the same proof. Stored hashed; the device_code is the real gate.
    let pin: String = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    let pin_for_hash = pin.clone();
    let pin_hash =
        tokio::task::spawn_blocking(move || bcrypt::hash(&pin_for_hash, bcrypt::DEFAULT_COST))
            .await
            .map_err(|e| HeadlessError::Internal(format!("Task join error: {}", e)))?
            .map_err(|e| HeadlessError::Internal(format!("PIN hash error: {}", e)))?;

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
            pin_hash: Some(&pin_hash),
        })
        .await?;

    // Send verification email. Only start the resend cooldown after confirmed delivery; otherwise
    // the user must be able to request an immediate replacement.
    let mut email_delivered = false;
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_verification_email(&req.email, &verification_token, Some(&pin))
                .await
            {
                tracing::error!("Failed to send verification email to {}: {}", req.email, e);
                // Continue - user can request resend later
            } else {
                email_delivered = true;
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
    if email_delivered {
        oauth_code_repo
            .mark_pin_sent(&device_code, tenant_id)
            .await?;
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
    headers: HeaderMap,
    Json(mut req): Json<HeadlessLoginRequest>,
) -> Result<impl IntoResponse, HeadlessError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;
    let endpoint = "/api/headless/login";

    req.email = req.email.to_lowercase();

    tracing::info!(
        event = "headless_login_attempt",
        tenant_id = tenant_id,
        client_id = %req.client_id,
        "Headless login attempt"
    );

    // Validate redirect_uri
    let redirect_origin = match extract_origin(&req.redirect_uri) {
        Ok(origin) => origin,
        Err(e) => {
            super::auth_observability::record_auth_event_and_log(
                pool,
                &headers,
                None,
                super::auth_observability::AuthEvent {
                    tenant_id,
                    endpoint,
                    event_type: "login",
                    outcome: "failure",
                    reason_code: Some("invalid_request"),
                    http_status: 400,
                    email: Some(&req.email),
                    pubkey: None,
                    client_id: Some(&req.client_id),
                    redirect_origin: None,
                    metadata_json: serde_json::json!({
                        "error": format!("Invalid redirect_uri: {:?}", e),
                    }),
                },
            )
            .await;
            return Err(HeadlessError::InvalidRequest(format!(
                "Invalid redirect_uri: {:?}",
                e
            )));
        }
    };

    // Fetch user with password hash
    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo.find_with_password(&req.email, tenant_id).await?;

    let (public_key, password_hash, email_verified, _user_status) = match user {
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
                    client_id: Some(&req.client_id),
                    redirect_origin: Some(&redirect_origin),
                    metadata_json: serde_json::json!({}),
                },
            )
            .await;
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
                client_id: Some(&req.client_id),
                redirect_origin: Some(&redirect_origin),
                metadata_json: serde_json::json!({}),
            },
        )
        .await;
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
                client_id: Some(&req.client_id),
                redirect_origin: Some(&redirect_origin),
                metadata_json: serde_json::json!({}),
            },
        )
        .await;
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
            client_id: Some(&req.client_id),
            redirect_origin: Some(&redirect_origin),
            metadata_json: serde_json::json!({}),
        },
    )
    .await;

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

    let user_pubkey = extract_first_party_or_user_signed_user(&headers, tenant_id).await?;

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

async fn extract_first_party_or_user_signed_user(
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<String, HeadlessError> {
    let auth_header = if let Some(auth_header) = headers.get("Authorization") {
        auth_header
            .to_str()
            .map_err(|_| HeadlessError::Unauthorized)?
            .to_string()
    } else if let Some(token) = super::auth::extract_ucan_from_cookie(headers) {
        format!("Bearer {}", token)
    } else {
        return Err(HeadlessError::Unauthorized);
    };

    let (user_pubkey, redirect_origin, _, ucan) =
        crate::ucan_auth::validate_ucan_token(&auth_header, tenant_id)
            .await
            .map_err(|_| HeadlessError::Unauthorized)?;

    let issuer = crate::ucan_auth::did_to_nostr_pubkey(ucan.issuer())
        .map_err(|_| HeadlessError::Unauthorized)?
        .to_hex();
    let is_user_signed = issuer == user_pubkey;
    let is_first_party = ucan
        .facts()
        .iter()
        .find_map(|fact| fact.get("first_party").and_then(|value| value.as_bool()))
        .unwrap_or(false);

    if !is_user_signed && !is_first_party {
        tracing::warn!(
            event = "headless_authorize_denied",
            tenant_id = tenant_id,
            user_pubkey = %user_pubkey,
            redirect_origin = %redirect_origin,
            "Denied: bearer token is not user-signed or first-party"
        );
        return Err(HeadlessError::Unauthorized);
    }

    Ok(user_pubkey)
}

// ============================================================================
// Headless Verify PIN (in-app fallback for the email verification link)
// ============================================================================

/// Failed PIN attempts allowed before the PIN is locked until resend (keycast#262).
const MAX_PIN_ATTEMPTS: i32 = 5;

#[derive(Debug, Deserialize)]
pub struct HeadlessVerifyPinRequest {
    /// RFC 8628 device_code from registration — the 64-char app-held secret and real gate.
    pub device_code: String,
    /// 6-digit PIN emailed to the user (defense-in-depth on top of device_code).
    pub pin: String,
}

#[derive(Debug, Serialize)]
pub struct HeadlessVerifyPinResponse {
    pub success: bool,
    /// Authorization code to exchange for bunker_url — returned synchronously (Redis-independent).
    pub code: String,
    /// Nostr public key (hex)
    pub pubkey: String,
    /// OAuth state (echoed back)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Record a verify-pin failure to the shared brute-force feed (#258). The `reason` is internal
/// only — the client always sees the same uniform error (anti-enumeration).
async fn record_pin_verify_failure(
    pool: &sqlx::PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
    pubkey: Option<&str>,
    email: Option<&str>,
    reason: &str,
) {
    super::auth_observability::record_auth_event_and_log(
        pool,
        headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint: "/api/headless/verify-pin",
            event_type: "email_pin_verify",
            outcome: "failure",
            reason_code: Some(reason),
            http_status: 401,
            email,
            pubkey,
            client_id: None,
            redirect_origin: None,
            metadata_json: serde_json::json!({}),
        },
    )
    .await;
}

/// Spend bcrypt work equivalent to a real PIN comparison.
///
/// Verify-pin rejects several states before ever reaching the bcrypt compare (unknown
/// `device_code`, no PIN issued, already locked). Burning a dummy hash on those paths keeps their
/// latency comparable to a wrong-PIN attempt so the rejected state is not distinguishable by timing.
async fn burn_dummy_bcrypt() {
    let _ = tokio::task::spawn_blocking(|| {
        let _ = bcrypt::hash("dummy", bcrypt::DEFAULT_COST);
    })
    .await;
}

/// POST /api/headless/verify-pin
///
/// In-app fallback for the email verification link (keycast#262): for webviews that never run the
/// link page, a different device, or a mangled link, the user types the 6-digit PIN. The pending
/// row is located by `device_code` (the real authenticator); the PIN is defense-in-depth, bounded
/// by [`MAX_PIN_ATTEMPTS`]. On success the same finalize path as the link runs and the OAuth
/// authorization code is returned synchronously in the body (no Redis dependency).
pub async fn headless_verify_pin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<HeadlessVerifyPinRequest>,
) -> Result<impl IntoResponse, HeadlessError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    let pending = oauth_code_repo
        .find_by_device_code(&req.device_code, tenant_id)
        .await?;

    let Some(pending) = pending else {
        // Burn comparable time so an unknown/expired device_code isn't distinguishable by latency.
        burn_dummy_bcrypt().await;
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            None,
            None,
            "device_code_not_found",
        )
        .await;
        return Err(HeadlessError::PinVerificationFailed);
    };

    if pending.consumed_at.is_some() {
        return Ok(Json(HeadlessVerifyPinResponse {
            success: true,
            code: String::new(),
            pubkey: pending.user_pubkey,
            state: pending.state,
        }));
    }

    let Some(pin_hash) = pending.pin_hash.clone() else {
        // No PIN was issued for this registration. Burn comparable bcrypt work so this is
        // indistinguishable by latency from a wrong-PIN attempt before rejecting uniformly.
        burn_dummy_bcrypt().await;
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            "no_pin_issued",
        )
        .await;
        return Err(HeadlessError::PinVerificationFailed);
    };

    // Atomically reserve an attempt slot BEFORE the expensive bcrypt compare. The conditional
    // UPDATE increments only while under the cap, so at most MAX_PIN_ATTEMPTS comparisons can run
    // for this device_code even across concurrent requests. `None` means the row is at the cap
    // (locked) — reject uniformly, burning comparable time so lockout is not a timing signal.
    let Some(attempt) = oauth_code_repo
        .reserve_pin_attempt(&req.device_code, tenant_id, MAX_PIN_ATTEMPTS)
        .await?
    else {
        burn_dummy_bcrypt().await;
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            "pin_locked",
        )
        .await;
        return Err(HeadlessError::PinVerificationFailed);
    };

    // Constant-time PIN comparison (bcrypt's own compare; work factor dominates).
    let candidate = req.pin.clone();
    let stored = pin_hash;
    let valid = tokio::task::spawn_blocking(move || verify(&candidate, &stored))
        .await
        .map_err(|e| HeadlessError::Internal(format!("Task join error: {}", e)))?
        .unwrap_or(false);

    if !valid {
        // The slot was already consumed by the atomic reserve above; just classify and record.
        let reason = if attempt >= MAX_PIN_ATTEMPTS {
            "pin_locked"
        } else {
            "wrong_pin"
        };
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            reason,
        )
        .await;
        return Err(HeadlessError::PinVerificationFailed);
    }

    // Correct PIN: run the SAME finalize path as the link (idempotent; does not delete the row).
    // RedisBestEffort because the code is returned synchronously below, so a Redis outage is fine.
    let finalized = match super::auth::finalize_pending_registration(
        pool,
        auth_state.state.redis.as_ref(),
        tenant_id,
        &pending,
        super::auth::HeadlessDelivery::RedisBestEffort,
    )
    .await
    {
        Ok(finalized) => finalized,
        Err(super::auth::AuthError::RegistrationAlreadyCompleted) => {
            return Ok(Json(HeadlessVerifyPinResponse {
                success: true,
                code: String::new(),
                pubkey: pending.user_pubkey,
                state: pending.state,
            }))
        }
        Err(e) => return Err(e.into()),
    };

    // Correct PIN: clear the failed-attempt counter that `reserve_pin_attempt` incremented before
    // the bcrypt compare. Only failed attempts should count toward the lockout cap (keycast#262), so
    // a successful verify (and any idempotent re-verify of the same correct PIN) must not lock out.
    // Best-effort: the registration already finalized, so a stray counter is not worth failing on.
    if let Err(e) = oauth_code_repo
        .reset_pin_attempts(&req.device_code, tenant_id)
        .await
    {
        tracing::warn!(
            "Failed to reset pin_attempts after successful PIN verify for {}: {}",
            pending.user_pubkey,
            e
        );
    }

    tracing::info!(
        event = "email_pin_verify",
        tenant_id = tenant_id,
        outcome = "success",
        "PIN verified, registration finalized"
    );

    Ok(Json(HeadlessVerifyPinResponse {
        success: true,
        code: finalized.new_code,
        pubkey: pending.user_pubkey,
        state: finalized.state,
    }))
}

// ============================================================================
// Headless Resend PIN (lockout recovery + new code)
// ============================================================================

/// Minutes between PIN resends (mirrors the users-table `email_verification_sent_at` cooldown).
const PIN_RESEND_COOLDOWN_MINUTES: i64 = 5;

#[derive(Debug, Deserialize)]
pub struct HeadlessResendPinRequest {
    /// RFC 8628 device_code from registration (the app-held secret).
    pub device_code: String,
}

#[derive(Debug, Serialize)]
pub struct HeadlessResendPinResponse {
    pub success: bool,
    pub message: String,
}

/// POST /api/headless/resend-pin
///
/// Lockout recovery + PIN resend (keycast#262). Keyed by device_code, it re-mints a fresh
/// verification token + 6-digit PIN, resets the attempt counter, refreshes the verify window, and
/// re-sends the email — subject to a 5-minute cooldown. Always returns a uniform success response
/// so it leaks neither registration existence nor lockout state.
///
/// Pending headless registrations have no `users` row yet, so the users-table resend path does not
/// apply; this is the device_code-keyed equivalent on the `oauth_codes` row.
pub async fn headless_resend_pin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<HeadlessResendPinRequest>,
) -> Result<impl IntoResponse, HeadlessError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    // Uniform response regardless of outcome (anti-enumeration / no lockout signal).
    let success = || {
        Json(HeadlessResendPinResponse {
            success: true,
            message: "If your registration is pending, a new code has been sent.".to_string(),
        })
    };

    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    let Some(pending) = oauth_code_repo
        .find_by_device_code(&req.device_code, tenant_id)
        .await?
    else {
        return Ok(success());
    };

    if pending.consumed_at.is_some() {
        return Ok(success());
    }

    // Cooldown: silently skip if a PIN was sent within the window.
    if let Some(sent_at) = pending.pin_sent_at {
        if (Utc::now() - sent_at).num_minutes() < PIN_RESEND_COOLDOWN_MINUTES {
            tracing::debug!("resend-pin: within cooldown, skipping (not revealed to client)");
            return Ok(success());
        }
    }

    let Some(email) = pending.pending_email.clone() else {
        return Ok(success());
    };

    // Mint a fresh token + PIN and reset the attempt counter. The original 24h verify window is
    // preserved (resend does not extend expires_at) so the pending row stays bounded (keycast#262).
    let new_token = generate_secure_token();
    let new_pin: String = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    let pin_for_hash = new_pin.clone();
    let new_pin_hash =
        tokio::task::spawn_blocking(move || bcrypt::hash(&pin_for_hash, bcrypt::DEFAULT_COST))
            .await
            .map_err(|e| HeadlessError::Internal(format!("Task join error: {}", e)))?
            .map_err(|e| HeadlessError::Internal(format!("PIN hash error: {}", e)))?;

    let old_token = pending.pending_email_verification_token.clone();
    let old_pin_hash = pending.pin_hash.clone();
    let old_pin_attempts = pending.pin_attempts;
    let old_pin_sent_at = pending.pin_sent_at;

    oauth_code_repo
        .reset_pin_for_resend(&req.device_code, tenant_id, &new_token, &new_pin_hash)
        .await?;

    // Re-send the link + PIN. If delivery fails, roll back the mutation so the previous credential
    // remains valid and the resend cooldown is not armed by an undelivered replacement.
    let send_result = match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            email_service
                .send_verification_email(&email, &new_token, Some(&new_pin))
                .await
        }
        Err(e) => {
            tracing::warn!(
                "Email service unavailable, skipping PIN resend email: {}",
                e
            );
            Err(e)
        }
    };

    if let Err(e) = send_result {
        tracing::error!("Failed to resend verification email to {}: {}", email, e);
        oauth_code_repo
            .restore_pin_after_failed_resend(
                &req.device_code,
                tenant_id,
                old_token.as_deref(),
                old_pin_hash.as_deref(),
                old_pin_attempts,
                old_pin_sent_at,
            )
            .await?;
        return Ok(success());
    }

    tracing::info!(
        event = "email_pin_resend",
        tenant_id = tenant_id,
        "Re-armed PIN and resent verification email"
    );

    Ok(success())
}

// ============================================================================
// Error Type
// ============================================================================

#[derive(Debug)]
pub enum HeadlessError {
    Unauthorized,
    EmailNotVerified,
    InvalidEmail,
    InvalidRequest(String),
    Conflict(String),
    Internal(String),
    /// Uniform rejection for every verify-pin failure mode (unknown device_code, wrong/locked/
    /// expired PIN) — never reveals which, nor lockout state (anti-enumeration).
    PinVerificationFailed,
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
            HeadlessError::InvalidEmail => (
                StatusCode::BAD_REQUEST,
                INVALID_EMAIL_MESSAGE.to_string(),
                INVALID_EMAIL_CODE,
            ),
            HeadlessError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg, "INVALID_REQUEST"),
            HeadlessError::Conflict(msg) => (StatusCode::CONFLICT, msg, "CONFLICT"),
            HeadlessError::PinVerificationFailed => (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired verification code. Please try again or request a new one."
                    .to_string(),
                "PIN_VERIFICATION_FAILED",
            ),
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

#[cfg(test)]
mod tests {
    use nostr_sdk::Keys;
    use serial_test::serial;

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
        let bcrypt_queue = crate::bcrypt_queue::BcryptQueue::new();
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
                bcrypt_sender: bcrypt_queue.sender(),
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

    struct EmailEnvGuard {
        rust_env: Option<String>,
        node_env: Option<String>,
        sendgrid_api_key: Option<String>,
        disable_emails: Option<String>,
    }

    impl Drop for EmailEnvGuard {
        fn drop(&mut self) {
            restore_env_var("RUST_ENV", self.rust_env.as_deref());
            restore_env_var("NODE_ENV", self.node_env.as_deref());
            restore_env_var("SENDGRID_API_KEY", self.sendgrid_api_key.as_deref());
            restore_env_var("DISABLE_EMAILS", self.disable_emails.as_deref());
        }
    }

    fn restore_env_var(key: &str, value: Option<&str>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    fn force_email_service_failure() -> EmailEnvGuard {
        let guard = EmailEnvGuard {
            rust_env: std::env::var("RUST_ENV").ok(),
            node_env: std::env::var("NODE_ENV").ok(),
            sendgrid_api_key: std::env::var("SENDGRID_API_KEY").ok(),
            disable_emails: std::env::var("DISABLE_EMAILS").ok(),
        };
        std::env::set_var("RUST_ENV", "production");
        std::env::remove_var("NODE_ENV");
        std::env::remove_var("SENDGRID_API_KEY");
        std::env::remove_var("DISABLE_EMAILS");
        guard
    }

    #[tokio::test]
    async fn test_headless_register_rejects_malformed_email_with_stable_error() {
        let response = match super::headless_register(
            create_unit_test_tenant(),
            axum::extract::State(create_lazy_auth_state()),
            axum::Json(super::HeadlessRegisterRequest {
                email: "person@gmail..com".to_string(),
                password: "testpassword123".to_string(),
                client_id: "TestClient".to_string(),
                redirect_uri: "https://client.example/callback".to_string(),
                nsec: None,
                scope: None,
                code_challenge: None,
                code_challenge_method: None,
                state: None,
            }),
        )
        .await
        {
            Ok(response) => axum::response::IntoResponse::into_response(response),
            Err(error) => axum::response::IntoResponse::into_response(error),
        };

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = response_json(response).await;
        assert_eq!(body["code"], crate::api::http::auth::INVALID_EMAIL_CODE);
        assert_eq!(body["error"], "Please enter a valid email address.");
    }

    /// A genuinely missing policy is a client error surfaced as "Unknown policy '<slug>'".
    #[test]
    fn test_map_policy_lookup_error_not_found_reports_unknown_policy() {
        use keycast_core::repositories::RepositoryError;
        let err = super::map_policy_lookup_error(
            "full",
            RepositoryError::NotFound("record not found".to_string()),
        );
        match err {
            super::HeadlessError::InvalidRequest(msg) => {
                assert_eq!(msg, "Unknown policy 'full'");
            }
            other => panic!("expected InvalidRequest for a missing policy, got {other:?}"),
        }
    }

    /// A real DB failure (e.g. 28P01 auth error) must NOT be masked as a missing policy —
    /// masking a connection error as "Unknown policy" caused a review mis-triage (keycast#262).
    #[test]
    fn test_map_policy_lookup_error_db_error_is_not_masked() {
        use keycast_core::repositories::RepositoryError;
        let err = super::map_policy_lookup_error(
            "full",
            RepositoryError::Database("password authentication failed".to_string()),
        );
        match err {
            super::HeadlessError::Internal(msg) => {
                assert!(
                    !msg.contains("Unknown policy"),
                    "a DB error must not be reported as a missing policy, got: {msg}"
                );
                assert!(
                    msg.contains("password authentication failed"),
                    "the real DB error should surface, got: {msg}"
                );
            }
            other => panic!("expected Internal for a DB failure, got {other:?}"),
        }
    }

    /// headless_register stores a hashed 6-digit PIN on the pending row (keycast#262).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_headless_register_stores_hashed_pin() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("headless-pin-{}@example.com", uuid::Uuid::new_v4());

        let response = super::headless_register(
            create_unit_test_tenant(),
            axum::extract::State(auth_state),
            axum::Json(super::HeadlessRegisterRequest {
                email: email.clone(),
                password: "testpassword123".to_string(),
                client_id: "TestClient".to_string(),
                redirect_uri: "https://client.example/callback".to_string(),
                nsec: None,
                scope: None,
                code_challenge: None,
                code_challenge_method: None,
                state: None,
            }),
        )
        .await
        .map(axum::response::IntoResponse::into_response)
        .expect("headless_register should succeed");

        let body = response_json(response).await;
        let device_code = body["device_code"]
            .as_str()
            .expect("response carries device_code")
            .to_string();

        let (pin_hash, pin_attempts): (Option<String>, i32) = sqlx::query_as(
            "SELECT pin_hash, pin_attempts FROM oauth_codes WHERE device_code = $1 AND tenant_id = 1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .expect("pending row should exist");

        let pin_hash = pin_hash.expect("a PIN must be hashed and stored at registration");
        assert!(
            pin_hash.starts_with("$2"),
            "pin_hash must be a bcrypt hash, got {pin_hash}"
        );
        assert_eq!(pin_attempts, 0, "attempt counter starts at zero");

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE email = $1")
            .bind(&email)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_headless_register_email_failure_does_not_start_resend_cooldown() {
        let _email_env = force_email_service_failure();

        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("headless-email-fail-{}@example.com", uuid::Uuid::new_v4());

        let response = super::headless_register(
            create_unit_test_tenant(),
            axum::extract::State(auth_state),
            axum::Json(super::HeadlessRegisterRequest {
                email: email.clone(),
                password: "testpassword123".to_string(),
                client_id: "TestClient".to_string(),
                redirect_uri: "https://client.example/callback".to_string(),
                nsec: None,
                scope: None,
                code_challenge: None,
                code_challenge_method: None,
                state: None,
            }),
        )
        .await
        .map(axum::response::IntoResponse::into_response)
        .expect("headless_register should still create the pending registration");

        let body = response_json(response).await;
        let device_code = body["device_code"]
            .as_str()
            .expect("response carries device_code")
            .to_string();

        let (pin_sent_at,): (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
            "SELECT pin_sent_at FROM oauth_codes WHERE device_code = $1 AND tenant_id = 1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .expect("pending row should exist");

        assert!(
            pin_sent_at.is_none(),
            "failed initial email delivery must allow immediate resend"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE email = $1")
            .bind(&email)
            .execute(&pool)
            .await;
    }

    /// Insert a pending headless registration with a known PIN. Returns (pubkey, device_code).
    #[cfg(feature = "integration-tests")]
    async fn insert_pending_with_pin(
        pool: &sqlx::PgPool,
        email: &str,
        pin_plain: &str,
    ) -> (String, String) {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let token = format!("verify_{}", uuid::Uuid::new_v4());
        let placeholder = format!("placeholder_{}", uuid::Uuid::new_v4());
        let password_hash = bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap();
        let pin_hash = bcrypt::hash(pin_plain, bcrypt::DEFAULT_COST).unwrap();
        let encrypted_secret = keys.secret_key().to_secret_bytes().to_vec();
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

        sqlx::query(
            "INSERT INTO oauth_codes (
                tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                expires_at, created_at, pending_email, pending_password_hash,
                pending_email_verification_token, pending_encrypted_secret,
                device_code, is_headless, pin_hash, pin_attempts
            ) VALUES (1, $1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9, $10, $11, true, $12, 0)",
        )
        .bind(&placeholder)
        .bind(&pubkey)
        .bind("TestApp")
        .bind("https://test.example.com/callback")
        .bind("policy:social")
        .bind(expires_at)
        .bind(email)
        .bind(&password_hash)
        .bind(&token)
        .bind(&encrypted_secret)
        .bind(&device_code)
        .bind(&pin_hash)
        .execute(pool)
        .await
        .unwrap();

        (pubkey, device_code)
    }

    #[cfg(feature = "integration-tests")]
    async fn call_verify_pin(
        auth_state: crate::api::http::routes::AuthState,
        device_code: &str,
        pin: &str,
    ) -> axum::response::Response {
        match super::headless_verify_pin(
            create_unit_test_tenant(),
            axum::extract::State(auth_state),
            axum::http::HeaderMap::new(),
            axum::Json(super::HeadlessVerifyPinRequest {
                device_code: device_code.to_string(),
                pin: pin.to_string(),
            }),
        )
        .await
        {
            Ok(r) => axum::response::IntoResponse::into_response(r),
            Err(e) => axum::response::IntoResponse::into_response(e),
        }
    }

    /// Happy path: correct PIN finalizes and returns the OAuth code synchronously in the body.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_happy_path_returns_code_synchronously() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-ok-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let response = call_verify_pin(auth_state, &device_code, "123456").await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["success"], true);
        assert!(
            body["code"].as_str().is_some_and(|c| !c.is_empty()),
            "verify-pin must return an exchange code synchronously"
        );
        assert_eq!(body["pubkey"], pubkey);

        // User materialized as verified.
        let verified: (bool,) =
            sqlx::query_as("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(verified.0);

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    /// After 5 failed attempts the PIN is locked; even the correct PIN then fails uniformly.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_attempt_cap_locks_at_5() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-lock-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let mut statuses = Vec::new();
        for _ in 0..5 {
            let r = call_verify_pin(auth_state.clone(), &device_code, "000000").await;
            statuses.push(r.status());
        }
        assert!(
            statuses.iter().all(|s| !s.is_success()),
            "wrong PIN attempts must all fail"
        );

        // Correct PIN after the cap must still fail (locked), not succeed.
        let locked = call_verify_pin(auth_state, &device_code, "123456").await;
        assert!(
            !locked.status().is_success(),
            "correct PIN after lockout must not finalize"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    /// Anti-enumeration: an unknown device_code and a wrong PIN are indistinguishable to the client.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_anti_enumeration_uniform_errors() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-enum-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let wrong_pin = call_verify_pin(auth_state.clone(), &device_code, "000000").await;
        let wrong_device = call_verify_pin(
            auth_state,
            &format!("dc_{}", uuid::Uuid::new_v4()),
            "000000",
        )
        .await;

        assert_eq!(
            wrong_pin.status(),
            wrong_device.status(),
            "wrong PIN and wrong device_code must return the same status"
        );
        let wrong_pin_body = response_json(wrong_pin).await;
        let wrong_device_body = response_json(wrong_device).await;
        assert_eq!(
            wrong_pin_body, wrong_device_body,
            "failure bodies must be identical (no enumeration / lockout signal)"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    /// Duplicate email: the PIN path funnels through the shared finalize, so it inherits the
    /// 409 conflict behavior of the link path.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_duplicate_email_conflict() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-dup-{}@example.com", uuid::Uuid::new_v4());

        // Pre-existing user owns the email.
        let existing_pubkey = Keys::generate().public_key().to_hex();
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&existing_pubkey)
        .bind(&email)
        .bind(bcrypt::hash("testpassword123", bcrypt::DEFAULT_COST).unwrap())
        .execute(&pool)
        .await
        .unwrap();

        let (pending_pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let response = call_verify_pin(auth_state, &device_code, "123456").await;
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = ANY($1)")
            .bind(vec![existing_pubkey, pending_pubkey])
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_completed_registration_returns_idempotent_success() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-complete-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        sqlx::query("UPDATE oauth_codes SET consumed_at = NOW() WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();

        let response = call_verify_pin(auth_state, &device_code, "123456").await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "completed registrations should match the link path's friendly success semantics"
        );
        let body = response_json(response).await;
        assert_eq!(body["success"], true);
        assert!(
            body["code"].as_str().is_none_or(str::is_empty),
            "already-completed idempotent success must not mint a new exchange code"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "integration-tests")]
    async fn call_resend_pin(
        auth_state: crate::api::http::routes::AuthState,
        device_code: &str,
    ) -> axum::response::Response {
        match super::headless_resend_pin(
            create_unit_test_tenant(),
            axum::extract::State(auth_state),
            axum::Json(super::HeadlessResendPinRequest {
                device_code: device_code.to_string(),
            }),
        )
        .await
        {
            Ok(r) => axum::response::IntoResponse::into_response(r),
            Err(e) => axum::response::IntoResponse::into_response(e),
        }
    }

    /// After the attempt cap locks the PIN, a resend (past the cooldown) re-arms a fresh PIN/token
    /// and resets the attempt counter to zero.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_resend_pin_rearms_after_lockout() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-ok-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Simulate a locked PIN whose last send is past the cooldown.
        sqlx::query(
            "UPDATE oauth_codes SET pin_attempts = 5, pin_sent_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1",
        )
        .bind(&device_code)
        .execute(&pool)
        .await
        .unwrap();

        let (old_hash, old_token): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pin_hash, pending_email_verification_token FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        let response = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let (attempts, new_hash, new_token): (i32, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pin_attempts, pin_hash, pending_email_verification_token FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(attempts, 0, "resend resets the attempt counter");
        assert_ne!(new_hash, old_hash, "resend mints a fresh PIN");
        assert_ne!(
            new_token, old_token,
            "resend mints a fresh verification token"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    /// Within the 5-minute cooldown, resend is a silent no-op (PIN/token unchanged).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_resend_pin_respects_cooldown() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-cooldown-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Last send just now → inside the cooldown window.
        sqlx::query("UPDATE oauth_codes SET pin_sent_at = NOW() WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();

        let (old_hash, old_token): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pin_hash, pending_email_verification_token FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        let response = call_resend_pin(auth_state, &device_code).await;
        // Uniform success response (no lockout/cooldown signal leaked to the client).
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let (new_hash, new_token): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pin_hash, pending_email_verification_token FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(new_hash, old_hash, "cooldown must not re-mint the PIN");
        assert_eq!(new_token, old_token, "cooldown must not re-mint the token");

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_resend_pin_email_failure_preserves_existing_pin_and_cooldown() {
        let _email_env = force_email_service_failure();

        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-email-fail-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let old_sent_at = chrono::Utc::now() - chrono::Duration::minutes(10);
        sqlx::query(
            "UPDATE oauth_codes SET pin_attempts = 5, pin_sent_at = $2 WHERE device_code = $1",
        )
        .bind(&device_code)
        .bind(old_sent_at)
        .execute(&pool)
        .await
        .unwrap();

        let (old_hash, old_token, old_attempts, old_pin_sent_at): (
            Option<String>,
            Option<String>,
            i32,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT pin_hash, pending_email_verification_token, pin_attempts, pin_sent_at FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        let response = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let (new_hash, new_token, new_attempts, new_pin_sent_at): (
            Option<String>,
            Option<String>,
            i32,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT pin_hash, pending_email_verification_token, pin_attempts, pin_sent_at FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(new_hash, old_hash, "failed resend must preserve old PIN");
        assert_eq!(
            new_token, old_token,
            "failed resend must preserve old verification link"
        );
        assert_eq!(
            new_attempts, old_attempts,
            "failed resend must preserve lockout state until replacement is deliverable"
        );
        assert_eq!(
            new_pin_sent_at, old_pin_sent_at,
            "failed resend must not arm a new cooldown"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_resend_pin_completed_registration_is_noop() {
        let _email_env = force_email_service_failure();

        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-complete-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        sqlx::query(
            "UPDATE oauth_codes SET consumed_at = NOW(), pin_sent_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1",
        )
        .bind(&device_code)
        .execute(&pool)
        .await
        .unwrap();

        let (old_hash, old_token, old_attempts): (Option<String>, Option<String>, i32) =
            sqlx::query_as(
                "SELECT pin_hash, pending_email_verification_token, pin_attempts FROM oauth_codes WHERE device_code = $1",
            )
            .bind(&device_code)
            .fetch_one(&pool)
            .await
            .unwrap();

        let response = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let (new_hash, new_token, new_attempts): (Option<String>, Option<String>, i32) =
            sqlx::query_as(
                "SELECT pin_hash, pending_email_verification_token, pin_attempts FROM oauth_codes WHERE device_code = $1",
            )
            .bind(&device_code)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(new_hash, old_hash, "completed resend must not rotate PIN");
        assert_eq!(
            new_token, old_token,
            "completed resend must not rotate link"
        );
        assert_eq!(
            new_attempts, old_attempts,
            "completed resend must not reset attempts"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }
}
