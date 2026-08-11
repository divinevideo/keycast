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
    OAuthCodeRepository, PinAttemptReservation, PolicyRepository,
    StoreOAuthCodeWithRegistrationParams, UserRepository,
};
use nostr_sdk::Keys;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::auth::{
    generate_secure_token, normalize_registration_email, EMAIL_ALREADY_EXISTS_CODE,
    EMAIL_ALREADY_EXISTS_MESSAGE, EMAIL_VERIFICATION_EXPIRY_HOURS, INVALID_EMAIL_CODE,
    INVALID_EMAIL_MESSAGE,
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
    let stored = oauth_code_repo
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

    // A duplicate register supersedes the earlier pending registration in place and keeps its
    // device_code (keycast#268). Poll on the row's device_code, not the one we just generated, so
    // the app polls the registration that actually exists.
    let device_code = stored.device_code.unwrap_or(device_code);
    if stored.superseded {
        tracing::info!(
            event = "headless_registration_superseded",
            tenant_id = tenant_id,
            client_id = %req.client_id,
            "Duplicate registration re-armed the existing pending registration"
        );
    }

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

/// Failed attempts allowed against the *current* PIN before it locks (keycast#262). A resend
/// clears this, which is what makes a resend the way out of a lockout.
const MAX_PIN_ATTEMPTS: i32 = 5;

/// Failed attempts allowed across every PIN a single registration issues. Nothing clears this.
///
/// [`MAX_PIN_ATTEMPTS`] alone is escapable: it resets on resend, so an attacker who resends each
/// time it is spent gets a fresh PIN and a fresh cap indefinitely, leaving the resend cooldown as
/// the only real limit — roughly 1,440 guesses over the registration's 24-hour window. This cap
/// bounds the registration's whole life instead, and exhausting it disables PIN entry while
/// leaving the emailed link working.
///
/// The value is bounded from both sides rather than derived, and 50 is a choice inside that band:
///
/// - Ceiling: NIST SP 800-63B-4 §3.2.2 requires a verifier to limit consecutive failed attempts
///   against a specific authenticator to no more than 100 before disabling it. That rules out
///   anything above 100; it is not a reason to pick any particular value below it.
/// - Floor: a legitimate user must not hit this. The realistic worst case is the per-PIN cap spent
///   against the original PIN plus each of two or three resends, so 20 rather than 15.
/// - Exposure: against a 10^6 PIN space the cap is very nearly the whole story, so N attempts is
///   about N in a million. 50 gives roughly 0.005%, against roughly 0.14% with no lifetime cap.
///
/// Anything in roughly 25..100 satisfies all three. 50 is picked for headroom over the floor
/// without crowding the ceiling, and the honest description is that the band is justified and the
/// exact number inside it is not.
const MAX_PIN_ATTEMPTS_LIFETIME: i32 = 50;

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

/// Record a verify-pin failure to the shared brute-force feed (#258).
///
/// `reason` is the internal classification and `http_status` the status actually returned, so the
/// feed stays aligned with what the caller observed.
async fn record_pin_verify_failure(
    pool: &sqlx::PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
    pubkey: Option<&str>,
    email: Option<&str>,
    reason: &str,
    http_status: i32,
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

/// Spend bcrypt work equivalent to a real PIN comparison.
///
/// Used on the one verify-pin rejection that must stay indistinguishable from a wrong PIN: an
/// unknown `device_code`. Every other rejection reports its own status and code, so burning work
/// on those would buy no secrecy while consuming the bounded bcrypt worker pool.
async fn burn_dummy_bcrypt(
    bcrypt_sender: &crate::bcrypt_queue::BcryptSender,
) -> Result<(), HeadlessError> {
    bcrypt_sender.burn_dummy().await.map_err(Into::into)
}

/// POST /api/headless/verify-pin
///
/// In-app fallback for the email verification link (keycast#262): for webviews that never run the
/// link page, a different device, or a mangled link, the user types the 6-digit PIN. The pending
/// row is located by `device_code` (the real authenticator); the PIN is defense-in-depth, bounded
/// by [`MAX_PIN_ATTEMPTS`]. On success the same finalize path as the link runs and the OAuth
/// authorization code is returned synchronously in the body (no Redis dependency).
///
/// # Rejection detail
///
/// Rejections are specific rather than uniform, so the caller can tell the user what to do:
/// [`HeadlessError::PinLocked`], [`HeadlessError::PinExpired`], and
/// [`HeadlessError::PinUnavailable`] each direct the user to request a new code, while
/// [`HeadlessError::PinInvalid`] means "check the digits and retry".
///
/// The single state kept deliberately uniform is an unknown `device_code`, which is reported as
/// [`HeadlessError::PinInvalid`] with matching bcrypt work burned so it is indistinguishable from
/// a wrong PIN. Every state that *is* reported specifically is reachable only by a caller already
/// holding the 64-char server-issued `device_code` for that registration, so naming it discloses
/// nothing to anyone else. What bounds PIN guessing is the [`MAX_PIN_ATTEMPTS`] cap enforced in
/// [`OAuthCodeRepository::reserve_pin_attempt`], not the opacity of the reply.
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
        // The only rejection kept uniform: an unknown or expired device_code must be
        // indistinguishable from a wrong PIN, in latency as well as in status and code.
        burn_dummy_bcrypt(&auth_state.state.bcrypt_sender).await?;
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            None,
            None,
            "device_code_not_found",
            StatusCode::UNAUTHORIZED.as_u16().into(),
        )
        .await;
        return Err(HeadlessError::PinInvalid);
    };

    // The registration already finished issuing tokens. Report it as a terminal conflict rather
    // than a success carrying no code: the caller's poll can never complete against a consumed
    // row, so a success-shaped reply would leave it waiting out its own timeout instead of
    // telling the user the account exists and they should sign in.
    if pending.consumed_at.is_some() {
        return Err(HeadlessError::RegistrationAlreadyCompleted);
    }

    // The registration's verification window has closed. `find_by_device_code` deliberately does
    // not filter this out, so that an expired registration reads differently from an unknown
    // device_code: telling the user their code did not match would be false and would invite them
    // to retype it forever. The PIN carries no window of its own — it is one of two presentations
    // of the same confirmation code as the emailed link, so it expires exactly when the link does.
    if pending.expires_at <= Utc::now() {
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            "registration_expired",
            StatusCode::GONE.as_u16().into(),
        )
        .await;
        return Err(HeadlessError::PinExpired);
    }

    let Some(pin_hash) = pending.pin_hash.clone() else {
        // No PIN was ever issued for this registration (for example a browser OAuth registration).
        // Say so, so the caller steers the user to the email link or a resend instead of insisting
        // the digits were wrong.
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            "no_pin_issued",
            StatusCode::FORBIDDEN.as_u16().into(),
        )
        .await;
        return Err(HeadlessError::PinUnavailable);
    };

    // A PIN exists but was never confirmed delivered, so the user cannot be holding it. Treat it
    // as unavailable rather than wrong: a resend both delivers and re-arms.
    if pending.pin_sent_at.is_none() {
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            "pin_never_delivered",
            StatusCode::FORBIDDEN.as_u16().into(),
        )
        .await;
        return Err(HeadlessError::PinUnavailable);
    }

    // Atomically reserve an attempt slot BEFORE the expensive bcrypt compare. The conditional
    // UPDATE increments only while under both caps, so no more comparisons can run for this
    // device_code than the caps allow, even across concurrent requests.
    let attempt = match oauth_code_repo
        .reserve_pin_attempt(
            &req.device_code,
            tenant_id,
            MAX_PIN_ATTEMPTS,
            MAX_PIN_ATTEMPTS_LIFETIME,
        )
        .await?
    {
        PinAttemptReservation::Reserved { attempt } => attempt,
        PinAttemptReservation::CurrentPinLocked => {
            record_pin_verify_failure(
                pool,
                &headers,
                tenant_id,
                Some(&pending.user_pubkey),
                pending.pending_email.as_deref(),
                "pin_locked",
                StatusCode::LOCKED.as_u16().into(),
            )
            .await;
            return Err(HeadlessError::PinLocked);
        }
        // Lifetime cap spent: a resend cannot recover this, so do not say "request a new code".
        // PIN entry is done for this registration; the emailed link still works, which is what
        // the unavailable response steers the user to.
        PinAttemptReservation::LifetimeExhausted => {
            record_pin_verify_failure(
                pool,
                &headers,
                tenant_id,
                Some(&pending.user_pubkey),
                pending.pending_email.as_deref(),
                "pin_lifetime_exhausted",
                StatusCode::FORBIDDEN.as_u16().into(),
            )
            .await;
            return Err(HeadlessError::PinUnavailable);
        }
        // The window closed between the snapshot check above and this reservation. Same answer as
        // that check, so the boundary reports expiry rather than falling through to a comparison
        // against a dead registration.
        PinAttemptReservation::Expired => {
            record_pin_verify_failure(
                pool,
                &headers,
                tenant_id,
                Some(&pending.user_pubkey),
                pending.pending_email.as_deref(),
                "registration_expired",
                StatusCode::GONE.as_u16().into(),
            )
            .await;
            return Err(HeadlessError::PinExpired);
        }
    };

    // Constant-time PIN comparison (bcrypt's own compare; work factor dominates). Both this real
    // comparison and the dummy rejection paths share the same bounded worker pool.
    let valid = match auth_state
        .state
        .bcrypt_sender
        .verify(secrecy::SecretString::from(req.pin.clone()), pin_hash)
        .await
    {
        Ok(valid) => valid,
        Err(error) => {
            // The queue rejected or abandoned the job before bcrypt produced a comparison result,
            // so this request must not consume the attempt slot reserved above.
            oauth_code_repo
                .refund_pin_attempt(&req.device_code, tenant_id)
                .await?;
            return Err(error.into());
        }
    };

    // bcrypt is deliberately slow, so the registration's window can close while it runs. Classify
    // that as expiry rather than letting a wrong PIN read as "did not match" or a correct one fall
    // through to a finalize that cannot succeed. Uses the window already loaded above, so this
    // costs no query.
    if pending.expires_at <= Utc::now() {
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            "registration_expired",
            StatusCode::GONE.as_u16().into(),
        )
        .await;
        return Err(HeadlessError::PinExpired);
    }

    if !valid {
        // The slot was already consumed by the atomic reserve above; just classify and record.
        // Spending the last slot is reported as locked rather than merely wrong, so the user is
        // told to request a new code on the attempt that exhausts the cap instead of on the next
        // one.
        let (error, reason, status) = if attempt >= MAX_PIN_ATTEMPTS {
            (HeadlessError::PinLocked, "pin_locked", StatusCode::LOCKED)
        } else {
            (
                HeadlessError::PinInvalid,
                "wrong_pin",
                StatusCode::UNAUTHORIZED,
            )
        };
        record_pin_verify_failure(
            pool,
            &headers,
            tenant_id,
            Some(&pending.user_pubkey),
            pending.pending_email.as_deref(),
            reason,
            status.as_u16().into(),
        )
        .await;
        return Err(error);
    }

    // The PIN was correct, so release the slot this request reserved BEFORE running finalize.
    // `reserve_pin_attempt` charges every attempt up front, including this one, and finalize is
    // fallible for reasons that have nothing to do with the user's PIN — a database blip, a Redis
    // outage, a key-manager error. Releasing afterwards would leave a correct PIN permanently
    // counted as a failed guess on every finalize error, so repeated server-side failures could
    // burn a legitimate user's lifetime budget with the right code in their hand.
    //
    // Best-effort: this is a counter, not the gate. If it fails the user has at worst one fewer
    // attempt, and the caps are still exact.
    if let Err(e) = oauth_code_repo
        .reset_pin_attempts(&req.device_code, tenant_id)
        .await
    {
        tracing::warn!(
            "Failed to release the PIN attempt slot after a correct PIN for {}: {}",
            pending.user_pubkey,
            e
        );
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
        // Same terminal case as the `consumed_at` check above, reached when the registration
        // completed between that read and this call.
        Err(super::auth::AuthError::RegistrationAlreadyCompleted) => {
            return Err(HeadlessError::RegistrationAlreadyCompleted)
        }
        Err(e) => return Err(e.into()),
    };

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

/// Minutes between successive PIN resends.
///
/// Measured from `pin_resend_at`, which is stamped only by an actual resend. Registration stamps
/// `pin_sent_at` instead, so the first resend a user asks for is never swallowed by a cooldown
/// they never started — which matters because a resend is the only way out of a PIN lockout.
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

    // `find_by_device_code` no longer filters expired rows, so this path has to. A resend
    // deliberately does not extend `expires_at` (keycast#262 bounded lifecycle), so re-arming a
    // registration whose window has closed would mail the user a PIN and a link that both fail.
    //
    // Report this one honestly instead of through the uniform success. Verify-pin answers an
    // expired registration with PIN_EXPIRED, and the caller's recovery for that is to resend — so
    // claiming a resend succeeded here would send the user into a cooldown waiting for mail that
    // is never coming, which is the same false-success trap this change set removed from the
    // cooldown path. A failed resend leaves the affordance retryable and lets the user conclude
    // they need to register again. Reaching this requires holding the registration's device_code,
    // so it discloses nothing the caller did not already have.
    if pending.expires_at <= Utc::now() {
        tracing::debug!("resend-pin: registration expired, nothing can be re-armed");
        return Ok(Json(HeadlessResendPinResponse {
            success: false,
            message: "This registration has expired. Please sign up again.".to_string(),
        }));
    }

    // Cheap pre-check so an obvious cooldown hit does not pay for bcrypt. This is an optimization,
    // not the gate: `reset_pin_for_resend` re-evaluates the cooldown atomically as part of the
    // rotation, which is what actually prevents two concurrent resends from both rotating.
    // Anchored on `pin_resend_at`, which registration leaves NULL, so the first resend proceeds.
    if let Some(resent_at) = pending.pin_resend_at {
        if Utc::now() - resent_at < Duration::minutes(PIN_RESEND_COOLDOWN_MINUTES) {
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
    let old_pin_resend_at = pending.pin_resend_at;

    // Atomically claim the resend. A loser exits through the same uniform response, so a
    // double-submit costs the user nothing and never leaves them holding a PIN that was overwritten
    // by a concurrent rotation.
    let cooldown_cutoff = Utc::now() - Duration::minutes(PIN_RESEND_COOLDOWN_MINUTES);
    if !oauth_code_repo
        .reset_pin_for_resend(
            &req.device_code,
            tenant_id,
            &new_token,
            &new_pin_hash,
            cooldown_cutoff,
        )
        .await?
    {
        tracing::debug!("resend-pin: lost the resend claim, skipping (not revealed to client)");
        return Ok(success());
    }

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
        // Guarded on the hash this call wrote, so a later resend that did reach the user is never
        // rolled back out from under them.
        let restored = oauth_code_repo
            .restore_pin_after_failed_resend(
                &req.device_code,
                tenant_id,
                keycast_core::repositories::PinResendSnapshot {
                    verification_token: old_token.as_deref(),
                    pin_hash: old_pin_hash.as_deref(),
                    pin_attempts: old_pin_attempts,
                    pin_sent_at: old_pin_sent_at,
                    pin_resend_at: old_pin_resend_at,
                },
                &new_pin_hash,
            )
            .await?;
        if !restored {
            tracing::info!(
                "resend-pin: skipped rollback because a later resend already replaced the PIN"
            );
        }
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
    /// Duplicate email during registration finalize. Dedicated variant (not `Conflict`) so the
    /// body carries the documented `EMAIL_ALREADY_EXISTS` code byte-identical to the link path.
    EmailAlreadyExists,
    Internal(String),
    /// The registration this PIN belongs to already completed token issuance. Terminal: the
    /// account exists, so the caller should stop waiting and sign in.
    RegistrationAlreadyCompleted,
    /// The submitted PIN did not match. Also covers an unknown `device_code`, deliberately, so
    /// that case stays indistinguishable from a wrong PIN.
    PinInvalid,
    /// The attempt cap is spent. Recoverable only by requesting a new code.
    PinLocked,
    /// The PIN aged out of its validity window while the registration is still open. Recoverable
    /// by requesting a new code.
    PinExpired,
    /// No usable PIN exists for this registration — none was issued, or none was delivered.
    PinUnavailable,
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
            HeadlessError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                EMAIL_ALREADY_EXISTS_MESSAGE.to_string(),
                EMAIL_ALREADY_EXISTS_CODE,
            ),
            HeadlessError::RegistrationAlreadyCompleted => (
                StatusCode::CONFLICT,
                "This registration has already been completed. Please sign in.".to_string(),
                EMAIL_ALREADY_EXISTS_CODE,
            ),
            HeadlessError::PinInvalid => (
                StatusCode::UNAUTHORIZED,
                "That code did not match. Please check it and try again.".to_string(),
                "PIN_INVALID",
            ),
            HeadlessError::PinLocked => (
                StatusCode::LOCKED,
                "Too many incorrect attempts. Please request a new code.".to_string(),
                "PIN_LOCKED",
            ),
            HeadlessError::PinExpired => (
                StatusCode::GONE,
                "That code has expired. Please request a new one.".to_string(),
                "PIN_EXPIRED",
            ),
            HeadlessError::PinUnavailable => (
                StatusCode::FORBIDDEN,
                "Code entry is not available for this registration. Please use the link in your \
                 email or request a new code."
                    .to_string(),
                "PIN_UNAVAILABLE",
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

impl From<crate::bcrypt_queue::BcryptQueueError> for HeadlessError {
    fn from(_error: crate::bcrypt_queue::BcryptQueueError) -> Self {
        HeadlessError::ServiceUnavailable {
            message: "Verification service is busy. Please try again shortly.".to_string(),
            retry_after: Some(1),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "integration-tests")]
    use super::{MAX_PIN_ATTEMPTS, MAX_PIN_ATTEMPTS_LIFETIME};
    #[cfg(feature = "integration-tests")]
    use chrono::{DateTime, Duration, Utc};
    use nostr_sdk::Keys;
    #[cfg(feature = "integration-tests")]
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
        let _bcrypt_workers = bcrypt_queue.spawn_workers(pool.clone());
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

    #[cfg(feature = "integration-tests")]
    struct EmailEnvGuard {
        rust_env: Option<String>,
        node_env: Option<String>,
        sendgrid_api_key: Option<String>,
        disable_emails: Option<String>,
    }

    #[cfg(feature = "integration-tests")]
    impl Drop for EmailEnvGuard {
        fn drop(&mut self) {
            restore_env_var("RUST_ENV", self.rust_env.as_deref());
            restore_env_var("NODE_ENV", self.node_env.as_deref());
            restore_env_var("SENDGRID_API_KEY", self.sendgrid_api_key.as_deref());
            restore_env_var("DISABLE_EMAILS", self.disable_emails.as_deref());
        }
    }

    #[cfg(feature = "integration-tests")]
    fn restore_env_var(key: &str, value: Option<&str>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    #[cfg(feature = "integration-tests")]
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

    /// A duplicate register for the same email supersedes the first pending registration instead
    /// of minting a second row, token and email (keycast#268).
    ///
    /// Production symptom this covers: divine-mobile called `POST /api/headless/register` twice
    /// 2.9s apart for one signup. Two pending rows meant two verification emails; opening the
    /// older link 409'd (deleting the stale row) and opening it again 401'd with "Invalid or
    /// expired token. Please log in again."
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_duplicate_headless_register_supersedes_pending_registration() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("headless-dup-{}@example.com", uuid::Uuid::new_v4());

        let register = |password: &'static str, challenge: &'static str| {
            let auth_state = auth_state.clone();
            let email = email.clone();
            async move {
                let response = super::headless_register(
                    create_unit_test_tenant(),
                    axum::extract::State(auth_state),
                    axum::Json(super::HeadlessRegisterRequest {
                        email,
                        password: password.to_string(),
                        client_id: "TestClient".to_string(),
                        redirect_uri: "https://client.example/callback".to_string(),
                        nsec: None,
                        scope: None,
                        code_challenge: Some(challenge.to_string()),
                        code_challenge_method: Some("S256".to_string()),
                        state: None,
                    }),
                )
                .await
                .map(axum::response::IntoResponse::into_response)
                .expect("headless_register should succeed");
                response_json(response).await
            }
        };

        let first = register("firstpassword123", "challenge-one").await;

        // Registration itself is an uncooldowned recovery path: model a current PIN that has hit
        // its five-attempt lockout and whose resend cooldown is armed. Supersession may restore
        // usability, but it must not restore the lifetime guessing budget.
        let first_expiry = Utc::now() + chrono::Duration::hours(1);
        let first_sent_at = Utc::now() - chrono::Duration::minutes(1);
        sqlx::query(
            "UPDATE oauth_codes
             SET pin_attempts = 5, pin_failed_total = 5,
                 pin_sent_at = $2, pin_resend_at = $2, expires_at = $3
             WHERE pending_email = $1 AND tenant_id = 1 AND consumed_at IS NULL",
        )
        .bind(&email)
        .bind(first_sent_at)
        .bind(first_expiry)
        .execute(&pool)
        .await
        .expect("locked registration setup should succeed");

        let second = register("secondpassword456", "challenge-two").await;

        let first_device_code = first["device_code"]
            .as_str()
            .expect("first response carries device_code")
            .to_string();
        let second_device_code = second["device_code"]
            .as_str()
            .expect("second response carries device_code")
            .to_string();

        // The app keeps polling the registration it already knows about.
        assert_eq!(
            second_device_code, first_device_code,
            "a duplicate register must return the existing registration's device_code"
        );

        // Exactly one pending row, one live verification token: only one email is actionable.
        #[derive(sqlx::FromRow)]
        struct PendingRegistrationState {
            pending_password_hash: String,
            code_challenge: Option<String>,
            pending_email_verification_token: Option<String>,
            pin_attempts: i32,
            pin_failed_total: i32,
            pin_sent_at: Option<DateTime<Utc>>,
            pin_resend_at: Option<DateTime<Utc>>,
            expires_at: DateTime<Utc>,
        }

        let rows: Vec<PendingRegistrationState> = sqlx::query_as(
            "SELECT pending_password_hash, code_challenge, pending_email_verification_token,
                    pin_attempts, pin_failed_total, pin_sent_at, pin_resend_at, expires_at
             FROM oauth_codes
             WHERE pending_email = $1 AND tenant_id = 1 AND consumed_at IS NULL",
        )
        .bind(&email)
        .fetch_all(&pool)
        .await
        .expect("query should succeed");

        assert_eq!(
            rows.len(),
            1,
            "a duplicate register must not create a second pending registration"
        );
        let row = rows.into_iter().next().unwrap();

        // The newest attempt wins: a user who retyped their password must be able to log in with
        // the password they last submitted, and the stored PKCE challenge must match the verifier
        // the app is now holding or token exchange would fail PKCE.
        assert!(
            bcrypt::verify("secondpassword456", &row.pending_password_hash)
                .expect("stored hash should be verifiable"),
            "the second attempt's password must win"
        );
        assert!(
            !bcrypt::verify("firstpassword123", &row.pending_password_hash)
                .expect("stored hash should be verifiable"),
            "the superseded attempt's password must not survive"
        );
        assert_eq!(
            row.code_challenge.as_deref(),
            Some("challenge-two"),
            "the second attempt's PKCE challenge must win"
        );
        assert_eq!(
            row.pin_attempts, 0,
            "superseding re-arms the attempt counter"
        );
        assert_eq!(
            row.pin_failed_total, 5,
            "superseding must not grant a fresh lifetime guessing budget"
        );
        assert!(
            row.pin_resend_at.is_none(),
            "superseding must not inherit the old PIN's resend cooldown"
        );
        assert!(
            row.pin_sent_at
                .is_some_and(|sent_at| sent_at > first_sent_at),
            "the replacement PIN should be stamped only after its delivery succeeds"
        );
        assert!(
            row.expires_at > first_expiry,
            "an explicit re-registration should start a fresh verification window"
        );

        // The first email's token is dead — that link now renders the terminal
        // superseded page rather than stranding the user on a 401.
        let token = row
            .pending_email_verification_token
            .expect("pending row keeps a verification token");
        let stale_token_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE pending_email_verification_token = $1 AND tenant_id = 1",
        )
        .bind(&token)
        .fetch_one(&pool)
        .await
        .expect("query should succeed");
        assert_eq!(
            stale_token_rows, 1,
            "only the surviving registration's token resolves"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE pending_email = $1")
            .bind(&email)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE email = $1")
            .bind(&email)
            .execute(&pool)
            .await;
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
    async fn test_headless_register_leaves_the_resend_cooldown_unarmed() {
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

        let (pin_sent_at, pin_resend_at): (
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
        ) = sqlx::query_as(
            "SELECT pin_sent_at, pin_resend_at FROM oauth_codes WHERE device_code = $1 AND tenant_id = 1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .expect("pending row should exist");

        assert!(
            pin_sent_at.is_none(),
            "an undelivered PIN must not be stamped as sent"
        );
        assert!(
            pin_resend_at.is_none(),
            "registration must never arm the resend cooldown, delivered or not"
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

    /// Insert a pending headless registration with a known, freshly delivered PIN.
    ///
    /// Mirrors the state `headless_register` leaves behind on a successful send: `pin_sent_at`
    /// stamped, `pin_resend_at` still NULL because no resend has happened yet.
    ///
    /// Returns (pubkey, device_code).
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
                device_code, is_headless, pin_hash, pin_attempts, pin_sent_at
            ) VALUES (1, $1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9, $10, $11, true, $12, 0, NOW())",
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

    /// After 5 failed attempts the PIN is locked, and lockout is reported distinguishably from a
    /// merely wrong PIN so the caller can tell the user to request a new code instead of repeating
    /// "that code didn't match" forever.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_attempt_cap_reports_lockout_distinguishably() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-lock-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Attempts 1..=4 are ordinary wrong-PIN rejections.
        for attempt in 1..MAX_PIN_ATTEMPTS {
            let r = call_verify_pin(auth_state.clone(), &device_code, "000000").await;
            assert_eq!(
                r.status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "attempt {attempt} is below the cap and must read as a wrong PIN"
            );
            assert_eq!(response_json(r).await["code"], "PIN_INVALID");
        }

        // The attempt that spends the last slot already reports lockout.
        let capped = call_verify_pin(auth_state.clone(), &device_code, "000000").await;
        assert_eq!(
            capped.status(),
            axum::http::StatusCode::LOCKED,
            "the attempt exhausting the cap must report lockout, not a wrong PIN"
        );
        assert_eq!(response_json(capped).await["code"], "PIN_LOCKED");

        // Correct PIN after the cap must still fail, and say why.
        let locked = call_verify_pin(auth_state, &device_code, "123456").await;
        assert_eq!(
            locked.status(),
            axum::http::StatusCode::LOCKED,
            "correct PIN after lockout must not finalize, and must report lockout"
        );
        assert_eq!(response_json(locked).await["code"], "PIN_LOCKED");

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    /// Once the registration's own window closes, the PIN goes with it — the PIN and the emailed
    /// link are two presentations of the same confirmation code, so they expire together. That is
    /// reported as expired rather than as a wrong PIN, which would be false and would invite the
    /// user to retype a code that can never work again.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_expired_registration_reports_expired() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-expired-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        sqlx::query("UPDATE oauth_codes SET expires_at = $2 WHERE device_code = $1")
            .bind(&device_code)
            .bind(Utc::now() - Duration::minutes(1))
            .execute(&pool)
            .await
            .unwrap();

        // Even the correct PIN is refused once the registration has expired.
        let response = call_verify_pin(auth_state, &device_code, "123456").await;
        assert_eq!(response.status(), axum::http::StatusCode::GONE);
        assert_eq!(response_json(response).await["code"], "PIN_EXPIRED");

        // Expiry must not consume an attempt slot: there is nothing to brute-force here.
        let (attempts, failed_total): (i32, i32) = sqlx::query_as(
            "SELECT pin_attempts, pin_failed_total FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempts, 0);
        assert_eq!(failed_total, 0);

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await;
    }

    /// The per-PIN cap resets on resend, which is what makes a resend the way out of a lockout.
    /// That alone would be escapable forever, so a lifetime cap bounds the whole registration.
    /// Exhausting it disables PIN entry permanently — a resend does not recover it — so the reply
    /// must steer the user to the emailed link rather than telling them to request a new code.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_verify_pin_lifetime_cap_is_not_cleared_by_a_resend() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-lifetime-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Park the registration one failure short of its lifetime cap, with the current PIN
        // already locked and the resend cooldown clear — exactly the state an attacker who has
        // been cycling resend-then-guess arrives in.
        sqlx::query(
            "UPDATE oauth_codes SET pin_attempts = $2, pin_failed_total = $3, \
             pin_resend_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1",
        )
        .bind(&device_code)
        .bind(MAX_PIN_ATTEMPTS)
        .bind(MAX_PIN_ATTEMPTS_LIFETIME - 1)
        .execute(&pool)
        .await
        .unwrap();

        // A resend clears the per-PIN lockout, as it must for legitimate recovery...
        let resend = call_resend_pin(auth_state.clone(), &device_code).await;
        assert_eq!(resend.status(), axum::http::StatusCode::OK);
        let (attempts, failed_total): (i32, i32) = sqlx::query_as(
            "SELECT pin_attempts, pin_failed_total FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempts, 0, "resend clears the per-PIN cap");
        assert_eq!(
            failed_total,
            MAX_PIN_ATTEMPTS_LIFETIME - 1,
            "resend must NOT clear the lifetime counter"
        );

        // ...and the very next failure spends the lifetime cap.
        let last = call_verify_pin(auth_state.clone(), &device_code, "000000").await;
        assert_eq!(last.status(), axum::http::StatusCode::UNAUTHORIZED);

        // From here PIN entry is closed for this registration, and a resend does not reopen it.
        let exhausted = call_verify_pin(auth_state.clone(), &device_code, "000000").await;
        assert_eq!(exhausted.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(response_json(exhausted).await["code"], "PIN_UNAVAILABLE");

        sqlx::query("UPDATE oauth_codes SET pin_resend_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1")
            .bind(&device_code).execute(&pool).await.unwrap();
        let resend_again = call_resend_pin(auth_state.clone(), &device_code).await;
        assert_eq!(resend_again.status(), axum::http::StatusCode::OK);
        let still_closed = call_verify_pin(auth_state, &device_code, "000000").await;
        assert_eq!(
            still_closed.status(),
            axum::http::StatusCode::FORBIDDEN,
            "a resend must not reopen PIN entry once the lifetime cap is spent"
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

    /// Verify-pin answers an expired registration with PIN_EXPIRED, whose recovery affordance is
    /// resend. A resend cannot revive an expired registration, so it must say so rather than
    /// report the uniform success — otherwise the user is sent into a cooldown waiting for mail
    /// that will never arrive, which is the same false success this change set removed elsewhere.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_resend_pin_on_an_expired_registration_reports_failure() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-expired-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let (old_hash,): (Option<String>,) =
            sqlx::query_as("SELECT pin_hash FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();

        sqlx::query("UPDATE oauth_codes SET expires_at = $2 WHERE device_code = $1")
            .bind(&device_code)
            .bind(Utc::now() - Duration::minutes(1))
            .execute(&pool)
            .await
            .unwrap();

        let response = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response_json(response).await["success"],
            false,
            "a resend that cannot possibly work must not claim it succeeded"
        );

        let (new_hash,): (Option<String>,) =
            sqlx::query_as("SELECT pin_hash FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            new_hash, old_hash,
            "an expired registration must not be re-armed"
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

    /// A correct PIN must give its reserved slot back even when what follows fails.
    ///
    /// `reserve_pin_attempt` charges every attempt up front, and finalize is fallible for reasons
    /// that have nothing to do with the user's PIN. If the slot were released only after a
    /// successful finalize, a correct PIN would stay counted as a failed guess on every such
    /// failure, so repeated server-side errors could burn a legitimate user's lifetime budget while
    /// they hold the right code.
    ///
    /// Clearing `pending_password_hash` is the deterministic finalize failure used here: unlike the
    /// duplicate-email conflict, it leaves the pending row in place to be inspected.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_correct_pin_releases_its_slot_even_when_finalize_fails() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-release-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Two prior failures, so the release reads as a decrement rather than as a reset.
        sqlx::query(
            "UPDATE oauth_codes \
             SET pin_attempts = 2, pin_failed_total = 2, pending_password_hash = NULL \
             WHERE device_code = $1",
        )
        .bind(&device_code)
        .execute(&pool)
        .await
        .unwrap();

        // Correct PIN, but finalize fails.
        let response = call_verify_pin(auth_state, &device_code, "123456").await;
        assert!(
            !response.status().is_success(),
            "finalize must fail for this test to mean anything, got {}",
            response.status()
        );

        let (attempts, failed_total): (i32, i32) = sqlx::query_as(
            "SELECT pin_attempts, pin_failed_total FROM oauth_codes \
             WHERE device_code = $1 AND pending_email IS NOT NULL",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .expect("the pending row must survive an incomplete-registration failure");
        assert_eq!(attempts, 0, "a correct PIN clears the per-PIN counter");
        assert_eq!(
            failed_total, 2,
            "a correct PIN must give back the slot it reserved even though finalize failed, \
             leaving only the two real failures counted"
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

    /// bcrypt is deliberately slow, so the registration's window can close while a comparison is
    /// running. That must still read as expiry rather than as a wrong PIN. Simulated by expiring
    /// the row mid-flight, which is what the elapsed bcrypt time would otherwise do.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_expiring_during_the_comparison_reports_expired() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-race-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Alive at the snapshot check and at the reservation, so the request gets past both and
        // runs a real comparison; the window then closes before the result is classified.
        let expire_at = Utc::now() + Duration::milliseconds(120);
        sqlx::query("UPDATE oauth_codes SET expires_at = $2 WHERE device_code = $1")
            .bind(&device_code)
            .bind(expire_at)
            .execute(&pool)
            .await
            .unwrap();

        // A wrong PIN would otherwise be reported as simply not matching.
        let response = call_verify_pin(auth_state, &device_code, "000000").await;
        assert!(
            Utc::now() > expire_at,
            "the comparison must actually outlast the window for this test to mean anything"
        );
        assert_eq!(response.status(), axum::http::StatusCode::GONE);
        assert_eq!(response_json(response).await["code"], "PIN_EXPIRED");

        // Prove the 410 came from the post-comparison check rather than from the reservation
        // refusing an already-expired row. Reaching bcrypt requires the reservation to have
        // succeeded while the window was still open, and a reservation charges both counters
        // exactly once. Without this the test would pass vacuously whenever scheduling ate the
        // window before the reservation ran.
        let (attempts, failed_total): (i32, i32) = sqlx::query_as(
            "SELECT pin_attempts, pin_failed_total FROM oauth_codes \
             WHERE device_code = $1 AND pending_email IS NOT NULL",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (attempts, failed_total),
            (1, 1),
            "the reservation must have succeeded before expiry, so the comparison actually ran"
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

    /// A registration carrying no usable PIN reports that, rather than insisting the digits were
    /// wrong, so the caller steers the user to the email link or a resend.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_without_usable_pin_reports_unavailable() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();

        // No PIN was ever issued for this registration.
        let no_pin_email = format!("verify-pin-nopin-{}@example.com", uuid::Uuid::new_v4());
        let (no_pin_pubkey, no_pin_device) =
            insert_pending_with_pin(&pool, &no_pin_email, "123456").await;
        sqlx::query("UPDATE oauth_codes SET pin_hash = NULL WHERE device_code = $1")
            .bind(&no_pin_device)
            .execute(&pool)
            .await
            .unwrap();

        let response = call_verify_pin(auth_state.clone(), &no_pin_device, "123456").await;
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(response_json(response).await["code"], "PIN_UNAVAILABLE");

        // A PIN exists but was never confirmed delivered, so the user cannot be holding it.
        let undelivered_email = format!("verify-pin-undeliv-{}@example.com", uuid::Uuid::new_v4());
        let (undelivered_pubkey, undelivered_device) =
            insert_pending_with_pin(&pool, &undelivered_email, "123456").await;
        sqlx::query("UPDATE oauth_codes SET pin_sent_at = NULL WHERE device_code = $1")
            .bind(&undelivered_device)
            .execute(&pool)
            .await
            .unwrap();

        let response = call_verify_pin(auth_state, &undelivered_device, "123456").await;
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(response_json(response).await["code"], "PIN_UNAVAILABLE");

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = ANY($1)")
            .bind(vec![no_pin_device, undelivered_device])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = ANY($1)")
            .bind(vec![no_pin_pubkey, undelivered_pubkey])
            .execute(&pool)
            .await;
    }

    /// A rejected bcrypt job returns 503 without consuming a PIN-attempt slot.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_bcrypt_503_refunds_reserved_attempt() {
        let mut auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-busy-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        let disconnected_queue = crate::bcrypt_queue::BcryptQueue::new();
        let disconnected_sender = disconnected_queue.sender();
        drop(disconnected_queue);
        std::sync::Arc::get_mut(&mut auth_state.state)
            .expect("test auth state should have one owner")
            .bcrypt_sender = disconnected_sender;

        let response = call_verify_pin(auth_state, &device_code, "000000").await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let (attempts, failed_total): (i32, i32) = sqlx::query_as(
            "SELECT pin_attempts, pin_failed_total FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            attempts, 0,
            "bcrypt backpressure must not advance the lockout counter"
        );
        assert_eq!(
            failed_total, 0,
            "bcrypt backpressure must not advance the lifetime counter either"
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

    /// The one rejection that must stay uniform: an unknown device_code is indistinguishable from
    /// a wrong PIN. Every other rejection is reported specifically, but this one is reachable
    /// without holding a device_code, so it must reveal nothing.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_unknown_device_code_is_indistinguishable_from_wrong_pin() {
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
        let body = response_json(response).await;
        assert_eq!(
            body["code"],
            super::super::auth::EMAIL_ALREADY_EXISTS_CODE,
            "PIN path must emit the same documented duplicate-email code as the link path"
        );

        let _ = sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = ANY($1)")
            .bind(vec![existing_pubkey, pending_pubkey])
            .execute(&pool)
            .await;
    }

    /// A registration that already issued tokens is terminal. It must not answer with a
    /// success-shaped body carrying no code: a caller that keeps polling against a consumed row
    /// can never complete, so it would sit until its own timeout instead of telling the user the
    /// account exists and they should sign in.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_completed_registration_is_terminal_conflict() {
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
            axum::http::StatusCode::CONFLICT,
            "a completed registration must be reported as terminal, not as a codeless success"
        );
        let body = response_json(response).await;
        assert_eq!(
            body["code"],
            super::super::auth::EMAIL_ALREADY_EXISTS_CODE,
            "the account exists, so reuse the documented already-registered code"
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

    /// The PIN path runs the same finalize as the email link, so it must inherit the link path's
    /// recovery for a users row that already exists without the pending credentials — created, for
    /// example, by team membership or authorization pre-creation. Treating "a row exists" as
    /// "nothing left to do" would leave that row permanently without an email, a password, or a
    /// personal key while still handing the caller a usable exchange code.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_verify_pin_completes_a_bare_pre_existing_user_row() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("verify-pin-bare-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // A bare row for the same pubkey, carrying none of the pending registration.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) \
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        let response = call_verify_pin(auth_state, &device_code, "123456").await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(
            response_json(response).await["code"]
                .as_str()
                .is_some_and(|c| !c.is_empty()),
            "verify-pin still returns an exchange code"
        );

        let (row_email, verified, has_password, has_key): (Option<String>, bool, bool, bool) =
            sqlx::query_as(
                "SELECT u.email, u.email_verified, u.password_hash IS NOT NULL, \
                 EXISTS(SELECT 1 FROM personal_keys pk WHERE pk.user_pubkey = u.pubkey) \
                 FROM users u WHERE u.pubkey = $1 AND u.tenant_id = 1",
            )
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(
            row_email.as_deref(),
            Some(email.as_str()),
            "the pending email must be applied to the pre-existing row"
        );
        assert!(verified, "the row must end up verified");
        assert!(has_password, "the pending password must be applied");
        assert!(has_key, "the pending personal key must be applied");

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

        // Simulate a locked PIN whose last resend is past the cooldown.
        sqlx::query(
            "UPDATE oauth_codes SET pin_attempts = 5, pin_sent_at = NOW() - INTERVAL '10 minutes', \
             pin_resend_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1",
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

    /// The resend a user asks for right after registering must actually send. Registration stamps
    /// `pin_sent_at`, so anchoring the cooldown there would swallow that first request while still
    /// reporting success — and since a resend is the only way out of a PIN lockout, a user who
    /// burns the attempt cap in the first few minutes would have no working recovery at all.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_resend_pin_after_registration_is_not_swallowed_by_a_cooldown() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-first-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // Exactly the state registration leaves behind, plus a lockout the user must escape:
        // the PIN was delivered moments ago and no resend has happened yet.
        sqlx::query(
            "UPDATE oauth_codes SET pin_attempts = 5, pin_sent_at = NOW() WHERE device_code = $1",
        )
        .bind(&device_code)
        .execute(&pool)
        .await
        .unwrap();

        let (old_hash, old_resend_at): (Option<String>, Option<chrono::DateTime<Utc>>) =
            sqlx::query_as(
                "SELECT pin_hash, pin_resend_at FROM oauth_codes WHERE device_code = $1",
            )
            .bind(&device_code)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            old_resend_at.is_none(),
            "registration must not pre-arm the resend cooldown"
        );

        let response = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let (attempts, new_hash, new_resend_at): (
            i32,
            Option<String>,
            Option<chrono::DateTime<Utc>>,
        ) = sqlx::query_as(
            "SELECT pin_attempts, pin_hash, pin_resend_at FROM oauth_codes WHERE device_code = $1",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_ne!(
            new_hash, old_hash,
            "the first resend after registration must mint a fresh PIN, not silently do nothing"
        );
        assert_eq!(attempts, 0, "the first resend must clear the lockout");
        assert!(
            new_resend_at.is_some(),
            "a real resend arms the cooldown for the ones after it"
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

    /// Within the 5-minute cooldown, a *subsequent* resend is a silent no-op (PIN/token unchanged).
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_resend_pin_respects_cooldown() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("resend-pin-cooldown-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        // A resend already ran just now → inside the cooldown window.
        sqlx::query(
            "UPDATE oauth_codes SET pin_sent_at = NOW(), pin_resend_at = NOW() WHERE device_code = $1",
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

        let old_sent_at = Utc::now() - Duration::minutes(10);
        sqlx::query(
            "UPDATE oauth_codes SET pin_attempts = 5, pin_sent_at = $2, pin_resend_at = $2 \
             WHERE device_code = $1",
        )
        .bind(&device_code)
        .bind(old_sent_at)
        .execute(&pool)
        .await
        .unwrap();

        type ResendFields = (
            Option<String>,
            Option<String>,
            i32,
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
        );
        const RESEND_FIELDS_SQL: &str = "SELECT pin_hash, pending_email_verification_token, \
                                         pin_attempts, pin_sent_at, pin_resend_at \
                                         FROM oauth_codes WHERE device_code = $1";

        let (old_hash, old_token, old_attempts, old_pin_sent_at, old_pin_resend_at): ResendFields =
            sqlx::query_as(RESEND_FIELDS_SQL)
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();

        let response = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let (new_hash, new_token, new_attempts, new_pin_sent_at, new_pin_resend_at): ResendFields =
            sqlx::query_as(RESEND_FIELDS_SQL)
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
            "failed resend must not restamp the PIN validity window"
        );
        assert_eq!(
            new_pin_resend_at, old_pin_resend_at,
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

    /// A resend whose email could not be delivered rolls its own mutation back. That rollback must
    /// be guarded: if another resend already succeeded in the meantime, restoring the older
    /// snapshot would invalidate the PIN that is sitting in the user's inbox right now, so the code
    /// they were just sent would not work.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    #[serial]
    async fn test_failed_resend_does_not_clobber_a_later_successful_one() {
        let auth_state = create_lazy_auth_state();
        let pool = auth_state.state.db.clone();
        let email = format!("repro-clobber-{}@example.com", uuid::Uuid::new_v4());
        let (pubkey, device_code) = insert_pending_with_pin(&pool, &email, "123456").await;

        sqlx::query("UPDATE oauth_codes SET pin_resend_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1")
            .bind(&device_code).execute(&pool).await.unwrap();

        type Snap = (
            Option<String>,
            Option<String>,
            i32,
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
        );
        let (b_hash, b_token, b_attempts, b_sent, b_resend): Snap =
            sqlx::query_as("SELECT pin_hash, pending_email_verification_token, pin_attempts, pin_sent_at, pin_resend_at FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code).fetch_one(&pool).await.unwrap();

        let r = call_resend_pin(auth_state, &device_code).await;
        assert_eq!(r.status(), axum::http::StatusCode::OK);
        let (a_hash,): (Option<String>,) =
            sqlx::query_as("SELECT pin_hash FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_ne!(
            a_hash, b_hash,
            "precondition: the successful resend rotated the PIN"
        );

        keycast_core::repositories::OAuthCodeRepository::new(pool.clone())
            .restore_pin_after_failed_resend(
                &device_code,
                1,
                keycast_core::repositories::PinResendSnapshot {
                    verification_token: b_token.as_deref(),
                    pin_hash: b_hash.as_deref(),
                    pin_attempts: b_attempts,
                    pin_sent_at: b_sent,
                    pin_resend_at: b_resend,
                },
                b_hash.as_deref().expect("snapshot carries a PIN hash"),
            )
            .await
            .unwrap();

        let (final_hash,): (Option<String>,) =
            sqlx::query_as("SELECT pin_hash FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(
            final_hash, a_hash,
            "a failed resend must not restore over a PIN a later resend already delivered"
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
