// ABOUTME: OAuth 2.0 authorization flow handlers for third-party app access
// ABOUTME: Implements authorization code flow that issues bunker URLs for NIP-46 remote signing

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use base64::Engine;
use bcrypt::verify;
use chrono::{Duration, Utc};
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    CreateOAuthAuthorizationParams, OAuthAuthorizationRepository, OAuthCodeRepository,
    PersonalKeysRepository, PolicyRepository, RefreshTokenRepository, RepositoryError,
    StoreOAuthCodeParams, StoreOAuthCodeWithRegistrationParams, UserRepository,
};
use keycast_core::types::refresh_token::generate_refresh_token;
use nostr_sdk::{Keys, ToBech32};
use rand::Rng;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

// Import constants and helpers from auth module
use super::auth::{
    generate_secure_token, normalize_registration_email, token_expiry_seconds,
    EMAIL_VERIFICATION_EXPIRY_HOURS, INVALID_EMAIL_CODE, INVALID_EMAIL_MESSAGE,
};
use super::html_safety::{escape_attr, escape_html, js_string_literal};
use crate::brand::BRAND_NAME;

/// Generate a 256-bit random authorization handle (64 hex characters)
/// Used for silent re-authentication in OAuth flows
pub fn generate_authorization_handle() -> String {
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(random_bytes)
}

/// Extract optional nsec from PKCE code_verifier
/// Format: "{random}.{nsec}" where nsec is either nsec1... (bech32) or 64-char hex
/// Returns None if no nsec embedded (standard PKCE flow)
pub fn extract_nsec_from_verifier_public(verifier: &str) -> Option<String> {
    if let Some((_random, nsec)) = verifier.split_once('.') {
        // Check if it looks like an nsec (starts with nsec1) or hex (64 chars)
        if nsec.starts_with("nsec1")
            || (nsec.len() == 64 && nsec.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Some(nsec.to_string());
        }
    }
    None
}

fn password_visibility_toggle_html(field_id: &str) -> String {
    format!(
        r#"<button type="button" class="password_toggle" data-password-target="{}" aria-label="Show password" title="Show password" onclick="togglePasswordVisibility(this)">Show</button>"#,
        escape_attr(field_id)
    )
}

#[cfg(test)]
fn password_visibility_controls_html(field_ids: &[&str]) -> String {
    let buttons = field_ids
        .iter()
        .map(|field_id| password_visibility_toggle_html(field_id))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"{buttons}
<script>
function togglePasswordVisibility(button) {{
    const input = document.getElementById(button.dataset.passwordTarget);
    if (!input) return;
}}
</script>"#
    )
}

/// Extract origin (scheme + host + optional port) from a redirect_uri
/// Examples: "https://example.com/callback" -> "https://example.com"
///           "http://localhost:3000/auth" -> "http://localhost:3000"
///
/// Security: Only HTTPS URLs are allowed (HTTP for localhost only).
/// Custom URL schemes (divine://, myapp://) are rejected because any app can
/// register any scheme, making them vulnerable to hijacking attacks.
/// HTTPS URLs use DNS for identity verification.
pub fn extract_origin(redirect_uri: &str) -> Result<String, OAuthError> {
    use nostr_sdk::Url;
    let url = Url::parse(redirect_uri)
        .map_err(|_| OAuthError::InvalidRequest("Invalid redirect_uri".to_string()))?;

    let scheme = url.scheme();
    let host = url.host_str().ok_or(OAuthError::InvalidRequest(
        "redirect_uri missing host".to_string(),
    ))?;

    // For http/https schemes, apply web security rules
    if scheme == "http" || scheme == "https" {
        // RFC 6761 reserves `localhost.` and every `*.localhost.` subdomain as
        // loopback; browsers and OS resolvers honor this. Accepting `.localhost`
        // subdomains here lets multiple local dev services coexist on distinct
        // hostnames (e.g. admin.localhost, api.localhost) without each claiming
        // the bare `localhost`. The subdomain match requires a non-empty label
        // before `.localhost` so `xxxlocalhost` or the empty prefix are rejected.
        let is_localhost = host == "localhost"
            || host == "127.0.0.1"
            || host == "[::1]"
            || host == "::1"
            || (host.ends_with(".localhost") && host.len() > ".localhost".len());
        if scheme == "http" && !is_localhost {
            return Err(OAuthError::InvalidRequest(
                "HTTPS required for non-localhost redirect_uri".to_string(),
            ));
        }

        let origin = match url.port() {
            Some(port) => format!("{}://{}:{}", scheme, host, port),
            None => format!("{}://{}", scheme, host),
        };
        return Ok(origin);
    }

    // Reject custom URL schemes - only http/https allowed
    // Custom schemes (divine://, myapp://) are vulnerable to hijacking attacks
    // since any app can register any scheme. HTTPS URLs use DNS for identity verification.
    Err(OAuthError::InvalidRequest(format!(
        "Invalid redirect_uri scheme '{}'. Only https:// URLs are allowed (http:// for localhost only).",
        scheme
    )))
}

/// Parse OAuth scope parameter for policy-based authorization.
/// Accepts either "policy:slug" format (new) or legacy scopes (rejected with error).
/// Returns the policy slug if valid, or error if invalid format.
pub fn parse_policy_scope(scope: &str) -> Result<String, OAuthError> {
    if let Some(policy_slug) = scope.strip_prefix("policy:") {
        if policy_slug.is_empty() {
            return Err(OAuthError::InvalidRequest(
                "Policy scope cannot be empty. Use 'policy:social', 'policy:readonly', etc."
                    .to_string(),
            ));
        }
        Ok(policy_slug.to_string())
    } else {
        // Legacy scopes are no longer accepted
        Err(OAuthError::InvalidRequest(format!(
            "Invalid scope '{}'. Use 'policy:social', 'policy:readonly', etc. See GET /api/policies for available options.",
            scope
        )))
    }
}

/// Store an OAuth authorization code with PKCE support.
#[allow(clippy::too_many_arguments)]
async fn store_oauth_code(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    code: &str,
    user_pubkey: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    expires_at: chrono::DateTime<Utc>,
    previous_auth_id: Option<i32>,
    state: Option<&str>,
) -> Result<(), OAuthError> {
    let repo = OAuthCodeRepository::new(pool.clone());
    repo.store(StoreOAuthCodeParams {
        tenant_id,
        code,
        user_pubkey,
        client_id,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method,
        expires_at,
        previous_auth_id,
        state,
        is_headless: false,
    })
    .await?;
    Ok(())
}

/// Store OAuth code with pending registration data (deferred user creation)
/// Used by oauth_register to defer user creation until token exchange
#[allow(clippy::too_many_arguments)]
async fn store_oauth_code_with_pending_registration(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    code: &str,
    user_pubkey: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    expires_at: chrono::DateTime<Utc>,
    pending_email: &str,
    pending_password_hash: &str,
    pending_email_verification_token: &str,
    pending_encrypted_secret: Option<&[u8]>,
    state: Option<&str>,
    device_code: Option<&str>,
) -> Result<(), OAuthError> {
    let repo = OAuthCodeRepository::new(pool.clone());
    repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
        tenant_id,
        code,
        user_pubkey,
        client_id,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method,
        expires_at,
        pending_email,
        pending_password_hash,
        pending_email_verification_token,
        pending_encrypted_secret,
        state,
        device_code,
        is_headless: false,
    })
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>, // OAuth 2.0 state parameter for CSRF protection
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>, // OAuth 2.0 prompt parameter: "login", "consent", "none"
    pub byok_pubkey: Option<String>, // BYOK: force registration with this pubkey
    pub default_register: Option<bool>, // Legacy: show register form by default
    pub authorization_handle: Option<String>, // For silent re-authentication
    pub screen: Option<String>, // Internal auth-server UI state, e.g. "consent"
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>, // OAuth 2.0 state parameter
    pub approved: bool,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>, // "authorization_code" or "refresh_token"
    pub code: Option<String>,       // For authorization_code grant
    pub client_id: String,
    pub redirect_uri: Option<String>, // For authorization_code grant
    pub code_verifier: Option<String>, // For PKCE (authorization_code grant)
    pub refresh_token: Option<String>, // For refresh_token grant
}

/// Generate UCAN token signed by user's key
/// Note: Currently using auth::generate_ucan_token instead, but keeping this for potential future use
#[allow(dead_code)]
async fn generate_ucan_token(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
) -> Result<String, OAuthError> {
    use crate::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());

    // Create facts as a single JSON object - redirect_origin identifies the authorization
    let facts = json!({
        "tenant_id": tenant_id,
        "email": email,
        "redirect_origin": redirect_origin,
    });

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did) // Self-issued
        .with_lifetime(token_expiry_seconds() as u64)
        .with_fact(facts)
        .build()
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to build UCAN: {}", e)))?
        .sign()
        .await
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to sign UCAN: {}", e)))?;

    ucan.encode()
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to encode UCAN: {}", e)))
}

/// RFC 6749 Section 5.1 - Successful Response (Keycast variant)
///
/// Returns bunker URL for NIP-46 remote signing, plus access_token for REST RPC API
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.1>
/// Policy info included in token responses
#[derive(Debug, Serialize)]
pub struct TokenPolicyInfo {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub permissions: Vec<keycast_core::custom_permissions::PermissionDisplay>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub bunker_url: String, // Keycast extension - NIP-46 credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>, // UCAN token for REST RPC API (/api/nostr)
    pub token_type: String, // RFC 6749 required - "Bearer"
    pub expires_in: i64,    // RFC 6749 recommended - UCAN expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, // RFC 6749 optional - granted permissions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<TokenPolicyInfo>, // Keycast extension - policy details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_handle: Option<String>, // For silent re-authentication (consent-skip)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>, // RFC 6749 - for silent token renewal
}

#[derive(Debug)]
pub enum OAuthError {
    Unauthorized,
    InvalidEmail,
    InvalidRequest(String),
    InvalidGrant(String), // RFC 6749 - for invalid/expired refresh tokens or auth codes
    Database(sqlx::Error),
    Encryption(String),
    ServerError(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            OAuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password. Please check your credentials and try again."
                    .to_string(),
            ),
            OAuthError::InvalidEmail => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": INVALID_EMAIL_MESSAGE,
                        "code": INVALID_EMAIL_CODE,
                    })),
                )
                    .into_response();
            }
            OAuthError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid request: {}", msg))
            }
            OAuthError::InvalidGrant(msg) => {
                // RFC 6749 error response format for invalid_grant
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": msg
                    })),
                )
                    .into_response();
            }
            OAuthError::Database(e) => {
                // Log the real error but return generic message to user
                tracing::error!("OAuth database error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes."
                        .to_string(),
                )
            }
            OAuthError::Encryption(e) => {
                // Log the real error but return generic message to user
                tracing::error!("OAuth encryption error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes."
                        .to_string(),
                )
            }
            OAuthError::ServerError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Server error: {}", msg),
            ),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(e: sqlx::Error) -> Self {
        OAuthError::Database(e)
    }
}

impl From<keycast_core::repositories::RepositoryError> for OAuthError {
    fn from(e: keycast_core::repositories::RepositoryError) -> Self {
        OAuthError::InvalidRequest(e.to_string())
    }
}

/// Validate PKCE code_verifier against stored code_challenge
/// Implements RFC 7636 validation for both S256 and plain methods
fn validate_pkce(
    code_verifier: &str,
    code_challenge: &str,
    code_challenge_method: &str,
) -> Result<(), OAuthError> {
    match code_challenge_method {
        "S256" => {
            // Compute SHA256 hash of code_verifier
            let hash = sha256::digest(code_verifier);

            // Convert hex to bytes then base64url encode
            let hash_bytes = hex::decode(&hash)
                .map_err(|e| OAuthError::InvalidRequest(format!("Hash decode error: {}", e)))?;

            // Base64 URL-safe encoding (no padding)
            let computed_challenge =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash_bytes);

            if computed_challenge != code_challenge {
                tracing::warn!(
                    "PKCE validation failed: computed {} != stored {}",
                    &computed_challenge[..16],
                    &code_challenge[..16]
                );
                return Err(OAuthError::InvalidRequest(
                    "Invalid code_verifier: PKCE validation failed".to_string(),
                ));
            }
            Ok(())
        }
        "plain" => {
            if code_verifier != code_challenge {
                return Err(OAuthError::InvalidRequest(
                    "Invalid code_verifier: plain PKCE validation failed".to_string(),
                ));
            }
            Ok(())
        }
        _ => Err(OAuthError::InvalidRequest(format!(
            "Unsupported code_challenge_method: {}",
            code_challenge_method
        ))),
    }
}

/// Resolve policy ID from scope parameter.
/// Parses "policy:slug" format and validates against app's default policy.
/// Resolve policy ID from scope string (e.g., "policy:social" -> policy.id)
async fn resolve_policy_from_scope(pool: &sqlx::PgPool, scope: &str) -> Result<i32, OAuthError> {
    // Parse scope for policy slug
    let policy_slug = parse_policy_scope(scope)?;

    // Look up the requested policy (policies are now global)
    let policy_repo = PolicyRepository::new(pool.clone());
    let requested_policy = policy_repo
        .find_by_slug(&policy_slug)
        .await
        .map_err(|e| match e {
            RepositoryError::NotFound(_) => OAuthError::InvalidRequest(format!(
                "Unknown policy '{}'. See GET /api/policies for available options.",
                policy_slug
            )),
            _ => OAuthError::Database(sqlx::Error::Protocol(e.to_string())),
        })?;

    Ok(requested_policy.id)
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// GET /oauth/auth-status
/// Check if user has a valid session cookie
pub async fn auth_status(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, OAuthError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Extract and validate UCAN from cookie (async)
    let user_pubkey = if let Some(token) = super::auth::extract_ucan_from_cookie(&headers) {
        crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id)
            .await
            .ok()
            .map(|(pubkey, _, _, _)| pubkey)
    } else {
        None
    };

    if let Some(user_pubkey) = user_pubkey {
        // Query user from database - user must exist for session to be valid
        let user_repo = UserRepository::new(pool.clone());
        let user_info = user_repo
            .get_account_status(&user_pubkey, tenant_id)
            .await
            .ok()
            .flatten();

        // Return authenticated with pubkey, optionally with email info if user exists in DB
        // NIP-07 admins may not have a user record, but their UCAN session is still valid
        if let Some((email, email_verified, _status, _reason)) = user_info {
            Ok(Json(AuthStatusResponse {
                authenticated: true,
                pubkey: Some(user_pubkey),
                email,
                email_verified,
            }))
        } else {
            // User not in DB (NIP-07 admin) - still authenticated via UCAN
            Ok(Json(AuthStatusResponse {
                authenticated: true,
                pubkey: Some(user_pubkey),
                email: None,
                email_verified: None,
            }))
        }
    } else {
        Ok(Json(AuthStatusResponse {
            authenticated: false,
            pubkey: None,
            email: None,
            email_verified: None,
        }))
    }
}

/// GET /oauth/authorize
/// Shows login form if not authenticated, or auto-approves if already authorized, or shows approval page
pub async fn authorize_get(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeRequest>,
) -> Result<Response, OAuthError> {
    use axum::response::Html;

    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Validate redirect_uri against registered client patterns (only if client is registered).
    // Open OAuth: unregistered client_ids are permitted; registration only narrows redirect URIs.
    {
        let client_repo = keycast_core::repositories::RegisteredClientRepository::new(pool.clone());

        if let Err(e) = client_repo
            .validate_redirect_uri(&params.client_id, &params.redirect_uri, tenant_id)
            .await
        {
            tracing::warn!(
                "Redirect URI validation failed for client '{}': {}",
                params.client_id,
                e
            );
            return Err(OAuthError::InvalidRequest(format!(
                "redirect_uri is not allowed for this client: {}",
                e
            )));
        }
    }

    // Check if user is authenticated via cookie and extract pubkey
    let user_pubkey = if let Some(token) = super::auth::extract_ucan_from_cookie(&headers) {
        crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id)
            .await
            .ok()
            .map(|(pubkey, _redirect_origin, _bunker_pubkey, _ucan)| pubkey)
    } else {
        None
    };

    // Handle prompt=login: force fresh login by clearing cookie
    let force_login = params.prompt.as_deref() == Some("login");
    let force_consent = params.prompt.as_deref() == Some("consent");
    let has_byok_pubkey = params.byok_pubkey.is_some();

    // Validate that the user actually exists in the database
    let (user_pubkey, clear_cookie, user_email) = if let Some(ref pubkey) = user_pubkey {
        // If prompt=login or byok_pubkey present, ignore existing session and force fresh registration
        if force_login {
            tracing::info!("prompt=login: forcing fresh login, clearing cookie");
            (None, true, None)
        } else if has_byok_pubkey {
            tracing::info!("byok_pubkey present: forcing registration, clearing cookie");
            (None, true, None)
        } else {
            // Check if user exists and get their email
            let user_repo = UserRepository::new(pool.clone());
            let account_status = user_repo.get_account_status(pubkey, tenant_id).await?;

            match account_status {
                None => {
                    tracing::warn!("UCAN cookie has pubkey {} but user doesn't exist in tenant {}, clearing stale cookie", pubkey, tenant_id);
                    (None, true, None) // User was deleted, clear the cookie
                }
                Some((email, _verified, _status, _reason)) => (user_pubkey, false, email),
            }
        }
    } else {
        (None, false, None)
    };

    let mut has_existing_authorization = false;

    // Check for silent re-authentication via authorization_handle (primary mechanism)
    if let Some(ref pubkey) = user_pubkey {
        let previous_auth_id: Option<i32> = if let Some(ref handle) = params.authorization_handle {
            tracing::info!(
                "Auto-approve check via authorization_handle for user {}",
                pubkey
            );

            // Look up by handle, scoped to this user
            let repo = OAuthAuthorizationRepository::new(pool.clone());
            repo.find_id_by_handle(handle, pubkey).await?
        } else {
            None
        };

        tracing::info!(
            "Authorization handle lookup: found={}",
            previous_auth_id.is_some()
        );
        has_existing_authorization = previous_auth_id.is_some();

        // Skip auto-approve if prompt=consent (always show approval screen)
        if previous_auth_id.is_some() && !force_consent {
            tracing::info!(
                "Auto-approving via authorization_handle for user {}",
                pubkey
            );

            // Auto-approve: generate code and send directly to parent window
            let code: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            let expires_at = Utc::now() + Duration::minutes(10);
            let scope = params.scope.as_deref().unwrap_or("sign_event");

            store_oauth_code(
                pool,
                tenant_id,
                &code,
                pubkey,
                &params.client_id,
                &params.redirect_uri,
                scope,
                params.code_challenge.as_deref(),
                params.code_challenge_method.as_deref(),
                expires_at,
                previous_auth_id,
                params.state.as_deref(),
            )
            .await?;

            // Auto-approve: redirect to redirect_uri with code (standard OAuth pattern)
            // Include state in redirect if provided
            let redirect_url = if let Some(ref state) = params.state {
                format!("{}?code={}&state={}", params.redirect_uri, code, state)
            } else {
                format!("{}?code={}", params.redirect_uri, code)
            };
            return Ok(Redirect::to(&redirect_url).into_response());
        } else if previous_auth_id.is_some() && force_consent {
            tracing::info!("prompt=consent: skipping auto-approve, showing approval screen");
        }
    }

    // Origin-based auto-approve fallback: if no handle was provided (or handle was invalid),
    // check if the user already has an active authorization for this origin.
    if let Some(ref pubkey) = user_pubkey {
        let redirect_origin = extract_origin(&params.redirect_uri)?;
        let repo = OAuthAuthorizationRepository::new(pool.clone());
        let has_active_origin_authorization = repo
            .has_active_for_origin(pubkey, &redirect_origin, tenant_id)
            .await?;

        if has_active_origin_authorization {
            has_existing_authorization = true;

            if !force_consent {
                tracing::info!(
                    "Auto-approving via active origin authorization for user {} origin {}",
                    pubkey,
                    redirect_origin
                );

                let code: String = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(32)
                    .map(char::from)
                    .collect();

                let expires_at = Utc::now() + Duration::minutes(10);
                let scope = params.scope.as_deref().unwrap_or("sign_event");

                store_oauth_code(
                    pool,
                    tenant_id,
                    &code,
                    pubkey,
                    &params.client_id,
                    &params.redirect_uri,
                    scope,
                    params.code_challenge.as_deref(),
                    params.code_challenge_method.as_deref(),
                    expires_at,
                    None,
                    params.state.as_deref(),
                )
                .await?;

                let redirect_url = if let Some(ref state) = params.state {
                    format!("{}?code={}&state={}", params.redirect_uri, code, state)
                } else {
                    format!("{}?code={}", params.redirect_uri, code)
                };
                return Ok(Redirect::to(&redirect_url).into_response());
            }
        }
    }

    // Load policy info from scope for display
    // Default to "policy:full" if no scope provided (permissive for dev, can tighten later)
    let scope_str = params.scope.as_deref().unwrap_or("policy:full");
    let policy_info_json = {
        // Parse policy slug from scope
        let policy_slug = match parse_policy_scope(scope_str) {
            Ok(slug) => slug,
            Err(_) => {
                // For now, default to "social" for backward compatibility during transition
                tracing::warn!(
                    "Invalid scope '{}', defaulting to 'social' policy",
                    scope_str
                );
                "social".to_string()
            }
        };

        // Load policy and its permissions (policies are now global)
        let policy_repo = PolicyRepository::new(pool.clone());
        match policy_repo.find_by_slug(&policy_slug).await {
            Ok(policy) => {
                let permissions = policy.permission_displays(pool).await.unwrap_or_default();
                serde_json::json!({
                    "slug": policy.slug.clone().unwrap_or_else(|| policy.id.to_string()),
                    "display_name": policy.display_name.clone().unwrap_or_else(|| policy.name.clone()),
                    "description": policy.description.clone().unwrap_or_default(),
                    "permissions": permissions
                })
                .to_string()
            }
            Err(_) => {
                // Fallback to minimal info if policy not found
                tracing::warn!("Policy '{}' not found, using fallback", policy_slug);
                serde_json::json!({
                    "slug": policy_slug,
                    "display_name": "App Access",
                    "description": "Grant access to this application",
                    "permissions": []
                })
                .to_string()
            }
        }
    };

    let chooser_confirmed = params.screen.as_deref() == Some("consent");

    let html = if let Some(pubkey) = user_pubkey {
        // Convert pubkey to npub for display
        let npub = nostr_sdk::PublicKey::from_hex(&pubkey)
            .ok()
            .and_then(|pk| pk.to_bech32().ok())
            .unwrap_or_else(|| pubkey.clone());

        if !chooser_confirmed && !has_existing_authorization {
            let identity_label = user_email.as_deref().unwrap_or(npub.as_str());
            format!(
                r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Choose Account</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --divine-green: #27C58B;
            --divine-green-dark: #1AA575;
            --bg: #F9F7F6;
            --surface: hsl(0 0% 100%);
            --border: hsl(214.3 31.8% 91.4%);
            --text: hsl(222.2 84% 4.9%);
            --text-secondary: hsl(215.4 16.3% 46.9%);
            --muted: hsl(210 40% 96.1%);
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 1.5rem;
        }}
        .header h1 {{
            font-family: 'Bricolage Grotesque', system-ui, sans-serif;
            font-size: 1.75rem;
            margin-bottom: 0.5rem;
        }}
        .header p {{
            color: var(--text-secondary);
            line-height: 1.5;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 18px 60px rgba(11, 18, 32, 0.08);
        }}
        .account {{
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .account-label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 0.35rem;
        }}
        .account-value {{
            font-size: 1rem;
            font-weight: 600;
            word-break: break-word;
        }}
        .app-context {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
            margin-bottom: 1rem;
        }}
        .actions {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}
        button {{
            width: 100%;
            border: none;
            border-radius: 9999px;
            padding: 0.9rem 1.1rem;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
        }}
        .continue {{
            background: var(--divine-green);
            color: white;
        }}
        .switch {{
            background: var(--muted);
            color: var(--text);
            border: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Choose an account</h1>
            <p>{} wants to connect to your Keycast account. Confirm which account you want to use before reviewing access.</p>
        </div>
        <div class="card">
            <div class="account">
                <div class="account-label">Signed in as</div>
                <div class="account-value">{}</div>
            </div>
            <p class="app-context">You’re already signed in on this browser, but this app hasn’t been authorized yet.</p>
            <div class="actions">
                <button type="button" class="continue" onclick="continueAsCurrentAccount()">Continue as</button>
                <button type="button" class="switch" onclick="useDifferentAccount()">Use a different account</button>
            </div>
        </div>
    </div>
    <script>
        function continueAsCurrentAccount() {{
            const url = new URL(window.location.href);
            url.searchParams.set('screen', 'consent');
            window.location.href = url.toString();
        }}

        async function useDifferentAccount() {{
            await fetch('/api/auth/logout', {{
                method: 'POST',
                credentials: 'include',
            }});

            const url = new URL(window.location.href);
            url.searchParams.delete('screen');
            window.location.href = url.toString();
        }}
    </script>
</body>
</html>
        "#,
                escape_html(&params.client_id), // header app context
                escape_html(identity_label),    // signed-in identity
            )
        } else {
            // User is authenticated - show approval screen
            format!(
                r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Authorize {client_id_html}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --divine-green: #27C58B;
            --divine-green-dark: #1AA575;
            --bg: #F9F7F6;
            --surface: hsl(0 0% 100%);
            --border: hsl(214.3 31.8% 91.4%);
            --text: hsl(222.2 84% 4.9%);
            --text-secondary: hsl(215.4 16.3% 46.9%);
            --muted: hsl(210 40% 96.1%);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: #072218;
                --surface: #0F2E23;
                --border: #1C4033;
                --text: hsl(210 40% 98%);
                --text-secondary: hsl(215 20.2% 65.1%);
                --muted: #0F2E23;
            }}
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .logo {{
            display: inline-flex;
            flex-direction: column;
            align-items: center;
            gap: 2px;
            margin-bottom: 1rem;
        }}
        .logo img {{
            height: 28px;
        }}
        .logo .logo-sub {{
            font-family: 'Inter', system-ui, sans-serif;
            font-weight: 500;
            font-size: 11px;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--divine-green);
            opacity: 0.6;
        }}
        .header h1 {{
            font-family: 'Bricolage Grotesque', system-ui, sans-serif;
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.25rem;
        }}
        .header p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        .user-identity {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }}
        .user-avatar {{
            width: 24px;
            height: 24px;
            border-radius: 50%;
            object-fit: cover;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
        }}
        .app_header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1rem;
        }}
        .app_icon {{
            width: 48px;
            height: 48px;
            background: var(--divine-green);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: white;
            flex-shrink: 0;
        }}
        .app_info h2 {{
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.125rem;
        }}
        .app_domain {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
        }}
        .session_notice {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            padding: 0.9rem 1rem;
            margin-bottom: 1rem;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: color-mix(in srgb, var(--divine-green) 8%, var(--surface));
        }}
        .session_label {{
            display: block;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 0.2rem;
        }}
        .session_identity {{
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text);
            word-break: break-word;
        }}
        .switch_account {{
            flex: 0 0 auto;
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.7rem 0.95rem;
        }}
        .switch_account:hover {{
            background: var(--muted);
        }}
        .permissions_list {{
            margin-bottom: 1rem;
        }}
        .permission_item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 0;
        }}
        .permission_icon {{
            width: 36px;
            height: 36px;
            background: color-mix(in srgb, var(--divine-green) 15%, transparent);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            flex-shrink: 0;
        }}
        .permission_content {{
            flex: 1;
        }}
        .permission_content h3 {{
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 0.125rem;
        }}
        .permission_content p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }}
        .disclaimer {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
            line-height: 1.5;
            text-align: center;
        }}
        .disclaimer a {{
            color: var(--divine-green);
            text-decoration: none;
        }}
        .disclaimer a:hover {{
            text-decoration: underline;
        }}
        .buttons {{
            display: flex;
            gap: 0.75rem;
        }}
        button {{
            flex: 1;
            padding: 0.875rem 1.25rem;
            border-radius: 9999px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }}
        .btn_deny {{
            background: var(--muted);
            color: var(--text);
            border: 1px solid var(--border);
        }}
        .btn_deny:hover {{
            background: var(--border);
        }}
        .btn_approve {{
            background: var(--divine-green);
            color: #fff;
        }}
        .btn_approve:hover {{
            background: var(--divine-green-dark);
        }}
        #npub_fallback {{
            display: none;
        }}
        .nostr-link {{
            color: var(--divine-green);
            text-decoration: none;
        }}
        .nostr-link:hover {{
            text-decoration: underline;
        }}
        /* Mobile: reduce padding for more working area */
        @media (max-width: 480px) {{
            body {{
                padding: 0.5rem;
            }}
            .header {{
                margin-bottom: 1rem;
            }}
            .card {{
                padding: 1rem;
                border-radius: 0.75rem;
            }}
            .app_header {{
                padding-bottom: 0.75rem;
                margin-bottom: 0.75rem;
            }}
            .logo {{
                margin-bottom: 0.75rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="/divine-logo.svg" alt="{brand}" />
                <span class="logo-sub">Login</span>
            </div>
            <h1>Authorize App</h1>
            <p>Grant access to <span class="user-identity"><img id="user_avatar" class="user-avatar" /><span id="display_name">your account</span></span></p>
        </div>

        <div class="card">
            <div class="app_header">
                <div class="app_icon">
                    <span id="app_icon_letter">{app_icon_letter}</span>
                </div>
                <div class="app_info">
                    <div class="app_domain" id="app_domain"></div>
                    <h2 id="app_name">{client_id_html2}</h2>
                </div>
            </div>

            <div class="session_notice">
                <div class="session_copy">
                    <span class="session_label">Signed in as</span>
                    <div class="session_identity">{session_identity_html}</div>
                </div>
                <button type="button" class="switch_account" onclick="useDifferentAccount()">Use a different account</button>
            </div>

            <div class="permissions_list" id="permissions_list">
                <!-- Permissions will be populated by JavaScript -->
            </div>

            <p class="disclaimer">
                By authorizing, you agree to {brand}'s <a href="https://divine.video/terms" target="_blank">terms</a> and <a href="https://divine.video/privacy" target="_blank">privacy policy</a>.
            </p>

            <div class="buttons">
                <button class="btn_deny" onclick="deny()">Deny</button>
                <button class="btn_approve" onclick="approve()">Authorize</button>
            </div>
        </div>
    </div>

    <div id="npub_fallback">{npub_html}</div>

    <script>
        const clientId = {client_id_js};
        const redirectUri = {redirect_uri_js};
        const scope = {scope_js};
        const codeChallenge = {code_challenge_js};
        const codeChallengeMethod = {code_challenge_method_js};
        const oauthState = {oauth_state_js};
        const userPubkey = {user_pubkey_js};
        const userEmail = {user_email_js};
        const policyInfo = {policy_info_json};

        // Build permissions list from policy info
        function buildPermissionsList() {{
            const container = document.getElementById('permissions_list');

            // If we have policy permissions from the server, use them
            if (policyInfo.permissions && policyInfo.permissions.length > 0) {{
                policyInfo.permissions.forEach(perm => {{
                    const item = document.createElement('div');
                    item.className = 'permission_item';
                    item.innerHTML = `
                        <div class="permission_icon">${{perm.icon}}</div>
                        <div class="permission_content">
                            <h3>${{perm.title}}</h3>
                            <p>${{perm.description}}</p>
                        </div>
                    `;
                    container.appendChild(item);
                }});
            }} else {{
                // Fallback for policy not found - show generic permission
                const item = document.createElement('div');
                item.className = 'permission_item';
                item.innerHTML = `
                    <div class="permission_icon">🔐</div>
                    <div class="permission_content">
                        <h3>App Access</h3>
                        <p>Grant this application access to your account</p>
                    </div>
                `;
                container.appendChild(item);
            }}
        }}

        // Extract first letter for app icon
        function setAppIcon() {{
            const name = clientId.replace(/[-_]/g, ' ');
            const firstLetter = name.charAt(0).toUpperCase();
            document.getElementById('app_icon_letter').textContent = firstLetter;
        }}

        // Extract and display domain from redirect URI
        function setAppDomain() {{
            try {{
                const url = new URL(redirectUri);
                document.getElementById('app_domain').textContent = url.host;
            }} catch (e) {{
                // Invalid URL, hide domain
                document.getElementById('app_domain').style.display = 'none';
            }}
        }}

        function mediaNostrBandUrl(hexPubkey) {{
            const last4 = hexPubkey.slice(-4);
            return 'https://media.nostr.band/thumbs/' + last4 + '/' + hexPubkey + '-picture-64';
        }}

        function setIdentity(name, pictureUrl) {{
            if (name) {{
                document.getElementById('display_name').textContent = name;
            }}
            const avatar = document.getElementById('user_avatar');
            if (pictureUrl) {{
                avatar.src = pictureUrl;
                avatar.onerror = function() {{
                    // Try media.nostr.band as second attempt, then robohash
                    if (!this.dataset.triedMediaBand) {{
                        this.dataset.triedMediaBand = '1';
                        this.src = mediaNostrBandUrl(userPubkey);
                    }} else {{
                        this.onerror = null;
                        this.src = 'https://robohash.org/' + userPubkey + '?set=set4&size=48x48';
                    }}
                }};
            }}
        }}

        function getCachedProfile() {{
            try {{
                const raw = localStorage.getItem('nostr_profile_' + userPubkey);
                if (!raw) return null;
                const cached = JSON.parse(raw);
                const age = Date.now() - cached.fetched_at;
                cached._stale = age > 24 * 60 * 60 * 1000;
                return cached;
            }} catch (e) {{}}
            return null;
        }}

        function cacheProfile(profile) {{
            try {{
                localStorage.setItem('nostr_profile_' + userPubkey, JSON.stringify({{
                    name: profile.name || null,
                    display_name: profile.display_name || null,
                    picture: profile.picture || null,
                    fetched_at: Date.now()
                }}));
            }} catch (e) {{}}
        }}

        async function fetchProfile() {{
            const last4 = userPubkey.slice(-4);
            const url = 'https://media.nostr.band/thumbs/' + last4 + '/' + userPubkey + '.json';
            try {{
                const res = await fetch(url, {{ signal: AbortSignal.timeout(5000) }});
                if (!res.ok) return null;
                return await res.json();
            }} catch (e) {{
                console.warn('Could not load profile:', e);
            }}
            return null;
        }}

        async function loadProfile() {{
            console.log('Authorizing as:', document.getElementById('npub_fallback').textContent);

            // 1. Show cached profile immediately (even if stale)
            const cached = getCachedProfile();
            if (cached) {{
                const name = cached.display_name || cached.name;
                setIdentity(name || userEmail || 'your account', cached.picture);
                if (!cached._stale) return; // Fresh cache, no relay fetch needed
            }} else {{
                // No cache: show email + media.nostr.band avatar while fetching
                setIdentity(userEmail || 'your account', mediaNostrBandUrl(userPubkey));
            }}

            // 2. Background fetch (stale cache or no cache)
            const profile = await fetchProfile();
            if (profile) {{
                cacheProfile(profile);
                const displayName = profile.display_name || profile.name;
                if (displayName || profile.picture) {{
                    setIdentity(displayName || userEmail || 'your account', profile.picture);
                }}
            }} else if (!cached) {{
                // No relay result and no cache: store empty to avoid hammering relays
                cacheProfile({{}});
            }}
        }}

        // Initialize on page load
        window.addEventListener('load', () => {{
            buildPermissionsList();
            setAppIcon();
            setAppDomain();
            loadProfile();
        }});

        async function approve() {{
            try {{
                const response = await fetch('/api/oauth/authorize', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    credentials: 'include',
                    body: JSON.stringify({{
                        client_id: clientId,
                        redirect_uri: redirectUri,
                        scope: scope,
                        approved: true,
                        code_challenge: codeChallenge || undefined,
                        code_challenge_method: codeChallengeMethod || undefined
                    }})
                }});

                const data = await response.json();
                if (data.code) {{
                    let url = `${{redirectUri}}?code=${{data.code}}`;
                    if (oauthState) url += `&state=${{encodeURIComponent(oauthState)}}`;
                    window.location.href = url;
                }} else {{
                    alert('Error: ' + (data.error || 'Unknown error'));
                }}
            }} catch (e) {{
                alert('Request failed: ' + e.message);
            }}
        }}

        async function useDifferentAccount() {{
            await fetch('/api/auth/logout', {{
                method: 'POST',
                credentials: 'include',
            }});

            const url = new URL(window.location.href);
            url.searchParams.delete('screen');
            window.location.href = url.toString();
        }}

        function deny() {{
            let url = `${{redirectUri}}?error=access_denied`;
            if (oauthState) url += `&state=${{encodeURIComponent(oauthState)}}`;
            window.location.href = url;
        }}
    </script>
</body>
</html>
        "#,
                client_id_html = escape_html(&params.client_id),
                app_icon_letter = escape_html(
                    &params
                        .client_id
                        .chars()
                        .next()
                        .unwrap_or('A')
                        .to_uppercase()
                        .to_string()
                ),
                client_id_html2 = escape_html(&params.client_id),
                session_identity_html = escape_html(user_email.as_deref().unwrap_or(npub.as_str())),
                npub_html = escape_html(&npub),
                client_id_js = js_string_literal(&params.client_id),
                redirect_uri_js = js_string_literal(&params.redirect_uri),
                scope_js = js_string_literal(&scope_str),
                code_challenge_js =
                    js_string_literal(&params.code_challenge.as_deref().unwrap_or("")),
                code_challenge_method_js =
                    js_string_literal(&params.code_challenge_method.as_deref().unwrap_or("")),
                oauth_state_js = js_string_literal(&params.state.as_deref().unwrap_or("")),
                user_pubkey_js = js_string_literal(&pubkey),
                user_email_js = js_string_literal(&user_email.as_deref().unwrap_or("")),
                policy_info_json = policy_info_json, // already JSON-serialized
                brand = BRAND_NAME,
            )
        }
    } else {
        // User not authenticated - show login/register form (divine.video-inspired design)
        format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Sign in - {brand} Login</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Bricolage+Grotesque:wght@600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --divine-green: #27C58B;
            --divine-green-dark: #1AA575;
            --divine-green-light: #D0FBCB;
            --divine-purple: #8B5CF6;
            --bg: #F9F7F6;
            --surface: hsl(0 0% 100%);
            --border: hsl(214.3 31.8% 91.4%);
            --text: hsl(222.2 84% 4.9%);
            --text-secondary: hsl(215.4 16.3% 46.9%);
            --muted: hsl(210 40% 96.1%);
            --error: #EF4444;
            --shadow-sm: 0 2px 8px rgba(39, 197, 139, 0.08);
            --shadow-md: 0 4px 16px rgba(39, 197, 139, 0.12);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: #072218;
                --surface: #0F2E23;
                --border: #1C4033;
                --text: hsl(210 40% 98%);
                --text-secondary: hsl(215 20.2% 65.1%);
                --muted: #0F2E23;
            }}
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .logo {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 2px;
            margin-bottom: 1.5rem;
        }}
        .logo img {{
            height: 28px;
        }}
        .logo .logo-sub {{
            font-family: 'Inter', system-ui, sans-serif;
            font-weight: 500;
            font-size: 11px;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--divine-green);
            opacity: 0.6;
        }}
        .header h1 {{
            font-family: 'Bricolage Grotesque', system-ui, sans-serif;
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }}
        .header p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
        }}
        .app_header {{
            display: flex;
            align-items: center;
            gap: 0.875rem;
            padding-bottom: 1.25rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.25rem;
        }}
        .app_icon {{
            width: 44px;
            height: 44px;
            background: var(--divine-green);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            font-weight: 600;
            color: white;
            flex-shrink: 0;
        }}
        .app_info h2 {{
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.125rem;
        }}
        .app_domain {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
        }}
        .form_group {{
            margin-bottom: 1rem;
        }}
        label {{
            display: block;
            margin-bottom: 0.375rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }}
        input {{
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            background: var(--muted);
            color: var(--text);
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        input:focus {{
            outline: none;
            border-color: var(--divine-green);
            box-shadow: 0 0 0 2px rgba(39, 197, 139, 0.2);
        }}
        input::placeholder {{
            color: var(--text-secondary);
            opacity: 0.6;
        }}
        .password_input {{
            position: relative;
        }}
        .password_input input {{
            padding-right: 5.5rem;
        }}
        .password_toggle {{
            position: absolute;
            right: 0.5rem;
            top: 50%;
            transform: translateY(-50%);
            padding: 0.375rem 0.625rem;
            border: 1px solid var(--border);
            border-radius: 9999px;
            background: transparent;
            color: var(--divine-green);
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
        }}
        .password_toggle:hover {{
            background: rgba(39, 197, 139, 0.08);
        }}
        .btn_primary {{
            width: 100%;
            padding: 0.75rem 1.5rem;
            border-radius: 9999px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            background: var(--divine-green);
            color: white;
            margin-top: 0.5rem;
        }}
        .btn_primary:hover {{
            background: var(--divine-green-dark);
            box-shadow: var(--shadow-sm);
        }}
        .btn_primary:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .form_view {{
            display: none;
        }}
        .form_view.active {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(5px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .toggle_link {{
            text-align: center;
            margin-top: 1rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        .toggle_link a {{
            color: var(--divine-green);
            text-decoration: none;
            cursor: pointer;
            font-weight: 500;
        }}
        .toggle_link a:hover {{
            text-decoration: underline;
        }}
        .error {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--error);
            color: var(--error);
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            display: none;
            font-size: 0.875rem;
            text-align: center;
        }}
        .verification_notice {{
            text-align: center;
            padding: 2rem 1rem;
        }}
        .verification_icon {{
            color: var(--divine-green);
            margin-bottom: 1rem;
        }}
        .verification_notice h2 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.5rem;
        }}
        .verification_notice p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
            margin-bottom: 0.5rem;
        }}
        .verification_notice strong {{
            color: var(--text);
        }}
        .verification_subtext {{
            font-size: 0.8rem !important;
            color: var(--text-secondary);
        }}
        .advanced_section {{
            margin: 1rem 0;
        }}
        .advanced_toggle {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--divine-green);
            font-size: 0.875rem;
            cursor: pointer;
            text-decoration: none;
            user-select: none;
        }}
        .advanced_toggle:hover {{
            text-decoration: underline;
        }}
        .advanced_icon {{
            display: inline-block;
            transition: transform 0.2s;
            font-size: 0.65rem;
        }}
        .advanced_icon.expanded {{
            transform: rotate(90deg);
        }}
        .advanced_content {{
            display: none;
            margin-top: 0.75rem;
            padding: 1rem;
            background: var(--muted);
            border-radius: 0.75rem;
            border: 1px solid var(--border);
        }}
        .advanced_content.show {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}
        .help_text {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-top: 0.375rem;
            line-height: 1.4;
        }}
        /* Mobile: reduce padding for more working area */
        @media (max-width: 480px) {{
            body {{
                padding: 0.5rem;
            }}
            .header {{
                margin-bottom: 1rem;
            }}
            .header h1 {{
                font-size: 1.5rem;
            }}
            .card {{
                padding: 1rem;
                border-radius: 0.75rem;
            }}
            .app_header {{
                padding-bottom: 0.875rem;
                margin-bottom: 0.875rem;
            }}
            .logo {{
                margin-bottom: 1rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="/divine-logo.svg" alt="{brand}" />
                <span class="logo-sub">Login</span>
            </div>
            <h1>Sign in</h1>
            <p>to continue to <strong id="app_name_display">{client_id_html}</strong></p>
        </div>

        <div class="card">
            <div class="app_header">
                <div class="app_icon">
                    <span id="app_icon_letter">{app_icon_letter}</span>
                </div>
                <div class="app_info">
                    <div class="app_domain" id="app_domain"></div>
                    <h2 id="app_name">{client_id_html2}</h2>
                </div>
            </div>

            <div id="error" class="error"></div>

            <div id="verification_notice" class="verification_notice" style="display: none;">
                <div class="verification_icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
                        <path d="M224,48H32a8,8,0,0,0-8,8V192a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A8,8,0,0,0,224,48ZM203.43,64,128,133.15,52.57,64ZM216,192H40V74.19l82.59,75.71a8,8,0,0,0,10.82,0L216,74.19V192Z"></path>
                    </svg>
                </div>
                <h2>Check your email</h2>
                <p>We've sent a verification link to <strong id="verification_email"></strong></p>
                <p class="verification_subtext">Click the link in the email to verify your account and complete sign up. After verification, you'll be redirected back to the app.</p>
            </div>

            <div id="login_view" class="form_view">
                <form onsubmit="handleLogin(event)">
                    <div class="form_group">
                        <label for="login_email">Email</label>
                        <input type="email" id="login_email" placeholder="Enter your email" autocomplete="username" required>
                    </div>
                    <div class="form_group">
                        <label for="login_password">Password</label>
                        <div class="password_input">
                            <input type="password" id="login_password" placeholder="Enter your password" autocomplete="current-password" required>
                            {login_password_toggle}
                        </div>
                    </div>
                    <button type="submit" class="btn_primary">Sign in</button>
                </form>
                <div class="toggle_link">
                    <a href="/forgot-password">Forgot password?</a>
                </div>
                <div class="toggle_link">
                    Don't have an account? <a onclick="showForm('register')">Create one</a>
                </div>
            </div>

            <div id="register_view" class="form_view">
                <form onsubmit="handleRegister(event)">
                    <div class="form_group">
                        <label for="register_email">Email</label>
                        <input type="email" id="register_email" placeholder="Enter your email" autocomplete="username" required>
                    </div>
                    <div class="form_group">
                        <label for="register_password">Password</label>
                        <div class="password_input">
                            <input type="password" id="register_password" placeholder="Create a password" autocomplete="new-password" required minlength="8">
                            {register_password_toggle}
                        </div>
                    </div>
                    <div class="form_group">
                        <label for="register_password-confirm">Confirm Password</label>
                        <div class="password_input">
                            <input type="password" id="register_password-confirm" placeholder="Confirm your password" autocomplete="new-password" required minlength="8">
                            {register_confirmation_toggle}
                        </div>
                    </div>
                    <div class="advanced_section" id="advanced_section">
                        <a class="advanced_toggle" onclick="toggleAdvanced()">
                            <span class="advanced_icon" id="advanced_icon">▶</span>
                            Import existing Nostr key
                        </a>
                        <div id="advanced_content" class="advanced_content">
                            <div class="form_group" style="margin-bottom: 0;">
                                <label for="register_nsec">Nostr Secret Key</label>
                                <div class="password_input">
                                    <input type="password" id="register_nsec" placeholder="nsec1... or hex format" autocomplete="off">
                                    {register_nsec_toggle}
                                </div>
                                <p class="help_text">
                                    Optional: Import your existing Nostr identity. Leave empty to create a new one.
                                </p>
                            </div>
                        </div>
                    </div>
                    <button type="submit" class="btn_primary">Create account</button>
                </form>
                <div class="toggle_link">
                    Already have an account? <a onclick="showForm('login')">Sign in</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        const clientId = {client_id_js};
        const redirectUri = {redirect_uri_js};
        const scope = {scope_js};
        const codeChallenge = {code_challenge_js};
        const codeChallengeMethod = {code_challenge_method_js};
        const defaultRegister = new URLSearchParams(window.location.search).get('default_register') === 'true';
        const byokPubkey = new URLSearchParams(window.location.search).get('byok_pubkey');
        const state = new URLSearchParams(window.location.search).get('state');

        // Set app icon letter
        document.getElementById('app_icon_letter').textContent = clientId.charAt(0).toUpperCase();

        // Set app domain from redirect URI
        try {{
            const url = new URL(redirectUri);
            document.getElementById('app_domain').textContent = url.host;
        }} catch (e) {{
            document.getElementById('app_domain').style.display = 'none';
        }}

        function showForm(form) {{
            document.querySelectorAll('.form_view').forEach(v => v.classList.remove('active'));

            const headerTitle = document.querySelector('.header h1');
            if (form === 'login') {{
                document.getElementById('login_view').classList.add('active');
                if (headerTitle) headerTitle.textContent = 'Sign in';
                document.title = 'Sign in - {brand} Login';
            }} else {{
                document.getElementById('register_view').classList.add('active');
                if (headerTitle) headerTitle.textContent = 'Create account';
                document.title = 'Create account - {brand} Login';
            }}

            hideError();
        }}

        // Initialize form: show register if BYOK or explicitly requested
        if (defaultRegister || byokPubkey) {{
            showForm('register');
        }} else {{
            showForm('login');
        }}

        // Hide advanced nsec input if byok_pubkey is present (nsec will come via code_verifier)
        if (byokPubkey) {{
            const advancedSection = document.getElementById('advanced_section');
            if (advancedSection) {{
                advancedSection.style.display = 'none';
            }}
        }}

        function showError(message) {{
            const errorEl = document.getElementById('error');
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }}

        function hideError() {{
            document.getElementById('error').style.display = 'none';
        }}

        function togglePasswordVisibility(button) {{
            const input = document.getElementById(button.dataset.passwordTarget);
            if (!input) return;

            const showing = input.type === 'text';
            input.type = showing ? 'password' : 'text';
            const label = showing ? 'Show password' : 'Hide password';
            button.textContent = showing ? 'Show' : 'Hide';
            button.setAttribute('aria-label', label);
            button.setAttribute('title', label);
        }}

        function showVerificationNotice(email, deviceCode) {{
            // Hide forms and show verification notice
            document.getElementById('login_view').classList.remove('active');
            document.getElementById('register_view').classList.remove('active');
            hideError();

            const notice = document.getElementById('verification_notice');
            const emailSpan = document.getElementById('verification_email');
            if (emailSpan) emailSpan.textContent = email;
            notice.style.display = 'block';

            // Store device_code for polling (RFC 8628: secret, never in URL)
            // See: https://datatracker.ietf.org/doc/html/rfc8628
            if (deviceCode) {{
                sessionStorage.setItem('keycast_device_code', deviceCode);
            }}

            // Start polling for verification completion (multi-device support)
            startVerificationPolling();
        }}

        function startVerificationPolling() {{
            // RFC 8628: Use device_code (secret, from response body) not state (public, in URL)
            const deviceCode = sessionStorage.getItem('keycast_device_code');

            if (!deviceCode) {{
                console.log('No device_code, polling disabled');
                return;
            }}

            console.log('Starting verification polling');

            const pollInterval = setInterval(async () => {{
                try {{
                    const response = await fetch(`/api/oauth/poll?device_code=${{encodeURIComponent(deviceCode)}}`);

                    if (response.status === 200) {{
                        clearInterval(pollInterval);
                        sessionStorage.removeItem('keycast_device_code');
                        const data = await response.json();

                        // Redirect to app with code (state is for CSRF, include if available)
                        const urlParams = new URLSearchParams(window.location.search);
                        const state = urlParams.get('state');
                        let url = `${{redirectUri}}?code=${{encodeURIComponent(data.code)}}`;
                        if (state) url += `&state=${{encodeURIComponent(state)}}`;

                        // Chrome on Android doesn't trigger App Links for window.location.href
                        // Use intent:// URL format to force Chrome to check for App Links
                        // See: https://developer.chrome.com/docs/android/intents
                        const isAndroid = /Android/i.test(navigator.userAgent);
                        if (isAndroid && url.startsWith('https://')) {{
                            try {{
                                const parsed = new URL(url);
                                // Intent URL tells Chrome to try App Links first, fall back to browser
                                const intentUrl = `intent://${{parsed.host}}${{parsed.pathname}}${{parsed.search}}#Intent;scheme=https;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;end`;
                                window.location.href = intentUrl;
                            }} catch (e) {{
                                window.location.href = url;
                            }}
                        }} else {{
                            window.location.href = url;
                        }}
                    }} else if (response.status !== 202) {{
                        console.error('Poll error:', response.status);
                        // Don't clear interval on 500 - keep trying
                    }}
                }} catch (err) {{
                    console.error('Poll failed:', err);
                }}
            }}, 2000); // Poll every 2 seconds

            // Stop after 30 minutes
            setTimeout(() => {{
                clearInterval(pollInterval);
                sessionStorage.removeItem('keycast_device_code');
                console.log('Polling timed out');
            }}, 30 * 60 * 1000);
        }}

        function toggleAdvanced() {{
            const content = document.getElementById('advanced_content');
            const icon = document.getElementById('advanced_icon');
            content.classList.toggle('show');
            icon.classList.toggle('expanded');
        }}

        async function handleLogin(e) {{
            e.preventDefault();
            hideError();

            const email = document.getElementById('login_email').value;
            const password = document.getElementById('login_password').value;

            try {{
                const response = await fetch('/api/oauth/login', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    credentials: 'include',
                    body: JSON.stringify({{
                        email,
                        password,
                        client_id: clientId,
                        redirect_uri: redirectUri,
                        scope: scope,
                        code_challenge: codeChallenge || undefined,
                        code_challenge_method: codeChallengeMethod || undefined,
                        state: state || undefined
                    }})
                }});

                if (!response.ok) {{
                    const data = await response.json().catch(() => ({{}}));
                    // Check if email not verified
                    if (data.code === 'EMAIL_NOT_VERIFIED' || data.verification_required) {{
                        // No device_code for login flow - user needs to check email
                        showVerificationNotice(data.email || email, null);
                        return;
                    }}
                    showError(data.error || 'Login failed');
                    return;
                }}

                // Cookie is set, reload to show approval screen
                const url = new URL(window.location.href);
                url.searchParams.delete('prompt');
                url.searchParams.delete('byok_pubkey');
                url.searchParams.delete('default_register');
                window.location.href = url.toString();
            }} catch (e) {{
                showError('Request failed: ' + e.message);
            }}
        }}

        async function handleRegister(e) {{
            e.preventDefault();
            hideError();

            const email = document.getElementById('register_email').value;
            const password = document.getElementById('register_password').value;
            const passwordConfirm = document.getElementById('register_password-confirm').value;
            const nsecInput = document.getElementById('register_nsec').value.trim();

            if (password !== passwordConfirm) {{
                showError('Passwords do not match');
                return;
            }}

            let finalNsec = nsecInput || null;
            let finalPubkey = byokPubkey || null;

            try {{
                const response = await fetch('/api/oauth/register', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    credentials: 'include',
                    body: JSON.stringify({{
                        email,
                        password,
                        nsec: finalNsec || undefined,
                        pubkey: finalPubkey || undefined,
                        client_id: clientId,
                        redirect_uri: redirectUri,
                        scope: scope,
                        code_challenge: codeChallenge || undefined,
                        code_challenge_method: codeChallengeMethod || undefined,
                        state: state || undefined
                    }})
                }});

                const data = await response.json().catch(() => ({{}}));

                if (!response.ok) {{
                    showError(data.error || 'Registration failed');
                    return;
                }}

                // Check if email verification is required
                if (data.verification_required) {{
                    showVerificationNotice(data.email || email, data.device_code);
                    return;
                }}

                if (data.code) {{
                    // Include state in redirect if available
                    const state = new URLSearchParams(window.location.search).get('state');
                    if (state) {{
                        window.location.href = `${{redirectUri}}?code=${{data.code}}&state=${{encodeURIComponent(state)}}`;
                    }} else {{
                        window.location.href = `${{redirectUri}}?code=${{data.code}}`;
                    }}
                }} else {{
                    showError('Registration succeeded but no authorization code received');
                }}
            }} catch (e) {{
                showError('Request failed: ' + e.message);
            }}
        }}
    </script>
</body>
</html>
        "#,
            client_id_html = escape_html(&params.client_id),
            app_icon_letter = escape_html(
                &params
                    .client_id
                    .chars()
                    .next()
                    .unwrap_or('A')
                    .to_uppercase()
                    .to_string()
            ),
            client_id_html2 = escape_html(&params.client_id),
            client_id_js = js_string_literal(&params.client_id),
            redirect_uri_js = js_string_literal(&params.redirect_uri),
            scope_js = js_string_literal(&scope_str),
            code_challenge_js = js_string_literal(&params.code_challenge.as_deref().unwrap_or("")),
            code_challenge_method_js =
                js_string_literal(&params.code_challenge_method.as_deref().unwrap_or("")),
            login_password_toggle = password_visibility_toggle_html("login_password"),
            register_password_toggle = password_visibility_toggle_html("register_password"),
            register_confirmation_toggle =
                password_visibility_toggle_html("register_password-confirm"),
            register_nsec_toggle = password_visibility_toggle_html("register_nsec"),
            brand = BRAND_NAME,
        )
    };

    // If we detected a stale cookie, clear it
    if clear_cookie {
        let clear_cookie_header =
            "keycast_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
        Ok((
            [(axum::http::header::SET_COOKIE, clear_cookie_header)],
            Html(html),
        )
            .into_response())
    } else {
        Ok(Html(html).into_response())
    }
}

/// POST /oauth/authorize
/// User approves authorization, creates code and redirects back to app OR returns code directly
pub async fn authorize_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Response, OAuthError> {
    if !req.approved {
        return Ok(
            Redirect::to(&format!("{}?error=access_denied", req.redirect_uri)).into_response(),
        );
    }

    let tenant_id = tenant.0.id;

    // Extract user public key from UCAN cookie (async)
    let user_pubkey = if let Some(token) = super::auth::extract_ucan_from_cookie(&headers) {
        crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id)
            .await
            .ok()
            .map(|(pubkey, _, _, _)| pubkey)
    } else {
        None
    }
    .ok_or(OAuthError::Unauthorized)?;

    // Generate authorization code
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store authorization code (expires in 10 minutes)
    let expires_at = Utc::now() + Duration::minutes(10);

    // Store authorization code with PKCE support
    // No previous_auth_id since this is explicit user consent (first login or re-consent)
    store_oauth_code(
        &auth_state.state.db,
        tenant_id,
        &code,
        &user_pubkey,
        &req.client_id,
        &req.redirect_uri,
        &req.scope,
        req.code_challenge.as_deref(),
        req.code_challenge_method.as_deref(),
        expires_at,
        None,
        req.state.as_deref(),
    )
    .await?;

    // For JavaScript clients, return code directly instead of redirecting
    // Check if this is an XHR/fetch request by looking for Accept: application/json
    // For now, just return JSON with the code - client can handle it
    Ok(Json(serde_json::json!({
        "code": code,
        "redirect_uri": req.redirect_uri,
        "state": req.state
    }))
    .into_response())
}

/// POST /oauth/token
/// Exchange authorization code or refresh token for access tokens
/// This is the standard OAuth 2.0 token endpoint for third-party apps
/// Supports: authorization_code (default), refresh_token
pub async fn token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<TokenRequest>,
) -> Result<Response, OAuthError> {
    let tenant_id = tenant.0.id;
    let grant_type = req.grant_type.as_deref().unwrap_or("authorization_code");

    match grant_type {
        "authorization_code" => handle_authorization_code_grant(tenant_id, auth_state, req).await,
        "refresh_token" => handle_refresh_token_grant(tenant_id, auth_state, req).await,
        _ => Err(OAuthError::InvalidRequest(format!(
            "Invalid grant_type '{}'. Supported: authorization_code, refresh_token.",
            grant_type
        ))),
    }
}

/// Handle refresh token grant (RFC 6749 §6)
/// Exchanges a valid refresh token for new access token and rotated refresh token
async fn handle_refresh_token_grant(
    tenant_id: i64,
    auth_state: super::routes::AuthState,
    req: TokenRequest,
) -> Result<Response, OAuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Extract required refresh_token parameter
    let refresh_token = req.refresh_token.as_ref().ok_or_else(|| {
        OAuthError::InvalidRequest(
            "Missing 'refresh_token' parameter for refresh_token grant".into(),
        )
    })?;

    // Consume refresh token atomically (validates + marks as consumed)
    // This implements one-time use per RFC 9700 token rotation
    let refresh_token_repo = RefreshTokenRepository::new(pool.clone());
    let token_record = refresh_token_repo
        .consume(refresh_token)
        .await?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired refresh token".into()))?;

    // Get the OAuth authorization (verify not revoked)
    let oauth_auth = keycast_core::types::oauth_authorization::OAuthAuthorization::find(
        pool,
        tenant_id,
        token_record.authorization_id,
    )
    .await
    .map_err(|e| OAuthError::InvalidGrant(format!("Authorization not found: {}", e)))?;

    if oauth_auth.revoked_at.is_some() {
        return Err(OAuthError::InvalidGrant(
            "Authorization has been revoked".into(),
        ));
    }

    // Get user email and account status for UCAN generation
    let user_repo = UserRepository::new(pool.clone());
    let email = user_repo
        .get_email(&oauth_auth.user_pubkey, tenant_id)
        .await
        .unwrap_or_default();
    let user_status = user_repo
        .get_user_status(&oauth_auth.user_pubkey, tenant_id)
        .await
        .ok()
        .flatten()
        .map(|(s, _, _)| s);

    // Get user's encrypted keys for bunker key derivation (tenant-scoped)
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_user_key = personal_keys_repo
        .find_encrypted_key_for_tenant(&oauth_auth.user_pubkey, tenant_id)
        .await?
        .ok_or_else(|| OAuthError::InvalidGrant("User keys not found".into()))?;

    // Decrypt user key for bunker derivation
    let decrypted_user_secret = key_manager
        .decrypt(&encrypted_user_key)
        .await
        .map_err(|e| OAuthError::Encryption(format!("Failed to decrypt user key: {}", e)))?;
    let user_secret_key = nostr_sdk::SecretKey::from_slice(&decrypted_user_secret)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid secret key: {}", e)))?;

    // Re-derive bunker keys using the stored secret_hash (deterministic)
    let bunker_keys =
        keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &oauth_auth.secret_hash);
    let bunker_public_key = bunker_keys.public_key();

    // Generate new UCAN access token (server-signed)
    // Note: refresh tokens don't preserve first_party status - users need fresh headless login
    let access_token = super::auth::generate_server_signed_ucan(
        &nostr_sdk::PublicKey::from_hex(&oauth_auth.user_pubkey)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?,
        tenant_id,
        &email,
        &oauth_auth.redirect_origin,
        Some(&bunker_public_key.to_hex()),
        &auth_state.state.server_keys,
        false, // Refresh tokens are not first-party
        None,
        user_status.as_ref(),
    )
    .await
    .map_err(|e| OAuthError::InvalidRequest(format!("UCAN generation failed: {:?}", e)))?;

    // Generate new refresh token (rotation per RFC 9700)
    let new_refresh_token = generate_refresh_token();
    refresh_token_repo
        .create(&new_refresh_token, oauth_auth.id, tenant_id)
        .await?;

    tracing::info!(
        "Refreshed token for user {} authorization {}",
        oauth_auth.user_pubkey,
        oauth_auth.id
    );

    // Build bunker URL (same as initial issuance)
    let relays = keycast_core::types::authorization::Authorization::get_bunker_relays();
    let relay_params: String = relays
        .iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect::<Vec<_>>()
        .join("&");

    // Get connection secret from the stored hash (for bunker URL reconstruction)
    // Note: We can't recover the original secret, but client already has it
    // The bunker_url in refresh response uses the same bunker pubkey
    let bunker_url = format!("bunker://{}?{}", bunker_public_key.to_hex(), relay_params,);

    // Load policy info for response
    let policy_info = if let Some(policy_id) = oauth_auth.policy_id {
        let policy_repo = PolicyRepository::new(pool.clone());
        match policy_repo.find(policy_id).await {
            Ok(policy) => {
                let permissions = policy.permission_displays(pool).await.unwrap_or_default();
                Some(TokenPolicyInfo {
                    slug: policy.slug.clone().unwrap_or_else(|| policy.id.to_string()),
                    display_name: policy
                        .display_name
                        .clone()
                        .unwrap_or_else(|| policy.name.clone()),
                    description: policy.description.clone().unwrap_or_default(),
                    permissions,
                })
            }
            _ => None,
        }
    } else {
        None
    };

    // Parse scope from policy for response
    let scope = if let Some(ref info) = policy_info {
        format!("policy:{}", info.slug)
    } else {
        "policy:full".to_string()
    };

    Ok(Json(TokenResponse {
        bunker_url,
        access_token: Some(access_token),
        token_type: "Bearer".to_string(),
        expires_in: token_expiry_seconds(),
        scope: Some(scope),
        policy: policy_info,
        authorization_handle: oauth_auth.authorization_handle,
        refresh_token: Some(new_refresh_token),
    })
    .into_response())
}

/// Handle authorization code grant (standard OAuth flow)
async fn handle_authorization_code_grant(
    tenant_id: i64,
    auth_state: super::routes::AuthState,
    req: TokenRequest,
) -> Result<Response, OAuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Extract required fields for authorization_code grant
    let code = req.code.as_ref().ok_or_else(|| {
        OAuthError::InvalidRequest("Missing 'code' parameter for authorization_code grant".into())
    })?;
    let redirect_uri = req.redirect_uri.as_ref().ok_or_else(|| {
        OAuthError::InvalidRequest(
            "Missing 'redirect_uri' parameter for authorization_code grant".into(),
        )
    })?;

    // Fetch and validate authorization code with PKCE fields AND pending registration data
    let oauth_code_repo = OAuthCodeRepository::new(pool.clone());
    let auth_code = oauth_code_repo
        .find_valid(tenant_id, code)
        .await?
        .ok_or(OAuthError::Unauthorized)?;

    let user_pubkey = auth_code.user_pubkey;
    let client_id = auth_code.client_id;
    let stored_redirect_uri = auth_code.redirect_uri;
    let scope = auth_code.scope;
    let code_challenge = auth_code.code_challenge;
    let code_challenge_method = auth_code.code_challenge_method;
    let pending_email = auth_code.pending_email;
    let pending_password_hash = auth_code.pending_password_hash;
    let pending_email_verification_token = auth_code.pending_email_verification_token;
    let pending_encrypted_secret = auth_code.pending_encrypted_secret;
    let previous_auth_id = auth_code.previous_auth_id;
    let is_headless = auth_code.is_headless;

    // Validate redirect_uri matches
    if stored_redirect_uri != *redirect_uri {
        return Err(OAuthError::InvalidRequest(
            "redirect_uri mismatch".to_string(),
        ));
    }

    // PKCE validation (if code_challenge was provided during authorization)
    if let Some(challenge) = code_challenge {
        let method = code_challenge_method.as_deref().unwrap_or("plain");
        let verifier = req.code_verifier.as_ref().ok_or_else(|| {
            OAuthError::InvalidRequest("code_verifier required for PKCE flow".to_string())
        })?;

        validate_pkce(verifier, &challenge, method)?;
        tracing::debug!("PKCE validation successful for code: {}", &code[..8]);
    }

    // Extract optional nsec from code_verifier (for BYOK flow)
    let nsec_from_verifier = req
        .code_verifier
        .as_ref()
        .and_then(|v| extract_nsec_from_verifier_public(v));

    // Check if this is a registration flow (has pending_email)
    let email = if let Some(ref pending_email_val) = pending_email {
        // This is a registration - create user + keys atomically
        tracing::info!(
            "Token exchange completing deferred registration for email: {}",
            pending_email_val
        );

        // Re-check email uniqueness (handle race condition)
        let user_repo = UserRepository::new(pool.clone());
        if user_repo
            .find_pubkey_by_email(pending_email_val, tenant_id)
            .await?
            .is_some()
        {
            return Err(OAuthError::InvalidRequest(
                "This email is already registered. Please sign in instead.".to_string(),
            ));
        }

        // Re-check pubkey uniqueness (handle race condition)
        if user_repo.exists(&user_pubkey, tenant_id).await? {
            return Err(OAuthError::InvalidRequest(
                "This Nostr key is already registered.".to_string(),
            ));
        }

        // Get encrypted secret (from oauth_codes for auto-generate, or encrypt now for BYOK)
        let encrypted_secret: Vec<u8> = if let Some(stored_secret) = pending_encrypted_secret {
            // Auto-generate flow: secret was encrypted at registration, just copy it
            tracing::info!(
                "Using pre-encrypted secret from oauth_codes ({} bytes)",
                stored_secret.len()
            );
            stored_secret
        } else {
            // BYOK flow: nsec comes via code_verifier, encrypt now
            let nsec_str = nsec_from_verifier.as_ref().ok_or_else(|| {
                OAuthError::InvalidRequest(
                    "Missing nsec in code_verifier for BYOK flow".to_string(),
                )
            })?;
            let keys = Keys::parse(nsec_str).map_err(|e| {
                OAuthError::InvalidRequest(format!("Invalid nsec in code_verifier: {}", e))
            })?;
            if keys.public_key().to_hex() != user_pubkey {
                return Err(OAuthError::InvalidRequest(
                    "nsec doesn't match pubkey from registration".to_string(),
                ));
            }
            let secret_bytes = keys.secret_key().to_secret_bytes();
            key_manager
                .encrypt(&secret_bytes)
                .await
                .map_err(|e| OAuthError::Encryption(e.to_string()))?
        };

        let pending_password_hash_val = pending_password_hash.ok_or_else(|| {
            OAuthError::InvalidRequest("Missing password hash in pending registration".to_string())
        })?;
        let verification_token = pending_email_verification_token.ok_or_else(|| {
            OAuthError::InvalidRequest(
                "Missing verification token in pending registration".to_string(),
            )
        })?;

        // Finalize pending registration atomically (user + personal_keys + delete code)
        let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);
        let user_repo = UserRepository::new(pool.clone());
        user_repo
            .finalize_oauth_registration(
                &user_pubkey,
                tenant_id,
                pending_email_val,
                &pending_password_hash_val,
                &verification_token,
                verification_expires,
                &encrypted_secret,
                code,
            )
            .await
            .map_err(|e| OAuthError::Database(sqlx::Error::Protocol(e.to_string())))?;

        tracing::info!(
            "Created user + personal_keys atomically for: {} (email: {})",
            user_pubkey,
            pending_email_val
        );

        // Send verification email (optional - don't fail if email service unavailable)
        match crate::email_service::EmailService::new() {
            Ok(email_service) => {
                if let Err(e) = email_service
                    .send_verification_email(pending_email_val, &verification_token)
                    .await
                {
                    tracing::error!(
                        "Failed to send verification email to {}: {}",
                        pending_email_val,
                        e
                    );
                } else {
                    tracing::info!("Sent verification email to {}", pending_email_val);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Email service unavailable, skipping verification email: {}",
                    e
                );
            }
        }

        pending_email_val.clone()
    } else {
        // Normal token exchange (existing user, not registration)
        // Delete the authorization code (one-time use)
        oauth_code_repo.delete(tenant_id, code).await?;

        // Get user's email for UCAN
        let user_repo = UserRepository::new(pool.clone());
        user_repo.get_email(&user_pubkey, tenant_id).await?
    };

    tracing::info!(
        "Token exchange for user {}: has code_verifier: {}, has nsec in verifier: {}",
        user_pubkey,
        req.code_verifier.is_some(),
        nsec_from_verifier.is_some()
    );

    // Create OAuth authorization and generate token response
    create_oauth_authorization_and_token(
        CreateAuthorizationParams {
            tenant_id,
            user_pubkey: &user_pubkey,
            email: &email,
            client_id: &client_id,
            scope: &scope,
            redirect_uri: &stored_redirect_uri,
            nsec_from_verifier,
            previous_auth_id,
            is_headless,
        },
        auth_state,
    )
    .await
}

// handle_password_grant() removed - ROPC grant type deprecated and removed

/// Parameters for creating OAuth authorization and generating token
struct CreateAuthorizationParams<'a> {
    tenant_id: i64,
    user_pubkey: &'a str,
    email: &'a str,
    client_id: &'a str,
    scope: &'a str,
    redirect_uri: &'a str,
    nsec_from_verifier: Option<String>,
    previous_auth_id: Option<i32>,
    /// Whether this code was issued via headless flow (for first_party UCAN fact)
    is_headless: bool,
}

/// Common function to create OAuth authorization and generate TokenResponse
/// Creates personal_keys if missing (first token exchange with optional nsec from code_verifier)
#[allow(clippy::too_many_arguments)]
async fn create_oauth_authorization_and_token(
    params: CreateAuthorizationParams<'_>,
    auth_state: super::routes::AuthState,
) -> Result<Response, OAuthError> {
    let CreateAuthorizationParams {
        tenant_id,
        user_pubkey,
        email,
        client_id,
        scope,
        redirect_uri,
        nsec_from_verifier,
        previous_auth_id,
        is_headless,
    } = params;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Check if personal_keys exist (tenant-scoped)
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_user_key: Option<Vec<u8>> = personal_keys_repo
        .find_encrypted_key_for_tenant(user_pubkey, tenant_id)
        .await?;

    let (encrypted_user_key, _keys_just_created) = if let Some(existing_key) = encrypted_user_key {
        // Keys already exist
        if nsec_from_verifier.is_some() {
            tracing::warn!(
                "User {} already has personal_keys, ignoring nsec from code_verifier",
                user_pubkey
            );
        }
        (existing_key, false)
    } else {
        // Create personal_keys from code_verifier nsec or auto-generate
        tracing::info!(
            "Creating personal_keys for user {} during token exchange",
            user_pubkey
        );

        let keys = if let Some(nsec_str) = nsec_from_verifier {
            tracing::info!("Using nsec from code_verifier (BYOK)");
            let keys = Keys::parse(&nsec_str).map_err(|e| {
                OAuthError::InvalidRequest(format!("Invalid nsec in code_verifier: {}", e))
            })?;

            // Verify nsec matches user's registered pubkey
            if keys.public_key().to_hex() != user_pubkey {
                return Err(OAuthError::InvalidRequest(format!(
                    "nsec in code_verifier doesn't match registered pubkey. Expected: {}, got: {}",
                    user_pubkey,
                    keys.public_key().to_hex()
                )));
            }

            keys
        } else {
            // No nsec provided - check if user expects BYOK (has no keys) or auto-generate
            // If user was registered without keys, they MUST provide nsec
            tracing::error!(
                "User {} has no personal_keys but no nsec in code_verifier",
                user_pubkey
            );
            return Err(OAuthError::InvalidRequest(
                "Missing nsec in code_verifier. BYOK flow requires nsec to be embedded."
                    .to_string(),
            ));
        };

        // Store secret key as raw bytes (32 bytes) - matches regular registration
        let secret_bytes = keys.secret_key().to_secret_bytes();

        let encrypted_secret = key_manager
            .encrypt(&secret_bytes)
            .await
            .map_err(|e| OAuthError::Encryption(e.to_string()))?;

        // Insert personal_keys (must include tenant_id for multi-tenant isolation)
        personal_keys_repo
            .create(user_pubkey, &encrypted_secret, tenant_id)
            .await?;

        (encrypted_secret, true)
    };

    // Extract origin from redirect_uri - this is the primary identifier
    let redirect_origin = extract_origin(redirect_uri)?;

    // Get pre-computed (secret, hash) from pool - instant, no waiting for bcrypt
    let secret_pair = auth_state
        .state
        .secret_pool
        .get()
        .await
        .ok_or_else(|| OAuthError::ServerError("Secret pool exhausted".to_string()))?;
    let connection_secret = secret_pair.secret;
    let secret_hash = secret_pair.hash;

    // Derive bunker keys from user secret using HKDF with secret_hash as entropy
    // (privacy: bunker_pubkey ≠ user_pubkey, zero extra KMS calls at runtime)
    let decrypted_user_secret = key_manager
        .decrypt(&encrypted_user_key)
        .await
        .map_err(|e| OAuthError::Encryption(format!("Failed to decrypt user key: {}", e)))?;
    let user_secret_key = nostr_sdk::SecretKey::from_slice(&decrypted_user_secret)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid secret key: {}", e)))?;

    // Use secret_hash as HKDF entropy - can be re-derived at runtime without KMS
    let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &secret_hash);
    let bunker_public_key = bunker_keys.public_key();

    // Fetch account status for UCAN fact
    let code_exchange_user_status = {
        let user_repo = UserRepository::new(pool.clone());
        user_repo
            .get_user_status(user_pubkey, tenant_id)
            .await
            .ok()
            .flatten()
            .map(|(s, _, _)| s)
    };

    // Generate server-signed UCAN for REST RPC API access (after bunker key derivation)
    // is_headless enables first_party fact for account deletion authorization
    let access_token = super::auth::generate_server_signed_ucan(
        &nostr_sdk::PublicKey::from_hex(user_pubkey)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?,
        tenant_id,
        email,
        &redirect_origin,
        Some(&bunker_public_key.to_hex()),
        &auth_state.state.server_keys,
        is_headless, // first_party fact for headless flow tokens
        None,
        code_exchange_user_status.as_ref(),
    )
    .await
    .map_err(|e| OAuthError::InvalidRequest(format!("UCAN generation failed: {:?}", e)))?;

    // Create authorization in database - use relay that supports NIP-46
    let relay_url = "wss://relay.damus.io";
    let relays_json = serde_json::to_string(&vec![relay_url])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    // Resolve policy from scope (policy:slug format)
    let policy_id = resolve_policy_from_scope(pool, scope).await?;

    // Generate authorization handle for silent re-authentication
    let authorization_handle = generate_authorization_handle();

    // Handle absolute expiration (30 days from creation - hard ceiling for silent re-auth)
    let handle_expires_at = Utc::now() + Duration::days(30);

    // Create new OAuth authorization - always INSERT (multi-device support)
    // Each authorization is a separate "ticket" for one client/device
    // Old authorizations remain valid until explicitly revoked
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let auth_id = oauth_auth_repo
        .create(CreateOAuthAuthorizationParams {
            tenant_id,
            user_pubkey: user_pubkey.to_string(),
            redirect_origin: redirect_origin.clone(),
            client_id: client_id.to_string(),
            bunker_public_key: bunker_public_key.to_hex(),
            secret_hash,
            relays: relays_json.clone(),
            policy_id: Some(policy_id),
            client_pubkey: None,
            authorization_handle: Some(authorization_handle.clone()),
            handle_expires_at,
        })
        .await?;

    tracing::info!(
        "Created OAuth authorization {} for user {} app {}",
        auth_id,
        user_pubkey,
        redirect_origin
    );

    // Generate and store refresh token for silent token renewal (RFC 6749 §6)
    let refresh_token = generate_refresh_token();
    let refresh_token_repo = RefreshTokenRepository::new(pool.clone());
    refresh_token_repo
        .create(&refresh_token, auth_id, tenant_id)
        .await?;

    tracing::debug!("Created refresh token for authorization {}", auth_id);

    // Track OAuth authorization created
    METRICS.inc_oauth_created();

    // Revoke old authorization if this was a re-auth (cleanup)
    if let Some(old_auth_id) = previous_auth_id {
        // Revoke all refresh tokens for the old authorization
        let old_refresh_repo = RefreshTokenRepository::new(pool.clone());
        let revoked_count = old_refresh_repo
            .revoke_for_authorization(old_auth_id)
            .await?;
        if revoked_count > 0 {
            tracing::debug!(
                "Revoked {} refresh tokens for old authorization {}",
                revoked_count,
                old_auth_id
            );
        }

        oauth_auth_repo.revoke(old_auth_id).await?;
        METRICS.inc_oauth_revoked();
        tracing::info!(
            "Revoked old authorization {} after re-auth (signer will detect on next poll)",
            old_auth_id
        );
    }

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

    // Build bunker URL with deployment-wide relay list
    let relays = keycast_core::types::authorization::Authorization::get_bunker_relays();
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

    // Load policy info from scope for response (policies are now global)
    let policy_info = {
        // Parse policy slug from scope (e.g., "policy:social" -> "social")
        let policy_slug = parse_policy_scope(scope).unwrap_or_else(|_| "social".to_string());

        let policy_repo = PolicyRepository::new(pool.clone());
        match policy_repo.find_by_slug(&policy_slug).await {
            Ok(policy) => {
                let permissions = policy.permission_displays(pool).await.unwrap_or_default();
                Some(TokenPolicyInfo {
                    slug: policy.slug.clone().unwrap_or_else(|| policy.id.to_string()),
                    display_name: policy
                        .display_name
                        .clone()
                        .unwrap_or_else(|| policy.name.clone()),
                    description: policy.description.clone().unwrap_or_default(),
                    permissions,
                })
            }
            Err(_) => {
                tracing::warn!("Policy '{}' not found for token response", policy_slug);
                None
            }
        }
    };

    // Return bunker URL with access_token for REST RPC API
    Ok(Json(TokenResponse {
        bunker_url,
        access_token: Some(access_token),
        token_type: "Bearer".to_string(),
        expires_in: token_expiry_seconds(), // UCAN expiry in seconds
        scope: Some(scope.to_string()),
        policy: policy_info,
        authorization_handle: Some(authorization_handle),
        refresh_token: Some(refresh_token),
    })
    .into_response())
}

// ============================================================================
// OAuth Popup Login/Register Handlers (return approval HTML directly)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct OAuthLoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// POST /oauth/login
/// Login endpoint for OAuth popup - sets UCAN cookie and returns success
/// Page will reload to show approval screen
pub async fn oauth_login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(mut req): Json<OAuthLoginRequest>,
) -> Result<impl IntoResponse, OAuthError> {
    use super::auth::generate_ucan_token;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;
    let endpoint = "/api/oauth/login";

    req.email = req.email.to_lowercase();

    tracing::info!(
        "OAuth popup login for email: {} in tenant: {}",
        req.email,
        tenant_id
    );

    // Validate credentials
    let user_repo = UserRepository::new(pool.clone());
    let (public_key, password_hash, email_verified, user_status) =
        match user_repo.find_with_password(&req.email, tenant_id).await? {
            Some(user) => user,
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
                        redirect_origin: None,
                        metadata_json: serde_json::json!({}),
                    },
                )
                .await;
                return Err(OAuthError::Unauthorized);
            }
        };

    // Verify password (spawn_blocking to avoid blocking async runtime)
    let password = req.password.clone();
    let hash = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify(&password, &hash))
        .await
        .map_err(|e| OAuthError::InvalidRequest(format!("Task join error: {}", e)))?
        .map_err(|_| OAuthError::InvalidRequest("Password verification failed".to_string()))?;

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
                redirect_origin: None,
                metadata_json: serde_json::json!({}),
            },
        )
        .await;
        return Err(OAuthError::Unauthorized);
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
                http_status: 400,
                email: Some(&req.email),
                pubkey: Some(&public_key),
                client_id: Some(&req.client_id),
                redirect_origin: None,
                metadata_json: serde_json::json!({}),
            },
        )
        .await;
        tracing::warn!("OAuth login failed: email not verified for {}", req.email);
        return Err(OAuthError::InvalidRequest(
            "Please verify your email address before signing in. Check your inbox for the verification link.".to_string(),
        ));
    }

    // Get user's keys for UCAN generation (tenant-scoped)
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret = personal_keys_repo
        .find_encrypted_key_for_tenant(&public_key, tenant_id)
        .await?
        .ok_or_else(|| {
            tracing::warn!("User {} has no personal_keys - they registered via OAuth but haven't completed token exchange yet", public_key);
            OAuthError::InvalidRequest("Account setup incomplete. Please complete the OAuth flow to finalize your account.".to_string())
        })?;

    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| OAuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Extract redirect_origin from redirect_uri for UCAN
    let redirect_origin = match extract_origin(&req.redirect_uri) {
        Ok(origin) => origin,
        Err(error) => {
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
                    pubkey: Some(&public_key),
                    client_id: Some(&req.client_id),
                    redirect_origin: None,
                    metadata_json: serde_json::json!({
                        "error": format!("{:?}", error),
                    }),
                },
            )
            .await;
            return Err(error);
        }
    };

    // Generate UCAN token with redirect_origin and account status
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
    .await
    .map_err(|e| OAuthError::InvalidRequest(format!("UCAN generation failed: {:?}", e)))?;

    // OAuth popup login: bunker authorization will be created manually by user if needed

    tracing::info!("OAuth popup login successful for user: {}", public_key);

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

    // Set cookie and return success - page will reload to show approval
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "success": true,
            "pubkey": public_key
        })),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct OAuthRegisterRequest {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub pubkey: Option<String>, // Optional: for BYOK flow (hex), nsec will come in code_verifier
    pub nsec: Option<String>, // Optional: direct nsec input (nsec1... or hex), creates keys immediately
    pub relays: Option<Vec<String>>, // Optional: preferred relays
    pub state: Option<String>, // Optional: for iOS PWA polling pattern
}

/// POST /oauth/register
/// Registration endpoint for OAuth popup - sets UCAN cookie and returns success
/// Page will reload to show approval screen
pub async fn oauth_register(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(mut req): Json<OAuthRegisterRequest>,
) -> Result<impl IntoResponse, OAuthError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    req.email = normalize_registration_email(&req.email).map_err(|_| OAuthError::InvalidEmail)?;

    tracing::info!(
        "OAuth popup registration for email: {} in tenant: {}, nsec: {}, pubkey: {}, client_id: {}",
        req.email,
        tenant_id,
        req.nsec.is_some(),
        req.pubkey.as_deref().unwrap_or("none"),
        req.client_id
    );

    // Check if email already exists
    let user_repo = UserRepository::new(pool.clone());
    if user_repo
        .find_pubkey_by_email(&req.email, tenant_id)
        .await?
        .is_some()
    {
        return Err(OAuthError::InvalidRequest(
            "Email already registered".to_string(),
        ));
    }

    // Hash password (spawn_blocking to avoid blocking async runtime)
    let password = req.password.clone();
    let password_hash =
        tokio::task::spawn_blocking(move || bcrypt::hash(&password, bcrypt::DEFAULT_COST))
            .await
            .map_err(|e| OAuthError::InvalidRequest(format!("Task join error: {}", e)))?
            .map_err(|_| OAuthError::InvalidRequest("Password hashing failed".to_string()))?;

    // Priority: nsec (direct input) → pubkey (BYOK via code_verifier) → auto-generate
    let (public_key, generated_keys) = if let Some(ref nsec_str) = req.nsec {
        // Direct nsec input: parse nsec and create keys immediately
        let keys = Keys::parse(nsec_str)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid nsec: {}", e)))?;
        let pubkey = keys.public_key();
        tracing::info!(
            "OAuth registration with direct nsec input for pubkey: {}",
            pubkey.to_hex()
        );
        (pubkey, Some(keys)) // Keys provided by user
    } else if let Some(ref pubkey_hex) = req.pubkey {
        // BYOK flow: client provides pubkey, nsec will come in code_verifier
        let pubkey = nostr_sdk::PublicKey::from_hex(pubkey_hex)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid pubkey: {}", e)))?;
        tracing::info!(
            "OAuth registration BYOK flow for pubkey: {}",
            pubkey.to_hex()
        );
        (pubkey, None) // No keys generated, wait for token exchange
    } else {
        // Auto-generate flow: server generates keys immediately
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        tracing::info!(
            "OAuth registration auto-generate flow for email: {}",
            req.email
        );
        (pubkey, Some(keys)) // Keys generated now
    };

    // Check if user with this pubkey already exists
    if user_repo.exists(&public_key.to_hex(), tenant_id).await? {
        return Err(OAuthError::InvalidRequest(
            "This Nostr key is already registered. Please sign in instead.".to_string(),
        ));
    }

    // Check if email is already taken
    if user_repo
        .find_pubkey_by_email(&req.email, tenant_id)
        .await?
        .is_some()
    {
        return Err(OAuthError::InvalidRequest(
            "This email is already registered. Please sign in instead.".to_string(),
        ));
    }

    // Generate email verification token (will be stored in oauth_codes for later use)
    let verification_token = generate_secure_token();

    // For auto-generate or direct-nsec: encrypt secret now and store in oauth_codes
    // For BYOK: secret comes later via code_verifier at token exchange
    let pending_encrypted_secret: Option<Vec<u8>> = if let Some(ref keys) = generated_keys {
        let secret_bytes = keys.secret_key().to_secret_bytes();
        let encrypted = auth_state
            .state
            .key_manager
            .encrypt(&secret_bytes)
            .await
            .map_err(|e| OAuthError::Encryption(e.to_string()))?;
        tracing::info!(
            "Encrypted secret for deferred registration: {} ({} bytes)",
            public_key.to_hex(),
            encrypted.len()
        );
        Some(encrypted)
    } else {
        tracing::info!(
            "BYOK flow - nsec will come via code_verifier at token exchange: {}",
            public_key.to_hex()
        );
        None
    };

    // DO NOT create users row here - defer to token exchange
    // DO NOT create personal_keys row here - defer to token exchange
    // DO NOT send verification email here - defer to token exchange

    // Generate authorization code (will be used after email verification)
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Generate RFC 8628-style device_code for secure polling
    // Unlike 'state' (visible in URL), device_code is only returned in response body
    // This prevents polling credential leakage via referrer headers, logs, or browser history
    // See: https://datatracker.ietf.org/doc/html/rfc8628
    let device_code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Use 24-hour expiry for pending registrations (matches email verification expiry)
    let expires_at = Utc::now() + Duration::hours(24);

    // Store authorization code with pending registration data (including state for redirect after verification)
    // User + personal_keys will be created atomically when email is verified
    let scope = req.scope.as_deref().unwrap_or("sign_event");
    store_oauth_code_with_pending_registration(
        pool,
        tenant_id,
        &code,
        &public_key.to_hex(),
        &req.client_id,
        &req.redirect_uri,
        scope,
        req.code_challenge.as_deref(),
        req.code_challenge_method.as_deref(),
        expires_at,
        &req.email,
        &password_hash,
        &verification_token,
        pending_encrypted_secret.as_deref(),
        req.state.as_deref(),
        Some(&device_code),
    )
    .await?;

    tracing::info!(
        "OAuth registration pending email verification: user {}, email {}",
        public_key.to_hex(),
        req.email
    );

    // Send verification email (required - user must verify before OAuth flow completes)
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

    // DO NOT issue UCAN or set session cookie - user must verify email first
    // Return verification_required response so frontend shows "check your email" message
    // device_code is RFC 8628 polling credential - only returned here, never in URLs
    Ok(Json(serde_json::json!({
        "verification_required": true,
        "email": req.email,
        "pubkey": public_key.to_hex(),
        "device_code": device_code
    }))
    .into_response())
}

// generate_auto_approve_html_with_cookie() and generate_approval_page_html() removed
// Now using reload pattern - /oauth/authorize GET renders these directly

// ============================================================================
// nostr-login Integration Handlers
// ============================================================================

/// Nostr Connect parameters from nostrconnect:// URI
#[derive(Debug, Deserialize)]
pub struct NostrConnectParams {
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
    pub image: Option<String>,
}

/// Form data for connect approval
#[derive(Debug, Deserialize)]
pub struct ConnectApprovalForm {
    pub client_pubkey: String,
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub approved: bool,
}

/// Parse nostrconnect:// URI from path
/// Format: nostrconnect://CLIENT_PUBKEY?relay=RELAY&secret=SECRET&perms=...
fn parse_nostrconnect_uri(uri: &str) -> Result<(String, NostrConnectParams), OAuthError> {
    // Remove nostrconnect:// prefix
    let uri = uri
        .strip_prefix("nostrconnect://")
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid nostrconnect URI".to_string()))?;

    // Split pubkey and query params
    let parts: Vec<&str> = uri.split('?').collect();
    if parts.len() != 2 {
        return Err(OAuthError::InvalidRequest(
            "Missing query params".to_string(),
        ));
    }

    let client_pubkey = parts[0].to_string();

    // Validate pubkey format (64 hex chars)
    if client_pubkey.len() != 64 || !client_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OAuthError::InvalidRequest(
            "Invalid client public key format".to_string(),
        ));
    }

    let query = parts[1];

    // Parse query params manually (serde_urlencoded not available)
    let mut relay = String::new();
    let mut secret = String::new();
    let mut perms = None;
    let mut name = None;
    let mut url = None;
    let mut image = None;

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            let decoded_value = urlencoding::decode(value)
                .map_err(|e| OAuthError::InvalidRequest(format!("Invalid URL encoding: {}", e)))?
                .into_owned();

            match key {
                "relay" => relay = decoded_value,
                "secret" => secret = decoded_value,
                "perms" => perms = Some(decoded_value),
                "name" => name = Some(decoded_value),
                "url" => url = Some(decoded_value),
                "image" => image = Some(decoded_value),
                _ => {} // Ignore unknown params
            }
        }
    }

    if relay.is_empty() || secret.is_empty() {
        return Err(OAuthError::InvalidRequest(
            "Missing required params: relay and secret".to_string(),
        ));
    }

    let params = NostrConnectParams {
        relay,
        secret,
        perms,
        name,
        url,
        image,
    };

    // Validate relay URL
    if !params.relay.starts_with("wss://") && !params.relay.starts_with("ws://") {
        return Err(OAuthError::InvalidRequest("Invalid relay URL".to_string()));
    }

    Ok((client_pubkey, params))
}

/// GET /connect/*nostrconnect
/// Entry point from nostr-login popup - shows authorization page
pub async fn connect_get(
    State(_auth_state): State<super::routes::AuthState>,
    axum::extract::Path(nostrconnect_uri): axum::extract::Path<String>,
) -> Result<Response, OAuthError> {
    // Parse the nostrconnect:// URI
    let (client_pubkey, params) = parse_nostrconnect_uri(&nostrconnect_uri)?;

    tracing::info!(
        "nostr-login connect request - client: {}..., app: {}, relay: {}",
        &client_pubkey[..8],
        params.name.as_deref().unwrap_or("Unknown"),
        params.relay
    );

    // TODO: Check if user is logged in via session/UCAN
    // For now, show a simple auth form

    let app_name = params.name.as_deref().unwrap_or("Unknown App");
    let permissions_raw = params.perms.as_deref().unwrap_or("sign_event");

    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Authorize Connection - {brand} Login</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Bricolage+Grotesque:wght@600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --divine-green: #27C58B;
            --divine-green-dark: #1AA575;
            --bg: #072218;
            --surface: #0F2E23;
            --border: #1C4033;
            --text: hsl(210 40% 98%);
            --text-secondary: hsl(215 20.2% 65.1%);
            --muted: #0F2E23;
        }}
        @media (prefers-color-scheme: light) {{
            :root {{
                --bg: #F9F7F6;
                --surface: hsl(0 0% 100%);
                --border: hsl(214.3 31.8% 91.4%);
                --text: hsl(222.2 84% 4.9%);
                --text-secondary: hsl(215.4 16.3% 46.9%);
                --muted: hsl(210 40% 96.1%);
            }}
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1rem;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 1.5rem;
        }}
        .logo {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 2px;
            margin-bottom: 1.25rem;
        }}
        .logo img {{
            height: 28px;
        }}
        .logo .logo-sub {{
            font-family: 'Inter', system-ui, sans-serif;
            font-weight: 500;
            font-size: 11px;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--divine-green);
            opacity: 0.6;
        }}
        h1 {{
            font-family: 'Bricolage Grotesque', system-ui, sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 0.5rem;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        .app_header {{
            display: flex;
            align-items: center;
            gap: 0.875rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1rem;
        }}
        .app_icon {{
            width: 44px;
            height: 44px;
            background: var(--divine-green);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            font-weight: 600;
            color: white;
        }}
        .app_info h2 {{
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.125rem;
        }}
        .app_domain {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
        }}
        .permissions_list {{
            margin-bottom: 1rem;
        }}
        .permission_item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border);
        }}
        .permission_item:last-child {{
            border-bottom: none;
        }}
        .permission_icon {{
            font-size: 1.25rem;
            width: 32px;
            text-align: center;
        }}
        .permission_content h3 {{
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 0.125rem;
        }}
        .permission_content p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-align: left;
        }}
        .buttons {{
            display: flex;
            gap: 0.75rem;
            margin-top: 1rem;
        }}
        button {{
            flex: 1;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            border: none;
            border-radius: 9999px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
        }}
        .approve {{
            background: var(--divine-green);
            color: #fff;
        }}
        .approve:hover {{
            background: var(--divine-green-dark);
        }}
        .deny {{
            background: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }}
        .deny:hover {{
            background: var(--muted);
            color: var(--text);
        }}
        .warning {{
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            padding: 1rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
            color: #f59e0b;
            border-radius: 0.75rem;
            line-height: 1.5;
        }}
        /* Mobile: reduce padding for more working area */
        @media (max-width: 480px) {{
            body {{
                padding: 0.5rem;
            }}
            .header {{
                margin-bottom: 1rem;
            }}
            h1 {{
                font-size: 1.25rem;
            }}
            .card {{
                padding: 1rem;
                border-radius: 0.75rem;
            }}
            .app_header {{
                padding-bottom: 0.75rem;
                margin-bottom: 0.75rem;
            }}
            .logo {{
                margin-bottom: 0.75rem;
            }}
            .warning {{
                padding: 0.75rem;
                font-size: 0.8rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="/divine-logo.svg" alt="{brand}" />
                <span class="logo-sub">Login</span>
            </div>
            <h1>Authorize Connection</h1>
            <p class="subtitle">An app wants to connect to your account</p>
        </div>

        <div class="card">
            <div class="app_header">
                <div class="app_icon" id="app_icon">{app_icon_html}</div>
                <div class="app_info">
                    <div class="app_domain">{relay_html}</div>
                    <h2>{app_name_html}</h2>
                </div>
            </div>

            <div class="permissions_list" id="permissions_list">
                <!-- Populated by JavaScript -->
            </div>
        </div>

        <div class="warning">
            This will allow the app to sign events on your behalf using your {brand}-managed keys.
        </div>

        <form method="POST" action="/api/oauth/connect">
            <input type="hidden" name="client_pubkey" value="{client_pubkey_attr}">
            <input type="hidden" name="relay" value="{relay_attr}">
            <input type="hidden" name="secret" value="{secret_attr}">
            <input type="hidden" name="perms" value="{perms_attr}">
            <div class="buttons">
                <button type="submit" name="approved" value="false" class="deny">Deny</button>
                <button type="submit" name="approved" value="true" class="approve">Authorize</button>
            </div>
        </form>
    </div>

    <script>
        const permissions = {permissions_raw_js};
        const permissionMeta = {{
            'sign_event': {{
                icon: '✍️',
                title: 'Act on your behalf',
                description: 'Post and interact as you on Nostr'
            }},
            'encrypt': {{
                icon: '🔒',
                title: 'Send private messages',
                description: 'Encrypt messages to other users'
            }},
            'decrypt': {{
                icon: '🔓',
                title: 'Read private messages',
                description: 'Decrypt messages sent to you'
            }},
            'nip04_encrypt': {{
                icon: '🔐',
                title: 'Send DMs (legacy)',
                description: 'Encrypt direct messages'
            }},
            'nip04_decrypt': {{
                icon: '🔑',
                title: 'Read DMs (legacy)',
                description: 'Decrypt direct messages'
            }},
            'nip44_encrypt': {{
                icon: '🛡️',
                title: 'Send private messages',
                description: 'Encrypt messages securely'
            }},
            'nip44_decrypt': {{
                icon: '🔏',
                title: 'Read private messages',
                description: 'Decrypt messages sent to you'
            }}
        }};

        function buildPermissionsList() {{
            const scopes = permissions.split(/[\s,]+/).filter(s => s);
            const container = document.getElementById('permissions_list');

            scopes.forEach(s => {{
                const meta = permissionMeta[s] || {{
                    icon: '📋',
                    title: s.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                    description: 'Permission: ' + s
                }};

                const item = document.createElement('div');
                item.className = 'permission_item';
                item.innerHTML = `
                    <div class="permission_icon">${{meta.icon}}</div>
                    <div class="permission_content">
                        <h3>${{meta.title}}</h3>
                        <p>${{meta.description}}</p>
                    </div>
                `;
                container.appendChild(item);
            }});
        }}

        buildPermissionsList();
    </script>
</body>
</html>
    "#,
        app_name_html = escape_html(app_name),
        app_icon_html = escape_html(
            &app_name
                .chars()
                .next()
                .unwrap_or('A')
                .to_uppercase()
                .to_string()
        ),
        relay_html = escape_html(&params.relay),
        client_pubkey_attr = escape_attr(&client_pubkey),
        relay_attr = escape_attr(&params.relay),
        secret_attr = escape_attr(&params.secret),
        perms_attr = escape_attr(params.perms.as_deref().unwrap_or("")),
        permissions_raw_js = js_string_literal(&permissions_raw),
        brand = BRAND_NAME,
    );

    Ok(Html(html).into_response())
}

/// POST /oauth/connect
/// User approves/denies the nostr-login connection
pub async fn connect_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ConnectApprovalForm>,
) -> Result<Response, OAuthError> {
    let tenant_id = tenant.0.id;

    tracing::info!(
        "nostr-login connect approval - client: {}..., approved: {}",
        &form.client_pubkey[..8],
        form.approved
    );

    if !form.approved {
        return Ok(Html(
            r#"
<html>
<head>
    <title>Authorization Denied</title>
    <style>
        body {
            font-family: sans-serif;
            text-align: center;
            padding: 50px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        h1 { color: #f44336; }
    </style>
    <script>
        setTimeout(() => window.close(), 2000);
    </script>
</head>
<body>
    <h1>✗ Authorization Denied</h1>
    <p>You can close this window.</p>
</body>
</html>
        "#,
        )
        .into_response());
    }

    // Extract user public key from JWT token in Authorization header
    let user_pubkey = super::auth::extract_user_from_token(&headers, tenant_id)
        .await
        .map_err(|_| OAuthError::Unauthorized)?;

    // Get user's encrypted key
    let personal_keys_repo = PersonalKeysRepository::new(auth_state.state.db.clone());
    let encrypted_user_key: Vec<u8> = personal_keys_repo
        .find_encrypted_key_by_tenant(tenant_id, &user_pubkey)
        .await?
        .ok_or(OAuthError::Unauthorized)?;

    // For nostr-login, redirect_origin is "nostrconnect://{client_pubkey}" (the secure identifier)
    let redirect_origin = format!("nostrconnect://{}", &form.client_pubkey);

    // Hash the client-provided secret with bcrypt for storage
    let client_secret = form.secret.clone();
    let secret_hash = tokio::task::spawn_blocking(move || bcrypt::hash(&client_secret, 10))
        .await
        .map_err(|e| OAuthError::ServerError(format!("Hash task failed: {}", e)))?
        .map_err(|e| OAuthError::ServerError(format!("Failed to hash secret: {}", e)))?;

    // Derive bunker keys from user secret using HKDF with secret_hash as entropy
    // (privacy: bunker_pubkey ≠ user_pubkey, zero extra KMS calls at runtime)
    let key_manager = auth_state.state.key_manager.as_ref();
    let decrypted_user_secret = key_manager
        .decrypt(&encrypted_user_key)
        .await
        .map_err(|e| OAuthError::Encryption(format!("Failed to decrypt user key: {}", e)))?;
    let user_secret_key = nostr_sdk::SecretKey::from_slice(&decrypted_user_secret)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid secret key: {}", e)))?;

    // Use secret_hash as HKDF entropy - can be re-derived at runtime without KMS
    let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &secret_hash);
    let bunker_public_key = bunker_keys.public_key();

    // Use a descriptive name for nostr-login connections
    let client_id = format!("nostr-login-{}", &form.client_pubkey[..12]);

    // Create authorization
    let relays_json = serde_json::to_string(&vec![form.relay.clone()])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    // Generate authorization handle for silent re-authentication
    let authorization_handle = generate_authorization_handle();

    // Handle absolute expiration (30 days from creation - hard ceiling for silent re-auth)
    let handle_expires_at = Utc::now() + Duration::days(30);

    // Create new OAuth authorization - always INSERT (multi-device support)
    // Each nostr-login creates a NEW authorization for that client
    let oauth_auth_repo = OAuthAuthorizationRepository::new(auth_state.state.db.clone());
    let auth_id = oauth_auth_repo
        .create(CreateOAuthAuthorizationParams {
            tenant_id,
            user_pubkey: user_pubkey.clone(),
            redirect_origin: redirect_origin.clone(),
            client_id: client_id.clone(),
            bunker_public_key: bunker_public_key.to_hex(),
            secret_hash,
            relays: relays_json.clone(),
            policy_id: None,
            client_pubkey: Some(form.client_pubkey.clone()),
            authorization_handle: Some(authorization_handle.clone()),
            handle_expires_at,
        })
        .await?;

    tracing::info!(
        "Created nostr-login authorization {} for user {} app {}",
        auth_id,
        user_pubkey,
        redirect_origin
    );

    // Track OAuth authorization created
    METRICS.inc_oauth_created();

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
            tracing::error!(
                "Failed to send authorization upsert command (nostr-login): {}",
                e
            );
        } else {
            tracing::info!("Sent authorization upsert command to signer daemon (nostr-login)");
        }
    }

    Ok(Html(r#"
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            text-align: center;
            padding: 50px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        h1 {
            color: #4CAF50;
            font-size: 32px;
        }
        p {
            font-size: 18px;
            color: #888;
        }
        .checkmark {
            font-size: 64px;
            margin-bottom: 20px;
        }
    </style>
    <script>
        setTimeout(() => window.close(), 3000);
    </script>
</head>
<body>
    <div class="checkmark">✓</div>
    <h1>Authorization Successful</h1>
    <p>You can close this window.</p>
    <p style="font-size: 14px; margin-top: 20px;">(Closing automatically in 3 seconds...)</p>
</body>
</html>
    "#).into_response())
}

// ============================================================================
// Polling Endpoint for iOS PWA OAuth Flow
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PollRequest {
    /// RFC 8628 device_code - secret polling credential returned in registration response body
    /// Unlike 'state' (visible in URL), device_code is never exposed in URLs or referrer headers
    pub device_code: String,
}

#[derive(Debug, Serialize)]
pub struct PollResponse {
    pub code: String,
}

/// GET /oauth/poll?device_code={device_code}
/// Polling endpoint for multi-device OAuth flow (email verified on different device)
/// Uses RFC 8628-style device_code (secret, returned in response body) for secure polling
/// Returns HTTP 200 with code when ready, HTTP 202 if pending, HTTP 500 on server error
/// See: https://datatracker.ietf.org/doc/html/rfc8628
pub async fn poll(
    State(auth_state): State<super::routes::AuthState>,
    Query(req): Query<PollRequest>,
) -> Result<Response, OAuthError> {
    // Validate device_code parameter (basic sanity check - alphanumeric, reasonable length)
    if req.device_code.len() > 128
        || !req
            .device_code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(OAuthError::InvalidRequest(
            "Invalid device_code parameter".into(),
        ));
    }

    let Some(redis) = &auth_state.state.redis else {
        tracing::error!("Redis not configured for OAuth polling");
        return Err(OAuthError::ServerError(
            "Service temporarily unavailable".into(),
        ));
    };

    let key = format!("oauth_poll:{}", req.device_code);

    match redis.get(&key).await {
        Ok(Some(code)) => {
            // Delete key (one-time use)
            let _ = redis.del(&key).await;

            Ok((StatusCode::OK, Json(PollResponse { code })).into_response())
        }
        Ok(None) => {
            // Not ready yet
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({ "status": "pending" })),
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!("Redis error in poll: {}", e);
            Err(OAuthError::ServerError(
                "Service temporarily unavailable".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://postgres:password@localhost/keycast_test")
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

    #[tokio::test]
    async fn test_oauth_register_rejects_malformed_email_with_stable_error() {
        let response = match oauth_register(
            create_unit_test_tenant(),
            axum::extract::State(create_lazy_auth_state()),
            axum::Json(OAuthRegisterRequest {
                email: "person@-example.com".to_string(),
                password: "testpassword123".to_string(),
                client_id: "TestClient".to_string(),
                redirect_uri: "https://client.example/callback".to_string(),
                scope: None,
                code_challenge: None,
                code_challenge_method: None,
                pubkey: None,
                nsec: None,
                relays: None,
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
        assert_eq!(body["error"], crate::api::http::auth::INVALID_EMAIL_MESSAGE);
    }

    #[test]
    fn password_visibility_controls_target_oauth_login_and_registration_fields() {
        let markup = password_visibility_controls_html(&[
            "login_password",
            "register_password",
            "register_password-confirm",
            "register_nsec",
        ]);

        for field_id in [
            "login_password",
            "register_password",
            "register_password-confirm",
            "register_nsec",
        ] {
            assert!(markup.contains(&format!("data-password-target=\"{}\"", field_id)));
        }

        assert!(markup.contains("aria-label=\"Show password\""));
        assert!(markup.contains("type=\"button\""));
        assert!(markup.contains("function togglePasswordVisibility"));
    }

    #[test]
    fn test_extract_origin_https() {
        assert_eq!(
            extract_origin("https://example.com/callback").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            extract_origin("https://example.com:8080/path").unwrap(),
            "https://example.com:8080"
        );
    }

    #[test]
    fn test_extract_origin_http_localhost() {
        assert_eq!(
            extract_origin("http://localhost:3000/callback").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            extract_origin("http://127.0.0.1:3000/callback").unwrap(),
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            extract_origin("http://[::1]:3000/callback").unwrap(),
            "http://[::1]:3000"
        );
    }

    #[test]
    fn test_extract_origin_http_localhost_subdomain() {
        // RFC 6761 reserves *.localhost as loopback; browsers resolve these to 127.0.0.1.
        // Accepting them here lets multiple local dev services coexist on distinct hostnames.
        assert_eq!(
            extract_origin("http://admin.localhost:8787/callback").unwrap(),
            "http://admin.localhost:8787"
        );
        assert_eq!(
            extract_origin("http://api.localhost:3000/auth").unwrap(),
            "http://api.localhost:3000"
        );
        // Nested subdomain
        assert_eq!(
            extract_origin("http://admin.app.localhost:8080/callback").unwrap(),
            "http://admin.app.localhost:8080"
        );
    }

    #[test]
    fn test_extract_origin_http_non_localhost_rejected() {
        let err = extract_origin("http://example.com/callback").unwrap_err();
        assert!(matches!(err, OAuthError::InvalidRequest(msg) if msg.contains("HTTPS required")));
    }

    #[test]
    fn test_extract_origin_http_localhost_lookalike_rejected() {
        // Hosts that merely contain "localhost" as a substring must not be treated as loopback.
        // The subdomain match requires a `.` before `localhost`, so these are rejected.
        for lookalike in [
            "http://xxxlocalhost/callback",
            "http://localhost.evil.com/callback",
            "http://.localhost/callback", // empty label before .localhost
        ] {
            let err = extract_origin(lookalike).unwrap_err();
            assert!(
                matches!(&err, OAuthError::InvalidRequest(msg) if msg.contains("HTTPS required") || msg.contains("Invalid redirect_uri")),
                "{} should be rejected, got {:?}",
                lookalike,
                err
            );
        }
    }

    #[test]
    fn test_extract_origin_custom_schemes_rejected() {
        // Custom URL schemes are rejected - they're vulnerable to hijacking attacks
        let err = extract_origin("divine://callback").unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidRequest(msg) if msg.contains("Invalid redirect_uri scheme"))
        );

        let err = extract_origin("myapp://auth").unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidRequest(msg) if msg.contains("Only https:// URLs are allowed"))
        );

        let err = extract_origin("com.example.app://oauth").unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidRequest(msg) if msg.contains("Invalid redirect_uri scheme"))
        );
    }

    #[test]
    fn test_extract_origin_invalid_url() {
        let err = extract_origin("not-a-url").unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidRequest(msg) if msg.contains("Invalid redirect_uri"))
        );
    }
}
