// ABOUTME: Personal authentication handlers for email/password registration and login
// ABOUTME: Implements UCAN-based authentication and NIP-46 bunker URL generation

use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use bip39;
use chrono::{Duration, Utc};
use nostr_sdk::{Keys, UnsignedEvent, PublicKey, ToBech32};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use keycast_core::types::permission::Permission;
use keycast_core::traits::CustomPermission;

// Registration and login return simple JSON (not OAuth TokenResponse)

pub const TOKEN_EXPIRY_HOURS: i64 = 24;
pub const EMAIL_VERIFICATION_EXPIRY_HOURS: i64 = 24;
const PASSWORD_RESET_EXPIRY_HOURS: i64 = 1;

pub fn generate_secure_token() -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Generate UCAN token signed by user's key (server signs on behalf of user)
pub(crate) async fn generate_ucan_token(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
    relays: Option<&[String]>,
) -> Result<String, AuthError> {
    use crate::ucan_auth::{NostrKeyMaterial, nostr_pubkey_to_did};
    use ucan::builder::UcanBuilder;
    use serde_json::json;

    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());

    // Create facts with optional relays
    let mut facts_obj = json!({
        "tenant_id": tenant_id,
        "email": email,
    });

    if let Some(relays) = relays {
        facts_obj["relays"] = json!(relays);
    }

    let facts = facts_obj;

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)  // Self-issued
        .with_lifetime((TOKEN_EXPIRY_HOURS * 3600) as u64)  // 24 hours in seconds
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
pub(crate) async fn generate_server_signed_ucan(
    user_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    email: &str,
    server_keys: &Keys,
) -> Result<String, AuthError> {
    use crate::ucan_auth::{NostrKeyMaterial, nostr_pubkey_to_did};
    use ucan::builder::UcanBuilder;
    use serde_json::json;

    let server_key_material = NostrKeyMaterial::from_keys(server_keys.clone());
    let user_did = nostr_pubkey_to_did(user_pubkey);

    let facts = json!({
        "tenant_id": tenant_id,
        "email": email,
    });

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)  // Server issues
        .for_audience(&user_did)           // For this user
        .with_lifetime((TOKEN_EXPIRY_HOURS * 3600) as u64)
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
    pub nsec: Option<String>,  // Optional: user can provide their own nsec/hex secret key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,  // Optional: user's preferred relays
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub pubkey: String,
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
    DuplicateKey,  // Nostr pubkey already registered (BYOK case)
    BadRequest(String),
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
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        AuthError::Database(e)
    }
}

impl From<bcrypt::BcryptError> for AuthError {
    fn from(e: bcrypt::BcryptError) -> Self {
        AuthError::PasswordHash(e)
    }
}

/// Extract user public key from UCAN token in Authorization header or cookie
pub(crate) fn extract_user_from_token(headers: &HeaderMap) -> Result<String, AuthError> {
    // Try Bearer token first
    if let Some(auth_header) = headers.get("Authorization") {
        let auth_str = auth_header.to_str().map_err(|_| AuthError::InvalidToken)?;

        if auth_str.starts_with("Bearer ") {
            // Validate UCAN token and extract user pubkey
            return crate::ucan_auth::extract_user_from_ucan(headers, 0)
                .map_err(|_| AuthError::InvalidToken);
        }
    }

    // Fall back to cookie-based UCAN
    if let Some(token) = extract_ucan_from_cookie(headers) {
        // Parse UCAN from string using ucan_auth helper (tenant validation done by caller)
        let (pubkey, _ucan) = crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), 0)
            .map_err(|e| {
                tracing::warn!("UCAN parse error from cookie: {}", e);
                AuthError::InvalidToken
            })?;

        Ok(pubkey)
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

/// Register a new user with email and password, sets session cookie
pub async fn register(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;
    tracing::info!(
        event = "registration_attempt",
        tenant_id = tenant_id,
        "Registration attempt for email"
    );

    // Check if email already exists in this tenant
    let existing: Option<(String,)> = sqlx::query_as("SELECT public_key FROM users WHERE email = $1 AND tenant_id = $2")
        .bind(&req.email)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        return Err(AuthError::EmailAlreadyExists);
    }

    // Hash password
    let password_hash = hash(&req.password, DEFAULT_COST)?;

    // Generate email verification token
    let verification_token = generate_secure_token();
    let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

    // Use provided nsec or generate new Nostr keypair
    let keys = if let Some(ref nsec_str) = req.nsec {
        tracing::info!("User provided their own key (BYOK) for email: {}", req.email);
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
        let existing_pubkey: Option<(String,)> = sqlx::query_as(
            "SELECT public_key FROM users WHERE public_key = $1 AND tenant_id = $2"
        )
        .bind(public_key.to_hex())
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        if existing_pubkey.is_some() {
            return Err(AuthError::DuplicateKey);
        }
    }

    // Encrypt the secret key (as raw bytes)
    let secret_bytes = secret_key.to_secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&secret_bytes)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Generate bunker secret (random 32 bytes hex)
    let _bunker_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // Start transaction
    let mut tx = pool.begin().await?;

    // Insert user with email verification token
    sqlx::query(
        "INSERT INTO users (public_key, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(public_key.to_hex())
    .bind(tenant_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(false) // email_verified
    .bind(&verification_token)
    .bind(verification_expires)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    // Insert personal key
    sqlx::query(
        "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, created_at, updated_at)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(public_key.to_hex())
    .bind(&encrypted_secret)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Send verification email (optional - don't fail if email service unavailable)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service.send_verification_email(&req.email, &verification_token).await {
                tracing::error!("Failed to send verification email to {}: {}", req.email, e);
            } else {
                tracing::info!("Sent verification email to {}", req.email);
            }
        },
        Err(e) => {
            tracing::warn!("Email service unavailable, skipping verification email: {}", e);
        }
    }

    // Generate UCAN token for session cookie with optional relays
    let ucan_token = generate_ucan_token(&keys, tenant_id, &req.email, req.relays.as_deref()).await?;

    tracing::info!(
        event = "registration",
        tenant_id = tenant_id,
        success = true,
        "User registered successfully"
    );

    // Create response with UCAN session cookie (bunker_url NOT included - fetch via /user/bunker)
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    let response = (
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(AuthResponse {
            success: true,
            pubkey: public_key.to_hex(),
        })
    );

    Ok(response)
}

/// Login with email and password (REST endpoint for main web app)
/// Returns simple JSON response and sets UCAN cookie
/// To get bunker URL, call GET /user/bunker after login
pub async fn login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;
    tracing::info!(
        event = "login_attempt",
        tenant_id = tenant_id,
        "Login attempt"
    );

    // Fetch user with password hash from this tenant
    let user: Option<(String, String)> = sqlx::query_as(
        "SELECT public_key, password_hash FROM users WHERE email = $1 AND tenant_id = $2 AND password_hash IS NOT NULL"
    )
    .bind(&req.email)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let (public_key, password_hash) = match user {
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

    // Verify password
    let valid = verify(&req.password, &password_hash)?;
    if !valid {
        tracing::warn!(
            event = "login",
            tenant_id = tenant_id,
            success = false,
            reason = "invalid_password",
            "Login failed: invalid password"
        );
        return Err(AuthError::InvalidCredentials);
    }

    // Get user's Nostr keys from personal_keys
    let encrypted_secret: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE user_public_key = $1"
    )
    .bind(&public_key)
    .fetch_one(pool)
    .await?;

    let key_manager = auth_state.state.key_manager.as_ref();
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Generate UCAN token for session cookie (login doesn't set relays, uses registration defaults)
    let ucan_token = generate_ucan_token(&keys, tenant_id, &req.email, None).await?;

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

    let response = (
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(AuthResponse {
            success: true,
            pubkey: public_key,
        })
    );

    Ok(response)
}

/// Logout endpoint - clears the keycast_session cookie
pub async fn logout(
) -> Result<impl axum::response::IntoResponse, AuthError> {
    tracing::info!("User logging out");

    // Clear the session cookie by setting Max-Age=0
    let cookie = "keycast_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

    let response = (
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        }))
    );

    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct CreateBunkerRequest {
    pub app_name: String,
    pub relay_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateBunkerResponse {
    pub bunker_url: String,
    pub app_name: String,
    pub bunker_pubkey: String,
    pub created_at: String,
}

/// POST /user/bunker/create
/// Manually create a new bunker connection for NIP-46 clients
/// User can create multiple bunker connections for different apps
pub async fn create_bunker(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<CreateBunkerRequest>,
) -> Result<Json<CreateBunkerResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    tracing::info!("Creating manual bunker for user: {} in tenant: {}, app: {}", user_pubkey, tenant_id, req.app_name);

    // Get user's encrypted secret key
    let encrypted_secret: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE user_public_key = $1"
    )
    .bind(&user_pubkey)
    .fetch_one(pool)
    .await?;

    // Generate connection secret
    let connection_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();

    // Create a dummy OAuth application for this manual bunker (if not exists)
    let app_name_slug = req.app_name.to_lowercase().replace(' ', "-");
    let client_id = format!("manual-{}", app_name_slug);

    sqlx::query(
        "INSERT INTO oauth_applications (tenant_id, name, client_id, client_secret, redirect_uris, created_at, updated_at)
         VALUES ($1, $2, $3, 'manual', '[]', $4, $5)
         ON CONFLICT (client_id, tenant_id) DO NOTHING"
    )
    .bind(tenant_id)
    .bind(&req.app_name)
    .bind(&client_id)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(pool)
    .await?;

    // Get application ID and default policy
    let app_id: i32 = sqlx::query_scalar(
        "SELECT id FROM oauth_applications WHERE client_id = $1 AND tenant_id = $2"
    )
    .bind(&client_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    let policy_id: i32 = sqlx::query_scalar(
        "SELECT id FROM policies WHERE name = 'Standard Social (Default)' AND tenant_id = $1 LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    // Use deployment-wide relay list (ignore any client-provided relay)
    let relays = keycast_core::types::authorization::Authorization::get_bunker_relays();
    let relays_json = serde_json::to_string(&relays)
        .map_err(|e| AuthError::Internal(format!("Failed to serialize relays: {}", e)))?;

    // Create OAuth authorization
    let created_at = Utc::now();
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (tenant_id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, policy_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(tenant_id)
    .bind(&user_pubkey)
    .bind(app_id)
    .bind(&user_pubkey)  // bunker pubkey = user's pubkey
    .bind(&encrypted_secret)
    .bind(&connection_secret)
    .bind(&relays_json)
    .bind(policy_id)
    .bind(created_at)
    .bind(created_at)
    .execute(pool)
    .await?;

    // Signal signer daemon to reload via channel (instant notification)
    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx.send(AuthorizationCommand::Upsert {
            bunker_pubkey: user_pubkey.clone(),
            tenant_id,
            is_oauth: true,
        }).await {
            tracing::error!("Failed to send authorization upsert command: {}", e);
        } else {
            tracing::info!("Sent authorization upsert command to signer daemon");
        }
    }

    // Build bunker URL using same relay list
    let relay_params: String = relays
        .iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect::<Vec<_>>()
        .join("&");

    let bunker_url = format!(
        "bunker://{}?{}&secret={}",
        user_pubkey,
        relay_params,
        connection_secret
    );

    tracing::info!("Created manual bunker connection for user: {}, app: {}", user_pubkey, req.app_name);

    Ok(Json(CreateBunkerResponse {
        bunker_url,
        app_name: req.app_name,
        bunker_pubkey: user_pubkey.clone(),
        created_at: created_at.to_rfc3339(),
    }))
}

/// Get bunker URL for the authenticated user
pub async fn get_bunker_url(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<BunkerUrlResponse>, AuthError> {
    // Extract user pubkey from UCAN token
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Fetching bunker URL for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get the user's OAuth authorization bunker URL for keycast-ropc
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT oa.bunker_public_key, oa.secret FROM oauth_authorizations oa
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.user_public_key = $1
         AND u.tenant_id = $2
         AND oa.application_id = (SELECT id FROM oauth_applications WHERE client_id = 'keycast-ropc' AND tenant_id = $2)
         ORDER BY oa.created_at DESC LIMIT 1"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (bunker_pubkey, connection_secret) = result.ok_or(AuthError::UserNotFound)?;

    // Build bunker URL with deployment-wide relay list
    let relays = keycast_core::types::authorization::Authorization::get_bunker_relays();
    let relay_params: String = relays
        .iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect::<Vec<_>>()
        .join("&");

    let bunker_url = format!(
        "bunker://{}?{}&secret={}",
        bunker_pubkey,
        relay_params,
        connection_secret
    );

    tracing::info!("Returning bunker URL with pubkey: {}", bunker_pubkey);

    Ok(Json(BunkerUrlResponse { bunker_url }))
}

/// Verify email address with token
pub async fn verify_email(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!("Email verification attempt with token: {}... for tenant: {}", &req.token[..10], tenant_id);

    // Find user with this verification token in this tenant
    let user: Option<(String, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT public_key, email_verification_expires_at FROM users
         WHERE email_verification_token = $1 AND tenant_id = $2"
    )
    .bind(&req.token)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (public_key, expires_at) = user.ok_or(AuthError::InvalidToken)?;

    // Check if token is expired
    if let Some(expires) = expires_at {
        if expires < Utc::now() {
            return Ok(Json(VerifyEmailResponse {
                success: false,
                message: "Verification link has expired. Please request a new one.".to_string(),
            }));
        }
    }

    // Mark email as verified and clear verification token
    sqlx::query(
        "UPDATE users
         SET email_verified = $1,
             email_verification_token = NULL,
             email_verification_expires_at = NULL,
             updated_at = $2
         WHERE public_key = $3"
    )
    .bind(true)
    .bind(Utc::now())
    .bind(&public_key)
    .execute(&pool)
    .await?;

    tracing::info!(
        event = "email_verification",
        tenant_id = tenant_id,
        success = true,
        "Email verified successfully"
    );

    Ok(Json(VerifyEmailResponse {
        success: true,
        message: "Email verified successfully! You can now use all features.".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct ResendVerificationResponse {
    pub success: bool,
    pub message: String,
}

/// Resend email verification (requires authentication)
pub async fn resend_verification(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<ResendVerificationResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Resend verification requested for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get user's email and verification status
    let user: Option<(String, bool, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT email, email_verified, email_verification_sent_at FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (email, email_verified, last_sent) = match user {
        Some(u) => u,
        None => return Err(AuthError::UserNotFound),
    };

    // Already verified
    if email_verified {
        return Ok(Json(ResendVerificationResponse {
            success: true,
            message: "Email is already verified.".to_string(),
        }));
    }

    // Rate limit: 1 per 5 minutes
    if let Some(sent_at) = last_sent {
        let minutes_since = (Utc::now() - sent_at).num_minutes();
        if minutes_since < 5 {
            return Ok(Json(ResendVerificationResponse {
                success: false,
                message: format!("Please wait {} minutes before requesting another verification email.", 5 - minutes_since),
            }));
        }
    }

    // Generate new verification token
    let verification_token = generate_secure_token();
    let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

    sqlx::query(
        "UPDATE users
         SET email_verification_token = $1,
             email_verification_expires_at = $2,
             email_verification_sent_at = $3,
             updated_at = $4
         WHERE public_key = $5"
    )
    .bind(&verification_token)
    .bind(verification_expires)
    .bind(Utc::now())
    .bind(Utc::now())
    .bind(&user_pubkey)
    .execute(&pool)
    .await?;

    // Send verification email
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service.send_verification_email(&email, &verification_token).await {
                tracing::error!("Failed to send verification email to {}: {}", email, e);
                return Err(AuthError::EmailSendFailed(e.to_string()));
            }
            tracing::info!("Sent verification email to {}", email);
        },
        Err(e) => {
            tracing::warn!("Email service unavailable: {}", e);
            return Err(AuthError::EmailSendFailed("Email service unavailable".to_string()));
        }
    }

    Ok(Json(ResendVerificationResponse {
        success: true,
        message: "Verification email sent! Please check your inbox.".to_string(),
    }))
}

/// Request password reset email
pub async fn forgot_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!("Password reset requested for email: {} in tenant: {}", req.email, tenant_id);

    // Check if user exists in this tenant
    let user: Option<(String,)> = sqlx::query_as(
        "SELECT public_key FROM users WHERE email = $1 AND tenant_id = $2"
    )
    .bind(&req.email)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    // Always return success even if email doesn't exist (security best practice)
    if user.is_none() {
        tracing::info!("Password reset requested for non-existent email: {}", req.email);
        return Ok(Json(ForgotPasswordResponse {
            success: true,
            message: "If an account exists with that email, a password reset link has been sent.".to_string(),
        }));
    }

    let (public_key,) = user.unwrap();

    // Generate reset token
    let reset_token = generate_secure_token();
    let reset_expires = Utc::now() + Duration::hours(PASSWORD_RESET_EXPIRY_HOURS);

    // Store reset token
    sqlx::query(
        "UPDATE users
         SET password_reset_token = $1,
             password_reset_expires_at = $2,
             updated_at = $3
         WHERE public_key = $4"
    )
    .bind(&reset_token)
    .bind(reset_expires)
    .bind(Utc::now())
    .bind(&public_key)
    .execute(&pool)
    .await?;

    // Send password reset email (optional - don't fail if email service unavailable)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service.send_password_reset_email(&req.email, &reset_token).await {
                tracing::error!("Failed to send password reset email to {}: {}", req.email, e);
            } else {
                tracing::info!("Sent password reset email to {}", req.email);
            }
        },
        Err(e) => {
            tracing::warn!("Email service unavailable, skipping password reset email: {}", e);
        }
    }

    Ok(Json(ForgotPasswordResponse {
        success: true,
        message: "If an account exists with that email, a password reset link has been sent.".to_string(),
    }))
}

/// Reset password with token
pub async fn reset_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!("Password reset attempt with token: {}... for tenant: {}", &req.token[..10], tenant_id);

    // Find user with this reset token in this tenant
    let user: Option<(String, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT public_key, password_reset_expires_at FROM users
         WHERE password_reset_token = $1 AND tenant_id = $2"
    )
    .bind(&req.token)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (public_key, expires_at) = user.ok_or(AuthError::InvalidToken)?;

    // Check if token is expired
    if let Some(expires) = expires_at {
        if expires < Utc::now() {
            return Ok(Json(ResetPasswordResponse {
                success: false,
                message: "Password reset link has expired. Please request a new one.".to_string(),
            }));
        }
    }

    // Hash new password
    let password_hash = hash(&req.new_password, DEFAULT_COST)?;

    // Update password, clear reset token, and mark email as verified
    // (user proved email ownership by receiving and using the reset link)
    sqlx::query(
        "UPDATE users
         SET password_hash = $1,
             password_reset_token = NULL,
             password_reset_expires_at = NULL,
             email_verified = true,
             email_verification_token = NULL,
             email_verification_expires_at = NULL,
             updated_at = $2
         WHERE public_key = $3"
    )
    .bind(&password_hash)
    .bind(Utc::now())
    .bind(&public_key)
    .execute(&pool)
    .await?;

    tracing::info!(
        event = "password_reset",
        tenant_id = tenant_id,
        success = true,
        "Password reset successfully (email now verified)"
    );

    Ok(Json(ResetPasswordResponse {
        success: true,
        message: "Password reset successfully! You can now log in with your new password.".to_string(),
    }))
}

/// Get username for NIP-05 - the only profile data we store server-side
pub async fn get_profile(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<ProfileData>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Fetching username for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get username from users table - this is the ONLY thing we store
    // The client should fetch actual kind 0 profile data from Nostr relays via bunker
    let username: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT username FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let username = username.and_then(|(u,)| u);

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
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::debug!("Fetching account status for user: {} in tenant: {}", user_pubkey, tenant_id);

    let user: Option<(String, bool)> = sqlx::query_as(
        "SELECT email, email_verified FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    match user {
        Some((email, email_verified)) => Ok(Json(AccountStatusResponse {
            email,
            email_verified,
            public_key: user_pubkey,
        })),
        None => Err(AuthError::UserNotFound),
    }
}

/// Update username (for NIP-05) - the only profile data we store server-side
/// Client should publish kind 0 profile events to relays via bunker URL
pub async fn update_profile(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(profile): Json<ProfileData>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;

    tracing::info!("Updating username for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Only update username - everything else is stored on Nostr relays
    if let Some(ref username) = profile.username {
        // Validate username (alphanumeric, dash, underscore only)
        if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(AuthError::Internal("Username can only contain letters, numbers, dashes, and underscores".to_string()));
        }

        // Check if username is already taken in this tenant
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT public_key FROM users WHERE username = $1 AND public_key != $2 AND tenant_id = $3"
        )
        .bind(username)
        .bind(&user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await?;

        if existing.is_some() {
            return Err(AuthError::Internal("Username already taken".to_string()));
        }

        // Update username in users table
        sqlx::query(
            "UPDATE users SET username = $1, updated_at = $2 WHERE public_key = $3 AND tenant_id = $4"
        )
        .bind(username)
        .bind(Utc::now())
        .bind(&user_pubkey)
        .bind(tenant_id)
        .execute(&pool)
        .await?;

        tracing::info!("Username updated to '{}' for user: {}", username, user_pubkey);
    }

    // Client should publish profile to relays via bunker URL
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Username saved. Client should publish kind 0 event to relays via bunker."
    })))
}

#[derive(Debug, Serialize)]
pub struct BunkerSession {
    pub application_name: String,
    pub application_id: Option<i32>,
    pub bunker_pubkey: String,
    pub secret: String,
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
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Listing bunker sessions for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get OAuth authorizations with application details and activity stats
    type OAuthSessionRow = (String, i32, String, String, String, Option<String>, Option<i64>);
    let oauth_sessions: Vec<OAuthSessionRow> = sqlx::query_as(
        "SELECT
            COALESCE(a.name, 'Personal Bunker') as name,
            oa.application_id,
            oa.bunker_public_key,
            oa.secret,
            oa.created_at::text,
            (SELECT MAX(created_at)::text FROM signing_activity WHERE bunker_secret = oa.secret) as last_activity,
            (SELECT COUNT(*) FROM signing_activity WHERE bunker_secret = oa.secret) as activity_count
         FROM oauth_authorizations oa
         LEFT JOIN oauth_applications a ON oa.application_id = a.id
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.user_public_key = $1
           AND u.tenant_id = $2
           AND oa.revoked_at IS NULL
         ORDER BY oa.created_at DESC"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_all(&pool)
    .await?;

    let sessions = oauth_sessions
        .into_iter()
        .map(|(name, app_id, bunker_pubkey, secret, created_at, last_activity, activity_count)| BunkerSession {
            application_name: name,
            application_id: Some(app_id),
            bunker_pubkey,
            secret,
            client_pubkey: None,  // client_public_key column doesn't exist
            created_at,
            last_activity,
            activity_count: activity_count.unwrap_or(0),
        })
        .collect();

    Ok(Json(BunkerSessionsResponse { sessions }))
}

#[derive(Debug, Serialize)]
pub struct SessionActivity {
    pub event_kind: i64,
    pub event_content: Option<String>,
    pub event_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct SessionActivityResponse {
    pub activities: Vec<SessionActivity>,
}

/// Get activity log for a specific bunker session
pub async fn get_session_activity(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    axum::extract::Path(secret): axum::extract::Path<String>,
) -> Result<Json<SessionActivityResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Fetching activity for bunker secret: {} in tenant: {}", secret, tenant_id);

    // Verify this bunker session belongs to the user in this tenant
    let session: Option<(String,)> = sqlx::query_as(
        "SELECT oa.user_public_key FROM oauth_authorizations oa
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.secret = $1 AND u.tenant_id = $2"
    )
    .bind(&secret)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    if session.is_none() || session.unwrap().0 != user_pubkey {
        return Err(AuthError::InvalidToken);
    }

    // Get activity log
    let activities: Vec<(i64, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT event_kind, event_content, event_id, created_at
         FROM signing_activity
         WHERE bunker_secret = $1
         ORDER BY created_at DESC
         LIMIT 100"
    )
    .bind(&secret)
    .fetch_all(&pool)
    .await?;

    let activities = activities
        .into_iter()
        .map(|(kind, content, event_id, created_at)| SessionActivity {
            event_kind: kind,
            event_content: content,
            event_id,
            created_at,
        })
        .collect();

    Ok(Json(SessionActivityResponse { activities }))
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionRequest {
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeSessionResponse {
    pub success: bool,
    pub message: String,
}

/// Revoke a bunker session
pub async fn revoke_session(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<RevokeSessionRequest>,
) -> Result<Json<RevokeSessionResponse>, AuthError> {
    // Extract user from UCAN (supports both cookie and Bearer token)
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Revoking bunker session for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Verify this bunker session belongs to the user in this tenant and revoke it
    let result = sqlx::query(
        "UPDATE oauth_authorizations
         SET revoked_at = $1, updated_at = $2
         WHERE secret = $3 AND user_public_key = $4 AND revoked_at IS NULL
         AND user_public_key IN (SELECT public_key FROM users WHERE tenant_id = $5)"
    )
    .bind(Utc::now())
    .bind(Utc::now())
    .bind(&req.secret)
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AuthError::InvalidToken);
    }

    tracing::info!("Successfully revoked bunker session for user: {}", user_pubkey);

    Ok(Json(RevokeSessionResponse {
        success: true,
        message: "Session revoked successfully".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DisconnectClientRequest {
    pub secret: String,
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
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Disconnecting NIP-46 client for user: {} in tenant: {}", user_pubkey, tenant_id);

    let result = sqlx::query(
        "UPDATE oauth_authorizations
         SET connected_client_pubkey = NULL, connected_at = NULL, updated_at = $1
         WHERE secret = $2 AND user_public_key = $3 AND revoked_at IS NULL
         AND user_public_key IN (SELECT public_key FROM users WHERE tenant_id = $4)"
    )
    .bind(Utc::now())
    .bind(&req.secret)
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AuthError::InvalidToken);
    }

    tracing::info!("Successfully disconnected NIP-46 client for user: {}", user_pubkey);

    Ok(Json(DisconnectClientResponse {
        success: true,
        message: "Client disconnected - must reconnect to continue".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct PermissionDetail {
    pub application_name: String,
    pub application_id: i64,
    pub policy_name: String,
    pub policy_id: i64,
    pub allowed_event_kinds: Vec<i16>,
    pub event_kind_names: Vec<String>,
    pub created_at: String,
    pub last_activity: Option<String>,
    pub activity_count: i64,
    pub secret: String,
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
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Listing permissions for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get OAuth authorizations with policy and permission details
    type AuthDataRow = (i64, String, i64, String, String, String, Option<String>, Option<i64>);
    let auth_data: Vec<AuthDataRow> = sqlx::query_as(
        "SELECT
            oa.application_id,
            COALESCE(a.name, 'Personal Bunker') as app_name,
            COALESCE(oa.policy_id, a.policy_id) as policy_id,
            COALESCE(p.name, 'No Policy') as policy_name,
            oa.created_at,
            oa.secret,
            (SELECT MAX(created_at) FROM signing_activity WHERE bunker_secret = oa.secret) as last_activity,
            (SELECT COUNT(*) FROM signing_activity WHERE bunker_secret = oa.secret) as activity_count
         FROM oauth_authorizations oa
         LEFT JOIN oauth_applications a ON oa.application_id = a.id
         LEFT JOIN policies p ON COALESCE(oa.policy_id, a.policy_id) = p.id
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.user_public_key = $1
           AND u.tenant_id = $2
           AND oa.revoked_at IS NULL
         ORDER BY oa.created_at DESC"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_all(&pool)
    .await?;

    let mut permissions = Vec::new();

    for (app_id, app_name, policy_id, policy_name, created_at, secret, last_activity, activity_count) in auth_data {
        // Get allowed event kinds from policy permissions
        let event_kinds: Vec<i16> = if policy_id > 0 {
            let permissions_data: Vec<(String,)> = sqlx::query_as(
                "SELECT p.config FROM permissions p
                 JOIN policy_permissions pp ON p.id = pp.permission_id
                 WHERE pp.policy_id = $1 AND p.identifier = 'allowed_kinds'"
            )
            .bind(policy_id)
            .fetch_all(&pool)
            .await?;

            if let Some((config_json,)) = permissions_data.first() {
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(config_json) {
                    if let Some(kinds_array) = config.get("allowed_kinds").and_then(|v| v.as_array()) {
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
            application_id: app_id,
            policy_name,
            policy_id,
            allowed_event_kinds: event_kinds,
            event_kind_names,
            created_at,
            last_activity,
            activity_count: activity_count.unwrap_or(0),
            secret,
        });
    }

    Ok(Json(PermissionsResponse { permissions }))
}

#[derive(Debug, Deserialize)]
pub struct SignEventRequest {
    pub event: serde_json::Value,  // unsigned event JSON
}

#[derive(Debug, Serialize)]
pub struct SignEventResponse {
    pub signed_event: serde_json::Value,
}

/// Validate that the user has permission to sign this event
/// Returns the policy_id if successful, or an error if unauthorized
async fn validate_signing_permissions(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    event: &UnsignedEvent,
) -> Result<i64, AuthError> {
    // Get the policy_id from the keycast-login OAuth app for this tenant
    let policy_id: Option<i64> = sqlx::query_scalar(
        "SELECT app.policy_id
         FROM oauth_applications app
         WHERE app.client_id = 'keycast-login'
         AND app.tenant_id = $1
         LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let policy_id = policy_id.ok_or_else(|| {
        tracing::warn!("No policy found for user {} in tenant {}", user_pubkey, tenant_id);
        AuthError::InvalidCredentials
    })?;

    // Load permissions for this policy
    let permissions: Vec<Permission> = sqlx::query_as(
        "SELECT p.*
         FROM permissions p
         JOIN policy_permissions pp ON pp.permission_id = p.id
         WHERE pp.tenant_id = $1 AND pp.policy_id = $2"
    )
    .bind(tenant_id)
    .bind(policy_id)
    .fetch_all(pool)
    .await?;

    // Convert to custom permissions
    let custom_permissions: Result<Vec<Box<dyn CustomPermission>>, _> = permissions
        .iter()
        .map(|p| p.to_custom_permission())
        .collect();

    let custom_permissions = custom_permissions
        .map_err(|e| AuthError::Internal(format!("Failed to convert permissions: {}", e)))?;

    // Validate event against all permissions
    let event_kind = event.kind.as_u16();

    for permission in custom_permissions {
        if !permission.can_sign(event) {
            tracing::warn!(
                "Permission denied for user {} to sign event kind {} in tenant {}",
                user_pubkey,
                event_kind,
                tenant_id
            );
            return Err(AuthError::InvalidCredentials);
        }
    }

    tracing::info!(
        "✅ Permission validated for user {} to sign event kind {} in tenant {}",
        user_pubkey,
        event_kind,
        tenant_id
    );

    Ok(policy_id)
}

#[derive(Debug, Serialize)]
pub struct PubkeyResponse {
    pub pubkey: String,  // hex format
    pub npub: String,    // bech32 format
}

/// Fast HTTP signing endpoint - sign an event without NIP-46 relay overhead
/// This is 10-50x faster than NIP-46 for quick operations
pub async fn sign_event(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<SignEventRequest>,
) -> Result<Json<SignEventResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // Parse unsigned event first for validation
    let unsigned_event: UnsignedEvent = serde_json::from_value(req.event.clone())
        .map_err(|e| AuthError::Internal(format!("Invalid event format: {}", e)))?;

    // 🔒 VALIDATE PERMISSIONS BEFORE SIGNING
    validate_signing_permissions(pool, tenant_id, &user_pubkey, &unsigned_event).await?;

    // FAST PATH: Try to use cached signer handler if in unified mode
    if let Some(ref handlers) = auth_state.state.signer_handlers {
        tracing::info!("Attempting fast path signing for user: {} in tenant: {}", user_pubkey, tenant_id);

        // Query for user's bunker public key from OAuth authorization
        let bunker_pubkey: Option<String> = sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_public_key = u.public_key
             WHERE oa.user_public_key = $1 AND u.tenant_id = $2
             AND oa.application_id = (SELECT id FROM oauth_applications WHERE client_id = 'keycast-login')
             AND oa.revoked_at IS NULL
             ORDER BY oa.created_at DESC
             LIMIT 1"
        )
        .bind(&user_pubkey)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        if let Some(bunker_key) = bunker_pubkey {
            let handlers_read = handlers.read().await;
            if let Some(handler) = handlers_read.get(&bunker_key) {
                tracing::info!("✅ Using cached handler for user {}", user_pubkey);

                let signed_event = handler.sign_event_direct(unsigned_event).await
                    .map_err(|e| AuthError::Internal(format!("Signing failed: {}", e)))?;

                let signed_json = serde_json::to_value(&signed_event)
                    .map_err(|e| AuthError::Internal(format!("JSON serialization failed: {}", e)))?;

                tracing::info!("Fast path: Successfully signed event {} for user: {}", signed_event.id, user_pubkey);

                return Ok(Json(SignEventResponse {
                    signed_event: signed_json,
                }));
            }
        }
    }

    // SLOW PATH: Fallback to DB + KMS decryption
    tracing::warn!("⚠️  Handler not cached, using slow path (DB+KMS) for user {}", user_pubkey);

    // Get user's encrypted secret key
    let result: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT pk.encrypted_secret_key
         FROM personal_keys pk
         JOIN users u ON pk.user_public_key = u.public_key
         WHERE pk.user_public_key = $1 AND u.tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let (encrypted_secret,) = result.ok_or(AuthError::UserNotFound)?;

    // Decrypt the secret key (EXPENSIVE KMS OPERATION!)
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Permission validation already done above (before fast path check)
    // Sign the event
    let signed_event = unsigned_event.sign(&keys).await
        .map_err(|e| AuthError::Internal(format!("Signing failed: {}", e)))?;

    // Convert to JSON
    let signed_json = serde_json::to_value(&signed_event)
        .map_err(|e| AuthError::Internal(format!("JSON serialization failed: {}", e)))?;

    tracing::info!("Slow path: Successfully signed event {} for user: {}", signed_event.id, user_pubkey);

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
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;

    tracing::info!("Fetching pubkey for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Verify user exists in this tenant
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT public_key FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    if exists.is_none() {
        return Err(AuthError::UserNotFound);
    }

    // Convert hex pubkey to PublicKey and then to npub
    let pubkey = PublicKey::from_hex(&user_pubkey)
        .map_err(|e| AuthError::Internal(format!("Invalid public key: {}", e)))?;

    let npub = pubkey.to_bech32()
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
pub struct RequestKeyExportResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyExportCodeRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyExportCodeResponse {
    pub export_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ExportKeyRequest {
    pub export_token: String,
    pub format: String,  // "nsec", "ncryptsec", or "mnemonic"
    pub encryption_password: Option<String>,  // Required for ncryptsec
}

#[derive(Debug, Serialize)]
pub struct ExportKeyResponse {
    pub key: String,
}

const KEY_EXPORT_CODE_EXPIRY_MINUTES: i64 = 10;

/// Verify user's password before allowing key export
pub async fn verify_password_for_export(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<VerifyPasswordRequest>,
) -> Result<Json<VerifyPasswordResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;

    // Get user's email and password hash
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT email, password_hash FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (_email, password_hash) = result.ok_or(AuthError::UserNotFound)?;

    // Verify password
    let valid = verify(&req.password, &password_hash)
        .map_err(|_| AuthError::Internal("Password verification failed".to_string()))?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    Ok(Json(VerifyPasswordResponse { success: true }))
}

/// Request key export - sends verification code via email
pub async fn request_key_export(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<RequestKeyExportResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;

    // Get user's email and verification status
    let user: Option<(String, bool)> = sqlx::query_as(
        "SELECT email, email_verified FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (email, email_verified) = user.ok_or(AuthError::UserNotFound)?;

    // Require email verification before allowing key export
    if !email_verified {
        return Err(AuthError::EmailNotVerified);
    }

    // Generate 6-digit verification code
    let code: String = format!("{:06}", rand::thread_rng().gen_range(100000..999999));
    let expires_at = Utc::now() + Duration::minutes(KEY_EXPORT_CODE_EXPIRY_MINUTES);

    // Store code in database
    sqlx::query(
        "INSERT INTO key_export_codes (user_public_key, code, expires_at, created_at)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(&user_pubkey)
    .bind(&code)
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&pool)
    .await?;

    // Send email with code
    if let Ok(email_service) = crate::email_service::EmailService::new() {
        let _ = email_service.send_key_export_code(&email, &code).await;
    }

    Ok(Json(RequestKeyExportResponse {
        success: true,
        message: "Verification code sent to your email".to_string(),
    }))
}

/// Verify export code and return export token
pub async fn verify_export_code(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<VerifyExportCodeRequest>,
) -> Result<Json<VerifyExportCodeResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let _tenant_id = tenant.0.id;

    // Verify code and check expiration
    let result: Option<(String, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT code, expires_at FROM key_export_codes
         WHERE user_public_key = $1 AND code = $2 AND used_at IS NULL
         ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&user_pubkey)
    .bind(&req.code)
    .fetch_optional(&pool)
    .await?;

    let (code, expires_at) = result.ok_or(AuthError::InvalidToken)?;

    if expires_at < Utc::now() {
        return Err(AuthError::TokenExpired);
    }

    // Mark code as used
    sqlx::query(
        "UPDATE key_export_codes SET used_at = $1 WHERE user_public_key = $2 AND code = $3"
    )
    .bind(Utc::now())
    .bind(&user_pubkey)
    .bind(&code)
    .execute(&pool)
    .await?;

    // Generate export token (valid for 5 minutes)
    let export_token = generate_secure_token();
    let token_expires = Utc::now() + Duration::minutes(5);

    sqlx::query(
        "INSERT INTO key_export_tokens (user_public_key, token, expires_at, created_at)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(&user_pubkey)
    .bind(&export_token)
    .bind(token_expires)
    .bind(Utc::now())
    .execute(&pool)
    .await?;

    Ok(Json(VerifyExportCodeResponse { export_token }))
}

/// Export user's private key in requested format
pub async fn export_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<ExportKeyRequest>,
) -> Result<Json<ExportKeyResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // Require email verification
    let email_verified: Option<bool> = sqlx::query_scalar(
        "SELECT email_verified FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    if email_verified != Some(true) {
        return Err(AuthError::EmailNotVerified);
    }

    // Verify export token
    let token_result: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
        "SELECT expires_at FROM key_export_tokens
         WHERE user_public_key = $1 AND token = $2 AND used_at IS NULL"
    )
    .bind(&user_pubkey)
    .bind(&req.export_token)
    .fetch_optional(pool)
    .await?;

    let (token_expires,) = token_result.ok_or(AuthError::InvalidToken)?;

    if token_expires < Utc::now() {
        return Err(AuthError::TokenExpired);
    }

    // Mark token as used
    sqlx::query(
        "UPDATE key_export_tokens SET used_at = $1 WHERE user_public_key = $2 AND token = $3"
    )
    .bind(Utc::now())
    .bind(&user_pubkey)
    .bind(&req.export_token)
    .execute(pool)
    .await?;

    // Get user's encrypted secret key
    let encrypted_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT pk.encrypted_secret_key
         FROM personal_keys pk
         JOIN users u ON pk.user_public_key = u.public_key
         WHERE pk.user_public_key = $1 AND u.tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let encrypted_key = encrypted_key.ok_or(AuthError::UserNotFound)?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_key)
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to decrypt key: {}", e)))?;

    // Parse the secret key
    let keys = Keys::parse(&hex::encode(&decrypted_secret))
        .map_err(|e| AuthError::Internal(format!("Failed to parse key: {}", e)))?;

    // Format the key based on requested format
    let key_string = match req.format.as_str() {
        "nsec" => {
            // Plain nsec format
            keys.secret_key().to_bech32()
                .map_err(|e| AuthError::Internal(format!("Failed to encode nsec: {}", e)))?
        },
        "ncryptsec" => {
            // NIP-49 encrypted format
            let password = req.encryption_password
                .ok_or(AuthError::BadRequest("encryption_password required for ncryptsec format".to_string()))?;

            use nostr_sdk::nips::nip49::{EncryptedSecretKey, KeySecurity};

            let encrypted = EncryptedSecretKey::new(
                keys.secret_key(),
                &password,
                16,  // log_n parameter (2^16 rounds)
                KeySecurity::Unknown,
            ).map_err(|e| AuthError::Internal(format!("Failed to encrypt key: {}", e)))?;

            encrypted.to_bech32()
                .map_err(|e| AuthError::Internal(format!("Failed to encode ncryptsec: {}", e)))?
        },
        "mnemonic" => {
            // BIP-39 mnemonic format
            // Convert the secret key to mnemonic
            // Note: This is a bit tricky - we need to go from secret key to mnemonic
            // The proper way is to generate FROM mnemonic, but we're going backwards
            // For now, we'll generate a mnemonic from the secret key bytes

            let secret_bytes = keys.secret_key().as_secret_bytes();
            let mnemonic = bip39::Mnemonic::from_entropy(secret_bytes)
                .map_err(|e| AuthError::Internal(format!("Failed to generate mnemonic: {}", e)))?;

            mnemonic.to_string()
        },
        _ => {
            return Err(AuthError::BadRequest("Invalid format. Must be 'nsec', 'ncryptsec', or 'mnemonic'".to_string()));
        }
    };

    // Log the export for security audit
    sqlx::query(
        "INSERT INTO key_export_log (user_public_key, format, exported_at) VALUES ($1, $2, $3)"
    )
    .bind(&user_pubkey)
    .bind(&req.format)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(Json(ExportKeyResponse { key: key_string }))
}

#[derive(Debug, Deserialize)]
pub struct ChangeKeyRequest {
    pub password: String,
    pub nsec: Option<String>,  // If None, auto-generate new key
}

#[derive(Debug, Serialize)]
pub struct ChangeKeyResponse {
    pub success: bool,
    pub new_pubkey: String,
    pub message: String,
}

/// Simplified export that only requires password (requires verified email)
pub async fn export_key_simple(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ExportKeyResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // Extract password and format from request
    let password = req.get("password")
        .and_then(|v| v.as_str())
        .ok_or(AuthError::BadRequest("Missing password".to_string()))?;

    let format = req.get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("nsec");

    // Verify password and email verification status
    let result: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT email, password_hash, email_verified FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
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
    let encrypted_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT pk.encrypted_secret_key
         FROM personal_keys pk
         JOIN users u ON pk.user_public_key = u.public_key
         WHERE pk.user_public_key = $1 AND u.tenant_id = $2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let encrypted_key = encrypted_key.ok_or(AuthError::UserNotFound)?;

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
        "nsec" => keys.secret_key().to_bech32()
            .map_err(|e| AuthError::Internal(format!("Failed to encode nsec: {}", e)))?,
        _ => return Err(AuthError::BadRequest("Invalid format. Must be 'nsec'".to_string())),
    };

    // Log the export for security audit
    sqlx::query(
        "INSERT INTO key_export_log (user_public_key, format, exported_at) VALUES ($1, $2, $3)"
    )
    .bind(&user_pubkey)
    .bind(format)
    .bind(Utc::now())
    .execute(pool)
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
) -> Result<Json<ChangeKeyResponse>, AuthError> {
    let old_pubkey = extract_user_from_token(&headers)?;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    // Get user's email and verify password
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT email, password_hash FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&old_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let (email, password_hash) = result.ok_or(AuthError::UserNotFound)?;

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
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT public_key FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&new_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    if exists.is_some() {
        return Err(AuthError::DuplicateKey);
    }

    // Encrypt new secret key (as raw 32 bytes, consistent with registration)
    let encrypted_secret = key_manager
        .encrypt(&new_secret_bytes)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Start transaction
    let mut tx = pool.begin().await?;

    // Count OAuth authorizations that will be deleted (for response message)
    let oauth_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations WHERE user_public_key = $1"
    )
    .bind(&old_pubkey)
    .fetch_one(&mut *tx)
    .await?;

    // Delete OAuth authorizations (we can't sign with old nsec anymore)
    sqlx::query(
        "DELETE FROM oauth_authorizations WHERE user_public_key = $1"
    )
    .bind(&old_pubkey)
    .execute(&mut *tx)
    .await?;

    // Delete old personal_keys (we no longer hold old nsec)
    sqlx::query(
        "DELETE FROM personal_keys WHERE user_public_key = $1"
    )
    .bind(&old_pubkey)
    .execute(&mut *tx)
    .await?;

    // Transfer email/password to NULL on old identity (orphan it)
    sqlx::query(
        "UPDATE users SET email = NULL, password_hash = NULL, updated_at = $1
         WHERE public_key = $2 AND tenant_id = $3"
    )
    .bind(Utc::now())
    .bind(&old_pubkey)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;

    // Create new user identity with email/password
    sqlx::query(
        "INSERT INTO users (public_key, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(&new_pubkey)
    .bind(tenant_id)
    .bind(&email)
    .bind(&password_hash)
    .bind(true)  // Keep email verified status
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    // Create personal_keys for new identity
    sqlx::query(
        "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, created_at, updated_at)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(&new_pubkey)
    .bind(&encrypted_secret)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Signal signer daemon to remove old authorizations
    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx.send(AuthorizationCommand::Remove {
            bunker_pubkey: old_pubkey.clone(),
        }).await {
            tracing::error!("Failed to send authorization remove command: {}", e);
        }
    }

    tracing::info!(
        "Successfully changed key for user {} → {} (deleted {} OAuth authorizations)",
        old_pubkey, new_pubkey, oauth_count
    );

    Ok(Json(ChangeKeyResponse {
        success: true,
        new_pubkey: new_pubkey.clone(),
        message: format!(
            "Private key changed successfully. Deleted {} connected app(s). Your old identity ({}) still exists in teams if you backed up the old key.",
            oauth_count,
            &old_pubkey[..16]
        ),
    }))
}

#[cfg(test)]
mod tests {
    use keycast_core::encryption::file_key_manager::FileKeyManager;
    use keycast_core::encryption::KeyManager;
    use keycast_core::signing_handler::SigningHandler;
    use nostr_sdk::{Keys, UnsignedEvent, Kind, Timestamp};
    use sqlx::PgPool;

    /// Helper to create test database with schema
    /// Uses the existing test database which already has migrations applied
    async fn create_test_db() -> PgPool {
        PgPool::connect("postgres://postgres:password@localhost/keycast_test").await.unwrap()
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
            let signed = unsigned_event.sign(&self.user_keys).await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(signed)
        }

        fn authorization_id(&self) -> i64 {
            self.auth_id
        }

        fn user_public_key(&self) -> String {
            self.user_keys.public_key().to_hex()
        }
    }

    #[tokio::test]
    #[ignore] // TODO: Needs database isolation for PostgreSQL
    async fn test_fast_path_components() {
        // Test that all fast path components work correctly
        let pool = create_test_db().await;
        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();

        // Insert test user
        sqlx::query("INSERT INTO users (public_key, tenant_id) VALUES ($1, 1)")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();

        // Insert OAuth application
        sqlx::query("INSERT INTO oauth_applications (id, tenant_id, client_id, client_secret, redirect_uris, name) VALUES (1, 1, 'keycast-login', 'test-secret', '[]', 'Keycast Login')")
            .execute(&pool)
            .await
            .unwrap();

        // Insert OAuth authorization
        let bunker_keys = Keys::generate();
        let bunker_pubkey = bunker_keys.public_key().to_hex();

        sqlx::query(
            "INSERT INTO oauth_authorizations (user_public_key, application_id, bunker_public_key, bunker_secret, secret)
             VALUES ($1, 1, ?, X'00', 'test-secret')"
        )
        .bind(&user_pubkey)
        .bind(&bunker_pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // Verify we can query bunker_public_key (fast path lookup)
        let result: Option<String> = sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_public_key = u.public_key
             WHERE oa.user_public_key = $1 AND u.tenant_id = 1
             AND oa.application_id = (SELECT id FROM oauth_applications WHERE client_id = 'keycast-login')
             AND oa.revoked_at IS NULL
             ORDER BY oa.created_at DESC
             LIMIT 1"
        )
        .bind(&user_pubkey)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert_eq!(result, Some(bunker_pubkey), "Should find bunker pubkey for fast path");

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
            "Test fast path"
        );

        let signed = mock_handler.sign_event_direct(unsigned).await.unwrap();
        assert!(signed.verify().is_ok());

        println!("✅ Fast path components test passed");
    }

    #[tokio::test]
    #[ignore] // TODO: Needs database isolation for PostgreSQL
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
        sqlx::query("INSERT INTO users (public_key, tenant_id) VALUES ($1, 1)")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();

        // Insert personal keys
        sqlx::query("INSERT INTO personal_keys (user_public_key, encrypted_secret_key) VALUES ($1, ?)")
            .bind(&user_pubkey)
            .bind(&encrypted_secret)
            .execute(&pool)
            .await
            .unwrap();

        // Test slow path: DB query
        let result: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT pk.encrypted_secret_key
             FROM personal_keys pk
             JOIN users u ON pk.user_public_key = u.public_key
             WHERE pk.user_public_key = $1 AND u.tenant_id = 1"
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
            "Test slow path"
        );

        let signed = unsigned.sign(&recovered_keys).await.unwrap();
        assert!(signed.verify().is_ok());

        println!("✅ Slow path components test passed");
    }

    #[tokio::test]
    #[ignore] // TODO: Needs database isolation for PostgreSQL
    async fn test_fallback_when_handler_not_cached() {
        // Test that system falls back to slow path when handler not in cache
        let pool = create_test_db().await;
        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();

        // Insert user but NO OAuth authorization
        sqlx::query("INSERT INTO users (public_key, tenant_id) VALUES ($1, 1)")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();

        // Query for bunker_pubkey should return None
        let bunker_pubkey: Option<String> = sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_public_key = u.public_key
             WHERE oa.user_public_key = $1 AND u.tenant_id = 1"
        )
        .bind(&user_pubkey)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(bunker_pubkey.is_none(), "Should not find OAuth authorization for fallback");

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
            "Test signature"
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
            Kind::TextNote,  // Kind 1 - should be allowed
            vec![],
            "This is a normal text note"
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
                format!("Test {}", name)
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
            normal_content
        );

        let signed = unsigned_normal.sign(&user_keys).await.unwrap();
        assert!(signed.verify().is_ok());

        // Test very long content (currently no limit, but we might want one)
        let long_content = "x".repeat(100_000);  // 100KB of text
        let unsigned_long = UnsignedEvent::new(
            user_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            vec![],
            &long_content
        );

        let signed_long = unsigned_long.sign(&user_keys).await.unwrap();
        assert!(signed_long.verify().is_ok());

        // NOTE: Content length validation not implemented yet (would need new permission type)
        // Current permissions: allowed_kinds, content_filter (word blocking), encrypt_to_self
        println!("✅ Content length validation tested");
    }
}

