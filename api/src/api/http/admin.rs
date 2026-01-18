// ABOUTME: Admin endpoints for preloaded accounts and claim token generation
// ABOUTME: Used for Vine import and support workflows

use axum::{extract::State, Json};
use chrono::{Duration, Utc};
use nostr_sdk::Keys;
use serde::{Deserialize, Serialize};

use super::routes::AuthState;
use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use keycast_core::repositories::{ClaimTokenRepository, UserRepository};
use keycast_core::types::claim_token::generate_claim_token;

/// Admin token expiry in days (30 days for long-lived admin tokens)
const ADMIN_TOKEN_EXPIRY_DAYS: i64 = 30;

/// Preloaded user signing token expiry in days
const PRELOAD_TOKEN_EXPIRY_DAYS: i64 = 30;

/// Check if a pubkey is in the ALLOWED_PUBKEYS whitelist
pub fn is_admin_pubkey(pubkey: &str) -> bool {
    if let Ok(allowed_pubkeys) = std::env::var("ALLOWED_PUBKEYS") {
        if !allowed_pubkeys.is_empty() {
            let allowed: Vec<&str> = allowed_pubkeys.split(',').map(|s| s.trim()).collect();
            return allowed.contains(&pubkey);
        }
    }
    false
}

/// Get server keys from SERVER_NSEC environment variable
fn get_server_keys() -> Result<Keys, ApiError> {
    let server_nsec = std::env::var("SERVER_NSEC")
        .map_err(|_| ApiError::Internal("SERVER_NSEC not configured".to_string()))?;
    Keys::parse(&server_nsec).map_err(|e| ApiError::Internal(format!("Invalid SERVER_NSEC: {}", e)))
}

// ============================================================================
// GET /api/admin/status - Check if current user is admin
// ============================================================================

#[derive(Debug, Serialize)]
pub struct AdminStatusResponse {
    pub is_admin: bool,
}

/// Check if the current user is in the admin whitelist.
/// Returns { is_admin: true/false } - never errors for valid auth.
pub async fn get_admin_status(
    _tenant: crate::api::tenant::TenantExtractor,
    UcanAuth(user_pubkey_hex): UcanAuth,
) -> ApiResult<Json<AdminStatusResponse>> {
    let is_admin = is_admin_pubkey(&user_pubkey_hex);
    Ok(Json(AdminStatusResponse { is_admin }))
}

// ============================================================================
// GET /api/admin/token - Generate admin API token
// ============================================================================

#[derive(Debug, Serialize)]
pub struct AdminTokenResponse {
    pub token: String,
    pub expires_at: String,
}

/// Generate a long-lived admin API token for use in scripts.
/// Requires the user to be logged in and be in the ALLOWED_PUBKEYS whitelist.
pub async fn get_admin_token(
    tenant: crate::api::tenant::TenantExtractor,
    UcanAuth(user_pubkey_hex): UcanAuth,
) -> ApiResult<Json<AdminTokenResponse>> {
    let tenant_id = tenant.0.id;

    // Check if user is in admin whitelist
    if !is_admin_pubkey(&user_pubkey_hex) {
        tracing::warn!(
            "Admin token request denied for non-whitelisted pubkey: {}",
            &user_pubkey_hex[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    let server_keys = get_server_keys()?;
    let user_pubkey = nostr_sdk::PublicKey::from_hex(&user_pubkey_hex)
        .map_err(|e| ApiError::bad_request(format!("Invalid pubkey: {}", e)))?;

    // Generate admin token with longer expiry
    let token = generate_admin_ucan(&user_pubkey, tenant_id, &server_keys).await?;
    let expires_at = Utc::now() + Duration::days(ADMIN_TOKEN_EXPIRY_DAYS);

    tracing::info!(
        "Admin token generated for pubkey: {}",
        &user_pubkey_hex[..8]
    );

    Ok(Json(AdminTokenResponse {
        token,
        expires_at: expires_at.to_rfc3339(),
    }))
}

/// Generate admin UCAN token (server-signed, for admin's pubkey)
async fn generate_admin_ucan(
    admin_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    server_keys: &Keys,
) -> Result<String, ApiError> {
    use crate::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let server_key_material = NostrKeyMaterial::from_keys(server_keys.clone());
    let admin_did = nostr_pubkey_to_did(admin_pubkey);

    let facts = json!({
        "tenant_id": tenant_id,
        "redirect_origin": "admin",
        "admin": true,
    });

    let expiry_seconds = ADMIN_TOKEN_EXPIRY_DAYS * 24 * 3600;

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)
        .for_audience(&admin_did)
        .with_lifetime(expiry_seconds as u64)
        .with_fact(facts)
        .build()
        .map_err(|e| ApiError::Internal(format!("Failed to build UCAN: {}", e)))?
        .sign()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to sign UCAN: {}", e)))?;

    ucan.encode()
        .map_err(|e| ApiError::Internal(format!("Failed to encode UCAN: {}", e)))
}

// ============================================================================
// POST /api/admin/preload-user - Create preloaded user
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PreloadUserRequest {
    pub vine_id: String,
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PreloadUserResponse {
    pub pubkey: String,
    pub token: String,
}

/// Create a preloaded user and return a signing token.
/// Requires admin authentication (server-signed UCAN with admin in whitelist).
pub async fn preload_user(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    UcanAuth(admin_pubkey_hex): UcanAuth,
    Json(req): Json<PreloadUserRequest>,
) -> ApiResult<Json<PreloadUserResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Check if caller is admin
    if !is_admin_pubkey(&admin_pubkey_hex) {
        tracing::warn!(
            "Preload user request denied for non-whitelisted pubkey: {}",
            &admin_pubkey_hex[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    // Check if vine_id already exists
    let user_repo = UserRepository::new(pool.clone());
    if let Some(_existing) = user_repo
        .find_pubkey_by_vine_id(&req.vine_id, tenant_id)
        .await?
    {
        return Err(ApiError::conflict(format!(
            "User with vine_id {} already exists",
            req.vine_id
        )));
    }

    // Check if username already exists
    if let Some(_existing) = user_repo
        .find_pubkey_by_username(&req.username, tenant_id)
        .await?
    {
        return Err(ApiError::conflict(format!(
            "User with username {} already exists",
            req.username
        )));
    }

    // Generate new keypair
    let keys = Keys::generate();
    let pubkey = keys.public_key();
    let pubkey_hex = pubkey.to_hex();

    // Encrypt secret key
    let secret_bytes = keys.secret_key().to_secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&secret_bytes)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to encrypt secret: {}", e)))?;

    // Create preloaded user
    user_repo
        .create_preloaded_user(
            &pubkey_hex,
            tenant_id,
            &req.vine_id,
            &req.username,
            req.display_name.as_deref(),
            &encrypted_secret,
        )
        .await?;

    // Generate signing token for this user (server-signed UCAN)
    let server_keys = get_server_keys()?;
    let token = generate_preload_ucan(&pubkey, tenant_id, &server_keys).await?;

    tracing::info!(
        "Preloaded user created: vine_id={}, username={}, pubkey={}",
        req.vine_id,
        req.username,
        &pubkey_hex[..8]
    );

    Ok(Json(PreloadUserResponse {
        pubkey: pubkey_hex,
        token,
    }))
}

/// Generate UCAN for preloaded user signing (server-signed, for user's pubkey)
async fn generate_preload_ucan(
    user_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    server_keys: &Keys,
) -> Result<String, ApiError> {
    use crate::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use serde_json::json;
    use ucan::builder::UcanBuilder;

    let server_key_material = NostrKeyMaterial::from_keys(server_keys.clone());
    let user_did = nostr_pubkey_to_did(user_pubkey);

    // No bunker_pubkey = preloaded user mode (detected in nostr_rpc.rs)
    let facts = json!({
        "tenant_id": tenant_id,
        "redirect_origin": "preload",
    });

    let expiry_seconds = PRELOAD_TOKEN_EXPIRY_DAYS * 24 * 3600;

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)
        .for_audience(&user_did)
        .with_lifetime(expiry_seconds as u64)
        .with_fact(facts)
        .build()
        .map_err(|e| ApiError::Internal(format!("Failed to build UCAN: {}", e)))?
        .sign()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to sign UCAN: {}", e)))?;

    ucan.encode()
        .map_err(|e| ApiError::Internal(format!("Failed to encode UCAN: {}", e)))
}

// ============================================================================
// POST /api/admin/claim-tokens - Generate claim link
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateClaimTokenRequest {
    pub vine_id: String,
}

#[derive(Debug, Serialize)]
pub struct CreateClaimTokenResponse {
    pub claim_url: String,
    pub expires_at: String,
}

/// Generate a claim link for a preloaded user.
/// Requires admin authentication.
pub async fn create_claim_token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    UcanAuth(admin_pubkey_hex): UcanAuth,
    Json(req): Json<CreateClaimTokenRequest>,
) -> ApiResult<Json<CreateClaimTokenResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Check if caller is admin
    if !is_admin_pubkey(&admin_pubkey_hex) {
        tracing::warn!(
            "Claim token request denied for non-whitelisted pubkey: {}",
            &admin_pubkey_hex[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    // Find user by vine_id
    let user_repo = UserRepository::new(pool.clone());
    let user_pubkey = user_repo
        .find_pubkey_by_vine_id(&req.vine_id, tenant_id)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("User with vine_id {} not found", req.vine_id))
        })?;

    // Check user is unclaimed
    let is_unclaimed = user_repo.is_unclaimed(&user_pubkey, tenant_id).await?;
    if is_unclaimed != Some(true) {
        return Err(ApiError::conflict("User has already claimed their account"));
    }

    // Generate claim token
    let token = generate_claim_token();
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let claim_token = claim_token_repo
        .create(&token, &user_pubkey, Some(&admin_pubkey_hex), tenant_id)
        .await?;

    // Build claim URL
    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let claim_url = format!("{}/api/claim?token={}", app_url, token);

    tracing::info!(
        "Claim token created for vine_id={}, by admin={}",
        req.vine_id,
        &admin_pubkey_hex[..8]
    );

    Ok(Json(CreateClaimTokenResponse {
        claim_url,
        expires_at: claim_token.expires_at.to_rfc3339(),
    }))
}
