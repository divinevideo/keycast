// ABOUTME: Admin endpoints for preloaded accounts, claim token generation, and support admin management
// ABOUTME: Used for Vine import and support workflows

use axum::extract::{Path, State};
use axum::Json;
use chrono::{Duration, Utc};
use nostr_sdk::{FromBech32, Keys};
use serde::{Deserialize, Serialize};

use super::routes::AuthState;
use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use keycast_core::repositories::{
    ClaimTokenRepository, OAuthAuthorizationRepository, UserRepository,
};
use keycast_core::types::claim_token::generate_claim_token;

/// Admin token expiry in days (30 days for long-lived admin tokens)
const ADMIN_TOKEN_EXPIRY_DAYS: i64 = 30;

/// Preloaded user signing token expiry in days
const PRELOAD_TOKEN_EXPIRY_DAYS: i64 = 30;

/// Redis key for the support admins set
const SUPPORT_ADMINS_KEY: &str = "support_admins";

/// Full admin: has admin_role == "full" in UCAN, or pubkey in ALLOWED_PUBKEYS whitelist.
/// Full admins can access all admin endpoints including token generation and user preloading.
pub fn is_full_admin(auth: &UcanAuth) -> bool {
    if auth.admin_role.as_deref() == Some("full") {
        return true;
    }
    // Backwards compat: existing tokens without admin_role that have pubkey in whitelist
    if let Ok(allowed_pubkeys) = std::env::var("ALLOWED_PUBKEYS") {
        if !allowed_pubkeys.is_empty() {
            let allowed: Vec<&str> = allowed_pubkeys.split(',').map(|s| s.trim()).collect();
            if allowed.contains(&auth.pubkey.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Support admin or above: pubkey is in Redis support_admins set, or a full admin.
/// Support admins can access user lookup and read-only support tools.
pub async fn is_support_admin(auth: &UcanAuth) -> bool {
    if is_full_admin(auth) {
        return true;
    }
    if auth.admin_role.as_deref() == Some("support") {
        return true;
    }
    // Check Redis
    if let Ok(state) = crate::state::get_keycast_state() {
        if let Some(redis) = &state.redis {
            match redis::cmd("SISMEMBER")
                .arg(SUPPORT_ADMINS_KEY)
                .arg(&auth.pubkey)
                .query_async::<bool>(&mut redis.clone())
                .await
            {
                Ok(true) => return true,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!("Redis SISMEMBER failed for support admin check: {}", e);
                }
            }
        }
    }
    false
}

/// Determine the admin role string for a user (for status response).
async fn admin_role_for(auth: &UcanAuth) -> Option<&str> {
    if is_full_admin(auth) {
        Some("full")
    } else if is_support_admin(auth).await {
        Some("support")
    } else {
        None
    }
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
    /// "full", "support", or null
    pub role: Option<String>,
}

/// Check if the current user has admin privileges.
/// Returns { is_admin: true/false, role: "full"|"support"|null }.
pub async fn get_admin_status(
    _tenant: crate::api::tenant::TenantExtractor,
    auth: UcanAuth,
) -> ApiResult<Json<AdminStatusResponse>> {
    let role = admin_role_for(&auth).await;
    Ok(Json(AdminStatusResponse {
        is_admin: role.is_some(),
        role: role.map(String::from),
    }))
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
    auth: UcanAuth,
) -> ApiResult<Json<AdminTokenResponse>> {
    let tenant_id = tenant.0.id;

    if !is_full_admin(&auth) {
        tracing::warn!(
            "Admin token request denied for pubkey: {}",
            &auth.pubkey[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    let server_keys = get_server_keys()?;
    let user_pubkey = nostr_sdk::PublicKey::from_hex(&auth.pubkey)
        .map_err(|e| ApiError::bad_request(format!("Invalid pubkey: {}", e)))?;

    let token = generate_admin_ucan(&user_pubkey, tenant_id, &server_keys).await?;
    let expires_at = Utc::now() + Duration::days(ADMIN_TOKEN_EXPIRY_DAYS);

    tracing::info!("Admin token generated for pubkey: {}", &auth.pubkey[..8]);

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
        "admin_role": "full",
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
    auth: UcanAuth,
    Json(req): Json<PreloadUserRequest>,
) -> ApiResult<Json<PreloadUserResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    if !is_full_admin(&auth) {
        tracing::warn!(
            "Preload user request denied for pubkey: {}",
            &auth.pubkey[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    let server_keys = get_server_keys()?;

    // Check if vine_id already exists (idempotent)
    let user_repo = UserRepository::new(pool.clone());
    if let Some(existing_pubkey) = user_repo
        .find_pubkey_by_vine_id(&req.vine_id, tenant_id)
        .await?
    {
        let existing_user_pubkey = nostr_sdk::PublicKey::from_hex(&existing_pubkey)
            .map_err(|e| ApiError::Internal(format!("Invalid stored pubkey: {}", e)))?;

        let token =
            generate_preload_ucan(&existing_user_pubkey, tenant_id, &server_keys, &auth.pubkey)
                .await?;

        tracing::info!(
            "Returning existing preloaded user for vine_id '{}': {}",
            req.vine_id,
            &existing_pubkey[..8]
        );

        return Ok(Json(PreloadUserResponse {
            pubkey: existing_pubkey,
            token,
        }));
    }

    // Check if username already exists (different vine_id but same username)
    if user_repo
        .find_pubkey_by_username(&req.username, tenant_id)
        .await?
        .is_some()
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

    // Claim username on divine-name-server (best-effort, don't fail preload)
    if crate::divine_names::is_enabled() {
        match crate::divine_names::claim_username(&keys, &req.username, None).await {
            Ok(response) if response.ok => {
                tracing::info!("Username '{}' claimed on divine-name-server", req.username);
            }
            Ok(response) => {
                tracing::warn!(
                    "Username '{}' claim failed: {}",
                    req.username,
                    response.error.unwrap_or_default()
                );
            }
            Err(e) => {
                tracing::warn!("divine-name-server error for '{}': {}", req.username, e);
            }
        }
    }

    let token = generate_preload_ucan(&pubkey, tenant_id, &server_keys, &auth.pubkey).await?;

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

// ============================================================================
// POST /api/admin/user-token - Get signing token for existing preloaded user
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UserTokenRequest {
    pub pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct UserTokenResponse {
    pub token: String,
}

/// Get a signing token for an existing preloaded (unclaimed) user.
/// Requires admin authentication. Only works for users who have not claimed their account.
pub async fn get_user_token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<UserTokenRequest>,
) -> ApiResult<Json<UserTokenResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_full_admin(&auth) {
        tracing::warn!(
            "User token request denied for pubkey: {}",
            &auth.pubkey[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    let user_pubkey = nostr_sdk::PublicKey::from_hex(&req.pubkey)
        .map_err(|e| ApiError::bad_request(format!("Invalid pubkey: {}", e)))?;

    // Check user exists and is unclaimed
    let user_repo = UserRepository::new(pool.clone());
    let is_unclaimed = user_repo.is_unclaimed(&req.pubkey, tenant_id).await?;

    match is_unclaimed {
        None => {
            return Err(ApiError::not_found(format!(
                "User with pubkey {} not found",
                &req.pubkey[..8]
            )));
        }
        Some(false) => {
            return Err(ApiError::forbidden(
                "Cannot generate token for claimed user",
            ));
        }
        Some(true) => {} // User exists and is unclaimed, proceed
    }

    let server_keys = get_server_keys()?;
    let token = generate_preload_ucan(&user_pubkey, tenant_id, &server_keys, &auth.pubkey).await?;

    tracing::info!(
        "User token generated for pubkey: {} by admin: {}",
        &req.pubkey[..8],
        &auth.pubkey[..8]
    );

    Ok(Json(UserTokenResponse { token }))
}

/// Generate UCAN for preloaded user signing (server-signed, for user's pubkey)
async fn generate_preload_ucan(
    user_pubkey: &nostr_sdk::PublicKey,
    tenant_id: i64,
    server_keys: &Keys,
    admin_pubkey_hex: &str,
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
        "issued_by_admin": admin_pubkey_hex,
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

// ============================================================================
// GET /api/admin/claim-tokens?pubkey=... - Check existing valid claim token
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GetClaimTokenQuery {
    pub pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct GetClaimTokenResponse {
    pub has_token: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

pub async fn get_claim_token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    axum::extract::Query(query): axum::extract::Query<GetClaimTokenQuery>,
) -> ApiResult<Json<GetClaimTokenResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_support_admin(&auth).await {
        return Err(ApiError::forbidden("Admin access required"));
    }

    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let token = claim_token_repo
        .find_valid_by_user_pubkey(&query.pubkey, tenant_id)
        .await?;

    match token {
        Some(ct) => {
            let app_url =
                std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
            let claim_url = format!("{}/api/claim?token={}", app_url, ct.token);

            Ok(Json(GetClaimTokenResponse {
                has_token: true,
                claim_url: Some(claim_url),
                expires_at: Some(ct.expires_at.to_rfc3339()),
            }))
        }
        None => Ok(Json(GetClaimTokenResponse {
            has_token: false,
            claim_url: None,
            expires_at: None,
        })),
    }
}

/// Generate a claim link for a preloaded user.
/// Requires support admin or above.
pub async fn create_claim_token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<CreateClaimTokenRequest>,
) -> ApiResult<Json<CreateClaimTokenResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_support_admin(&auth).await {
        tracing::warn!(
            "Claim token request denied for pubkey: {}",
            &auth.pubkey[..8]
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
        .create(&token, &user_pubkey, Some(&auth.pubkey), tenant_id)
        .await?;

    // Build claim URL
    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let claim_url = format!("{}/api/claim?token={}", app_url, token);

    tracing::info!(
        "Claim token created for vine_id={}, by admin={}",
        req.vine_id,
        &auth.pubkey[..8]
    );

    Ok(Json(CreateClaimTokenResponse {
        claim_url,
        expires_at: claim_token.expires_at.to_rfc3339(),
    }))
}

// ============================================================================
// POST /api/admin/claim-tokens/batch - Generate claim links in bulk
// ============================================================================

/// Maximum number of vine_ids allowed in a single batch request
const BATCH_CLAIM_LIMIT: usize = 100;

#[derive(Debug, Deserialize)]
pub struct BatchCreateClaimTokensRequest {
    pub vine_ids: Vec<String>,
    /// If provided, send claim links to this email address for all tokens
    pub delivery_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchClaimTokenEntry {
    pub vine_id: String,
    pub claim_url: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct BatchSkippedEntry {
    pub vine_id: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct BatchCreateClaimTokensResponse {
    pub tokens: Vec<BatchClaimTokenEntry>,
    pub skipped: Vec<BatchSkippedEntry>,
    pub errors: Vec<String>,
}

pub async fn batch_create_claim_tokens(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<BatchCreateClaimTokensRequest>,
) -> ApiResult<Json<BatchCreateClaimTokensResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_support_admin(&auth).await {
        tracing::warn!(
            "Batch claim token request denied for pubkey: {}",
            &auth.pubkey[..8]
        );
        return Err(ApiError::forbidden("Admin access required"));
    }

    // Validate delivery email if provided
    if let Some(ref email) = req.delivery_email {
        if !email.contains('@') || email.len() < 3 {
            return Err(ApiError::bad_request("Invalid delivery_email format"));
        }
    }

    // Dedup vine_ids to prevent creating multiple tokens for the same user
    let mut seen = std::collections::HashSet::new();
    let vine_ids: Vec<String> = req
        .vine_ids
        .into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect();

    if vine_ids.is_empty() {
        return Err(ApiError::bad_request("vine_ids must not be empty"));
    }

    if vine_ids.len() > BATCH_CLAIM_LIMIT {
        return Err(ApiError::bad_request(format!(
            "vine_ids exceeds maximum batch size of {}",
            BATCH_CLAIM_LIMIT
        )));
    }

    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let user_repo = UserRepository::new(pool.clone());
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());

    // Create email service once outside the loop
    let email_service =
        req.delivery_email
            .as_ref()
            .and_then(|_| match crate::email_service::EmailService::new() {
                Ok(svc) => Some(svc),
                Err(e) => {
                    tracing::error!("Failed to create email service: {}", e);
                    None
                }
            });

    let mut tokens = Vec::new();
    let mut skipped = Vec::new();
    let mut errors = Vec::new();

    for vine_id in &vine_ids {
        // Find user by vine_id
        let user_pubkey = match user_repo.find_pubkey_by_vine_id(vine_id, tenant_id).await {
            Ok(Some(pk)) => pk,
            Ok(None) => {
                skipped.push(BatchSkippedEntry {
                    vine_id: vine_id.clone(),
                    reason: "user not found".to_string(),
                });
                continue;
            }
            Err(e) => {
                errors.push(format!("vine_id {}: database error: {}", vine_id, e));
                continue;
            }
        };

        // Skip already-claimed users
        match user_repo.is_unclaimed(&user_pubkey, tenant_id).await {
            Ok(Some(true)) => {} // unclaimed - proceed
            Ok(_) => {
                skipped.push(BatchSkippedEntry {
                    vine_id: vine_id.clone(),
                    reason: "already claimed".to_string(),
                });
                continue;
            }
            Err(e) => {
                errors.push(format!(
                    "vine_id {}: failed to check claim status: {}",
                    vine_id, e
                ));
                continue;
            }
        }

        // Skip if user already has a valid (unexpired, unused) claim token
        match claim_token_repo
            .find_valid_by_user_pubkey(&user_pubkey, tenant_id)
            .await
        {
            Ok(Some(_)) => {
                skipped.push(BatchSkippedEntry {
                    vine_id: vine_id.clone(),
                    reason: "valid claim token already exists".to_string(),
                });
                continue;
            }
            Ok(None) => {} // no existing token - proceed
            Err(e) => {
                errors.push(format!(
                    "vine_id {}: failed to check existing tokens: {}",
                    vine_id, e
                ));
                continue;
            }
        }

        // Generate and persist claim token
        let token = generate_claim_token();
        let claim_token = match claim_token_repo
            .create(&token, &user_pubkey, Some(&auth.pubkey), tenant_id)
            .await
        {
            Ok(ct) => ct,
            Err(e) => {
                errors.push(format!(
                    "vine_id {}: failed to create token: {}",
                    vine_id, e
                ));
                continue;
            }
        };

        let claim_url = format!("{}/api/claim?token={}", app_url, token);

        // Send email if requested
        if let (Some(email), Some(svc)) = (&req.delivery_email, &email_service) {
            if let Err(e) = svc.send_claim_email(email, &claim_url).await {
                tracing::warn!(
                    "Failed to send claim email for vine_id={} to {}: {}",
                    vine_id,
                    email,
                    e
                );
                errors.push(format!("vine_id {}: email delivery failed: {}", vine_id, e));
            }
        } else if req.delivery_email.is_some() && email_service.is_none() {
            errors.push(format!("vine_id {}: email service unavailable", vine_id));
        }

        tokens.push(BatchClaimTokenEntry {
            vine_id: vine_id.clone(),
            claim_url,
            expires_at: claim_token.expires_at.to_rfc3339(),
        });
    }

    tracing::info!(
        "Batch claim tokens: generated={}, skipped={}, errors={}, by admin={}",
        tokens.len(),
        skipped.len(),
        errors.len(),
        &auth.pubkey[..8]
    );

    Ok(Json(BatchCreateClaimTokensResponse {
        tokens,
        skipped,
        errors,
    }))
}

// ============================================================================
// GET /api/admin/claim-tokens/stats - Aggregate claim token statistics
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ClaimTokenStatsResponse {
    pub total_generated: i64,
    pub total_claimed: i64,
    pub total_expired: i64,
    pub total_pending: i64,
}

pub async fn get_claim_token_stats(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
) -> ApiResult<Json<ClaimTokenStatsResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_support_admin(&auth).await {
        return Err(ApiError::forbidden("Admin access required"));
    }

    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let stats = claim_token_repo.get_stats(tenant_id).await?;

    Ok(Json(ClaimTokenStatsResponse {
        total_generated: stats.total_generated,
        total_claimed: stats.total_claimed,
        total_expired: stats.total_expired,
        total_pending: stats.total_pending,
    }))
}

// ============================================================================
// GET /api/admin/user-lookup?q=<email_or_pubkey> - Look up user details
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UserLookupQuery {
    pub q: String,
}

#[derive(Debug, Serialize)]
pub struct UserLookupResponse {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserLookupDetails>,
}

#[derive(Debug, Serialize)]
pub struct UserLookupDetails {
    pub pubkey: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub vine_id: Option<String>,
    pub has_personal_key: bool,
    pub active_sessions: i64,
    pub created_at: String,
    pub last_active: Option<String>,
}

/// Look up a user by email or pubkey. Available to support admins and above.
pub async fn get_user_lookup(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    axum::extract::Query(query): axum::extract::Query<UserLookupQuery>,
) -> ApiResult<Json<UserLookupResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_support_admin(&auth).await {
        return Err(ApiError::forbidden("Admin access required"));
    }

    let q = query.q.trim();
    if q.is_empty() {
        return Err(ApiError::bad_request("Query parameter 'q' is required"));
    }

    let user_repo = UserRepository::new(pool.clone());
    let result = user_repo.find_user_for_admin(q, tenant_id).await?;

    match result {
        None => Ok(Json(UserLookupResponse {
            found: false,
            user: None,
        })),
        Some(details) => {
            // Count active sessions and find most recent activity
            let oauth_repo = OAuthAuthorizationRepository::new(pool.clone());
            let sessions = oauth_repo
                .list_active_sessions(&details.pubkey, tenant_id)
                .await
                .unwrap_or_default();

            let last_active = sessions
                .iter()
                .filter_map(|s| s.5.as_deref())
                .max()
                .map(String::from);

            Ok(Json(UserLookupResponse {
                found: true,
                user: Some(UserLookupDetails {
                    pubkey: details.pubkey,
                    email: details.email,
                    email_verified: details.email_verified,
                    username: details.username,
                    display_name: details.display_name,
                    vine_id: details.vine_id,
                    has_personal_key: details.has_personal_key,
                    active_sessions: sessions.len() as i64,
                    created_at: details.created_at.to_rfc3339(),
                    last_active,
                }),
            }))
        }
    }
}

// ============================================================================
// Support Admin Management (Redis-backed)
// ============================================================================

#[derive(Debug, Serialize)]
pub struct SupportAdminEntry {
    pub pubkey: String,
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SupportAdminsResponse {
    pub admins: Vec<SupportAdminEntry>,
}

/// List all support admins with email info. Full admin only.
pub async fn list_support_admins(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
) -> ApiResult<Json<SupportAdminsResponse>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    let state = crate::state::get_keycast_state()
        .map_err(|_| ApiError::Internal("State not initialized".to_string()))?;

    let redis = state
        .redis
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Redis not available".to_string()))?;

    let pubkeys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(SUPPORT_ADMINS_KEY)
        .query_async(&mut redis.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Redis error: {}", e)))?;

    // Look up emails for all pubkeys in one query
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT pubkey, email FROM users WHERE pubkey = ANY($1) AND tenant_id = $2")
            .bind(&pubkeys)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let email_map: std::collections::HashMap<String, Option<String>> = rows.into_iter().collect();

    let admins = pubkeys
        .into_iter()
        .map(|pk| SupportAdminEntry {
            email: email_map.get(&pk).cloned().flatten(),
            pubkey: pk,
        })
        .collect();

    Ok(Json(SupportAdminsResponse { admins }))
}

#[derive(Debug, Deserialize)]
pub struct AddSupportAdminRequest {
    /// npub1..., 64-char hex pubkey, or email address
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct AddSupportAdminResponse {
    pub pubkey: String,
    pub added: bool,
}

/// Add a support admin by pubkey, npub, or email. Full admin only.
pub async fn add_support_admin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<AddSupportAdminRequest>,
) -> ApiResult<Json<AddSupportAdminResponse>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    let identifier = req.identifier.trim();
    if identifier.is_empty() {
        return Err(ApiError::bad_request("Identifier is required"));
    }

    // Resolve identifier to hex pubkey
    let pubkey_hex = resolve_identifier(identifier, &auth_state, tenant.0.id).await?;

    let state = crate::state::get_keycast_state()
        .map_err(|_| ApiError::Internal("State not initialized".to_string()))?;

    let redis = state
        .redis
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Redis not available".to_string()))?;

    let added: i64 = redis::cmd("SADD")
        .arg(SUPPORT_ADMINS_KEY)
        .arg(&pubkey_hex)
        .query_async(&mut redis.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Redis error: {}", e)))?;

    tracing::info!(
        "Support admin added: {} (by admin {})",
        &pubkey_hex[..8],
        &auth.pubkey[..8]
    );

    Ok(Json(AddSupportAdminResponse {
        pubkey: pubkey_hex,
        added: added > 0,
    }))
}

/// Remove a support admin by pubkey. Full admin only.
pub async fn remove_support_admin(
    _tenant: crate::api::tenant::TenantExtractor,
    auth: UcanAuth,
    Path(pubkey): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    let state = crate::state::get_keycast_state()
        .map_err(|_| ApiError::Internal("State not initialized".to_string()))?;

    let redis = state
        .redis
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Redis not available".to_string()))?;

    let removed: i64 = redis::cmd("SREM")
        .arg(SUPPORT_ADMINS_KEY)
        .arg(&pubkey)
        .query_async(&mut redis.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Redis error: {}", e)))?;

    tracing::info!(
        "Support admin removed: {} (by admin {})",
        &pubkey[..std::cmp::min(8, pubkey.len())],
        &auth.pubkey[..8]
    );

    Ok(Json(serde_json::json!({
        "removed": removed > 0,
    })))
}

/// Resolve an identifier (npub, hex pubkey, or email) to a hex pubkey.
async fn resolve_identifier(
    identifier: &str,
    auth_state: &AuthState,
    tenant_id: i64,
) -> Result<String, ApiError> {
    // npub1... -> decode bech32
    if identifier.starts_with("npub1") {
        let pubkey = nostr_sdk::PublicKey::from_bech32(identifier)
            .map_err(|e| ApiError::bad_request(format!("Invalid npub: {}", e)))?;
        return Ok(pubkey.to_hex());
    }

    // 64-char hex -> validate as pubkey
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        nostr_sdk::PublicKey::from_hex(identifier)
            .map_err(|e| ApiError::bad_request(format!("Invalid hex pubkey: {}", e)))?;
        return Ok(identifier.to_string());
    }

    // Contains @ -> email lookup
    if identifier.contains('@') {
        let pool = &auth_state.state.db;
        let user_repo = UserRepository::new(pool.clone());
        let pubkey = user_repo
            .find_pubkey_by_email(identifier, tenant_id)
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
            .ok_or_else(|| {
                ApiError::not_found(format!("No user found with email: {}", identifier))
            })?;
        return Ok(pubkey);
    }

    Err(ApiError::bad_request(
        "Identifier must be an npub, 64-char hex pubkey, or email address",
    ))
}
