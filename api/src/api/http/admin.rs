// ABOUTME: Admin endpoints for preloaded accounts, claim token generation, and support admin management
// ABOUTME: Used for Vine import and support workflows

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{Duration, Utc};
use nostr_sdk::{FromBech32, Keys};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::routes::AuthState;
use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use keycast_core::repositories::{
    test_redirect_pattern, AdminAuditEventRecord, AdminAuditEventRepository, AdminUserDetails,
    AdminUserLookup, AdminUserMatchKind, AuthEventRepository, ClaimTokenRepository,
    FullAdminStatusRow, OAuthAuthorizationRepository, RegisteredClient, RegisteredClientRepository,
    RepositoryError, UserRepository, VerifiedMinorRow,
};
use keycast_core::types::claim_token::generate_claim_token;
use keycast_core::types::user::UserStatus;

/// Admin token expiry in days (30 days for long-lived admin tokens)
const ADMIN_TOKEN_EXPIRY_DAYS: i64 = 30;

/// Preloaded user signing token expiry in days
const PRELOAD_TOKEN_EXPIRY_DAYS: i64 = 30;

/// Redis key for the support admins set
const SUPPORT_ADMINS_KEY: &str = "support_admins";

/// Maximum delay for optional external-name promotion during an admin lookup.
///
/// Local candidates are already available, so external enrichment must not add the name
/// service's three-second request timeout to the support workflow.
const ADMIN_NAME_PROMOTION_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

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
            match redis.sismember(SUPPORT_ADMINS_KEY, &auth.pubkey).await {
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

    // Generate claim token. Invalidates prior valid tokens for the user in
    // the same transaction so Regenerate replaces cleanly and doesn't leave
    // stale credentials in circulation.
    let token = generate_claim_token();
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let (claim_token, invalidated_prior) = claim_token_repo
        .create_with_prior_invalidation(&token, &user_pubkey, Some(&auth.pubkey), tenant_id)
        .await?;

    if invalidated_prior > 0 {
        tracing::info!(
            "Claim token regenerate: {} prior token(s) invalidated for vine_id={}",
            invalidated_prior,
            req.vine_id,
        );
    }

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
// POST /api/admin/claim-tokens/invalidate - Invalidate claim token without replacement
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct InvalidateClaimTokenRequest {
    pub vine_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvalidateClaimTokenResponse {
    pub invalidated_count: u64,
    pub invalidated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Invalidate all valid claim tokens for a preloaded user without issuing a
/// replacement. Requires support admin. Idempotent: returns count=0 when
/// nothing is currently valid.
pub async fn invalidate_claim_token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<InvalidateClaimTokenRequest>,
) -> ApiResult<Json<InvalidateClaimTokenResponse>> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if !is_support_admin(&auth).await {
        tracing::warn!("Claim token invalidate denied (not support admin)");
        return Err(ApiError::forbidden("Admin access required"));
    }

    let user_repo = UserRepository::new(pool.clone());
    let user_pubkey = user_repo
        .find_pubkey_by_vine_id(&req.vine_id, tenant_id)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("User with vine_id {} not found", req.vine_id))
        })?;

    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let count = claim_token_repo
        .invalidate_valid_for_user(&user_pubkey, tenant_id, &auth.pubkey, req.reason.as_deref())
        .await?;

    tracing::info!(
        "Claim token invalidated: vine_id={} count={} reason={:?}",
        req.vine_id,
        count,
        req.reason,
    );

    Ok(Json(InvalidateClaimTokenResponse {
        invalidated_count: count,
        invalidated_at: if count > 0 {
            Some(chrono::Utc::now())
        } else {
            None
        },
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
    pub results: Vec<UserLookupDetails>,
    pub suggestions: Vec<UserLookupDetails>,
    pub total: usize,
    pub authoritative_match: bool,
    pub authoritative_count: usize,
}

#[derive(Debug, Serialize)]
pub struct UserLookupDetails {
    pub pubkey: String,
    pub authoritative: bool,
    pub match_kind: AdminUserMatchKind,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub vine_id: Option<String>,
    pub has_personal_key: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_reason: Option<String>,
    /// Approved protected-minor (13-15) flag. Terminal age-review signal; the in-review
    /// state lives in relay-manager, not keycast.
    pub verified_minor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_minor_at: Option<String>,
    pub active_sessions: i64,
    pub created_at: String,
    pub last_active: Option<String>,
}

async fn enrich_user_lookup_details(
    details: AdminUserDetails,
    oauth_repo: &OAuthAuthorizationRepository,
    tenant_id: i64,
) -> UserLookupDetails {
    let sessions = oauth_repo
        .list_active_sessions(&details.pubkey, tenant_id)
        .await
        .unwrap_or_default();

    let last_active = sessions
        .iter()
        .filter_map(|session| session.5.as_deref())
        .max()
        .map(String::from);

    UserLookupDetails {
        pubkey: details.pubkey,
        authoritative: details.authoritative,
        match_kind: details.match_kind,
        email: details.email,
        email_verified: details.email_verified,
        username: details.username,
        display_name: details.display_name,
        vine_id: details.vine_id,
        has_personal_key: details.has_personal_key,
        status: details.status.as_str().to_string(),
        suspended_reason: details.suspended_reason,
        verified_minor: details.verified_minor,
        verified_minor_at: details.verified_minor_at.map(|at| at.to_rfc3339()),
        active_sessions: sessions.len() as i64,
        created_at: details.created_at.to_rfc3339(),
        last_active,
    }
}

fn should_fetch_email_suggestions(authoritative_match: bool) -> bool {
    !authoritative_match
}

fn deduplicate_suggested_users(
    primary: &[AdminUserDetails],
    suggestions: Vec<AdminUserDetails>,
) -> Vec<AdminUserDetails> {
    let mut seen = primary
        .iter()
        .map(|user| user.pubkey.clone())
        .collect::<std::collections::HashSet<_>>();

    suggestions
        .into_iter()
        .filter(|user| seen.insert(user.pubkey.clone()))
        .collect()
}

fn authoritative_name_promotion_timeout(local_result_count: usize) -> Option<std::time::Duration> {
    (local_result_count > 0).then_some(ADMIN_NAME_PROMOTION_TIMEOUT)
}

async fn await_name_promotion_within<T>(
    future: impl std::future::Future<Output = T>,
    timeout: std::time::Duration,
) -> Option<T> {
    tokio::time::timeout(timeout, future).await.ok()
}

/// Combine a local admin lookup with the name server's resolution of the same handle.
///
/// The name server is authoritative for handles, so a local match is authoritative only when the
/// name server confirms it. `resolved` is `Some` iff the name server returned a keycast account:
/// - confirmed → that account is the sole authoritative match; every local row is demoted to a
///   candidate below it.
/// - not confirmed (`None`: timeout, transport error, unregistered handle, or a pubkey with no
///   keycast account) → any local authoritative match is demoted too, so an unconfirmed stale
///   `username` or a slow/unavailable name server cannot select the wrong account.
///
/// Demoted rows stay visible as candidates; nothing is hidden.
fn apply_name_promotion(
    local: AdminUserLookup,
    resolved: Option<AdminUserLookup>,
) -> AdminUserLookup {
    if let Some(resolved) = resolved {
        if resolved.authoritative_match {
            return resolved.append_loose_results(local.demote_to_candidates());
        }
    }
    if local.authoritative_match {
        local.demote_to_candidates()
    } else {
        local
    }
}

/// A support-lookup query reduced to its effective search string, plus whether it is a
/// Divine-handle-shaped query eligible for authoritative name-server promotion.
///
/// Support and users write a handle several ways: `mjb`, `@mjb`, `mjb.<domain>` (the profile
/// URL), `@mjb.<domain>`, and `mjb@<domain>` (the NIP-05 form). All reduce to the bare handle
/// `mjb`. Emails at other domains, `npub…`, and 64-char hex are not handles.
#[derive(Debug, PartialEq, Eq)]
struct CanonicalLookup {
    query: String,
    is_handle: bool,
}

/// Strip an ASCII `suffix` (matched case-insensitively via `lower`) from `s`, returning the
/// prefix. `lower` must be `s.to_lowercase()`; `suffix` must be lowercase ASCII. The suffix
/// region is ASCII, so `s.len() - suffix.len()` is a valid char boundary even if the prefix
/// is non-ASCII.
fn strip_ascii_suffix<'a>(s: &'a str, lower: &str, suffix: &str) -> Option<&'a str> {
    lower
        .ends_with(suffix)
        .then(|| &s[..s.len() - suffix.len()])
}

fn canonicalize_lookup_query(raw: &str, nip05_domain: &str) -> CanonicalLookup {
    let q = raw.trim();

    // Direct pubkey forms are searched as-is and never promoted by name.
    if q.starts_with("npub") || (q.len() == 64 && q.chars().all(|c| c.is_ascii_hexdigit())) {
        return CanonicalLookup {
            query: q.to_string(),
            is_handle: false,
        };
    }

    // A leading '@' is a common way to write a handle.
    let s = q.strip_prefix('@').unwrap_or(q);
    let domain = nip05_domain.trim().to_lowercase();
    let lower = s.to_lowercase();

    if !domain.is_empty() {
        // NIP-05 email form `handle@domain` reduces to the bare handle.
        if let Some(handle) = strip_ascii_suffix(s, &lower, &format!("@{domain}")) {
            if !handle.is_empty() {
                return CanonicalLookup {
                    query: handle.to_string(),
                    is_handle: true,
                };
            }
        }
        // Profile-URL / subdomain form `handle.domain` reduces to the bare handle too (it would
        // otherwise be mangled by the username query's dot-stripping normalization), but only for
        // a bare host: an email at a subdomain (e.g. `agent@qa.divine.video`) still contains `@`
        // and must fall through to the email branch, not be mis-read as the handle `agent@qa`.
        if !s.contains('@') {
            if let Some(handle) = strip_ascii_suffix(s, &lower, &format!(".{domain}")) {
                if !handle.is_empty() {
                    return CanonicalLookup {
                        query: handle.to_string(),
                        is_handle: true,
                    };
                }
            }
        }
    }

    // An email at some other domain: search as email, not a handle.
    if s.contains('@') || s.is_empty() {
        return CanonicalLookup {
            query: if s.is_empty() {
                q.to_string()
            } else {
                s.to_string()
            },
            is_handle: false,
        };
    }

    // A bare token is a Divine-handle candidate (the local ladder still tries username/vine_id/hex).
    CanonicalLookup {
        query: s.to_string(),
        is_handle: true,
    }
}

#[cfg(test)]
mod user_lookup_response_tests {
    use super::{
        apply_name_promotion, authoritative_name_promotion_timeout, await_name_promotion_within,
        canonicalize_lookup_query, deduplicate_suggested_users, should_fetch_email_suggestions,
        AdminUserDetails, CanonicalLookup, UserLookupDetails, UserLookupResponse, UserStatus,
        ADMIN_NAME_PROMOTION_TIMEOUT,
    };
    use chrono::Utc;
    use keycast_core::repositories::{AdminUserLookup, AdminUserMatchKind};

    fn lookup_details(pubkey: &str, authoritative: bool) -> AdminUserDetails {
        let now = Utc::now();
        AdminUserDetails {
            pubkey: pubkey.to_string(),
            authoritative,
            match_kind: if authoritative {
                AdminUserMatchKind::Authoritative
            } else {
                AdminUserMatchKind::Partial
            },
            email: None,
            email_verified: None,
            username: None,
            display_name: None,
            vine_id: None,
            has_personal_key: false,
            status: UserStatus::Active,
            suspended_reason: None,
            verified_minor: false,
            verified_minor_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn empty_local_lookup_preserves_upstream_name_timeout() {
        assert_eq!(authoritative_name_promotion_timeout(0), None);
        assert_eq!(
            authoritative_name_promotion_timeout(1),
            Some(ADMIN_NAME_PROMOTION_TIMEOUT)
        );
    }

    #[tokio::test]
    async fn authoritative_name_promotion_stops_at_the_admin_lookup_budget() {
        let completed = await_name_promotion_within(
            std::future::ready("authoritative"),
            std::time::Duration::from_millis(5),
        )
        .await;
        let result = await_name_promotion_within(
            std::future::pending::<()>(),
            std::time::Duration::from_millis(5),
        )
        .await;

        assert_eq!(completed, Some("authoritative"));
        assert_eq!(result, None);
        assert_eq!(
            ADMIN_NAME_PROMOTION_TIMEOUT,
            std::time::Duration::from_millis(250)
        );
    }

    #[test]
    fn serializes_suggestions_separately_from_results() {
        let result = UserLookupDetails {
            pubkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            authoritative: true,
            match_kind: AdminUserMatchKind::Authoritative,
            email: Some("exact@example.com".to_string()),
            email_verified: Some(true),
            username: None,
            display_name: None,
            vine_id: None,
            has_personal_key: false,
            status: "active".to_string(),
            suspended_reason: None,
            verified_minor: false,
            verified_minor_at: None,
            active_sessions: 0,
            created_at: "2026-07-17T12:00:00+00:00".to_string(),
            last_active: None,
        };
        let suggestion = UserLookupDetails {
            pubkey: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            authoritative: false,
            match_kind: AdminUserMatchKind::Fuzzy,
            email: Some("suggested@example.com".to_string()),
            email_verified: Some(true),
            username: None,
            display_name: None,
            vine_id: None,
            has_personal_key: false,
            status: "active".to_string(),
            suspended_reason: None,
            verified_minor: false,
            verified_minor_at: None,
            active_sessions: 0,
            created_at: "2026-07-17T12:00:00+00:00".to_string(),
            last_active: None,
        };
        let response = UserLookupResponse {
            results: vec![result],
            suggestions: vec![suggestion],
            total: 1,
            authoritative_match: true,
            authoritative_count: 1,
        };

        let json = serde_json::to_value(response).expect("lookup response should serialize");
        assert_eq!(json["authoritative_match"], true);
        assert_eq!(json["authoritative_count"], 1);
        assert_eq!(json["results"][0]["email"], "exact@example.com");
        assert_eq!(json["results"][0]["match_kind"], "authoritative");
        assert_eq!(json["total"], 1);
        assert_eq!(json["suggestions"][0]["email"], "suggested@example.com");
        assert_eq!(json["suggestions"][0]["authoritative"], false);
        assert_eq!(json["suggestions"][0]["match_kind"], "fuzzy");
    }

    #[test]
    fn name_promotion_merge_preserves_each_row_tier() {
        let promoted = AdminUserLookup {
            users: vec![lookup_details("authoritative", true)],
            authoritative_match: true,
            authoritative_count: 1,
        };
        let local = AdminUserLookup {
            users: vec![lookup_details("loose", false)],
            authoritative_match: false,
            authoritative_count: 0,
        };

        let merged = promoted.append_loose_results(local);

        assert_eq!(merged.users[0].pubkey, "authoritative");
        assert!(merged.users[0].authoritative);
        assert_eq!(
            merged.users[0].match_kind,
            AdminUserMatchKind::Authoritative
        );
        assert_eq!(merged.users[1].pubkey, "loose");
        assert!(!merged.users[1].authoritative);
        assert_eq!(merged.users[1].match_kind, AdminUserMatchKind::Partial);
        assert_eq!(merged.authoritative_count, 1);
    }

    #[test]
    fn demote_to_candidates_clears_authority() {
        let lookup = AdminUserLookup {
            users: vec![lookup_details("a", true), lookup_details("b", true)],
            authoritative_match: true,
            authoritative_count: 2,
        };
        let demoted = lookup.demote_to_candidates();
        assert!(demoted.users.iter().all(|user| !user.authoritative));
        // Demotion must also clear the tier: rows are ranked and labeled by `match_kind`, so a row
        // left as `Authoritative` would still present as the top-tier match despite the flag.
        assert!(demoted
            .users
            .iter()
            .all(|user| user.match_kind == AdminUserMatchKind::Partial));
        assert_eq!(demoted.authoritative_count, 0);
        assert!(!demoted.authoritative_match);
    }

    fn authoritative(pubkey: &str) -> AdminUserLookup {
        AdminUserLookup {
            users: vec![lookup_details(pubkey, true)],
            authoritative_match: true,
            authoritative_count: 1,
        }
    }

    #[test]
    fn apply_name_promotion_confirmed_demotes_a_disagreeing_local_match() {
        // Name server resolved the handle to `canonical`; a local exact-username match `stale`
        // disagrees. Only the name-server row stays authoritative; the stale local row is demoted.
        let merged = apply_name_promotion(authoritative("stale"), Some(authoritative("canonical")));

        assert_eq!(merged.users[0].pubkey, "canonical");
        assert!(merged.users[0].authoritative);
        assert_eq!(merged.users[1].pubkey, "stale");
        assert!(!merged.users[1].authoritative);
        assert_eq!(merged.authoritative_count, 1);
    }

    #[test]
    fn apply_name_promotion_confirmed_dedupes_when_it_agrees_with_local() {
        let merged = apply_name_promotion(authoritative("same"), Some(authoritative("same")));

        assert_eq!(merged.users.len(), 1, "same pubkey should dedupe");
        assert!(merged.users[0].authoritative);
        assert_eq!(merged.authoritative_count, 1);
    }

    #[test]
    fn apply_name_promotion_unconfirmed_demotes_a_local_authoritative_match() {
        // `resolved == None` models a timeout / transport error / unregistered handle. A stale
        // exact `username` must NOT stay authoritative just because the name server was too slow.
        let result = apply_name_promotion(authoritative("stale"), None);

        assert_eq!(result.users[0].pubkey, "stale");
        assert!(
            !result.users[0].authoritative,
            "an unconfirmed local match must not claim authority"
        );
        assert!(!result.authoritative_match);
        assert_eq!(result.authoritative_count, 0);
    }

    #[test]
    fn apply_name_promotion_unconfirmed_leaves_non_authoritative_local_untouched() {
        let loose = AdminUserLookup {
            users: vec![lookup_details("loose", false)],
            authoritative_match: false,
            authoritative_count: 0,
        };
        let result = apply_name_promotion(loose, None);

        assert_eq!(result.users.len(), 1);
        assert!(!result.users[0].authoritative);
        assert!(!result.authoritative_match);
    }

    #[test]
    fn apply_name_promotion_non_keycast_resolution_demotes_local_authority() {
        // Name server resolved the handle to a pubkey with no keycast account (empty, non-
        // authoritative resolution) — still not a confirmation of the local match, so demote it.
        let empty_resolution = AdminUserLookup {
            users: vec![],
            authoritative_match: false,
            authoritative_count: 0,
        };
        let result = apply_name_promotion(authoritative("stale"), Some(empty_resolution));

        assert_eq!(result.users[0].pubkey, "stale");
        assert!(!result.users[0].authoritative);
        assert!(!result.authoritative_match);
    }

    #[test]
    fn suggestions_exclude_primary_and_repeated_pubkeys() {
        let primary = vec![lookup_details("already-selected", false)];
        let mut selected_again = lookup_details("already-selected", false);
        selected_again.match_kind = AdminUserMatchKind::Fuzzy;
        let mut fuzzy = lookup_details("fuzzy", false);
        fuzzy.match_kind = AdminUserMatchKind::Fuzzy;
        let mut fuzzy_again = lookup_details("fuzzy", false);
        fuzzy_again.match_kind = AdminUserMatchKind::Fuzzy;

        let suggestions =
            deduplicate_suggested_users(&primary, vec![selected_again, fuzzy, fuzzy_again]);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].pubkey, "fuzzy");
        assert_eq!(suggestions[0].match_kind, AdminUserMatchKind::Fuzzy);
    }

    #[test]
    fn email_suggestions_only_when_no_authoritative_match() {
        assert!(should_fetch_email_suggestions(false));
        assert!(!should_fetch_email_suggestions(true));
    }

    fn handle(query: &str) -> CanonicalLookup {
        CanonicalLookup {
            query: query.to_string(),
            is_handle: true,
        }
    }

    fn non_handle(query: &str) -> CanonicalLookup {
        CanonicalLookup {
            query: query.to_string(),
            is_handle: false,
        }
    }

    #[test]
    fn canonicalize_reduces_handle_forms_to_bare_handle() {
        let d = "divine.video";
        assert_eq!(canonicalize_lookup_query("mjb", d), handle("mjb"));
        assert_eq!(canonicalize_lookup_query("@mjb", d), handle("mjb"));
        assert_eq!(
            canonicalize_lookup_query("mjb.divine.video", d),
            handle("mjb")
        );
        assert_eq!(
            canonicalize_lookup_query("@mjb.divine.video", d),
            handle("mjb")
        );
        assert_eq!(
            canonicalize_lookup_query("mjb@divine.video", d),
            handle("mjb")
        );
        // Case is preserved (DB match is case-insensitive; the name server resolves case-insensitively).
        assert_eq!(
            canonicalize_lookup_query("  MJB@Divine.Video  ", d),
            handle("MJB")
        );
    }

    #[test]
    fn canonicalize_marks_non_handles() {
        let d = "divine.video";
        assert_eq!(
            canonicalize_lookup_query("alice@gmail.com", d),
            non_handle("alice@gmail.com")
        );
        // An email at a subdomain of the Divine domain is still an email, not the handle `agent@qa`.
        assert_eq!(
            canonicalize_lookup_query("agent@qa.divine.video", d),
            non_handle("agent@qa.divine.video")
        );
        assert_eq!(
            canonicalize_lookup_query("npub1qqqqexample", d),
            non_handle("npub1qqqqexample")
        );
        let hex = "a".repeat(64);
        assert_eq!(canonicalize_lookup_query(&hex, d), non_handle(&hex));
    }

    #[test]
    fn canonicalize_dotted_handle_that_is_not_the_domain_stays_a_handle() {
        // The ladder normalizes dots, so a dotted handle is still a handle candidate.
        assert_eq!(
            canonicalize_lookup_query("lele.pons", "divine.video"),
            handle("lele.pons")
        );
    }
}

/// Look up users by email, username, vine ID, or pubkey.
///
/// Available to support admins and above. Non-authoritative lookups include de-duplicated fuzzy
/// email suggestions alongside any literal primary results.
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

    // Reduce the several ways a Divine handle is written (@mjb, mjb.<domain>, mjb@<domain>) to the
    // bare handle, and mark whether this is a handle-shaped query. Canonicalize against the public
    // handle domain (e.g. divine.video), NOT the tenant/login host (e.g. login.divine.video), or a
    // qualified handle like `mjb@divine.video` would never reduce to `mjb`.
    let handle_domain = crate::api::http::auth::public_handle_domain();
    let canonical = canonicalize_lookup_query(q, &handle_domain);

    let user_repo = UserRepository::new(pool.clone());
    let mut lookup = user_repo
        .find_users_for_admin(&canonical.query, tenant_id)
        .await?;

    // The Divine name server is authoritative for handles, so consult it for any handle-shaped
    // query even when a local row already matches: a stale local `username` must not shadow the
    // real account. A local match is authoritative only when the name server CONFIRMS it (see
    // `apply_name_promotion`); a timeout / error / unregistered handle demotes an unconfirmed local
    // match rather than let it claim identity. Note `is_handle` is syntactic, so a local match on
    // some other column (e.g. a coincidental `vine_id`) is subject to the same rule — intentional,
    // the name server owns a registered handle regardless, and demoted rows stay visible.
    if canonical.is_handle && crate::divine_names::is_enabled() {
        let name_lookup = crate::divine_names::lookup_by_name(&canonical.query);
        let promoted_name =
            if let Some(timeout) = authoritative_name_promotion_timeout(lookup.users.len()) {
                await_name_promotion_within(name_lookup, timeout).await
            } else {
                Some(name_lookup.await)
            };

        // Only a name-server response resolving to a keycast account confirms an identity; a
        // timeout, transport error, or unregistered handle leaves us unconfirmed.
        let resolved = match promoted_name {
            Some(Ok(Some(hex_pubkey))) => Some(
                user_repo
                    .find_users_for_admin(&hex_pubkey, tenant_id)
                    .await?,
            ),
            _ => None,
        };
        lookup = apply_name_promotion(lookup, resolved);
    }

    let suggested_users = if should_fetch_email_suggestions(lookup.authoritative_match) {
        user_repo
            .suggest_users_for_admin(&canonical.query, tenant_id)
            .await?
    } else {
        vec![]
    };
    let suggested_users = deduplicate_suggested_users(&lookup.users, suggested_users);

    let oauth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let total = lookup.users.len();
    let authoritative_match = lookup.authoritative_match;
    let authoritative_count = lookup.authoritative_count;
    let mut results = Vec::with_capacity(total);

    for details in lookup.users {
        results.push(enrich_user_lookup_details(details, &oauth_repo, tenant_id).await);
    }

    let mut suggestions = Vec::with_capacity(suggested_users.len());
    for details in suggested_users {
        suggestions.push(enrich_user_lookup_details(details, &oauth_repo, tenant_id).await);
    }

    Ok(Json(UserLookupResponse {
        results,
        suggestions,
        total,
        authoritative_match,
        authoritative_count,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuthDebugQuery {
    pub email: Option<String>,
    pub pubkey: Option<String>,
    pub npub: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthDebugAccount {
    pub pubkey: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub password_hash_present: bool,
    pub password_reset_pending: bool,
    pub active_sessions: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct AuthDebugDuplicate {
    pub pubkey: String,
    pub email: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct AuthDebugEvent {
    pub occurred_at: String,
    pub request_id: String,
    pub endpoint: String,
    pub event_type: String,
    pub outcome: String,
    pub reason_code: Option<String>,
    pub http_status: Option<i32>,
    pub email: Option<String>,
    pub pubkey: Option<String>,
    pub client_id: Option<String>,
    pub redirect_origin: Option<String>,
    pub user_agent: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Serialize)]
pub struct AuthDebugResponse {
    pub diagnosis: String,
    pub account: Option<AuthDebugAccount>,
    pub duplicates: Vec<AuthDebugDuplicate>,
    pub events: Vec<AuthDebugEvent>,
}

#[derive(Debug, sqlx::FromRow)]
struct AuthDebugAccountRow {
    pub pubkey: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub password_hash_present: bool,
    pub password_reset_pending: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct AuthDebugDuplicateRow {
    pub pubkey: String,
    pub email: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

/// Engineer-facing auth debugging endpoint. Support admin or above.
pub async fn get_auth_debug(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Query(query): Query<AuthDebugQuery>,
) -> ApiResult<Json<AuthDebugResponse>> {
    if !is_support_admin(&auth).await {
        return Err(ApiError::forbidden("Admin access required"));
    }

    if query.email.as_deref().is_none_or(str::is_empty)
        && query.pubkey.as_deref().is_none_or(str::is_empty)
        && query.npub.as_deref().is_none_or(str::is_empty)
        && query.request_id.as_deref().is_none_or(str::is_empty)
    {
        return Err(ApiError::bad_request(
            "Provide email, pubkey, npub, or request_id",
        ));
    }

    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let auth_event_repo = AuthEventRepository::new(pool.clone());

    let mut target_email = query
        .email
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|email| email.trim().to_lowercase());
    let mut target_pubkey = match query.pubkey.as_deref() {
        Some(pubkey) if !pubkey.trim().is_empty() => Some(
            nostr_sdk::PublicKey::from_hex(pubkey.trim())
                .map_err(|e| ApiError::bad_request(format!("Invalid pubkey: {}", e)))?
                .to_hex(),
        ),
        _ => None,
    };

    if target_pubkey.is_none() {
        if let Some(npub) = query
            .npub
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            target_pubkey = Some(
                nostr_sdk::PublicKey::from_bech32(npub.trim())
                    .map_err(|e| ApiError::bad_request(format!("Invalid npub: {}", e)))?
                    .to_hex(),
            );
        }
    }

    let mut auth_events = if let Some(request_id) = query.request_id.as_deref() {
        auth_event_repo
            .list_recent_by_request_id(tenant_id, request_id.trim(), 50)
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
    } else {
        Vec::new()
    };

    if target_email.is_none() {
        target_email = auth_events.iter().find_map(|event| event.email.clone());
    }
    if target_pubkey.is_none() {
        target_pubkey = auth_events.iter().find_map(|event| event.pubkey.clone());
    }

    if auth_events.is_empty() {
        if let Some(email) = target_email.as_deref() {
            auth_events = auth_event_repo
                .list_recent_by_email(tenant_id, email, 50)
                .await
                .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        } else if let Some(pubkey) = target_pubkey.as_deref() {
            auth_events = auth_event_repo
                .list_recent_by_pubkey(tenant_id, pubkey, 50)
                .await
                .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        }
    }

    if target_pubkey.is_none() {
        if let Some(email) = target_email.as_deref() {
            let user_repo = UserRepository::new(pool.clone());
            target_pubkey = user_repo
                .find_pubkey_by_email(email, tenant_id)
                .await
                .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        }
    }

    if target_email.is_none() {
        if let Some(pubkey) = target_pubkey.as_deref() {
            target_email = sqlx::query_scalar::<_, String>(
                "SELECT email FROM users WHERE tenant_id = $1 AND pubkey = $2",
            )
            .bind(tenant_id)
            .bind(pubkey)
            .fetch_optional(pool)
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        }
    }

    let account = if let Some(pubkey) = target_pubkey.as_deref() {
        let row = sqlx::query_as::<_, AuthDebugAccountRow>(
            "SELECT
                pubkey,
                email,
                email_verified,
                password_hash IS NOT NULL AS password_hash_present,
                password_reset_token IS NOT NULL
                    AND (password_reset_expires_at IS NULL OR password_reset_expires_at > NOW())
                    AS password_reset_pending,
                created_at,
                updated_at
             FROM users
             WHERE tenant_id = $1 AND pubkey = $2",
        )
        .bind(tenant_id)
        .bind(pubkey)
        .fetch_optional(pool)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

        match row {
            Some(row) => {
                let active_sessions = OAuthAuthorizationRepository::new(pool.clone())
                    .list_active_sessions(&row.pubkey, tenant_id)
                    .await
                    .unwrap_or_default()
                    .len() as i64;
                Some(AuthDebugAccount {
                    pubkey: row.pubkey,
                    email: row.email,
                    email_verified: row.email_verified,
                    password_hash_present: row.password_hash_present,
                    password_reset_pending: row.password_reset_pending,
                    active_sessions,
                    created_at: row.created_at.to_rfc3339(),
                    updated_at: row.updated_at.to_rfc3339(),
                })
            }
            None => None,
        }
    } else {
        None
    };

    let duplicates = if let Some(email) = target_email.as_deref() {
        sqlx::query_as::<_, AuthDebugDuplicateRow>(
            "SELECT pubkey, email, created_at
             FROM users
             WHERE tenant_id = $1
               AND LOWER(TRIM(email)) = LOWER(TRIM($2))
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_all(pool)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .into_iter()
        .map(|row| AuthDebugDuplicate {
            pubkey: row.pubkey,
            email: row.email,
            created_at: row.created_at.to_rfc3339(),
        })
        .collect()
    } else {
        Vec::new()
    };

    let events = auth_events
        .into_iter()
        .map(|row| AuthDebugEvent {
            occurred_at: row.occurred_at.to_rfc3339(),
            request_id: row.request_id,
            endpoint: row.endpoint,
            event_type: row.event_type,
            outcome: row.outcome,
            reason_code: row.reason_code,
            http_status: row.http_status,
            email: row.email,
            pubkey: row.pubkey,
            client_id: row.client_id,
            redirect_origin: row.redirect_origin,
            user_agent: row.user_agent,
            metadata_json: row.metadata_json,
        })
        .collect::<Vec<_>>();

    let diagnosis = diagnose_auth_debug(account.as_ref(), &duplicates, &events);

    Ok(Json(AuthDebugResponse {
        diagnosis,
        account,
        duplicates,
        events,
    }))
}

fn diagnose_auth_debug(
    account: Option<&AuthDebugAccount>,
    duplicates: &[AuthDebugDuplicate],
    events: &[AuthDebugEvent],
) -> String {
    if duplicates.len() > 1 {
        return "multiple_normalized_email_rows".to_string();
    }

    if let Some(reset_success) = events.iter().find(|event| {
        event.endpoint == "/api/auth/reset-password"
            && event.outcome == "success"
            && event.reason_code.as_deref() == Some("password_hash_updated")
    }) {
        if events.iter().any(|event| {
            event.occurred_at > reset_success.occurred_at
                && event.event_type == "login"
                && event.outcome == "failure"
                && event.reason_code.as_deref() == Some("invalid_password")
        }) {
            return "password_reset_persisted_but_login_failed_invalid_password".to_string();
        }
    }

    if account.is_none() {
        return "no_users_row_found".to_string();
    }

    if account.is_some_and(|account| account.email_verified == Some(false))
        || events
            .iter()
            .any(|event| event.reason_code.as_deref() == Some("email_not_verified"))
    {
        return "email_not_verified".to_string();
    }

    if account.is_some_and(|account| !account.password_hash_present) {
        return "password_not_set".to_string();
    }

    if let Some(reason_code) = events
        .iter()
        .find(|event| event.outcome == "failure")
        .and_then(|event| event.reason_code.clone())
    {
        return reason_code;
    }

    "no_obvious_auth_gate".to_string()
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

    let pubkeys: Vec<String> = redis
        .smembers(SUPPORT_ADMINS_KEY)
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

    let added: i64 = redis
        .sadd(SUPPORT_ADMINS_KEY, &pubkey_hex)
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

    let removed: i64 = redis
        .srem(SUPPORT_ADMINS_KEY, &pubkey)
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

// ============================================================================
// Registered OAuth Clients (admin CRUD)
// ============================================================================
//
// These endpoints let a full admin manage the per-tenant OAuth client allowlist
// stored in `registered_clients`. They mirror the same auth gate (is_full_admin
// + TenantExtractor) used by the support-admin endpoints above.

#[derive(Debug, Serialize)]
pub struct RegisteredClientView {
    pub id: i32,
    pub client_id: String,
    pub name: String,
    pub allowed_redirect_uris: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<RegisteredClient> for RegisteredClientView {
    fn from(c: RegisteredClient) -> Self {
        Self {
            id: c.id,
            client_id: c.client_id,
            name: c.name,
            allowed_redirect_uris: c.allowed_redirect_uris,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredClientsResponse {
    pub clients: Vec<RegisteredClientView>,
}

/// Map a repository error to an HTTP-shaped ApiError. Conflict for unique
/// violations, NotFound for missing rows, BadRequest for validation failures.
fn map_repo_error(err: RepositoryError) -> ApiError {
    match err {
        RepositoryError::Duplicate => {
            ApiError::conflict("A client with this client_id already exists for this tenant")
        }
        RepositoryError::NotFound(msg) => ApiError::not_found(msg),
        RepositoryError::Integrity(msg) => ApiError::bad_request(msg),
        RepositoryError::Database(msg) => ApiError::Internal(msg),
    }
}

/// Best-effort audit-trail write for a registered_client create/delete.
/// A failed insert logs an error and returns; it never fails the admin action.
///
/// Updates use [`record_registered_client_update_audit`] instead so the row
/// can carry both pre- and post-update snapshots.
async fn record_registered_client_audit(
    pool: &sqlx::PgPool,
    actor_pubkey: &str,
    action: &'static str,
    client: &RegisteredClient,
) {
    let metadata = serde_json::json!({
        "name": client.name,
        "allowed_redirect_uris": client.allowed_redirect_uris,
    });
    let repo = AdminAuditEventRepository::new(pool.clone());
    if let Err(error) = repo
        .record(AdminAuditEventRecord {
            tenant_id: client.tenant_id,
            actor_pubkey: actor_pubkey.to_string(),
            action: action.to_string(),
            target_resource_type: "registered_client".to_string(),
            target_resource_id: Some(client.id.to_string()),
            target_client_id: Some(client.client_id.clone()),
            metadata_json: metadata,
        })
        .await
    {
        tracing::error!(
            action = action,
            client_id = %client.client_id,
            tenant_id = client.tenant_id,
            error = %error,
            "Failed to write admin_audit_events row for registered_client"
        );
    }
}

/// Best-effort audit-trail write for a registered_client update, recording
/// `{before, after}` snapshots so forensic queries can answer "what changed"
/// from a single row. Mirrors the no-fail pattern of
/// [`record_registered_client_audit`].
async fn record_registered_client_update_audit(
    pool: &sqlx::PgPool,
    actor_pubkey: &str,
    before: &RegisteredClient,
    after: &RegisteredClient,
) {
    let metadata = serde_json::json!({
        "before": {
            "name": before.name,
            "allowed_redirect_uris": before.allowed_redirect_uris,
        },
        "after": {
            "name": after.name,
            "allowed_redirect_uris": after.allowed_redirect_uris,
        },
    });
    let repo = AdminAuditEventRepository::new(pool.clone());
    if let Err(error) = repo
        .record(AdminAuditEventRecord {
            tenant_id: after.tenant_id,
            actor_pubkey: actor_pubkey.to_string(),
            action: "registered_client.update".to_string(),
            target_resource_type: "registered_client".to_string(),
            target_resource_id: Some(after.id.to_string()),
            target_client_id: Some(after.client_id.clone()),
            metadata_json: metadata,
        })
        .await
    {
        tracing::error!(
            action = "registered_client.update",
            client_id = %after.client_id,
            tenant_id = after.tenant_id,
            error = %error,
            "Failed to write admin_audit_events row for registered_client"
        );
    }
}

/// GET /api/admin/registered-clients
/// List all registered OAuth clients for the current tenant.
pub async fn list_registered_clients(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
) -> ApiResult<Json<RegisteredClientsResponse>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    let repo = RegisteredClientRepository::new(auth_state.state.db.clone());
    let clients = repo.list(tenant.0.id).await.map_err(map_repo_error)?;
    Ok(Json(RegisteredClientsResponse {
        clients: clients.into_iter().map(Into::into).collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreateRegisteredClientRequest {
    pub client_id: String,
    pub name: String,
    pub allowed_redirect_uris: Vec<String>,
}

/// POST /api/admin/registered-clients
/// Create a new registered OAuth client for the current tenant.
pub async fn create_registered_client(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<CreateRegisteredClientRequest>,
) -> ApiResult<Json<RegisteredClientView>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    let repo = RegisteredClientRepository::new(auth_state.state.db.clone());
    let created = repo
        .create(
            tenant.0.id,
            req.client_id.trim(),
            req.name.trim(),
            &req.allowed_redirect_uris,
        )
        .await
        .map_err(map_repo_error)?;

    record_registered_client_audit(
        &auth_state.state.db,
        &auth.pubkey,
        "registered_client.create",
        &created,
    )
    .await;

    tracing::info!(
        "Registered client created: {} (by admin {})",
        created.client_id,
        &auth.pubkey[..8]
    );
    Ok(Json(created.into()))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRegisteredClientRequest {
    /// New display name. Omit to keep the existing name.
    pub name: Option<String>,
    /// Replacement set of allowed redirect URI patterns. Omit to keep existing.
    /// When provided, this REPLACES the current list — patterns not present in
    /// the new list are removed.
    pub allowed_redirect_uris: Option<Vec<String>>,
}

/// PATCH /api/admin/registered-clients/:id
pub async fn update_registered_client(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path(id): Path<i32>,
    Json(req): Json<UpdateRegisteredClientRequest>,
) -> ApiResult<Json<RegisteredClientView>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    if req.name.is_none() && req.allowed_redirect_uris.is_none() {
        return Err(ApiError::bad_request(
            "Provide at least one of: name, allowed_redirect_uris",
        ));
    }

    let repo = RegisteredClientRepository::new(auth_state.state.db.clone());
    let update = repo
        .update(
            id,
            tenant.0.id,
            req.name.as_deref(),
            req.allowed_redirect_uris.as_deref(),
        )
        .await
        .map_err(map_repo_error)?;

    record_registered_client_update_audit(
        &auth_state.state.db,
        &auth.pubkey,
        &update.before,
        &update.after,
    )
    .await;

    tracing::info!(
        "Registered client updated: id={} client_id={} (by admin {})",
        update.after.id,
        update.after.client_id,
        &auth.pubkey[..8]
    );
    Ok(Json(update.after.into()))
}

/// DELETE /api/admin/registered-clients/:id
pub async fn delete_registered_client(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path(id): Path<i32>,
) -> ApiResult<Json<serde_json::Value>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    let repo = RegisteredClientRepository::new(auth_state.state.db.clone());
    let deleted = repo.delete(id, tenant.0.id).await.map_err(map_repo_error)?;

    record_registered_client_audit(
        &auth_state.state.db,
        &auth.pubkey,
        "registered_client.delete",
        &deleted,
    )
    .await;

    let admin_display = &auth.pubkey[..8];
    tracing::info!(
        "Registered client deleted: id={} client_id={} (by admin {})",
        deleted.id,
        deleted.client_id,
        admin_display
    );
    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[derive(Debug, Deserialize)]
pub struct TestRedirectPatternRequest {
    pub pattern: String,
    pub uri: String,
}

#[derive(Debug, Serialize)]
pub struct TestRedirectPatternResponse {
    pub matches: bool,
}

/// POST /api/admin/registered-clients/test
/// Inline pattern tester: returns whether `uri` matches `pattern` according to
/// the same matcher used by the OAuth validator.
pub async fn test_registered_client_pattern(
    _tenant: crate::api::tenant::TenantExtractor,
    auth: UcanAuth,
    Json(req): Json<TestRedirectPatternRequest>,
) -> ApiResult<Json<TestRedirectPatternResponse>> {
    if !is_full_admin(&auth) {
        return Err(ApiError::forbidden("Full admin access required"));
    }

    Ok(Json(TestRedirectPatternResponse {
        matches: test_redirect_pattern(&req.pattern, &req.uri),
    }))
}

// --- Service-token-authenticated admin endpoints (for relay-manager, COOP) ---

fn authorize_service_token(headers: &HeaderMap) -> Result<(), ApiError> {
    use subtle::ConstantTimeEq;

    let expected = std::env::var("KEYCAST_SERVICE_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::internal("KEYCAST_SERVICE_TOKEN not configured"))?;

    let actual = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::auth("Missing Authorization header"))?;

    // Hash both to fixed length to avoid leaking expected token length via timing
    let expected_hash = blake3::hash(format!("Bearer {expected}").as_bytes());
    let actual_hash = blake3::hash(actual.as_bytes());
    if expected_hash
        .as_bytes()
        .ct_eq(actual_hash.as_bytes())
        .into()
    {
        Ok(())
    } else {
        Err(ApiError::auth("Invalid service token"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserStatusResponse {
    pub pubkey: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub verified_minor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_minor_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn get_user_status_admin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
) -> ApiResult<Json<UserStatusResponse>> {
    authorize_service_token(&headers)?;
    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(auth_state.state.db.clone());

    let FullAdminStatusRow {
        status,
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    } = user_repo
        .get_full_admin_status(&pubkey, tenant_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(Json(UserStatusResponse {
        pubkey,
        status: status.as_str().to_string(),
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SetUserStatusRequest {
    pub status: String,
    pub reason: Option<String>,
    /// Moderator's hex pubkey. Optional; when present and the status actually
    /// changes it drives the durable admin_audit_events row. That table's
    /// actor_pubkey is NOT NULL, so an absent actor falls back to log-only
    /// (same contract as clear_verified_minor_admin).
    pub actor: Option<String>,
}

pub async fn set_user_status_admin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
    Json(req): Json<SetUserStatusRequest>,
) -> ApiResult<Json<UserStatusResponse>> {
    authorize_service_token(&headers)?;
    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(auth_state.state.db.clone());

    let status = match req.status.as_str() {
        "active" => UserStatus::Active,
        "suspended" => UserStatus::Suspended,
        "banned" => UserStatus::Banned,
        _ => {
            return Err(ApiError::bad_request(
                "Invalid status. Must be: active, suspended, banned",
            ))
        }
    };

    // Validate the optional actor as a 64-char hex pubkey so a T&S action never
    // silently loses its audit trail to a malformed actor (mirrors
    // clear_verified_minor_admin).
    if let Some(actor) = req.actor.as_deref() {
        if actor.len() != 64 || !actor.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request(
                "actor must be a 64-character hex pubkey",
            ));
        }
    }

    // Sanitize the caller-supplied reason (strip control/bidi/zero-width, bound to
    // 500) before it is logged OR persisted -- to the suspended_reason column and
    // the audit metadata alike. A suspend/ban whose reason is empty after cleaning
    // is rejected as missing, same as an absent reason.
    let reason_clean = sanitize_reason(req.reason.clone());
    if !status.is_active() && reason_clean.is_none() {
        return Err(ApiError::bad_request(
            "reason is required when status is suspended or banned",
        ));
    }

    // active clears the reason; suspended/banned carry the sanitized reason.
    let reason = if status.is_active() {
        None
    } else {
        reason_clean.as_deref()
    };
    let (old_status, updated_status, suspended_reason, suspended_at) = user_repo
        .set_user_status(&pubkey, tenant_id, &status, reason)
        .await?;

    tracing::info!(
        event = "user_status_changed",
        pubkey = %pubkey,
        old_status = %old_status.as_str(),
        new_status = %updated_status.as_str(),
        actor = ?req.actor,
        reason = ?reason,
        "Admin changed user status"
    );

    // Durable audit row (best-effort) only for a real status transition and only
    // when an actor is supplied -- the same bar clear_verified_minor sets. Gating
    // on the status actually changing keeps a relay-manager retry after a lost
    // response from appending a second event asserting a change that never
    // happened. The table's actor_pubkey is NOT NULL, so no actor -> log-only. A
    // failed insert logs and the status change still succeeds. (keycast#279)
    if old_status.as_str() != updated_status.as_str() {
        if let Some(actor) = req.actor.as_deref() {
            let audit_repo = AdminAuditEventRepository::new(auth_state.state.db.clone());
            if let Err(error) = audit_repo
                .record(AdminAuditEventRecord {
                    tenant_id,
                    actor_pubkey: actor.to_string(),
                    action: "set_user_status".to_string(),
                    target_resource_type: "user".to_string(),
                    target_resource_id: Some(pubkey.clone()),
                    target_client_id: None,
                    metadata_json: serde_json::json!({
                        "old_status": old_status.as_str(),
                        "new_status": updated_status.as_str(),
                        "reason": reason,
                    }),
                })
                .await
            {
                tracing::error!(
                    pubkey = %pubkey,
                    error = %error,
                    "Failed to write admin_audit_events row for user status change"
                );
            }
        }
    }

    // set_user_status doesn't return verified_minor, so fetch it separately.
    // This is the write path (infrequent), so the extra query is acceptable.
    let VerifiedMinorRow {
        verified_minor,
        verified_minor_at,
    } = user_repo
        .get_verified_minor(&pubkey, tenant_id)
        .await?
        .unwrap_or(VerifiedMinorRow {
            verified_minor: false,
            verified_minor_at: None,
        });

    Ok(Json(UserStatusResponse {
        pubkey,
        status: updated_status.as_str().to_string(),
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    }))
}

// --- Clear verified_minor (service-token auth: age-up / revocation) ---

/// Query params for the clear-verified_minor endpoint. Both optional; `actor`
/// (the moderator's hex pubkey) drives the durable audit row.
#[derive(Debug, Deserialize)]
pub struct ClearVerifiedMinorParams {
    pub actor: Option<String>,
    pub reason: Option<String>,
}

/// True for Unicode bidi / zero-width / line-separator characters that
/// `char::is_control` (category Cc) misses. Stripping these prevents log/console
/// display spoofing via right-to-left overrides, invisible characters, and
/// newline-equivalent separators (U+2028/U+2029).
fn is_unsafe_format_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // zero-width space .. right-to-left mark
        | '\u{2028}'..='\u{2029}' // line / paragraph separator
        | '\u{202A}'..='\u{202E}' // bidi embeddings / overrides
        | '\u{2060}'..='\u{2064}' // word joiner + invisible math operators
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}'              // zero-width no-break space / BOM
        | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation anchors
    )
}

/// Bound and strip control + bidi/zero-width characters from a caller-supplied
/// reason before it is logged or persisted (prevents log injection, display
/// spoofing, and unbounded audit rows). Returns None when empty after cleaning.
fn sanitize_reason(raw: Option<String>) -> Option<String> {
    let cleaned: String = raw?
        .chars()
        .filter(|c| !c.is_control() && !is_unsafe_format_char(*c))
        .take(500)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub async fn clear_verified_minor_admin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
    Query(params): Query<ClearVerifiedMinorParams>,
) -> ApiResult<Json<UserStatusResponse>> {
    authorize_service_token(&headers)?;
    let tenant_id = tenant.0.id;

    // Validate the optional actor as a 64-char hex pubkey so a T&S action never
    // silently loses its audit trail to a malformed actor.
    if let Some(actor) = params.actor.as_deref() {
        if actor.len() != 64 || !actor.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request(
                "actor must be a 64-character hex pubkey",
            ));
        }
    }

    let reason_clean = sanitize_reason(params.reason);

    let user_repo = UserRepository::new(auth_state.state.db.clone());
    let transitioned = user_repo.clear_verified_minor(&pubkey, tenant_id).await?;

    tracing::info!(
        event = "verified_minor_cleared",
        pubkey = %pubkey,
        actor = ?params.actor,
        reason = ?reason_clean,
        transitioned,
        "Admin cleared verified_minor"
    );

    // Durable audit row (best-effort) only for a real transition and only when an
    // actor is supplied. Gating on `transitioned` keeps a relay-manager retry after
    // a lost response, or a duplicate revocation, from appending a second event
    // asserting a state change that never happened. The table's actor_pubkey is
    // NOT NULL, so no actor -> log-only. A failed insert logs and the clear still
    // succeeds. (keycast#279 raises the same bar for status changes.)
    if transitioned {
        if let Some(actor) = params.actor.as_deref() {
            let audit_repo = AdminAuditEventRepository::new(auth_state.state.db.clone());
            if let Err(error) = audit_repo
                .record(AdminAuditEventRecord {
                    tenant_id,
                    actor_pubkey: actor.to_string(),
                    action: "clear_verified_minor".to_string(),
                    target_resource_type: "user".to_string(),
                    target_resource_id: Some(pubkey.clone()),
                    target_client_id: None,
                    metadata_json: serde_json::json!({ "reason": reason_clean }),
                })
                .await
            {
                tracing::error!(
                    pubkey = %pubkey,
                    error = %error,
                    "Failed to write admin_audit_events row for verified_minor clear"
                );
            }
        }
    }

    // Close the revocation door. Clearing the flag alone leaves any claim link
    // issued before the clear live, and claim redemption gates only on token
    // validity -- not on status or verified_minor -- so a minor account revoked
    // before it is claimed could still be claimed and land as a normal account
    // with no minor protections. Invalidate outstanding tokens so that path is
    // shut regardless of whether relay-manager also changes status.
    //
    // Run this unconditionally, not just on a transition: a retry after a
    // mid-request crash (flag already cleared, tokens not yet invalidated) must
    // still close the door. `invalidate_valid_for_user` only touches still-valid,
    // unused tokens, so it is idempotent and a no-op for an already-claimed
    // (age-up) account. Unlike the best-effort audit row this is a safety
    // invariant: a failure fails the request so the idempotent caller retries
    // rather than silently leaving the link open.
    let claim_token_repo = ClaimTokenRepository::new(auth_state.state.db.clone());
    let invalidated_by = params
        .actor
        .as_deref()
        .unwrap_or("system:verified_minor_clear");
    let invalidated = match claim_token_repo
        .invalidate_valid_for_user(&pubkey, tenant_id, invalidated_by, reason_clean.as_deref())
        .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(
                pubkey = %pubkey,
                error = %error,
                "Failed to invalidate outstanding claim tokens on verified_minor clear"
            );
            return Err(error.into());
        }
    };
    if invalidated > 0 {
        tracing::info!(
            pubkey = %pubkey,
            invalidated,
            "Invalidated outstanding claim tokens on verified_minor clear"
        );
    }

    let FullAdminStatusRow {
        status,
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    } = user_repo
        .get_full_admin_status(&pubkey, tenant_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(Json(UserStatusResponse {
        pubkey,
        status: status.as_str().to_string(),
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    }))
}

// --- Create approved minor account (service-token auth) ---

#[derive(Debug, Deserialize)]
pub struct CreateMinorAccountRequest {
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMinorAccountResponse {
    pub pubkey: String,
    pub claim_url: String,
    pub expires_at: String,
}

pub async fn create_minor_account(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<CreateMinorAccountRequest>,
) -> ApiResult<axum::response::Response> {
    authorize_service_token(&headers)?;
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    let username = req.username.trim().to_lowercase();
    if username.is_empty() {
        return Err(ApiError::bad_request("username is required"));
    }
    if username.len() > 64
        || !username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        || !username.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !username.ends_with(|c: char| c.is_ascii_alphanumeric())
    {
        return Err(ApiError::bad_request(
            "username must be 1-64 characters, start and end with alphanumeric, containing only lowercase letters, digits, hyphens, or underscores",
        ));
    }

    let user_repo = UserRepository::new(pool.clone());
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());

    // Single query checks username existence + minor/unclaimed status atomically.
    if let Some((existing_pubkey, _verified_minor, is_unclaimed)) = user_repo
        .find_user_minor_status_by_username(&username, tenant_id)
        .await?
    {
        if !is_unclaimed {
            return Err(ApiError::conflict(format!(
                "User with username {} already exists",
                username
            )));
        }

        // Existing unclaimed minor — return existing valid token or create a new one
        let claim_token = if let Some(existing_token) = claim_token_repo
            .find_valid_by_user_pubkey(&existing_pubkey, tenant_id)
            .await?
        {
            existing_token
        } else {
            let token = generate_claim_token();
            let (new_token, _invalidated) = claim_token_repo
                .create_with_prior_invalidation(&token, &existing_pubkey, None, tenant_id)
                .await?;
            new_token
        };

        let app_url =
            std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let claim_url = format!("{}/api/claim?token={}", app_url, claim_token.token);

        tracing::info!(
            event = "minor_account_retry",
            pubkey = %existing_pubkey,
            username = %username,
            "Returning claim link for existing unclaimed minor account"
        );

        return Ok((
            StatusCode::OK,
            Json(CreateMinorAccountResponse {
                pubkey: existing_pubkey,
                claim_url,
                expires_at: claim_token.expires_at.to_rfc3339(),
            }),
        )
            .into_response());
    }

    let keys = Keys::generate();
    let pubkey_hex = keys.public_key().to_hex();

    let secret_bytes = keys.secret_key().to_secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&secret_bytes)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to encrypt secret: {}", e)))?;

    match user_repo
        .create_minor_account(
            &pubkey_hex,
            tenant_id,
            &username,
            req.display_name.as_deref(),
            &encrypted_secret,
        )
        .await
    {
        Ok(()) => {}
        Err(RepositoryError::Duplicate) => {
            // Concurrent request created this user first. Re-query and return idempotently.
            if let Some((dup_pubkey, _, true)) = user_repo
                .find_user_minor_status_by_username(&username, tenant_id)
                .await?
            {
                let claim_token = if let Some(existing_token) = claim_token_repo
                    .find_valid_by_user_pubkey(&dup_pubkey, tenant_id)
                    .await?
                {
                    existing_token
                } else {
                    let token = generate_claim_token();
                    let (new_token, _) = claim_token_repo
                        .create_with_prior_invalidation(&token, &dup_pubkey, None, tenant_id)
                        .await?;
                    new_token
                };

                let app_url = std::env::var("APP_URL")
                    .unwrap_or_else(|_| "http://localhost:3000".to_string());
                let claim_url = format!("{}/api/claim?token={}", app_url, claim_token.token);

                return Ok((
                    StatusCode::OK,
                    Json(CreateMinorAccountResponse {
                        pubkey: dup_pubkey,
                        claim_url,
                        expires_at: claim_token.expires_at.to_rfc3339(),
                    }),
                )
                    .into_response());
            }
            return Err(ApiError::conflict(format!(
                "User with username {} already exists",
                username
            )));
        }
        Err(e) => return Err(e.into()),
    }

    if crate::divine_names::is_enabled() {
        match crate::divine_names::claim_username(&keys, &username, None).await {
            Ok(response) if response.ok => {
                tracing::info!("Username '{}' claimed on divine-name-server", username);
            }
            Ok(response) => {
                tracing::warn!(
                    "divine-name-server rejected username '{}': {}",
                    username,
                    response.error.unwrap_or_default()
                );
            }
            Err(e) => {
                tracing::warn!("divine-name-server unreachable for '{}': {}", username, e);
            }
        }
    }

    let token = generate_claim_token();
    let claim_token = claim_token_repo
        .create(&token, &pubkey_hex, None, tenant_id)
        .await?;

    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let claim_url = format!("{}/api/claim?token={}", app_url, claim_token.token);

    tracing::info!(
        event = "minor_account_created",
        pubkey = %pubkey_hex,
        username = %username,
        "Approved minor account created with claim link"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateMinorAccountResponse {
            pubkey: pubkey_hex,
            claim_url,
            expires_at: claim_token.expires_at.to_rfc3339(),
        }),
    )
        .into_response())
}

// --- Batch user lookup by email (for divine-invite-sync HubSpot enrichment) ---

#[derive(Debug, Deserialize)]
pub struct BatchLookupRequest {
    pub emails: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchLookupUser {
    pub email: String,
    pub pubkey: String,
    pub status: String,
    pub email_verified: bool,
    pub has_personal_key: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchLookupResponse {
    pub results: std::collections::HashMap<String, BatchLookupUser>,
    pub not_found: Vec<String>,
}

pub async fn batch_lookup_users(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<BatchLookupRequest>,
) -> ApiResult<Json<BatchLookupResponse>> {
    authorize_service_token(&headers)?;

    if req.emails.len() > 1000 {
        return Err(ApiError::bad_request("Maximum 1000 emails per request"));
    }

    let deduped: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        req.emails
            .iter()
            .map(|e| e.to_lowercase())
            .filter(|e| seen.insert(e.clone()))
            .collect()
    };

    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(auth_state.state.db.clone());

    let users = user_repo.find_users_by_emails(&deduped, tenant_id).await?;

    let mut results = std::collections::HashMap::new();
    let mut found_emails: std::collections::HashSet<String> = std::collections::HashSet::new();

    for user in users {
        if let Some(email) = &user.email {
            let lower = email.to_lowercase();
            found_emails.insert(lower.clone());
            results.insert(
                lower,
                BatchLookupUser {
                    email: email.clone(),
                    pubkey: user.pubkey,
                    status: user.status.as_str().to_string(),
                    email_verified: user.email_verified.unwrap_or(false),
                    has_personal_key: user.has_personal_key,
                    created_at: user.created_at.to_rfc3339(),
                },
            );
        }
    }

    let not_found: Vec<String> = deduped
        .into_iter()
        .filter(|e| !found_emails.contains(e))
        .collect();

    Ok(Json(BatchLookupResponse { results, not_found }))
}
