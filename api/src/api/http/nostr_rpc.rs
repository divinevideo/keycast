// ABOUTME: REST RPC API that mirrors NIP-46 methods for low-latency signing
// ABOUTME: Allows HTTP-based signing instead of relay-based NIP-46 communication

use crate::handlers::http_rpc_handler::{HandlerError, HttpRpcHandler};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    OAuthAuthorizationRepository, PersonalKeysRepository, PolicyRepository, UserRepository,
};
use keycast_core::signing_session::{parse_cache_key, CacheKey, SigningSession};
use keycast_core::traits::CustomPermission;
use nostr_sdk::{Keys, PublicKey, UnsignedEvent};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::sync::Arc;

use super::auth::AuthError;
use super::routes::AuthState;

/// RPC request format (mirrors NIP-46)
#[derive(Debug, Deserialize)]
pub struct NostrRpcRequest {
    pub method: String,
    #[serde(default)]
    pub params: Vec<JsonValue>,
}

/// RPC response format
#[derive(Debug, Serialize)]
pub struct NostrRpcResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl NostrRpcResponse {
    fn success(result: JsonValue) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(message.into()),
        }
    }
}

#[derive(Debug)]
pub enum RpcError {
    Auth(AuthError),
    InvalidParams(String),
    UnsupportedMethod(String),
    SigningFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    Internal(String),
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            RpcError::Auth(e) => return e.into_response(),
            RpcError::InvalidParams(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::UnsupportedMethod(method) => (
                StatusCode::BAD_REQUEST,
                format!("Unsupported method: {}", method),
            ),
            RpcError::SigningFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::EncryptionFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::DecryptionFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(NostrRpcResponse::error(message))).into_response()
    }
}

impl From<AuthError> for RpcError {
    fn from(e: AuthError) -> Self {
        RpcError::Auth(e)
    }
}

impl From<HandlerError> for RpcError {
    fn from(e: HandlerError) -> Self {
        match e {
            HandlerError::AuthorizationInvalid => RpcError::Auth(AuthError::InvalidToken),
            HandlerError::PermissionDenied => {
                RpcError::Auth(AuthError::Forbidden("Operation denied by policy".into()))
            }
            HandlerError::Signing(msg) => RpcError::SigningFailed(msg),
            HandlerError::Encryption(msg) => RpcError::EncryptionFailed(msg),
        }
    }
}

/// POST /api/nostr - JSON-RPC style endpoint for NIP-46 operations
///
/// Supports all NIP-46 methods:
/// - get_public_key: Returns user's hex pubkey
/// - sign_event: Signs an unsigned event
/// - nip04_encrypt: Encrypts plaintext using NIP-04
/// - nip04_decrypt: Decrypts ciphertext using NIP-04
/// - nip44_encrypt: Encrypts plaintext using NIP-44
/// - nip44_decrypt: Decrypts ciphertext using NIP-44
///
/// Uses BLAKE3 token cache - on cache hit, skips UCAN verification entirely.
/// All operations use cached handler with in-memory permission validation (no DB hits).
pub async fn nostr_rpc(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<NostrRpcRequest>,
) -> Result<Json<NostrRpcResponse>, RpcError> {
    // Track total HTTP RPC requests
    METRICS.inc_http_rpc_request();

    // Extract raw Authorization header for BLAKE3 caching
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(RpcError::Auth(AuthError::MissingToken))?;

    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    tracing::debug!("RPC request: method={}", req.method);

    // Get cached handler using BLAKE3(token) as cache key
    // On cache hit: skips UCAN verification entirely (~25% CPU savings)
    // On cache miss: verifies UCAN, loads from DB, caches result
    let handler = match get_handler(&auth_state, pool, auth_header, tenant_id, &headers).await {
        Ok(h) => h,
        Err(e) => {
            METRICS.inc_http_rpc_auth_error();
            return Err(e);
        }
    };

    // Dispatch based on method - all permission checks use cached data (no DB hits)
    let result = match req.method.as_str() {
        "get_public_key" => JsonValue::String(handler.user_pubkey_hex()),

        "sign_event" => {
            let unsigned_event = parse_unsigned_event(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            let signed = handler.sign_event(unsigned_event).await?;

            tracing::info!(
                "RPC: Signed event {} kind={}",
                signed.id,
                signed.kind.as_u16()
            );

            // Log activity in background (non-blocking)
            spawn_log_activity(pool.clone(), handler.is_oauth(), handler.authorization_id());

            serde_json::to_value(&signed)
                .map_err(|e| RpcError::Internal(format!("JSON serialization failed: {}", e)))?
        }

        "nip44_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let ciphertext = handler.nip44_encrypt(&recipient_pubkey, &plaintext).await?;

            // Log activity in background (non-blocking)
            spawn_log_activity(pool.clone(), handler.is_oauth(), handler.authorization_id());

            JsonValue::String(ciphertext)
        }

        "nip44_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let plaintext = handler.nip44_decrypt(&sender_pubkey, &ciphertext).await?;

            // Log activity in background (non-blocking)
            spawn_log_activity(pool.clone(), handler.is_oauth(), handler.authorization_id());

            // Expose secret only at serialization boundary
            JsonValue::String(plaintext.expose_secret().to_string())
        }

        "nip04_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let ciphertext = handler.nip04_encrypt(&recipient_pubkey, &plaintext).await?;

            // Log activity in background (non-blocking)
            spawn_log_activity(pool.clone(), handler.is_oauth(), handler.authorization_id());

            JsonValue::String(ciphertext)
        }

        "nip04_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let plaintext = handler.nip04_decrypt(&sender_pubkey, &ciphertext).await?;

            // Log activity in background (non-blocking)
            spawn_log_activity(pool.clone(), handler.is_oauth(), handler.authorization_id());

            // Expose secret only at serialization boundary
            JsonValue::String(plaintext.expose_secret().to_string())
        }

        method => {
            return Err(RpcError::UnsupportedMethod(method.to_string()));
        }
    };

    // Track successful requests
    METRICS.inc_http_rpc_success();

    Ok(Json(NostrRpcResponse::success(result)))
}

/// Load an HttpRpcHandler on-demand from DB and cache it
/// Called when http_handler_cache misses for the given bunker_pubkey
/// Loads authorization metadata, user keys, AND permissions - all cached in handler
async fn load_handler_on_demand(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    bunker_pubkey_hex: &str,
    tenant_id: i64,
    dpop_cnf_jkt: Option<String>,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    let key_manager = auth_state.state.key_manager.as_ref();

    // Query oauth_authorization for this bunker_pubkey, scoped to tenant
    // Includes: expires_at, revoked_at (for validity), policy_id (for permissions)
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let auth_data = oauth_auth_repo
        .find_by_bunker_pubkey_for_tenant(bunker_pubkey_hex, tenant_id)
        .await
        .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?;

    let (auth_id, user_pubkey, auth_handle_opt, expires_at, revoked_at, policy_id) =
        auth_data.ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // Load permissions for this authorization's policy (if any)
    let permissions: Vec<Box<dyn CustomPermission>> = if let Some(pid) = policy_id {
        let policy_repo = PolicyRepository::new(pool.clone());
        let db_permissions = policy_repo.get_permissions(pid).await.map_err(|e| {
            RpcError::Internal(format!("Database error loading permissions: {}", e))
        })?;

        // Convert to CustomPermission trait objects
        db_permissions
            .iter()
            .filter_map(|p| p.to_custom_permission().ok())
            .collect()
    } else {
        // No policy = full access (empty permissions vec)
        vec![]
    };

    // Get user's encrypted secret key, scoped to tenant
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await
        .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| RpcError::Internal("Personal keys not found".to_string()))?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| RpcError::Internal(format!("Decryption failed: {}", e)))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| RpcError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let user_keys = Keys::new(secret_key.into());

    // Parse cache keys
    let bunker_key = parse_cache_key(bunker_pubkey_hex)
        .map_err(|e| RpcError::Internal(format!("Invalid bunker_pubkey: {}", e)))?;

    // For authorization_handle, use it if present, otherwise use bunker_pubkey as fallback
    let auth_handle = if let Some(ref handle) = auth_handle_opt {
        parse_cache_key(handle)
            .map_err(|e| RpcError::Internal(format!("Invalid authorization_handle: {}", e)))?
    } else {
        bunker_key // Fallback: use bunker_pubkey as handle for legacy auths
    };

    // Create signing session (pure crypto wrapper - just keys)
    let session = Arc::new(SigningSession::new(user_keys));

    // Create handler with cached authorization metadata, permissions, and cache keys
    let handler = Arc::new(HttpRpcHandler::new(
        session,
        auth_id as i64,
        expires_at,
        revoked_at,
        permissions,
        true, // OAuth authorization
        bunker_key,
        auth_handle,
        dpop_cnf_jkt,
    ));

    // Note: Caching is done by caller with BLAKE3(token) key, not here
    // This allows skipping UCAN verification entirely on cache hits

    Ok(handler)
}

/// Construct the absolute htu (HTTP Target URI) from request headers per RFC 9449.
/// Uses x-forwarded-proto for scheme and Host header for host.
fn construct_htu(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{}://{}/api/nostr", scheme, host)
}

/// Compute BLAKE3 hash of token for cache lookup
/// BLAKE3 is ~500ns for 500-byte token vs ~1-2ms for Schnorr verification (2000-4000x faster)
fn compute_token_cache_key(auth_header: &str) -> Option<CacheKey> {
    let token = auth_header.strip_prefix("Bearer ")?;
    Some(*blake3::hash(token.as_bytes()).as_bytes())
}

fn map_dpop_error_to_rpc_error(error: anyhow::Error, context: &str) -> RpcError {
    if crate::ucan_auth::is_replay_cache_unavailable_error(&error) {
        tracing::error!("RPC: DPoP verification failed ({context}): {}", error);
        RpcError::Internal("DPoP replay protection temporarily unavailable. Please retry.".into())
    } else {
        tracing::warn!("RPC: DPoP verification failed ({context}): {}", error);
        RpcError::Auth(AuthError::InvalidToken)
    }
}

async fn enforce_cached_dpop_binding(
    handler: &HttpRpcHandler,
    headers: &HeaderMap,
    htu: &str,
) -> Result<(), RpcError> {
    let Some(expected_jkt) = handler.expected_dpop_jkt() else {
        return Ok(());
    };

    match crate::ucan_auth::verify_dpop_proof(headers, "POST", htu, Some(expected_jkt)).await {
        Ok(Some(_)) => {
            tracing::debug!("RPC: DPoP binding verified on cache hit");
            Ok(())
        }
        Ok(None) => {
            tracing::warn!(
                "RPC: DPoP-bound token used without DPoP proof on cache hit (jkt={})",
                &expected_jkt[..8.min(expected_jkt.len())]
            );
            Err(RpcError::Auth(AuthError::InvalidToken))
        }
        Err(e) => Err(map_dpop_error_to_rpc_error(e, "cache hit")),
    }
}

/// Check if issuer matches server pubkey (server-signed UCAN)
fn is_server_signed(ucan: &ucan::Ucan) -> bool {
    crate::ucan_auth::is_server_signed(ucan)
}

/// Load handler for preloaded user (server-signed UCAN, no bunker_pubkey)
/// Originally for unclaimed Vine imports; gate dropped to allow admin-issued
/// preload UCANs to keep signing for accounts after claim — needed to publish
/// additional legacy Vine archives discovered after handover.
///
/// Caller must pass the UCAN's `redirect_origin` and `exp` so we can (1) reject
/// non-preload server-signed UCANs (admin sessions, claim UCANs, etc.) and (2)
/// propagate the UCAN expiry into the cached handler so warm cache hits stop
/// signing once the UCAN lifetime ends.
async fn load_preloaded_user_handler(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    user_pubkey_hex: &str,
    tenant_id: i64,
    redirect_origin: &str,
    ucan_expires_at: Option<DateTime<Utc>>,
    dpop_cnf_jkt: Option<String>,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    // Only accept UCANs minted by generate_preload_ucan (admin.rs).
    // Other server-signed UCANs (admin sessions, claim flow) must not be usable
    // to sign as preload users via this path.
    if redirect_origin != "preload" {
        tracing::warn!(
            "Preloaded user RPC denied: redirect_origin={} for user {}",
            redirect_origin,
            &user_pubkey_hex[..8]
        );
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    let key_manager = auth_state.state.key_manager.as_ref();

    // Verify user exists (encrypted key lookup below will also catch missing rows).
    let user_repo = UserRepository::new(pool.clone());
    if user_repo
        .is_unclaimed(user_pubkey_hex, tenant_id)
        .await
        .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?
        .is_none()
    {
        tracing::warn!(
            "Preloaded user RPC denied: user {} not found",
            &user_pubkey_hex[..8]
        );
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    // Get user's encrypted secret key, scoped to tenant
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key_for_tenant(user_pubkey_hex, tenant_id)
        .await
        .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| {
            RpcError::Internal("Personal keys not found for preloaded user".to_string())
        })?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| RpcError::Internal(format!("Decryption failed: {}", e)))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| RpcError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let user_keys = Keys::new(secret_key.into());

    // Create a synthetic cache key from user pubkey (for cache storage)
    let cache_key = parse_cache_key(user_pubkey_hex)
        .map_err(|e| RpcError::Internal(format!("Invalid user_pubkey: {}", e)))?;

    // Create signing session
    let session = Arc::new(SigningSession::new(user_keys));

    // Create handler with NO policy restrictions (empty permissions = full access).
    // The cached handler's expiry is the UCAN's exp: cache hits short-circuit UCAN
    // validation entirely, so without this, a warm cache entry would keep signing
    // past the UCAN's lifetime until the entry was idle-evicted.
    let handler = Arc::new(HttpRpcHandler::new(
        session,
        0,               // No authorization_id - this is direct access
        ucan_expires_at, // Stop signing when the UCAN expires (Daniel feedback)
        None,            // Not revoked
        vec![],          // No permissions = full access
        false,           // Not OAuth (preloaded user mode)
        cache_key,
        cache_key, // Use same key for auth_handle
        dpop_cnf_jkt,
    ));

    tracing::info!(
        "Preloaded user handler created for pubkey: {}",
        &user_pubkey_hex[..8]
    );

    Ok(handler)
}

/// Get the HttpRpcHandler for this request using BLAKE3 token cache
///
/// FAST PATH (cache hit): BLAKE3(token) lookup → return handler (~500ns)
/// - Skips UCAN parsing and Schnorr signature verification entirely
///
/// SLOW PATH (cache miss): Full UCAN verification → DB load → cache insert
/// Three authentication modes are supported:
/// 1. OAuth tokens: bunker_pubkey in UCAN → load from oauth_authorizations
/// 2. Preloaded users: server-signed UCAN without bunker_pubkey → load personal key directly
/// 3. Session UCANs: user-signed without bunker_pubkey → rejected (use OAuth flow)
///
/// All subsequent operations (sign, encrypt, decrypt) use cached data - no DB hits.
async fn get_handler(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    auth_header: &str,
    tenant_id: i64,
    headers: &HeaderMap,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    // Compute BLAKE3 hash for cache lookup (~500ns)
    let blake3_key =
        compute_token_cache_key(auth_header).ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // FAST PATH: Check cache by BLAKE3(token) - skips UCAN entirely!
    if let Some(handler) = auth_state.state.http_handler_cache.get(&blake3_key).await {
        // Check cached validity (no DB hit for expired/revoked)
        if !handler.is_valid() {
            // Evict invalid handler from cache
            auth_state
                .state
                .http_handler_cache
                .invalidate(&blake3_key)
                .await;
            return Err(RpcError::Auth(AuthError::InvalidToken));
        }

        // On cache hit, enforce DPoP binding from cached UCAN cnf.jkt.
        let htu = construct_htu(headers);
        enforce_cached_dpop_binding(&handler, headers, &htu).await?;

        // Cache hit! Skip full UCAN verification
        METRICS.inc_http_rpc_cache_hit();
        tracing::trace!("RPC: Cache hit (BLAKE3)");
        return Ok(handler);
    }

    // SLOW PATH: Cache miss - full UCAN verification
    METRICS.inc_http_rpc_cache_miss();

    // Verify UCAN and extract bunker_pubkey (Schnorr signature verification ~1-2ms)
    let (user_pubkey, redirect_origin, bunker_pubkey, ucan) =
        crate::ucan_auth::validate_ucan_token(auth_header, tenant_id)
            .await
            .map_err(|_| RpcError::Auth(AuthError::InvalidToken))?;

    // Extract UCAN expiry (unix seconds → DateTime<Utc>) so cached preload
    // handlers can be invalidated once the UCAN lifetime ends.
    let ucan_expires_at: Option<DateTime<Utc>> =
        DateTime::<Utc>::from_timestamp(*ucan.expires_at() as i64, 0);

    let dpop_cnf_jkt = crate::ucan_auth::extract_cnf_jkt_from_ucan(&ucan);

    // Enforce DPoP binding if the UCAN contains cnf.jkt.
    if let Some(expected_jkt) = dpop_cnf_jkt.as_deref() {
        // RFC 9449 requires htu to be the absolute URI (scheme + host + path)
        let htu = construct_htu(headers);
        match crate::ucan_auth::verify_dpop_proof(headers, "POST", &htu, Some(expected_jkt)).await {
            Ok(Some(_)) => {
                tracing::debug!("RPC: DPoP binding verified for cnf.jkt");
            }
            Ok(None) => {
                tracing::warn!(
                    "RPC: DPoP-bound token used without DPoP proof (jkt={})",
                    &expected_jkt[..8.min(expected_jkt.len())]
                );
                return Err(RpcError::Auth(AuthError::InvalidToken));
            }
            Err(e) => {
                return Err(map_dpop_error_to_rpc_error(e, "cache miss"));
            }
        }
    }

    // Determine which authentication mode to use
    let handler = if let Some(bunker_key_hex) = bunker_pubkey {
        // MODE 1: OAuth token with bunker_pubkey - load from oauth_authorizations (tenant-scoped)
        let h = load_handler_on_demand(
            auth_state,
            pool,
            &bunker_key_hex,
            tenant_id,
            dpop_cnf_jkt.clone(),
        )
        .await?;
        tracing::debug!(
            "RPC: Loaded OAuth handler for bunker {}",
            &bunker_key_hex[..8]
        );
        h
    } else if is_server_signed(&ucan) {
        // MODE 2: Preloaded user - server-signed UCAN without bunker_pubkey
        // Used for Vine import; works for both unclaimed and claimed accounts so
        // admins can publish additional legacy archives after handover.
        // The callee rejects server-signed UCANs whose redirect_origin != "preload"
        // so admin-session / claim UCANs cannot fall through this path.
        let h = load_preloaded_user_handler(
            auth_state,
            pool,
            &user_pubkey,
            tenant_id,
            &redirect_origin,
            ucan_expires_at,
            dpop_cnf_jkt.clone(),
        )
        .await?;
        tracing::debug!(
            "RPC: Loaded preloaded user handler for pubkey {}",
            &user_pubkey[..8]
        );
        h
    } else {
        // MODE 3: Session UCAN (user-signed, no bunker_pubkey) - not valid for RPC
        // Users must go through OAuth flow to get a bunker_pubkey token
        tracing::warn!(
            "RPC: Rejected session UCAN for user {} (no bunker_pubkey, not server-signed)",
            &user_pubkey[..8]
        );
        return Err(RpcError::Auth(AuthError::InvalidToken));
    };

    if !handler.is_valid() {
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    // Insert into cache with BLAKE3(token) as key
    auth_state
        .state
        .http_handler_cache
        .insert(blake3_key, handler.clone())
        .await;

    // Update cache size metric
    METRICS.set_http_rpc_cache_size(auth_state.state.http_handler_cache.entry_count());

    Ok(handler)
}

/// Parse unsigned event from params (first param is the event object)
fn parse_unsigned_event(params: &[JsonValue]) -> Result<UnsignedEvent, RpcError> {
    let event_value = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams("Missing event parameter".into()))?;

    // Handle both string (NIP-46 style) and object (direct JSON) formats
    let unsigned_event: UnsignedEvent = if let Some(event_str) = event_value.as_str() {
        serde_json::from_str(event_str)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid event JSON: {}", e)))?
    } else {
        serde_json::from_value(event_value.clone())
            .map_err(|e| RpcError::InvalidParams(format!("Invalid event format: {}", e)))?
    };

    Ok(unsigned_event)
}

/// Parse encrypt params: [pubkey, plaintext]
fn parse_encrypt_params(params: &[JsonValue]) -> Result<(PublicKey, String), RpcError> {
    let pubkey_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing recipient pubkey parameter".into()))?;

    let plaintext = params
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing plaintext parameter".into()))?;

    let pubkey = PublicKey::from_hex(pubkey_hex)
        .map_err(|e| RpcError::InvalidParams(format!("Invalid pubkey: {}", e)))?;

    Ok((pubkey, plaintext.to_string()))
}

/// Parse decrypt params: [pubkey, ciphertext]
fn parse_decrypt_params(params: &[JsonValue]) -> Result<(PublicKey, String), RpcError> {
    let pubkey_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing sender pubkey parameter".into()))?;

    let ciphertext = params
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing ciphertext parameter".into()))?;

    let pubkey = PublicKey::from_hex(pubkey_hex)
        .map_err(|e| RpcError::InvalidParams(format!("Invalid pubkey: {}", e)))?;

    Ok((pubkey, ciphertext.to_string()))
}

/// Spawn activity logging in background (non-blocking)
/// Updates oauth_authorizations stats without blocking the response
fn spawn_log_activity(pool: PgPool, is_oauth: bool, authorization_id: i64) {
    if !is_oauth {
        return;
    }

    tokio::spawn(async move {
        if let Err(e) = sqlx::query(
            "UPDATE oauth_authorizations
             SET last_activity = NOW(), activity_count = activity_count + 1
             WHERE id = $1",
        )
        .bind(authorization_id)
        .execute(&pool)
        .await
        {
            tracing::error!("Failed to update oauth_authorizations activity: {}", e);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};
    use rand::rngs::OsRng;

    fn create_test_handler_with_dpop(expected_jkt: Option<String>) -> HttpRpcHandler {
        let keys = Keys::generate();
        let session = Arc::new(SigningSession::new(keys));
        HttpRpcHandler::new(
            session,
            1,
            None,
            None,
            vec![],
            true,
            [0u8; 32],
            [1u8; 32],
            expected_jkt,
        )
    }

    fn create_dpop_proof(signing_key: &SigningKey, method: &str, htu: &str, jti: &str) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"));
        let iat = chrono::Utc::now().timestamp();

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y
            }
        });
        let payload = serde_json::json!({
            "htm": method,
            "htu": htu,
            "iat": iat,
            "jti": jti
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P256Signature = signing_key.sign(signing_input.as_bytes());
        let (r_bytes, s_bytes) = signature.split_bytes();
        let mut sig_raw = Vec::with_capacity(64);
        sig_raw.extend_from_slice(&r_bytes);
        sig_raw.extend_from_slice(&s_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_raw);

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    fn thumbprint_for_signing_key(signing_key: &SigningKey) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let jwk_map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate")),
                "y": URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"))
            }))
            .expect("jwk map");

        crate::ucan_auth::dpop::jwk_thumbprint(&jwk_map).expect("jwk thumbprint")
    }

    #[test]
    fn test_parse_unsigned_event_object() {
        let params = vec![serde_json::json!({
            "kind": 1,
            "content": "Hello",
            "tags": [],
            "created_at": 1234567890,
            "pubkey": "0000000000000000000000000000000000000000000000000000000000000000"
        })];

        let result = parse_unsigned_event(&params);
        assert!(result.is_ok());
        let event = result.unwrap();
        assert_eq!(event.kind.as_u16(), 1);
        assert_eq!(event.content, "Hello");
    }

    #[test]
    fn test_parse_unsigned_event_string() {
        let event_str = r#"{"kind":1,"content":"Hello","tags":[],"created_at":1234567890,"pubkey":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let params = vec![JsonValue::String(event_str.to_string())];

        let result = parse_unsigned_event(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_encrypt_params() {
        let params = vec![
            JsonValue::String(
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
            JsonValue::String("Hello, world!".to_string()),
        ];

        let result = parse_encrypt_params(&params);
        assert!(result.is_ok());
        let (pubkey, plaintext) = result.unwrap();
        assert_eq!(plaintext, "Hello, world!");
        assert_eq!(
            pubkey.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_parse_encrypt_params_missing_pubkey() {
        let params = vec![];
        let result = parse_encrypt_params(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_encrypt_params_missing_plaintext() {
        let params = vec![JsonValue::String(
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        )];
        let result = parse_encrypt_params(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_rpc_response_success() {
        let response = NostrRpcResponse::success(JsonValue::String("test".to_string()));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_rpc_response_error() {
        let response = NostrRpcResponse::error("test error");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap(), "test error");
    }

    #[test]
    fn test_map_dpop_error_to_rpc_error_replay_cache_unavailable_is_internal() {
        let error = anyhow::Error::new(crate::ucan_auth::dpop::ReplayCacheUnavailableError::new(
            "DPoP replay protection unavailable",
        ));
        let mapped = map_dpop_error_to_rpc_error(error, "test");
        assert!(matches!(mapped, RpcError::Internal(_)));
    }

    #[test]
    fn test_map_dpop_error_to_rpc_error_invalid_proof_is_auth_error() {
        let mapped = map_dpop_error_to_rpc_error(anyhow::anyhow!("invalid dpop proof"), "test");
        assert!(matches!(mapped, RpcError::Auth(AuthError::InvalidToken)));
    }

    #[tokio::test]
    async fn test_cache_hit_dpop_bound_missing_proof_rejected() {
        let handler = create_test_handler_with_dpop(Some("expected-thumbprint".to_string()));
        let headers = HeaderMap::new();

        let result =
            enforce_cached_dpop_binding(&handler, &headers, "https://example.com/api/nostr").await;
        assert!(matches!(
            result,
            Err(RpcError::Auth(AuthError::InvalidToken))
        ));
    }

    #[tokio::test]
    async fn test_cache_hit_dpop_unbound_missing_proof_allowed() {
        let handler = create_test_handler_with_dpop(None);
        let headers = HeaderMap::new();

        let result =
            enforce_cached_dpop_binding(&handler, &headers, "https://example.com/api/nostr").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_hit_dpop_bound_valid_proof_allowed() {
        let signing_key = SigningKey::random(&mut OsRng);
        let expected_jkt = thumbprint_for_signing_key(&signing_key);
        let handler = create_test_handler_with_dpop(Some(expected_jkt));
        let htu = "https://example.com/api/nostr";
        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            htu,
            &format!("cache-hit-jti-{}", uuid::Uuid::new_v4()),
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().expect("valid header value"));

        let result = enforce_cached_dpop_binding(&handler, &headers, htu).await;
        assert!(result.is_ok());
    }
}
