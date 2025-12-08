// ABOUTME: REST RPC API that mirrors NIP-46 methods for low-latency signing
// ABOUTME: Allows HTTP-based signing instead of relay-based NIP-46 communication

use crate::handlers::http_rpc_handler::{HandlerError, HttpRpcHandler};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::metrics::METRICS;
use keycast_core::signing_session::{parse_cache_key, CacheKey, SigningSession};
use keycast_core::traits::CustomPermission;
use keycast_core::types::permission::Permission;
use nostr_sdk::{Keys, PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
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
    _tenant: crate::api::tenant::TenantExtractor,
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

    tracing::debug!("RPC request: method={}", req.method);

    // Get cached handler using BLAKE3(token) as cache key
    // On cache hit: skips UCAN verification entirely (~25% CPU savings)
    // On cache miss: verifies UCAN, loads from DB, caches result
    let handler = match get_handler(&auth_state, pool, auth_header).await {
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

            serde_json::to_value(&signed)
                .map_err(|e| RpcError::Internal(format!("JSON serialization failed: {}", e)))?
        }

        "nip44_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let ciphertext = handler.nip44_encrypt(&recipient_pubkey, &plaintext).await?;

            JsonValue::String(ciphertext)
        }

        "nip44_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let plaintext = handler.nip44_decrypt(&sender_pubkey, &ciphertext).await?;

            JsonValue::String(plaintext)
        }

        "nip04_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let ciphertext = handler.nip04_encrypt(&recipient_pubkey, &plaintext).await?;

            JsonValue::String(ciphertext)
        }

        "nip04_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let plaintext = handler.nip04_decrypt(&sender_pubkey, &ciphertext).await?;

            JsonValue::String(plaintext)
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
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    let key_manager = auth_state.state.key_manager.as_ref();

    // Query oauth_authorization for this bunker_pubkey
    // Includes: expires_at, revoked_at (for validity), policy_id (for permissions)
    #[allow(clippy::type_complexity)]
    let auth_data: Option<(
        i32,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<i32>,
    )> = sqlx::query_as(
        "SELECT id, user_pubkey, authorization_handle, expires_at, revoked_at, policy_id
         FROM oauth_authorizations
         WHERE bunker_public_key = $1",
    )
    .bind(bunker_pubkey_hex)
    .fetch_optional(pool)
    .await
    .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?;

    let (auth_id, user_pubkey, auth_handle_opt, expires_at, revoked_at, policy_id) =
        auth_data.ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // Load permissions for this authorization's policy (if any)
    let permissions: Vec<Box<dyn CustomPermission>> = if let Some(pid) = policy_id {
        let db_permissions: Vec<Permission> = sqlx::query_as(
            "SELECT p.*
             FROM permissions p
             JOIN policy_permissions pp ON pp.permission_id = p.id
             WHERE pp.policy_id = $1",
        )
        .bind(pid)
        .fetch_all(pool)
        .await
        .map_err(|e| RpcError::Internal(format!("Database error loading permissions: {}", e)))?;

        // Convert to CustomPermission trait objects
        db_permissions
            .iter()
            .filter_map(|p| p.to_custom_permission().ok())
            .collect()
    } else {
        // No policy = full access (empty permissions vec)
        vec![]
    };

    // Get user's encrypted secret key
    let encrypted_secret: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .fetch_one(pool)
            .await
            .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?;

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
    ));

    // Note: Caching is done by caller with BLAKE3(token) key, not here
    // This allows skipping UCAN verification entirely on cache hits

    Ok(handler)
}

/// Compute BLAKE3 hash of token for cache lookup
/// BLAKE3 is ~500ns for 500-byte token vs ~1-2ms for Schnorr verification (2000-4000x faster)
fn compute_token_cache_key(auth_header: &str) -> Option<CacheKey> {
    let token = auth_header.strip_prefix("Bearer ")?;
    Some(*blake3::hash(token.as_bytes()).as_bytes())
}

/// Get the HttpRpcHandler for this request using BLAKE3 token cache
///
/// FAST PATH (cache hit): BLAKE3(token) lookup → return handler (~500ns)
/// - Skips UCAN parsing and Schnorr signature verification entirely
///
/// SLOW PATH (cache miss): Full UCAN verification → DB load → cache insert
/// - Requires bunker_pubkey in UCAN (only OAuth access tokens are valid)
/// - Session UCANs (from /api/auth/login) do not have bunker_pubkey and will be rejected
///
/// All subsequent operations (sign, encrypt, decrypt) use cached data - no DB hits.
async fn get_handler(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    auth_header: &str,
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
        // Cache hit! Skip UCAN verification entirely
        METRICS.inc_http_rpc_cache_hit();
        tracing::trace!("RPC: Cache hit (BLAKE3)");
        return Ok(handler);
    }

    // SLOW PATH: Cache miss - full UCAN verification
    METRICS.inc_http_rpc_cache_miss();

    // Verify UCAN and extract bunker_pubkey (Schnorr signature verification ~1-2ms)
    let (_user_pubkey, _redirect_origin, bunker_pubkey, _ucan) =
        crate::ucan_auth::validate_ucan_token(auth_header, 0)
            .await
            .map_err(|_| RpcError::Auth(AuthError::InvalidToken))?;

    // Require bunker_pubkey - session UCANs are not valid for HTTP RPC
    let bunker_key_hex = bunker_pubkey.ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // Load handler from DB using bunker_pubkey
    let handler = load_handler_on_demand(auth_state, pool, &bunker_key_hex).await?;

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

    tracing::debug!(
        "RPC: Loaded and cached handler for bunker {}",
        &bunker_key_hex[..8]
    );

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
