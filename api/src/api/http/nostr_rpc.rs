// ABOUTME: REST RPC API that mirrors NIP-46 methods for low-latency signing
// ABOUTME: Allows HTTP-based signing instead of relay-based NIP-46 communication

use crate::handlers::http_rpc_handler::{insert_handler_dual_key, HandlerError, HttpRpcHandler};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::signing_session::{parse_cache_key, SigningSession};
use keycast_core::traits::CustomPermission;
use keycast_core::types::permission::Permission;
use nostr_sdk::{Keys, PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;

use super::auth::{extract_user_and_origin_from_token, AuthError};
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
/// All operations use cached handler with in-memory permission validation (no DB hits).
pub async fn nostr_rpc(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<NostrRpcRequest>,
) -> Result<Json<NostrRpcResponse>, RpcError> {
    let (user_pubkey, redirect_origin, bunker_pubkey) =
        extract_user_and_origin_from_token(&headers).await?;
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    tracing::info!(
        "RPC request: method={} from user={} origin={}",
        req.method,
        &user_pubkey[..8],
        &redirect_origin
    );

    // Get cached handler (loads from DB on cache miss, then all ops use cached data)
    let handler = get_handler(
        &auth_state,
        pool,
        tenant_id,
        &user_pubkey,
        &redirect_origin,
        bunker_pubkey.as_deref(),
    )
    .await?;

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
            let ciphertext = handler.nip44_encrypt(&recipient_pubkey, &plaintext)?;

            JsonValue::String(ciphertext)
        }

        "nip44_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            let plaintext = handler.nip44_decrypt(&sender_pubkey, &ciphertext)?;

            JsonValue::String(plaintext)
        }

        "nip04_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            let ciphertext = handler.nip04_encrypt(&recipient_pubkey, &plaintext)?;

            JsonValue::String(ciphertext)
        }

        "nip04_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            let plaintext = handler.nip04_decrypt(&sender_pubkey, &ciphertext)?;

            JsonValue::String(plaintext)
        }

        method => {
            return Err(RpcError::UnsupportedMethod(method.to_string()));
        }
    };

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

    // Cache the handler for future requests
    insert_handler_dual_key(&auth_state.state.http_handler_cache, handler.clone()).await;

    tracing::debug!(
        "RPC: Loaded and cached handler for bunker {} (policy_id={:?})",
        &bunker_pubkey_hex[..8],
        policy_id
    );

    Ok(handler)
}

/// Get the HttpRpcHandler for this request (uses cache with on-demand loading)
///
/// Returns the full handler with cached permissions and validity state.
/// The handler is loaded on-demand from the database if not in cache.
/// All subsequent operations (sign, encrypt, decrypt) use cached data - no DB hits.
async fn get_handler(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    bunker_pubkey_from_ucan: Option<&str>,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    // FAST PATH: Check http_handler_cache by bunker_pubkey (if provided in UCAN)
    if let Some(bunker_key_hex) = bunker_pubkey_from_ucan {
        if let Ok(cache_key) = parse_cache_key(bunker_key_hex) {
            if let Some(handler) = auth_state.state.http_handler_cache.get(&cache_key).await {
                // Check cached validity (no DB hit for expired/revoked)
                if !handler.is_valid() {
                    // Evict invalid handler from cache
                    auth_state
                        .state
                        .http_handler_cache
                        .invalidate(&cache_key)
                        .await;
                    return Err(RpcError::Auth(AuthError::InvalidToken));
                }
                tracing::debug!(
                    "RPC: Cache hit for user {} (bunker={})",
                    &user_pubkey[..8],
                    &bunker_key_hex[..8]
                );
                return Ok(handler);
            }
        }

        // On-demand load using bunker_pubkey from UCAN (one-time DB hit)
        let handler = load_handler_on_demand(auth_state, pool, bunker_key_hex).await?;
        if !handler.is_valid() {
            return Err(RpcError::Auth(AuthError::InvalidToken));
        }
        return Ok(handler);
    }

    // Legacy path: resolve bunker_pubkey from DB (for older UCANs without bunker_pubkey)
    let bunker_pubkey_hex: String = sqlx::query_scalar(
        "SELECT oa.bunker_public_key
         FROM oauth_authorizations oa
         JOIN users u ON oa.user_pubkey = u.pubkey
         WHERE oa.user_pubkey = $1 AND u.tenant_id = $2 AND oa.redirect_origin = $3
         AND oa.revoked_at IS NULL
         ORDER BY oa.created_at DESC
         LIMIT 1",
    )
    .bind(user_pubkey)
    .bind(tenant_id)
    .bind(redirect_origin)
    .fetch_optional(pool)
    .await
    .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?
    .ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // Check http_handler_cache with resolved bunker_pubkey
    if let Ok(cache_key) = parse_cache_key(&bunker_pubkey_hex) {
        if let Some(handler) = auth_state.state.http_handler_cache.get(&cache_key).await {
            if !handler.is_valid() {
                auth_state
                    .state
                    .http_handler_cache
                    .invalidate(&cache_key)
                    .await;
                return Err(RpcError::Auth(AuthError::InvalidToken));
            }
            tracing::debug!(
                "RPC: Cache hit (after legacy lookup) for user {}",
                &user_pubkey[..8]
            );
            return Ok(handler);
        }
    }

    // On-demand load (one-time DB hit)
    let handler = load_handler_on_demand(auth_state, pool, &bunker_pubkey_hex).await?;
    if !handler.is_valid() {
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }
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
