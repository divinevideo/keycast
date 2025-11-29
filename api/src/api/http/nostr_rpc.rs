// ABOUTME: REST RPC API that mirrors NIP-46 methods for low-latency signing
// ABOUTME: Allows HTTP-based signing instead of relay-based NIP-46 communication

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use nostr_sdk::nips::{nip04, nip44};
use nostr_sdk::{Keys, PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

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
            RpcError::UnsupportedMethod(method) => {
                (StatusCode::BAD_REQUEST, format!("Unsupported method: {}", method))
            }
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

/// POST /api/nostr - JSON-RPC style endpoint for NIP-46 operations
///
/// Supports all NIP-46 methods:
/// - get_public_key: Returns user's hex pubkey
/// - sign_event: Signs an unsigned event
/// - nip04_encrypt: Encrypts plaintext using NIP-04
/// - nip04_decrypt: Decrypts ciphertext using NIP-04
/// - nip44_encrypt: Encrypts plaintext using NIP-44
/// - nip44_decrypt: Decrypts ciphertext using NIP-44
pub async fn nostr_rpc(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<NostrRpcRequest>,
) -> Result<Json<NostrRpcResponse>, RpcError> {
    let (user_pubkey, redirect_origin) = extract_user_and_origin_from_token(&headers)?;
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    tracing::info!("RPC request: method={} from user={} origin={}", req.method, &user_pubkey[..8], &redirect_origin);

    // Get user keys (try fast path first, then slow path)
    let keys = get_user_keys(&auth_state, pool, tenant_id, &user_pubkey, &redirect_origin).await?;

    // Dispatch based on method
    let result = match req.method.as_str() {
        "get_public_key" => {
            JsonValue::String(keys.public_key().to_hex())
        }

        "sign_event" => {
            let unsigned_event = parse_unsigned_event(&req.params)?;

            // Validate permissions before signing
            super::auth::validate_signing_permissions(pool, tenant_id, &user_pubkey, &redirect_origin, &unsigned_event).await
                .map_err(RpcError::Auth)?;

            // Sign the event
            let signed = unsigned_event.sign(&keys).await
                .map_err(|e| RpcError::SigningFailed(format!("Signing failed: {}", e)))?;

            tracing::info!("RPC: Signed event {} kind={}", signed.id, signed.kind.as_u16());

            serde_json::to_value(&signed)
                .map_err(|e| RpcError::Internal(format!("JSON serialization failed: {}", e)))?
        }

        "nip44_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Validate permissions before encrypting
            super::auth::validate_encrypt_permissions(pool, tenant_id, &user_pubkey, &redirect_origin, &plaintext, &recipient_pubkey).await
                .map_err(RpcError::Auth)?;

            let ciphertext = nip44::encrypt(
                keys.secret_key(),
                &recipient_pubkey,
                &plaintext,
                nip44::Version::V2,
            ).map_err(|e| RpcError::EncryptionFailed(format!("NIP-44 encryption failed: {}", e)))?;

            JsonValue::String(ciphertext)
        }

        "nip44_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Validate permissions before decrypting
            super::auth::validate_decrypt_permissions(pool, tenant_id, &user_pubkey, &redirect_origin, &ciphertext, &sender_pubkey).await
                .map_err(RpcError::Auth)?;

            let plaintext = nip44::decrypt(
                keys.secret_key(),
                &sender_pubkey,
                &ciphertext,
            ).map_err(|e| RpcError::DecryptionFailed(format!("NIP-44 decryption failed: {}", e)))?;

            JsonValue::String(plaintext)
        }

        "nip04_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            // Validate permissions before encrypting
            super::auth::validate_encrypt_permissions(pool, tenant_id, &user_pubkey, &redirect_origin, &plaintext, &recipient_pubkey).await
                .map_err(RpcError::Auth)?;

            let ciphertext = nip04::encrypt(
                keys.secret_key(),
                &recipient_pubkey,
                &plaintext,
            ).map_err(|e| RpcError::EncryptionFailed(format!("NIP-04 encryption failed: {}", e)))?;

            JsonValue::String(ciphertext)
        }

        "nip04_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Validate permissions before decrypting
            super::auth::validate_decrypt_permissions(pool, tenant_id, &user_pubkey, &redirect_origin, &ciphertext, &sender_pubkey).await
                .map_err(RpcError::Auth)?;

            let plaintext = nip04::decrypt(
                keys.secret_key(),
                &sender_pubkey,
                &ciphertext,
            ).map_err(|e| RpcError::DecryptionFailed(format!("NIP-04 decryption failed: {}", e)))?;

            JsonValue::String(plaintext)
        }

        method => {
            return Err(RpcError::UnsupportedMethod(method.to_string()));
        }
    };

    Ok(Json(NostrRpcResponse::success(result)))
}

/// Get user's signing keys (tries fast path with cached handlers, falls back to DB+KMS)
async fn get_user_keys(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
) -> Result<Keys, RpcError> {
    // FAST PATH: Try to use cached signer handler if in unified mode
    if let Some(ref handlers) = auth_state.state.signer_handlers {
        // Query for user's bunker public key for this specific origin
        let bunker_pubkey: Option<String> = sqlx::query_scalar(
            "SELECT oa.bunker_public_key
             FROM oauth_authorizations oa
             JOIN users u ON oa.user_public_key = u.public_key
             WHERE oa.user_public_key = $1 AND u.tenant_id = $2 AND oa.redirect_origin = $3
             ORDER BY oa.created_at DESC
             LIMIT 1"
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .bind(redirect_origin)
        .fetch_optional(pool)
        .await
        .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?;

        if let Some(bunker_key) = bunker_pubkey {
            let handlers_read = handlers.lock().await;
            if let Some(handler) = handlers_read.get(&bunker_key) {
                tracing::debug!("RPC: Using cached keys for user {}", &user_pubkey[..8]);
                return Ok(handler.get_keys());
            }
        }
    }

    // SLOW PATH: Fallback to DB + KMS decryption
    tracing::warn!("RPC: Using slow path (DB+KMS) for user {}", &user_pubkey[..8]);

    let key_manager = auth_state.state.key_manager.as_ref();

    // First verify an oauth_authorization exists for this user+origin combination
    // (protects against using revoked/deleted authorizations)
    let auth_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM oauth_authorizations oa
            JOIN users u ON oa.user_public_key = u.public_key
            WHERE oa.user_public_key = $1 AND u.tenant_id = $2 AND oa.redirect_origin = $3
         )"
    )
    .bind(user_pubkey)
    .bind(tenant_id)
    .bind(redirect_origin)
    .fetch_one(pool)
    .await
    .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?;

    if !auth_exists {
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    // Get user's encrypted secret key
    let result: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT pk.encrypted_secret_key
         FROM personal_keys pk
         JOIN users u ON pk.user_public_key = u.public_key
         WHERE pk.user_public_key = $1 AND u.tenant_id = $2"
    )
    .bind(user_pubkey)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| RpcError::Internal(format!("Database error: {}", e)))?;

    let (encrypted_secret,) = result.ok_or(RpcError::Auth(AuthError::UserNotFound))?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| RpcError::Internal(format!("Decryption failed: {}", e)))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| RpcError::Internal(format!("Invalid secret key bytes: {}", e)))?;

    Ok(Keys::new(secret_key.into()))
}

/// Parse unsigned event from params (first param is the event object)
fn parse_unsigned_event(params: &[JsonValue]) -> Result<UnsignedEvent, RpcError> {
    let event_value = params.first()
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
    let pubkey_hex = params.first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing recipient pubkey parameter".into()))?;

    let plaintext = params.get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing plaintext parameter".into()))?;

    let pubkey = PublicKey::from_hex(pubkey_hex)
        .map_err(|e| RpcError::InvalidParams(format!("Invalid pubkey: {}", e)))?;

    Ok((pubkey, plaintext.to_string()))
}

/// Parse decrypt params: [pubkey, ciphertext]
fn parse_decrypt_params(params: &[JsonValue]) -> Result<(PublicKey, String), RpcError> {
    let pubkey_hex = params.first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing sender pubkey parameter".into()))?;

    let ciphertext = params.get(1)
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
            JsonValue::String("0000000000000000000000000000000000000000000000000000000000000001".to_string()),
            JsonValue::String("Hello, world!".to_string()),
        ];

        let result = parse_encrypt_params(&params);
        assert!(result.is_ok());
        let (pubkey, plaintext) = result.unwrap();
        assert_eq!(plaintext, "Hello, world!");
        assert_eq!(pubkey.to_hex(), "0000000000000000000000000000000000000000000000000000000000000001");
    }

    #[test]
    fn test_parse_encrypt_params_missing_pubkey() {
        let params = vec![];
        let result = parse_encrypt_params(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_encrypt_params_missing_plaintext() {
        let params = vec![
            JsonValue::String("0000000000000000000000000000000000000000000000000000000000000001".to_string()),
        ];
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
