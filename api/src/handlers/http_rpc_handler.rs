// ABOUTME: HTTP RPC handler for on-demand session loading
// ABOUTME: Caches authorization metadata AND permissions for spam protection without DB hits

use chrono::{DateTime, Utc};
use keycast_core::signing_session::{CacheKey, SigningSession};
use keycast_core::traits::CustomPermission;
use moka::future::Cache;
use nostr_sdk::nips::nip04;
use nostr_sdk::{Event, Keys, PublicKey, UnsignedEvent};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("authorization expired or revoked")]
    AuthorizationInvalid,
    #[error("permission denied")]
    PermissionDenied,
    #[error("signing error: {0}")]
    Signing(String),
    #[error("encryption error: {0}")]
    Encryption(String),
}

/// HTTP RPC handler - caches authorization state AND permissions for spam protection
///
/// This handler wraps a SigningSession (pure crypto) and caches:
/// - Authorization metadata (expires_at, revoked_at) for validity checking
/// - Permission rules for policy-based access control
/// - Cache keys for dual-path lookups
///
/// All validation is done in-memory without DB hits after initial load.
pub struct HttpRpcHandler {
    /// The underlying signing session (pure crypto - just Keys)
    signing: Arc<SigningSession>,

    /// Authorization ID (for logging and audit trails)
    authorization_id: i64,

    /// User's public key (for encrypt/decrypt permission checks)
    user_pubkey: PublicKey,

    /// Cached expiration time (checked without DB hit)
    expires_at: Option<DateTime<Utc>>,

    /// Cached revocation time (checked without DB hit)
    revoked_at: Option<DateTime<Utc>>,

    /// Cached permission rules (checked without DB hit)
    /// Empty vec means full access (permissive default)
    permissions: Vec<Box<dyn CustomPermission>>,

    /// Whether this is an OAuth-based authorization
    is_oauth: bool,

    /// Cache key: bunker public key (used for NIP-46 relay + HTTP RPC lookups)
    bunker_pubkey: CacheKey,

    /// Cache key: authorization handle (used for OAuth re-auth only)
    authorization_handle: CacheKey,
}

impl HttpRpcHandler {
    /// Create a new HTTP RPC handler with cached permissions and cache keys
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signing: Arc<SigningSession>,
        authorization_id: i64,
        expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
        permissions: Vec<Box<dyn CustomPermission>>,
        is_oauth: bool,
        bunker_pubkey: CacheKey,
        authorization_handle: CacheKey,
    ) -> Self {
        let user_pubkey = signing.public_key();
        Self {
            signing,
            authorization_id,
            user_pubkey,
            expires_at,
            revoked_at,
            permissions,
            is_oauth,
            bunker_pubkey,
            authorization_handle,
        }
    }

    /// Check if authorization is still valid (cached check - no DB hit)
    ///
    /// Returns false if the authorization has been revoked or has expired.
    /// This allows rejecting spam from invalid authorizations without
    /// hitting the database every request.
    pub fn is_valid(&self) -> bool {
        // Check revocation
        if self.revoked_at.is_some() {
            return false;
        }

        // Check expiration
        if let Some(expires) = self.expires_at {
            if expires < Utc::now() {
                return false;
            }
        }

        true
    }

    /// Validate signing permission against cached policy rules (no DB hit)
    ///
    /// Returns Ok(()) if signing is allowed, Err if denied.
    /// Uses AND logic: ALL permissions must allow for the operation to proceed.
    pub fn validate_sign_permission(&self, event: &UnsignedEvent) -> Result<(), HandlerError> {
        // Empty permissions = full access (permissive default)
        if self.permissions.is_empty() {
            return Ok(());
        }

        // All permissions must allow (defense-in-depth)
        let allowed = self.permissions.iter().all(|p| p.can_sign(event));

        if allowed {
            Ok(())
        } else {
            Err(HandlerError::PermissionDenied)
        }
    }

    /// Validate encryption permission against cached policy rules (no DB hit)
    pub fn validate_encrypt_permission(
        &self,
        plaintext: &str,
        recipient: &PublicKey,
    ) -> Result<(), HandlerError> {
        if self.permissions.is_empty() {
            return Ok(());
        }

        let allowed = self
            .permissions
            .iter()
            .all(|p| p.can_encrypt(plaintext, &self.user_pubkey, recipient));

        if allowed {
            Ok(())
        } else {
            Err(HandlerError::PermissionDenied)
        }
    }

    /// Validate decryption permission against cached policy rules (no DB hit)
    pub fn validate_decrypt_permission(
        &self,
        ciphertext: &str,
        sender: &PublicKey,
    ) -> Result<(), HandlerError> {
        if self.permissions.is_empty() {
            return Ok(());
        }

        let allowed = self
            .permissions
            .iter()
            .all(|p| p.can_decrypt(ciphertext, sender, &self.user_pubkey));

        if allowed {
            Ok(())
        } else {
            Err(HandlerError::PermissionDenied)
        }
    }

    /// Get the user's signing keys
    pub fn keys(&self) -> &Keys {
        self.signing.keys()
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        self.user_pubkey
    }

    /// Get the user's public key as hex string
    pub fn user_pubkey_hex(&self) -> String {
        self.user_pubkey.to_hex()
    }

    /// Get the authorization ID
    pub fn authorization_id(&self) -> i64 {
        self.authorization_id
    }

    /// Get the bunker public key cache key
    pub fn bunker_pubkey(&self) -> &CacheKey {
        &self.bunker_pubkey
    }

    /// Get the authorization handle cache key
    pub fn authorization_handle(&self) -> &CacheKey {
        &self.authorization_handle
    }

    /// Check if this is an OAuth authorization
    pub fn is_oauth(&self) -> bool {
        self.is_oauth
    }

    /// Sign an event after checking validity and permissions
    ///
    /// Returns an error if:
    /// - Authorization has expired or been revoked
    /// - Permission policy denies this event kind
    pub async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_sign_permission(&unsigned)?;

        self.signing
            .sign_event(unsigned)
            .await
            .map_err(|e| HandlerError::Signing(e.to_string()))
    }

    /// Encrypt plaintext using NIP-44 after checking validity and permissions
    /// (CPU-bound crypto runs on spawn_blocking via SigningSession)
    pub async fn nip44_encrypt(
        &self,
        recipient: &PublicKey,
        plaintext: &str,
    ) -> Result<String, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_encrypt_permission(plaintext, recipient)?;

        self.signing
            .nip44_encrypt(recipient, plaintext)
            .await
            .map_err(|e| HandlerError::Encryption(e.to_string()))
    }

    /// Decrypt ciphertext using NIP-44 after checking validity and permissions
    /// (CPU-bound crypto runs on spawn_blocking via SigningSession)
    pub async fn nip44_decrypt(
        &self,
        sender: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_decrypt_permission(ciphertext, sender)?;

        self.signing
            .nip44_decrypt(sender, ciphertext)
            .await
            .map_err(|e| HandlerError::Encryption(e.to_string()))
    }

    /// Encrypt plaintext using NIP-04 after checking validity and permissions
    /// (CPU-bound crypto runs on spawn_blocking)
    pub async fn nip04_encrypt(
        &self,
        recipient: &PublicKey,
        plaintext: &str,
    ) -> Result<String, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_encrypt_permission(plaintext, recipient)?;

        let secret = self.signing.keys().secret_key().clone();
        let recipient = *recipient;
        let plaintext = plaintext.to_string();

        tokio::task::spawn_blocking(move || nip04::encrypt(&secret, &recipient, &plaintext))
            .await
            .map_err(|e| HandlerError::Encryption(format!("blocking task failed: {}", e)))?
            .map_err(|e| HandlerError::Encryption(e.to_string()))
    }

    /// Decrypt ciphertext using NIP-04 after checking validity and permissions
    /// (CPU-bound crypto runs on spawn_blocking)
    pub async fn nip04_decrypt(
        &self,
        sender: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_decrypt_permission(ciphertext, sender)?;

        let secret = self.signing.keys().secret_key().clone();
        let sender = *sender;
        let ciphertext = ciphertext.to_string();

        tokio::task::spawn_blocking(move || nip04::decrypt(&secret, &sender, &ciphertext))
            .await
            .map_err(|e| HandlerError::Encryption(format!("blocking task failed: {}", e)))?
            .map_err(|e| HandlerError::Encryption(e.to_string()))
    }
}

/// Cache type for HTTP RPC handlers
/// Uses the same CacheKey as SigningSession for bunker_pubkey lookups
pub type HttpHandlerCache = Cache<CacheKey, Arc<HttpRpcHandler>>;

/// Default handler cache size (1 million entries)
const DEFAULT_HANDLER_CACHE_SIZE: u64 = 1_000_000;

/// Create a new HTTP handler cache
///
/// Cache size is configurable via `HANDLER_CACHE_SIZE` env var (default: 1,000,000)
pub fn new_http_handler_cache() -> HttpHandlerCache {
    let cache_size = std::env::var("HANDLER_CACHE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HANDLER_CACHE_SIZE);

    tracing::info!("HTTP handler cache capacity: {}", cache_size);

    Cache::builder()
        .max_capacity(cache_size)
        .time_to_idle(std::time::Duration::from_secs(3600)) // 1 hour idle timeout
        .build()
}

/// Insert handler into cache under both keys for dual-path lookups
/// - bunker_pubkey: used by NIP-46 relay + HTTP RPC
/// - authorization_handle: used by OAuth re-auth only
pub async fn insert_handler_dual_key(cache: &HttpHandlerCache, handler: Arc<HttpRpcHandler>) {
    cache
        .insert(*handler.authorization_handle(), handler.clone())
        .await;
    cache.insert(*handler.bunker_pubkey(), handler).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_handler(
        expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> HttpRpcHandler {
        create_test_handler_with_permissions(expires_at, revoked_at, vec![])
    }

    fn create_test_handler_with_permissions(
        expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
        permissions: Vec<Box<dyn CustomPermission>>,
    ) -> HttpRpcHandler {
        let keys = Keys::generate();
        let bunker_key = [0u8; 32];
        let auth_handle = [1u8; 32];
        let signing = Arc::new(SigningSession::new(keys));

        HttpRpcHandler::new(
            signing,
            1,
            expires_at,
            revoked_at,
            permissions,
            true,
            bunker_key,
            auth_handle,
        )
    }

    #[test]
    fn test_is_valid_no_expiration() {
        let handler = create_test_handler(None, None);
        assert!(handler.is_valid());
    }

    #[test]
    fn test_is_valid_not_expired() {
        let expires = Utc::now() + chrono::Duration::hours(1);
        let handler = create_test_handler(Some(expires), None);
        assert!(handler.is_valid());
    }

    #[test]
    fn test_is_valid_expired() {
        let expires = Utc::now() - chrono::Duration::hours(1);
        let handler = create_test_handler(Some(expires), None);
        assert!(!handler.is_valid());
    }

    #[test]
    fn test_is_valid_revoked() {
        let revoked = Utc::now() - chrono::Duration::minutes(30);
        let handler = create_test_handler(None, Some(revoked));
        assert!(!handler.is_valid());
    }

    #[test]
    fn test_is_valid_expired_and_revoked() {
        let expires = Utc::now() - chrono::Duration::hours(1);
        let revoked = Utc::now() - chrono::Duration::minutes(30);
        let handler = create_test_handler(Some(expires), Some(revoked));
        assert!(!handler.is_valid());
    }

    #[test]
    fn test_validate_sign_permission_no_permissions() {
        let handler = create_test_handler(None, None);
        let unsigned = nostr_sdk::EventBuilder::text_note("test").build(handler.public_key());
        assert!(handler.validate_sign_permission(&unsigned).is_ok());
    }

    #[tokio::test]
    async fn test_sign_event_when_valid() {
        let handler = create_test_handler(None, None);

        let unsigned = nostr_sdk::EventBuilder::text_note("test").build(handler.public_key());

        let result = handler.sign_event(unsigned).await;
        assert!(result.is_ok());

        let signed = result.unwrap();
        signed.verify().expect("Signature should be valid");
    }

    #[tokio::test]
    async fn test_sign_event_when_expired() {
        let expires = Utc::now() - chrono::Duration::hours(1);
        let handler = create_test_handler(Some(expires), None);

        let unsigned = nostr_sdk::EventBuilder::text_note("test").build(handler.public_key());

        let result = handler.sign_event(unsigned).await;
        assert!(matches!(result, Err(HandlerError::AuthorizationInvalid)));
    }

    #[tokio::test]
    async fn test_sign_event_when_revoked() {
        let revoked = Utc::now() - chrono::Duration::minutes(30);
        let handler = create_test_handler(None, Some(revoked));

        let unsigned = nostr_sdk::EventBuilder::text_note("test").build(handler.public_key());

        let result = handler.sign_event(unsigned).await;
        assert!(matches!(result, Err(HandlerError::AuthorizationInvalid)));
    }

    #[tokio::test]
    async fn test_handler_cache() {
        let cache = new_http_handler_cache();
        let handler = Arc::new(create_test_handler(None, None));

        let key = [42u8; 32];
        cache.insert(key, handler.clone()).await;

        let cached = cache.get(&key).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().authorization_id(), 1);
    }
}
