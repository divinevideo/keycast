// ABOUTME: HTTP RPC handler for on-demand session loading
// ABOUTME: Caches authorization metadata AND permissions for spam protection without DB hits

use chrono::{DateTime, Utc};
use keycast_core::secret_types::DecryptedPlaintext;
use keycast_core::signing_session::{CacheKey, SigningSession};
use keycast_core::traits::CustomPermission;
use moka::future::Cache;
use nostr_sdk::nips::nip04;
use nostr_sdk::nips::nip59::{self, UnwrappedGift};
use nostr_sdk::{Event, Keys, Kind, PublicKey, UnsignedEvent};
use once_cell::sync::Lazy;
use secrecy::SecretString;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Semaphore;

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

/// Per-item failure reason for the NIP-17 gift-wrap unwrap batch.
///
/// Each variant maps to a stable, machine-readable `code()` returned in the
/// per-item `{"error": "<code>"}` response slot so one malformed gift wrap
/// never fails the whole batch.
#[derive(Debug, Error)]
pub enum UnwrapError {
    #[error("authorization expired or revoked")]
    AuthorizationInvalid,
    #[error("not a gift wrap event")]
    NotGiftWrap,
    #[error("invalid gift wrap signature")]
    InvalidWrapSignature,
    #[error("gift wrap decryption failed")]
    DecryptFailed,
    #[error("rumor author does not match seal signer")]
    SenderMismatch,
    #[error("permission denied")]
    PermissionDenied,
    #[error("internal error")]
    Internal,
}

impl UnwrapError {
    /// Stable wire code for the per-item error slot. Keep these strings stable —
    /// clients branch on them (e.g. to route a slot into a retry queue).
    pub fn code(&self) -> &'static str {
        match self {
            UnwrapError::AuthorizationInvalid => "authorization_invalid",
            UnwrapError::NotGiftWrap => "not_gift_wrap",
            UnwrapError::InvalidWrapSignature => "invalid_wrap_signature",
            UnwrapError::DecryptFailed => "decrypt_failed",
            UnwrapError::SenderMismatch => "sender_mismatch",
            UnwrapError::PermissionDenied => "permission_denied",
            UnwrapError::Internal => "internal",
        }
    }
}

/// Global cap on gift-wrap unwraps running crypto at once, shared across ALL
/// requests. Each unwrap holds one permit for the full lifetime of its
/// `spawn_blocking` crypto closure (see [`HttpRpcHandler::nip17_unwrap`]), so this
/// is a hard ceiling on concurrent unwrap blocking-pool work even when requests
/// cancel mid-batch — aborting a request cannot preempt a closure that has already
/// started, and that closure keeps its permit until it returns. Sized well under
/// tokio's default 512-thread blocking pool (shared with all signing) so a burst
/// of large unwrap batches cannot crowd signing off the pool, while still letting
/// a full 100-item page drain in a couple of waves.
const UNWRAP_CRYPTO_CONCURRENCY: usize = 64;

/// Process-wide permit pool enforcing [`UNWRAP_CRYPTO_CONCURRENCY`]. Held as an
/// owned permit moved into each unwrap's `spawn_blocking` closure so the limit
/// tracks crypto that is actually running, not async tasks that may be cancelled.
static UNWRAP_CRYPTO_PERMITS: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(UNWRAP_CRYPTO_CONCURRENCY)));

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

    /// Optional DPoP JWK thumbprint bound via UCAN cnf.jkt
    dpop_cnf_jkt: Option<String>,
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
        dpop_cnf_jkt: Option<String>,
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
            dpop_cnf_jkt,
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

    /// Get expected DPoP JWK thumbprint if token is DPoP-bound.
    pub fn expected_dpop_jkt(&self) -> Option<&str> {
        self.dpop_cnf_jkt.as_deref()
    }

    /// Sign an event after checking validity and permissions
    ///
    /// Returns an error if:
    /// - Authorization has expired or been revoked
    /// - Permission policy denies this event kind
    ///
    /// Note: if `unsigned.pubkey` disagrees with the signer's pubkey, this
    /// emits a structured warning before delegating to `SigningSession`, which
    /// canonicalizes the field. The warning gives us telemetry to confirm the
    /// previous "Invalid signature" outage is no longer firing — see
    /// `signing_session.rs::sign_event` for the canonicalization itself.
    pub async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_sign_permission(&unsigned)?;

        let signer_pubkey = self.signing.public_key();
        if unsigned.pubkey != signer_pubkey {
            tracing::debug!(
                event = "http_rpc.sign_event.pubkey_mismatch",
                authorization_id = self.authorization_id,
                is_oauth = self.is_oauth,
                supplied_pubkey = %unsigned.pubkey,
                signer_pubkey = %signer_pubkey,
                kind = unsigned.kind.as_u16(),
                "sign_event: client unsigned.pubkey differs from signer pubkey; SigningSession will canonicalize"
            );
        }

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
    /// Returns DecryptedPlaintext (SecretString) for automatic memory zeroization on drop.
    pub async fn nip44_decrypt(
        &self,
        sender: &PublicKey,
        ciphertext: &str,
    ) -> Result<DecryptedPlaintext, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_decrypt_permission(ciphertext, sender)?;

        self.signing
            .nip44_decrypt(sender, ciphertext)
            .await
            .map_err(|e| HandlerError::Encryption(e.to_string()))
    }

    /// Unwrap a single NIP-59 gift wrap (kind 1059) → seal (kind 13) → rumor.
    ///
    /// This is the per-item primitive behind the `nip17_unwrap_batch` RPC. It
    /// reproduces the security guarantees the divine-mobile client enforces in
    /// `GiftWrapUtil.getRumorEvent`, delegating the protocol unwrap to the
    /// vetted `nostr_sdk` implementation rather than hand-rolling NIP-59:
    ///
    /// 1. validity (expiration/revocation) is checked first (cached, no DB hit);
    /// 2. the OUTER gift wrap's id+Schnorr signature is verified — defense in
    ///    depth, since `UnwrappedGift::from_gift_wrap` verifies the *seal* but
    ///    NOT the outer wrap;
    /// 3. `UnwrappedGift::from_gift_wrap` decrypts the outer layer, **verifies
    ///    the seal's signature** (the sole cryptographic anchor of the sender's
    ///    identity), decrypts the inner layer, and rejects a rumor whose
    ///    `pubkey` disagrees with the authenticated seal signer (`SenderMismatch`);
    /// 4. the cached decrypt policy is enforced against the **authenticated**
    ///    inner sender — `from_gift_wrap` decrypts internally, so without this an
    ///    `encrypt_to_self`-restricted authorization could read others' DMs.
    ///
    /// CPU-bound work (two Schnorr verifies + two NIP-44 decrypts) runs on
    /// `spawn_blocking`, mirroring `SigningSession::sign_event`, under a permit
    /// from the global [`UNWRAP_CRYPTO_PERMITS`] semaphore that bounds total
    /// concurrent unwrap crypto so a burst of large batches cannot crowd signing
    /// off the shared blocking pool.
    pub async fn nip17_unwrap(&self, gift_wrap: Event) -> Result<UnwrappedGift, UnwrapError> {
        if !self.is_valid() {
            return Err(UnwrapError::AuthorizationInvalid);
        }

        // Cheap kind gate before doing any crypto (from_gift_wrap also checks this).
        if gift_wrap.kind != Kind::GiftWrap {
            return Err(UnwrapError::NotGiftWrap);
        }

        let keys = self.signing.keys().clone();

        // Bound total in-flight unwrap crypto across ALL requests with one shared
        // semaphore. Acquire an OWNED permit and move it INTO the spawn_blocking
        // closure so it is released only when the blocking crypto returns — not when
        // the awaiting async task is dropped. This keeps the cap a TRUE bound under
        // disconnect/cancel churn: aborting the per-request JoinSet drops the async
        // task awaiting this handle, but cannot preempt an already-running
        // spawn_blocking closure, which holds its permit (and its blocking-pool slot)
        // until it finishes.
        let permit = Arc::clone(&UNWRAP_CRYPTO_PERMITS)
            .acquire_owned()
            .await
            // Defensive: acquire_owned only errors on a closed semaphore, and this
            // process-wide static is never closed, so this branch is unreachable.
            .map_err(|_| UnwrapError::Internal)?;

        let unwrapped =
            tokio::task::spawn_blocking(move || -> Result<UnwrappedGift, UnwrapError> {
                // Hold the global crypto permit for the lifetime of this blocking
                // closure; it releases on return, i.e. when the crypto truly completes.
                let _permit = permit;

                // Defense-in-depth: verify the outer wrap's own id+signature (parity
                // with the client's getRumorEvent). from_gift_wrap does not do this.
                gift_wrap
                    .verify()
                    .map_err(|_| UnwrapError::InvalidWrapSignature)?;

                // from_gift_wrap is async but its crypto is synchronous; drive it to
                // completion on this blocking thread (same pattern as sign_event).
                tokio::runtime::Handle::current()
                    .block_on(UnwrappedGift::from_gift_wrap(&keys, &gift_wrap))
                    .map_err(|e| match e {
                        // Defensive/unreachable: the kind gate above already rejects
                        // non-gift-wraps before we get here, so from_gift_wrap's own
                        // kind check never fires. Mapped anyway for exhaustiveness.
                        nip59::Error::NotGiftWrap => UnwrapError::NotGiftWrap,
                        nip59::Error::SenderMismatch => UnwrapError::SenderMismatch,
                        // Signer (wrong recipient / decrypt failure) and Event (malformed
                        // seal/rumor json) both surface as a decrypt failure to the client.
                        _ => UnwrapError::DecryptFailed,
                    })
            })
            .await
            .map_err(|_| UnwrapError::Internal)??;

        // Enforce decrypt policy on the authenticated inner sender. Only
        // `encrypt_to_self` actually denies decrypt today; DM authorizations
        // have no policy (full access) and pass through.
        self.validate_decrypt_permission(&unwrapped.rumor.content, &unwrapped.sender)
            .map_err(|_| UnwrapError::PermissionDenied)?;

        Ok(unwrapped)
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
    /// Returns DecryptedPlaintext (SecretString) for automatic memory zeroization on drop.
    pub async fn nip04_decrypt(
        &self,
        sender: &PublicKey,
        ciphertext: &str,
    ) -> Result<DecryptedPlaintext, HandlerError> {
        if !self.is_valid() {
            return Err(HandlerError::AuthorizationInvalid);
        }

        self.validate_decrypt_permission(ciphertext, sender)?;

        let secret = self.signing.keys().secret_key().clone();
        let sender = *sender;
        let ciphertext = ciphertext.to_string();

        tokio::task::spawn_blocking(move || {
            nip04::decrypt(&secret, &sender, &ciphertext).map(SecretString::from)
        })
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
            None,
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

    #[test]
    fn test_expected_dpop_jkt_accessor() {
        let keys = Keys::generate();
        let signing = Arc::new(SigningSession::new(keys));
        let handler = HttpRpcHandler::new(
            signing,
            1,
            None,
            None,
            vec![],
            true,
            [0u8; 32],
            [1u8; 32],
            Some("thumbprint-123".to_string()),
        );

        assert_eq!(handler.expected_dpop_jkt(), Some("thumbprint-123"));
    }

    // -- nip17_unwrap (NIP-59 gift-wrap unwrap) ------------------------------

    /// Build a kind:1059 gift wrap from `sender` to `receiver` carrying a
    /// kind:14 private DM rumor with the given text.
    async fn build_gift_wrap(sender: &Keys, receiver: &PublicKey, text: &str) -> nostr_sdk::Event {
        let rumor =
            nostr_sdk::EventBuilder::private_msg_rumor(*receiver, text).build(sender.public_key());
        nostr_sdk::EventBuilder::gift_wrap(sender, receiver, rumor, Vec::<nostr_sdk::Tag>::new())
            .await
            .expect("gift wrap should build")
    }

    #[tokio::test]
    async fn nip17_unwrap_round_trips_gift_wrap() {
        let handler = create_test_handler(None, None);
        let receiver = handler.public_key();
        let sender = Keys::generate();

        let gift_wrap = build_gift_wrap(&sender, &receiver, "hello dm").await;

        let unwrapped = handler
            .nip17_unwrap(gift_wrap)
            .await
            .expect("unwrap should succeed");

        assert_eq!(
            unwrapped.sender,
            sender.public_key(),
            "sender must be the authenticated seal signer"
        );
        assert_eq!(unwrapped.rumor.content, "hello dm");
        assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);
    }

    #[tokio::test]
    async fn nip17_unwrap_rejects_non_gift_wrap() {
        let handler = create_test_handler(None, None);
        let sender = Keys::generate();
        let event = nostr_sdk::EventBuilder::text_note("not a wrap")
            .sign_with_keys(&sender)
            .expect("sign");

        let err = handler
            .nip17_unwrap(event)
            .await
            .expect_err("non-gift-wrap should be rejected");
        assert_eq!(err.code(), "not_gift_wrap");
    }

    #[tokio::test]
    async fn nip17_unwrap_rejects_wrong_recipient() {
        let handler = create_test_handler(None, None);
        let other_receiver = Keys::generate();
        let sender = Keys::generate();

        // Wrap addressed to someone else: this handler's key cannot decrypt it.
        let gift_wrap = build_gift_wrap(&sender, &other_receiver.public_key(), "secret").await;

        let err = handler
            .nip17_unwrap(gift_wrap)
            .await
            .expect_err("wrong recipient should fail to decrypt");
        assert_eq!(err.code(), "decrypt_failed");
    }

    #[tokio::test]
    async fn nip17_unwrap_denied_when_expired() {
        let expires = Utc::now() - chrono::Duration::hours(1);
        let handler = create_test_handler(Some(expires), None);
        let receiver = handler.public_key();
        let sender = Keys::generate();

        let gift_wrap = build_gift_wrap(&sender, &receiver, "hi").await;

        let err = handler
            .nip17_unwrap(gift_wrap)
            .await
            .expect_err("expired authorization should be denied");
        assert_eq!(err.code(), "authorization_invalid");
    }

    #[tokio::test]
    async fn nip17_unwrap_denied_by_encrypt_to_self_policy() {
        // I4: the unwrap path decrypts inside the SDK, so it must still enforce
        // the decrypt policy on the authenticated inner sender. encrypt_to_self
        // only permits decrypting messages from oneself, so a DM from another
        // sender must be denied rather than silently bypassing the policy.
        use keycast_core::custom_permissions::encrypt_to_self::EncryptToSelf;
        let handler =
            create_test_handler_with_permissions(None, None, vec![Box::new(EncryptToSelf {})]);
        let receiver = handler.public_key();
        let sender = Keys::generate(); // not the user -> encrypt_to_self denies

        let gift_wrap = build_gift_wrap(&sender, &receiver, "from someone else").await;

        let err = handler
            .nip17_unwrap(gift_wrap)
            .await
            .expect_err("encrypt_to_self should deny a DM from another sender");
        assert_eq!(err.code(), "permission_denied");
    }

    #[tokio::test]
    async fn nip17_unwrap_rejects_sender_mismatch() {
        // Pins the strict sender-mismatch behavior (NIP-59 requires rumor.pubkey ==
        // seal signer). Built like nostr-sdk's own `test_sender_mismatch`: the rumor
        // claims an impersonated author while the seal/wrap is signed by `sender`, so
        // `from_gift_wrap` authenticates `sender` but the inner author disagrees.
        let handler = create_test_handler(None, None);
        let receiver = handler.public_key();
        let sender = Keys::generate(); // signs the seal -> the authenticated sender
        let impersonated = Keys::generate(); // rumor lies about its author

        let rumor = nostr_sdk::EventBuilder::private_msg_rumor(receiver, "spoofed")
            .build(impersonated.public_key());
        let gift_wrap = nostr_sdk::EventBuilder::gift_wrap(
            &sender,
            &receiver,
            rumor,
            Vec::<nostr_sdk::Tag>::new(),
        )
        .await
        .expect("gift wrap should build");

        let err = handler
            .nip17_unwrap(gift_wrap)
            .await
            .expect_err("rumor author disagreeing with the seal signer must be rejected");
        assert_eq!(err.code(), "sender_mismatch");
    }

    #[tokio::test]
    async fn nip17_unwrap_rejects_invalid_wrap_signature() {
        // Exercises the OUTER-wrap defense-in-depth check, which `from_gift_wrap`
        // does NOT perform (it verifies only the seal). We can't sign a broken wrap
        // with EventBuilder, so we tamper a valid one: deserialization does not
        // verify id/signature, so mutating `content` while leaving id+sig untouched
        // yields a kind:1059 event whose recomputed id no longer matches -> verify()
        // fails before any decrypt runs.
        let handler = create_test_handler(None, None);
        let receiver = handler.public_key();
        let sender = Keys::generate();

        let gift_wrap = build_gift_wrap(&sender, &receiver, "tamper me").await;
        let mut json = serde_json::to_value(&gift_wrap).expect("serialize gift wrap");
        let original = json["content"]
            .as_str()
            .expect("content string")
            .to_string();
        json["content"] = serde_json::Value::String(format!("{original}x"));
        let tampered: Event =
            serde_json::from_value(json).expect("deserialize does not verify, so this succeeds");
        assert_eq!(
            tampered.kind,
            Kind::GiftWrap,
            "tamper must keep kind:1059 so it passes the kind gate"
        );

        let err = handler
            .nip17_unwrap(tampered)
            .await
            .expect_err("tampered outer wrap must fail the defense-in-depth verify");
        assert_eq!(err.code(), "invalid_wrap_signature");
    }
}
