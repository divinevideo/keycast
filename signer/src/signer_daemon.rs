// ABOUTME: Unified signer daemon that handles multiple NIP-46 bunker connections in a single process
// ABOUTME: Listens for NIP-46 requests and routes them to the appropriate authorization/key

use crate::activity_writer::RelayActivityLogger;
use crate::error::{SignerError, SignerResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cluster_hashring::{ClusterCoordinator, MembershipEvent};
use keycast_core::authorization_channel::{AuthorizationCommand, AuthorizationReceiver};
use keycast_core::encryption::KeyManager;
use keycast_core::metrics::METRICS;
use keycast_core::signing_handler::SigningHandler;
use keycast_core::signing_session::canonicalize_event_author;
use keycast_core::types::authorization::Authorization;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;

/// Default timeout for relay connection operations
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
// Fixed shards prevent unbounded per-key generation state. A hash collision only
// sheds the current request and is counted; it cannot admit stale data.
const LOOKUP_INVALIDATION_SHARDS: usize = 1_024;
const DEFAULT_NIP46_LOOKUP_CONCURRENCY: usize = 16;
const DEFAULT_NIP46_SINGLEFLIGHT_CACHE_SIZE: usize = 1_024;

/// Status of a NIP-46 handler for tombstone support
///
/// When authorizations are revoked or expired, handlers are kept in memory
/// as "tombstones" so they can still send error responses to clients instead
/// of silently timing out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerStatus {
    /// Handler is active and can process requests
    Active,
    /// Authorization was revoked by user - can only send error responses
    Revoked,
    /// Authorization has expired - can only send error responses
    Expired,
}

/// NIP-46 handler for a single authorization
///
/// Manages both wire encryption (bunker_keys) and user event signing (user_keys).
/// Handles NIP-46 protocol operations including connect, sign_event, encrypt/decrypt.
///
/// Note: Unlike HttpRpcHandler which caches everything, this handler maintains
/// DB access for real-time client tracking and permission validation.
#[derive(Clone)]
pub struct Nip46Handler {
    /// Keys for NIP-46 wire encryption (bunker identity)
    bunker_keys: Keys,
    /// Keys for signing user events
    pub user_keys: Keys,
    /// Bcrypt hash of connection secret for NIP-46 connect validation
    secret_hash: String,
    authorization_id: i32,
    tenant_id: i64,
    is_oauth: bool,
    pool: PgPool,
    activity_logger: RelayActivityLogger,
    /// Handler status for tombstone support (Active, Revoked, or Expired)
    ///
    /// This is a snapshot taken when the handler was loaded. Time-based expiry is
    /// re-evaluated per request from `expires_at` — see [`Self::effective_status`].
    status: HandlerStatus,
    /// When this handler became a tombstone (for cleanup after 24h)
    tombstone_at: Option<DateTime<Utc>>,
    /// The authorization's `expires_at`, carried so expiry can be re-evaluated
    /// against the clock on every request rather than only at load time. The
    /// handler cache has no TTL, so a handler cached while valid would otherwise
    /// keep signing, encrypting, and decrypting forever past its expiry.
    expires_at: Option<DateTime<Utc>>,
}

impl Nip46Handler {
    /// Constructor for testing only - do not use in production code
    #[doc(hidden)]
    pub fn new_for_test(
        bunker_keys: Keys,
        user_keys: Keys,
        secret_hash: String,
        authorization_id: i32,
        tenant_id: i64,
        is_oauth: bool,
        pool: PgPool,
    ) -> Self {
        let (activity_logger, _worker) = RelayActivityLogger::new(pool.clone());
        Self {
            bunker_keys,
            user_keys,
            secret_hash,
            authorization_id,
            tenant_id,
            is_oauth,
            pool,
            activity_logger,
            status: HandlerStatus::Active,
            tombstone_at: None,
            expires_at: None,
        }
    }

    /// Set the authorization expiry on a test handler, so tests can cover a
    /// handler that was cached while valid and has since fallen due.
    #[doc(hidden)]
    pub fn with_expires_at(mut self, expires_at: Option<DateTime<Utc>>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set the cached status on a test handler, so tests can cover the
    /// revoked-beats-expired precedence.
    #[doc(hidden)]
    pub fn with_status(mut self, status: HandlerStatus) -> Self {
        self.status = status;
        self
    }

    /// The bunker (wire) public key for this handler. Test-only accessor so the
    /// relay-reply tests can decrypt the response event addressed to the client.
    #[doc(hidden)]
    pub fn bunker_public_key(&self) -> PublicKey {
        self.bunker_keys.public_key()
    }

    /// Build the encrypted NIP-46 wire response event for a request.
    ///
    /// Dispatches `method`, converts an EXPECTED per-request denial (see
    /// [`SignerError::is_expected_client_denial`]) into a JSON-RPC `{id, error}`
    /// reply, and builds+signs the encrypted `NostrConnect` response event
    /// addressed to the client. Returns `Err` ONLY for internal failures (the
    /// caller logs those); every expected denial yields an `{id, error}`
    /// response event so the client gets a clean refusal, never a relay timeout.
    ///
    /// Extracted from `handle_nip46_request` so the relay reply path is testable
    /// without a live relay/coordinator (keeps the handler thin per the layering
    /// guideline). `request_event_pubkey` / `request_event_id` are the client's
    /// request event pubkey (response encryption target + `p` tag) and id
    /// (`e` tag); `use_nip44` mirrors how the request itself was decrypted.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub async fn build_nip46_response_event(
        &self,
        method: &str,
        request: &serde_json::Value,
        request_id: &serde_json::Value,
        client_pubkey: &str,
        request_event_pubkey: PublicKey,
        request_event_id: EventId,
        use_nip44: bool,
    ) -> SignerResult<Event> {
        // Dispatch the method; convert an EXPECTED per-request denial into a
        // JSON-RPC {id, error} reply so the client gets a clean refusal instead
        // of a relay timeout. Internal failures propagate to be logged.
        let response = match self
            .dispatch_nip46_method(method, request, request_id, client_pubkey)
            .await
        {
            Ok(value) => value,
            Err(e) if e.is_expected_client_denial() => {
                tracing::info!(
                    event = "nip46.denial_response",
                    method = %method,
                    reason = %e,
                    "returning JSON-RPC error for expected per-request denial"
                );
                serde_json::json!({ "id": request_id, "error": e.to_string() })
            }
            Err(e) => return Err(e),
        };

        // Encrypt the response to the client with the same scheme the request
        // arrived under (CPU-bound, spawn_blocking).
        let response_str = response.to_string();
        let encrypted_response = {
            let secret = self.bunker_keys.secret_key().clone();
            let pubkey = request_event_pubkey;
            let text = response_str;
            tokio::task::spawn_blocking(move || {
                if use_nip44 {
                    nip44::encrypt(&secret, &pubkey, &text, nip44::Version::V2)
                        .map_err(SignerError::from)
                } else {
                    nip04::encrypt(&secret, &pubkey, &text).map_err(SignerError::from)
                }
            })
            .await
            .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
        };

        // Build + sign the NostrConnect response event addressed to the client.
        let response_event = {
            let keys = self.bunker_keys.clone();
            let content = encrypted_response;
            let sender = request_event_pubkey;
            let event_id = request_event_id.to_hex();
            tokio::task::spawn_blocking(move || {
                EventBuilder::new(Kind::NostrConnect, content)
                    .tags(vec![
                        Tag::public_key(sender),
                        Tag::parse(vec!["e".to_string(), event_id]).unwrap(),
                    ])
                    .sign_with_keys(&keys)
            })
            .await
            .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
        };

        Ok(response_event)
    }

    /// Dispatch a decrypted NIP-46 method to its JSON-RPC result value, or a
    /// `SignerError`. Split out of `handle_nip46_request` so the reply path is
    /// testable and the wire handler stays thin. `?` here surfaces denials as
    /// `Err`, which the caller ([`Nip46Handler::build_nip46_response_event`])
    /// converts into a JSON-RPC `{id, error}` reply for expected denials.
    async fn dispatch_nip46_method(
        &self,
        method: &str,
        request: &serde_json::Value,
        request_id: &serde_json::Value,
        client_pubkey: &str,
    ) -> SignerResult<serde_json::Value> {
        Ok(match method {
            "sign_event" => {
                // handle_sign_event already returns a full response with id
                self.handle_sign_event(request).await?
            }
            "get_public_key" => serde_json::json!({
                "id": request_id,
                "result": self.user_keys.public_key().to_hex()
            }),
            "connect" => {
                // Process connect with client pubkey tracking (NIP-46 security)
                if let Some(provided_secret) = request["params"][1].as_str() {
                    match self.process_connect(client_pubkey, provided_secret).await {
                        Ok(result) => serde_json::json!({"id": request_id, "result": result}),
                        Err(e) => serde_json::json!({"id": request_id, "error": e.to_string()}),
                    }
                } else {
                    // No secret provided - still track client pubkey for future validation
                    serde_json::json!({"id": request_id, "result": "ack"})
                }
            }
            "nip44_encrypt" => {
                // params: [third_party_pubkey, plaintext]
                let third_party_hex = request["params"][0]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let plaintext = request["params"][1]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("plaintext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;

                self.ensure_authorization_active()?;

                // Validate policy before encryption
                self.validate_permissions_for_encrypt(plaintext, &third_party_pubkey)
                    .await?;
                // Recheck after the await: clock-derived expiry can fall due mid-request.
                self.ensure_authorization_active()?;

                // CPU-bound crypto wrapped in spawn_blocking
                let ciphertext = {
                    let secret = self.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = plaintext.to_string();
                    tokio::task::spawn_blocking(move || {
                        nip44::encrypt(&secret, &pubkey, &text, nip44::Version::V2)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                // Log activity in background (non-blocking)
                self.spawn_update_activity();

                serde_json::json!({
                    "id": request_id,
                    "result": ciphertext
                })
            }
            "nip44_decrypt" => {
                // params: [third_party_pubkey, ciphertext]
                let third_party_hex = request["params"][0]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let ciphertext = request["params"][1]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("ciphertext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;

                self.ensure_authorization_active()?;

                // Validate policy before decryption
                self.validate_permissions_for_decrypt(ciphertext, &third_party_pubkey)
                    .await?;
                // Recheck after the await: clock-derived expiry can fall due mid-request.
                self.ensure_authorization_active()?;

                // CPU-bound crypto wrapped in spawn_blocking
                // Returns SecretString for automatic memory zeroization on drop
                let plaintext: SecretString = {
                    let secret = self.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = ciphertext.to_string();
                    tokio::task::spawn_blocking(move || {
                        nip44::decrypt(&secret, &pubkey, &text).map(SecretString::from)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                // Log activity in background (non-blocking)
                self.spawn_update_activity();

                // Expose secret only at serialization boundary
                serde_json::json!({
                    "id": request_id,
                    "result": plaintext.expose_secret()
                })
            }
            "nip04_encrypt" => {
                // params: [third_party_pubkey, plaintext]
                let third_party_hex = request["params"][0]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let plaintext = request["params"][1]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("plaintext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;

                self.ensure_authorization_active()?;

                // Validate policy before encryption
                self.validate_permissions_for_encrypt(plaintext, &third_party_pubkey)
                    .await?;
                // Recheck after the await: clock-derived expiry can fall due mid-request.
                self.ensure_authorization_active()?;

                // CPU-bound crypto wrapped in spawn_blocking
                let ciphertext = {
                    let secret = self.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = plaintext.to_string();
                    tokio::task::spawn_blocking(move || nip04::encrypt(&secret, &pubkey, &text))
                        .await
                        .map_err(|e| {
                            SignerError::internal(format!("spawn_blocking failed: {}", e))
                        })??
                };

                // Log activity in background (non-blocking)
                self.spawn_update_activity();

                serde_json::json!({
                    "id": request_id,
                    "result": ciphertext
                })
            }
            "nip04_decrypt" => {
                // params: [third_party_pubkey, ciphertext]
                let third_party_hex = request["params"][0]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let ciphertext = request["params"][1]
                    .as_str()
                    .ok_or(SignerError::MissingParameter("ciphertext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;

                self.ensure_authorization_active()?;

                // Validate policy before decryption
                self.validate_permissions_for_decrypt(ciphertext, &third_party_pubkey)
                    .await?;
                // Recheck after the await: clock-derived expiry can fall due mid-request.
                self.ensure_authorization_active()?;

                // CPU-bound crypto wrapped in spawn_blocking
                // Returns SecretString for automatic memory zeroization on drop
                let plaintext: SecretString = {
                    let secret = self.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = ciphertext.to_string();
                    tokio::task::spawn_blocking(move || {
                        nip04::decrypt(&secret, &pubkey, &text).map(SecretString::from)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                // Log activity in background (non-blocking)
                self.spawn_update_activity();

                // Expose secret only at serialization boundary
                serde_json::json!({
                    "id": request_id,
                    "result": plaintext.expose_secret()
                })
            }
            _ => {
                tracing::warn!("Unsupported NIP-46 method: {}", method);
                serde_json::json!({"id": request_id, "error": format!("Unsupported method: {}", method)})
            }
        })
    }

    /// The handler's status as of *now*, not as of when it was loaded.
    ///
    /// The handler cache has no TTL and `status` is only computed on a cache
    /// miss, so a handler cached while still valid keeps a stale `Active` status
    /// indefinitely. Re-checking `expires_at` here makes expiry take effect at
    /// the moment it falls due, whether or not the handler is cached.
    ///
    /// Revocation still wins over expiry: a revoked handler stays revoked.
    fn effective_status(&self) -> HandlerStatus {
        if self.status == HandlerStatus::Active
            && self.expires_at.is_some_and(|exp| exp <= Utc::now())
        {
            return HandlerStatus::Expired;
        }
        self.status
    }

    /// The time from which the 24-hour tombstone retention window is measured.
    ///
    /// Clock-derived expiry does not mutate a cached handler, so an authorization
    /// that expires while cached has no stamped `tombstone_at`. In that case its
    /// actual `expires_at` is the start of the retention window.
    fn effective_tombstone_at(&self) -> Option<DateTime<Utc>> {
        if self.tombstone_at.is_some() {
            return self.tombstone_at;
        }

        (self.effective_status() == HandlerStatus::Expired)
            .then_some(self.expires_at)
            .flatten()
    }

    fn tombstone_is_older_than(&self, cutoff: DateTime<Utc>) -> bool {
        self.effective_tombstone_at()
            .is_some_and(|tombstone_at| tombstone_at < cutoff)
    }

    /// Check if this handler is a tombstone (revoked or expired)
    pub fn is_tombstone(&self) -> bool {
        self.effective_status() != HandlerStatus::Active
    }

    /// Get the error message for this tombstone status
    pub fn tombstone_error_message(&self) -> Option<&'static str> {
        match self.effective_status() {
            HandlerStatus::Active => None,
            HandlerStatus::Revoked => Some("Authorization has been revoked"),
            HandlerStatus::Expired => Some("Authorization has expired"),
        }
    }

    /// Refuse the request if the authorization is a tombstone (revoked or expired).
    ///
    /// Call sites check twice: once up front, so an already-dead authorization
    /// does not get policy validation done on its behalf, and again immediately
    /// before the key is used. The second check is the one that protects the
    /// key — expiry is clock-derived (see [`Self::effective_status`]), so it can
    /// fall due while the validation await is in flight. Do not collapse the pair.
    fn ensure_authorization_active(&self) -> SignerResult<()> {
        match self.tombstone_error_message() {
            Some(message) => Err(SignerError::permission_denied(message)),
            None => Ok(()),
        }
    }

    /// Compute handler status from OAuth authorization database fields.
    ///
    /// Priority: Revoked > Expired > Active
    fn compute_status_from_oauth(
        auth: &OAuthAuthorization,
    ) -> (HandlerStatus, Option<DateTime<Utc>>) {
        if auth.revoked_at.is_some() {
            (HandlerStatus::Revoked, auth.revoked_at)
        } else {
            Self::compute_status_from_expiry(auth.expires_at)
        }
    }

    /// Compute handler status from an authorization's `expires_at` alone.
    ///
    /// Used for team authorizations, which are hard-deleted rather than revoked,
    /// so expiry is their only tombstone signal.
    fn compute_status_from_expiry(
        expires_at: Option<DateTime<Utc>>,
    ) -> (HandlerStatus, Option<DateTime<Utc>>) {
        match expires_at {
            Some(exp) if exp <= Utc::now() => (HandlerStatus::Expired, Some(exp)),
            _ => (HandlerStatus::Active, None),
        }
    }

    /// Check that the user's account is active (not suspended or banned).
    /// Only applies to OAuth authorizations (personal keys tied to a user account).
    /// Team authorizations don't have user rows — they're managed through team
    /// admin, are not minor accounts, and return `false` for the flag.
    ///
    /// Returns the account's `verified_minor` flag (same row, no extra query)
    /// so callers can apply the DM containment gate (support-trust-safety#183).
    async fn check_user_active(&self) -> SignerResult<bool> {
        if !self.is_oauth {
            return Ok(false);
        }
        let user_pubkey = self.user_keys.public_key().to_hex();
        let status: Option<(String, bool)> = sqlx::query_as(
            "SELECT status, verified_minor FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(&user_pubkey)
        .bind(self.tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match status {
            Some((s, verified_minor)) if s == "active" => Ok(verified_minor),
            Some(_) => Err(SignerError::permission_denied("Account restricted")),
            None => Err(SignerError::permission_denied("User not found")),
        }
    }

    /// Account-level gates that must run before any signing: active status and
    /// the verified_minor DM containment gate (support-trust-safety#183).
    /// Both relay-dispatched (`handle_sign_event`) and direct
    /// (`sign_event_direct`) signing must pass through here.
    async fn check_user_sign_gates(&self, unsigned_event: &UnsignedEvent) -> SignerResult<()> {
        let verified_minor = self.check_user_active().await?;
        if verified_minor {
            keycast_core::verified_minor_dm::validate_minor_sign(&self.user_keys, unsigned_event)
                .map_err(|denied| {
                tracing::warn!(
                    event = "minor_dm_gate.sign_denied",
                    user_pubkey = %self.user_keys.public_key().to_hex(),
                    kind = unsigned_event.kind.as_u16(),
                    reason = %denied,
                    "verified_minor DM sign refused (NIP-46 signer)"
                );
                SignerError::permission_denied("Operation denied by policy")
            })?;
        }
        Ok(())
    }

    /// Validate permissions before signing an event.
    ///
    /// Loads the policy permissions for this authorization and checks each one.
    /// Uses AND logic: ALL permissions must allow the operation.
    async fn validate_permissions_for_sign(
        &self,
        unsigned_event: &UnsignedEvent,
    ) -> SignerResult<()> {
        // Load permissions based on authorization type
        let permissions = if self.is_oauth {
            let oauth_auth =
                OAuthAuthorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            oauth_auth.permissions(&self.pool, self.tenant_id).await?
        } else {
            let auth =
                Authorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            auth.permissions(&self.pool, self.tenant_id).await?
        };

        // If no permissions configured, allow all (backward compatibility)
        if permissions.is_empty() {
            return Ok(());
        }

        // Convert and validate - ALL permissions must pass (AND logic)
        for permission in &permissions {
            let custom_permission = permission.to_custom_permission().map_err(|e| {
                SignerError::invalid_permission(format!(
                    "Failed to convert permission '{}': {}",
                    permission.identifier, e
                ))
            })?;

            if !custom_permission.can_sign(unsigned_event) {
                return Err(SignerError::permission_denied(format!(
                    "Blocked by '{}' policy",
                    custom_permission.identifier()
                )));
            }
        }

        Ok(())
    }

    /// Validate permissions before encrypting plaintext for a recipient.
    /// Includes a user status check (DB query) — callers should NOT add a separate check.
    #[doc(hidden)]
    pub async fn validate_permissions_for_encrypt(
        &self,
        plaintext: &str,
        recipient_pubkey: &PublicKey,
    ) -> SignerResult<()> {
        let verified_minor = self.check_user_active().await?;
        // verified_minor DM containment (support-trust-safety#183): the
        // encryption primitive is where a NIP-17 seal's recipient is in the
        // clear, so this is the containment point for DM egress.
        if verified_minor {
            keycast_core::verified_minor_dm::validate_minor_encrypt(
                &self.user_keys.public_key(),
                recipient_pubkey,
            )
            .map_err(|denied| {
                tracing::warn!(
                    event = "minor_dm_gate.encrypt_denied",
                    user_pubkey = %self.user_keys.public_key().to_hex(),
                    recipient = %recipient_pubkey.to_hex(),
                    reason = %denied,
                    "verified_minor DM encrypt refused (NIP-46 signer)"
                );
                SignerError::permission_denied("Operation denied by policy")
            })?;
        }
        // Load permissions based on authorization type
        let permissions = if self.is_oauth {
            let oauth_auth =
                OAuthAuthorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            oauth_auth.permissions(&self.pool, self.tenant_id).await?
        } else {
            let auth =
                Authorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            auth.permissions(&self.pool, self.tenant_id).await?
        };

        // If no permissions configured, allow all (backward compatibility)
        if permissions.is_empty() {
            return Ok(());
        }

        let user_pubkey = self.user_keys.public_key();

        // Convert and validate - ALL permissions must pass (AND logic)
        for permission in &permissions {
            let custom_permission = permission.to_custom_permission().map_err(|e| {
                SignerError::invalid_permission(format!(
                    "Failed to convert permission '{}': {}",
                    permission.identifier, e
                ))
            })?;

            if !custom_permission.can_encrypt(plaintext, &user_pubkey, recipient_pubkey) {
                return Err(SignerError::permission_denied(format!(
                    "Blocked by '{}' policy",
                    custom_permission.identifier()
                )));
            }
        }

        Ok(())
    }

    /// Validate permissions before decrypting ciphertext from a sender.
    /// Includes a user status check (DB query) — callers should NOT add a separate check.
    #[doc(hidden)]
    pub async fn validate_permissions_for_decrypt(
        &self,
        ciphertext: &str,
        sender_pubkey: &PublicKey,
    ) -> SignerResult<()> {
        // Status gate only: decrypt is ingress, out of the DM containment
        // gate's egress-only scope (support-trust-safety#183).
        self.check_user_active().await?;
        // Load permissions based on authorization type
        let permissions = if self.is_oauth {
            let oauth_auth =
                OAuthAuthorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            oauth_auth.permissions(&self.pool, self.tenant_id).await?
        } else {
            let auth =
                Authorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            auth.permissions(&self.pool, self.tenant_id).await?
        };

        // If no permissions configured, allow all (backward compatibility)
        if permissions.is_empty() {
            return Ok(());
        }

        let user_pubkey = self.user_keys.public_key();

        // Convert and validate - ALL permissions must pass (AND logic)
        for permission in &permissions {
            let custom_permission = permission.to_custom_permission().map_err(|e| {
                SignerError::invalid_permission(format!(
                    "Failed to convert permission '{}': {}",
                    permission.identifier, e
                ))
            })?;

            if !custom_permission.can_decrypt(ciphertext, sender_pubkey, &user_pubkey) {
                return Err(SignerError::permission_denied(format!(
                    "Blocked by '{}' policy",
                    custom_permission.identifier()
                )));
            }
        }

        Ok(())
    }

    /// Process a NIP-46 connect request with client tracking.
    ///
    /// Validates the secret and stores the client pubkey for future request validation.
    /// Per NIP-46, the secret becomes single-use after first successful connect.
    ///
    /// # Errors
    ///
    /// Returns error if secret is invalid or already used by a different client.
    pub async fn process_connect(
        &self,
        client_pubkey: &str,
        provided_secret: &str,
    ) -> SignerResult<String> {
        // Validate secret against bcrypt hash (same for both OAuth and team authorizations)
        let valid =
            keycast_core::secret_pool::verify_secret(provided_secret, &self.secret_hash).await;
        if !valid {
            tracing::warn!("Invalid secret for authorization {}", self.authorization_id);
            return Err(SignerError::permission_denied("Invalid secret"));
        }

        // Enforce one-client-per-authorization (NIP-46 spec: secrets are single-use)
        // Check if a client is already connected
        let existing_client: Option<String> = if self.is_oauth {
            sqlx::query_scalar(
                "SELECT connected_client_pubkey FROM oauth_authorizations
                 WHERE id = $1 AND tenant_id = $2
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW())",
            )
            .bind(self.authorization_id)
            .bind(self.tenant_id)
            .fetch_optional(&self.pool)
            .await?
            .flatten()
        } else {
            sqlx::query_scalar(
                "SELECT connected_client_pubkey FROM authorizations
                 WHERE id = $1 AND tenant_id = $2
                   AND (expires_at IS NULL OR expires_at > NOW())",
            )
            .bind(self.authorization_id)
            .bind(self.tenant_id)
            .fetch_optional(&self.pool)
            .await?
            .flatten()
        };

        match existing_client {
            Some(existing) if existing == client_pubkey => {
                // Same client reconnecting - allowed
                tracing::debug!("Same client reconnecting: {}", client_pubkey);
                Ok("ack".to_string())
            }
            Some(existing) => {
                // Different client trying to use same bunker - rejected
                tracing::warn!(
                    "Secret already used by different client. Existing: {}, Attempting: {}",
                    existing,
                    client_pubkey
                );
                Err(SignerError::permission_denied(
                    "Secret already used by another client",
                ))
            }
            None => {
                // First connect - store client pubkey
                tracing::info!(
                    "First connect for auth {} (oauth={}), storing client pubkey: {}",
                    self.authorization_id,
                    self.is_oauth,
                    client_pubkey
                );
                if self.is_oauth {
                    sqlx::query(
                        "UPDATE oauth_authorizations
                         SET connected_client_pubkey = $1, connected_at = NOW()
                         WHERE id = $2",
                    )
                    .bind(client_pubkey)
                    .bind(self.authorization_id)
                    .execute(&self.pool)
                    .await?;
                } else {
                    sqlx::query(
                        "UPDATE authorizations
                         SET connected_client_pubkey = $1, connected_at = NOW()
                         WHERE id = $2",
                    )
                    .bind(client_pubkey)
                    .bind(self.authorization_id)
                    .execute(&self.pool)
                    .await?;
                }

                Ok("ack".to_string())
            }
        }
    }

    /// Validate that a client is authorized to make requests.
    ///
    /// Checks if the provided client pubkey matches the stored connected client.
    ///
    /// # Errors
    ///
    /// Returns error if client pubkey doesn't match the connected client.
    pub async fn validate_client(&self, client_pubkey: &str) -> SignerResult<()> {
        let bunker_pubkey = self.bunker_keys.public_key().to_hex();

        // Check if this client is the connected client for any active authorization with this bunker pubkey
        let is_valid: bool = if self.is_oauth {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM oauth_authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey = $2
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW()))",
            )
            .bind(&bunker_pubkey)
            .bind(client_pubkey)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey = $2
                   AND (expires_at IS NULL OR expires_at > NOW()))",
            )
            .bind(&bunker_pubkey)
            .bind(client_pubkey)
            .fetch_one(&self.pool)
            .await?
        };

        if is_valid {
            Ok(())
        } else {
            // Check if there's any active authorization with NULL connected_client_pubkey
            // If so, this client hasn't connected yet
            let has_unconnected: bool = if self.is_oauth {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM oauth_authorizations
                     WHERE bunker_public_key = $1 AND connected_client_pubkey IS NULL
                       AND revoked_at IS NULL
                       AND (expires_at IS NULL OR expires_at > NOW()))",
                )
                .bind(&bunker_pubkey)
                .fetch_one(&self.pool)
                .await
                .unwrap_or(false)
            } else {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM authorizations
                     WHERE bunker_public_key = $1 AND connected_client_pubkey IS NULL
                       AND (expires_at IS NULL OR expires_at > NOW()))",
                )
                .bind(&bunker_pubkey)
                .fetch_one(&self.pool)
                .await
                .unwrap_or(false)
            };

            if has_unconnected {
                Err(SignerError::permission_denied(
                    "Unknown client - must connect first",
                ))
            } else {
                Err(SignerError::permission_denied(
                    "Unknown client - not connected to any authorization",
                ))
            }
        }
    }

    /// Validate client and store on first request.
    ///
    /// Provides graceful upgrade for existing connections. If no client is connected
    /// yet, stores this client as the connected client. Subsequent requests must
    /// come from the same client.
    ///
    /// # Errors
    ///
    /// Returns error if a different client is already connected.
    pub async fn validate_and_store_client(&self, client_pubkey: &str) -> SignerResult<()> {
        let bunker_pubkey = self.bunker_keys.public_key().to_hex();

        // Check if this client is already the connected client for an active auth
        let is_valid: bool = if self.is_oauth {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM oauth_authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey = $2
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW()))",
            )
            .bind(&bunker_pubkey)
            .bind(client_pubkey)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey = $2
                   AND (expires_at IS NULL OR expires_at > NOW()))",
            )
            .bind(&bunker_pubkey)
            .bind(client_pubkey)
            .fetch_one(&self.pool)
            .await?
        };

        if is_valid {
            return Ok(());
        }

        // Check if there's an unconnected active authorization we can claim
        let unconnected_id: Option<i32> = if self.is_oauth {
            sqlx::query_scalar(
                "SELECT id FROM oauth_authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey IS NULL
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW())
                 LIMIT 1",
            )
            .bind(&bunker_pubkey)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT id FROM authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW())
                 LIMIT 1",
            )
            .bind(&bunker_pubkey)
            .fetch_optional(&self.pool)
            .await?
        };

        match unconnected_id {
            Some(auth_id) => {
                // First request without connect - store this client (graceful upgrade)
                tracing::info!(
                    "Storing client pubkey on first request (graceful upgrade) for auth {} (oauth={}): {}",
                    auth_id,
                    self.is_oauth,
                    client_pubkey
                );
                if self.is_oauth {
                    sqlx::query(
                        "UPDATE oauth_authorizations
                         SET connected_client_pubkey = $1, connected_at = NOW()
                         WHERE id = $2",
                    )
                    .bind(client_pubkey)
                    .bind(auth_id)
                    .execute(&self.pool)
                    .await?;
                } else {
                    sqlx::query(
                        "UPDATE authorizations
                         SET connected_client_pubkey = $1, connected_at = NOW()
                         WHERE id = $2",
                    )
                    .bind(client_pubkey)
                    .bind(auth_id)
                    .execute(&self.pool)
                    .await?;
                }

                Ok(())
            }
            None => {
                // No unconnected authorization and client not recognized
                Err(SignerError::permission_denied(
                    "Unknown client - not connected to any authorization",
                ))
            }
        }
    }
}

/// Default LRU cache capacity for authorization handlers
/// At ~1KB per handler, 1M handlers ≈ 1GB memory
/// This is a hard cap - moka evicts LRU entries when full
const DEFAULT_HANDLER_CACHE_SIZE: usize = 1_000_000;

pub struct UnifiedSigner {
    handlers: Cache<String, Nip46Handler>, // bunker_pubkey -> handler (concurrent LRU cache)
    client: Client,
    pool: PgPool,
    key_manager: Arc<Box<dyn KeyManager>>,
    coordinator: Arc<ClusterCoordinator>,
    auth_rx: Option<AuthorizationReceiver>,
    relay_sender: Option<crate::work_queue::RelaySender>,
    authorization_lookup: AuthorizationLookup,
    activity_logger: RelayActivityLogger,
}

#[derive(Clone)]
pub(crate) struct AuthorizationLookup {
    negative: Cache<String, u64>,
    singleflight: Cache<String, VersionedLookupResult>,
    permits: Arc<Semaphore>,
    invalidation_generations: Arc<[AtomicU64]>,
}

#[derive(Clone)]
struct VersionedLookupResult {
    generation: u64,
    handler: Option<Nip46Handler>,
}

#[derive(Debug, thiserror::Error)]
enum LookupFailure {
    #[error("authorization lookup admission full")]
    Saturated,
    #[error("authorization lookup dependency failed: {0}")]
    Dependency(String),
    #[error("authorization changed during lookup")]
    Invalidated,
}

#[derive(Clone)]
pub(crate) struct RelayWorkerContext {
    handlers: Cache<String, Nip46Handler>,
    client: Client,
    pool: PgPool,
    key_manager: Arc<Box<dyn KeyManager>>,
    coordinator: Arc<ClusterCoordinator>,
    authorization_lookup: AuthorizationLookup,
    activity_logger: RelayActivityLogger,
}

struct ActiveLookupGuard;

impl Drop for ActiveLookupGuard {
    fn drop(&mut self) {
        METRICS.dec_nip46_lookup_in_flight();
    }
}

impl AuthorizationLookup {
    fn new() -> Self {
        let negative_capacity = configured_usize("NIP46_NEGATIVE_CACHE_SIZE", 10_000);
        let singleflight_capacity = configured_usize(
            "NIP46_SINGLEFLIGHT_CACHE_SIZE",
            DEFAULT_NIP46_SINGLEFLIGHT_CACHE_SIZE,
        );
        let ttl_secs = configured_usize("NIP46_NEGATIVE_CACHE_TTL_SECS", 30);
        let concurrency =
            configured_usize("NIP46_LOOKUP_CONCURRENCY", DEFAULT_NIP46_LOOKUP_CONCURRENCY);
        Self::with_capacities(
            negative_capacity,
            singleflight_capacity,
            Duration::from_secs(ttl_secs as u64),
            concurrency,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_config(capacity: usize, ttl: Duration, concurrency: usize) -> Self {
        Self::with_capacities(capacity, capacity, ttl, concurrency)
    }

    fn with_capacities(
        negative_capacity: usize,
        singleflight_capacity: usize,
        ttl: Duration,
        concurrency: usize,
    ) -> Self {
        METRICS.set_nip46_lookup_limit(concurrency as u64);
        Self {
            negative: Cache::builder()
                .max_capacity(negative_capacity as u64)
                .time_to_live(ttl)
                .build(),
            singleflight: Cache::builder()
                .max_capacity(singleflight_capacity as u64)
                .time_to_live(ttl.min(Duration::from_secs(1)))
                .build(),
            permits: Arc::new(Semaphore::new(concurrency)),
            invalidation_generations: (0..LOOKUP_INVALIDATION_SHARDS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into(),
        }
    }

    async fn invalidate(&self, bunker_pubkey: &str) {
        self.invalidation_generations[invalidation_shard(bunker_pubkey)]
            .fetch_add(1, Ordering::SeqCst);
        self.negative.invalidate(bunker_pubkey).await;
        self.singleflight.invalidate(bunker_pubkey).await;
        METRICS.set_nip46_negative_cache_size(self.negative.entry_count());
    }

    fn invalidate_all(&self) {
        for generation in self.invalidation_generations.iter() {
            generation.fetch_add(1, Ordering::SeqCst);
        }
        self.negative.invalidate_all();
        self.singleflight.invalidate_all();
        METRICS.set_nip46_negative_cache_size(0);
    }

    pub(crate) async fn resolve_with<F>(
        &self,
        bunker_pubkey: &str,
        handlers: &Cache<String, Nip46Handler>,
        load: F,
    ) -> SignerResult<Option<Nip46Handler>>
    where
        F: std::future::Future<Output = SignerResult<Option<Nip46Handler>>> + Send + 'static,
    {
        let invalidation_shard = invalidation_shard(bunker_pubkey);
        if let Some(cached_generation) = self.negative.get(bunker_pubkey).await {
            let current_generation =
                self.invalidation_generations[invalidation_shard].load(Ordering::SeqCst);
            if cached_generation == current_generation {
                METRICS.inc_nip46_negative_cache_hit();
                METRICS.inc_nip46_handler_not_found();
                return Ok(None);
            }
            self.negative.invalidate(bunker_pubkey).await;
        }

        let permits = self.permits.clone();
        let negative = self.negative.clone();
        let loader_handlers = handlers.clone();
        let invalidation_generations = self.invalidation_generations.clone();
        let lookup_generation = invalidation_generations[invalidation_shard].load(Ordering::SeqCst);
        let key = bunker_pubkey.to_string();
        let result = match self
            .singleflight
            .try_get_with(key.clone(), async move {
                let _permit = permits
                    .try_acquire_owned()
                    .map_err(|_| LookupFailure::Saturated)?;
                METRICS.inc_nip46_lookup_in_flight();
                let _active_lookup = ActiveLookupGuard;
                METRICS.inc_nip46_lookup_database();
                let handler = load
                    .await
                    .map_err(|error| LookupFailure::Dependency(error.to_string()))?;
                if invalidation_generations[invalidation_shard].load(Ordering::SeqCst)
                    != lookup_generation
                {
                    return Err(LookupFailure::Invalidated);
                }
                if let Some(handler) = &handler {
                    loader_handlers.insert(key.clone(), handler.clone()).await;
                } else {
                    negative.insert(key.clone(), lookup_generation).await;
                }
                Ok::<VersionedLookupResult, LookupFailure>(VersionedLookupResult {
                    generation: lookup_generation,
                    handler,
                })
            })
            .await
        {
            Ok(handler) => handler,
            Err(error) => match error.as_ref() {
                LookupFailure::Saturated => {
                    METRICS.inc_nip46_lookup_shed();
                    // Saturation is a deliberate shed, not authoritative absence.
                    // The request can retry and no negative entry is written.
                    return Ok(None);
                }
                LookupFailure::Dependency(message) => {
                    METRICS.inc_nip46_lookup_error();
                    return Err(SignerError::internal(message));
                }
                // The result raced an authorization change and was not cached.
                // The client can retry without waiting for the negative TTL.
                LookupFailure::Invalidated => {
                    METRICS.inc_nip46_lookup_invalidated();
                    return Ok(None);
                }
            },
        };
        let current_generation =
            self.invalidation_generations[invalidation_shard].load(Ordering::SeqCst);
        if result.generation != current_generation {
            self.negative.invalidate(bunker_pubkey).await;
            self.singleflight.invalidate(bunker_pubkey).await;
            handlers.invalidate(bunker_pubkey).await;
            METRICS.inc_nip46_lookup_invalidated();
            METRICS.set_nip46_negative_cache_size(self.negative.entry_count());
            return Ok(None);
        }
        let handler = result.handler;
        if handler.is_none() {
            METRICS.inc_nip46_handler_not_found();
            METRICS.set_nip46_negative_cache_size(self.negative.entry_count());
        }
        Ok(handler)
    }
}

fn invalidation_shard(bunker_pubkey: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    bunker_pubkey.hash(&mut hasher);
    hasher.finish() as usize % LOOKUP_INVALIDATION_SHARDS
}

fn configured_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[derive(Clone, Copy)]
pub(crate) enum OwnershipStage {
    Prequeue,
    Worker,
}

pub(crate) fn admits_owned_request(owned: bool, stage: OwnershipStage) -> bool {
    if owned {
        return true;
    }
    match stage {
        OwnershipStage::Prequeue => METRICS.inc_nip46_rejected_hashring_prequeue(),
        OwnershipStage::Worker => METRICS.inc_nip46_rejected_hashring_worker(),
    }
    false
}

pub(crate) fn enqueue_owned_relay_event(
    sender: &crate::work_queue::RelaySender,
    event: Box<Event>,
    bunker_pubkey: String,
    owned: bool,
) -> bool {
    if !admits_owned_request(owned, OwnershipStage::Prequeue) {
        return false;
    }
    match sender.try_send(event, bunker_pubkey) {
        Ok(()) => true,
        Err(crate::work_queue::RelayQueueError::Disconnected) => {
            tracing::warn!("NIP-46 relay queue disconnected");
            false
        }
        Err(error) => {
            tracing::trace!(
                reason = %error,
                "NIP-46 request shed before queue admission"
            );
            false
        }
    }
}

impl UnifiedSigner {
    /// Create a new UnifiedSigner with the given database pool and key manager.
    pub async fn new(
        pool: PgPool,
        key_manager: Box<dyn KeyManager>,
        auth_rx: AuthorizationReceiver,
        coordinator: Arc<ClusterCoordinator>,
        activity_logger: RelayActivityLogger,
    ) -> SignerResult<Self> {
        let client = Client::default();

        // Get cache size from environment or use default
        let cache_size = std::env::var("HANDLER_CACHE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_HANDLER_CACHE_SIZE);

        let handlers = Cache::builder().max_capacity(cache_size as u64).build();

        tracing::info!("Initialized authorization cache (capacity: {})", cache_size);

        Ok(Self {
            handlers,
            client,
            pool,
            key_manager: Arc::new(key_manager),
            coordinator,
            auth_rx: Some(auth_rx),
            relay_sender: None,
            authorization_lookup: AuthorizationLookup::new(),
            activity_logger,
        })
    }

    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Get the handlers cache (for spawning RPC workers)
    pub fn handlers(&self) -> Cache<String, Nip46Handler> {
        self.handlers.clone()
    }

    /// Get the database pool
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Get the key manager
    pub fn key_manager(&self) -> Arc<Box<dyn KeyManager>> {
        self.key_manager.clone()
    }

    /// Get the cluster coordinator
    pub fn coordinator(&self) -> Arc<ClusterCoordinator> {
        self.coordinator.clone()
    }

    pub fn activity_logger(&self) -> RelayActivityLogger {
        self.activity_logger.clone()
    }

    pub fn spawn_relay_workers(
        &self,
        queue: &crate::work_queue::RelayQueue,
        num_workers: usize,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        queue.spawn_workers(num_workers, self.relay_worker_context())
    }

    fn relay_worker_context(&self) -> RelayWorkerContext {
        RelayWorkerContext {
            handlers: self.handlers(),
            client: self.client(),
            pool: self.pool(),
            key_manager: self.key_manager(),
            coordinator: self.coordinator(),
            authorization_lookup: self.authorization_lookup.clone(),
            activity_logger: self.activity_logger.clone(),
        }
    }

    /// Set the relay sender for queue-based processing
    /// When set, incoming NIP-46 relay requests are sent to the queue instead of spawning tasks
    pub fn set_relay_sender(&mut self, sender: crate::work_queue::RelaySender) {
        self.relay_sender = Some(sender);
    }

    /// No-op: authorizations are now loaded on-demand with LRU caching
    pub async fn load_authorizations(&mut self) -> SignerResult<()> {
        // Lazy loading: handlers are loaded on-demand when requests arrive
        // This scales to millions of users without memory issues
        tracing::info!("Lazy loading enabled - authorizations will be loaded on-demand");
        Ok(())
    }

    /// Connect to all configured bunker relays.
    ///
    /// Adds all relays to the client and initiates connections with a timeout
    /// to prevent indefinite blocking if relays are unreachable.
    pub async fn connect_to_relays(&self) -> SignerResult<()> {
        // Get relay list from environment variable (comma-separated)
        let relay_urls = Self::get_bunker_relays();

        // Add all relays with individual timeouts
        for relay_url in &relay_urls {
            match tokio::time::timeout(
                RELAY_CONNECT_TIMEOUT,
                self.client.add_relay(relay_url.as_str()),
            )
            .await
            {
                Ok(Ok(_)) => {
                    tracing::debug!("Added relay: {}", relay_url);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to add relay {}: {}", relay_url, e);
                    // Continue with other relays instead of failing entirely
                }
                Err(_) => {
                    tracing::warn!("Timeout adding relay {}", relay_url);
                    // Continue with other relays
                }
            }
        }

        // Connect to all added relays with a timeout
        match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, self.client.connect()).await {
            Ok(_) => {
                tracing::info!(
                    "Connected to {} relay(s) for NIP-46 communication: {:?}",
                    relay_urls.len(),
                    relay_urls
                );
            }
            Err(_) => {
                tracing::warn!(
                    "Timeout connecting to relays ({}s) - continuing in background",
                    RELAY_CONNECT_TIMEOUT.as_secs()
                );
                // Connection will continue in background; don't fail startup
            }
        }

        Ok(())
    }

    /// Get the configured bunker relay list
    ///
    /// Requires BUNKER_RELAYS environment variable to be set.
    /// Panics if not configured - relay connections must be explicit.
    pub fn get_bunker_relays() -> Vec<String> {
        let relays_str =
            std::env::var("BUNKER_RELAYS").expect("BUNKER_RELAYS environment variable is required");

        let relays: Vec<String> = relays_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if relays.is_empty() {
            panic!("BUNKER_RELAYS must contain at least one relay URL");
        }

        relays
    }

    /// Run the signer daemon event loop.
    ///
    /// Subscribes to NIP-46 events and processes incoming signing requests.
    pub async fn run(&mut self) -> SignerResult<()> {
        let handlers = self.handlers.clone();

        // OPTIMIZATION: Single subscription for ALL kind 24133 events
        // We'll filter by bunker pubkey in the handler, not at relay level
        // This scales to millions of users with just ONE relay connection
        let filter = Filter::new().kind(Kind::NostrConnect);

        self.client
            .subscribe(filter, None)
            .await
            .map_err(|e| SignerError::relay(format!("Failed to subscribe: {}", e)))?;

        // Spawn background task to handle authorization commands via channel
        let pool_clone = self.pool.clone();
        let key_manager_clone = self.key_manager.clone();
        let handlers_clone = self.handlers.clone();
        let lookup_clone = self.authorization_lookup.clone();
        let activity_logger_clone = self.activity_logger.clone();
        let coordinator_clone = self.coordinator.clone();

        let mut cluster_events = self.coordinator.subscribe();
        let cluster_lookup = self.authorization_lookup.clone();
        tokio::spawn(async move {
            loop {
                match cluster_events.recv().await {
                    Ok(MembershipEvent::AuthorizationInvalidated(bunker_pubkey)) => {
                        cluster_lookup.invalidate(&bunker_pubkey).await;
                    }
                    Ok(MembershipEvent::Joined(_) | MembershipEvent::Left(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        cluster_lookup.invalidate_all();
                        tracing::warn!(
                            skipped,
                            "Authorization invalidation listener lagged; cleared lookup caches conservatively"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        // Take ownership of the receiver (we only spawn this once)
        if let Some(mut auth_rx) = self.auth_rx.take() {
            tokio::spawn(async move {
                tracing::debug!("Authorization channel listener started");
                while let Some(command) = auth_rx.recv().await {
                    match command {
                        AuthorizationCommand::Upsert {
                            bunker_pubkey,
                            tenant_id,
                            is_oauth,
                        } => {
                            lookup_clone.invalidate(&bunker_pubkey).await;
                            if let Err(error) = coordinator_clone
                                .publish_authorization_invalidation(&bunker_pubkey)
                                .await
                            {
                                tracing::warn!(
                                    error = %error,
                                    "Failed to publish authorization cache invalidation; TTL remains the fallback"
                                );
                            }
                            tracing::debug!(
                                "Received Upsert command for bunker: {}",
                                bunker_pubkey
                            );
                            if let Err(e) = Self::load_single_authorization(
                                &pool_clone,
                                &key_manager_clone,
                                &handlers_clone,
                                &bunker_pubkey,
                                tenant_id,
                                is_oauth,
                                &activity_logger_clone,
                            )
                            .await
                            {
                                tracing::error!(
                                    "Error loading authorization {}: {}",
                                    bunker_pubkey,
                                    e
                                );
                            }
                        }
                        AuthorizationCommand::Remove { bunker_pubkey } => {
                            tracing::debug!("Marking authorization as revoked: {}", bunker_pubkey);
                            if let Some(handler) = handlers_clone.get(&bunker_pubkey).await {
                                let mut updated = handler.clone();
                                updated.status = HandlerStatus::Revoked;
                                updated.tombstone_at = Some(Utc::now());
                                handlers_clone.insert(bunker_pubkey.clone(), updated).await;
                            }
                            // If not in cache, next request will load from DB as revoked
                        }
                        AuthorizationCommand::ReloadAll => {
                            // No-op with lazy loading - cache is populated on-demand
                            tracing::debug!("ReloadAll is no-op with lazy loading");
                        }
                    }
                }
                tracing::warn!("Authorization channel closed");
            });
        } else {
            tracing::warn!("No authorization receiver available, channel updates disabled");
        }

        // Spawn background task for tombstone cleanup (remove old revoked/expired handlers)
        // This prevents memory buildup from tombstones while still giving clients time to receive errors
        let handlers_cleanup = handlers.clone();
        tokio::spawn(async move {
            // Run every hour, clean up tombstones older than 24 hours
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let cutoff = Utc::now() - chrono::Duration::hours(24);
                let mut to_remove = Vec::new();

                // Collect tombstone keys older than 24 hours
                // Note: iter() yields (Arc<K>, V) pairs, so key is Arc<String>
                for (key, handler) in handlers_cleanup.iter() {
                    if handler.tombstone_is_older_than(cutoff) {
                        to_remove.push(key.as_ref().clone());
                    }
                }

                // Remove old tombstones
                let count = to_remove.len();
                for key in &to_remove {
                    handlers_cleanup.invalidate(key).await;
                }
                if count > 0 {
                    tracing::info!("Cleaned up {} old tombstone handlers", count);
                }
            }
        });

        // Handle incoming events
        let client = self.client.clone();
        let pool = self.pool.clone();
        let key_manager = self.key_manager.clone();
        let coordinator = self.coordinator.clone();
        let relay_sender = self.relay_sender.clone();
        let authorization_lookup = self.authorization_lookup.clone();
        let activity_logger = self.activity_logger.clone();

        self.client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect {
                        // Extract bunker pubkey early for queue-based processing
                        let bunker_pubkey = event
                            .tags
                            .iter()
                            .find(|tag| tag.kind() == TagKind::p())
                            .and_then(|tag| tag.content())
                            .map(|s| s.to_string());

                        if let Some(ref sender) = relay_sender {
                            // QUEUE-BASED PROCESSING: Send to relay queue for bounded concurrency
                            if let Some(bunker_pubkey) = bunker_pubkey {
                                // Reject peer-owned work before it can consume local queue
                                // or per-flow capacity. Workers repeat this check because
                                // hashring ownership can change while an item waits.
                                let owned = coordinator.should_handle(&bunker_pubkey);
                                enqueue_owned_relay_event(sender, event, bunker_pubkey, owned);
                            } else {
                                tracing::trace!("Ignoring NIP-46 event without p-tag");
                            }
                        } else {
                            // LEGACY: Direct spawning (for backwards compatibility / testing)
                            let context = RelayWorkerContext {
                                handlers: handlers.clone(),
                                client: client.clone(),
                                pool: pool.clone(),
                                key_manager: key_manager.clone(),
                                coordinator: coordinator.clone(),
                                authorization_lookup: authorization_lookup.clone(),
                                activity_logger: activity_logger.clone(),
                            };
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_nip46_request(&context, event).await {
                                    // Filter out expected noise from malformed external requests
                                    match &e {
                                        SignerError::MissingParameter("p-tag") => {
                                            tracing::trace!(
                                                "Ignoring malformed NIP-46 request: {}",
                                                e
                                            );
                                        }
                                        _ => {
                                            tracing::error!("Error handling NIP-46 request: {}", e);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
                Ok(false) // Continue listening
            })
            .await
            .map_err(|e| SignerError::relay(format!("Notification handler failed: {}", e)))?;

        Ok(())
    }

    /// Load a single authorization into cache (called via channel for new authorizations)
    async fn load_single_authorization(
        pool: &PgPool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        handlers: &Cache<String, Nip46Handler>,
        bunker_pubkey: &str,
        tenant_id: i64,
        is_oauth: bool,
        activity_logger: &RelayActivityLogger,
    ) -> SignerResult<()> {
        if is_oauth {
            // Load active OAuth authorization (filter out revoked/expired)
            let auth = OAuthAuthorization::find_active_by_bunker_pubkey_for_tenant(
                pool,
                bunker_pubkey,
                tenant_id,
            )
            .await?;

            if let Some(auth) = auth {
                // Get user's key from personal_keys first (needed for HKDF derivation)
                let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
                    "SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2"
                )
                .bind(&auth.user_pubkey)
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;

                let decrypted_user_secret = key_manager
                    .decrypt(&encrypted_user_key)
                    .await
                    .map_err(|e| SignerError::encryption(e.to_string()))?;
                let user_secret_key =
                    SecretKey::from_slice(&decrypted_user_secret).map_err(|e| {
                        SignerError::invalid_key(format!("Invalid user secret key: {}", e))
                    })?;
                let user_keys = Keys::new(user_secret_key.clone());

                // Derive bunker keys using HKDF with secret_hash as entropy
                // This avoids an extra KMS call - user_secret is already decrypted
                let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(
                    &user_secret_key,
                    &auth.secret_hash,
                );

                // The query above already filters out revoked/expired rows, but the
                // status is still computed rather than assumed: the handler is cached
                // without a TTL, so it must carry the expiry it was loaded with.
                let (status, tombstone_at) = Nip46Handler::compute_status_from_oauth(&auth);

                let handler = Nip46Handler {
                    bunker_keys,
                    user_keys,
                    secret_hash: auth.secret_hash.clone(),
                    authorization_id: auth.id,
                    tenant_id,
                    is_oauth: true,
                    pool: pool.clone(),
                    activity_logger: activity_logger.clone(),
                    status,
                    tombstone_at,
                    expires_at: auth.expires_at,
                };

                handlers.insert(bunker_pubkey.to_string(), handler).await;
                tracing::debug!("Cached authorization: {}", bunker_pubkey);
            }
        } else {
            // Load regular authorization. Team authorizations use hard-delete
            // (no revoked_at), so expires_at is the only tombstone signal.
            let auth_data: Option<(i32, String, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
                "SELECT id, secret_hash, stored_key_id, expires_at FROM authorizations
                 WHERE tenant_id = $1 AND bunker_public_key = $2",
            )
            .bind(tenant_id)
            .bind(bunker_pubkey)
            .fetch_optional(pool)
            .await?;

            if let Some((auth_id, secret_hash, stored_key_id, expires_at)) = auth_data {
                // Load stored_key (team's signing key) first - needed for HKDF derivation
                let stored_key_secret: Vec<u8> = sqlx::query_scalar(
                    "SELECT secret_key FROM stored_keys WHERE id = $1 AND tenant_id = $2",
                )
                .bind(stored_key_id)
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;

                let decrypted_user_secret = key_manager
                    .decrypt(&stored_key_secret)
                    .await
                    .map_err(|e| SignerError::encryption(e.to_string()))?;
                let user_secret_key =
                    SecretKey::from_slice(&decrypted_user_secret).map_err(|e| {
                        SignerError::invalid_key(format!("Invalid user secret key: {}", e))
                    })?;
                let user_keys = Keys::new(user_secret_key.clone());

                // Derive bunker keys using HKDF with secret_hash as entropy
                // This avoids an extra KMS call - user_secret is already decrypted
                let bunker_keys =
                    keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &secret_hash);

                // Unlike the OAuth branch, this query cannot filter expiry out in SQL
                // without losing the row needed to answer with a tombstone error, so
                // the status is computed here.
                let (status, tombstone_at) = Nip46Handler::compute_status_from_expiry(expires_at);

                let handler = Nip46Handler {
                    bunker_keys,
                    user_keys,
                    secret_hash,
                    authorization_id: auth_id,
                    tenant_id,
                    is_oauth: false,
                    pool: pool.clone(),
                    activity_logger: activity_logger.clone(),
                    status,
                    tombstone_at,
                    expires_at,
                };

                handlers.insert(bunker_pubkey.to_string(), handler).await;
                tracing::debug!("Cached authorization: {}", bunker_pubkey);
            }
        }

        Ok(())
    }

    async fn lookup_authorization(
        lookup: &AuthorizationLookup,
        handlers: &Cache<String, Nip46Handler>,
        pool: &PgPool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        activity_logger: &RelayActivityLogger,
        bunker_pubkey: &str,
    ) -> SignerResult<Option<Nip46Handler>> {
        let pool = pool.clone();
        let key_manager = key_manager.clone();
        let activity_logger = activity_logger.clone();
        let key = bunker_pubkey.to_string();
        lookup
            .resolve_with(bunker_pubkey, handlers, async move {
                Self::load_authorization_from_database(&pool, &key_manager, &activity_logger, &key)
                    .await
            })
            .await
    }

    async fn load_authorization_from_database(
        pool: &PgPool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        activity_logger: &RelayActivityLogger,
        bunker_pubkey: &str,
    ) -> SignerResult<Option<Nip46Handler>> {
        if let Some(auth) =
            OAuthAuthorization::find_by_bunker_pubkey_for_signer(pool, bunker_pubkey).await?
        {
            let (status, tombstone_at) = Nip46Handler::compute_status_from_oauth(&auth);
            let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
                "SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2",
            )
            .bind(&auth.user_pubkey)
            .bind(auth.tenant_id)
            .fetch_one(pool)
            .await?;
            let decrypted_user_secret = key_manager
                .decrypt(&encrypted_user_key)
                .await
                .map_err(|error| SignerError::encryption(error.to_string()))?;
            let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
                .map_err(|error| SignerError::invalid_key(error.to_string()))?;
            let bunker_keys =
                keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &auth.secret_hash);
            return Ok(Some(Nip46Handler {
                bunker_keys,
                user_keys: Keys::new(user_secret_key),
                secret_hash: auth.secret_hash,
                authorization_id: auth.id,
                tenant_id: auth.tenant_id,
                is_oauth: true,
                pool: pool.clone(),
                activity_logger: activity_logger.clone(),
                status,
                tombstone_at,
                expires_at: auth.expires_at,
            }));
        }

        #[allow(clippy::type_complexity)]
        let auth_data: Option<(i32, String, i32, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT id, secret_hash, stored_key_id, tenant_id, expires_at
             FROM authorizations WHERE bunker_public_key = $1",
        )
        .bind(bunker_pubkey)
        .fetch_optional(pool)
        .await?;

        let Some((authorization_id, secret_hash, stored_key_id, tenant_id, expires_at)) = auth_data
        else {
            return Ok(None);
        };
        let stored_key_secret: Vec<u8> = sqlx::query_scalar(
            "SELECT secret_key FROM stored_keys WHERE id = $1 AND tenant_id = $2",
        )
        .bind(stored_key_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
        let decrypted_user_secret = key_manager
            .decrypt(&stored_key_secret)
            .await
            .map_err(|error| SignerError::encryption(error.to_string()))?;
        let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
            .map_err(|error| SignerError::invalid_key(error.to_string()))?;
        let bunker_keys =
            keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &secret_hash);
        let (status, tombstone_at) = Nip46Handler::compute_status_from_expiry(expires_at);
        Ok(Some(Nip46Handler {
            bunker_keys,
            user_keys: Keys::new(user_secret_key),
            secret_hash,
            authorization_id,
            tenant_id,
            is_oauth: false,
            pool: pool.clone(),
            activity_logger: activity_logger.clone(),
            status,
            tombstone_at,
            expires_at,
        }))
    }

    pub(crate) async fn handle_nip46_request(
        context: &RelayWorkerContext,
        event: Box<Event>,
    ) -> SignerResult<()> {
        let RelayWorkerContext {
            handlers,
            client,
            pool,
            key_manager,
            coordinator,
            authorization_lookup,
            activity_logger,
        } = context;
        // SINGLE SUBSCRIPTION ARCHITECTURE:
        // We receive ALL kind 24133 events from the relay (no pubkey filter)
        // Now we check if the target bunker pubkey (in #p tag) is one we manage
        // If yes: decrypt and handle. If no: silently ignore
        // This scales to millions of users with just ONE relay connection!

        // Get the bunker pubkey from p-tag (target of the signing request)
        let bunker_pubkey = event
            .tags
            .iter()
            .find(|tag| tag.kind() == TagKind::p())
            .and_then(|tag| tag.content())
            .ok_or(SignerError::MissingParameter("p-tag"))?;

        // HASHRING CHECK: Only process if this instance owns this pubkey
        // Note: should_handle() is lock-free (uses arc_swap)
        if !admits_owned_request(
            coordinator.should_handle(bunker_pubkey),
            OwnershipStage::Worker,
        ) {
            tracing::trace!(
                "Hashring: bunker {} assigned to another instance, skipping",
                bunker_pubkey
            );
            return Ok(());
        }

        // Count all requests that pass hashring check (our responsibility)
        METRICS.inc_nip46_request();
        tracing::trace!("Received NIP-46 request for bunker: {}", bunker_pubkey);

        // Check if this bunker pubkey is in cache (concurrent LRU)
        let handler = handlers.get(bunker_pubkey).await;

        let handler = match handler {
            Some(h) => {
                METRICS.inc_cache_hit();
                h
            }
            None => {
                METRICS.inc_cache_miss();
                match Self::lookup_authorization(
                    authorization_lookup,
                    handlers,
                    pool,
                    key_manager,
                    activity_logger,
                    bunker_pubkey,
                )
                .await?
                {
                    Some(handler) => handler,
                    None => return Ok(()),
                }
            }
        };

        // Decrypt the request - try NIP-44 first, fall back to NIP-04
        let bunker_secret = handler.bunker_keys.secret_key();

        tracing::debug!(
            "Attempting to decrypt NIP-46 request - content_len: {}, from_pubkey: {}",
            event.content.len(),
            event.pubkey.to_hex()
        );

        // Try NIP-44 first (new standard), fall back to NIP-04
        // CPU-bound crypto wrapped in spawn_blocking to avoid blocking async runtime
        // Returns SecretString for automatic memory zeroization on drop
        let (decrypted, use_nip44): (SecretString, bool) = {
            let secret = bunker_secret.clone();
            let sender_pubkey = event.pubkey;
            let content = event.content.clone();

            tokio::task::spawn_blocking(move || {
                match nip44::decrypt(&secret, &sender_pubkey, &content) {
                    Ok(d) => {
                        tracing::debug!("Successfully decrypted with NIP-44");
                        Ok((SecretString::from(d), true))
                    }
                    Err(nip44_err) => {
                        tracing::debug!("NIP-44 decrypt failed ({}), trying NIP-04...", nip44_err);
                        match nip04::decrypt(&secret, &sender_pubkey, &content) {
                            Ok(d) => {
                                tracing::debug!("Successfully decrypted with NIP-04");
                                Ok((SecretString::from(d), false))
                            }
                            Err(nip04_err) => {
                                tracing::error!(
                                    "Both NIP-44 and NIP-04 decrypt failed - NIP-44: {}, NIP-04: {} | From: {}",
                                    nip44_err,
                                    nip04_err,
                                    sender_pubkey.to_hex()
                                );
                                Err(SignerError::from(nip04_err))
                            }
                        }
                    }
                }
            })
            .await
            .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
        };

        tracing::debug!(
            "Decrypted NIP-46 request ({} bytes)",
            decrypted.expose_secret().len()
        );

        // Parse the JSON-RPC request - expose secret only for deserialization
        let request: serde_json::Value = serde_json::from_str(decrypted.expose_secret())?;
        let method = request["method"]
            .as_str()
            .ok_or(SignerError::MissingParameter("method"))?;
        let request_id = request["id"].clone(); // Extract request ID for response

        // Check for tombstone status - send error response instead of processing
        if let Some(error_message) = handler.tombstone_error_message() {
            tracing::info!(
                "Sending tombstone error response for {}: {}",
                bunker_pubkey,
                error_message
            );
            METRICS.inc_nip46_tombstone_response();

            let response = serde_json::json!({
                "id": request_id,
                "error": error_message
            });

            // Encrypt and send error response (CPU-bound, use spawn_blocking)
            let response_str = response.to_string();
            let encrypted_response = {
                let secret = bunker_secret.clone();
                let pubkey = event.pubkey;
                let text = response_str.clone();
                let use_44 = use_nip44;
                tokio::task::spawn_blocking(move || {
                    if use_44 {
                        nip44::encrypt(&secret, &pubkey, &text, nip44::Version::V2)
                            .map_err(SignerError::from)
                    } else {
                        nip04::encrypt(&secret, &pubkey, &text).map_err(SignerError::from)
                    }
                })
                .await
                .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
            };

            let response_event = {
                let keys = handler.bunker_keys.clone();
                let content = encrypted_response;
                let sender = event.pubkey;
                tokio::task::spawn_blocking(move || {
                    EventBuilder::new(Kind::NostrConnect, content)
                        .tags(vec![Tag::public_key(sender)])
                        .sign_with_keys(&keys)
                })
                .await
                .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))?
            }?;

            client.send_event(&response_event).await?;
            return Ok(());
        }

        tracing::info!("Processing NIP-46 method: {}", method);

        // For OAuth authorizations, validate client pubkey for sensitive methods
        // Per NIP-46: after connect, client_pubkey becomes the identifier for security
        let client_pubkey = event.pubkey.to_hex();
        let requires_validation = matches!(
            method,
            "sign_event" | "nip44_encrypt" | "nip44_decrypt" | "nip04_encrypt" | "nip04_decrypt"
        );

        if handler.is_oauth && requires_validation {
            // Use validate_and_store_client for graceful upgrade:
            // - If no client connected yet, stores this client and allows
            // - If client matches stored, allows
            // - If client doesn't match stored, rejects
            if let Err(e) = handler.validate_and_store_client(&client_pubkey).await {
                tracing::warn!("Client validation failed for {}: {}", client_pubkey, e);
                let response = serde_json::json!({
                    "id": request_id,
                    "error": format!("Client not authorized: {}", e)
                });

                // Encrypt and send error response (CPU-bound, use spawn_blocking)
                let response_str = response.to_string();
                let encrypted_response = {
                    let secret = bunker_secret.clone();
                    let pubkey = event.pubkey;
                    let text = response_str.clone();
                    let use_44 = use_nip44;
                    tokio::task::spawn_blocking(move || {
                        if use_44 {
                            nip44::encrypt(&secret, &pubkey, &text, nip44::Version::V2)
                                .map_err(SignerError::from)
                        } else {
                            nip04::encrypt(&secret, &pubkey, &text).map_err(SignerError::from)
                        }
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                let response_event = {
                    let keys = handler.bunker_keys.clone();
                    let content = encrypted_response;
                    let sender = event.pubkey;
                    let event_id = event.id.to_hex();
                    tokio::task::spawn_blocking(move || {
                        EventBuilder::new(Kind::NostrConnect, content)
                            .tags(vec![
                                Tag::public_key(sender),
                                Tag::parse(vec!["e".to_string(), event_id]).unwrap(),
                            ])
                            .sign_with_keys(&keys)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                client.send_event(&response_event).await?;
                return Ok(());
            }
        }

        // Dispatch the method and build the encrypted response event. Expected
        // per-request denials (permission denied, bad params/key) become a clean
        // JSON-RPC {id, error} reply here instead of ?-propagating out of this
        // handler and leaving the client to time out; only internal failures
        // still propagate to be logged. See build_nip46_response_event.
        let response_event = handler
            .build_nip46_response_event(
                method,
                &request,
                &request_id,
                &client_pubkey,
                event.pubkey,
                event.id,
                use_nip44,
            )
            .await?;

        tracing::debug!(
            "Sending response event {} (size: {} bytes)",
            response_event.id,
            response_event.content.len()
        );

        let send_result = client.send_event(&response_event).await.map_err(|e| {
            tracing::error!("Failed to send response event: {:?}", e);
            e
        })?;

        tracing::info!(
            "Sent NIP-46 response for request {} (send_result: {:?})",
            event.id,
            send_result
        );

        // Count successful processing and update cache size metric
        METRICS.inc_nip46_processed();
        METRICS.set_cache_size(handlers.entry_count());

        Ok(())
    }
}

#[async_trait]
impl SigningHandler for Nip46Handler {
    async fn sign_event_direct(
        &self,
        mut unsigned_event: UnsignedEvent,
    ) -> Result<Event, Box<dyn std::error::Error + Send + Sync>> {
        let kind = unsigned_event.kind.as_u16();

        tracing::info!(
            "Direct signing event kind {} for authorization {}",
            kind,
            self.authorization_id
        );

        self.ensure_authorization_active()?;

        // Check account status, minor DM gate, and policy permissions before signing
        self.check_user_sign_gates(&unsigned_event).await?;
        self.validate_permissions_for_sign(&unsigned_event).await?;
        // Recheck after the awaits: clock-derived expiry can fall due mid-request.
        self.ensure_authorization_active()?;

        // Canonicalize the pubkey to match the signer keys, matching SigningSession::sign_event behavior.
        // This prevents producing an event where event.pubkey disagrees with the keypair that signed it.
        let signer_pubkey = self.user_keys.public_key();
        canonicalize_event_author(
            &mut unsigned_event,
            signer_pubkey,
            "signer_daemon.pubkey_canonicalized",
        );

        // Sign the event with user keys (consumes unsigned_event)
        let signed_event = unsigned_event
            .sign(&self.user_keys)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        tracing::debug!("Successfully signed event: {}", signed_event.id);

        self.spawn_update_activity();

        Ok(signed_event)
    }

    fn authorization_id(&self) -> i64 {
        self.authorization_id as i64
    }

    fn user_pubkey(&self) -> String {
        self.user_keys.public_key().to_hex()
    }

    fn get_keys(&self) -> Keys {
        self.user_keys.clone()
    }
}

impl Nip46Handler {
    async fn handle_sign_event(
        &self,
        request: &serde_json::Value,
    ) -> SignerResult<serde_json::Value> {
        // Parse the unsigned event from params
        let event_json = request["params"][0]
            .as_str()
            .ok_or(SignerError::MissingParameter("event"))?;
        let unsigned_event: serde_json::Value = serde_json::from_str(event_json)?;

        // Extract fields from unsigned event
        let kind = unsigned_event["kind"]
            .as_u64()
            .ok_or(SignerError::MissingParameter("kind"))? as u16;
        let content = unsigned_event["content"]
            .as_str()
            .ok_or(SignerError::MissingParameter("content"))?;
        let created_at = unsigned_event["created_at"]
            .as_u64()
            .ok_or(SignerError::MissingParameter("created_at"))?;
        let tags_json = unsigned_event["tags"]
            .as_array()
            .ok_or(SignerError::MissingParameter("tags"))?;

        // Parse tags
        let mut tags = Vec::new();
        for tag_arr in tags_json {
            if let Some(arr) = tag_arr.as_array() {
                let tag_strs: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if !tag_strs.is_empty() {
                    tags.push(Tag::parse(tag_strs)?);
                }
            }
        }

        tracing::info!(
            "Signing event kind {} for authorization {}",
            kind,
            self.authorization_id
        );

        tracing::debug!(
            "Building event to sign: kind={}, content_len={}, tags_count={}",
            kind,
            content.len(),
            tags.len()
        );

        // Build unsigned event for validation
        let unsigned_event = UnsignedEvent::new(
            self.user_keys.public_key(),
            Timestamp::from(created_at),
            Kind::from(kind),
            tags.clone(),
            content,
        );

        self.ensure_authorization_active()?;

        // Check account status, minor DM gate, and policy permissions before signing
        self.check_user_sign_gates(&unsigned_event).await?;
        self.validate_permissions_for_sign(&unsigned_event).await?;
        // Recheck after the awaits: clock-derived expiry can fall due mid-request.
        self.ensure_authorization_active()?;

        // Sign the event with user keys (CPU-bound, use spawn_blocking)
        let signed_event = {
            let keys = self.user_keys.clone();
            let kind = unsigned_event.kind;
            let content = unsigned_event.content.clone();
            let tags = tags.clone();
            tokio::task::spawn_blocking(move || {
                EventBuilder::new(kind, &content)
                    .tags(tags)
                    .custom_created_at(Timestamp::from(created_at))
                    .sign_with_keys(&keys)
            })
            .await
            .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))?
            .map_err(|e| {
                tracing::error!("Failed to sign event: {:?}", e);
                SignerError::from(e)
            })?
        };

        tracing::debug!("Successfully signed event: {}", signed_event.id);

        self.spawn_update_activity();

        // Extract request ID to include in response
        let request_id = request["id"].clone();

        Ok(serde_json::json!({
            "id": request_id,
            "result": serde_json::to_string(&signed_event)?
        }))
    }

    /// Queue activity for the bounded, coalescing relay writer.
    fn spawn_update_activity(&self) {
        if !self.is_oauth {
            return;
        }
        self.activity_logger
            .record(self.tenant_id, self.authorization_id as i64);
    }
}

impl UnifiedSigner {
    /// Get authorization handler for a user's OAuth session
    /// Returns cached handler if available (fast path), otherwise None
    pub async fn get_handler_for_user(
        &self,
        user_pubkey: &str,
    ) -> SignerResult<Option<Nip46Handler>> {
        // Find any active OAuth authorization for this user
        let bunker_pubkey: Option<String> = sqlx::query_scalar(
            "SELECT bunker_public_key FROM oauth_authorizations
             WHERE user_pubkey = $1
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(bunker_key) = bunker_pubkey {
            Ok(self.handlers.get(&bunker_key).await)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod authorization_lookup_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_handler() -> Nip46Handler {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        Nip46Handler::new_for_test(
            Keys::generate(),
            Keys::generate(),
            "test-hash".to_string(),
            1,
            1,
            true,
            pool,
        )
    }

    #[test]
    fn singleflight_capacity_is_independent_from_negative_cache() {
        let lookup = AuthorizationLookup::with_capacities(3, 7, Duration::from_secs(1), 2);
        assert_eq!(lookup.negative.policy().max_capacity(), Some(3));
        assert_eq!(lookup.singleflight.policy().max_capacity(), Some(7));
        assert_eq!(DEFAULT_NIP46_SINGLEFLIGHT_CACHE_SIZE, 1_024);
        assert_eq!(DEFAULT_NIP46_LOOKUP_CONCURRENCY, 16);
    }

    #[tokio::test]
    async fn concurrent_unknown_target_is_coalesced() {
        let lookup = AuthorizationLookup::with_config(16, Duration::from_secs(1), 4);
        let handlers: Cache<String, Nip46Handler> = Cache::new(16);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in 0..12 {
            let lookup = lookup.clone();
            let handlers = handlers.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                lookup
                    .resolve_with("unknown", &handlers, async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(None)
                    })
                    .await
                    .expect("lookup")
            }));
        }

        for task in tasks {
            assert!(task.await.expect("task").is_none());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn varied_unknown_targets_obey_lookup_concurrency() {
        let lookup = AuthorizationLookup::with_config(4, Duration::from_secs(1), 2);
        let handlers: Cache<String, Nip46Handler> = Cache::new(16);
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for index in 0..16 {
            let lookup = lookup.clone();
            let handlers = handlers.clone();
            let active = active.clone();
            let peak = peak.clone();
            let attempts = attempts.clone();
            tasks.push(tokio::spawn(async move {
                lookup
                    .resolve_with(&format!("unknown-{index}"), &handlers, async move {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        attempts.fetch_add(1, Ordering::SeqCst);
                        peak.fetch_max(current, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(None)
                    })
                    .await
            }));
        }

        for task in tasks {
            assert!(task.await.expect("task").expect("lookup").is_none());
        }
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert!(
            attempts.load(Ordering::SeqCst) < 16,
            "varied misses beyond lookup capacity must shed instead of parking workers"
        );
    }

    #[tokio::test]
    async fn concurrent_positive_lookup_loads_and_caches_once() {
        let lookup = AuthorizationLookup::with_config(16, Duration::from_secs(1), 4);
        let handlers: Cache<String, Nip46Handler> = Cache::new(16);
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = test_handler();
        let mut tasks = Vec::new();

        for _ in 0..8 {
            let lookup = lookup.clone();
            let handlers = handlers.clone();
            let calls = calls.clone();
            let handler = handler.clone();
            tasks.push(tokio::spawn(async move {
                lookup
                    .resolve_with("known", &handlers, async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(Some(handler))
                    })
                    .await
            }));
        }

        for task in tasks {
            assert!(task.await.expect("task").expect("lookup").is_some());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(handlers.get("known").await.is_some());
    }

    #[tokio::test]
    async fn concurrent_dependency_failure_is_shared_without_negative_caching() {
        let lookup = AuthorizationLookup::with_config(16, Duration::from_secs(1), 4);
        let handlers: Cache<String, Nip46Handler> = Cache::new(16);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in 0..8 {
            let lookup = lookup.clone();
            let handlers = handlers.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                lookup
                    .resolve_with("dependency-error", &handlers, async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Err(SignerError::internal("database unavailable"))
                    })
                    .await
            }));
        }

        for task in tasks {
            assert!(task.await.expect("task").is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(lookup.negative.get("dependency-error").await.is_none());
    }

    #[tokio::test]
    async fn negative_cache_expires_and_creation_invalidation_clears_it() {
        let lookup = AuthorizationLookup::with_config(4, Duration::from_millis(20), 1);
        let handlers: Cache<String, Nip46Handler> = Cache::new(4);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let calls = calls.clone();
            assert!(lookup
                .resolve_with("created-later", &handlers, async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(None)
                })
                .await
                .expect("lookup")
                .is_none());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        lookup.invalidate("created-later").await;
        let calls_after_invalidation = calls.clone();
        lookup
            .resolve_with("created-later", &handlers, async move {
                calls_after_invalidation.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
            .await
            .expect("lookup");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        tokio::time::sleep(Duration::from_millis(25)).await;
        let calls_after_expiry = calls.clone();
        lookup
            .resolve_with("created-later", &handlers, async move {
                calls_after_expiry.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
            .await
            .expect("lookup");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn invalidation_during_lookup_cannot_repopulate_stale_caches() {
        let lookup = AuthorizationLookup::with_config(4, Duration::from_secs(30), 1);
        let handlers: Cache<String, Nip46Handler> = Cache::new(4);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let lookup_task = {
            let lookup = lookup.clone();
            let handlers = handlers.clone();
            tokio::spawn(async move {
                lookup
                    .resolve_with("created-during-lookup", &handlers, async move {
                        started_tx.send(()).expect("signal lookup start");
                        release_rx.await.expect("release lookup");
                        Ok(None)
                    })
                    .await
            })
        };

        started_rx.await.expect("lookup started");
        lookup.invalidate("created-during-lookup").await;
        release_tx.send(()).expect("release stale lookup");
        assert!(lookup_task
            .await
            .expect("lookup task")
            .expect("lookup")
            .is_none());
        assert!(lookup.negative.get("created-during-lookup").await.is_none());
        assert!(lookup
            .singleflight
            .get("created-during-lookup")
            .await
            .is_none());

        // Model the remaining interleaving: invalidation completed after the
        // loader's first check but stale values were inserted afterward.
        handlers
            .insert("created-during-lookup".to_string(), test_handler())
            .await;
        lookup
            .negative
            .insert("created-during-lookup".to_string(), 0)
            .await;
        lookup
            .singleflight
            .insert(
                "created-during-lookup".to_string(),
                VersionedLookupResult {
                    generation: 0,
                    handler: None,
                },
            )
            .await;
        assert!(lookup
            .resolve_with("created-during-lookup", &handlers, async {
                panic!("stale singleflight value should be rejected before loading")
            })
            .await
            .expect("stale cached result")
            .is_none());
        assert!(lookup.negative.get("created-during-lookup").await.is_none());
        assert!(lookup
            .singleflight
            .get("created-during-lookup")
            .await
            .is_none());
        assert!(handlers.get("created-during-lookup").await.is_none());

        let loaded = lookup
            .resolve_with("created-during-lookup", &handlers, async {
                Ok(Some(test_handler()))
            })
            .await
            .expect("post-invalidation lookup");
        assert!(loaded.is_some());
        assert!(handlers.get("created-during-lookup").await.is_some());
    }

    #[tokio::test]
    async fn dependency_failure_is_not_negative_cached() {
        let lookup = AuthorizationLookup::with_config(4, Duration::from_secs(1), 1);
        let handlers: Cache<String, Nip46Handler> = Cache::new(4);
        assert!(lookup
            .resolve_with("dependency-error", &handlers, async {
                Err(SignerError::internal("database unavailable"))
            })
            .await
            .is_err());

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_retry = calls.clone();
        lookup
            .resolve_with("dependency-error", &handlers, async move {
                calls_for_retry.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
            .await
            .expect("retry must run");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod ownership_admission_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn peer_owned_request_is_rejected_before_queue_admission() {
        let before = METRICS
            .nip46_requests_rejected_hashring_prequeue
            .load(Ordering::Relaxed);
        assert!(!admits_owned_request(false, OwnershipStage::Prequeue));
        assert!(
            METRICS
                .nip46_requests_rejected_hashring_prequeue
                .load(Ordering::Relaxed)
                > before
        );
    }

    #[test]
    fn ownership_is_rechecked_after_queueing() {
        assert!(admits_owned_request(true, OwnershipStage::Prequeue));
        let before = METRICS
            .nip46_requests_rejected_hashring_worker
            .load(Ordering::Relaxed);
        assert!(!admits_owned_request(false, OwnershipStage::Worker));
        assert!(
            METRICS
                .nip46_requests_rejected_hashring_worker
                .load(Ordering::Relaxed)
                > before
        );
    }
}

#[cfg(test)]
mod tombstone_cleanup_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    fn cached_handler_expiring_at(expires_at: DateTime<Utc>) -> Nip46Handler {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool construction should not require a live database");

        Nip46Handler::new_for_test(
            Keys::generate(),
            Keys::generate(),
            "test_hash".to_string(),
            1,
            1,
            false,
            pool,
        )
        .with_expires_at(Some(expires_at))
    }

    #[tokio::test]
    async fn cleanup_selects_clock_expired_handler_only_after_twenty_four_hours() {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::hours(24);
        let old_expiry = cached_handler_expiring_at(now - chrono::Duration::hours(25));
        let recent_expiry = cached_handler_expiring_at(now - chrono::Duration::hours(23));

        assert_eq!(old_expiry.tombstone_at, None);
        assert!(old_expiry.tombstone_is_older_than(cutoff));
        assert!(!recent_expiry.tombstone_is_older_than(cutoff));
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;

    /// Helper to create test database connection
    /// Note: Requires DATABASE_URL env var or running postgres at localhost
    /// CI runs migrations automatically, so we just need to connect
    async fn create_test_db() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        PgPool::connect(&database_url).await.unwrap()
    }

    /// Helper to create test keys
    fn create_test_keys() -> Keys {
        Keys::generate()
    }

    /// Helper to create test authorization handler with database records
    async fn create_test_handler_with_db(pool: PgPool) -> Nip46Handler {
        let user_keys = create_test_keys();
        let bunker_keys = create_test_keys();
        let user_pubkey = user_keys.public_key().to_hex();
        let bunker_pubkey = bunker_keys.public_key().to_hex();

        // Ensure tenant exists
        sqlx::query(
            "INSERT INTO tenants (id, domain, name, created_at, updated_at)
             VALUES (1, 'test.example.com', 'Test Tenant', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create user
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())
             ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // Create personal_keys entry (required FK for oauth_authorizations)
        // No ON CONFLICT needed since each test generates unique keys
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
             VALUES ($1, $2, 1)",
        )
        .bind(&user_pubkey)
        .bind(vec![0u8; 32]) // Dummy encrypted key
        .execute(&pool)
        .await
        .unwrap();

        // Create oauth_authorization and get the ID
        // bunker_keys are derived via HKDF at runtime from user_secret + secret_hash
        let auth_id: i32 = sqlx::query_scalar(
            "INSERT INTO oauth_authorizations
             (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, tenant_id, handle_expires_at, created_at, updated_at)
             VALUES ($1, 'http://test.example.com', $2, 'test_hash', '[\"wss://relay.test\"]', 1, NOW() + INTERVAL '30 days', NOW(), NOW())
             RETURNING id"
        )
        .bind(&user_pubkey)
        .bind(&bunker_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

        let (activity_logger, _worker) = RelayActivityLogger::new(pool.clone());

        Nip46Handler {
            bunker_keys,
            user_keys,
            secret_hash: "test_hash".to_string(),
            authorization_id: auth_id,
            tenant_id: 1,
            is_oauth: true,
            pool,
            activity_logger,
            status: HandlerStatus::Active,
            tombstone_at: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn test_sign_event_direct_creates_valid_signature() {
        // Arrange
        let pool = create_test_db().await;
        let handler = create_test_handler_with_db(pool).await;

        let unsigned_event = UnsignedEvent::new(
            handler.user_keys.public_key(),
            Timestamp::now(),
            Kind::from(1),
            vec![],                            // tags first
            "Test message for direct signing", // content last
        );

        // Act
        let signed_event = handler
            .sign_event_direct(unsigned_event)
            .await
            .expect("Signing should succeed");

        // Assert
        assert_eq!(signed_event.kind, Kind::from(1));
        assert_eq!(signed_event.content, "Test message for direct signing");
        assert_eq!(signed_event.pubkey, handler.user_keys.public_key());
        assert!(signed_event.verify().is_ok(), "Signature should be valid");
    }

    #[tokio::test]
    async fn test_sign_event_direct_preserves_tags() {
        // Arrange
        let pool = create_test_db().await;
        let handler = create_test_handler_with_db(pool).await;

        let tag1 = Tag::parse(vec!["e", "event_id_123"]).unwrap();
        let tag2 = Tag::parse(vec!["p", "pubkey_456"]).unwrap();

        let unsigned_event = UnsignedEvent::new(
            handler.user_keys.public_key(),
            Timestamp::now(),
            Kind::from(1),
            vec![tag1.clone(), tag2.clone()], // tags first
            "Test with tags",                 // content last
        );

        // Act
        let signed_event = handler
            .sign_event_direct(unsigned_event)
            .await
            .expect("Signing should succeed");

        // Assert
        assert_eq!(signed_event.tags.len(), 2);
        // Check tags individually since Tags doesn't implement contains()
        let tags_vec: Vec<Tag> = signed_event.tags.iter().cloned().collect();
        assert!(tags_vec.contains(&tag1));
        assert!(tags_vec.contains(&tag2));
    }

    // Regression: ensures the NIP-46 relay path (sign_event_direct) keeps
    // calling canonicalize_event_author. If a future edit removes the call,
    // this test fails because the produced signature would not verify against
    // the (canonicalized) event.pubkey, mirroring the divine-blossom
    // "Invalid signature" failure mode.
    #[tokio::test]
    async fn test_sign_event_direct_canonicalizes_mismatched_pubkey() {
        let pool = create_test_db().await;
        let handler = create_test_handler_with_db(pool).await;

        let stale_keys = Keys::generate();
        assert_ne!(
            stale_keys.public_key(),
            handler.user_keys.public_key(),
            "test setup should pick distinct keys",
        );

        // Client supplied a stale pubkey (different from the signer's keys).
        let unsigned_event = UnsignedEvent::new(
            stale_keys.public_key(),
            Timestamp::now(),
            Kind::from(1),
            vec![],
            "stale-pubkey content",
        );

        let signed_event = handler
            .sign_event_direct(unsigned_event)
            .await
            .expect("sign should succeed after canonicalization");

        assert_eq!(
            signed_event.pubkey,
            handler.user_keys.public_key(),
            "event.pubkey must be canonicalized to the signer keypair",
        );
        signed_event
            .verify()
            .expect("signature must verify after canonicalization");
    }

    #[tokio::test]
    async fn test_get_handler_for_user_returns_none_when_not_cached() {
        // Arrange
        let pool = create_test_db().await;
        let key_manager: Box<dyn KeyManager> =
            Box::new(keycast_core::encryption::file_key_manager::FileKeyManager::new().unwrap());
        let (_tx, rx) = tokio::sync::mpsc::channel(100);
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must be set to run Redis tests");
        let coordinator = Arc::new(ClusterCoordinator::start(&redis_url).await.unwrap());
        let (activity_logger, _worker) = RelayActivityLogger::new(pool.clone());
        let signer = UnifiedSigner::new(pool, key_manager, rx, coordinator, activity_logger)
            .await
            .unwrap();

        let user_pubkey = Keys::generate().public_key().to_hex();

        // Act
        let handler = signer
            .get_handler_for_user(&user_pubkey)
            .await
            .expect("Should not error");

        // Assert
        assert!(
            handler.is_none(),
            "Handler should not exist for non-existent user"
        );
    }

    #[tokio::test]
    async fn test_handlers_clone_shares_cache() {
        // Arrange
        let pool = create_test_db().await;
        let key_manager: Box<dyn KeyManager> =
            Box::new(keycast_core::encryption::file_key_manager::FileKeyManager::new().unwrap());
        let (_tx, rx) = tokio::sync::mpsc::channel(100);
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must be set to run Redis tests");
        let coordinator = Arc::new(ClusterCoordinator::start(&redis_url).await.unwrap());
        let (activity_logger, _worker) = RelayActivityLogger::new(pool.clone());
        let signer = UnifiedSigner::new(
            pool.clone(),
            key_manager,
            rx,
            coordinator,
            activity_logger.clone(),
        )
        .await
        .unwrap();

        // Act - clone handlers (moka Cache uses internal Arc, clones are cheap and share data)
        let handlers1 = signer.handlers.clone();
        let handlers2 = signer.handlers.clone();

        // Insert into one clone
        let test_handler = Nip46Handler {
            bunker_keys: Keys::generate(),
            user_keys: Keys::generate(),
            secret_hash: "test_hash".to_string(),
            authorization_id: 999,
            tenant_id: 1,
            is_oauth: true,
            pool: pool.clone(),
            activity_logger,
            status: HandlerStatus::Active,
            tombstone_at: None,
            expires_at: None,
        };
        handlers1.insert("test_key".to_string(), test_handler).await;

        // Assert - both clones see the same data (shared underlying cache)
        assert!(
            handlers2.get("test_key").await.is_some(),
            "Cloned cache should share underlying data"
        );
    }

    #[tokio::test]
    async fn relay_activity_writer_coalesces_and_persists_counts_on_shutdown() {
        let pool = create_test_db().await;
        let handler = create_test_handler_with_db(pool.clone()).await;
        let (logger, worker) = RelayActivityLogger::new(pool.clone());
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let worker_task = tokio::spawn(worker.run_until_shutdown(shutdown.clone()));

        logger.record(handler.tenant_id, handler.authorization_id as i64);
        logger.record(handler.tenant_id, handler.authorization_id as i64);
        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown.notify_waiters();
        worker_task.await.expect("activity worker");

        let count: i64 = sqlx::query_scalar(
            "SELECT activity_count::bigint FROM oauth_authorizations WHERE id = $1 AND tenant_id = $2",
        )
        .bind(handler.authorization_id)
        .bind(handler.tenant_id)
        .fetch_one(&pool)
        .await
        .expect("activity count");
        assert_eq!(count, 2);
    }
}
