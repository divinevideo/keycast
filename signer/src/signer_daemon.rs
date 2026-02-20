// ABOUTME: Unified signer daemon that handles multiple NIP-46 bunker connections in a single process
// ABOUTME: Listens for NIP-46 requests and routes them to the appropriate authorization/key

use crate::error::{SignerError, SignerResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cluster_hashring::ClusterCoordinator;
use keycast_core::authorization_channel::{AuthorizationCommand, AuthorizationReceiver};
use keycast_core::encryption::KeyManager;
use keycast_core::metrics::METRICS;
use keycast_core::signing_handler::SigningHandler;
use keycast_core::types::authorization::Authorization;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// Default timeout for relay connection operations
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Handler status for tombstone support (Active, Revoked, or Expired)
    status: HandlerStatus,
    /// When this handler became a tombstone (for cleanup after 24h)
    tombstone_at: Option<DateTime<Utc>>,
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
        Self {
            bunker_keys,
            user_keys,
            secret_hash,
            authorization_id,
            tenant_id,
            is_oauth,
            pool,
            status: HandlerStatus::Active,
            tombstone_at: None,
        }
    }

    /// Check if this handler is a tombstone (revoked or expired)
    pub fn is_tombstone(&self) -> bool {
        self.status != HandlerStatus::Active
    }

    /// Get the error message for this tombstone status
    pub fn tombstone_error_message(&self) -> Option<&'static str> {
        match self.status {
            HandlerStatus::Active => None,
            HandlerStatus::Revoked => Some("Authorization has been revoked"),
            HandlerStatus::Expired => Some("Authorization has expired"),
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
        } else if let Some(expires_at) = auth.expires_at {
            if expires_at <= Utc::now() {
                (HandlerStatus::Expired, Some(expires_at))
            } else {
                (HandlerStatus::Active, None)
            }
        } else {
            (HandlerStatus::Active, None)
        }
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
}

impl UnifiedSigner {
    /// Create a new UnifiedSigner with the given database pool and key manager.
    pub async fn new(
        pool: PgPool,
        key_manager: Box<dyn KeyManager>,
        auth_rx: AuthorizationReceiver,
        coordinator: Arc<ClusterCoordinator>,
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
                    if let Some(tombstone_at) = handler.tombstone_at {
                        if tombstone_at < cutoff {
                            to_remove.push(key.as_ref().clone());
                        }
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
                                let item = crate::work_queue::Nip46RpcItem {
                                    event,
                                    bunker_pubkey,
                                };
                                if let Err(e) = sender.try_send(item) {
                                    tracing::warn!("Failed to enqueue NIP-46 request: {}", e);
                                }
                            } else {
                                tracing::trace!("Ignoring NIP-46 event without p-tag");
                            }
                        } else {
                            // LEGACY: Direct spawning (for backwards compatibility / testing)
                            let handlers_lock = handlers.clone();
                            let client_clone = client.clone();
                            let pool_clone = pool.clone();
                            let key_manager_clone = key_manager.clone();
                            let coordinator_clone = coordinator.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_nip46_request(
                                    handlers_lock,
                                    client_clone,
                                    event,
                                    &pool_clone,
                                    &key_manager_clone,
                                    &coordinator_clone,
                                )
                                .await
                                {
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
    ) -> SignerResult<()> {
        if is_oauth {
            // Load active OAuth authorization (filter out revoked/expired)
            let auth: Option<OAuthAuthorization> = sqlx::query_as(
                "SELECT * FROM oauth_authorizations
                 WHERE bunker_public_key = $1 AND tenant_id = $2
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW())",
            )
            .bind(bunker_pubkey)
            .bind(tenant_id)
            .fetch_optional(pool)
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

                let handler = Nip46Handler {
                    bunker_keys,
                    user_keys,
                    secret_hash: auth.secret_hash.clone(),
                    authorization_id: auth.id,
                    tenant_id,
                    is_oauth: true,
                    pool: pool.clone(),
                    status: HandlerStatus::Active,
                    tombstone_at: None,
                };

                handlers.insert(bunker_pubkey.to_string(), handler).await;
                tracing::debug!("Cached authorization: {}", bunker_pubkey);
            }
        } else {
            // Load regular authorization
            let auth_data: Option<(i32, String, i64)> = sqlx::query_as(
                "SELECT id, secret_hash, stored_key_id FROM authorizations
                 WHERE tenant_id = $1 AND bunker_public_key = $2",
            )
            .bind(tenant_id)
            .bind(bunker_pubkey)
            .fetch_optional(pool)
            .await?;

            if let Some((auth_id, secret_hash, stored_key_id)) = auth_data {
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

                let handler = Nip46Handler {
                    bunker_keys,
                    user_keys,
                    secret_hash,
                    authorization_id: auth_id,
                    tenant_id,
                    is_oauth: false,
                    pool: pool.clone(),
                    status: HandlerStatus::Active,
                    tombstone_at: None,
                };

                handlers.insert(bunker_pubkey.to_string(), handler).await;
                tracing::debug!("Cached authorization: {}", bunker_pubkey);
            }
        }

        Ok(())
    }

    pub async fn handle_nip46_request(
        handlers: Cache<String, Nip46Handler>,
        client: Client,
        event: Box<Event>,
        pool: &PgPool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        coordinator: &Arc<ClusterCoordinator>,
    ) -> SignerResult<()> {
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
        if !coordinator.should_handle(bunker_pubkey) {
            METRICS.inc_nip46_rejected_hashring();
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
                // Not in cache - check database (on-demand loading)
                tracing::trace!("Bunker {} not in cache, checking database", bunker_pubkey);

                // Query database for OAuth authorization with this bunker pubkey
                // Include revoked/expired to support tombstone error responses
                let auth_opt = sqlx::query_as::<_, OAuthAuthorization>(
                    r#"
                    SELECT * FROM oauth_authorizations
                    WHERE bunker_public_key = $1
                    "#,
                )
                .bind(bunker_pubkey)
                .fetch_optional(pool)
                .await?;

                match auth_opt {
                    Some(auth) => {
                        // Compute status from database fields (revoked/expired/active)
                        let (status, tombstone_at) = Nip46Handler::compute_status_from_oauth(&auth);

                        if status == HandlerStatus::Active {
                            tracing::debug!("Loading authorization on-demand: {}", bunker_pubkey);
                        } else {
                            tracing::debug!(
                                "Loading tombstone authorization on-demand: {} (status: {:?})",
                                bunker_pubkey,
                                status
                            );
                        }

                        // Get user's key from personal_keys table (single source of truth)
                        // Must load this first - needed for HKDF bunker key derivation
                        let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
                            "SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2"
                        )
                        .bind(&auth.user_pubkey)
                        .bind(auth.tenant_id)
                        .fetch_one(pool)
                        .await?;

                        let decrypted_user_secret = key_manager
                            .decrypt(&encrypted_user_key)
                            .await
                            .map_err(|e| SignerError::encryption(e.to_string()))?;
                        let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
                            .map_err(|e| {
                                SignerError::invalid_key(format!("Invalid user key: {}", e))
                            })?;
                        let user_keys = Keys::new(user_secret_key.clone());

                        // Derive bunker keys using HKDF with secret_hash as entropy
                        // This avoids an extra KMS call - user_secret is already decrypted
                        let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(
                            &user_secret_key,
                            &auth.secret_hash,
                        );

                        let handler = Nip46Handler {
                            bunker_keys,
                            user_keys,
                            secret_hash: auth.secret_hash.clone(),
                            authorization_id: auth.id,
                            tenant_id: auth.tenant_id,
                            is_oauth: true,
                            pool: pool.clone(),
                            status,
                            tombstone_at,
                        };

                        // Cache it for future requests (LRU will evict old entries automatically)
                        handlers
                            .insert(bunker_pubkey.to_string(), handler.clone())
                            .await;

                        handler
                    }
                    None => {
                        // Not in oauth_authorizations - check regular authorizations table
                        tracing::trace!(
                            "Bunker {} not in oauth_authorizations, checking authorizations table",
                            bunker_pubkey
                        );

                        // Query regular authorizations table (team bunkers)
                        // Include expired to support tombstone error responses
                        // Note: Team authorizations use hard-delete (no revoked_at), only expires_at
                        #[allow(clippy::type_complexity)]
                        let auth_data: Option<(
                            i32,
                            String,
                            i32,
                            i64,
                            Option<DateTime<Utc>>,
                        )> = sqlx::query_as(
                            r#"SELECT id, secret_hash, stored_key_id, tenant_id, expires_at
                               FROM authorizations
                               WHERE bunker_public_key = $1"#,
                        )
                        .bind(bunker_pubkey)
                        .fetch_optional(pool)
                        .await?;

                        match auth_data {
                            Some((auth_id, secret_hash, stored_key_id, tenant_id, expires_at)) => {
                                // Compute status from expires_at (team auths don't have revoked_at)
                                let (status, tombstone_at) = if let Some(exp) = expires_at {
                                    if exp <= Utc::now() {
                                        (HandlerStatus::Expired, Some(exp))
                                    } else {
                                        (HandlerStatus::Active, None)
                                    }
                                } else {
                                    (HandlerStatus::Active, None)
                                };

                                if status == HandlerStatus::Active {
                                    tracing::debug!(
                                        "Loading team authorization on-demand: {}",
                                        bunker_pubkey
                                    );
                                } else {
                                    tracing::debug!(
                                        "Loading tombstone team authorization on-demand: {} (status: {:?})",
                                        bunker_pubkey,
                                        status
                                    );
                                }

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
                                let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
                                    .map_err(|e| {
                                        SignerError::invalid_key(format!(
                                            "Invalid user secret key: {}",
                                            e
                                        ))
                                    })?;
                                let user_keys = Keys::new(user_secret_key.clone());

                                // Derive bunker keys using HKDF with secret_hash as entropy
                                // This avoids an extra KMS call - user_secret is already decrypted
                                let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(
                                    &user_secret_key,
                                    &secret_hash,
                                );

                                let handler = Nip46Handler {
                                    bunker_keys,
                                    user_keys,
                                    secret_hash,
                                    authorization_id: auth_id,
                                    tenant_id,
                                    is_oauth: false,
                                    pool: pool.clone(),
                                    status,
                                    tombstone_at,
                                };

                                // Cache it for future requests
                                handlers
                                    .insert(bunker_pubkey.to_string(), handler.clone())
                                    .await;

                                handler
                            }
                            None => {
                                // Not in any database table - not our bunker
                                METRICS.inc_nip46_handler_not_found();
                                tracing::trace!(
                                    "Bunker {} not found in any database, ignoring",
                                    bunker_pubkey
                                );
                                return Ok(());
                            }
                        }
                    }
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

        // Handle different NIP-46 methods
        let result = match method {
            "sign_event" => {
                let signed = handler.handle_sign_event(&request).await?;
                // handle_sign_event already returns full response with id
                signed
            }
            "get_public_key" => {
                serde_json::json!({
                    "id": request_id,
                    "result": handler.user_keys.public_key().to_hex()
                })
            }
            "connect" => {
                // Process connect with client pubkey tracking (NIP-46 security)
                // client_pubkey already extracted above from event.pubkey
                if let Some(provided_secret) = request["params"][1].as_str() {
                    match handler
                        .process_connect(&client_pubkey, provided_secret)
                        .await
                    {
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

                // CPU-bound crypto wrapped in spawn_blocking
                let ciphertext = {
                    let secret = handler.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = plaintext.to_string();
                    tokio::task::spawn_blocking(move || {
                        nip44::encrypt(&secret, &pubkey, &text, nip44::Version::V2)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                // Log activity in background (non-blocking)
                handler.spawn_update_activity();

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

                // CPU-bound crypto wrapped in spawn_blocking
                // Returns SecretString for automatic memory zeroization on drop
                let plaintext: SecretString = {
                    let secret = handler.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = ciphertext.to_string();
                    tokio::task::spawn_blocking(move || {
                        nip44::decrypt(&secret, &pubkey, &text).map(SecretString::from)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                // Log activity in background (non-blocking)
                handler.spawn_update_activity();

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

                // CPU-bound crypto wrapped in spawn_blocking
                let ciphertext = {
                    let secret = handler.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = plaintext.to_string();
                    tokio::task::spawn_blocking(move || nip04::encrypt(&secret, &pubkey, &text))
                        .await
                        .map_err(|e| {
                            SignerError::internal(format!("spawn_blocking failed: {}", e))
                        })??
                };

                // Log activity in background (non-blocking)
                handler.spawn_update_activity();

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

                // CPU-bound crypto wrapped in spawn_blocking
                // Returns SecretString for automatic memory zeroization on drop
                let plaintext: SecretString = {
                    let secret = handler.user_keys.secret_key().clone();
                    let pubkey = third_party_pubkey;
                    let text = ciphertext.to_string();
                    tokio::task::spawn_blocking(move || {
                        nip04::decrypt(&secret, &pubkey, &text).map(SecretString::from)
                    })
                    .await
                    .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
                };

                // Log activity in background (non-blocking)
                handler.spawn_update_activity();

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
        };

        let response = result;

        // Encrypt response using the same method as the request (CPU-bound, use spawn_blocking)
        let response_str = response.to_string();
        let encrypted_response = {
            let secret = bunker_secret.clone();
            let pubkey = event.pubkey;
            let text = response_str.clone();
            let use_44 = use_nip44;
            tokio::task::spawn_blocking(move || {
                if use_44 {
                    tracing::debug!("Encrypting response with NIP-44");
                    nip44::encrypt(&secret, &pubkey, &text, nip44::Version::V2)
                        .map_err(SignerError::from)
                } else {
                    tracing::debug!("Encrypting response with NIP-04");
                    nip04::encrypt(&secret, &pubkey, &text).map_err(SignerError::from)
                }
            })
            .await
            .map_err(|e| SignerError::internal(format!("spawn_blocking failed: {}", e)))??
        };

        // Build and publish response event (signing is CPU-bound, use spawn_blocking)
        tracing::debug!("Sending NIP-46 response to {}", event.pubkey);

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
        unsigned_event: UnsignedEvent,
    ) -> Result<Event, Box<dyn std::error::Error + Send + Sync>> {
        let kind = unsigned_event.kind.as_u16();

        tracing::info!(
            "Direct signing event kind {} for authorization {}",
            kind,
            self.authorization_id
        );

        // VALIDATE PERMISSIONS BEFORE SIGNING
        self.validate_permissions_for_sign(&unsigned_event).await?;

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

        // VALIDATE PERMISSIONS BEFORE SIGNING
        self.validate_permissions_for_sign(&unsigned_event).await?;

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

    /// Spawn activity stats update in background (non-blocking)
    fn spawn_update_activity(&self) {
        if !self.is_oauth {
            return;
        }

        let pool = self.pool.clone();
        let tenant_id = self.tenant_id;
        let authorization_id = self.authorization_id as i64;

        tokio::spawn(async move {
            if let Err(e) = sqlx::query(
                "UPDATE oauth_authorizations
                 SET last_activity = NOW(), activity_count = activity_count + 1
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(authorization_id)
            .bind(tenant_id)
            .execute(&pool)
            .await
            {
                tracing::error!("Failed to update oauth_authorizations activity: {}", e);
            }
        });
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

        Nip46Handler {
            bunker_keys,
            user_keys,
            secret_hash: "test_hash".to_string(),
            authorization_id: auth_id,
            tenant_id: 1,
            is_oauth: true,
            pool,
            status: HandlerStatus::Active,
            tombstone_at: None,
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
        let signer = UnifiedSigner::new(pool, key_manager, rx, coordinator)
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
        let signer = UnifiedSigner::new(pool.clone(), key_manager, rx, coordinator)
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
            status: HandlerStatus::Active,
            tombstone_at: None,
        };
        handlers1.insert("test_key".to_string(), test_handler).await;

        // Assert - both clones see the same data (shared underlying cache)
        assert!(
            handlers2.get("test_key").await.is_some(),
            "Cloned cache should share underlying data"
        );
    }
}
