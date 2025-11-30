// ABOUTME: Unified signer daemon that handles multiple NIP-46 bunker connections in a single process
// ABOUTME: Listens for NIP-46 requests and routes them to the appropriate authorization/key

use crate::error::{SignerError, SignerResult};
use async_trait::async_trait;
use keycast_core::authorization_channel::{AuthorizationReceiver, AuthorizationCommand};
use keycast_core::encryption::KeyManager;
use keycast_core::hashring::HashRing;
use keycast_core::signing_handler::{SigningHandler, SignerHandlersCache};
use keycast_core::types::authorization::Authorization;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Default timeout for relay connection operations
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct AuthorizationHandler {
    bunker_keys: Keys,
    pub user_keys: Keys,
    secret: String,
    authorization_id: i32,
    tenant_id: i64,
    is_oauth: bool,
    pool: PgPool,
}

impl AuthorizationHandler {
    /// Constructor for testing only - do not use in production code
    #[doc(hidden)]
    pub fn new_for_test(
        bunker_keys: Keys,
        user_keys: Keys,
        secret: String,
        authorization_id: i32,
        tenant_id: i64,
        is_oauth: bool,
        pool: PgPool,
    ) -> Self {
        Self {
            bunker_keys,
            user_keys,
            secret,
            authorization_id,
            tenant_id,
            is_oauth,
            pool,
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
            let oauth_auth = OAuthAuthorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            oauth_auth.permissions(&self.pool, self.tenant_id).await?
        } else {
            let auth = Authorization::find(&self.pool, self.tenant_id, self.authorization_id).await?;
            auth.permissions(&self.pool, self.tenant_id).await?
        };

        // If no permissions configured, allow all (backward compatibility)
        if permissions.is_empty() {
            return Ok(());
        }

        // Convert and validate - ALL permissions must pass (AND logic)
        for permission in &permissions {
            let custom_permission = permission.to_custom_permission()
                .map_err(|e| SignerError::invalid_permission(format!(
                    "Failed to convert permission '{}': {}",
                    permission.identifier, e
                )))?;

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
        if !self.is_oauth {
            // For regular authorizations, just validate secret
            if provided_secret == self.secret {
                return Ok("ack".to_string());
            } else {
                return Err(SignerError::permission_denied("Invalid secret"));
            }
        }

        // For OAuth authorizations, check if secret exists and if client is already connected
        let bunker_pubkey = self.bunker_keys.public_key().to_hex();

        let existing: Option<(i32, Option<String>)> = sqlx::query_as(
            "SELECT id, connected_client_pubkey FROM oauth_authorizations
             WHERE bunker_public_key = $1 AND secret = $2"
        )
        .bind(&bunker_pubkey)
        .bind(provided_secret)
        .fetch_optional(&self.pool)
        .await?;

        match existing {
            Some((_auth_id, Some(existing_client))) => {
                // Already connected - verify it's the same client
                if existing_client == client_pubkey {
                    tracing::debug!("Same client reconnecting: {}", client_pubkey);
                    Ok("ack".to_string())
                } else {
                    tracing::warn!(
                        "Secret already used by different client. Existing: {}, Attempting: {}",
                        existing_client, client_pubkey
                    );
                    Err(SignerError::permission_denied("Secret already used by another client"))
                }
            }
            Some((auth_id, None)) => {
                // First connect - store client pubkey
                tracing::info!(
                    "First connect for OAuth auth {}, storing client pubkey: {}",
                    auth_id, client_pubkey
                );
                sqlx::query(
                    "UPDATE oauth_authorizations
                     SET connected_client_pubkey = $1, connected_at = NOW()
                     WHERE id = $2"
                )
                .bind(client_pubkey)
                .bind(auth_id)
                .execute(&self.pool)
                .await?;

                Ok("ack".to_string())
            }
            None => {
                tracing::warn!("Invalid secret for bunker {}", bunker_pubkey);
                Err(SignerError::permission_denied("Invalid secret"))
            }
        }
    }

    /// Validate that a client is authorized to make requests.
    ///
    /// Checks if the provided client pubkey matches the stored connected client.
    /// For non-OAuth authorizations, always succeeds.
    ///
    /// # Errors
    ///
    /// Returns error if client pubkey doesn't match the connected client.
    pub async fn validate_client(
        &self,
        client_pubkey: &str,
    ) -> SignerResult<()> {
        if !self.is_oauth {
            // Regular authorizations don't track client pubkey (yet)
            return Ok(());
        }

        let bunker_pubkey = self.bunker_keys.public_key().to_hex();

        // Check if this client is the connected client for any authorization with this bunker pubkey
        let is_valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_authorizations
             WHERE bunker_public_key = $1 AND connected_client_pubkey = $2)"
        )
        .bind(&bunker_pubkey)
        .bind(client_pubkey)
        .fetch_one(&self.pool)
        .await?;

        if is_valid {
            Ok(())
        } else {
            // Check if there's any authorization with NULL connected_client_pubkey
            // If so, this client hasn't connected yet
            let has_unconnected: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM oauth_authorizations
                 WHERE bunker_public_key = $1 AND connected_client_pubkey IS NULL)"
            )
            .bind(&bunker_pubkey)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(false);

            if has_unconnected {
                Err(SignerError::permission_denied("Unknown client - must connect first"))
            } else {
                Err(SignerError::permission_denied("Unknown client - not connected to any authorization"))
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
    pub async fn validate_and_store_client(
        &self,
        client_pubkey: &str,
    ) -> SignerResult<()> {
        if !self.is_oauth {
            return Ok(());
        }

        let bunker_pubkey = self.bunker_keys.public_key().to_hex();

        // Check if this client is already the connected client
        let is_valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_authorizations
             WHERE bunker_public_key = $1 AND connected_client_pubkey = $2)"
        )
        .bind(&bunker_pubkey)
        .bind(client_pubkey)
        .fetch_one(&self.pool)
        .await?;

        if is_valid {
            return Ok(());
        }

        // Check if there's an unconnected authorization we can claim
        let unconnected_id: Option<i32> = sqlx::query_scalar(
            "SELECT id FROM oauth_authorizations
             WHERE bunker_public_key = $1 AND connected_client_pubkey IS NULL
             LIMIT 1"
        )
        .bind(&bunker_pubkey)
        .fetch_optional(&self.pool)
        .await?;

        match unconnected_id {
            Some(auth_id) => {
                // First request without connect - store this client (graceful upgrade)
                tracing::info!(
                    "Storing client pubkey on first request (graceful upgrade) for auth {}: {}",
                    auth_id, client_pubkey
                );
                sqlx::query(
                    "UPDATE oauth_authorizations
                     SET connected_client_pubkey = $1, connected_at = NOW()
                     WHERE id = $2"
                )
                .bind(client_pubkey)
                .bind(auth_id)
                .execute(&self.pool)
                .await?;

                Ok(())
            }
            None => {
                // No unconnected authorization and client not recognized
                Err(SignerError::permission_denied("Unknown client - not connected to any authorization"))
            }
        }
    }
}

/// Default LRU cache capacity for authorization handlers
const DEFAULT_HANDLER_CACHE_SIZE: usize = 10_000;

pub struct UnifiedSigner {
    handlers: Cache<String, AuthorizationHandler>, // bunker_pubkey -> handler (concurrent LRU cache, internal use)
    shared_handlers: SignerHandlersCache,          // Same data as trait objects (shared with API)
    client: Client,
    pool: PgPool,
    key_manager: Arc<Box<dyn KeyManager>>,
    hashring: Arc<Mutex<HashRing>>,
    auth_rx: Option<AuthorizationReceiver>,
}

impl UnifiedSigner {
    /// Create a new UnifiedSigner with the given database pool and key manager.
    pub async fn new(
        pool: PgPool,
        key_manager: Box<dyn KeyManager>,
        auth_rx: AuthorizationReceiver,
        hashring: Arc<Mutex<HashRing>>,
    ) -> SignerResult<Self> {
        let client = Client::default();

        // Get cache size from environment or use default
        let cache_size = std::env::var("HANDLER_CACHE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_HANDLER_CACHE_SIZE);

        let handlers = Cache::builder()
            .max_capacity(cache_size as u64)
            .build();

        // Shared cache for API access (same data as trait objects)
        let shared_handlers: SignerHandlersCache = Cache::builder()
            .max_capacity(cache_size as u64)
            .build();

        tracing::info!("Initialized authorization cache (capacity: {})", cache_size);

        Ok(Self {
            handlers,
            shared_handlers,
            client,
            pool,
            key_manager: Arc::new(key_manager),
            hashring,
            auth_rx: Some(auth_rx),
        })
    }

    pub fn client(&self) -> Client {
        self.client.clone()
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
                self.client.add_relay(relay_url.as_str())
            ).await {
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
    pub fn get_bunker_relays() -> Vec<String> {
        let relays_str = std::env::var("BUNKER_RELAYS")
            .unwrap_or_else(|_| "wss://relay.divine.video,wss://relay.primal.net,wss://relay.nsec.app,wss://nos.lol".to_string());

        relays_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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

        self.client.subscribe(filter, None).await
            .map_err(|e| SignerError::relay(format!("Failed to subscribe: {}", e)))?;

        // Spawn background task to handle authorization commands via channel
        let pool_clone = self.pool.clone();
        let key_manager_clone = self.key_manager.clone();
        let handlers_clone = self.handlers.clone();
        let shared_handlers_clone = self.shared_handlers.clone();

        // Take ownership of the receiver (we only spawn this once)
        if let Some(mut auth_rx) = self.auth_rx.take() {
            tokio::spawn(async move {
                tracing::debug!("Authorization channel listener started");
                while let Some(command) = auth_rx.recv().await {
                    match command {
                        AuthorizationCommand::Upsert { bunker_pubkey, tenant_id, is_oauth } => {
                            tracing::debug!("Received Upsert command for bunker: {}", bunker_pubkey);
                            if let Err(e) = Self::load_single_authorization(
                                &pool_clone,
                                &key_manager_clone,
                                &handlers_clone,
                                &shared_handlers_clone,
                                &bunker_pubkey,
                                tenant_id,
                                is_oauth,
                            ).await {
                                tracing::error!("Error loading authorization {}: {}", bunker_pubkey, e);
                            }
                        }
                        AuthorizationCommand::Remove { bunker_pubkey } => {
                            tracing::debug!("Removing authorization from cache: {}", bunker_pubkey);
                            handlers_clone.invalidate(&bunker_pubkey).await;
                            shared_handlers_clone.invalidate(&bunker_pubkey).await;
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

        // Handle incoming events
        let client = self.client.clone();
        let pool = self.pool.clone();
        let key_manager = self.key_manager.clone();
        let hashring = self.hashring.clone();
        let shared_handlers = self.shared_handlers.clone();
        self.client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect {
                        let handlers_lock = handlers.clone();
                        let shared_handlers_clone = shared_handlers.clone();
                        let client_clone = client.clone();
                        let pool_clone = pool.clone();
                        let key_manager_clone = key_manager.clone();
                        let hashring_clone = hashring.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_nip46_request(
                                handlers_lock,
                                shared_handlers_clone,
                                client_clone,
                                event,
                                &pool_clone,
                                &key_manager_clone,
                                &hashring_clone,
                            ).await {
                                // Filter out expected noise from malformed external requests
                                match &e {
                                    SignerError::MissingParameter("p-tag") => {
                                        tracing::trace!("Ignoring malformed NIP-46 request: {}", e);
                                    }
                                    _ => {
                                        tracing::error!("Error handling NIP-46 request: {}", e);
                                    }
                                }
                            }
                        });
                    }
                }
                Ok(false) // Continue listening
            })
            .await
            .map_err(|e| SignerError::relay(format!("Notification handler failed: {}", e)))?;

        Ok(())
    }

    /// Load a single authorization into both caches (called via channel for new authorizations)
    async fn load_single_authorization(
        pool: &PgPool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        handlers: &Cache<String, AuthorizationHandler>,
        shared_handlers: &SignerHandlersCache,
        bunker_pubkey: &str,
        tenant_id: i64,
        is_oauth: bool,
    ) -> SignerResult<()> {
        if is_oauth {
            // Load OAuth authorization
            let auth: Option<OAuthAuthorization> = sqlx::query_as(
                "SELECT * FROM oauth_authorizations WHERE bunker_public_key = $1 AND tenant_id = $2"
            )
            .bind(bunker_pubkey)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;

            if let Some(auth) = auth {
                // Get user's key from personal_keys (single source of truth)
                let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
                    "SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2"
                )
                .bind(&auth.user_pubkey)
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;

                let decrypted_user_secret = key_manager.decrypt(&encrypted_user_key).await
                    .map_err(|e| SignerError::encryption(e.to_string()))?;
                let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
                    .map_err(|e| SignerError::invalid_key(format!("Invalid user secret key: {}", e)))?;
                let user_keys = Keys::new(user_secret_key.clone());

                // Derive bunker keys using HKDF with connection secret (privacy: bunker_pubkey ≠ user_pubkey)
                let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &auth.secret);

                // Validate derived key matches stored bunker_public_key
                if bunker_keys.public_key().to_hex() != auth.bunker_public_key {
                    tracing::error!(
                        "Derived bunker key mismatch for auth {}: expected {}, got {}",
                        auth.id,
                        auth.bunker_public_key,
                        bunker_keys.public_key().to_hex()
                    );
                    return Err(SignerError::data_corruption(
                        "Derived bunker key mismatch - possible data corruption or migration issue"
                    ));
                }

                let handler = AuthorizationHandler {
                    bunker_keys,
                    user_keys,
                    secret: auth.secret.clone(),
                    authorization_id: auth.id,
                    tenant_id,
                    is_oauth: true,
                    pool: pool.clone(),
                };

                // Insert into both caches (internal + shared for API)
                handlers.insert(bunker_pubkey.to_string(), handler.clone()).await;
                shared_handlers.insert(bunker_pubkey.to_string(), Arc::new(handler) as Arc<dyn SigningHandler>).await;
                tracing::debug!("Cached authorization: {}", bunker_pubkey);
            }
        } else {
            // Load regular authorization
            let auth_data: Option<(i32, Vec<u8>, String, i64)> = sqlx::query_as(
                "SELECT id, bunker_secret, secret, stored_key_id FROM authorizations
                 WHERE tenant_id = $1
                 AND bunker_public_key = (SELECT pubkey FROM stored_keys WHERE pubkey = $2 AND tenant_id = $1)"
            )
            .bind(tenant_id)
            .bind(bunker_pubkey)
            .fetch_optional(pool)
            .await?;

            if let Some((auth_id, bunker_secret, connection_secret, stored_key_id)) = auth_data {
                let decrypted_bunker_secret = key_manager.decrypt(&bunker_secret).await
                    .map_err(|e| SignerError::encryption(e.to_string()))?;
                let bunker_secret_key = SecretKey::from_slice(&decrypted_bunker_secret)
                    .map_err(|e| SignerError::invalid_key(format!("Invalid bunker secret key: {}", e)))?;
                let bunker_keys = Keys::new(bunker_secret_key);

                let stored_key_secret: Vec<u8> = sqlx::query_scalar(
                    "SELECT secret_key FROM stored_keys WHERE id = $1 AND tenant_id = $2"
                )
                .bind(stored_key_id)
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;

                let decrypted_user_secret = key_manager.decrypt(&stored_key_secret).await
                    .map_err(|e| SignerError::encryption(e.to_string()))?;
                let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
                    .map_err(|e| SignerError::invalid_key(format!("Invalid user secret key: {}", e)))?;
                let user_keys = Keys::new(user_secret_key);

                let handler = AuthorizationHandler {
                    bunker_keys,
                    user_keys,
                    secret: connection_secret,
                    authorization_id: auth_id,
                    tenant_id,
                    is_oauth: false,
                    pool: pool.clone(),
                };

                // Insert into both caches (internal + shared for API)
                handlers.insert(bunker_pubkey.to_string(), handler.clone()).await;
                shared_handlers.insert(bunker_pubkey.to_string(), Arc::new(handler) as Arc<dyn SigningHandler>).await;
                tracing::debug!("Cached authorization: {}", bunker_pubkey);
            }
        }

        Ok(())
    }

    async fn handle_nip46_request(
        handlers: Cache<String, AuthorizationHandler>,
        shared_handlers: SignerHandlersCache,
        client: Client,
        event: Box<Event>,
        pool: &PgPool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        hashring: &Arc<Mutex<HashRing>>,
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
        {
            let ring = hashring.lock().await;
            if !ring.should_handle(bunker_pubkey) {
                tracing::trace!(
                    "Hashring: bunker {} assigned to another instance, skipping",
                    bunker_pubkey
                );
                return Ok(());
            }
        }

        tracing::trace!("Received NIP-46 request for bunker: {}", bunker_pubkey);

        // Check if this bunker pubkey is in cache (concurrent LRU)
        let handler = handlers.get(bunker_pubkey).await;

        let handler = match handler {
            Some(h) => h,
            None => {
                // Not in cache - check database (on-demand loading)
                tracing::trace!("Bunker {} not in cache, checking database", bunker_pubkey);

                // Query database for OAuth authorization with this bunker pubkey
                let auth_opt = sqlx::query_as::<_, OAuthAuthorization>(
                    r#"
                    SELECT * FROM oauth_authorizations
                    WHERE bunker_public_key = $1
                    "#
                )
                .bind(bunker_pubkey)
                .fetch_optional(pool)
                .await?;

                match auth_opt {
                    Some(auth) => {
                        // Found in database - load it now
                        tracing::debug!("Loading authorization on-demand: {}", bunker_pubkey);

                        // Get user's key from personal_keys table (single source of truth)
                        let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
                            "SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2"
                        )
                        .bind(&auth.user_pubkey)
                        .bind(auth.tenant_id)
                        .fetch_one(pool)
                        .await?;

                        let decrypted_user_secret = key_manager.decrypt(&encrypted_user_key).await
                            .map_err(|e| SignerError::encryption(e.to_string()))?;
                        let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)
                            .map_err(|e| SignerError::invalid_key(format!("Invalid user key: {}", e)))?;
                        let user_keys = Keys::new(user_secret_key.clone());

                        // Derive bunker keys using HKDF with connection secret (privacy: bunker_pubkey ≠ user_pubkey)
                        let bunker_keys = keycast_core::bunker_key::derive_bunker_keys(&user_secret_key, &auth.secret);

                        // Validate derived key matches stored bunker_public_key
                        if bunker_keys.public_key().to_hex() != auth.bunker_public_key {
                            return Err(SignerError::data_corruption(format!(
                                "Derived bunker key mismatch for auth {} - possible data corruption",
                                auth.id
                            )));
                        }

                        let handler = AuthorizationHandler {
                            bunker_keys,
                            user_keys,
                            secret: auth.secret.clone(),
                            authorization_id: auth.id,
                            tenant_id: auth.tenant_id,
                            is_oauth: true,
                            pool: pool.clone(),
                        };

                        // Cache it for future requests (LRU will evict old entries automatically)
                        // Insert into both caches (internal + shared for API)
                        handlers.insert(bunker_pubkey.to_string(), handler.clone()).await;
                        shared_handlers.insert(bunker_pubkey.to_string(), Arc::new(handler.clone()) as Arc<dyn SigningHandler>).await;

                        handler
                    },
                    None => {
                        // Not in database either - not our bunker
                        tracing::trace!("Bunker {} not found in database, ignoring", bunker_pubkey);
                        return Ok(());
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

        // Try NIP-44 first (new standard), track which method worked
        let (decrypted, use_nip44) = match nip44::decrypt(
            bunker_secret,
            &event.pubkey,
            &event.content,
        ) {
            Ok(d) => {
                tracing::debug!("Successfully decrypted with NIP-44");
                (d, true)
            },
            Err(nip44_err) => {
                tracing::debug!("NIP-44 decrypt failed ({}), trying NIP-04...", nip44_err);
                // Fall back to NIP-04 for backwards compatibility
                match nip04::decrypt(
                    bunker_secret,
                    &event.pubkey,
                    &event.content,
                ) {
                    Ok(d) => {
                        tracing::debug!("Successfully decrypted with NIP-04");
                        (d, false)
                    },
                    Err(nip04_err) => {
                        tracing::error!(
                            "Both NIP-44 and NIP-04 decrypt failed - NIP-44: {}, NIP-04: {} | From: {}",
                            nip44_err,
                            nip04_err,
                            event.pubkey.to_hex()
                        );
                        return Err(nip04_err.into());
                    }
                }
            }
        };

        tracing::debug!("Decrypted NIP-46 request: {}", decrypted);

        // Parse the JSON-RPC request
        let request: serde_json::Value = serde_json::from_str(&decrypted)?;
        let method = request["method"].as_str()
            .ok_or(SignerError::MissingParameter("method"))?;
        let request_id = request["id"].clone(); // Extract request ID for response

        tracing::info!("Processing NIP-46 method: {}", method);

        // For OAuth authorizations, validate client pubkey for sensitive methods
        // Per NIP-46: after connect, client_pubkey becomes the identifier for security
        let client_pubkey = event.pubkey.to_hex();
        let requires_validation = matches!(method, "sign_event" | "nip44_encrypt" | "nip44_decrypt" | "nip04_encrypt" | "nip04_decrypt");

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

                // Encrypt and send error response
                let response_str = response.to_string();
                let encrypted_response = if use_nip44 {
                    nip44::encrypt(
                        bunker_secret,
                        &event.pubkey,
                        &response_str,
                        nip44::Version::V2,
                    )?
                } else {
                    nip04::encrypt(
                        bunker_secret,
                        &event.pubkey,
                        &response_str,
                    )?
                };

                let response_event = EventBuilder::new(
                    Kind::NostrConnect,
                    encrypted_response
                )
                .tags(vec![
                    Tag::public_key(event.pubkey),
                    Tag::parse(vec!["e".to_string(), event.id.to_hex()])?,
                ])
                .sign(&handler.bunker_keys).await?;

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
                    match handler.process_connect(&client_pubkey, provided_secret).await {
                        Ok(result) => serde_json::json!({"id": request_id, "result": result}),
                        Err(e) => serde_json::json!({"id": request_id, "error": e.to_string()})
                    }
                } else {
                    // No secret provided - still track client pubkey for future validation
                    serde_json::json!({"id": request_id, "result": "ack"})
                }
            }
            "nip44_encrypt" => {
                // params: [third_party_pubkey, plaintext]
                let third_party_hex = request["params"][0].as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let plaintext = request["params"][1].as_str()
                    .ok_or(SignerError::MissingParameter("plaintext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;
                let ciphertext = nip44::encrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    plaintext,
                    nip44::Version::V2,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": ciphertext
                })
            }
            "nip44_decrypt" => {
                // params: [third_party_pubkey, ciphertext]
                let third_party_hex = request["params"][0].as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let ciphertext = request["params"][1].as_str()
                    .ok_or(SignerError::MissingParameter("ciphertext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;
                let plaintext = nip44::decrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    ciphertext,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": plaintext
                })
            }
            "nip04_encrypt" => {
                // params: [third_party_pubkey, plaintext]
                let third_party_hex = request["params"][0].as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let plaintext = request["params"][1].as_str()
                    .ok_or(SignerError::MissingParameter("plaintext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;
                let ciphertext = nip04::encrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    plaintext,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": ciphertext
                })
            }
            "nip04_decrypt" => {
                // params: [third_party_pubkey, ciphertext]
                let third_party_hex = request["params"][0].as_str()
                    .ok_or(SignerError::MissingParameter("pubkey"))?;
                let ciphertext = request["params"][1].as_str()
                    .ok_or(SignerError::MissingParameter("ciphertext"))?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)
                    .map_err(|e| SignerError::invalid_key(e.to_string()))?;
                let plaintext = nip04::decrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    ciphertext,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": plaintext
                })
            }
            _ => {
                tracing::warn!("Unsupported NIP-46 method: {}", method);
                serde_json::json!({"id": request_id, "error": format!("Unsupported method: {}", method)})
            }
        };

        // Update activity tracking for all successful methods (not just signing)
        // Check if this was a successful response (has "result" key, not "error")
        if result.get("result").is_some() {
            if let Err(e) = handler.update_activity().await {
                tracing::warn!("Failed to update activity: {}", e);
                // Don't fail the request if activity tracking fails
            }
        }

        let response = result;

        // Encrypt response using the same method as the request
        let response_str = response.to_string();
        let encrypted_response = if use_nip44 {
            tracing::debug!("Encrypting response with NIP-44");
            nip44::encrypt(
                bunker_secret,
                &event.pubkey,
                &response_str,
                nip44::Version::V2,
            )?
        } else {
            tracing::debug!("Encrypting response with NIP-04");
            nip04::encrypt(
                bunker_secret,
                &event.pubkey,
                &response_str,
            )?
        };

        // Build and publish response event
        tracing::debug!("Sending NIP-46 response to {}", event.pubkey);

        let response_event = EventBuilder::new(
            Kind::NostrConnect,
            encrypted_response
        )
        .tags(vec![
            Tag::public_key(event.pubkey),  // Tag the original requester
            Tag::parse(vec!["e".to_string(), event.id.to_hex()])?,  // Reference the request event
        ])
        .sign(&handler.bunker_keys).await?;

        tracing::debug!("Sending response event {} (size: {} bytes)", response_event.id, response_event.content.len());

        let send_result = client.send_event(&response_event).await.map_err(|e| {
            tracing::error!("Failed to send response event: {:?}", e);
            e
        })?;

        tracing::info!("Sent NIP-46 response for request {} (send_result: {:?})", event.id, send_result);

        Ok(())
    }
}

#[async_trait]
impl SigningHandler for AuthorizationHandler {
    async fn sign_event_direct(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<Event, Box<dyn std::error::Error + Send + Sync>> {
        // Extract event details for logging
        let kind = unsigned_event.kind.as_u16();
        let content = unsigned_event.content.clone();

        tracing::info!(
            "Direct signing event kind {} for authorization {}",
            kind,
            self.authorization_id
        );

        // VALIDATE PERMISSIONS BEFORE SIGNING
        self.validate_permissions_for_sign(&unsigned_event).await?;

        // Sign the event with user keys (consumes unsigned_event)
        let signed_event = unsigned_event.sign(&self.user_keys).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        tracing::debug!("Successfully signed event: {}", signed_event.id);

        // Log signing activity to database
        if let Err(e) = self.log_signing_activity(kind, &content, &signed_event.id.to_hex(), "relay").await {
            tracing::error!("Failed to log signing activity: {}", e);
            // Don't fail the signing request if activity logging fails
        }

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

impl AuthorizationHandler {
    async fn handle_sign_event(&self, request: &serde_json::Value) -> SignerResult<serde_json::Value> {
        // Parse the unsigned event from params
        let event_json = request["params"][0].as_str()
            .ok_or(SignerError::MissingParameter("event"))?;
        let unsigned_event: serde_json::Value = serde_json::from_str(event_json)?;

        // Extract fields from unsigned event
        let kind = unsigned_event["kind"].as_u64()
            .ok_or(SignerError::MissingParameter("kind"))? as u16;
        let content = unsigned_event["content"].as_str()
            .ok_or(SignerError::MissingParameter("content"))?;
        let created_at = unsigned_event["created_at"].as_u64()
            .ok_or(SignerError::MissingParameter("created_at"))?;
        let tags_json = unsigned_event["tags"].as_array()
            .ok_or(SignerError::MissingParameter("tags"))?;

        // Parse tags
        let mut tags = Vec::new();
        for tag_arr in tags_json {
            if let Some(arr) = tag_arr.as_array() {
                let tag_strs: Vec<String> = arr.iter()
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

        tracing::debug!("Building event to sign: kind={}, content_len={}, tags_count={}", kind, content.len(), tags.len());

        // Build unsigned event for validation
        let unsigned_event = UnsignedEvent::new(
            self.user_keys.public_key(),
            Timestamp::from(created_at),
            Kind::from(kind),
            tags.clone(),
            content
        );

        // VALIDATE PERMISSIONS BEFORE SIGNING
        self.validate_permissions_for_sign(&unsigned_event).await?;

        // Sign the event with user keys
        let signed_event = EventBuilder::new(
            unsigned_event.kind,
            &unsigned_event.content
        )
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign(&self.user_keys).await.map_err(|e| {
            tracing::error!("Failed to sign event: {:?}", e);
            e
        })?;

        tracing::debug!("Successfully signed event: {}", signed_event.id);

        // Log signing activity to database
        if let Err(e) = self.log_signing_activity(kind, content, &signed_event.id.to_hex(), "relay").await {
            tracing::error!("Failed to log signing activity: {}", e);
            // Don't fail the signing request if activity logging fails
        }

        // Extract request ID to include in response
        let request_id = request["id"].clone();

        Ok(serde_json::json!({
            "id": request_id,
            "result": serde_json::to_string(&signed_event)?
        }))
    }

    async fn log_signing_activity(
        &self,
        event_kind: u16,
        event_content: &str,
        event_id: &str,
        source: &str,
    ) -> SignerResult<()> {
        // Get user public key and application ID
        let (user_pubkey, application_id, client_pubkey, bunker_secret) = if self.is_oauth {
            // For OAuth, look up the oauth_authorization
            let oauth_auth: (String, Option<i64>, Option<String>, String) = sqlx::query_as(
                "SELECT user_pubkey, application_id, client_pubkey, secret
                 FROM oauth_authorizations
                 WHERE tenant_id = $1 AND id = $2"
            )
            .bind(self.tenant_id)
            .bind(self.authorization_id as i64)
            .fetch_one(&self.pool)
            .await?;
            oauth_auth
        } else {
            // For regular authorizations, look up via authorizations table
            let auth: (i64, String) = sqlx::query_as(
                "SELECT stored_key_id, secret FROM authorizations WHERE tenant_id = $1 AND id = $2"
            )
            .bind(self.tenant_id)
            .bind(self.authorization_id as i64)
            .fetch_one(&self.pool)
            .await?;

            let stored_key_id = auth.0;
            let bunker_secret = auth.1;

            // Get public_key from stored_keys
            let stored_key: (String,) = sqlx::query_as(
                "SELECT pubkey FROM stored_keys WHERE tenant_id = $1 AND id = $2"
            )
            .bind(self.tenant_id)
            .bind(stored_key_id)
            .fetch_one(&self.pool)
            .await?;

            (stored_key.0, None, None, bunker_secret)
        };

        // Truncate content for storage (don't store huge amounts of text)
        let truncated_content = if event_content.len() > 500 {
            format!("{}... (truncated)", &event_content[..500])
        } else {
            event_content.to_string()
        };

        // Insert signing activity
        sqlx::query(
            "INSERT INTO signing_activity
             (user_pubkey, application_id, bunker_secret, event_kind, event_content, event_id, client_pubkey, tenant_id, source, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())"
        )
        .bind(&user_pubkey)
        .bind(application_id)
        .bind(&bunker_secret)
        .bind(event_kind as i32)
        .bind(&truncated_content)
        .bind(event_id)
        .bind(&client_pubkey)
        .bind(self.tenant_id)
        .bind(source)
        .execute(&self.pool)
        .await?;

        tracing::debug!("Logged signing activity for tenant {} user {} kind {}", self.tenant_id, user_pubkey, event_kind);

        Ok(())
    }

    /// Update last_activity timestamp and increment activity_count for this authorization
    /// Called on every successful NIP-46 method (connect, get_public_key, sign_event, etc.)
    async fn update_activity(&self) -> SignerResult<()> {
        if self.is_oauth {
            sqlx::query(
                "UPDATE oauth_authorizations
                 SET last_activity = NOW(), activity_count = activity_count + 1
                 WHERE tenant_id = $1 AND id = $2"
            )
            .bind(self.tenant_id)
            .bind(self.authorization_id as i64)
            .execute(&self.pool)
            .await?;

            tracing::debug!(
                "Updated activity for OAuth authorization {} (tenant {})",
                self.authorization_id,
                self.tenant_id
            );
        }
        // For regular authorizations, we could add similar tracking if needed

        Ok(())
    }
}

impl UnifiedSigner {
    /// Get authorization handler for a user's keycast-login session
    /// Returns cached handler if available (fast path), otherwise None
    pub async fn get_handler_for_user(
        &self,
        user_pubkey: &str,
    ) -> SignerResult<Option<AuthorizationHandler>> {
        // Find user's keycast-login OAuth authorization
        let bunker_pubkey: Option<String> = sqlx::query_scalar(
            "SELECT bunker_public_key FROM oauth_authorizations
             WHERE user_pubkey = $1
             AND application_id = (
                 SELECT id FROM oauth_applications WHERE redirect_origin = 'app://keycast-login'
             )
             ORDER BY created_at DESC
             LIMIT 1"
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

    /// Get the shared handlers cache for API access
    /// Returns a clone of the cache Arc (not the data) - changes are immediately visible
    pub fn handlers(&self) -> SignerHandlersCache {
        self.shared_handlers.clone()
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
    async fn create_test_handler_with_db(pool: PgPool) -> AuthorizationHandler {
        let user_keys = create_test_keys();
        let bunker_keys = create_test_keys();
        let user_pubkey = user_keys.public_key().to_hex();
        let bunker_pubkey = bunker_keys.public_key().to_hex();

        // Ensure tenant exists
        sqlx::query(
            "INSERT INTO tenants (id, domain, name, created_at, updated_at)
             VALUES (1, 'test.example.com', 'Test Tenant', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING"
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create user
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())
             ON CONFLICT (pubkey) DO NOTHING"
        )
        .bind(&user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // Create personal_keys entry (required FK for oauth_authorizations)
        // No ON CONFLICT needed since each test generates unique keys
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
             VALUES ($1, $2, 1)"
        )
        .bind(&user_pubkey)
        .bind(vec![0u8; 32]) // Dummy encrypted key
        .execute(&pool)
        .await
        .unwrap();

        // Create oauth_authorization and get the ID
        // Note: bunker_secret is no longer stored (derived via HKDF on demand)
        let auth_id: i32 = sqlx::query_scalar(
            "INSERT INTO oauth_authorizations
             (user_pubkey, redirect_origin, bunker_public_key, secret, relays, tenant_id, created_at, updated_at)
             VALUES ($1, 'http://test.example.com', $2, 'test_secret', '[\"wss://relay.test\"]', 1, NOW(), NOW())
             RETURNING id"
        )
        .bind(&user_pubkey)
        .bind(&bunker_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

        AuthorizationHandler {
            bunker_keys,
            user_keys,
            secret: "test_secret".to_string(),
            authorization_id: auth_id,
            tenant_id: 1,
            is_oauth: true,
            pool,
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
            vec![],  // tags first
            "Test message for direct signing",  // content last
        );

        // Act
        let signed_event = handler.sign_event_direct(unsigned_event)
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
            vec![tag1.clone(), tag2.clone()],  // tags first
            "Test with tags",  // content last
        );

        // Act
        let signed_event = handler.sign_event_direct(unsigned_event)
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
        let key_manager: Box<dyn KeyManager> = Box::new(
            keycast_core::encryption::file_key_manager::FileKeyManager::new().unwrap()
        );
        let (_tx, rx) = tokio::sync::mpsc::channel(100);
        let hashring = Arc::new(Mutex::new(HashRing::new("test-instance".to_string())));
        let signer = UnifiedSigner::new(pool, key_manager, rx, hashring).await.unwrap();

        let user_pubkey = Keys::generate().public_key().to_hex();

        // Act
        let handler = signer.get_handler_for_user(&user_pubkey)
            .await
            .expect("Should not error");

        // Assert
        assert!(handler.is_none(), "Handler should not exist for non-existent user");
    }

    #[tokio::test]
    async fn test_handlers_clone_shares_cache() {
        // Arrange
        let pool = create_test_db().await;
        let key_manager: Box<dyn KeyManager> = Box::new(
            keycast_core::encryption::file_key_manager::FileKeyManager::new().unwrap()
        );
        let (_tx, rx) = tokio::sync::mpsc::channel(100);
        let hashring = Arc::new(Mutex::new(HashRing::new("test-instance".to_string())));
        let signer = UnifiedSigner::new(pool.clone(), key_manager, rx, hashring).await.unwrap();

        // Act - clone handlers (moka Cache uses internal Arc, clones are cheap and share data)
        let handlers1 = signer.handlers.clone();
        let handlers2 = signer.handlers.clone();

        // Insert into one clone
        let test_handler = AuthorizationHandler {
            bunker_keys: Keys::generate(),
            user_keys: Keys::generate(),
            secret: "test".to_string(),
            authorization_id: 999,
            tenant_id: 1,
            is_oauth: true,
            pool: pool.clone(),
        };
        handlers1.insert("test_key".to_string(), test_handler).await;

        // Assert - both clones see the same data (shared underlying cache)
        assert!(
            handlers2.get("test_key").await.is_some(),
            "Cloned cache should share underlying data"
        );
    }
}

