use crate::activity_log::ActivityLogger;
use crate::api::tenant::Tenant;
use crate::handlers::http_rpc_handler::HttpHandlerCache;
use crate::redis::PrefixedRedis;
use keycast_core::bcrypt_admission::BcryptAdmission;
use keycast_core::encryption::KeyManager;
use keycast_core::secret_pool::SecretPoolReceiver;
use keycast_core::signing_handler::SignerHandlersCache;
use moka::future::Cache;
use nostr_sdk::Keys;
use once_cell::sync::OnceCell;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Tenant cache: domain -> Tenant (preloaded at startup, rarely changes)
pub type TenantCache = Cache<String, Arc<Tenant>>;

pub const ACCOUNT_STATUS_CACHE_TTL: Duration = Duration::from_secs(5);
const ACCOUNT_STATUS_CACHE_CAPACITY: u64 = 100_000;
pub type AccountStatusCacheKey = (i64, String);

#[derive(Clone, Debug)]
pub enum AccountGateState {
    Present {
        status: String,
        verified_minor: bool,
    },
    Missing,
}

pub type AccountStatusCache = Cache<AccountStatusCacheKey, AccountGateState>;

pub fn new_account_status_cache() -> AccountStatusCache {
    Cache::builder()
        .max_capacity(ACCOUNT_STATUS_CACHE_CAPACITY)
        .time_to_live(ACCOUNT_STATUS_CACHE_TTL)
        .build()
}

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Database not initialized")]
    DatabaseNotInitialized,
    #[error("Key manager not initialized")]
    KeyManagerNotInitialized,
}

pub struct KeycastState {
    pub db: PgPool,
    pub key_manager: Arc<Box<dyn KeyManager>>,
    /// Shared signer handlers cache for unified mode (populated by NIP-46 signer)
    /// Moka cache handles concurrency internally - no Mutex needed
    pub signer_handlers: Option<SignerHandlersCache>,
    /// HTTP RPC handler cache for on-demand loaded handlers (HTTP RPC path)
    /// Keyed by [u8; 32] for both bunker_pubkey and authorization_handle
    /// Caches authorization metadata (expires_at, revoked_at) for spam protection
    pub http_handler_cache: HttpHandlerCache,
    /// Short-lived account restrictions and minor-safety state for warm HTTP RPCs.
    pub account_status_cache: AccountStatusCache,
    /// Server keys for signing UCANs for users without personal keys
    pub server_keys: Keys,
    /// Tenant cache: domain -> Tenant (preloaded at startup for zero-latency lookups)
    pub tenant_cache: TenantCache,
    /// Process-wide bounded admission for every bcrypt operation.
    pub bcrypt: BcryptAdmission,
    /// Redis connection for OAuth polling (multi-device email verification)
    /// Optional to allow graceful degradation if Redis is unavailable
    pub redis: Option<PrefixedRedis>,
    /// Pre-computed secret pool for instant authorization creation
    /// Background producer generates (secret, bcrypt_hash) pairs ahead of time
    pub secret_pool: SecretPoolReceiver,
    /// Bounded writer for OAuth authorization activity updates.
    pub activity_logger: ActivityLogger,
}

pub static KEYCAST_STATE: OnceCell<Arc<KeycastState>> = OnceCell::new();

pub fn get_db_pool() -> Result<&'static PgPool, StateError> {
    KEYCAST_STATE
        .get()
        .map(|state| &state.db)
        .ok_or(StateError::DatabaseNotInitialized)
}

pub fn get_key_manager() -> Result<&'static dyn KeyManager, StateError> {
    KEYCAST_STATE
        .get()
        .map(|state| state.key_manager.as_ref().as_ref())
        .ok_or(StateError::KeyManagerNotInitialized)
}

pub fn get_keycast_state() -> Result<&'static Arc<KeycastState>, StateError> {
    KEYCAST_STATE
        .get()
        .ok_or(StateError::DatabaseNotInitialized)
}

pub fn get_tenant_cache() -> Result<&'static TenantCache, StateError> {
    KEYCAST_STATE
        .get()
        .map(|state| &state.tenant_cache)
        .ok_or(StateError::DatabaseNotInitialized)
}

pub fn get_secret_pool() -> Result<&'static SecretPoolReceiver, StateError> {
    KEYCAST_STATE
        .get()
        .map(|state| &state.secret_pool)
        .ok_or(StateError::DatabaseNotInitialized)
}
