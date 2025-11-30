use keycast_core::encryption::KeyManager;
use keycast_core::signing_handler::SignerHandlersCache;
use nostr_sdk::Keys;
use once_cell::sync::OnceCell;
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

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
    /// Shared signer handlers cache for unified mode (live, not a snapshot)
    /// Moka cache handles concurrency internally - no Mutex needed
    pub signer_handlers: Option<SignerHandlersCache>,
    /// Server keys for signing UCANs for users without personal keys
    pub server_keys: Keys,
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
