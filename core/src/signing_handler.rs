// ABOUTME: Trait for signing handlers that can be shared between API and Signer crates
// ABOUTME: Allows API to use cached signer handlers without direct dependency on signer crate

use async_trait::async_trait;
use nostr_sdk::{Keys, UnsignedEvent};
use std::error::Error;

/// Trait for handlers that can sign Nostr events
/// Implemented by AuthorizationHandler in the signer crate
#[async_trait]
pub trait SigningHandler: Send + Sync {
    /// Sign an event directly without NIP-46 encryption overhead
    /// Returns the signed event
    async fn sign_event_direct(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<nostr_sdk::Event, Box<dyn Error + Send + Sync>>;

    /// Get the authorization ID for this handler
    fn authorization_id(&self) -> i64;

    /// Get the user public key for this handler
    fn user_public_key(&self) -> String;

    /// Get the user's signing keys for RPC operations
    /// Used by the REST RPC API for encryption/decryption
    fn get_keys(&self) -> Keys;
}
