// ABOUTME: Pure crypto signing session wrapping Nostr Keys
// ABOUTME: Provides sign/encrypt/decrypt operations for both HTTP and NIP-46 paths

use nostr_sdk::nips::nip44;
use nostr_sdk::{Event, Keys, PublicKey, UnsignedEvent};
use thiserror::Error;

/// 32-byte key for efficient cache lookups (stack-only, no heap allocation)
pub type CacheKey = [u8; 32];

/// Parse hex string to CacheKey
pub fn parse_cache_key(hex_str: &str) -> Result<CacheKey, SessionError> {
    let bytes = hex::decode(hex_str).map_err(SessionError::HexDecode)?;
    bytes.try_into().map_err(|_| SessionError::InvalidKeyLength)
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid key length (expected 32 bytes)")]
    InvalidKeyLength,
    #[error("hex decode error: {0}")]
    HexDecode(hex::FromHexError),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("encryption error: {0}")]
    Encryption(String),
}

/// Pure crypto signing session wrapping Nostr Keys.
/// Provides sign_event, nip44_encrypt, and nip44_decrypt operations.
///
/// This is a building block used by HttpRpcHandler and Nip46Handler.
/// All authorization metadata (expiration, permissions, cache keys) lives
/// in the handlers, not here.
pub struct SigningSession {
    keys: Keys,
}

impl SigningSession {
    pub fn new(keys: Keys) -> Self {
        Self { keys }
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Sign an unsigned event
    pub async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, SessionError> {
        unsigned
            .sign(&self.keys)
            .await
            .map_err(|e| SessionError::Signing(e.to_string()))
    }

    /// Encrypt plaintext using NIP-44
    pub fn nip44_encrypt(
        &self,
        recipient: &PublicKey,
        plaintext: &str,
    ) -> Result<String, SessionError> {
        nip44::encrypt(
            self.keys.secret_key(),
            recipient,
            plaintext,
            nip44::Version::V2,
        )
        .map_err(|e| SessionError::Encryption(e.to_string()))
    }

    /// Decrypt ciphertext using NIP-44
    pub fn nip44_decrypt(
        &self,
        sender: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, SessionError> {
        nip44::decrypt(self.keys.secret_key(), sender, ciphertext)
            .map_err(|e| SessionError::Encryption(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cache_key_valid() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = parse_cache_key(hex);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_parse_cache_key_invalid_length() {
        let hex = "0123456789abcdef"; // Only 8 bytes
        let result = parse_cache_key(hex);
        assert!(matches!(result, Err(SessionError::InvalidKeyLength)));
    }

    #[test]
    fn test_parse_cache_key_invalid_hex() {
        let hex = "not_valid_hex_string_at_all_definitely_not_valid_hex_string!!";
        let result = parse_cache_key(hex);
        assert!(matches!(result, Err(SessionError::HexDecode(_))));
    }
}
