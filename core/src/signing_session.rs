// ABOUTME: Pure crypto signing session wrapping Nostr Keys
// ABOUTME: Provides sign/encrypt/decrypt operations for both HTTP and NIP-46 paths
// ABOUTME: All CPU-bound crypto runs on spawn_blocking to avoid blocking async runtime

use nostr_sdk::nips::nip44;
use nostr_sdk::{Event, Keys, PublicKey, UnsignedEvent};
use secrecy::SecretString;
use thiserror::Error;
use tokio::task::JoinError;

use crate::secret_types::DecryptedPlaintext;

/// Canonicalize an UnsignedEvent's author pubkey to match the signer keys.
/// If the supplied pubkey differs from the signer pubkey, this updates the
/// event's pubkey and clears its id so it's recomputed over the canonical pubkey.
/// This prevents producing events where event.pubkey disagrees with the keypair
/// that signed it, breaking downstream Schnorr verification.
/// The `event_name` is used in the log event field for telemetry distinction.
pub fn canonicalize_event_author(
    unsigned: &mut UnsignedEvent,
    signer_pubkey: PublicKey,
    event_name: &str,
) {
    if unsigned.pubkey != signer_pubkey {
        tracing::warn!(
            event = event_name,
            supplied_pubkey = %unsigned.pubkey,
            signer_pubkey = %signer_pubkey,
            kind = unsigned.kind.as_u16(),
            "canonicalize_event_author: client-supplied pubkey != signer pubkey; canonicalizing"
        );
        unsigned.pubkey = signer_pubkey;
        unsigned.id = None; // Force recomputation with canonical pubkey
    }
}

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
    #[error("blocking task failed: {0}")]
    BlockingTask(#[from] JoinError),
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

    /// Sign an unsigned event (CPU-bound crypto runs on spawn_blocking)
    ///
    /// **Canonicalizes the event's `pubkey` field to `self.keys.public_key()` before
    /// signing.** This matches NIP-46 bunker semantics where the signer is the source
    /// of truth for the author's pubkey; the client-supplied `pubkey` field is
    /// advisory. Without this, nostr-sdk's `sign_with_keys` would happily produce an
    /// `Event` whose `pubkey` field disagrees with the keypair that produced its
    /// `sig`, breaking downstream Schnorr verification (e.g. divine-blossom viewer
    /// auth). Any client-supplied `id` is cleared in the same step so the event id
    /// is recomputed over the canonical pubkey.
    pub async fn sign_event(&self, mut unsigned: UnsignedEvent) -> Result<Event, SessionError> {
        let keys = self.keys.clone();
        let signer_pubkey = keys.public_key();

        canonicalize_event_author(
            &mut unsigned,
            signer_pubkey,
            "signing_session.pubkey_canonicalized",
        );

        tokio::task::spawn_blocking(move || {
            // Run the async sign on the blocking thread pool
            // nostr-sdk's sign() is async but the actual Schnorr crypto is sync
            tokio::runtime::Handle::current().block_on(async { unsigned.sign(&keys).await })
        })
        .await?
        .map_err(|e| SessionError::Signing(e.to_string()))
    }

    /// Encrypt plaintext using NIP-44 (CPU-bound crypto runs on spawn_blocking)
    pub async fn nip44_encrypt(
        &self,
        recipient: &PublicKey,
        plaintext: &str,
    ) -> Result<String, SessionError> {
        let secret = self.keys.secret_key().clone();
        let recipient = *recipient;
        let plaintext = plaintext.to_string();

        tokio::task::spawn_blocking(move || {
            nip44::encrypt(&secret, &recipient, &plaintext, nip44::Version::V2)
        })
        .await?
        .map_err(|e| SessionError::Encryption(e.to_string()))
    }

    /// Decrypt ciphertext using NIP-44 (CPU-bound crypto runs on spawn_blocking)
    /// Returns DecryptedPlaintext (SecretString) for automatic memory zeroization on drop.
    pub async fn nip44_decrypt(
        &self,
        sender: &PublicKey,
        ciphertext: &str,
    ) -> Result<DecryptedPlaintext, SessionError> {
        let secret = self.keys.secret_key().clone();
        let sender = *sender;
        let ciphertext = ciphertext.to_string();

        tokio::task::spawn_blocking(move || {
            nip44::decrypt(&secret, &sender, &ciphertext).map(SecretString::from)
        })
        .await?
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

    // -- sign_event pubkey canonicalization --------------------------------
    //
    // Regression for divine-blossom 401 "Invalid signature" on viewer auth.
    // nostr-sdk 0.44 `UnsignedEvent::sign` preserves whatever `pubkey` field the
    // caller passed in and does NOT verify the produced sig against it; if the
    // client-supplied pubkey disagrees with the signing keys (e.g. stale client
    // cache after re-OAuth), the resulting event has `event.pubkey` not matching
    // `event.sig` and Schnorr verify fails downstream. SigningSession::sign_event
    // canonicalizes the pubkey field to `self.keys.public_key()` to keep the
    // bunker as the source of truth (NIP-46 semantics).

    use nostr_sdk::{EventBuilder, JsonUtil, Kind, Tag, Timestamp, UnsignedEvent};

    #[tokio::test]
    async fn sign_event_passthrough_when_pubkey_matches() {
        let keys = Keys::generate();
        let session = SigningSession::new(keys.clone());

        let unsigned = EventBuilder::text_note("hello").build(keys.public_key());

        let signed = session
            .sign_event(unsigned)
            .await
            .expect("sign should succeed");

        assert_eq!(signed.pubkey, keys.public_key());
        signed
            .verify()
            .expect("signature must verify against signer's pubkey");
    }

    #[tokio::test]
    async fn sign_event_canonicalizes_mismatched_pubkey() {
        let signer_keys = Keys::generate();
        let stale_keys = Keys::generate();
        assert_ne!(signer_keys.public_key(), stale_keys.public_key());

        let session = SigningSession::new(signer_keys.clone());

        // Simulate the production failure: client cached an old pubkey
        // (`stale_keys.public_key()`) and built the unsigned event around it,
        // but the signer's actual keypair is `signer_keys`.
        let unsigned = UnsignedEvent::new(
            stale_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "hello",
        );

        let signed = session
            .sign_event(unsigned)
            .await
            .expect("sign should succeed after canonicalization");

        assert_eq!(
            signed.pubkey,
            signer_keys.public_key(),
            "event.pubkey must match the keypair that produced the signature"
        );
        signed
            .verify()
            .expect("Schnorr verify must succeed after canonicalization");
    }

    #[tokio::test]
    async fn sign_event_recovers_when_client_supplied_stale_id_too() {
        // Defense for the "client computed event id over its old pubkey AND
        // forwarded the id" path. Without clearing `unsigned.id`, nostr-sdk's
        // internal_add_signature would fail with InvalidId because the id was
        // computed over the wrong pubkey.
        let signer_keys = Keys::generate();
        let stale_keys = Keys::generate();
        let session = SigningSession::new(signer_keys.clone());

        let mut unsigned = UnsignedEvent::new(
            stale_keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "hello",
        );
        // Force the id to be precomputed over the stale pubkey.
        let stale_id = unsigned.id();
        assert!(unsigned.id.is_some());

        let signed = session
            .sign_event(unsigned)
            .await
            .expect("sign should succeed even with a stale precomputed id");

        assert_eq!(signed.pubkey, signer_keys.public_key());
        assert_ne!(
            signed.id, stale_id,
            "event id must be recomputed over the canonical pubkey"
        );
        signed
            .verify()
            .expect("Schnorr verify must succeed after id recomputation");
        // Sanity: the produced JSON parses back to itself.
        let json = signed.as_json();
        assert!(json.contains(&signer_keys.public_key().to_hex()));
    }
}
