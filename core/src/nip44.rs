// ABOUTME: NIP-44 decryption for payloads from clients and relays: payloads outside the
// ABOUTME: NIP-44 v2 size limits get the library's ordinary errors before decryption runs

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nostr_sdk::nips::nip44::{self, v2::ErrorV2};
use nostr_sdk::{PublicKey, SecretKey};

/// Smallest NIP-44 v2 payload: version, nonce, length prefix, the smallest
/// padded message, and the MAC.
const MIN_PAYLOAD_LEN: usize = 1 + 32 + 2 + 32 + 32;
/// Largest NIP-44 v2 payload, with the largest padded message.
const MAX_PAYLOAD_LEN: usize = 1 + 32 + 2 + 65_536 + 32;
/// Base64 length of the largest payload.
const MAX_ENCODED_LEN: usize = MAX_PAYLOAD_LEN.div_ceil(3) * 4;

/// [`nip44::decrypt`] for payloads that came from outside the process.
///
/// Payloads outside the NIP-44 v2 size limits are rejected before they reach
/// the library: too short as invalid padding, too long as too long.
pub fn decrypt(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    payload: &str,
) -> Result<String, nip44::Error> {
    if payload.len() > MAX_ENCODED_LEN {
        return Err(ErrorV2::MessageTooLong.into());
    }
    if let Ok(decoded) = STANDARD.decode(payload) {
        if decoded.len() < MIN_PAYLOAD_LEN {
            return Err(ErrorV2::InvalidPadding.into());
        }
        if decoded.len() > MAX_PAYLOAD_LEN {
            return Err(ErrorV2::MessageTooLong.into());
        }
    }
    nip44::decrypt(secret_key, public_key, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    /// A base64 payload of `len` bytes that starts with the v2 version byte.
    fn payload_of_len(len: usize) -> String {
        let mut bytes = vec![7u8; len];
        bytes[0] = 2;
        STANDARD.encode(bytes)
    }

    #[test]
    fn decrypts_well_formed_payloads() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let payload = nip44::encrypt(
            sender.secret_key(),
            &recipient.public_key(),
            "hello",
            nip44::Version::V2,
        )
        .unwrap();
        assert_eq!(
            decrypt(recipient.secret_key(), &sender.public_key(), &payload).unwrap(),
            "hello"
        );
    }

    #[test]
    fn rejects_payloads_below_the_minimum_size() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        for len in [1, 65, 66, MIN_PAYLOAD_LEN - 1] {
            assert_eq!(
                decrypt(
                    recipient.secret_key(),
                    &sender.public_key(),
                    &payload_of_len(len)
                ),
                Err(ErrorV2::InvalidPadding.into()),
                "{len}-byte payload"
            );
        }
    }

    #[test]
    fn rejects_payloads_above_the_maximum_size() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        // The second is rejected on its length alone, without decoding it.
        for payload in [
            payload_of_len(MAX_PAYLOAD_LEN + 1),
            "!".repeat(MAX_ENCODED_LEN + 1),
        ] {
            assert_eq!(
                decrypt(recipient.secret_key(), &sender.public_key(), &payload),
                Err(ErrorV2::MessageTooLong.into())
            );
        }
    }

    #[test]
    fn leaves_other_malformed_payloads_to_the_library() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        for payload in ["", "#abc", "not base64!"] {
            assert!(decrypt(recipient.secret_key(), &sender.public_key(), payload).is_err());
        }
    }
}
