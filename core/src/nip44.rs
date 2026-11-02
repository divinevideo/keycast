// ABOUTME: NIP-44 v2 encryption and decryption behind one bounded entry point, including the
// ABOUTME: six-byte length prefix for plaintext of 65,536 bytes and up that nostr 0.44 cannot handle

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nostr_next::nips::nip44 as next;
use nostr_sdk::{PublicKey, SecretKey};
use thiserror::Error;
use zeroize::Zeroizing;

/// Largest plaintext this service encrypts or decrypts: the bound the Divine
/// app puts on a NIP-17 layer it receives. NIP-44 itself allows `u32::MAX`, but
/// decryption needs several times the payload in memory, and payloads arrive
/// from outside the process.
pub const MAX_PLAINTEXT_LEN: usize = 128 * 1024;

/// Smallest NIP-44 v2 payload: version, nonce, length prefix, the smallest
/// padded message, and the MAC.
const MIN_PAYLOAD_LEN: usize = 1 + 32 + 2 + 32 + 32;
/// Largest NIP-44 v2 payload: version, nonce, the six-byte extended length
/// prefix, the largest padded message, and the MAC. [`MAX_PLAINTEXT_LEN`] is a
/// power of two, so it pads to itself.
const MAX_PAYLOAD_LEN: usize = 1 + 32 + 6 + MAX_PLAINTEXT_LEN + 32;
/// Base64 length of the largest payload.
const MAX_ENCODED_LEN: usize = MAX_PAYLOAD_LEN.div_ceil(3) * 4;

/// Why a NIP-44 operation failed. The display text of the first two matches the
/// wording the 0.44 library used, which callers and tests match on.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Nip44Error {
    #[error("message too long")]
    MessageTooLong,
    #[error("invalid padding")]
    InvalidPadding,
    /// Anything else the library rejects: bad base64, unknown version, a MAC
    /// that does not match, an empty message.
    #[error("{0}")]
    Invalid(String),
}

/// For the callers that still use the 0.44 library on purpose.
impl From<nostr_sdk::nips::nip44::Error> for Nip44Error {
    fn from(error: nostr_sdk::nips::nip44::Error) -> Self {
        use nostr_sdk::nips::nip44::{v2::ErrorV2, Error};
        match error {
            Error::MessageTooLong | Error::V2(ErrorV2::MessageTooLong) => Self::MessageTooLong,
            Error::V2(ErrorV2::InvalidPadding) => Self::InvalidPadding,
            other => Self::Invalid(other.to_string()),
        }
    }
}

fn invalid(error: impl std::fmt::Display) -> Nip44Error {
    Nip44Error::Invalid(error.to_string())
}

/// The 0.44 key types this workspace uses, as the 0.45 types the library
/// needs. The secret's bytes are wiped when the copy goes out of scope.
fn next_keys(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<(nostr_next::key::SecretKey, nostr_next::key::PublicKey), Nip44Error> {
    let secret_bytes = Zeroizing::new(secret_key.to_secret_bytes());
    let secret = nostr_next::key::SecretKey::from_slice(secret_bytes.as_ref()).map_err(invalid)?;
    let public = nostr_next::key::PublicKey::from_slice(&public_key.to_bytes()).map_err(invalid)?;
    Ok((secret, public))
}

/// NIP-44 v2 encryption of at most [`MAX_PLAINTEXT_LEN`] bytes.
///
/// Plaintext of 65,536 bytes and up gets the six-byte length prefix, which a
/// reader on nostr 0.44 cannot decrypt.
pub fn encrypt(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    plaintext: &str,
) -> Result<String, Nip44Error> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(Nip44Error::MessageTooLong);
    }
    let (secret, public) = next_keys(secret_key, public_key)?;
    next::encrypt(&secret, &public, plaintext, next::Version::V2).map_err(invalid)
}

/// NIP-44 v2 decryption for payloads that came from outside the process.
///
/// Payloads outside the size limits are rejected before they reach the
/// library: too short as invalid padding, too long as too long.
pub fn decrypt(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    payload: &str,
) -> Result<String, Nip44Error> {
    if payload.len() > MAX_ENCODED_LEN {
        return Err(Nip44Error::MessageTooLong);
    }
    if let Ok(decoded) = STANDARD.decode(payload) {
        if decoded.len() < MIN_PAYLOAD_LEN {
            return Err(Nip44Error::InvalidPadding);
        }
        if decoded.len() > MAX_PAYLOAD_LEN {
            return Err(Nip44Error::MessageTooLong);
        }
    }
    let (secret, public) = next_keys(secret_key, public_key)?;
    next::decrypt(&secret, &public, payload).map_err(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::nips::nip44 as previous;
    use nostr_sdk::Keys;

    /// The contract, stated independently of [`MAX_PLAINTEXT_LEN`] so that
    /// moving the production constant fails a test: the bound the Divine app
    /// puts on a NIP-17 layer it receives.
    const CEILING: usize = 128 * 1024;

    /// A base64 payload of `len` bytes that starts with the v2 version byte.
    fn payload_of_len(len: usize) -> String {
        let mut bytes = vec![7u8; len];
        bytes[0] = 2;
        STANDARD.encode(bytes)
    }

    /// The most the previous library will encrypt.
    const PREVIOUS_LIBRARY_MAX: usize = 65_536 - 128;

    #[test]
    fn decrypts_payloads_the_previous_library_wrote() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        for len in [1, 5, PREVIOUS_LIBRARY_MAX] {
            let plaintext = "a".repeat(len);
            let payload = previous::encrypt(
                sender.secret_key(),
                &recipient.public_key(),
                &plaintext,
                previous::Version::V2,
            )
            .unwrap();
            assert_eq!(
                decrypt(recipient.secret_key(), &sender.public_key(), &payload).unwrap(),
                plaintext,
                "{len}-byte plaintext"
            );
        }
    }

    #[test]
    fn writes_payloads_the_previous_library_can_read_below_the_extended_prefix() {
        // 65,409 to 65,535 is where this code starts writing what the previous
        // library never could, still with the two-byte prefix it can read.
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        for len in [1, 5, PREVIOUS_LIBRARY_MAX, PREVIOUS_LIBRARY_MAX + 1, 65_535] {
            let plaintext = "a".repeat(len);
            let payload =
                encrypt(sender.secret_key(), &recipient.public_key(), &plaintext).unwrap();
            assert_eq!(
                previous::decrypt(recipient.secret_key(), &sender.public_key(), &payload).unwrap(),
                plaintext,
                "{len}-byte plaintext"
            );
        }
    }

    #[test]
    fn writes_the_extended_prefix_from_65536_bytes_which_the_previous_library_cannot_read() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        for len in [65_536, 70_000] {
            let payload = encrypt(
                sender.secret_key(),
                &recipient.public_key(),
                &"a".repeat(len),
            )
            .unwrap();
            assert!(
                previous::decrypt(recipient.secret_key(), &sender.public_key(), &payload).is_err(),
                "{len}-byte plaintext"
            );
        }
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
                Err(Nip44Error::InvalidPadding),
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
                Err(Nip44Error::MessageTooLong)
            );
        }
    }

    /// Encrypts `len` bytes with nostr 0.45 directly, an implementation
    /// independent of [`encrypt`], then decrypts them through [`decrypt`].
    fn independent_payload_round_trip(len: usize) -> Result<String, Nip44Error> {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let (secret, public) = next_keys(sender.secret_key(), &recipient.public_key()).unwrap();
        let payload = next::encrypt(&secret, &public, "a".repeat(len), next::Version::V2).unwrap();
        decrypt(recipient.secret_key(), &sender.public_key(), &payload)
    }

    #[test]
    fn decrypts_plaintext_that_needs_the_extended_length_prefix() {
        // NIP-44 gives 65,536 bytes and up a six-byte length prefix. 65,535 is
        // the control: the longest plaintext the two-byte prefix can carry.
        for len in [65_535, 65_536, 65_537, 100_000] {
            assert_eq!(
                independent_payload_round_trip(len).unwrap().len(),
                len,
                "{len}-byte plaintext"
            );
        }
    }

    #[test]
    fn decrypts_the_largest_plaintext_the_ceiling_admits() {
        assert_eq!(
            independent_payload_round_trip(CEILING).unwrap().len(),
            CEILING
        );
    }

    #[test]
    fn rejects_plaintext_above_the_ceiling() {
        assert_eq!(
            independent_payload_round_trip(CEILING + 1),
            Err(Nip44Error::MessageTooLong)
        );
    }

    #[test]
    fn encrypts_plaintext_that_needs_the_extended_length_prefix() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let plaintext = "a".repeat(70_000);
        let payload = encrypt(sender.secret_key(), &recipient.public_key(), &plaintext).unwrap();

        // Read back with the independent implementation, not with `decrypt`.
        let (secret, public) = next_keys(recipient.secret_key(), &sender.public_key()).unwrap();
        assert_eq!(
            next::decrypt(&secret, &public, &payload).unwrap(),
            plaintext
        );
    }

    #[test]
    fn encrypts_the_largest_plaintext_the_ceiling_admits() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let plaintext = "a".repeat(CEILING);
        let payload = encrypt(sender.secret_key(), &recipient.public_key(), &plaintext).unwrap();
        assert_eq!(
            decrypt(recipient.secret_key(), &sender.public_key(), &payload).unwrap(),
            plaintext
        );
    }

    #[test]
    fn refuses_to_encrypt_plaintext_above_the_ceiling() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        assert_eq!(
            encrypt(
                sender.secret_key(),
                &recipient.public_key(),
                &"a".repeat(CEILING + 1)
            ),
            Err(Nip44Error::MessageTooLong)
        );
    }

    #[test]
    fn converts_the_previous_librarys_bound_errors() {
        use previous::{v2::ErrorV2, Error};
        assert_eq!(
            Nip44Error::from(Error::V2(ErrorV2::MessageTooLong)),
            Nip44Error::MessageTooLong
        );
        assert_eq!(
            Nip44Error::from(Error::MessageTooLong),
            Nip44Error::MessageTooLong
        );
        assert_eq!(
            Nip44Error::from(Error::V2(ErrorV2::InvalidPadding)),
            Nip44Error::InvalidPadding
        );
        assert_eq!(
            Nip44Error::from(Error::UnknownVersion(9)),
            Nip44Error::Invalid(Error::UnknownVersion(9).to_string())
        );
    }

    #[test]
    fn leaves_other_malformed_payloads_to_the_library() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        for payload in ["", "#abc", "not base64!"] {
            assert!(decrypt(recipient.secret_key(), &sender.public_key(), payload).is_err());
        }
    }
}
