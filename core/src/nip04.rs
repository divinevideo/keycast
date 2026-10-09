// ABOUTME: NIP-04 decryption for content from clients and relays: content whose IV is not
// ABOUTME: 16 bytes gets the library's ordinary content-format error before decryption runs

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nostr_sdk::nips::nip04;
use nostr_sdk::{PublicKey, SecretKey};

/// Length of the AES-CBC IV that NIP-04 content carries.
const IV_LEN: usize = 16;
/// Base64 length of a 16-byte IV.
const ENCODED_IV_LEN: usize = 24;

/// [`nip04::decrypt`] for content that came from outside the process.
///
/// Content that is not exactly `<ciphertext>?iv=<iv>` with a 16-byte IV is
/// rejected with [`nip04::Error::InvalidContentFormat`] before it reaches the
/// library.
pub fn decrypt(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    content: &str,
) -> Result<String, nip04::Error> {
    let Some((_, iv)) = content.split_once("?iv=") else {
        return Err(nip04::Error::InvalidContentFormat);
    };
    if iv.len() != ENCODED_IV_LEN
        || iv.contains("?iv=")
        || STANDARD.decode(iv).is_ok_and(|iv| iv.len() != IV_LEN)
    {
        return Err(nip04::Error::InvalidContentFormat);
    }
    nip04::decrypt(secret_key, public_key, content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    fn encrypted(sender: &Keys, recipient: &Keys) -> String {
        nip04::encrypt(sender.secret_key(), &recipient.public_key(), "hello").unwrap()
    }

    #[test]
    fn decrypts_well_formed_content() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let content = encrypted(&sender, &recipient);
        assert_eq!(
            decrypt(recipient.secret_key(), &sender.public_key(), &content).unwrap(),
            "hello"
        );
    }

    #[test]
    fn rejects_an_iv_that_is_not_16_bytes() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let content = encrypted(&sender, &recipient);
        let (ciphertext, _) = content.split_once("?iv=").unwrap();
        for len in [0, 1, 15, 17, 18, 32] {
            let malformed = format!("{ciphertext}?iv={}", STANDARD.encode(vec![0u8; len]));
            assert!(
                matches!(
                    decrypt(recipient.secret_key(), &sender.public_key(), &malformed),
                    Err(nip04::Error::InvalidContentFormat)
                ),
                "{len}-byte IV"
            );
        }
    }

    #[test]
    fn rejects_an_iv_of_the_wrong_encoded_length() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let content = encrypted(&sender, &recipient);
        let (ciphertext, iv) = content.split_once("?iv=").unwrap();
        for malformed in [
            format!("{ciphertext}?iv={iv}="),
            format!("{ciphertext}?iv={}", "A".repeat(4096)),
            format!("{ciphertext}?iv={iv}?iv={iv}"),
        ] {
            assert!(
                matches!(
                    decrypt(recipient.secret_key(), &sender.public_key(), &malformed),
                    Err(nip04::Error::InvalidContentFormat)
                ),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn rejects_other_malformed_content() {
        let (sender, recipient) = (Keys::generate(), Keys::generate());
        let content = encrypted(&sender, &recipient);
        let (ciphertext, iv) = content.split_once("?iv=").unwrap();
        for malformed in [
            String::new(),
            ciphertext.to_string(),
            format!("{ciphertext}?iv={iv}?iv={iv}"),
            format!("{ciphertext}?iv=!!!"),
            format!("{}?iv={iv}", STANDARD.encode([0u8; 5])),
        ] {
            assert!(
                decrypt(recipient.secret_key(), &sender.public_key(), &malformed).is_err(),
                "{malformed:?}"
            );
        }
    }
}
