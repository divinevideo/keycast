//! HKDF-based bunker key derivation for NIP-46 privacy
//!
//! Derives unique bunker keys per authorization from user's secret key.
//! This ensures bunker_pubkey ≠ user_pubkey for relay traffic privacy.
//!
//! # Security Properties
//!
//! - Bunker key is cryptographically derived from user's KMS-protected secret
//! - Cannot reverse: knowing bunker_key doesn't reveal user_key
//! - Deterministic: same inputs always produce same output
//! - Per-authorization isolation via connection secret (unique per auth)

use hkdf::Hkdf;
use nostr_sdk::{Keys, SecretKey};
use sha2::Sha256;

/// Domain separator for bunker key derivation (versioned for future changes)
pub const HKDF_INFO_PREFIX: &str = "keycast-bunker-nip46-v1-";

/// Derive a bunker keypair from user's secret key using the connection secret.
///
/// Uses HKDF-SHA256 with:
/// - IKM (input key material): user's 32-byte secret key (KMS-protected)
/// - Info: "{HKDF_INFO_PREFIX}{connection_secret}"
///
/// The connection secret is the NIP-46 secret from the bunker URL, unique per authorization.
/// This approach avoids extra KMS calls (derive vs decrypt) while maintaining same security.
///
/// # Arguments
///
/// * `user_secret` - User's secret key (from KMS-protected storage)
/// * `connection_secret` - The NIP-46 connection secret (unique per authorization)
///
/// # Returns
///
/// A new `Keys` struct containing the derived bunker keypair.
pub fn derive_bunker_keys(user_secret: &SecretKey, connection_secret: &str) -> Keys {
    let hkdf = Hkdf::<Sha256>::new(None, user_secret.as_secret_bytes());

    let info = format!("{}{}", HKDF_INFO_PREFIX, connection_secret);

    // Loop until valid secp256k1 scalar (probability of retry: ~2^-128)
    for counter in 0u32.. {
        let mut bytes = [0u8; 32];
        let derived_info = if counter == 0 {
            info.clone()
        } else {
            format!("{}-retry{}", info, counter)
        };

        hkdf.expand(derived_info.as_bytes(), &mut bytes)
            .expect("32 bytes is valid HKDF-SHA256 output length");

        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Keys::new(secret);
        }
        // Astronomically unlikely to ever loop, but mathematically correct
    }
    unreachable!("HKDF will always produce a valid key within reasonable iterations")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    // =========================================================================
    // Test 1: Derivation is deterministic
    // =========================================================================
    #[test]
    fn test_derivation_deterministic() {
        let user_keys = Keys::generate();
        let secret = "test-connection-secret-abc123";

        let bunker1 = derive_bunker_keys(user_keys.secret_key(), secret);
        let bunker2 = derive_bunker_keys(user_keys.secret_key(), secret);

        assert_eq!(
            bunker1.public_key(),
            bunker2.public_key(),
            "Same inputs should produce same bunker key"
        );
    }

    // =========================================================================
    // Test 2: Different secrets produce different keys
    // =========================================================================
    #[test]
    fn test_different_secrets_different_keys() {
        let user_keys = Keys::generate();

        let bunker1 = derive_bunker_keys(user_keys.secret_key(), "secret-1");
        let bunker2 = derive_bunker_keys(user_keys.secret_key(), "secret-2");

        assert_ne!(
            bunker1.public_key(),
            bunker2.public_key(),
            "Different secrets should produce different bunker keys"
        );
    }

    // =========================================================================
    // Test 3: Bunker key is different from user key (privacy requirement)
    // =========================================================================
    #[test]
    fn test_bunker_key_different_from_user_key() {
        let user_keys = Keys::generate();
        let bunker = derive_bunker_keys(user_keys.secret_key(), "any-secret");

        assert_ne!(
            bunker.public_key(),
            user_keys.public_key(),
            "Bunker pubkey must differ from user pubkey for privacy"
        );
    }

    // =========================================================================
    // Test 4: Different user keys produce different bunker keys
    // =========================================================================
    #[test]
    fn test_different_users_different_bunker_keys() {
        let user1 = Keys::generate();
        let user2 = Keys::generate();
        let same_secret = "shared-secret-for-test";

        let bunker1 = derive_bunker_keys(user1.secret_key(), same_secret);
        let bunker2 = derive_bunker_keys(user2.secret_key(), same_secret);

        assert_ne!(
            bunker1.public_key(),
            bunker2.public_key(),
            "Different users should have different bunker keys even with same secret"
        );
    }

    // =========================================================================
    // Test 5: Real-world secret format works
    // =========================================================================
    #[test]
    fn test_realistic_connection_secret() {
        let user_keys = Keys::generate();
        // Realistic 48-char alphanumeric secret like we generate
        let secret = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6cD7eF8";

        let bunker = derive_bunker_keys(user_keys.secret_key(), secret);

        // Should produce valid keys
        assert_ne!(bunker.public_key(), user_keys.public_key());
        assert_eq!(bunker.public_key().to_hex().len(), 64);
    }

    // =========================================================================
    // Test 6: Empty secret still works (edge case)
    // =========================================================================
    #[test]
    fn test_empty_secret() {
        let user_keys = Keys::generate();

        let bunker_empty = derive_bunker_keys(user_keys.secret_key(), "");
        let bunker_nonempty = derive_bunker_keys(user_keys.secret_key(), "nonempty");

        // Empty should work but produce different key than non-empty
        assert_ne!(bunker_empty.public_key(), bunker_nonempty.public_key());
    }
}
