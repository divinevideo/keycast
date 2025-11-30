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
//! - Per-authorization isolation via derivation input

use hkdf::Hkdf;
use nostr_sdk::{Keys, SecretKey};
use sha2::{Digest, Sha256};

/// Domain separator for bunker key derivation (versioned for future changes)
pub const HKDF_INFO_PREFIX: &str = "keycast-bunker-nip46-v1-";

/// Derive a bunker keypair from user's secret key for a specific authorization.
///
/// Uses HKDF-SHA256 with:
/// - IKM (input key material): user's 32-byte secret key
/// - Info: "{HKDF_INFO_PREFIX}{derivation_id}"
///
/// The derivation is deterministic: same inputs always produce same output.
/// Different derivation_id values produce cryptographically independent keys.
///
/// # Arguments
///
/// * `user_secret` - User's secret key (from KMS-protected storage)
/// * `derivation_id` - Unique identifier for this authorization (e.g., hash of user_pubkey + redirect_origin)
///
/// # Returns
///
/// A new `Keys` struct containing the derived bunker keypair.
pub fn derive_bunker_keys(user_secret: &SecretKey, derivation_id: i32) -> Keys {
    let hkdf = Hkdf::<Sha256>::new(None, user_secret.as_secret_bytes());

    let info = format!("{}{}", HKDF_INFO_PREFIX, derivation_id);

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

/// Convert a string to a stable i32 for HKDF derivation.
///
/// Uses first 4 bytes of SHA256 hash to produce a deterministic i32.
/// This allows using string identifiers (like "user_pubkey-redirect_origin")
/// as derivation inputs.
///
/// # Arguments
///
/// * `input` - String to hash (e.g., "{user_pubkey}-{redirect_origin}")
///
/// # Returns
///
/// A stable i32 derived from the input string.
pub fn hash_to_i32(input: &str) -> i32 {
    let hash = Sha256::digest(input.as_bytes());
    i32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
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
        let derivation_id = 42;

        let bunker1 = derive_bunker_keys(user_keys.secret_key(), derivation_id);
        let bunker2 = derive_bunker_keys(user_keys.secret_key(), derivation_id);

        assert_eq!(
            bunker1.public_key(),
            bunker2.public_key(),
            "Same inputs should produce same bunker key"
        );
    }

    // =========================================================================
    // Test 2: Different derivation IDs produce different keys
    // =========================================================================
    #[test]
    fn test_different_derivation_ids_different_keys() {
        let user_keys = Keys::generate();

        let bunker1 = derive_bunker_keys(user_keys.secret_key(), 1);
        let bunker2 = derive_bunker_keys(user_keys.secret_key(), 2);

        assert_ne!(
            bunker1.public_key(),
            bunker2.public_key(),
            "Different derivation IDs should produce different bunker keys"
        );
    }

    // =========================================================================
    // Test 3: Bunker key is different from user key (privacy requirement)
    // =========================================================================
    #[test]
    fn test_bunker_key_different_from_user_key() {
        let user_keys = Keys::generate();
        let bunker = derive_bunker_keys(user_keys.secret_key(), 1);

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
        let same_derivation_id = 100;

        let bunker1 = derive_bunker_keys(user1.secret_key(), same_derivation_id);
        let bunker2 = derive_bunker_keys(user2.secret_key(), same_derivation_id);

        assert_ne!(
            bunker1.public_key(),
            bunker2.public_key(),
            "Different users should have different bunker keys even with same derivation ID"
        );
    }

    // =========================================================================
    // Test 5: hash_to_i32 is deterministic
    // =========================================================================
    #[test]
    fn test_hash_to_i32_deterministic() {
        let input = "abc123def456-https://example.com";

        let hash1 = hash_to_i32(input);
        let hash2 = hash_to_i32(input);

        assert_eq!(hash1, hash2, "Same input should produce same hash");
    }

    // =========================================================================
    // Test 6: hash_to_i32 produces different values for different inputs
    // =========================================================================
    #[test]
    fn test_hash_to_i32_different_inputs() {
        let input1 = "user1-app1";
        let input2 = "user1-app2";
        let input3 = "user2-app1";

        let hash1 = hash_to_i32(input1);
        let hash2 = hash_to_i32(input2);
        let hash3 = hash_to_i32(input3);

        assert_ne!(hash1, hash2, "Different apps should produce different hashes");
        assert_ne!(hash1, hash3, "Different users should produce different hashes");
        assert_ne!(hash2, hash3, "All combinations should differ");
    }

    // =========================================================================
    // Test 7: End-to-end derivation with hash_to_i32
    // =========================================================================
    #[test]
    fn test_end_to_end_derivation() {
        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let redirect_origin = "https://example.com";

        // Simulate the real derivation flow
        let derivation_input = format!("{}-{}", user_pubkey, redirect_origin);
        let derivation_id = hash_to_i32(&derivation_input);
        let bunker_keys = derive_bunker_keys(user_keys.secret_key(), derivation_id);

        // Bunker should be different from user
        assert_ne!(bunker_keys.public_key(), user_keys.public_key());

        // Same derivation should be reproducible
        let derivation_id2 = hash_to_i32(&derivation_input);
        let bunker_keys2 = derive_bunker_keys(user_keys.secret_key(), derivation_id2);
        assert_eq!(bunker_keys.public_key(), bunker_keys2.public_key());
    }

    // =========================================================================
    // Test 8: Negative derivation IDs work correctly
    // =========================================================================
    #[test]
    fn test_negative_derivation_id() {
        let user_keys = Keys::generate();

        // hash_to_i32 can produce negative values
        let bunker_neg = derive_bunker_keys(user_keys.secret_key(), -12345);
        let bunker_pos = derive_bunker_keys(user_keys.secret_key(), 12345);

        // Both should work and produce different keys
        assert_ne!(
            bunker_neg.public_key(),
            bunker_pos.public_key(),
            "Negative and positive IDs should produce different keys"
        );
    }
}
