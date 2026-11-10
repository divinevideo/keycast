//! Hashing for high-entropy, one-time bearer tokens stored in the database.

use sha2::{Digest, Sha256};

/// Return the lowercase SHA-256 digest of a raw bearer token.
///
/// Only use for cryptographically random tokens, never passwords or short PINs.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::hash_token;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(hash_token("abc"), hash_token(&hash_token("abc")));
    }
}
