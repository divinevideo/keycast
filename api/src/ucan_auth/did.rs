// ABOUTME: DID:key utilities for converting Nostr pubkeys to/from DID format for UCAN

use anyhow::{anyhow, Result};
use nostr_sdk::PublicKey;

/// Convert Nostr public key to DID:key format
///
/// Format: `did:key:z<multibase-multicodec-pubkey>`
///
/// Uses secp256k1 multicodec: `0xe7 0x01`
pub fn nostr_pubkey_to_did(pubkey: &PublicKey) -> String {
    const SECP256K1_MULTICODEC: &[u8] = &[0xe7, 0x01];

    let pubkey_bytes = pubkey.to_bytes();

    let mut did_bytes = Vec::with_capacity(SECP256K1_MULTICODEC.len() + pubkey_bytes.len());
    did_bytes.extend_from_slice(SECP256K1_MULTICODEC);
    did_bytes.extend_from_slice(&pubkey_bytes);

    format!("did:key:z{}", bs58::encode(&did_bytes).into_string())
}

/// Parse DID:key back to Nostr public key
pub fn did_to_nostr_pubkey(did: &str) -> Result<PublicKey> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| anyhow!("Invalid DID format"))?;

    let decoded = bs58::decode(encoded).into_vec()?;

    if !decoded.starts_with(&[0xe7, 0x01]) {
        return Err(anyhow!("Not a secp256k1 key"));
    }

    let pubkey_bytes = &decoded[2..];

    PublicKey::from_slice(pubkey_bytes).map_err(|e| anyhow!("Invalid public key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    #[test]
    fn test_nostr_did_roundtrip() {
        let keys = Keys::generate();
        let original_pubkey = keys.public_key();

        let did = nostr_pubkey_to_did(&original_pubkey);
        assert!(did.starts_with("did:key:z"));

        let recovered_pubkey = did_to_nostr_pubkey(&did).unwrap();
        assert_eq!(original_pubkey, recovered_pubkey);
    }
}
