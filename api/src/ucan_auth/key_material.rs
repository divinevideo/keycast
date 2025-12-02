// ABOUTME: UCAN KeyMaterial implementation for Nostr secp256k1 keys

use anyhow::Result;
use async_trait::async_trait;
use nostr_sdk::{Keys, SecretKey};
use ucan::crypto::KeyMaterial;

use super::did::nostr_pubkey_to_did;

/// UCAN KeyMaterial implementation for Nostr secp256k1 keys
///
/// Note: UCAN uses ECDSA signatures (for JWT compatibility), not Schnorr
pub struct NostrKeyMaterial {
    keys: Keys,
}

impl NostrKeyMaterial {
    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }

    pub fn from_secret_key(sk: SecretKey) -> Self {
        let keys = Keys::new(sk);
        Self { keys }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl KeyMaterial for NostrKeyMaterial {
    fn get_jwt_algorithm_name(&self) -> String {
        "ES256K".to_string() // secp256k1 ECDSA
    }

    async fn get_did(&self) -> Result<String> {
        Ok(nostr_pubkey_to_did(&self.keys.public_key()))
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        use secp256k1::{Message, Secp256k1, SecretKey as Secp256k1SecretKey};
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::signing_only();

        // Hash the payload (ECDSA signs message hash)
        let hash = Sha256::digest(payload);
        let message = Message::from_digest_slice(&hash)?;

        // Get secret key - nostr SecretKey wraps secp256k1 SecretKey
        let nostr_sk = self.keys.secret_key();

        // Convert to secp256k1::SecretKey (Secp256k1SecretKey already imported above)
        let secret_key = Secp256k1SecretKey::from_slice(nostr_sk.as_ref())?;

        // Sign with ECDSA (not Schnorr!)
        let sig = secp.sign_ecdsa(&message, &secret_key);

        Ok(sig.serialize_compact().to_vec())
    }

    async fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        use secp256k1::{ecdsa::Signature, Message, Secp256k1};
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::verification_only();

        let hash = Sha256::digest(payload);
        let message = Message::from_digest_slice(&hash)?;

        let sig = Signature::from_compact(signature)?;

        let pubkey_bytes = self.keys.public_key().to_bytes();
        let public_key = secp256k1::PublicKey::from_slice(&pubkey_bytes)?;

        secp.verify_ecdsa(&message, &sig, &public_key)?;

        Ok(())
    }
}
