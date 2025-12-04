//! UCAN KeyMaterial implementation for Nostr secp256k1 keys using Schnorr signatures.
//!
//! Keycast UCANs use Schnorr signatures (BIP-340) over secp256k1,
//! identified by alg: "SchnorrSecp256k1". This differs from standard
//! UCAN's ES256K (ECDSA) to align with Nostr's native signature scheme.
//! These UCANs are not compatible with generic UCAN validators.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nostr_sdk::{Keys, SecretKey};
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use ucan::crypto::KeyMaterial;

use super::did::nostr_pubkey_to_did;

/// UCAN KeyMaterial implementation for Nostr secp256k1 keys.
/// Uses Schnorr BIP-340 signatures (Nostr native).
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
        "SchnorrSecp256k1".to_string()
    }

    async fn get_did(&self) -> Result<String> {
        Ok(nostr_pubkey_to_did(&self.keys.public_key()))
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let secp = Secp256k1::new();

        // Hash the payload (Schnorr signs message hash)
        let hash = Sha256::digest(payload);
        let message = Message::from_digest_slice(&hash)?;

        // Get secret key bytes
        let nostr_sk = self.keys.secret_key();
        let secret_key = secp256k1::SecretKey::from_slice(nostr_sk.as_ref())?;

        // Create Keypair for Schnorr signing
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        // Sign with Schnorr (BIP-340) - deterministic signing
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        // Schnorr signatures are 64 bytes
        Ok(sig.serialize().to_vec())
    }

    async fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let secp = Secp256k1::verification_only();

        let hash = Sha256::digest(payload);
        let message = Message::from_digest_slice(&hash)?;

        let sig = secp256k1::schnorr::Signature::from_slice(signature)
            .map_err(|e| anyhow!("Invalid Schnorr signature: {}", e))?;

        // Nostr public keys are x-only (32 bytes)
        let pubkey_bytes = self.keys.public_key().to_bytes();
        let xonly_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| anyhow!("Invalid x-only public key: {}", e))?;

        secp.verify_schnorr(&sig, &message, &xonly_pubkey)
            .map_err(|e| anyhow!("Schnorr signature verification failed: {}", e))?;

        Ok(())
    }
}

/// Verify-only KeyMaterial for signature verification from public key bytes.
/// Used by DidParser when verifying incoming UCANs (no private key available).
pub struct NostrVerifyKeyMaterial {
    xonly_pubkey: XOnlyPublicKey,
}

impl NostrVerifyKeyMaterial {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let xonly_pubkey = XOnlyPublicKey::from_slice(bytes)
            .map_err(|e| anyhow!("Invalid public key bytes: {}", e))?;
        Ok(Self { xonly_pubkey })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl KeyMaterial for NostrVerifyKeyMaterial {
    fn get_jwt_algorithm_name(&self) -> String {
        "SchnorrSecp256k1".to_string()
    }

    async fn get_did(&self) -> Result<String> {
        let pk = nostr_sdk::PublicKey::from_slice(&self.xonly_pubkey.serialize())
            .map_err(|e| anyhow!("Failed to convert to nostr PublicKey: {}", e))?;
        Ok(nostr_pubkey_to_did(&pk))
    }

    async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(
            "NostrVerifyKeyMaterial cannot sign - no private key available"
        ))
    }

    async fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let secp = Secp256k1::verification_only();

        let hash = Sha256::digest(payload);
        let message = Message::from_digest_slice(&hash)?;

        let sig = secp256k1::schnorr::Signature::from_slice(signature)
            .map_err(|e| anyhow!("Invalid Schnorr signature: {}", e))?;

        secp.verify_schnorr(&sig, &message, &self.xonly_pubkey)
            .map_err(|e| anyhow!("Schnorr signature verification failed: {}", e))?;

        Ok(())
    }
}
