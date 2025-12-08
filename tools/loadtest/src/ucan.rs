use anyhow::Result;
use async_trait::async_trait;
use nostr_sdk::Keys;
use secp256k1::{Keypair, Message, Secp256k1};
use sha2::{Digest, Sha256};
use ucan::builder::UcanBuilder;
use ucan::crypto::KeyMaterial;

const TOKEN_EXPIRY_HOURS: u64 = 24;

/// Key material for UCAN signing using Nostr keys
pub struct NostrKeyMaterial {
    keys: Keys,
}

impl NostrKeyMaterial {
    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl KeyMaterial for NostrKeyMaterial {
    fn get_jwt_algorithm_name(&self) -> String {
        "SchnorrSecp256k1".to_string()
    }

    async fn get_did(&self) -> anyhow::Result<String> {
        Ok(nostr_pubkey_to_did(&self.keys.public_key()))
    }

    async fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let secp = Secp256k1::new();
        let hash = Sha256::digest(payload);
        let message = Message::from_digest_slice(&hash)?;
        let secret_key = secp256k1::SecretKey::from_slice(self.keys.secret_key().as_ref())?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(sig.serialize().to_vec())
    }

    async fn verify(&self, _payload: &[u8], _signature: &[u8]) -> anyhow::Result<()> {
        // Verification not needed for token generation
        unimplemented!("Verification not needed for load testing")
    }
}

/// Convert Nostr public key to DID format
pub fn nostr_pubkey_to_did(pubkey: &nostr_sdk::PublicKey) -> String {
    let bytes = pubkey.to_bytes();
    let mut key_bytes = vec![0xe7, 0x01]; // secp256k1 multicodec prefix
    key_bytes.extend_from_slice(&bytes);
    format!("did:key:z{}", bs58::encode(&key_bytes).into_string())
}

/// Generate a UCAN token for load testing
/// NOTE: bunker_pubkey is required for HTTP RPC access. Session UCANs without
/// bunker_pubkey are rejected by the HTTP RPC endpoint.
pub async fn generate_ucan_token(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
    bunker_pubkey: &str,
) -> Result<String> {
    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());

    let facts = serde_json::json!({
        "tenant_id": tenant_id,
        "email": email,
        "redirect_origin": redirect_origin,
        "bunker_pubkey": bunker_pubkey,
    });

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(TOKEN_EXPIRY_HOURS * 3600)
        .with_fact(facts)
        .build()?
        .sign()
        .await?;

    ucan.encode()
}
