// ABOUTME: Pure RSA crypto for ActivityPub HTTP Signatures (RSA-SHA256, draft-cavage)
// ABOUTME: Keygen + SPKI public PEM + RSASSA-PKCS1-v1_5/SHA-256 signing. No DB, no Nostr.
// ABOUTME: Private keys are handled as PKCS#8 DER and encrypted at rest by KeyManager.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Forward-compatible discriminator stored in `ap_actor_keys.key_type`.
pub const AP_KEY_TYPE: &str = "rsa-2048";

const RSA_BITS: usize = 2048;

#[derive(Debug, Error)]
pub enum ApSigningError {
    #[error("RSA key generation failed: {0}")]
    KeyGen(String),
    #[error("PKCS#8 encode failed: {0}")]
    Encode(String),
    #[error("PKCS#8 decode failed: {0}")]
    Decode(String),
    #[error("SPKI PEM encode failed: {0}")]
    Pem(String),
    #[error("signing failed: {0}")]
    Sign(String),
}

/// A freshly generated RSA keypair, split into the two persisted halves.
pub struct RsaKeyMaterial {
    /// Private key as PKCS#8 DER. Encrypt with `KeyManager` before storing. Zeroized on drop.
    pub pkcs8_der: Zeroizing<Vec<u8>>,
    /// Public key as SPKI PEM (`-----BEGIN PUBLIC KEY-----`). Safe to store in plaintext.
    pub public_pem: String,
}

/// Generate an RSA-2048 keypair. CPU-bound (~tens of ms) — callers wrap in `spawn_blocking`.
pub fn generate_rsa_2048() -> Result<RsaKeyMaterial, ApSigningError> {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, RSA_BITS)
        .map_err(|e| ApSigningError::KeyGen(e.to_string()))?;
    let der = private
        .to_pkcs8_der()
        .map_err(|e| ApSigningError::Encode(e.to_string()))?;
    let pkcs8_der = der.to_bytes();
    let public_pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ApSigningError::Pem(e.to_string()))?;
    Ok(RsaKeyMaterial {
        pkcs8_der,
        public_pem,
    })
}

/// Re-derive the SPKI public PEM from a decrypted PKCS#8 DER private key.
/// Utility for tests / backfill; the GET path serves the stored column instead.
pub fn public_pem_from_pkcs8_der(pkcs8_der: &[u8]) -> Result<String, ApSigningError> {
    let private = RsaPrivateKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| ApSigningError::Decode(e.to_string()))?;
    RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ApSigningError::Pem(e.to_string()))
}

/// Sign `message` with RSASSA-PKCS1-v1_5 + SHA-256. Returns raw signature bytes.
/// CPU-bound — callers wrap in `spawn_blocking`.
pub fn sign_pkcs1v15_sha256(pkcs8_der: &[u8], message: &[u8]) -> Result<Vec<u8>, ApSigningError> {
    let private = RsaPrivateKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| ApSigningError::Decode(e.to_string()))?;
    let signing_key = SigningKey::<Sha256>::new(private);
    let signature = signing_key
        .try_sign(message)
        .map_err(|e| ApSigningError::Sign(e.to_string()))?;
    Ok(signature.to_vec())
}

/// Convenience: sign and base64-encode (standard alphabet) for the HTTP `signature="…"` field.
pub fn sign_base64(pkcs8_der: &[u8], message: &[u8]) -> Result<String, ApSigningError> {
    Ok(BASE64.encode(sign_pkcs1v15_sha256(pkcs8_der, message)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;

    #[test]
    fn generate_produces_spki_pem_and_parseable_der() {
        let km = generate_rsa_2048().expect("keygen");
        assert!(
            km.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "must be SPKI PEM, not PKCS#1; got: {}",
            &km.public_pem[..km.public_pem.len().min(40)]
        );
        RsaPrivateKey::from_pkcs8_der(&km.pkcs8_der).expect("der parses");
    }

    #[test]
    fn sign_then_verify_with_public_pem() {
        let km = generate_rsa_2048().expect("keygen");
        let msg = b"(request-target): post /inbox\nhost: divine.video\ndate: x";
        let sig_bytes = sign_pkcs1v15_sha256(&km.pkcs8_der, msg).expect("sign");
        let public = RsaPublicKey::from_public_key_pem(&km.public_pem).expect("pem parses");
        let vk = VerifyingKey::<Sha256>::new(public);
        let sig = Signature::try_from(sig_bytes.as_slice()).expect("sig decodes");
        vk.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn public_pem_from_der_matches_generate() {
        let km = generate_rsa_2048().expect("keygen");
        let rederived = public_pem_from_pkcs8_der(&km.pkcs8_der).expect("rederive");
        assert_eq!(km.public_pem, rederived);
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let km1 = generate_rsa_2048().expect("keygen 1");
        let km2 = generate_rsa_2048().expect("keygen 2");
        let msg = b"test";
        let sig_bytes = sign_pkcs1v15_sha256(&km1.pkcs8_der, msg).expect("sign");
        let public2 = RsaPublicKey::from_public_key_pem(&km2.public_pem).expect("pem");
        let vk = VerifyingKey::<Sha256>::new(public2);
        let sig = Signature::try_from(sig_bytes.as_slice()).expect("sig decodes");
        assert!(vk.verify(msg, &sig).is_err(), "wrong key must not verify");
    }

    #[test]
    fn sign_base64_is_decodable_and_verifies() {
        let km = generate_rsa_2048().expect("keygen");
        let msg = b"hello ap";
        let b64 = sign_base64(&km.pkcs8_der, msg).expect("sign b64");
        let raw = BASE64.decode(&b64).expect("base64 decodes");
        let public = RsaPublicKey::from_public_key_pem(&km.public_pem).expect("pem");
        let vk = VerifyingKey::<Sha256>::new(public);
        let sig = Signature::try_from(raw.as_slice()).expect("sig");
        vk.verify(msg, &sig).expect("verify");
    }
}
