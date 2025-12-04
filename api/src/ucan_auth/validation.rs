// ABOUTME: UCAN token validation and pubkey extraction with Schnorr signature verification

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use once_cell::sync::Lazy;
use std::env;
use ucan::crypto::did::{DidParser, SECP256K1_MAGIC_BYTES};
use ucan::crypto::KeyMaterial;
use ucan::Ucan;

use super::did::did_to_nostr_pubkey;
use super::key_material::NostrVerifyKeyMaterial;

/// Server public key for validating server-signed UCANs
/// Loaded from SERVER_NSEC environment variable
static SERVER_PUBKEY: Lazy<String> = Lazy::new(|| {
    env::var("SERVER_NSEC")
        .ok()
        .and_then(|nsec| nostr_sdk::Keys::parse(&nsec).ok())
        .map(|k| k.public_key().to_hex())
        .expect("SERVER_NSEC must be set and valid")
});

/// Create a DidParser configured for Nostr secp256k1 keys with Schnorr verification
fn create_nostr_did_parser() -> DidParser {
    DidParser::new(&[(
        SECP256K1_MAGIC_BYTES,
        nostr_key_constructor as fn(Vec<u8>) -> anyhow::Result<Box<dyn KeyMaterial>>,
    )])
}

/// Constructor function for DidParser - creates a verify-only KeyMaterial from public key bytes
fn nostr_key_constructor(key_bytes: Vec<u8>) -> anyhow::Result<Box<dyn KeyMaterial>> {
    Ok(Box::new(NostrVerifyKeyMaterial::from_bytes(&key_bytes)?))
}

/// Validate UCAN token from Authorization header with cryptographic signature verification.
///
/// Returns: (user_pubkey_hex, redirect_origin, bunker_pubkey, ucan)
/// redirect_origin identifies which app/authorization this token is for
/// bunker_pubkey uniquely identifies the authorization for direct cache lookup (optional)
pub async fn validate_ucan_token(
    auth_header: &str,
    expected_tenant_id: i64,
) -> Result<(String, String, Option<String>, Ucan)> {
    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow!("Invalid Authorization header format"))?;

    // Decode UCAN from token string (does not verify signature)
    let ucan = Ucan::try_from_token_string(token)?;

    // Verify signature cryptographically using Schnorr (BIP-340)
    let mut did_parser = create_nostr_did_parser();
    ucan.check_signature(&mut did_parser)
        .await
        .map_err(|e| anyhow!("UCAN signature verification failed: {}", e))?;

    tracing::debug!("UCAN Schnorr signature verified for issuer: {}", ucan.issuer());

    // Validate expiry
    if ucan.is_expired() {
        return Err(anyhow!("Token expired"));
    }

    let facts: &Vec<serde_json::Value> = ucan.facts();

    // Extract redirect_origin from facts (required)
    let redirect_origin = facts
        .iter()
        .find_map(|fact| fact.get("redirect_origin").and_then(|v| v.as_str()))
        .map(String::from)
        .ok_or_else(|| anyhow!("UCAN missing required redirect_origin fact"))?;

    // Extract bunker_pubkey from facts (optional - for direct cache lookup)
    let bunker_pubkey = facts
        .iter()
        .find_map(|fact| fact.get("bunker_pubkey").and_then(|v| v.as_str()))
        .map(String::from);

    // Validate tenant_id from facts (if expected_tenant_id != 0)
    if expected_tenant_id != 0 {
        // Look for tenant_id in facts array
        let mut found_tenant = false;
        for fact in facts {
            if let Some(tenant_value) = fact.get("tenant_id") {
                if let Some(tenant_int) = tenant_value.as_i64() {
                    if tenant_int != expected_tenant_id {
                        return Err(anyhow!("Tenant mismatch"));
                    }
                    found_tenant = true;
                    break;
                }
            }
        }

        if !found_tenant && expected_tenant_id != 0 {
            tracing::warn!("UCAN missing tenant_id fact, but tenant validation required");
            // Allow for now - tenant validation will happen at DB query level
        }
    }

    // Extract user pubkey from audience DID (works for both user-signed and server-signed)
    let user_pubkey = did_to_nostr_pubkey(ucan.audience())?;

    // Verify issuer is either the user (self-issued) or server (delegated)
    let issuer_pubkey = did_to_nostr_pubkey(ucan.issuer())?;
    let issuer_pubkey_hex = issuer_pubkey.to_hex();
    let user_pubkey_hex = user_pubkey.to_hex();

    if issuer_pubkey_hex != user_pubkey_hex && issuer_pubkey_hex != *SERVER_PUBKEY {
        return Err(anyhow!(
            "Invalid UCAN issuer: must be signed by user ({}) or server ({}), got {}",
            &user_pubkey_hex[..8],
            &SERVER_PUBKEY[..8],
            &issuer_pubkey_hex[..8]
        ));
    }

    Ok((user_pubkey_hex, redirect_origin, bunker_pubkey, ucan))
}

/// Extract user pubkey, redirect_origin, and bunker_pubkey from UCAN in Authorization header
pub async fn extract_user_from_ucan(
    headers: &HeaderMap,
    expected_tenant_id: i64,
) -> Result<(String, String, Option<String>)> {
    let auth_header = headers
        .get("Authorization")
        .ok_or_else(|| anyhow!("Missing Authorization header"))?
        .to_str()
        .map_err(|_| anyhow!("Invalid Authorization header"))?;

    let (pubkey, redirect_origin, bunker_pubkey, _ucan) =
        validate_ucan_token(auth_header, expected_tenant_id).await?;

    Ok((pubkey, redirect_origin, bunker_pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use crate::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use nostr_sdk::Keys;
    use ucan::builder::UcanBuilder;

    #[tokio::test]
    async fn test_ucan_generation_and_validation() {
        // Generate test keys
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);

        // Create key material
        let key_material = NostrKeyMaterial::from_keys(keys.clone());

        // Build UCAN with required facts including redirect_origin
        let facts = serde_json::json!({
            "tenant_id": 1,
            "email": "test@example.com",
            "redirect_origin": "https://test.example.com"
        });

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_lifetime(3600)
            .with_fact(facts)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = ucan.encode().unwrap();

        // Validate the token (now with signature verification!)
        let auth_header = format!("Bearer {}", token);
        let (extracted_pubkey, redirect_origin, bunker_pubkey, _) =
            validate_ucan_token(&auth_header, 1).await.unwrap();

        assert_eq!(extracted_pubkey, pubkey.to_hex());
        assert_eq!(redirect_origin, "https://test.example.com");
        assert!(bunker_pubkey.is_none()); // No bunker_pubkey in test facts
    }

    #[tokio::test]
    async fn test_ucan_expired_token() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);
        let key_material = NostrKeyMaterial::from_keys(keys);

        // Create token that expired 1 hour ago (set expiration in the past)
        use ucan::time::now;
        let expired_time = now() - 3600; // 1 hour ago

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_expiration(expired_time)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = ucan.encode().unwrap();
        let auth_header = format!("Bearer {}", token);
        let result = validate_ucan_token(&auth_header, 0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_ucan_tenant_validation() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);
        let key_material = NostrKeyMaterial::from_keys(keys);

        // Create token with tenant_id = 1 and redirect_origin
        let facts = serde_json::json!({
            "tenant_id": 1,
            "email": "test@example.com",
            "redirect_origin": "https://test.example.com"
        });

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_lifetime(3600)
            .with_fact(facts)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = ucan.encode().unwrap();
        let auth_header = format!("Bearer {}", token);

        // Should succeed with correct tenant_id
        assert!(validate_ucan_token(&auth_header, 1).await.is_ok());

        // Should fail with different tenant_id
        let result = validate_ucan_token(&auth_header, 2).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[tokio::test]
    async fn test_ucan_missing_bearer_prefix() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);
        let key_material = NostrKeyMaterial::from_keys(keys);

        let facts = serde_json::json!({
            "redirect_origin": "https://test.example.com"
        });

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_lifetime(3600)
            .with_fact(facts)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = ucan.encode().unwrap();

        // Missing "Bearer " prefix
        let result = validate_ucan_token(&token, 0).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Authorization header format"));
    }

    #[tokio::test]
    async fn test_ucan_invalid_token_format() {
        let result = validate_ucan_token("Bearer invalid-token-string", 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_extract_user_from_ucan_missing_header() {
        let headers = axum::http::HeaderMap::new();
        let result = extract_user_from_ucan(&headers, 0).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing Authorization"));
    }

    #[tokio::test]
    async fn test_ucan_self_issued() {
        // Test that issuer and audience are the same (self-issued)
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);
        let key_material = NostrKeyMaterial::from_keys(keys);

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_lifetime(3600)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        // Verify issuer == audience (self-issued pattern)
        assert_eq!(ucan.issuer(), ucan.audience());
        assert_eq!(ucan.issuer(), &user_did);
    }

    #[tokio::test]
    async fn test_ucan_tampered_signature_rejected() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);
        let key_material = NostrKeyMaterial::from_keys(keys);

        let facts = serde_json::json!({
            "redirect_origin": "https://test.example.com"
        });

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_lifetime(3600)
            .with_fact(facts)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = ucan.encode().unwrap();

        // Tamper with the signature (flip a bit in the signature part)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("valid base64");
        sig_bytes[0] ^= 0x01; // Flip one bit
        let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

        let auth_header = format!("Bearer {}", tampered_token);
        let result = validate_ucan_token(&auth_header, 0).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("signature verification failed"),
            "Should reject tampered signature"
        );
    }

    #[tokio::test]
    async fn test_schnorr_signature_is_64_bytes() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let user_did = nostr_pubkey_to_did(&pubkey);
        let key_material = NostrKeyMaterial::from_keys(keys);

        let ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&user_did)
            .with_lifetime(3600)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = ucan.encode().unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("valid base64");

        // Schnorr signatures are always 64 bytes
        assert_eq!(sig_bytes.len(), 64, "Schnorr signature should be 64 bytes");
    }
}
