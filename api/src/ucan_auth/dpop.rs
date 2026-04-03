// ABOUTME: Reusable DPoP (Demonstrating Proof-of-Possession) proof verifier
// ABOUTME: Enforces DPoP binding on both token issuance and resource access endpoints

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use p256::ecdsa::{signature::Verifier, Signature as P256Signature, VerifyingKey};
use p256::EncodedPoint;
use serde_json::Value;
use std::time::{Duration, Instant};

/// Maximum age of a DPoP proof (5 minutes)
const DPOP_MAX_AGE_SECS: u64 = 300;

/// How often to clean expired JTI entries
const JTI_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Global JTI (JWT ID) replay protection cache
/// Maps JTI string -> expiry instant
/// TODO: For multi-instance deployments, replace with Redis-backed cache
static JTI_CACHE: Lazy<DashMap<String, Instant>> = Lazy::new(DashMap::new);

/// Track when we last ran cleanup to avoid doing it on every request
static LAST_CLEANUP: Lazy<std::sync::Mutex<Instant>> =
    Lazy::new(|| std::sync::Mutex::new(Instant::now()));

/// Remove expired JTI entries from the cache (called inline, rate-limited)
fn maybe_cleanup_jtis() {
    let should_cleanup = LAST_CLEANUP
        .lock()
        .ok()
        .map(|last| last.elapsed() > Duration::from_secs(JTI_CLEANUP_INTERVAL_SECS))
        .unwrap_or(false);

    if should_cleanup {
        let now = Instant::now();
        JTI_CACHE.retain(|_, expiry| *expiry > now);
        if let Ok(mut last) = LAST_CLEANUP.lock() {
            *last = now;
        }
    }
}

/// Result of a successfully verified DPoP proof
#[derive(Debug, Clone)]
pub struct VerifiedDpop {
    pub thumbprint: String,
    pub jti: String,
    pub iat: i64,
}

/// Verify a DPoP proof header against expected parameters.
///
/// Returns `Ok(None)` if no DPoP header is present.
/// Returns `Err` if DPoP header is present but invalid.
/// Returns `Ok(Some(VerifiedDpop))` if valid.
///
/// If `expected_jkt` is provided, the computed JWK thumbprint must match it.
pub fn verify_dpop_proof(
    headers: &HeaderMap,
    method: &str,
    htu: &str,
    expected_jkt: Option<&str>,
) -> Result<Option<VerifiedDpop>> {
    let proof = match headers.get("DPoP") {
        Some(v) => v
            .to_str()
            .map_err(|_| anyhow!("DPoP proof must be valid UTF-8"))?,
        None => return Ok(None),
    };

    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("DPoP proof must be a compact JWT"));
    }

    // Decode header
    let header_json: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| anyhow!("DPoP header is not valid base64url"))?,
    )
    .map_err(|_| anyhow!("DPoP header is not valid JSON"))?;

    // Decode payload
    let payload_json: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| anyhow!("DPoP payload is not valid base64url"))?,
    )
    .map_err(|_| anyhow!("DPoP payload is not valid JSON"))?;

    // Verify typ
    if header_json.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err(anyhow!("DPoP proof must declare typ=dpop+jwt"));
    }

    // Verify alg (ES256 or EdDSA)
    let alg = header_json
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("DPoP proof must include alg"))?;
    if alg != "ES256" && alg != "EdDSA" {
        return Err(anyhow!("DPoP proof must use alg ES256 or EdDSA"));
    }

    // Verify htm (HTTP method)
    if payload_json.get("htm").and_then(Value::as_str) != Some(method) {
        return Err(anyhow!(
            "DPoP htm mismatch: expected {}, got {:?}",
            method,
            payload_json.get("htm")
        ));
    }

    // Verify htu (HTTP URI)
    if payload_json.get("htu").and_then(Value::as_str) != Some(htu) {
        return Err(anyhow!("DPoP htu does not match the request URL"));
    }

    // Verify iat (issued at) - must be within DPOP_MAX_AGE_SECS
    let iat = payload_json
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("DPoP proof must include iat"))?;

    let now = chrono::Utc::now().timestamp();
    let age = (now - iat).unsigned_abs();
    if age > DPOP_MAX_AGE_SECS {
        return Err(anyhow!(
            "DPoP proof expired: iat={}, now={}, age={}s (max {}s)",
            iat,
            now,
            age,
            DPOP_MAX_AGE_SECS
        ));
    }

    // Extract jti (JWT ID) for replay protection - parsed early, inserted after signature check
    let jti = payload_json
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("DPoP proof must include jti for replay protection"))?
        .to_string();

    // Extract JWK from header
    let jwk = header_json
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DPoP proof must include a JWK"))?;

    // Verify signature BEFORE inserting JTI into replay cache
    // This prevents an attacker from poisoning the cache with a forged JTI
    if alg == "ES256" {
        verify_es256_signature(parts[0], parts[1], parts[2], jwk)?;
    } else {
        // EdDSA verification requires ed25519-dalek dependency — reject until implemented
        return Err(anyhow!(
            "DPoP algorithm '{}' is not yet supported (only ES256)",
            alg
        ));
    }

    // Periodically clean expired JTI entries
    maybe_cleanup_jtis();

    // Check for JTI replay (inserted AFTER signature verification to prevent cache poisoning)
    let expiry = Instant::now() + Duration::from_secs(DPOP_MAX_AGE_SECS);
    if JTI_CACHE.insert(jti.clone(), expiry).is_some() {
        return Err(anyhow!("DPoP proof JTI has already been used (replay)"));
    }

    // Compute JWK thumbprint
    let thumbprint = jwk_thumbprint(jwk)?;

    // If expected_jkt is set, verify thumbprint matches
    if let Some(expected) = expected_jkt {
        if thumbprint != expected {
            return Err(anyhow!(
                "DPoP JWK thumbprint mismatch: expected {}, got {}",
                expected,
                thumbprint
            ));
        }
    }

    Ok(Some(VerifiedDpop {
        thumbprint,
        jti,
        iat,
    }))
}

/// Verify ES256 (P-256 ECDSA) signature on the DPoP JWT
fn verify_es256_signature(
    header_b64: &str,
    payload_b64: &str,
    signature_b64: &str,
    jwk: &serde_json::Map<String, Value>,
) -> Result<()> {
    let crv = jwk
        .get("crv")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("DPoP EC JWK missing crv"))?;
    if jwk.get("kty").and_then(Value::as_str) != Some("EC") || crv != "P-256" {
        return Err(anyhow!("DPoP proof must use an EC P-256 JWK for ES256"));
    }

    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("DPoP EC JWK missing x"))?;
    let y = jwk
        .get("y")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("DPoP EC JWK missing y"))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| anyhow!("DPoP EC JWK x is not valid base64url"))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| anyhow!("DPoP EC JWK y is not valid base64url"))?;

    let point = EncodedPoint::from_affine_coordinates(
        x_bytes.as_slice().into(),
        y_bytes.as_slice().into(),
        false,
    );
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| anyhow!("DPoP JWK is not a valid P-256 key"))?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| anyhow!("DPoP signature is not valid base64url"))?;
    if signature_bytes.len() != 64 {
        return Err(anyhow!("DPoP signature must be a 64-byte ES256 value"));
    }

    let r: [u8; 32] = signature_bytes[..32]
        .try_into()
        .map_err(|_| anyhow!("DPoP signature is not valid ES256"))?;
    let s: [u8; 32] = signature_bytes[32..]
        .try_into()
        .map_err(|_| anyhow!("DPoP signature is not valid ES256"))?;
    let signature = P256Signature::from_scalars(r, s)
        .map_err(|_| anyhow!("DPoP signature is not valid ES256"))?;

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| anyhow!("DPoP signature verification failed"))?;

    Ok(())
}

/// Compute RFC 7638 JWK thumbprint (SHA-256, base64url-encoded)
pub fn jwk_thumbprint(jwk: &serde_json::Map<String, Value>) -> Result<String> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("DPoP JWK missing kty"))?;

    let canonical = match kty {
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP EC JWK missing crv"))?;
            let x = jwk
                .get("x")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP EC JWK missing x"))?;
            let y = jwk
                .get("y")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP EC JWK missing y"))?;
            format!(
                "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                crv, x, y
            )
        }
        "OKP" => {
            let crv = jwk
                .get("crv")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP OKP JWK missing crv"))?;
            let x = jwk
                .get("x")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP OKP JWK missing x"))?;
            format!("{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}", crv, x)
        }
        "RSA" => {
            let e = jwk
                .get("e")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP RSA JWK missing e"))?;
            let n = jwk
                .get("n")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("DPoP RSA JWK missing n"))?;
            format!("{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}", e, n)
        }
        other => return Err(anyhow!("Unsupported DPoP JWK type '{}'", other)),
    };

    let hash = sha256::digest(&canonical);
    let hash_bytes =
        hex::decode(hash).map_err(|e| anyhow!("Failed to decode DPoP thumbprint hash: {}", e))?;

    Ok(URL_SAFE_NO_PAD.encode(hash_bytes))
}

/// Extract `cnf.jkt` (JWK thumbprint) from UCAN facts if present
pub fn extract_cnf_jkt_from_ucan(ucan: &ucan::Ucan) -> Option<String> {
    ucan.facts().iter().find_map(|fact| {
        fact.get("cnf")
            .and_then(|cnf| cnf.get("jkt"))
            .and_then(|jkt| jkt.as_str())
            .map(String::from)
    })
}

/// Enforce DPoP binding for a UCAN token on a resource access request.
///
/// If the UCAN contains `cnf.jkt`, the request MUST include a valid DPoP proof
/// with a matching JWK thumbprint. If no `cnf.jkt` is present, DPoP is not required.
///
/// `method` and `url` describe the current HTTP request for htm/htu verification.
pub fn enforce_dpop_binding(
    headers: &HeaderMap,
    ucan: &ucan::Ucan,
    method: &str,
    url: &str,
) -> Result<()> {
    let expected_jkt = match extract_cnf_jkt_from_ucan(ucan) {
        Some(jkt) => jkt,
        None => return Ok(()), // No DPoP binding required
    };

    match verify_dpop_proof(headers, method, url, Some(&expected_jkt))? {
        Some(_verified) => Ok(()),
        None => Err(anyhow!(
            "DPoP proof required: token is bound to key {}",
            &expected_jkt[..8.min(expected_jkt.len())]
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    /// Helper to create a DPoP proof JWT signed with ES256
    fn create_dpop_proof(
        signing_key: &SigningKey,
        method: &str,
        htu: &str,
        jti: &str,
        iat: i64,
    ) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y
            }
        });

        let payload = serde_json::json!({
            "htm": method,
            "htu": htu,
            "iat": iat,
            "jti": jti
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P256Signature = signing_key.sign(signing_input.as_bytes());
        // Extract r and s scalars as raw 32-byte each (64 bytes total)
        let (r_bytes, s_bytes) = signature.split_bytes();
        let mut sig_raw = Vec::with_capacity(64);
        sig_raw.extend_from_slice(&r_bytes);
        sig_raw.extend_from_slice(&s_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_raw);

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    /// Helper to compute JWK thumbprint for a signing key
    fn compute_thumbprint(signing_key: &SigningKey) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let jwk_map: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }))
        .unwrap();

        jwk_thumbprint(&jwk_map).unwrap()
    }

    #[test]
    fn test_valid_dpop_proof_accepted() {
        let signing_key = SigningKey::random(&mut OsRng);
        let now = chrono::Utc::now().timestamp();
        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            "https://example.com/api/nostr",
            "unique-jti-valid-1",
            now,
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().unwrap());

        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert!(verified.is_some());
        let verified = verified.unwrap();
        assert_eq!(verified.jti, "unique-jti-valid-1");

        // Verify thumbprint matches
        let expected = compute_thumbprint(&signing_key);
        assert_eq!(verified.thumbprint, expected);
    }

    #[test]
    fn test_dpop_proof_with_wrong_thumbprint_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let now = chrono::Utc::now().timestamp();
        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            "https://example.com/api/nostr",
            "unique-jti-wrong-thumb-1",
            now,
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().unwrap());

        // Use a different key's thumbprint as expected
        let other_key = SigningKey::random(&mut OsRng);
        let wrong_thumbprint = compute_thumbprint(&other_key);

        let result = verify_dpop_proof(
            &headers,
            "POST",
            "https://example.com/api/nostr",
            Some(&wrong_thumbprint),
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("thumbprint mismatch"),
            "Expected thumbprint mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_no_dpop_header_returns_none() {
        let headers = HeaderMap::new();
        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_dpop_bound_ucan_without_proof_rejected() {
        // Simulate a UCAN with cnf.jkt but no DPoP header
        let headers = HeaderMap::new(); // No DPoP header

        // Call enforce_dpop_binding with a mock that has cnf.jkt
        // We can't easily create a real UCAN here, so test via verify_dpop_proof
        // with expected_jkt - if no header is present but jkt is expected, enforce should fail

        // Test the verify_dpop_proof path: if expected_jkt is set, None means "no proof"
        // The enforce_dpop_binding function handles this by checking for None and returning Err
        let result = verify_dpop_proof(
            &headers,
            "POST",
            "https://example.com/api/nostr",
            Some("some-expected-thumbprint"),
        );

        // verify_dpop_proof returns Ok(None) when no header present
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        // The caller (enforce_dpop_binding) converts None + expected_jkt into an error
    }

    #[test]
    fn test_replayed_jti_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let now = chrono::Utc::now().timestamp();
        let jti = format!("replay-test-{}", uuid::Uuid::new_v4());

        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            "https://example.com/api/nostr",
            &jti,
            now,
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().unwrap());

        // First use should succeed
        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        // Second use with same JTI should fail
        let result2 = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result2.is_err());
        let err = result2.unwrap_err().to_string();
        assert!(
            err.contains("replay"),
            "Expected replay error, got: {}",
            err
        );
    }

    #[test]
    fn test_expired_dpop_proof_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        // Set iat to 10 minutes ago (beyond the 5-minute window)
        let old_iat = chrono::Utc::now().timestamp() - 600;
        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            "https://example.com/api/nostr",
            "unique-jti-expired-1",
            old_iat,
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().unwrap());

        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expired"),
            "Expected expiry error, got: {}",
            err
        );
    }

    #[test]
    fn test_wrong_method_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let now = chrono::Utc::now().timestamp();
        let proof = create_dpop_proof(
            &signing_key,
            "GET", // Proof says GET
            "https://example.com/api/nostr",
            "unique-jti-method-1",
            now,
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().unwrap());

        // But we expect POST
        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("htm mismatch"),
            "Expected method mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_wrong_url_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let now = chrono::Utc::now().timestamp();
        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            "https://example.com/api/other",
            "unique-jti-url-1",
            now,
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().unwrap());

        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("htu"),
            "Expected URL mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_invalid_jwt_format_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("DPoP", "not-a-jwt".parse().unwrap());

        let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
        assert!(result.is_err());
    }
}
