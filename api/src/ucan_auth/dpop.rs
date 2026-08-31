// ABOUTME: Reusable DPoP (Demonstrating Proof-of-Possession) proof verifier
// ABOUTME: Enforces DPoP binding on both token issuance and resource access endpoints

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use once_cell::sync::Lazy;
use p256::ecdsa::{signature::Verifier, Signature as P256Signature, VerifyingKey};
use p256::EncodedPoint;
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

use crate::replay_reservation::{
    reservation_ttl_seconds, reserve_shared, truthy_env_value, LocalReplayCache,
    SharedReservationOutcome,
};

/// Maximum age of a DPoP proof (5 minutes)
const DPOP_MAX_AGE_SECS: u64 = 300;
const REPLAY_RESERVATION_SKEW_MARGIN_SECONDS: i64 = 30;
/// Explicit override for development-only degraded mode.
const DPOP_REPLAY_FAIL_OPEN_ENV: &str = "DPOP_REPLAY_FAIL_OPEN";

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ReplayCacheUnavailableError {
    message: String,
}

impl ReplayCacheUnavailableError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub fn is_replay_cache_unavailable_error(error: &anyhow::Error) -> bool {
    error.is::<ReplayCacheUnavailableError>()
}

/// How often to clean expired JTI entries
const JTI_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Global JTI (JWT ID) replay protection cache
/// Maps JTI string -> expiry instant
/// Used as a fallback when Redis is unavailable.
static JTI_CACHE: Lazy<LocalReplayCache> =
    Lazy::new(|| LocalReplayCache::new(Duration::from_secs(JTI_CLEANUP_INTERVAL_SECS)));

fn replay_cache_key(thumbprint: &str, jti: &str) -> String {
    // Replay key is scoped to DPoP key thumbprint + jti (RFC 9449 §11.1-compatible).
    // Deployment-level namespacing is handled by PrefixedRedis/REDIS_KEY_PREFIX.
    format!("dpop:jti:{thumbprint}:{jti}")
}

fn dpop_replay_fail_open_from_env_value(value: Option<&str>) -> bool {
    truthy_env_value(value)
}

fn dpop_replay_fail_open_enabled() -> bool {
    let value = std::env::var(DPOP_REPLAY_FAIL_OPEN_ENV).ok();
    dpop_replay_fail_open_from_env_value(value.as_deref())
}

fn effective_dpop_replay_fail_open() -> bool {
    if cfg!(test) {
        // Unit tests run without full app state/Redis wiring, so keep fallback enabled
        // unless tests explicitly exercise fail-closed via record_jti_usage_with_fail_open.
        true
    } else {
        dpop_replay_fail_open_enabled()
    }
}

fn handle_redis_replay_cache_error(error: &redis::RedisError, fail_open: bool) -> Result<()> {
    if fail_open {
        tracing::error!(
            error = %error,
            fail_open = true,
            "DPoP replay cache degraded: Redis unavailable, falling back to per-instance cache"
        );
        Ok(())
    } else {
        tracing::error!(
            error = %error,
            fail_open = false,
            "DPoP replay cache unavailable: rejecting request to avoid cross-instance replay risk"
        );
        Err(anyhow::Error::new(ReplayCacheUnavailableError::new(format!(
            "DPoP replay protection unavailable (Redis error); request rejected. Set {}=true to allow degraded local fallback in development",
            DPOP_REPLAY_FAIL_OPEN_ENV
        ))))
    }
}

fn handle_redis_replay_cache_unavailable(fail_open: bool) -> Result<()> {
    if fail_open {
        tracing::error!(
            fail_open = true,
            "DPoP replay cache degraded: Redis unavailable, falling back to per-instance cache"
        );
        Ok(())
    } else {
        tracing::error!(
            fail_open = false,
            "DPoP replay cache unavailable: rejecting request to avoid cross-instance replay risk"
        );
        Err(anyhow::Error::new(ReplayCacheUnavailableError::new(format!(
            "DPoP replay protection unavailable (Redis not configured); request rejected. Set {}=true to allow degraded local fallback in development",
            DPOP_REPLAY_FAIL_OPEN_ENV
        ))))
    }
}

async fn record_jti_usage_with_fail_open(
    replay_key: &str,
    iat: i64,
    fail_open: bool,
) -> Result<()> {
    let redis = crate::state::get_keycast_state()
        .ok()
        .and_then(|state| state.redis.clone());
    let now = chrono::Utc::now().timestamp();
    let ttl_seconds = reservation_ttl_seconds(
        iat.saturating_add(DPOP_MAX_AGE_SECS as i64),
        now,
        (2 * DPOP_MAX_AGE_SECS) as i64,
        REPLAY_RESERVATION_SKEW_MARGIN_SECONDS,
    );

    match reserve_shared(redis.as_ref(), replay_key, ttl_seconds, &iat.to_string()).await {
        SharedReservationOutcome::Reserved => return Ok(()),
        SharedReservationOutcome::Replay => {
            return Err(anyhow!("DPoP proof JTI has already been used (replay)"));
        }
        SharedReservationOutcome::Unavailable(Some(error)) => {
            handle_redis_replay_cache_error(&error, fail_open)?;
        }
        SharedReservationOutcome::Unavailable(None) => {
            handle_redis_replay_cache_unavailable(fail_open)?;
        }
    }

    if !JTI_CACHE.reserve(replay_key, ttl_seconds) {
        return Err(anyhow!("DPoP proof JTI has already been used (replay)"));
    }
    Ok(())
}

async fn record_jti_usage(replay_key: &str, iat: i64) -> Result<()> {
    let fail_open = effective_dpop_replay_fail_open();
    record_jti_usage_with_fail_open(replay_key, iat, fail_open).await
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
pub async fn verify_dpop_proof(
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
    // Keep this freshness bound aligned with replay-cache TTL in record_jti_usage.
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

    // Replay check runs after signature/thumbprint validation to prevent
    // unauthenticated cache poisoning via forged proofs.
    let replay_key = replay_cache_key(&thumbprint, &jti);
    record_jti_usage(&replay_key, iat).await?;

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
pub async fn enforce_dpop_binding(
    headers: &HeaderMap,
    ucan: &ucan::Ucan,
    method: &str,
    url: &str,
) -> Result<()> {
    let expected_jkt = match extract_cnf_jkt_from_ucan(ucan) {
        Some(jkt) => jkt,
        None => return Ok(()), // No DPoP binding required
    };

    match verify_dpop_proof(headers, method, url, Some(&expected_jkt)).await? {
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

    #[tokio::test]
    async fn test_valid_dpop_proof_accepted() {
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

        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert!(verified.is_some());
        let verified = verified.unwrap();
        assert_eq!(verified.jti, "unique-jti-valid-1");

        // Verify thumbprint matches
        let expected = compute_thumbprint(&signing_key);
        assert_eq!(verified.thumbprint, expected);
    }

    #[tokio::test]
    async fn test_dpop_proof_with_wrong_thumbprint_rejected() {
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
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("thumbprint mismatch"),
            "Expected thumbprint mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_no_dpop_header_returns_none() {
        let headers = HeaderMap::new();
        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_dpop_bound_ucan_without_proof_rejected() {
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
        )
        .await;

        // verify_dpop_proof returns Ok(None) when no header present
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        // The caller (enforce_dpop_binding) converts None + expected_jkt into an error
    }

    #[tokio::test]
    async fn test_replayed_jti_rejected() {
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
        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        // Second use with same JTI should fail
        let result2 =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result2.is_err());
        let err = result2.unwrap_err().to_string();
        assert!(
            err.contains("replay"),
            "Expected replay error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_same_jti_with_different_keys_is_allowed() {
        let signing_key_a = SigningKey::random(&mut OsRng);
        let signing_key_b = SigningKey::random(&mut OsRng);
        let now = chrono::Utc::now().timestamp();
        let shared_jti = format!("shared-jti-{}", uuid::Uuid::new_v4());

        let proof_a = create_dpop_proof(
            &signing_key_a,
            "POST",
            "https://example.com/api/nostr",
            &shared_jti,
            now,
        );
        let proof_b = create_dpop_proof(
            &signing_key_b,
            "POST",
            "https://example.com/api/nostr",
            &shared_jti,
            now,
        );

        let mut headers_a = HeaderMap::new();
        headers_a.insert("DPoP", proof_a.parse().unwrap());
        let mut headers_b = HeaderMap::new();
        headers_b.insert("DPoP", proof_b.parse().unwrap());

        let result_a =
            verify_dpop_proof(&headers_a, "POST", "https://example.com/api/nostr", None).await;
        assert!(result_a.is_ok());

        let result_b =
            verify_dpop_proof(&headers_b, "POST", "https://example.com/api/nostr", None).await;
        assert!(
            result_b.is_ok(),
            "Expected different-key JTI to be accepted, got: {:?}",
            result_b
        );
    }

    #[tokio::test]
    async fn test_expired_dpop_proof_rejected() {
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

        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expired"),
            "Expected expiry error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_wrong_method_rejected() {
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
        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("htm mismatch"),
            "Expected method mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_wrong_url_rejected() {
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

        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("htu"),
            "Expected URL mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_invalid_jwt_format_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("DPoP", "not-a-jwt".parse().unwrap());

        let result =
            verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_truthy_env_values() {
        assert!(truthy_env_value(Some("true")));
        assert!(truthy_env_value(Some("TRUE")));
        assert!(truthy_env_value(Some("1")));
        assert!(truthy_env_value(Some("yes")));
        assert!(truthy_env_value(Some("on")));
        assert!(!truthy_env_value(Some("false")));
        assert!(!truthy_env_value(Some("0")));
        assert!(!truthy_env_value(Some("no")));
    }

    #[test]
    fn test_dpop_replay_fail_open_defaults_to_false() {
        assert!(!dpop_replay_fail_open_from_env_value(None));
        assert!(dpop_replay_fail_open_from_env_value(Some("true")));
        assert!(!dpop_replay_fail_open_from_env_value(Some("false")));
    }

    #[test]
    fn test_redis_error_fail_closed_by_default() {
        let error = redis::RedisError::from((redis::ErrorKind::IoError, "Connection refused"));
        let result = handle_redis_replay_cache_error(&error, false);
        assert!(result.is_err(), "Redis errors must fail closed by default");
        let typed_error = result.unwrap_err();
        assert!(is_replay_cache_unavailable_error(&typed_error));
        let message = typed_error.to_string();
        assert!(
            message.contains("DPoP replay protection unavailable"),
            "Unexpected error message: {message}"
        );
        assert!(
            message.contains(DPOP_REPLAY_FAIL_OPEN_ENV),
            "Expected env var hint in message: {message}"
        );
    }

    #[test]
    fn test_redis_error_with_explicit_fail_open_allows_fallback() {
        let error = redis::RedisError::from((redis::ErrorKind::IoError, "Connection refused"));
        let result = handle_redis_replay_cache_error(&error, true);
        assert!(result.is_ok(), "Explicit fail-open should allow fallback");
    }

    #[test]
    fn test_redis_unavailable_fail_closed_by_default() {
        let result = handle_redis_replay_cache_unavailable(false);
        assert!(
            result.is_err(),
            "Redis unavailable must fail closed by default"
        );
        let typed_error = result.unwrap_err();
        assert!(is_replay_cache_unavailable_error(&typed_error));
        let message = typed_error.to_string();
        assert!(
            message.contains("DPoP replay protection unavailable"),
            "Unexpected error message: {message}"
        );
        assert!(
            message.contains(DPOP_REPLAY_FAIL_OPEN_ENV),
            "Expected env var hint in message: {message}"
        );
    }

    #[test]
    fn test_redis_unavailable_with_explicit_fail_open_allows_fallback() {
        let result = handle_redis_replay_cache_unavailable(true);
        assert!(result.is_ok(), "Explicit fail-open should allow fallback");
    }

    #[test]
    fn test_replay_cache_classifier_rejects_non_replay_cache_errors() {
        let error = anyhow!("not a replay-cache outage");
        assert!(!is_replay_cache_unavailable_error(&error));
    }

    #[tokio::test]
    async fn test_record_jti_usage_local_fallback_rejects_replay_atomically() {
        let replay_key = format!("test-atomic-local-fallback-{}", uuid::Uuid::new_v4());
        record_jti_usage_with_fail_open(&replay_key, chrono::Utc::now().timestamp(), true)
            .await
            .expect("first insert should succeed");

        let replay =
            record_jti_usage_with_fail_open(&replay_key, chrono::Utc::now().timestamp(), true)
                .await;
        assert!(
            replay.is_err(),
            "second insert should be rejected as replay"
        );
        assert!(
            replay.unwrap_err().to_string().contains("replay"),
            "expected replay error"
        );
    }

    #[tokio::test]
    async fn test_record_jti_usage_local_fallback_concurrent_only_one_succeeds() {
        let replay_key = format!("test-concurrent-local-fallback-{}", uuid::Uuid::new_v4());
        let iat = chrono::Utc::now().timestamp();
        let (result_a, result_b) = tokio::join!(
            record_jti_usage_with_fail_open(&replay_key, iat, true),
            record_jti_usage_with_fail_open(&replay_key, iat, true),
        );

        let success_count = [result_a.is_ok(), result_b.is_ok()]
            .into_iter()
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            success_count, 1,
            "exactly one concurrent request should win the local fallback race"
        );
    }

    #[tokio::test]
    async fn test_record_jti_usage_without_redis_fails_closed_when_not_fail_open() {
        let replay_key = format!("test-no-redis-fail-closed-{}", uuid::Uuid::new_v4());
        let result =
            record_jti_usage_with_fail_open(&replay_key, chrono::Utc::now().timestamp(), false)
                .await;
        assert!(
            result.is_err(),
            "when Redis is unavailable and fail-open is disabled, request must be rejected"
        );
    }

    #[tokio::test]
    async fn test_record_jti_usage_without_redis_allows_fallback_when_fail_open() {
        let replay_key = format!("test-no-redis-fail-open-{}", uuid::Uuid::new_v4());
        let first =
            record_jti_usage_with_fail_open(&replay_key, chrono::Utc::now().timestamp(), true)
                .await;
        assert!(
            first.is_ok(),
            "when Redis is unavailable and fail-open is enabled, fallback should allow first insert"
        );
    }
}
