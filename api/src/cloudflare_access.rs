// ABOUTME: Cloudflare Access JWT validation and synthetic keypair derivation
// ABOUTME: Enables admin login via Cloudflare Access SSO (GitHub/Google)

use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use nostr_sdk::Keys;
use serde::Deserialize;
use sha2::Sha256;
use std::sync::RwLock;
use std::time::Instant;

/// JWKS cache with 1-hour TTL
static JWKS_CACHE: std::sync::OnceLock<RwLock<(Instant, JwkSet)>> = std::sync::OnceLock::new();

/// Cache TTL: 1 hour
const JWKS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Claims from a Cloudflare Access JWT
#[derive(Debug, Deserialize)]
pub struct CfAccessClaims {
    pub email: String,
    pub sub: String,
    pub aud: serde_json::Value, // Can be string or array of strings
    pub iat: u64,
    pub exp: u64,
}

/// Check if CF Access is configured (both env vars set)
pub fn is_configured() -> bool {
    std::env::var("CF_ACCESS_TEAM").is_ok() && std::env::var("CF_ACCESS_AUD").is_ok()
}

/// Validate a Cloudflare Access JWT token.
///
/// Fetches JWKS from the CF Access certs endpoint, validates the RS256 signature,
/// checks the audience tag matches CF_ACCESS_AUD, and verifies expiry.
pub async fn validate_cf_jwt(token: &str) -> Result<CfAccessClaims> {
    let team = std::env::var("CF_ACCESS_TEAM").context("CF_ACCESS_TEAM not configured")?;
    let expected_aud = std::env::var("CF_ACCESS_AUD").context("CF_ACCESS_AUD not configured")?;

    let certs_url = format!("https://{}.cloudflareaccess.com/cdn-cgi/access/certs", team);

    // Decode JWT header to find the key ID
    let header = decode_header(token).context("Failed to decode CF JWT header")?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow!("CF JWT missing kid in header"))?;

    // Get JWKS (from cache or fetch)
    let jwks = get_jwks(&certs_url).await?;

    // Find the matching key
    let jwk =
        find_jwk(&jwks, &kid).ok_or_else(|| anyhow!("No matching key found for kid: {}", kid))?;

    let decoding_key =
        DecodingKey::from_jwk(jwk).context("Failed to create decoding key from JWK")?;

    // Validate: RS256, check exp, check aud
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&expected_aud]);
    validation.validate_exp = true;

    let token_data = match decode::<CfAccessClaims>(token, &decoding_key, &validation) {
        Ok(data) => data,
        Err(e) => {
            // On validation failure, try refetching JWKS in case keys rotated
            tracing::info!("CF JWT validation failed, refetching JWKS: {}", e);
            let fresh_jwks = fetch_jwks(&certs_url).await?;
            let jwk = find_jwk(&fresh_jwks, &kid)
                .ok_or_else(|| anyhow!("No matching key after JWKS refresh for kid: {}", kid))?;
            let decoding_key = DecodingKey::from_jwk(jwk)
                .context("Failed to create decoding key from refreshed JWK")?;
            decode::<CfAccessClaims>(token, &decoding_key, &validation)
                .context("CF JWT validation failed after JWKS refresh")?
        }
    };

    tracing::info!(
        "CF Access JWT validated for email: {}",
        token_data.claims.email
    );

    Ok(token_data.claims)
}

/// Derive a deterministic synthetic keypair from an admin's email.
///
/// Uses HKDF-SHA256 with SERVER_NSEC as input keying material, "cf-admin" as salt,
/// and the email as info. This gives the CF admin a stable internal pubkey for UCAN audience.
pub fn derive_synthetic_keys(email: &str) -> Result<Keys> {
    let server_nsec = std::env::var("SERVER_NSEC").context("SERVER_NSEC not configured")?;
    let server_keys =
        Keys::parse(&server_nsec).map_err(|e| anyhow!("Invalid SERVER_NSEC: {}", e))?;

    let ikm = server_keys.secret_key().to_secret_bytes();
    let salt = b"cf-admin";
    let info = email.as_bytes();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

    let secret_key = nostr_sdk::SecretKey::from_slice(&okm)
        .map_err(|e| anyhow!("Failed to create secret key from HKDF output: {}", e))?;

    Ok(Keys::new(secret_key))
}

/// Get JWKS from cache or fetch fresh
async fn get_jwks(certs_url: &str) -> Result<JwkSet> {
    // Check cache
    if let Some(cache) = JWKS_CACHE.get() {
        let guard = cache
            .read()
            .map_err(|e| anyhow!("JWKS cache lock poisoned: {}", e))?;
        if guard.0.elapsed() < JWKS_CACHE_TTL {
            return Ok(guard.1.clone());
        }
    }

    fetch_jwks(certs_url).await
}

/// Fetch JWKS from Cloudflare and update cache
async fn fetch_jwks(certs_url: &str) -> Result<JwkSet> {
    tracing::debug!("Fetching JWKS from {}", certs_url);

    let jwks: JwkSet = reqwest::get(certs_url)
        .await
        .context("Failed to fetch CF Access JWKS")?
        .json()
        .await
        .context("Failed to parse CF Access JWKS")?;

    // Update cache
    let cache = JWKS_CACHE.get_or_init(|| RwLock::new((Instant::now(), jwks.clone())));
    if let Ok(mut guard) = cache.write() {
        *guard = (Instant::now(), jwks.clone());
    }

    Ok(jwks)
}

/// Find a JWK by key ID
fn find_jwk<'a>(jwks: &'a JwkSet, kid: &str) -> Option<&'a jsonwebtoken::jwk::Jwk> {
    jwks.keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
}
