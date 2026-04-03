use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect},
    Form, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use dashmap::DashMap;
use jwt_simple::algorithms::ECDSAP256kKeyPairLike;
use jwt_simple::prelude::{Claims, Duration as JwtDuration, ES256kKeyPair};
use keycast_core::repositories::{
    AtprotoOAuthSession, AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams,
    IssueAtprotoTokensParams,
};
use keycast_core::types::refresh_token::hash_refresh_token;
use once_cell::sync::Lazy;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration as StdDuration;

use crate::api::tenant::{get_or_create_tenant, TenantError};

use super::atproto_oauth_metadata::authorization_server_origin;
use super::auth::{extract_user_from_token, generate_secure_token, AuthError};

const PAR_EXPIRY_MINUTES: i64 = 10;
const AUTH_CODE_EXPIRY_MINUTES: i64 = 5;
const ACCESS_TOKEN_EXPIRY_MINUTES: i64 = 15;
const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 30;
const DPOP_MAX_IAT_SKEW_SECONDS: i64 = 300;
const CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS: i64 = 300;
const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const PAR_PATH_SUFFIX: &str = "/atproto/oauth/par";
const TOKEN_PATH_SUFFIX: &str = "/atproto/oauth/token";

static DPOP_REPLAY_CACHE: Lazy<DashMap<String, i64>> = Lazy::new(DashMap::new);
static CLIENT_ASSERTION_REPLAY_CACHE: Lazy<DashMap<String, i64>> = Lazy::new(DashMap::new);

#[derive(Debug, Deserialize)]
pub struct ParRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub request_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
    pub sub: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AtprotoTokenConfirmation {
    jkt: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AtprotoCustomClaims {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    lxm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<AtprotoTokenConfirmation>,
}

#[derive(Debug, Deserialize)]
struct DpopProofHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    jwk: DpopProofJwk,
}

#[derive(Debug, Deserialize)]
struct DpopProofJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
struct DpopProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    ath: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientMetadata {
    client_id: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default = "default_client_auth_method")]
    token_endpoint_auth_method: String,
    #[serde(default)]
    token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    dpop_bound_access_tokens: Option<bool>,
    #[serde(default)]
    jwks: Option<ClientJwks>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

fn default_client_auth_method() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct ClientJwks {
    #[serde(default)]
    keys: Vec<ClientJwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientJwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientAssertionHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    iat: i64,
    jti: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientAuthBinding {
    None,
    PrivateKeyJwt {
        alg: String,
        kid: Option<String>,
        jkt: String,
    },
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn redirect_to_login(request_uri: &str) -> Redirect {
    let path = format!(
        "/api/atproto/oauth/authorize?request_uri={}",
        urlencoding::encode(request_uri)
    );
    Redirect::to(&format!("/login?redirect={}", urlencoding::encode(&path)))
}

fn atproto_jwt_key() -> Result<ES256kKeyPair, AuthError> {
    let key_hex = std::env::var("ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX").map_err(|_| {
        AuthError::Internal("ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX not configured".to_string())
    })?;
    let key_bytes = hex::decode(key_hex).map_err(|error| {
        AuthError::Internal(format!(
            "Invalid ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX: {error}"
        ))
    })?;
    ES256kKeyPair::from_bytes(&key_bytes)
        .map_err(|error| AuthError::Internal(format!("Invalid ATPROTO OAuth signing key: {error}")))
}

fn atproto_pds_did() -> Result<String, AuthError> {
    std::env::var("ATPROTO_OAUTH_PDS_DID")
        .or_else(|_| std::env::var("PDS_SERVICE_DID"))
        .map_err(|_| {
            AuthError::Internal(
                "ATPROTO_OAUTH_PDS_DID or PDS_SERVICE_DID must be configured".to_string(),
            )
        })
}

fn create_access_token(
    subject_did: &str,
    token_id: &str,
    dpop_jkt: &str,
) -> Result<String, AuthError> {
    let key = atproto_jwt_key()?;
    let audience = atproto_pds_did()?;
    let issuer = authorization_server_origin();
    let claims = Claims::with_custom_claims(
        AtprotoCustomClaims {
            scope: "com.atproto.access".to_string(),
            lxm: None,
            cnf: Some(AtprotoTokenConfirmation {
                jkt: dpop_jkt.to_string(),
            }),
        },
        JwtDuration::from_mins(ACCESS_TOKEN_EXPIRY_MINUTES as u64),
    )
    .with_subject(subject_did)
    .with_audience(audience)
    .with_issuer(issuer)
    .with_jwt_id(token_id);

    key.sign(claims).map_err(|error| {
        AuthError::Internal(format!("Failed to sign ATPROTO access token: {error}"))
    })
}

fn dpop_nonce() -> String {
    generate_secure_token()
}

fn response_with_dpop_nonce<T: Serialize>(
    payload: T,
    nonce: &str,
) -> Result<impl IntoResponse, AuthError> {
    let mut headers = HeaderMap::new();
    let header_value = HeaderValue::from_str(nonce)
        .map_err(|error| AuthError::Internal(format!("Invalid DPoP nonce header: {error}")))?;
    headers.insert("DPoP-Nonce", header_value);
    Ok((headers, Json(payload)))
}

fn dpop_jwk_thumbprint(jwk: &DpopProofJwk) -> String {
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn dpop_htu_matches_expected(htu: &str, expected_path_suffix: &str) -> bool {
    if let Ok(url) = reqwest::Url::parse(htu) {
        return url.path().ends_with(expected_path_suffix);
    }
    htu.ends_with(expected_path_suffix)
}

fn validate_dpop_proof(
    headers: &HeaderMap,
    expected_method: &str,
    expected_path_suffix: &str,
    expected_nonce: Option<&str>,
    expected_ath: Option<&str>,
) -> Result<String, AuthError> {
    let proof = headers
        .get("DPoP")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AuthError::BadRequest("Missing DPoP proof".to_string()))?;

    let segments: Vec<&str> = proof.split('.').collect();
    if segments.len() != 3 {
        return Err(AuthError::BadRequest(
            "DPoP proof must be a compact JWT".to_string(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(segments[0]).map_err(|_| {
        AuthError::BadRequest("DPoP proof has invalid JWT header encoding".to_string())
    })?;
    let claims_bytes = URL_SAFE_NO_PAD.decode(segments[1]).map_err(|_| {
        AuthError::BadRequest("DPoP proof has invalid JWT payload encoding".to_string())
    })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(segments[2]).map_err(|_| {
        AuthError::BadRequest("DPoP proof has invalid JWT signature encoding".to_string())
    })?;

    let header: DpopProofHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AuthError::BadRequest("DPoP proof header is invalid JSON".to_string()))?;
    let claims: DpopProofClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AuthError::BadRequest("DPoP proof payload is invalid JSON".to_string()))?;

    if header.alg != "ES256" {
        return Err(AuthError::BadRequest(
            "DPoP proof must use ES256".to_string(),
        ));
    }
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(AuthError::BadRequest(
            "DPoP proof typ must be dpop+jwt".to_string(),
        ));
    }
    if header.jwk.kty != "EC" || header.jwk.crv != "P-256" {
        return Err(AuthError::BadRequest(
            "DPoP proof must carry an EC P-256 JWK".to_string(),
        ));
    }

    let jwk_x = URL_SAFE_NO_PAD
        .decode(&header.jwk.x)
        .map_err(|_| AuthError::BadRequest("Invalid DPoP JWK x coordinate".to_string()))?;
    let jwk_y = URL_SAFE_NO_PAD
        .decode(&header.jwk.y)
        .map_err(|_| AuthError::BadRequest("Invalid DPoP JWK y coordinate".to_string()))?;
    if jwk_x.len() != 32 || jwk_y.len() != 32 {
        return Err(AuthError::BadRequest(
            "DPoP JWK coordinates must be 32 bytes".to_string(),
        ));
    }

    let mut uncompressed_key = Vec::with_capacity(65);
    uncompressed_key.push(0x04);
    uncompressed_key.extend_from_slice(&jwk_x);
    uncompressed_key.extend_from_slice(&jwk_y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&uncompressed_key).map_err(|_| {
        AuthError::BadRequest("DPoP JWK does not encode a valid P-256 key".to_string())
    })?;

    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|_| {
        AuthError::BadRequest("DPoP proof signature is not valid ES256 format".to_string())
    })?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthError::BadRequest("DPoP proof signature validation failed".to_string()))?;

    if !claims.htm.eq_ignore_ascii_case(expected_method) {
        return Err(AuthError::BadRequest(
            "DPoP proof htm does not match request".to_string(),
        ));
    }
    if !dpop_htu_matches_expected(&claims.htu, expected_path_suffix) {
        return Err(AuthError::BadRequest(
            "DPoP proof htu does not match endpoint".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    if claims.iat < now - DPOP_MAX_IAT_SKEW_SECONDS || claims.iat > now + DPOP_MAX_IAT_SKEW_SECONDS
    {
        return Err(AuthError::BadRequest(
            "DPoP proof iat is outside the allowed window".to_string(),
        ));
    }
    if claims.jti.trim().is_empty() {
        return Err(AuthError::BadRequest(
            "DPoP proof must include a non-empty jti".to_string(),
        ));
    }

    match (expected_nonce, claims.nonce.as_deref()) {
        (Some(expected), Some(actual)) if actual == expected => {}
        (Some(_), _) => {
            return Err(AuthError::BadRequest(
                "DPoP proof nonce is missing or invalid".to_string(),
            ))
        }
        _ => {}
    }

    if let Some(expected_ath) = expected_ath {
        if claims.ath.as_deref() != Some(expected_ath) {
            return Err(AuthError::BadRequest(
                "DPoP proof ath does not match access token".to_string(),
            ));
        }
    }

    let jkt = dpop_jwk_thumbprint(&header.jwk);
    let replay_key = format!("{jkt}:{}", claims.jti);
    if let Some(previous) = DPOP_REPLAY_CACHE.get(&replay_key) {
        if now - *previous < DPOP_MAX_IAT_SKEW_SECONDS {
            return Err(AuthError::BadRequest(
                "DPoP proof jti has already been used".to_string(),
            ));
        }
    }
    DPOP_REPLAY_CACHE.insert(replay_key, now);

    Ok(jkt)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn ensure_secure_or_loopback_url(url: &reqwest::Url, label: &str) -> Result<(), AuthError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = url.host_str().unwrap_or_default();
            if is_loopback_host(host) {
                Ok(())
            } else {
                Err(AuthError::BadRequest(format!(
                    "{label} must use HTTPS outside local development"
                )))
            }
        }
        _ => Err(AuthError::BadRequest(format!(
            "{label} must use HTTPS outside local development"
        ))),
    }
}

fn metadata_document_url(
    client_id: &str,
    require_document: bool,
) -> Result<Option<reqwest::Url>, AuthError> {
    let url = match reqwest::Url::parse(client_id) {
        Ok(url) => url,
        Err(_) if require_document => {
            return Err(AuthError::BadRequest(
                "Confidential clients must use an HTTP(S) client_id metadata URL".to_string(),
            ))
        }
        Err(_) => return Ok(None),
    };
    if !matches!(url.scheme(), "https" | "http") {
        if require_document {
            return Err(AuthError::BadRequest(
                "Confidential clients must use an HTTP(S) client_id metadata URL".to_string(),
            ));
        }
        return Ok(None);
    }
    if !require_document && url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        return Ok(None);
    }
    Ok(Some(url))
}

async fn fetch_json(url: &reqwest::Url, label: &str) -> Result<Value, AuthError> {
    ensure_secure_or_loopback_url(url, label)?;
    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(3))
        .build()
        .map_err(|error| AuthError::Internal(format!("Failed to build HTTP client: {error}")))?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| AuthError::BadRequest(format!("Failed to fetch {label}: {error}")))?;
    if !response.status().is_success() {
        return Err(AuthError::BadRequest(format!(
            "{label} returned {}",
            response.status()
        )));
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| AuthError::BadRequest(format!("Invalid {label} JSON: {error}")))
}

async fn fetch_client_metadata(
    client_id: &str,
    require_document: bool,
) -> Result<Option<ClientMetadata>, AuthError> {
    let Some(url) = metadata_document_url(client_id, require_document)? else {
        return Ok(None);
    };
    let raw = fetch_json(&url, "client metadata document").await?;
    let metadata: ClientMetadata = serde_json::from_value(raw).map_err(|error| {
        AuthError::BadRequest(format!("Invalid client metadata document: {error}"))
    })?;
    if metadata.client_id != client_id {
        return Err(AuthError::BadRequest(
            "Client metadata client_id mismatch".to_string(),
        ));
    }
    Ok(Some(metadata))
}

fn validate_metadata_redirect(
    metadata: &ClientMetadata,
    redirect_uri: &str,
) -> Result<(), AuthError> {
    if metadata.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        Ok(())
    } else {
        Err(AuthError::BadRequest(
            "redirect_uri is not registered in client metadata".to_string(),
        ))
    }
}

async fn load_client_signing_keys(metadata: &ClientMetadata) -> Result<Vec<ClientJwk>, AuthError> {
    if metadata.jwks.is_some() && metadata.jwks_uri.is_some() {
        return Err(AuthError::BadRequest(
            "Client metadata must provide either jwks or jwks_uri, not both".to_string(),
        ));
    }
    if let Some(jwks) = &metadata.jwks {
        if jwks.keys.is_empty() {
            return Err(AuthError::BadRequest(
                "Client metadata jwks must contain at least one key".to_string(),
            ));
        }
        return Ok(jwks.keys.clone());
    }
    if let Some(jwks_uri) = metadata.jwks_uri.as_deref() {
        let url = reqwest::Url::parse(jwks_uri)
            .map_err(|error| AuthError::BadRequest(format!("Invalid jwks_uri: {error}")))?;
        let raw = fetch_json(&url, "client jwks_uri").await?;
        let jwks: ClientJwks = serde_json::from_value(raw)
            .map_err(|error| AuthError::BadRequest(format!("Invalid JWKS payload: {error}")))?;
        if jwks.keys.is_empty() {
            return Err(AuthError::BadRequest(
                "Client metadata jwks_uri must resolve to at least one key".to_string(),
            ));
        }
        return Ok(jwks.keys);
    }
    Err(AuthError::BadRequest(
        "private_key_jwt clients must provide jwks or jwks_uri".to_string(),
    ))
}

fn expected_client_assertion_audiences() -> Vec<String> {
    vec![authorization_server_origin()]
}

type CompactJwtParts = (Vec<u8>, Vec<u8>, Vec<u8>, String);

fn compact_jwt_parts(jwt: &str) -> Result<CompactJwtParts, AuthError> {
    let segments: Vec<&str> = jwt.split('.').collect();
    if segments.len() != 3 {
        return Err(AuthError::BadRequest(
            "client_assertion must be a compact JWT".to_string(),
        ));
    }
    let header = URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|_| AuthError::BadRequest("Invalid client_assertion header".to_string()))?;
    let claims = URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| AuthError::BadRequest("Invalid client_assertion payload".to_string()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(segments[2])
        .map_err(|_| AuthError::BadRequest("Invalid client_assertion signature".to_string()))?;
    Ok((
        header,
        claims,
        signature,
        format!("{}.{}", segments[0], segments[1]),
    ))
}

fn client_jwk_verifying_key(jwk: &ClientJwk) -> Result<VerifyingKey, AuthError> {
    if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
        return Err(AuthError::BadRequest(
            "private_key_jwt requires EC P-256 keys".to_string(),
        ));
    }
    if let Some(key_use) = jwk.key_use.as_deref() {
        if key_use != "sig" {
            return Err(AuthError::BadRequest(
                "private_key_jwt key use must be sig".to_string(),
            ));
        }
    }
    if let Some(alg) = jwk.alg.as_deref() {
        if alg != "ES256" {
            return Err(AuthError::BadRequest(
                "private_key_jwt key alg must be ES256".to_string(),
            ));
        }
    }
    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("JWK missing x coordinate".to_string()))?;
    let y = jwk
        .y
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("JWK missing y coordinate".to_string()))?;
    let jwk_x = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| AuthError::BadRequest("Invalid JWK x coordinate".to_string()))?;
    let jwk_y = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| AuthError::BadRequest("Invalid JWK y coordinate".to_string()))?;
    if jwk_x.len() != 32 || jwk_y.len() != 32 {
        return Err(AuthError::BadRequest(
            "JWK coordinates must be 32 bytes".to_string(),
        ));
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&jwk_x);
    uncompressed.extend_from_slice(&jwk_y);
    VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|_| AuthError::BadRequest("Invalid JWK public key".to_string()))
}

fn client_jwk_thumbprint(jwk: &ClientJwk) -> Result<String, AuthError> {
    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("JWK missing x coordinate".to_string()))?;
    let y = jwk
        .y
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("JWK missing y coordinate".to_string()))?;
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn aud_matches_expected(aud: &Value, expected: &[String]) -> bool {
    match aud {
        Value::String(value) => expected.iter().any(|candidate| candidate == value),
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .map(|claim| expected.iter().any(|candidate| candidate == claim))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn validate_private_key_jwt_metadata(metadata: &ClientMetadata) -> Result<(), AuthError> {
    if metadata.token_endpoint_auth_signing_alg.as_deref() != Some("ES256") {
        return Err(AuthError::BadRequest(
            "private_key_jwt clients must publish token_endpoint_auth_signing_alg=ES256"
                .to_string(),
        ));
    }
    if metadata.dpop_bound_access_tokens != Some(true) {
        return Err(AuthError::BadRequest(
            "private_key_jwt clients must publish dpop_bound_access_tokens=true".to_string(),
        ));
    }
    Ok(())
}

fn assertion_field<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, AuthError> {
    value
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest(format!("Missing {name}")))
}

fn unexpected_client_assertion(
    client_assertion_type: &Option<String>,
    client_assertion: &Option<String>,
) -> Result<(), AuthError> {
    if client_assertion_type.is_some() || client_assertion.is_some() {
        Err(AuthError::BadRequest(
            "client_assertion is not allowed for public clients".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn verify_client_assertion(
    client_id: &str,
    client_assertion_type: &Option<String>,
    client_assertion: &Option<String>,
    expected_audiences: &[String],
    signing_keys: &[ClientJwk],
    expected_jkt: Option<&str>,
) -> Result<ClientAuthBinding, AuthError> {
    if assertion_field(client_assertion_type, "client_assertion_type")?
        != CLIENT_ASSERTION_TYPE_JWT_BEARER
    {
        return Err(AuthError::BadRequest(
            "Unsupported client_assertion_type".to_string(),
        ));
    }
    let assertion = assertion_field(client_assertion, "client_assertion")?;
    let (header_bytes, claims_bytes, signature_bytes, signing_input) =
        compact_jwt_parts(assertion)?;
    let header: ClientAssertionHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        AuthError::BadRequest("client_assertion header is invalid JSON".to_string())
    })?;
    if header.alg != "ES256" {
        return Err(AuthError::BadRequest(
            "client_assertion must use ES256".to_string(),
        ));
    }
    let claims: ClientAssertionClaims = serde_json::from_slice(&claims_bytes).map_err(|_| {
        AuthError::BadRequest("client_assertion payload is invalid JSON".to_string())
    })?;
    if claims.iss != client_id || claims.sub != client_id {
        return Err(AuthError::BadRequest(
            "client_assertion must set iss and sub to client_id".to_string(),
        ));
    }
    if !aud_matches_expected(&claims.aud, expected_audiences) {
        return Err(AuthError::BadRequest(format!(
            "client_assertion aud does not match authorization server issuer (got {}, expected one of {})",
            claims.aud,
            expected_audiences.join(", ")
        )));
    }
    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(AuthError::BadRequest(
            "client_assertion is expired".to_string(),
        ));
    }
    if claims.exp > now + CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS {
        return Err(AuthError::BadRequest(
            "client_assertion exp is too far in the future".to_string(),
        ));
    }
    if claims.iat < now - CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS
        || claims.iat > now + DPOP_MAX_IAT_SKEW_SECONDS
    {
        return Err(AuthError::BadRequest(
            "client_assertion iat is outside the allowed window".to_string(),
        ));
    }
    if claims.jti.trim().is_empty() {
        return Err(AuthError::BadRequest(
            "client_assertion must include a non-empty jti".to_string(),
        ));
    }

    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|_| {
        AuthError::BadRequest("client_assertion signature has invalid format".to_string())
    })?;

    let key_candidates: Vec<&ClientJwk> = match header.kid.as_deref() {
        Some(kid) => signing_keys
            .iter()
            .filter(|key| key.kid.as_deref() == Some(kid))
            .collect(),
        None => signing_keys.iter().collect(),
    };
    if key_candidates.is_empty() {
        return Err(AuthError::BadRequest(
            "No matching client signing key found".to_string(),
        ));
    }

    for key in key_candidates {
        let verifying_key = match client_jwk_verifying_key(key) {
            Ok(verifying_key) => verifying_key,
            Err(_) => continue,
        };
        if verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .is_err()
        {
            continue;
        }
        let key_jkt = client_jwk_thumbprint(key)?;
        if let Some(expected) = expected_jkt {
            if key_jkt != expected {
                return Err(AuthError::BadRequest(
                    "client_assertion key does not match PAR binding".to_string(),
                ));
            }
        }
        let replay_key = format!("{client_id}:{}", claims.jti);
        if let Some(previous_exp) = CLIENT_ASSERTION_REPLAY_CACHE.get(&replay_key) {
            if now <= *previous_exp {
                return Err(AuthError::BadRequest(
                    "client_assertion jti has already been used".to_string(),
                ));
            }
        }
        CLIENT_ASSERTION_REPLAY_CACHE.insert(replay_key, claims.exp);
        return Ok(ClientAuthBinding::PrivateKeyJwt {
            alg: header.alg.clone(),
            kid: header.kid.clone(),
            jkt: key_jkt,
        });
    }

    Err(AuthError::BadRequest(
        "client_assertion signature validation failed".to_string(),
    ))
}

async fn validate_par_client_binding(request: &ParRequest) -> Result<ClientAuthBinding, AuthError> {
    let require_metadata =
        request.client_assertion_type.is_some() || request.client_assertion.is_some();
    let metadata = fetch_client_metadata(&request.client_id, require_metadata).await?;
    let Some(metadata) = metadata else {
        unexpected_client_assertion(&request.client_assertion_type, &request.client_assertion)?;
        return Ok(ClientAuthBinding::None);
    };
    validate_metadata_redirect(&metadata, &request.redirect_uri)?;
    match metadata.token_endpoint_auth_method.as_str() {
        "none" => {
            unexpected_client_assertion(&request.client_assertion_type, &request.client_assertion)?;
            Ok(ClientAuthBinding::None)
        }
        "private_key_jwt" => {
            validate_private_key_jwt_metadata(&metadata)?;
            let keys = load_client_signing_keys(&metadata).await?;
            verify_client_assertion(
                &request.client_id,
                &request.client_assertion_type,
                &request.client_assertion,
                &expected_client_assertion_audiences(),
                &keys,
                None,
            )
        }
        _ => Err(AuthError::BadRequest(
            "Unsupported token_endpoint_auth_method in client metadata".to_string(),
        )),
    }
}

async fn enforce_session_client_binding(
    session: &AtprotoOAuthSession,
    client_assertion_type: &Option<String>,
    client_assertion: &Option<String>,
) -> Result<(), AuthError> {
    match session.client_auth_method.as_str() {
        "none" => unexpected_client_assertion(client_assertion_type, client_assertion),
        "private_key_jwt" => {
            let metadata = fetch_client_metadata(&session.client_id, true)
                .await?
                .ok_or_else(|| {
                    AuthError::BadRequest(
                        "Confidential client metadata document must be reachable".to_string(),
                    )
                })?;
            validate_metadata_redirect(&metadata, &session.redirect_uri)?;
            if metadata.token_endpoint_auth_method != "private_key_jwt" {
                return Err(AuthError::BadRequest(
                    "Client metadata auth method changed after PAR".to_string(),
                ));
            }
            validate_private_key_jwt_metadata(&metadata)?;
            let keys = load_client_signing_keys(&metadata).await?;
            let binding = verify_client_assertion(
                &session.client_id,
                client_assertion_type,
                client_assertion,
                &expected_client_assertion_audiences(),
                &keys,
                session.client_auth_jkt.as_deref(),
            )?;
            let expected_binding = ClientAuthBinding::PrivateKeyJwt {
                alg: session.client_auth_alg.clone().ok_or_else(|| {
                    AuthError::BadRequest(
                        "Confidential session missing bound client auth alg".to_string(),
                    )
                })?,
                kid: session.client_auth_kid.clone(),
                jkt: session.client_auth_jkt.clone().ok_or_else(|| {
                    AuthError::BadRequest(
                        "Confidential session missing bound client auth key".to_string(),
                    )
                })?,
            };
            if binding != expected_binding {
                return Err(AuthError::BadRequest(
                    "client_assertion key does not match PAR binding".to_string(),
                ));
            }
            Ok(())
        }
        _ => Err(AuthError::BadRequest(
            "Unsupported session client auth binding".to_string(),
        )),
    }
}

async fn ready_atproto_identity(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<Option<String>, AuthError> {
    let did: Option<String> = sqlx::query_scalar(
        "SELECT atproto_did
         FROM users
         WHERE tenant_id = $1
           AND pubkey = $2
           AND atproto_enabled = true
           AND atproto_state = 'ready'
           AND atproto_did IS NOT NULL",
    )
    .bind(tenant_id)
    .bind(user_pubkey)
    .fetch_optional(pool)
    .await
    .map_err(AuthError::Database)?;

    Ok(did)
}

fn request_domain(headers: &HeaderMap) -> Result<String, AuthError> {
    if let Some(domain) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .and_then(|host| host.split(':').next())
        .filter(|host| !host.is_empty())
    {
        return Ok(domain.to_string());
    }

    let origin = authorization_server_origin();
    reqwest::Url::parse(&origin)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .ok_or_else(|| AuthError::Internal("Failed to determine request tenant".to_string()))
}

async fn request_tenant_id(pool: &PgPool, headers: &HeaderMap) -> Result<i64, AuthError> {
    let domain = request_domain(headers)?;
    let tenant = get_or_create_tenant(pool, &domain)
        .await
        .map_err(|error| match error {
            TenantError::DatabaseError(error) => AuthError::Database(error),
            TenantError::InvalidDomain(message) | TenantError::ValidationFailed(message) => {
                AuthError::BadRequest(message)
            }
        })?;

    Ok(tenant.id)
}

pub async fn par(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Form(request): Form<ParRequest>,
) -> Result<impl IntoResponse, AuthError> {
    if request.scope.trim() != "atproto" {
        return Err(AuthError::BadRequest(
            "ATProto PAR requests must request the atproto scope".to_string(),
        ));
    }

    let dpop_jkt = validate_dpop_proof(&headers, "POST", PAR_PATH_SUFFIX, None, None)?;
    let client_binding = validate_par_client_binding(&request).await?;
    let request_uri = format!(
        "urn:ietf:params:oauth:request_uri:{}",
        generate_secure_token()
    );
    let nonce = dpop_nonce();
    let tenant_id = request_tenant_id(&pool, &headers).await?;
    let repo = AtprotoOAuthSessionRepository::new(pool);
    repo.create_par(CreateAtprotoOAuthSessionParams {
        tenant_id,
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
        scope: request.scope,
        state: request.state,
        code_challenge: request.code_challenge,
        code_challenge_method: request.code_challenge_method,
        request_uri: request_uri.clone(),
        par_expires_at: Utc::now() + Duration::minutes(PAR_EXPIRY_MINUTES),
        dpop_jkt: Some(dpop_jkt),
        dpop_nonce: Some(nonce.clone()),
        client_auth_method: match &client_binding {
            ClientAuthBinding::None => "none".to_string(),
            ClientAuthBinding::PrivateKeyJwt { .. } => "private_key_jwt".to_string(),
        },
        client_auth_alg: match &client_binding {
            ClientAuthBinding::None => None,
            ClientAuthBinding::PrivateKeyJwt { alg, .. } => Some(alg.clone()),
        },
        client_auth_kid: match &client_binding {
            ClientAuthBinding::None => None,
            ClientAuthBinding::PrivateKeyJwt { kid, .. } => kid.clone(),
        },
        client_auth_jkt: match client_binding {
            ClientAuthBinding::None => None,
            ClientAuthBinding::PrivateKeyJwt { jkt, .. } => Some(jkt),
        },
    })
    .await?;

    response_with_dpop_nonce(
        ParResponse {
            request_uri,
            expires_in: PAR_EXPIRY_MINUTES * 60,
        },
        &nonce,
    )
}

pub async fn authorize(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(request): Query<AuthorizeRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let session = repo
        .find_by_request_uri(&request.request_uri)
        .await?
        .ok_or_else(|| AuthError::BadRequest("Unknown request_uri".to_string()))?;

    if session.par_expires_at <= Utc::now() {
        return Err(AuthError::BadRequest("Expired request_uri".to_string()));
    }

    let user_pubkey = match extract_user_from_token(&headers, session.tenant_id).await {
        Ok(user_pubkey) => user_pubkey,
        Err(AuthError::MissingToken | AuthError::InvalidToken) => {
            return Ok(redirect_to_login(&request.request_uri).into_response());
        }
        Err(error) => return Err(error),
    };

    let user_did = ready_atproto_identity(&pool, session.tenant_id, &user_pubkey)
        .await?
        .ok_or_else(|| {
            AuthError::Forbidden(
                "ATProto account link must be ready before approving external app login"
                    .to_string(),
            )
        })?;

    repo.approve_request(&request.request_uri, &user_pubkey, &user_did)
        .await?
        .ok_or_else(|| AuthError::BadRequest("Unknown or revoked request_uri".to_string()))?;

    let code = generate_secure_token();
    repo.store_authorization_code(
        &request.request_uri,
        &code,
        Utc::now() + Duration::minutes(AUTH_CODE_EXPIRY_MINUTES),
    )
    .await?
    .ok_or_else(|| AuthError::BadRequest("Unknown or revoked request_uri".to_string()))?;

    let mut redirect_url = reqwest::Url::parse(&session.redirect_uri)
        .map_err(|error| AuthError::BadRequest(format!("Invalid redirect_uri: {error}")))?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("code", &code);
        if let Some(state) = session.state.as_deref() {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", &authorization_server_origin());
    }

    Ok(Redirect::to(redirect_url.as_ref()).into_response())
}

pub async fn token(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let repo = AtprotoOAuthSessionRepository::new(pool);

    match request.grant_type.as_str() {
        "authorization_code" => {
            let code = request
                .code
                .as_deref()
                .ok_or_else(|| AuthError::BadRequest("Missing authorization code".to_string()))?;
            let client_id = request
                .client_id
                .as_deref()
                .ok_or_else(|| AuthError::BadRequest("Missing client_id".to_string()))?;
            let redirect_uri = request
                .redirect_uri
                .as_deref()
                .ok_or_else(|| AuthError::BadRequest("Missing redirect_uri".to_string()))?;
            let code_verifier = request
                .code_verifier
                .as_deref()
                .ok_or_else(|| AuthError::BadRequest("Missing code_verifier".to_string()))?;

            let session = repo
                .find_by_authorization_code(code)
                .await?
                .ok_or_else(|| {
                    AuthError::BadRequest("Unknown or expired authorization code".to_string())
                })?;

            if session.client_id != client_id || session.redirect_uri != redirect_uri {
                return Err(AuthError::BadRequest(
                    "Authorization code client binding mismatch".to_string(),
                ));
            }
            if let Err(error) = enforce_session_client_binding(
                &session,
                &request.client_assertion_type,
                &request.client_assertion,
            )
            .await
            {
                let _ = repo.revoke_session(&session.request_uri).await;
                return Err(error);
            }

            if session.code_challenge_method.as_deref() != Some("S256") {
                return Err(AuthError::BadRequest(
                    "ATProto OAuth requires S256 PKCE".to_string(),
                ));
            }

            let expected_challenge = pkce_challenge(code_verifier);
            if session.code_challenge.as_deref() != Some(expected_challenge.as_str()) {
                return Err(AuthError::BadRequest("Invalid PKCE verifier".to_string()));
            }

            let session_nonce = session.dpop_nonce.clone().ok_or_else(|| {
                AuthError::BadRequest("Missing DPoP nonce for authorization code".to_string())
            })?;
            let proof_jkt = validate_dpop_proof(
                &headers,
                "POST",
                TOKEN_PATH_SUFFIX,
                Some(&session_nonce),
                None,
            )?;
            let expected_jkt = session.dpop_jkt.clone().ok_or_else(|| {
                AuthError::BadRequest("Authorization code session is not DPoP-bound".to_string())
            })?;
            if proof_jkt != expected_jkt {
                return Err(AuthError::BadRequest(
                    "DPoP proof key does not match the session binding".to_string(),
                ));
            }
            repo.consume_authorization_code(code)
                .await?
                .ok_or_else(|| {
                    AuthError::BadRequest("Unknown or expired authorization code".to_string())
                })?;

            let subject_did = session.atproto_did.clone().ok_or_else(|| {
                AuthError::BadRequest(
                    "Authorization code is not bound to a ready ATProto DID".to_string(),
                )
            })?;

            let access_token_jti = generate_secure_token();
            let access_token = create_access_token(&subject_did, &access_token_jti, &proof_jkt)?;
            let refresh_token = generate_secure_token();
            let refresh_token_hash = hash_refresh_token(&refresh_token);
            let next_nonce = dpop_nonce();

            repo.store_token_artifacts(
                &session.request_uri,
                IssueAtprotoTokensParams {
                    authorization_code: code.to_string(),
                    authorization_code_expires_at: Utc::now(),
                    access_token_jti: access_token_jti.clone(),
                    access_token_expires_at: Utc::now()
                        + Duration::minutes(ACCESS_TOKEN_EXPIRY_MINUTES),
                    refresh_token_hash,
                    refresh_token_expires_at: Utc::now()
                        + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS),
                    dpop_jkt: Some(proof_jkt),
                    dpop_nonce: Some(next_nonce.clone()),
                },
            )
            .await?;

            response_with_dpop_nonce(
                TokenResponse {
                    access_token,
                    token_type: "DPoP".to_string(),
                    expires_in: ACCESS_TOKEN_EXPIRY_MINUTES * 60,
                    refresh_token,
                    scope: "atproto".to_string(),
                    sub: subject_did,
                },
                &next_nonce,
            )
        }
        "refresh_token" => {
            let refresh_token = request
                .refresh_token
                .as_deref()
                .ok_or_else(|| AuthError::BadRequest("Missing refresh_token".to_string()))?;
            let client_id = request
                .client_id
                .as_deref()
                .ok_or_else(|| AuthError::BadRequest("Missing client_id".to_string()))?;
            let refresh_token_hash = hash_refresh_token(refresh_token);

            let session = repo
                .find_by_refresh_token_hash(&refresh_token_hash)
                .await?
                .ok_or_else(|| {
                    AuthError::BadRequest("Invalid or expired refresh token".to_string())
                })?;
            if session.client_id != client_id {
                return Err(AuthError::BadRequest(
                    "Refresh token client binding mismatch".to_string(),
                ));
            }
            if let Err(error) = enforce_session_client_binding(
                &session,
                &request.client_assertion_type,
                &request.client_assertion,
            )
            .await
            {
                let _ = repo.revoke_refresh_session(&refresh_token_hash).await;
                return Err(error);
            }

            let session_nonce = session.dpop_nonce.clone().ok_or_else(|| {
                AuthError::BadRequest("Missing DPoP nonce for refresh token".to_string())
            })?;
            let proof_jkt = validate_dpop_proof(
                &headers,
                "POST",
                TOKEN_PATH_SUFFIX,
                Some(&session_nonce),
                None,
            )?;
            let expected_jkt = session.dpop_jkt.clone().ok_or_else(|| {
                AuthError::BadRequest("Refresh token session is not DPoP-bound".to_string())
            })?;
            if proof_jkt != expected_jkt {
                return Err(AuthError::BadRequest(
                    "DPoP proof key does not match the session binding".to_string(),
                ));
            }

            let subject_did = session.atproto_did.clone().ok_or_else(|| {
                AuthError::BadRequest(
                    "Refresh token is not bound to a ready ATProto DID".to_string(),
                )
            })?;

            let access_token_jti = generate_secure_token();
            let access_token = create_access_token(&subject_did, &access_token_jti, &proof_jkt)?;
            let next_refresh_token = generate_secure_token();
            let next_refresh_hash = hash_refresh_token(&next_refresh_token);
            let next_nonce = dpop_nonce();

            let rotated = repo
                .rotate_refresh_token(
                    &session.request_uri,
                    &refresh_token_hash,
                    IssueAtprotoTokensParams {
                        authorization_code: session.authorization_code.unwrap_or_default(),
                        authorization_code_expires_at: session
                            .authorization_code_expires_at
                            .unwrap_or_else(Utc::now),
                        access_token_jti: access_token_jti.clone(),
                        access_token_expires_at: Utc::now()
                            + Duration::minutes(ACCESS_TOKEN_EXPIRY_MINUTES),
                        refresh_token_hash: next_refresh_hash,
                        refresh_token_expires_at: Utc::now()
                            + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS),
                        dpop_jkt: Some(proof_jkt),
                        dpop_nonce: Some(next_nonce.clone()),
                    },
                )
                .await?;

            if rotated.is_none() {
                return Err(AuthError::BadRequest(
                    "Invalid or expired refresh token".to_string(),
                ));
            }

            response_with_dpop_nonce(
                TokenResponse {
                    access_token,
                    token_type: "DPoP".to_string(),
                    expires_in: ACCESS_TOKEN_EXPIRY_MINUTES * 60,
                    refresh_token: next_refresh_token,
                    scope: "atproto".to_string(),
                    sub: subject_did,
                },
                &next_nonce,
            )
        }
        _ => Err(AuthError::BadRequest(
            "Only authorization_code and refresh_token are supported for ATProto token exchange"
                .to_string(),
        )),
    }
}
