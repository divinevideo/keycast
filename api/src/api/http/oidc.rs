// ABOUTME: Sign-in through an upstream OpenID Provider (any OIDC identity provider)
// ABOUTME: Authorization-code + PKCE login that mints a server-signed UCAN session cookie

//! Upstream OIDC login.
//!
//! Keycast normally authenticates with e-mail and password. With `OIDC_ISSUER` set, it also
//! accepts a login at an upstream OpenID Provider:
//!
//! 1. `GET /api/auth/oidc/start?return_to=<path>` stores state, nonce and a PKCE verifier in a
//!    signed, short-lived cookie and redirects the browser to the provider.
//! 2. `GET /api/auth/oidc/callback` exchanges the code, verifies the ID token (signature from the
//!    provider's JWKS, `iss`, `aud`, `exp`, `nonce`), maps the subject to an account and sets the
//!    usual `keycast_session` cookie with a server-signed UCAN, then redirects to `return_to`
//!    (for the OAuth popup: back to `/api/oauth/authorize?…`, where consent continues).
//!
//! Each sign-in keeps its own flow cookie (`keycast_oidc_<state prefix>`), so two sign-ins in one
//! browser (e.g. a second tab while the first waits for an e-mail link at the provider) do not
//! overwrite each other.
//!
//! Accounts are never created here. The first login links the provider's subject to an existing
//! account whose `vine_id` equals the value of the configured link claim (`OIDC_LINK_CLAIM`);
//! later logins use the stored link (`oidc_identities`). Preloaded accounts need no claim step.
//!
//! Configuration (all read once from the environment):
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OIDC_ISSUER` | Issuer URL as the browser sees it; enables the feature. Must equal the discovery `issuer` and the ID token `iss`. |
//! | `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Confidential client at the provider. |
//! | `OIDC_REDIRECT_URL` | This server's callback, `<APP_URL>/api/auth/oidc/callback`. |
//! | `OIDC_BACKCHANNEL_URL` | Optional origin for server-to-server calls (discovery, token, JWKS) when the issuer's public host does not resolve from here (Docker Compose). Requests keep the issuer's `Host` header so the provider issues tokens for the public issuer. |
//! | `OIDC_SCOPES` | Default `openid email profile`. |
//! | `OIDC_LINK_CLAIM` | ID token claim matched against `users.vine_id` on first login. Default `keycast_vine_id`. |
//! | `OIDC_PROVIDER_NAME` | Button label, "Sign in with …". Default `single sign-on`. |
//! | `OIDC_HIDE_PASSWORD_LOGIN` | `true` hides the e-mail/password and registration forms in the login pages. The API endpoints stay (admins use them). |

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{AppendHeaders, Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use jwt_simple::prelude::*;
use keycast_core::repositories::{OidcIdentityRepository, OidcLinkOutcome, UserRepository};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::{OnceCell, RwLock};

use super::html_safety::escape_html;
use super::routes::AuthState;

const STATE_COOKIE: &str = "keycast_oidc";
const STATE_TTL_SECS: u64 = 600;
const MAX_RETURN_TO_LEN: usize = 4096;
const JWKS_MAX_AGE: StdDuration = StdDuration::from_secs(3600);
const JWKS_MIN_REFRESH: StdDuration = StdDuration::from_secs(30);

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub backchannel_url: Option<String>,
    pub scopes: String,
    pub link_claim: String,
    pub provider_name: String,
    pub hide_password_login: bool,
    /// Origin of this server's web app (`APP_URL`), the session's `redirect_origin` for logins
    /// that do not continue an OAuth request.
    pub app_origin: String,
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn origin_of(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("{url:?} is not a URL: {e}"))?;
    let origin = parsed.origin();
    if origin.is_tuple() {
        Ok(origin.ascii_serialization())
    } else {
        Err(format!("{url:?} has no origin"))
    }
}

impl OidcConfig {
    /// `Ok(None)` when `OIDC_ISSUER` is unset (feature off).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let Some(issuer) = get("OIDC_ISSUER") else {
            return Ok(None);
        };
        let need =
            |name: &str| get(name).ok_or_else(|| format!("{name} is required with OIDC_ISSUER"));
        let app_url = get("APP_URL").ok_or("APP_URL is required with OIDC_ISSUER")?;
        let config = OidcConfig {
            client_id: need("OIDC_CLIENT_ID")?,
            client_secret: need("OIDC_CLIENT_SECRET")?,
            redirect_url: need("OIDC_REDIRECT_URL")?,
            backchannel_url: get("OIDC_BACKCHANNEL_URL"),
            scopes: get("OIDC_SCOPES").unwrap_or_else(|| "openid email profile".to_string()),
            link_claim: get("OIDC_LINK_CLAIM").unwrap_or_else(|| "keycast_vine_id".to_string()),
            provider_name: get("OIDC_PROVIDER_NAME")
                .unwrap_or_else(|| "single sign-on".to_string()),
            hide_password_login: get("OIDC_HIDE_PASSWORD_LOGIN")
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
            app_origin: origin_of(&app_url)?,
            issuer,
        };
        origin_of(&config.issuer)?;
        origin_of(&config.redirect_url)?;
        if let Some(b) = &config.backchannel_url {
            origin_of(b)?;
        }
        if !config.scopes.split_whitespace().any(|s| s == "openid") {
            return Err("OIDC_SCOPES must include openid".to_string());
        }
        Ok(Some(config))
    }
}

// ---------------------------------------------------------------------------------------------
// Provider client (discovery, JWKS, token exchange)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

pub struct OidcProvider {
    pub config: OidcConfig,
    http: reqwest::Client,
    discovery: OnceCell<Discovery>,
    jwks: RwLock<Option<(Instant, Vec<Jwk>)>>,
}

static PROVIDER: Lazy<Option<Arc<OidcProvider>>> =
    Lazy::new(|| match OidcConfig::from_lookup(env_nonempty) {
        Ok(Some(config)) => {
            tracing::info!(
                issuer = %config.issuer,
                backchannel = config.backchannel_url.as_deref().unwrap_or("-"),
                "OIDC login enabled"
            );
            Some(Arc::new(OidcProvider::new(config)))
        }
        Ok(None) => None,
        Err(e) => {
            tracing::error!("OIDC login disabled, configuration error: {e}");
            None
        }
    });

/// The configured provider, or `None` when OIDC login is off.
pub fn provider() -> Option<Arc<OidcProvider>> {
    PROVIDER.clone()
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("OIDC login is not configured")]
    Disabled,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    NoAccount(String),
    #[error("upstream provider error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        Self {
            config,
            http,
            discovery: OnceCell::new(),
            jwks: RwLock::new(None),
        }
    }

    /// Map a URL on the issuer's public origin to the back-channel origin, returning the URL to
    /// call and the `Host` header to send (the issuer's authority).
    fn backchannel(&self, url: &str) -> Result<(String, Option<String>), OidcError> {
        let Some(base) = &self.config.backchannel_url else {
            return Ok((url.to_string(), None));
        };
        let public = reqwest::Url::parse(&self.config.issuer)
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        let public_origin = public.origin().ascii_serialization();
        let Some(rest) = url.strip_prefix(&public_origin) else {
            // Endpoint on another origin: call it as published.
            return Ok((url.to_string(), None));
        };
        let host = match public.port() {
            Some(port) => format!("{}:{}", public.host_str().unwrap_or_default(), port),
            None => public.host_str().unwrap_or_default().to_string(),
        };
        Ok((
            format!("{}{}", base.trim_end_matches('/'), rest),
            Some(host),
        ))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, OidcError> {
        let (target, host) = self.backchannel(url)?;
        let mut req = self
            .http
            .get(&target)
            .header(header::ACCEPT, "application/json");
        if let Some(h) = host {
            req = req.header(header::HOST, h);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| OidcError::Upstream(format!("GET {target}: {e}")))?;
        if !resp.status().is_success() {
            return Err(OidcError::Upstream(format!(
                "GET {target}: HTTP {}",
                resp.status()
            )));
        }
        resp.json::<T>()
            .await
            .map_err(|e| OidcError::Upstream(format!("GET {target}: {e}")))
    }

    async fn discovery(&self) -> Result<&Discovery, OidcError> {
        self.discovery
            .get_or_try_init(|| async {
                let url = format!(
                    "{}/.well-known/openid-configuration",
                    self.config.issuer.trim_end_matches('/')
                );
                let d: Discovery = self.get_json(&url).await?;
                if d.issuer != self.config.issuer {
                    return Err(OidcError::Upstream(format!(
                        "discovery issuer {:?} differs from OIDC_ISSUER {:?}",
                        d.issuer, self.config.issuer
                    )));
                }
                Ok(d)
            })
            .await
    }

    async fn jwks(&self, force: bool) -> Result<Vec<Jwk>, OidcError> {
        {
            let cached = self.jwks.read().await;
            if let Some((at, keys)) = cached.as_ref() {
                let age = at.elapsed();
                if age < JWKS_MAX_AGE && (!force || age < JWKS_MIN_REFRESH) {
                    return Ok(keys.clone());
                }
            }
        }
        let uri = self.discovery().await?.jwks_uri.clone();
        let set: JwkSet = self.get_json(&uri).await?;
        *self.jwks.write().await = Some((Instant::now(), set.keys.clone()));
        Ok(set.keys)
    }

    async fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> Result<String, OidcError> {
        let d = self.discovery().await?;
        let mut url = reqwest::Url::parse(&d.authorization_endpoint)
            .map_err(|e| OidcError::Upstream(format!("authorization_endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.to_string())
    }

    async fn exchange_code(&self, code: &str, verifier: &str) -> Result<String, OidcError> {
        let token_endpoint = self.discovery().await?.token_endpoint.clone();
        let (target, host) = self.backchannel(&token_endpoint)?;
        let mut req = self.http.post(&target).form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code_verifier", verifier),
        ]);
        if let Some(h) = host {
            req = req.header(header::HOST, h);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| OidcError::Upstream(format!("token request: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(%status, body = %body.chars().take(300).collect::<String>(), "OIDC token exchange refused");
            return Err(OidcError::Unauthorized(
                "The sign-in provider refused the login code.".to_string(),
            ));
        }
        let tokens: TokenResponse = resp
            .json()
            .await
            .map_err(|e| OidcError::Upstream(format!("token response: {e}")))?;
        tokens
            .id_token
            .ok_or_else(|| OidcError::Upstream("token response has no id_token".to_string()))
    }

    /// Verify an ID token against the provider's keys, refreshing the key set once when the
    /// token's `kid` is unknown (key rotation).
    async fn verify_id_token(&self, token: &str, nonce: &str) -> Result<IdTokenClaims, OidcError> {
        let keys = self.jwks(false).await?;
        match verify_id_token_with_keys(token, &keys, &self.config, nonce) {
            Err(VerifyError::UnknownKey) => {
                let keys = self.jwks(true).await?;
                verify_id_token_with_keys(token, &keys, &self.config, nonce)
                    .map_err(VerifyError::into_oidc)
            }
            other => other.map_err(VerifyError::into_oidc),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ID token verification (pure, unit-tested)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtraClaims {
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenClaims {
    pub subject: String,
    pub email: Option<String>,
    /// Value of the configured link claim, as a string (numbers are accepted).
    pub link: Option<String>,
}

#[derive(Debug)]
pub enum VerifyError {
    UnknownKey,
    Invalid(String),
}

impl VerifyError {
    fn into_oidc(self) -> OidcError {
        match self {
            VerifyError::UnknownKey => {
                OidcError::Unauthorized("ID token signed with an unknown key".to_string())
            }
            VerifyError::Invalid(m) => OidcError::Unauthorized(format!("ID token rejected: {m}")),
        }
    }
}

fn b64(s: &Option<String>, what: &str) -> Result<Vec<u8>, VerifyError> {
    let s = s
        .as_deref()
        .ok_or_else(|| VerifyError::Invalid(format!("JWK without {what}")))?;
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| VerifyError::Invalid(format!("JWK {what}: {e}")))
}

pub fn verify_id_token_with_keys(
    token: &str,
    keys: &[Jwk],
    config: &OidcConfig,
    nonce: &str,
) -> Result<IdTokenClaims, VerifyError> {
    let meta = Token::decode_metadata(token).map_err(|e| VerifyError::Invalid(e.to_string()))?;
    let alg = meta.algorithm().to_string();
    let kid = meta.key_id().map(str::to_string);
    let kty = match alg.as_str() {
        "RS256" => "RSA",
        "ES256" => "EC",
        other => return Err(VerifyError::Invalid(format!("unsupported alg {other}"))),
    };
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| k.kty == kty && k.use_.as_deref().is_none_or(|u| u == "sig"))
        .filter(|k| match (&kid, &k.kid) {
            (Some(want), Some(have)) => want == have,
            (Some(_), None) => false,
            (None, _) => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(VerifyError::UnknownKey);
    }

    let options = VerificationOptions {
        allowed_issuers: Some(HashSet::from([config.issuer.clone()])),
        allowed_audiences: Some(HashSet::from([config.client_id.clone()])),
        required_nonce: Some(nonce.to_string()),
        time_tolerance: Some(Duration::from_secs(60)),
        ..Default::default()
    };

    let mut last_err = String::from("no usable key");
    for jwk in candidates {
        let result = match alg.as_str() {
            "RS256" => {
                let pk = RS256PublicKey::from_components(&b64(&jwk.n, "n")?, &b64(&jwk.e, "e")?)
                    .map_err(|e| VerifyError::Invalid(e.to_string()))?;
                pk.verify_token::<ExtraClaims>(token, Some(options.clone()))
            }
            _ => {
                if jwk.crv.as_deref() != Some("P-256") {
                    continue;
                }
                let mut sec1 = vec![0x04];
                sec1.extend(b64(&jwk.x, "x")?);
                sec1.extend(b64(&jwk.y, "y")?);
                let pk = ES256PublicKey::from_bytes(&sec1)
                    .map_err(|e| VerifyError::Invalid(e.to_string()))?;
                pk.verify_token::<ExtraClaims>(token, Some(options.clone()))
            }
        };
        match result {
            Ok(claims) => {
                if claims.expires_at.is_none() {
                    return Err(VerifyError::Invalid("no exp".to_string()));
                }
                let subject = claims
                    .subject
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| VerifyError::Invalid("no sub".to_string()))?;
                let fields = claims.custom.fields;
                let email = fields
                    .get("email")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());
                let link = match fields.get(&config.link_claim) {
                    Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
                    Some(serde_json::Value::Number(n)) => Some(n.to_string()),
                    _ => None,
                };
                return Ok(IdTokenClaims {
                    subject,
                    email,
                    link,
                });
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(VerifyError::Invalid(last_err))
}

// ---------------------------------------------------------------------------------------------
// Flow state cookie and return_to handling (pure, unit-tested)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowState {
    #[serde(rename = "s")]
    pub state: String,
    #[serde(rename = "n")]
    pub nonce: String,
    #[serde(rename = "v")]
    pub verifier: String,
    #[serde(rename = "r")]
    pub return_to: String,
    #[serde(rename = "o")]
    pub redirect_origin: String,
    #[serde(rename = "e")]
    pub expires_at: u64,
}

fn cookie_key(server_secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"keycast-oidc-flow-state-v1");
    h.update(server_secret);
    h.finalize().into()
}

pub fn seal_flow_state(flow: &FlowState, server_secret: &[u8]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(flow).expect("serializable"));
    let mut mac = HmacSha256::new_from_slice(&cookie_key(server_secret)).expect("any key size");
    mac.update(payload.as_bytes());
    let tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload}.{tag}")
}

pub fn open_flow_state(value: &str, server_secret: &[u8], now: u64) -> Option<FlowState> {
    let (payload, tag) = value.split_once('.')?;
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    let mut mac = HmacSha256::new_from_slice(&cookie_key(server_secret)).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&tag).ok()?;
    let flow: FlowState = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    (flow.expires_at > now).then_some(flow)
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A same-origin relative path, or `None`. Rejects protocol-relative and backslash tricks and
/// control characters (the same rules as the web app's `safeRedirectPath`).
pub fn safe_return_to(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    if raw.len() > MAX_RETURN_TO_LEN
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || raw.contains('\\')
        || raw.chars().any(|c| c.is_control())
    {
        return None;
    }
    let base = reqwest::Url::parse("http://sentinel.invalid").ok()?;
    let joined = base.join(raw).ok()?;
    if joined.origin() != base.origin() || joined.path().starts_with("//") {
        return None;
    }
    let mut out = joined.path().to_string();
    if let Some(q) = joined.query() {
        out.push('?');
        out.push_str(q);
    }
    Some(out)
}

/// The session's `redirect_origin`: the OAuth client's origin when the login continues an
/// `/api/oauth/authorize` request, otherwise this server's own web origin.
pub fn redirect_origin_for(return_to: &str, app_origin: &str) -> Result<String, OidcError> {
    let joined = reqwest::Url::parse("http://sentinel.invalid")
        .and_then(|b| b.join(return_to))
        .map_err(|_| OidcError::BadRequest("invalid return_to".to_string()))?;
    if joined.path() == "/api/oauth/authorize" {
        let redirect_uri = joined
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .ok_or_else(|| {
                OidcError::BadRequest("authorize request without redirect_uri".to_string())
            })?;
        return super::oauth::extract_origin(&redirect_uri)
            .map_err(|_| OidcError::BadRequest("invalid redirect_uri".to_string()));
    }
    Ok(app_origin.to_string())
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&prefix).map(str::to_string))
}

/// The flow cookie of one sign-in, named after a prefix of its `state` (URL-safe base64). `None`
/// for a `state` that is not of that alphabet.
fn flow_cookie_name(state: &str) -> Option<String> {
    let prefix: String = state.chars().take(12).collect();
    (prefix.len() == 12
        && prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then(|| format!("{STATE_COOKIE}_{prefix}"))
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/oidc; Max-Age=0")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ---------------------------------------------------------------------------------------------
// UI helpers for the login pages
// ---------------------------------------------------------------------------------------------

/// Extra HTML for the OAuth popup's login view: the "Sign in with …" button, and a style block
/// that hides the password and registration forms when `OIDC_HIDE_PASSWORD_LOGIN` is set.
/// Empty when OIDC login is off.
pub fn popup_login_html() -> String {
    let Some(p) = provider() else {
        return String::new();
    };
    let hide = if p.config.hide_password_login {
        "<style>#login_view form, #login_view .toggle_link, #register_view { display: none !important; } \
         .oidc_divider { display: none; }</style>"
    } else {
        ""
    };
    format!(
        r##"{hide}
                <a id="oidc_login" class="btn_primary oidc_login" href="#" onclick="startOidcLogin(event)" style="display:block;text-align:center;text-decoration:none;box-sizing:border-box;">Sign in with {name}</a>
                <div class="oidc_divider toggle_link">or use your e-mail and password</div>
                <script>
                    function startOidcLogin(e) {{
                        e.preventDefault();
                        const url = new URL(window.location.href);
                        // prompt=login would discard the session the provider is about to create.
                        url.searchParams.delete('prompt');
                        url.searchParams.delete('byok_pubkey');
                        url.searchParams.delete('default_register');
                        window.location.href = '/api/auth/oidc/start?return_to=' +
                            encodeURIComponent(url.pathname + url.search);
                    }}
                </script>"##,
        name = escape_html(&p.config.provider_name),
    )
}

#[derive(Serialize)]
pub struct OidcPublicConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    pub hide_password_login: bool,
}

/// GET /api/auth/oidc/config: what the web app needs to render its login page.
pub async fn oidc_config() -> Json<OidcPublicConfig> {
    Json(match provider() {
        Some(p) => OidcPublicConfig {
            enabled: true,
            provider_name: Some(p.config.provider_name.clone()),
            hide_password_login: p.config.hide_password_login,
        },
        None => OidcPublicConfig {
            enabled: false,
            provider_name: None,
            hide_password_login: false,
        },
    })
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{t}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5}}a{{color:inherit}}</style></head>
<body><h1>{t}</h1><p>{m}</p><p><a href="/">Back</a></p></body></html>"#,
        t = escape_html(title),
        m = escape_html(message),
    );
    // The flow cookie, if any, expires on its own (STATE_TTL_SECS).
    (status, Html(html)).into_response()
}

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        match &self {
            OidcError::Disabled => {
                error_page(StatusCode::NOT_FOUND, "Not available", &self.to_string())
            }
            OidcError::BadRequest(m) => error_page(StatusCode::BAD_REQUEST, "Sign-in failed", m),
            OidcError::Unauthorized(m) => error_page(StatusCode::UNAUTHORIZED, "Sign-in failed", m),
            OidcError::NoAccount(m) => error_page(StatusCode::FORBIDDEN, "No account", m),
            OidcError::Upstream(m) => {
                tracing::error!("OIDC upstream error: {m}");
                error_page(
                    StatusCode::BAD_GATEWAY,
                    "Sign-in unavailable",
                    "The sign-in provider could not be reached. Try again in a moment.",
                )
            }
            OidcError::Internal(m) => {
                tracing::error!("OIDC internal error: {m}");
                error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Sign-in failed",
                    "Internal error.",
                )
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StartParams {
    pub return_to: Option<String>,
}

/// GET /api/auth/oidc/start
pub async fn oidc_start(
    _tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Query(params): Query<StartParams>,
) -> Result<Response, OidcError> {
    let p = provider().ok_or(OidcError::Disabled)?;
    let return_to = safe_return_to(params.return_to.as_deref()).unwrap_or_else(|| "/".to_string());
    let redirect_origin = redirect_origin_for(&return_to, &p.config.app_origin)?;

    let flow = FlowState {
        state: random_b64(24),
        nonce: random_b64(24),
        verifier: random_b64(48),
        return_to,
        redirect_origin,
        expires_at: now_unix() + STATE_TTL_SECS,
    };
    let url = p
        .authorization_url(&flow.state, &flow.nonce, &pkce_challenge(&flow.verifier))
        .await?;
    let secret = auth_state.state.server_keys.secret_key().to_secret_bytes();
    let name = flow_cookie_name(&flow.state)
        .ok_or_else(|| OidcError::Internal("flow state is not URL-safe base64".to_string()))?;
    let cookie = format!(
        "{name}={}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/oidc; Max-Age={STATE_TTL_SECS}",
        seal_flow_state(&flow, &secret)
    );
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to(&url)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GET /api/auth/oidc/callback
pub async fn oidc_callback(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Result<Response, OidcError> {
    let p = provider().ok_or(OidcError::Disabled)?;
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let endpoint = "/api/auth/oidc/callback";

    let secret = auth_state.state.server_keys.secret_key().to_secret_bytes();
    let state_param = params.state.as_deref().unwrap_or("");
    let flow = flow_cookie_name(state_param)
        .and_then(|name| read_cookie(&headers, &name))
        .and_then(|v| open_flow_state(&v, &secret, now_unix()))
        .ok_or_else(|| {
            OidcError::BadRequest(
                "This sign-in was started in another browser, or it took longer than 10 minutes. \
                 Please start again."
                    .to_string(),
            )
        })?;
    if !constant_time_eq(state_param, &flow.state) {
        return Err(OidcError::BadRequest(
            "This page belongs to an older sign-in attempt. Please start again.".to_string(),
        ));
    }
    if let Some(err) = params.error {
        tracing::info!(error = %err, description = params.error_description.as_deref().unwrap_or(""), "OIDC provider returned an error");
        return Err(OidcError::Unauthorized(format!(
            "The sign-in provider ended the login ({err})."
        )));
    }
    let code = params
        .code
        .ok_or_else(|| OidcError::BadRequest("Missing code.".to_string()))?;

    let id_token = p.exchange_code(&code, &flow.verifier).await?;
    let claims = p.verify_id_token(&id_token, &flow.nonce).await?;
    let issuer = p.config.issuer.as_str();

    // Map the subject to an account: stored link first, then the link claim (first login).
    let identities = OidcIdentityRepository::new(pool.clone());
    let db_err =
        |e: keycast_core::repositories::RepositoryError| OidcError::Internal(e.to_string());
    let pubkey = match identities
        .find_pubkey(tenant_id, issuer, &claims.subject)
        .await
        .map_err(db_err)?
    {
        Some(pk) => pk,
        None => {
            let link = claims.link.as_deref().ok_or_else(|| {
                OidcError::NoAccount("This login is not linked to a signing account.".to_string())
            })?;
            let user_repo = UserRepository::new(pool.clone());
            let pk = user_repo
                .find_pubkey_by_vine_id(link, tenant_id)
                .await
                .map_err(db_err)?
                .ok_or_else(|| {
                    tracing::warn!(subject = %claims.subject, "OIDC login: link claim names no account");
                    OidcError::NoAccount("No signing account exists for this login yet.".to_string())
                })?;
            match identities
                .link(tenant_id, issuer, &claims.subject, &pk)
                .await
                .map_err(db_err)?
            {
                OidcLinkOutcome::Linked | OidcLinkOutcome::AlreadyLinked => pk,
                OidcLinkOutcome::Conflict => {
                    tracing::warn!(subject = %claims.subject, pubkey = %pk, "OIDC login: account already linked to another subject");
                    return Err(OidcError::NoAccount(
                        "This signing account is linked to a different login.".to_string(),
                    ));
                }
            }
        }
    };

    let user_repo = UserRepository::new(pool.clone());
    let account = user_repo
        .get_account_status(&pubkey, tenant_id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            OidcError::NoAccount("The linked signing account no longer exists.".to_string())
        })?;
    identities
        .touch(tenant_id, issuer, &claims.subject)
        .await
        .map_err(db_err)?;

    let user_pk = nostr_sdk::PublicKey::from_hex(&pubkey)
        .map_err(|e| OidcError::Internal(format!("stored pubkey: {e}")))?;
    let email = account.email.clone().unwrap_or_default();
    let status = (!account.status.is_active()).then_some(&account.status);
    let ucan = super::auth::generate_server_signed_ucan(
        &user_pk,
        tenant_id,
        &email,
        &flow.redirect_origin,
        None,
        &auth_state.state.server_keys,
        false,
        None,
        status,
    )
    .await
    .map_err(|e| OidcError::Internal(format!("UCAN: {e:?}")))?;

    super::auth_observability::record_auth_event_and_log(
        pool,
        &headers,
        None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint,
            event_type: "login",
            outcome: "success",
            reason_code: None,
            http_status: 303,
            email: None,
            pubkey: Some(&pubkey),
            client_id: None,
            redirect_origin: Some(&flow.redirect_origin),
            metadata_json: serde_json::json!({ "method": "oidc", "issuer": issuer }),
        },
    )
    .await;
    tracing::info!(event = "login", method = "oidc", tenant_id, "OIDC login");

    let session =
        format!("keycast_session={ucan}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400");
    // `flow.state` was read from its own cookie, so the name always exists.
    let clear =
        clear_cookie(&flow_cookie_name(&flow.state).unwrap_or_else(|| STATE_COOKIE.to_string()));
    let mut response = (
        AppendHeaders([(header::SET_COOKIE, session), (header::SET_COOKIE, clear)]),
        Redirect::to(&flow.return_to),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    #[test]
    fn flow_cookie_names_follow_the_state_prefix() {
        assert_eq!(
            flow_cookie_name("abcdefghijkl_rest").as_deref(),
            Some("keycast_oidc_abcdefghijkl")
        );
        assert_eq!(flow_cookie_name("short"), None);
        assert_eq!(flow_cookie_name("abc;defghijkl"), None);
        let a = random_b64(24);
        let b = random_b64(24);
        assert_ne!(flow_cookie_name(&a), flow_cookie_name(&b));
    }

    use super::*;

    fn config() -> OidcConfig {
        OidcConfig::from_lookup(|k| {
            Some(
                match k {
                    "OIDC_ISSUER" => "https://sso.example/application/o/keycast/",
                    "OIDC_CLIENT_ID" => "keycast",
                    "OIDC_CLIENT_SECRET" => "s3cret",
                    "OIDC_REDIRECT_URL" => "https://keys.example/api/auth/oidc/callback",
                    "APP_URL" => "https://keys.example",
                    _ => return None,
                }
                .to_string(),
            )
        })
        .unwrap()
        .unwrap()
    }

    #[test]
    fn config_off_without_issuer_and_strict_with_it() {
        assert!(OidcConfig::from_lookup(|_| None).unwrap().is_none());
        let err =
            OidcConfig::from_lookup(|k| (k == "OIDC_ISSUER").then(|| "https://x/".to_string()))
                .unwrap_err();
        assert!(err.contains("required"), "{err}");
        let c = config();
        assert_eq!(c.app_origin, "https://keys.example");
        assert_eq!(c.link_claim, "keycast_vine_id");
        assert!(!c.hide_password_login);
    }

    #[test]
    fn backchannel_rewrites_only_the_issuer_origin() {
        let mut c = config();
        c.issuer = "http://localhost:9000/application/o/keycast/".into();
        c.backchannel_url = Some("http://idp:8080".into());
        let p = OidcProvider::new(c);
        let (url, host) = p
            .backchannel("http://localhost:9000/application/o/token/")
            .unwrap();
        assert_eq!(url, "http://idp:8080/application/o/token/");
        assert_eq!(host.as_deref(), Some("localhost:9000"));
        let (url, host) = p.backchannel("https://elsewhere.example/jwks").unwrap();
        assert_eq!(url, "https://elsewhere.example/jwks");
        assert!(host.is_none());
    }

    #[test]
    fn flow_state_roundtrip_tamper_and_expiry() {
        let flow = FlowState {
            state: "st".into(),
            nonce: "no".into(),
            verifier: "ve".into(),
            return_to: "/api/oauth/authorize?client_id=a".into(),
            redirect_origin: "https://app.example".into(),
            expires_at: 1_000,
        };
        let sealed = seal_flow_state(&flow, b"k1");
        assert_eq!(open_flow_state(&sealed, b"k1", 999), Some(flow.clone()));
        assert_eq!(open_flow_state(&sealed, b"k1", 1_000), None, "expired");
        assert_eq!(open_flow_state(&sealed, b"k2", 999), None, "other key");
        let (payload, tag) = sealed.split_once('.').unwrap();
        let mut forged = flow.clone();
        forged.return_to = "/evil".into();
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        assert_eq!(
            open_flow_state(&format!("{forged_payload}.{tag}"), b"k1", 999),
            None
        );
        assert_eq!(open_flow_state(payload, b"k1", 999), None, "no tag");
    }

    #[test]
    fn pkce_matches_rfc7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn return_to_accepts_relative_paths_only() {
        assert_eq!(safe_return_to(Some("/")).as_deref(), Some("/"));
        assert_eq!(
            safe_return_to(Some(
                "/api/oauth/authorize?client_id=a&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"
            ))
            .as_deref(),
            Some("/api/oauth/authorize?client_id=a&redirect_uri=https%3A%2F%2Fapp.example%2Fcb")
        );
        for bad in [
            "https://evil.example/",
            "//evil.example",
            "/\\evil.example",
            "/\t/evil",
            "evil",
            "",
        ] {
            assert_eq!(safe_return_to(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(safe_return_to(None), None);
        assert_eq!(safe_return_to(Some("/%2e%2e//evil.example")), None);
    }

    #[test]
    fn redirect_origin_follows_the_oauth_request() {
        let o = redirect_origin_for(
            "/api/oauth/authorize?client_id=a&redirect_uri=https%3A%2F%2Fapp.example%3A8443%2Fcb",
            "https://keys.example",
        )
        .unwrap();
        assert_eq!(o, "https://app.example:8443");
        assert_eq!(
            redirect_origin_for("/settings", "https://keys.example").unwrap(),
            "https://keys.example"
        );
        assert!(
            redirect_origin_for("/api/oauth/authorize?client_id=a", "https://keys.example")
                .is_err()
        );
    }

    fn rsa_jwks(kp: &RS256KeyPair, kid: &str) -> Vec<Jwk> {
        let c = kp.public_key().to_components();
        vec![Jwk {
            kty: "RSA".into(),
            kid: Some(kid.into()),
            use_: Some("sig".into()),
            n: Some(URL_SAFE_NO_PAD.encode(c.n)),
            e: Some(URL_SAFE_NO_PAD.encode(c.e)),
            crv: None,
            x: None,
            y: None,
        }]
    }

    fn id_token(
        kp: &RS256KeyPair,
        kid: &str,
        iss: &str,
        aud: &str,
        nonce: &str,
        extra: serde_json::Value,
    ) -> String {
        let extra = ExtraClaims {
            fields: extra.as_object().cloned().unwrap_or_default(),
        };
        let claims = Claims::with_custom_claims(extra, Duration::from_mins(5))
            .with_issuer(iss)
            .with_audience(aud)
            .with_subject("idp-sub-1")
            .with_nonce(nonce);
        kp.clone().with_key_id(kid).sign(claims).unwrap()
    }

    #[test]
    fn rs256_id_token_is_verified_and_claims_extracted() {
        let c = config();
        let kp = RS256KeyPair::generate(2048).unwrap();
        let keys = rsa_jwks(&kp, "k1");
        let tok = id_token(
            &kp,
            "k1",
            &c.issuer,
            "keycast",
            "n0",
            serde_json::json!({"email": "Alice@Example.org", "keycast_vine_id": "vine-7"}),
        );
        let claims = verify_id_token_with_keys(&tok, &keys, &c, "n0").unwrap();
        assert_eq!(
            claims,
            IdTokenClaims {
                subject: "idp-sub-1".into(),
                email: Some("alice@example.org".into()),
                link: Some("vine-7".into())
            }
        );

        let numeric = id_token(
            &kp,
            "k1",
            &c.issuer,
            "keycast",
            "n0",
            serde_json::json!({"keycast_vine_id": 7}),
        );
        assert_eq!(
            verify_id_token_with_keys(&numeric, &keys, &c, "n0")
                .unwrap()
                .link
                .as_deref(),
            Some("7")
        );
    }

    #[test]
    fn id_token_rejections() {
        let c = config();
        let kp = RS256KeyPair::generate(2048).unwrap();
        let keys = rsa_jwks(&kp, "k1");
        let ok = |iss: &str, aud: &str, nonce: &str| {
            id_token(&kp, "k1", iss, aud, nonce, serde_json::json!({}))
        };

        assert!(
            matches!(
                verify_id_token_with_keys(&ok(&c.issuer, "keycast", "n0"), &keys, &c, "other"),
                Err(VerifyError::Invalid(_))
            ),
            "nonce"
        );
        assert!(
            matches!(
                verify_id_token_with_keys(&ok("https://evil/", "keycast", "n0"), &keys, &c, "n0"),
                Err(VerifyError::Invalid(_))
            ),
            "issuer"
        );
        assert!(
            matches!(
                verify_id_token_with_keys(&ok(&c.issuer, "someone-else", "n0"), &keys, &c, "n0"),
                Err(VerifyError::Invalid(_))
            ),
            "audience"
        );

        let unknown_kid = id_token(&kp, "k2", &c.issuer, "keycast", "n0", serde_json::json!({}));
        assert!(matches!(
            verify_id_token_with_keys(&unknown_kid, &keys, &c, "n0"),
            Err(VerifyError::UnknownKey)
        ));

        let other = RS256KeyPair::generate(2048).unwrap();
        let forged = id_token(
            &other,
            "k1",
            &c.issuer,
            "keycast",
            "n0",
            serde_json::json!({}),
        );
        assert!(
            matches!(
                verify_id_token_with_keys(&forged, &keys, &c, "n0"),
                Err(VerifyError::Invalid(_))
            ),
            "signature"
        );

        // HS256 with the public key as secret (alg confusion) is refused outright.
        let hs = HS256Key::from_bytes(b"a-long-enough-shared-secret-0123456789").with_key_id("k1");
        let hs_tok = hs
            .authenticate(
                Claims::create(Duration::from_mins(5))
                    .with_issuer(&c.issuer)
                    .with_audience("keycast")
                    .with_subject("x")
                    .with_nonce("n0"),
            )
            .unwrap();
        assert!(matches!(
            verify_id_token_with_keys(&hs_tok, &keys, &c, "n0"),
            Err(VerifyError::Invalid(_))
        ));
    }

    #[test]
    fn es256_id_token_is_verified() {
        let c = config();
        let kp = ES256KeyPair::generate().with_key_id("e1");
        let pk = kp.public_key().public_key().to_bytes_uncompressed();
        let keys = vec![Jwk {
            kty: "EC".into(),
            kid: Some("e1".into()),
            use_: None,
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(URL_SAFE_NO_PAD.encode(&pk[1..33])),
            y: Some(URL_SAFE_NO_PAD.encode(&pk[33..65])),
        }];
        let claims = Claims::with_custom_claims(ExtraClaims::default(), Duration::from_mins(5))
            .with_issuer(&c.issuer)
            .with_audience("keycast")
            .with_subject("idp-sub-2")
            .with_nonce("n1");
        let tok = kp.sign(claims).unwrap();
        assert_eq!(
            verify_id_token_with_keys(&tok, &keys, &c, "n1")
                .unwrap()
                .subject,
            "idp-sub-2"
        );
    }
}
