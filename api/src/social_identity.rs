// ABOUTME: Verifies Google and Apple ID tokens for "Continue with Google / Apple"
// ABOUTME: Caches provider signing keys and exchanges Apple authorization codes for refresh tokens

use crate::api::http::auth::normalize_registration_email;
use crate::api::http::expensive_work::admit_remote_fetch;
use async_trait::async_trait;
use base64::Engine;
use jwt_simple::prelude::{
    Audiences, Claims, Duration as JwtDuration, ECDSAP256KeyPairLike, ES256KeyPair, JWTClaims,
    RS256PublicKey, RSAPublicKeyLike, Token, VerificationOptions,
};
use jwt_simple::JWTError;
use keycast_core::social_login::{SocialProvider, VerifiedSocialIdentity};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
pub const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
pub const APPLE_TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const APPLE_REVOCATION_URL: &str = "https://appleid.apple.com/auth/revoke";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const APPLE_ISSUER: &str = "https://appleid.apple.com";
/// Google is authoritative for these addresses: nobody else can own them.
const GOOGLE_CONSUMER_DOMAINS: [&str; 2] = ["gmail.com", "googlemail.com"];

pub const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;
pub const MAX_RAW_NONCE_BYTES: usize = 256;
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 1024;
const MAX_SUBJECT_BYTES: usize = 255;
const MAX_REMOTE_BODY_BYTES: usize = 64 * 1024;
const REMOTE_TIMEOUT: Duration = Duration::from_secs(5);
/// Clock drift tolerated on `exp`, `iat` and `nbf`.
pub const CLOCK_SKEW_SECONDS: u64 = 60;
/// Provider keys are reused for this long before they are fetched again.
pub const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(60 * 60);
/// Fetches triggered by an unknown key id or a failed fetch happen at most this often.
pub const DEFAULT_MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);
/// While no key has ever been fetched, retry sooner so a blip at startup is short-lived.
const NO_KEYS_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Apple client secrets are minted per exchange and only need to outlive the request.
const APPLE_CLIENT_SECRET_LIFETIME_SECONDS: u64 = 5 * 60;

// ============================================================================
// Settings
// ============================================================================

/// Google token audiences.
///
/// Native apps ask Google for an ID token addressed to the server (web) client, so `aud` is the
/// server client ID and `azp` is the iOS or Android client that asked for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GoogleSettings {
    /// Accepted `aud` values: the server (web) OAuth client IDs.
    pub audiences: Vec<String>,
    /// Accepted `azp` values: the iOS and Android OAuth client IDs.
    pub authorized_parties: Vec<String>,
}

/// Apple token audiences: the app bundle IDs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppleSettings {
    pub audiences: Vec<String>,
}

/// Google on Keycast's hosted login page, through Google Identity Services.
///
/// The page renders Google's button with this public web client ID, so the token's `aud` and
/// `azp` are both this client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleWebSettings {
    pub client_id: String,
}

/// Apple on Keycast's hosted login page, through Sign in with Apple JS.
///
/// App bundle IDs cannot be used on the web: the page signs in with a Services ID, which becomes
/// the token's `aud`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppleWebSettings {
    pub services_id: String,
    /// Return URL registered for the Services ID. Apple's popup only answers a page on this URL's
    /// origin, and the code exchange must repeat it.
    pub redirect_uri: String,
}

/// Where an ID token was obtained, which decides the audiences it may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInChannel {
    /// A native app, through `POST /api/headless/social-login`.
    App,
    /// Keycast's hosted login page, through `POST /api/oauth/social-login`.
    Web,
}

/// Sign in with Apple key used to mint client secrets for the code exchange.
#[derive(Clone)]
pub struct AppleSigningKey {
    pub team_id: String,
    pub key_id: String,
    /// PKCS#8 PEM (`.p8` file contents).
    pub private_key_pem: SecretString,
}

impl std::fmt::Debug for AppleSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppleSigningKey")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// Which providers are accepted, read from the environment. A provider that is not configured
/// answers `503 PROVIDER_UNAVAILABLE`, so the server starts without any of these variables.
#[derive(Clone, Debug, Default)]
pub struct SocialLoginSettings {
    /// Native apps.
    pub google: Option<GoogleSettings>,
    /// Native apps.
    pub apple: Option<AppleSettings>,
    /// The hosted login page.
    pub google_web: Option<GoogleWebSettings>,
    /// The hosted login page.
    pub apple_web: Option<AppleWebSettings>,
    pub apple_signing_key: Option<AppleSigningKey>,
}

impl SocialLoginSettings {
    /// Read `GOOGLE_CLIENT_IDS`, `GOOGLE_AUTHORIZED_PARTIES`, `APPLE_CLIENT_IDS` (native apps),
    /// `GOOGLE_WEB_CLIENT_ID`, `APPLE_SERVICES_ID`, `APPLE_WEB_REDIRECT_URI` (hosted login page),
    /// and `APPLE_TEAM_ID`, `APPLE_KEY_ID` and `APPLE_PRIVATE_KEY` (Apple code exchange).
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let google_audiences = comma_list(lookup("GOOGLE_CLIENT_IDS"));
        let google_parties = comma_list(lookup("GOOGLE_AUTHORIZED_PARTIES"));
        let google = match (google_audiences.is_empty(), google_parties.is_empty()) {
            (false, false) => Some(GoogleSettings {
                audiences: google_audiences,
                authorized_parties: google_parties,
            }),
            (true, true) => None,
            _ => {
                tracing::warn!(
                    "Google sign-in needs both GOOGLE_CLIENT_IDS and GOOGLE_AUTHORIZED_PARTIES; \
                     it stays off"
                );
                None
            }
        };

        let apple_audiences = comma_list(lookup("APPLE_CLIENT_IDS"));
        let apple = (!apple_audiences.is_empty()).then_some(AppleSettings {
            audiences: apple_audiences,
        });

        let google_web = non_empty(lookup("GOOGLE_WEB_CLIENT_ID"))
            .map(|client_id| GoogleWebSettings { client_id });

        let apple_web = match (
            non_empty(lookup("APPLE_SERVICES_ID")),
            non_empty(lookup("APPLE_WEB_REDIRECT_URI")),
        ) {
            (Some(services_id), Some(redirect_uri)) if is_web_redirect_uri(&redirect_uri) => {
                Some(AppleWebSettings {
                    services_id,
                    redirect_uri,
                })
            }
            (Some(_), Some(_)) => {
                tracing::warn!(
                    "APPLE_WEB_REDIRECT_URI must be an absolute http(s) URL; \
                     Sign in with Apple on the login page stays off"
                );
                None
            }
            (None, None) => None,
            _ => {
                tracing::warn!(
                    "Sign in with Apple on the login page needs both APPLE_SERVICES_ID and \
                     APPLE_WEB_REDIRECT_URI; it stays off"
                );
                None
            }
        };

        let team_id = non_empty(lookup("APPLE_TEAM_ID"));
        let key_id = non_empty(lookup("APPLE_KEY_ID"));
        let private_key = non_empty(lookup("APPLE_PRIVATE_KEY"));
        let apple_signing_key = match (team_id, key_id, private_key) {
            (Some(team_id), Some(key_id), Some(private_key)) => Some(AppleSigningKey {
                team_id,
                key_id,
                // Secret managers and .env files often carry the PEM with escaped newlines.
                private_key_pem: SecretString::from(private_key.replace("\\n", "\n")),
            }),
            (None, None, None) => None,
            _ => {
                tracing::warn!(
                    "Apple code exchange needs APPLE_TEAM_ID, APPLE_KEY_ID and APPLE_PRIVATE_KEY; \
                     refresh tokens will not be stored"
                );
                None
            }
        };

        Self {
            google,
            apple,
            google_web,
            apple_web,
            apple_signing_key,
        }
    }
}

fn is_web_redirect_uri(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "https" | "http")
            && url.host_str().is_some_and(|host| !host.is_empty())
    })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn comma_list(value: Option<String>) -> Vec<String> {
    let mut items: Vec<String> = Vec::new();
    for item in value.unwrap_or_default().split(',') {
        let item = item.trim();
        if !item.is_empty() && !items.iter().any(|existing| existing == item) {
            items.push(item.to_string());
        }
    }
    items
}

// ============================================================================
// Provider signing keys
// ============================================================================

/// One key from a provider's JWKS document.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

/// A provider's JWKS document.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    #[error("remote fetch capacity is busy")]
    Busy,
    #[error("{0}")]
    Failed(String),
}

/// Source of provider signing keys. Production fetches over HTTPS; tests supply their own.
#[async_trait]
pub trait JwksFetcher: Send + Sync {
    async fn fetch(&self, provider: SocialProvider) -> Result<JwkSet, JwksFetchError>;
}

/// Fetches JWKS documents from Google and Apple.
pub struct HttpJwksFetcher {
    client: reqwest::Client,
}

impl HttpJwksFetcher {
    pub fn new() -> Self {
        Self {
            client: bounded_client(),
        }
    }
}

impl Default for HttpJwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self, provider: SocialProvider) -> Result<JwkSet, JwksFetchError> {
        let url = match provider {
            SocialProvider::Google => GOOGLE_JWKS_URL,
            SocialProvider::Apple => APPLE_JWKS_URL,
        };
        let _permit = admit_remote_fetch().map_err(|_| JwksFetchError::Busy)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| JwksFetchError::Failed(format!("request failed: {error}")))?;
        if !response.status().is_success() {
            return Err(JwksFetchError::Failed(format!(
                "returned {}",
                response.status()
            )));
        }
        let body = read_bounded_body(response)
            .await
            .map_err(JwksFetchError::Failed)?;
        serde_json::from_slice(&body)
            .map_err(|error| JwksFetchError::Failed(format!("invalid JWKS JSON: {error}")))
    }
}

fn bounded_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REMOTE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|error| {
            tracing::error!("Falling back to a default HTTP client for social login: {error}");
            reqwest::Client::new()
        })
}

async fn read_bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    if response.content_length().unwrap_or(0) > MAX_REMOTE_BODY_BYTES as u64 {
        return Err("response is too large".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read response: {error}"))?
    {
        if chunk.len() > MAX_REMOTE_BODY_BYTES.saturating_sub(body.len()) {
            return Err("response is too large".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Turn a JWKS document into RS256 verification keys by key id. Keys of any other type or
/// algorithm are ignored.
pub fn parse_jwks(set: &JwkSet) -> HashMap<String, RS256PublicKey> {
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        if jwk.kty != "RSA"
            || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
            || jwk
                .key_use
                .as_deref()
                .is_some_and(|key_use| key_use != "sig")
        {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (&jwk.kid, &jwk.n, &jwk.e) else {
            continue;
        };
        let (Some(n), Some(e)) = (decode_base64url(n), decode_base64url(e)) else {
            continue;
        };
        match RS256PublicKey::from_components(&n, &e) {
            Ok(key) => {
                keys.insert(kid.clone(), key);
            }
            Err(error) => tracing::warn!(kid = %kid, "Ignoring unusable provider key: {error}"),
        }
    }
    keys
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .ok()
}

struct CachedKeys {
    keys: HashMap<String, RS256PublicKey>,
    fetched_at: Instant,
}

#[derive(Default)]
struct RefreshState {
    last_attempt: Option<Instant>,
    last_failed: bool,
}

/// Signing keys of one provider. Fresh keys are reused for the TTL; when a fetch fails the
/// previous keys stay in use, so a provider outage does not stop sign-in with known keys.
#[derive(Default)]
struct ProviderKeys {
    cached: RwLock<Option<CachedKeys>>,
    refresh: tokio::sync::Mutex<RefreshState>,
}

impl ProviderKeys {
    /// A key that is cached and still fresh.
    fn fresh(&self, kid: &str, ttl: Duration) -> Option<RS256PublicKey> {
        let cached = self
            .cached
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        cached
            .as_ref()
            .filter(|cached| cached.fetched_at.elapsed() < ttl)
            .and_then(|cached| cached.keys.get(kid).cloned())
    }

    fn stored(&self, kid: &str) -> Option<RS256PublicKey> {
        let cached = self
            .cached
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        cached
            .as_ref()
            .and_then(|cached| cached.keys.get(kid).cloned())
    }

    fn has_keys(&self) -> bool {
        let cached = self
            .cached
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        cached
            .as_ref()
            .is_some_and(|cached| !cached.keys.is_empty())
    }

    fn replace(&self, keys: HashMap<String, RS256PublicKey>) {
        let mut cached = self
            .cached
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *cached = Some(CachedKeys {
            keys,
            fetched_at: Instant::now(),
        });
    }
}

// ============================================================================
// Verification
// ============================================================================

/// Why an ID token was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SocialTokenError {
    #[error("{0} sign-in is not configured")]
    NotConfigured(SocialProvider),
    #[error("identity provider keys are unavailable")]
    ProviderUnavailable,
    #[error("invalid ID token: {0}")]
    Invalid(&'static str),
}

/// A verified ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdToken {
    pub identity: VerifiedSocialIdentity,
    /// The configured client ID the token was addressed to.
    pub audience: String,
    /// Lowercase hex SHA-256 of the token, used as the replay key.
    pub token_hash: String,
    /// `exp` in Unix seconds.
    pub expires_at: u64,
}

/// Claims Google and Apple add beyond the registered JWT claims.
#[derive(Debug, Default, Deserialize)]
struct ProviderClaims {
    #[serde(default)]
    email: Option<String>,
    /// Google sends a boolean, Apple a boolean or the string "true".
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    hd: Option<String>,
}

fn claim_is_true(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(value)) => *value,
        Some(serde_json::Value::String(value)) => value.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Verifies Google and Apple ID tokens.
pub struct SocialIdentityVerifier {
    settings: SocialLoginSettings,
    fetcher: Arc<dyn JwksFetcher>,
    google_keys: ProviderKeys,
    apple_keys: ProviderKeys,
    jwks_ttl: Duration,
    min_refetch_interval: Duration,
}

impl SocialIdentityVerifier {
    pub fn new(settings: SocialLoginSettings, fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            settings,
            fetcher,
            google_keys: ProviderKeys::default(),
            apple_keys: ProviderKeys::default(),
            jwks_ttl: DEFAULT_JWKS_TTL,
            min_refetch_interval: DEFAULT_MIN_REFETCH_INTERVAL,
        }
    }

    /// Override key caching, e.g. to exercise refetching in tests.
    #[must_use]
    pub fn with_jwks_timing(mut self, ttl: Duration, min_refetch_interval: Duration) -> Self {
        self.jwks_ttl = ttl;
        self.min_refetch_interval = min_refetch_interval;
        self
    }

    pub fn settings(&self) -> &SocialLoginSettings {
        &self.settings
    }

    /// Whether `provider` can be used from `channel`.
    pub fn is_configured(&self, provider: SocialProvider, channel: SignInChannel) -> bool {
        self.audience_rule(provider, channel).is_ok()
    }

    /// The issuers, audiences and authorized parties a token from `channel` may carry.
    fn audience_rule(
        &self,
        provider: SocialProvider,
        channel: SignInChannel,
    ) -> Result<AudienceRule, SocialTokenError> {
        let not_configured = SocialTokenError::NotConfigured(provider);
        let rule = match (provider, channel) {
            (SocialProvider::Google, SignInChannel::App) => {
                let google = self.settings.google.as_ref().ok_or(not_configured)?;
                AudienceRule {
                    audiences: google.audiences.iter().cloned().collect(),
                    party: PartyRule::OneOf(google.authorized_parties.iter().cloned().collect()),
                }
            }
            (SocialProvider::Google, SignInChannel::Web) => {
                let google = self.settings.google_web.as_ref().ok_or(not_configured)?;
                AudienceRule {
                    audiences: HashSet::from([google.client_id.clone()]),
                    party: PartyRule::AudienceItself,
                }
            }
            (SocialProvider::Apple, SignInChannel::App) => {
                let apple = self.settings.apple.as_ref().ok_or(not_configured)?;
                AudienceRule {
                    audiences: apple.audiences.iter().cloned().collect(),
                    party: PartyRule::Ignored,
                }
            }
            (SocialProvider::Apple, SignInChannel::Web) => {
                let apple = self.settings.apple_web.as_ref().ok_or(not_configured)?;
                AudienceRule {
                    audiences: HashSet::from([apple.services_id.clone()]),
                    party: PartyRule::Ignored,
                }
            }
        };
        Ok(rule)
    }

    fn keys(&self, provider: SocialProvider) -> &ProviderKeys {
        match provider {
            SocialProvider::Google => &self.google_keys,
            SocialProvider::Apple => &self.apple_keys,
        }
    }

    /// Verify a provider ID token: RS256 signature by a current provider key, issuer, an audience
    /// (and for Google an authorized party) configured for `channel`, expiry, issue time, and
    /// `nonce == sha256(raw_nonce)`.
    pub async fn verify(
        &self,
        provider: SocialProvider,
        channel: SignInChannel,
        id_token: &str,
        raw_nonce: &str,
    ) -> Result<VerifiedIdToken, SocialTokenError> {
        let rule = self.audience_rule(provider, channel)?;
        let issuers: HashSet<String> = match provider {
            SocialProvider::Google => GOOGLE_ISSUERS
                .iter()
                .map(|issuer| issuer.to_string())
                .collect(),
            SocialProvider::Apple => HashSet::from([APPLE_ISSUER.to_string()]),
        };

        if raw_nonce.is_empty() || raw_nonce.len() > MAX_RAW_NONCE_BYTES {
            return Err(SocialTokenError::Invalid("invalid_nonce"));
        }

        let options = VerificationOptions {
            allowed_issuers: Some(issuers),
            allowed_audiences: Some(rule.audiences.clone()),
            required_nonce: Some(sha256_hex(raw_nonce)),
            time_tolerance: Some(JwtDuration::from_secs(CLOCK_SKEW_SECONDS)),
            max_token_length: Some(MAX_ID_TOKEN_BYTES),
            ..Default::default()
        };
        let claims = self.verify_claims(provider, id_token, options).await?;

        let expires_at = claims
            .expires_at
            .ok_or(SocialTokenError::Invalid("missing_expiry"))?
            .as_secs();
        if claims.issued_at.is_none() {
            return Err(SocialTokenError::Invalid("missing_issued_at"));
        }
        let subject = claims
            .subject
            .filter(|subject| !subject.is_empty() && subject.len() <= MAX_SUBJECT_BYTES)
            .ok_or(SocialTokenError::Invalid("missing_subject"))?;
        let audience = matched_audience(claims.audiences.as_ref(), &rule.audiences)
            .ok_or(SocialTokenError::Invalid("wrong_audience"))?;

        let custom = claims.custom;
        let authorized = match &rule.party {
            PartyRule::Ignored => true,
            PartyRule::OneOf(parties) => custom
                .azp
                .as_deref()
                .is_some_and(|azp| parties.contains(azp)),
            PartyRule::AudienceItself => custom.azp.as_deref().is_none_or(|azp| azp == audience),
        };
        if !authorized {
            return Err(SocialTokenError::Invalid("unauthorized_party"));
        }

        let email = custom
            .email
            .as_deref()
            .and_then(|email| normalize_registration_email(email).ok());
        let email_verified = claim_is_true(custom.email_verified.as_ref());
        let email_authoritative = email_verified
            && match provider {
                SocialProvider::Google => {
                    custom.hd.as_deref().is_some_and(|hd| !hd.trim().is_empty())
                        || email.as_deref().is_some_and(|email| {
                            email.rsplit_once('@').is_some_and(|(_, domain)| {
                                GOOGLE_CONSUMER_DOMAINS.contains(&domain)
                            })
                        })
                }
                SocialProvider::Apple => true,
            };

        Ok(VerifiedIdToken {
            identity: VerifiedSocialIdentity {
                provider,
                subject,
                email,
                email_verified,
                email_authoritative,
            },
            audience,
            token_hash: sha256_hex(id_token),
            expires_at,
        })
    }

    async fn verify_claims(
        &self,
        provider: SocialProvider,
        id_token: &str,
        options: VerificationOptions,
    ) -> Result<JWTClaims<ProviderClaims>, SocialTokenError> {
        if id_token.is_empty() || id_token.len() > MAX_ID_TOKEN_BYTES {
            return Err(SocialTokenError::Invalid("malformed"));
        }
        let metadata =
            Token::decode_metadata(id_token).map_err(|_| SocialTokenError::Invalid("malformed"))?;
        if metadata.algorithm() != "RS256" {
            return Err(SocialTokenError::Invalid("unsupported_algorithm"));
        }
        let kid = metadata
            .key_id()
            .ok_or(SocialTokenError::Invalid("missing_key_id"))?;
        self.signing_key(provider, kid)
            .await?
            .verify_token::<ProviderClaims>(id_token, Some(options))
            .map_err(|error| SocialTokenError::Invalid(classify_jwt_error(&error)))
    }

    pub(crate) async fn verify_apple_grant(
        &self,
        id_token: &str,
        login: &VerifiedIdToken,
    ) -> Result<(), SocialTokenError> {
        let claims = self
            .verify_claims(
                SocialProvider::Apple,
                id_token,
                VerificationOptions {
                    allowed_issuers: Some(HashSet::from([APPLE_ISSUER.to_string()])),
                    allowed_audiences: Some(HashSet::from([login.audience.clone()])),
                    time_tolerance: Some(JwtDuration::from_secs(CLOCK_SKEW_SECONDS)),
                    max_token_length: Some(MAX_ID_TOKEN_BYTES),
                    ..Default::default()
                },
            )
            .await?;
        if claims.subject.as_deref() != Some(login.identity.subject.as_str())
            || claims.expires_at.is_none()
            || claims.issued_at.is_none()
        {
            return Err(SocialTokenError::Invalid("invalid_grant_identity"));
        }
        Ok(())
    }

    async fn signing_key(
        &self,
        provider: SocialProvider,
        kid: &str,
    ) -> Result<RS256PublicKey, SocialTokenError> {
        let keys = self.keys(provider);
        if let Some(key) = keys.fresh(kid, self.jwks_ttl) {
            return Ok(key);
        }

        let mut refresh = keys.refresh.lock().await;
        // Another request may have refreshed while this one waited.
        if let Some(key) = keys.fresh(kid, self.jwks_ttl) {
            return Ok(key);
        }
        let retry_interval = if keys.has_keys() {
            self.min_refetch_interval
        } else {
            self.min_refetch_interval.min(NO_KEYS_RETRY_INTERVAL)
        };
        let may_fetch = refresh
            .last_attempt
            .is_none_or(|attempt| attempt.elapsed() >= retry_interval);
        if may_fetch {
            let previous_attempt = refresh.last_attempt.replace(Instant::now());
            match self.fetcher.fetch(provider).await {
                Ok(set) => {
                    let parsed = parse_jwks(&set);
                    if parsed.is_empty() {
                        refresh.last_failed = true;
                        tracing::warn!(%provider, "Provider JWKS contained no usable keys");
                    } else {
                        refresh.last_failed = false;
                        keys.replace(parsed);
                    }
                }
                Err(JwksFetchError::Busy) => {
                    // Nothing was sent, so this does not count against the refetch interval.
                    refresh.last_attempt = previous_attempt;
                    refresh.last_failed = true;
                    tracing::warn!(%provider, "Provider JWKS fetch skipped: outbound capacity busy");
                }
                Err(error) => {
                    refresh.last_failed = true;
                    tracing::warn!(%provider, "Provider JWKS fetch failed: {error}");
                }
            }
        }
        let last_failed = refresh.last_failed;
        drop(refresh);

        // Stale keys stay usable while the provider cannot be reached.
        if let Some(key) = keys.stored(kid) {
            return Ok(key);
        }
        if last_failed || !keys.has_keys() {
            return Err(SocialTokenError::ProviderUnavailable);
        }
        Err(SocialTokenError::Invalid("unknown_key"))
    }
}

/// What a token from one channel must be addressed to.
struct AudienceRule {
    audiences: HashSet<String>,
    party: PartyRule,
}

/// How Google's `azp` (authorized party) is checked.
enum PartyRule {
    /// Apple tokens: no authorized party to check.
    Ignored,
    /// Native Google tokens: `azp` is the iOS or Android client that asked for the token.
    OneOf(HashSet<String>),
    /// Google Identity Services tokens: `azp`, when present, is the web client itself, so a
    /// token a native app obtained for the same server client is not accepted here.
    AudienceItself,
}

fn matched_audience(audiences: Option<&Audiences>, allowed: &HashSet<String>) -> Option<String> {
    match audiences? {
        Audiences::AsString(audience) => allowed.contains(audience).then(|| audience.clone()),
        Audiences::AsSet(set) => {
            let mut matched: Vec<&String> = set.intersection(allowed).collect();
            matched.sort();
            matched.first().map(|audience| (*audience).clone())
        }
    }
}

fn classify_jwt_error(error: &jwt_simple::Error) -> &'static str {
    match error.downcast_ref::<JWTError>() {
        Some(JWTError::InvalidSignature) => "invalid_signature",
        Some(JWTError::TokenHasExpired) => "expired",
        Some(JWTError::ClockDrift | JWTError::TokenNotValidYet) => "not_yet_valid",
        Some(JWTError::RequiredIssuerMismatch | JWTError::RequiredIssuerMissing) => "wrong_issuer",
        Some(JWTError::RequiredAudienceMismatch | JWTError::RequiredAudienceMissing) => {
            "wrong_audience"
        }
        Some(JWTError::RequiredNonceMismatch | JWTError::RequiredNonceMissing) => "nonce_mismatch",
        Some(JWTError::AlgorithmMismatch) => "unsupported_algorithm",
        Some(JWTError::TokenTooLong) => "malformed",
        _ => "invalid",
    }
}

// ============================================================================
// Apple authorization code exchange
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum AppleExchangeError {
    #[error("grant identity could not be verified")]
    UnverifiedIdentity,
    #[error("remote fetch capacity is busy")]
    Busy,
    #[error("client secret could not be signed: {0}")]
    ClientSecret(String),
    #[error("Apple token endpoint: {0}")]
    Remote(String),
}

#[derive(Deserialize)]
struct AppleTokenResponse {
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

pub(crate) struct AppleGrant {
    pub(crate) refresh_token: SecretString,
    pub(crate) id_token: SecretString,
}

/// Exchanges Apple authorization codes for refresh tokens, so a grant can later be revoked.
pub struct AppleTokenClient {
    team_id: String,
    /// Carries the Sign in with Apple key id, which Apple requires in the secret's header.
    key_pair: ES256KeyPair,
    token_url: String,
    revoke_url: String,
    client: reqwest::Client,
}

impl AppleTokenClient {
    pub(crate) async fn revoke(
        &self,
        client_id: &str,
        token: &str,
    ) -> Result<(), AppleExchangeError> {
        let secret = self.client_secret(client_id)?;
        let _permit = admit_remote_fetch().map_err(|_| AppleExchangeError::Busy)?;
        let response = self
            .client
            .post(&self.revoke_url)
            .form(&[
                ("client_id", client_id),
                ("client_secret", secret.as_str()),
                ("token", token),
                ("token_type_hint", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|_| AppleExchangeError::Remote("revocation request failed".into()))?;
        if !response.status().is_success() {
            return Err(AppleExchangeError::Remote(format!(
                "revocation returned {}",
                response.status()
            )));
        }
        Ok(())
    }

    /// Build a client from configured settings. `None` when no signing key is configured or the
    /// key cannot be read; sign-in still works, but no refresh token is stored.
    pub fn from_settings(settings: &SocialLoginSettings) -> Option<Self> {
        let signing_key = settings.apple_signing_key.as_ref()?;
        match ES256KeyPair::from_pem(signing_key.private_key_pem.expose_secret()) {
            Ok(key_pair) => Some(Self {
                team_id: signing_key.team_id.clone(),
                key_pair: key_pair.with_key_id(&signing_key.key_id),
                token_url: APPLE_TOKEN_URL.to_string(),
                revoke_url: APPLE_REVOCATION_URL.to_string(),
                client: bounded_client(),
            }),
            Err(error) => {
                tracing::error!("APPLE_PRIVATE_KEY is not a usable PKCS#8 P-256 key: {error}");
                None
            }
        }
    }

    /// Point the client at another token endpoint (tests).
    #[must_use]
    pub fn with_token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = token_url.into();
        self
    }

    #[cfg(all(test, feature = "integration-tests"))]
    pub(crate) fn with_revoke_url(mut self, url: String) -> Self {
        self.revoke_url = url;
        self
    }

    /// Client secret for `client_id`: an ES256 JWT signed with the Sign in with Apple key.
    pub fn client_secret(&self, client_id: &str) -> Result<String, AppleExchangeError> {
        let claims = Claims::create(JwtDuration::from_secs(APPLE_CLIENT_SECRET_LIFETIME_SECONDS))
            .with_issuer(&self.team_id)
            .with_subject(client_id)
            .with_audience(APPLE_ISSUER);
        self.key_pair
            .sign(claims)
            .map_err(|error| AppleExchangeError::ClientSecret(error.to_string()))
    }

    /// Exchange a one-time authorization code. Returns the refresh token when Apple issued one.
    ///
    /// `redirect_uri` is required for codes issued to a web page (Sign in with Apple JS) and must
    /// be the one the page passed to Apple; codes issued to an app have none.
    pub(crate) async fn exchange_code(
        &self,
        client_id: &str,
        authorization_code: &str,
        redirect_uri: Option<&str>,
    ) -> Result<Option<AppleGrant>, AppleExchangeError> {
        let client_secret = self.client_secret(client_id)?;
        let mut form = vec![
            ("client_id", client_id),
            ("client_secret", client_secret.as_str()),
            ("code", authorization_code),
            ("grant_type", "authorization_code"),
        ];
        if let Some(redirect_uri) = redirect_uri {
            form.push(("redirect_uri", redirect_uri));
        }
        let _permit = admit_remote_fetch().map_err(|_| AppleExchangeError::Busy)?;
        let response = self
            .client
            .post(&self.token_url)
            .form(&form)
            .send()
            .await
            .map_err(|error| AppleExchangeError::Remote(format!("request failed: {error}")))?;
        let status = response.status();
        let body = read_bounded_body(response)
            .await
            .map_err(AppleExchangeError::Remote)?;
        if !status.is_success() {
            // Apple's error body names the OAuth error (e.g. invalid_grant), never a secret.
            let error = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.get("error")?.as_str().map(str::to_string))
                .unwrap_or_default();
            return Err(AppleExchangeError::Remote(format!(
                "returned {status} {error}"
            )));
        }
        let parsed: AppleTokenResponse = serde_json::from_slice(&body)
            .map_err(|error| AppleExchangeError::Remote(format!("invalid JSON: {error}")))?;
        Ok(parsed
            .refresh_token
            .filter(|token| !token.is_empty())
            .zip(parsed.id_token.filter(|token| !token.is_empty()))
            .map(|(refresh_token, id_token)| AppleGrant {
                refresh_token: SecretString::from(refresh_token),
                id_token: SecretString::from(id_token),
            }))
    }
}

// ============================================================================
// Shared service
// ============================================================================

/// Everything the social-login handler needs from the outside world, shared across requests.
pub struct SocialLoginProviders {
    pub verifier: SocialIdentityVerifier,
    pub apple_tokens: Option<AppleTokenClient>,
}

impl SocialLoginProviders {
    pub fn new(verifier: SocialIdentityVerifier, apple_tokens: Option<AppleTokenClient>) -> Self {
        Self {
            verifier,
            apple_tokens,
        }
    }

    /// No provider configured: every sign-in answers `503 PROVIDER_UNAVAILABLE` and the login
    /// page shows no provider buttons.
    pub fn unconfigured() -> Self {
        Self::new(
            SocialIdentityVerifier::new(
                SocialLoginSettings::default(),
                Arc::new(HttpJwksFetcher::new()),
            ),
            None,
        )
    }

    /// Configure providers from the environment and fetch keys from Google and Apple.
    pub fn from_env() -> Self {
        let settings = SocialLoginSettings::from_env();
        let apple_tokens = AppleTokenClient::from_settings(&settings);
        tracing::info!(
            google = settings.google.is_some(),
            apple = settings.apple.is_some(),
            google_web = settings.google_web.is_some(),
            apple_web = settings.apple_web.is_some(),
            apple_code_exchange = apple_tokens.is_some(),
            "Social login providers configured"
        );
        Self::new(
            SocialIdentityVerifier::new(settings, Arc::new(HttpJwksFetcher::new())),
            apple_tokens,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jwt_simple::prelude::{
        ECDSAP256PublicKeyLike, NoCustomClaims, RS256KeyPair, RSAKeyPairLike,
    };

    #[tokio::test]
    async fn apple_grant_must_match_the_signed_in_subject_and_client() {
        let key = RS256KeyPair::generate(2048)
            .unwrap()
            .with_key_id("test-key");
        let verifier = SocialIdentityVerifier::new(
            SocialLoginSettings::default(),
            Arc::new(HttpJwksFetcher::new()),
        );
        verifier
            .apple_keys
            .replace(HashMap::from([("test-key".into(), key.public_key())]));
        let login = VerifiedIdToken {
            identity: VerifiedSocialIdentity {
                provider: SocialProvider::Apple,
                subject: "subject-a".into(),
                email: None,
                email_verified: false,
                email_authoritative: false,
            },
            audience: "co.example.app".into(),
            token_hash: String::new(),
            expires_at: 0,
        };
        for (subject, audience, expected) in [
            ("subject-a", "co.example.app", true),
            ("subject-b", "co.example.app", false),
            ("subject-a", "co.example.web", false),
        ] {
            let token = key
                .sign(
                    Claims::create(JwtDuration::from_secs(60))
                        .with_issuer(APPLE_ISSUER)
                        .with_subject(subject)
                        .with_audience(audience),
                )
                .unwrap();
            assert_eq!(
                verifier.verify_apple_grant(&token, &login).await.is_ok(),
                expected
            );
        }
    }

    fn lookup(values: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: HashMap<String, String> = values
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        move |name| values.get(name).cloned()
    }

    #[test]
    fn unset_environment_configures_no_provider() {
        let settings = SocialLoginSettings::from_lookup(lookup(&[]));
        assert!(settings.google.is_none());
        assert!(settings.apple.is_none());
        assert!(settings.google_web.is_none());
        assert!(settings.apple_web.is_none());
        assert!(settings.apple_signing_key.is_none());
    }

    #[test]
    fn login_page_providers_are_configured_apart_from_the_apps() {
        let settings = SocialLoginSettings::from_lookup(lookup(&[
            ("GOOGLE_WEB_CLIENT_ID", " web.apps "),
            ("APPLE_SERVICES_ID", "co.example.web"),
            (
                "APPLE_WEB_REDIRECT_URI",
                "https://login.example/api/oauth/authorize",
            ),
        ]));
        assert!(settings.google.is_none());
        assert!(settings.apple.is_none());
        assert_eq!(
            settings.google_web,
            Some(GoogleWebSettings {
                client_id: "web.apps".to_string()
            })
        );
        assert_eq!(
            settings.apple_web,
            Some(AppleWebSettings {
                services_id: "co.example.web".to_string(),
                redirect_uri: "https://login.example/api/oauth/authorize".to_string(),
            })
        );

        let verifier = SocialIdentityVerifier::new(settings, Arc::new(HttpJwksFetcher::new()));
        for provider in [SocialProvider::Google, SocialProvider::Apple] {
            assert!(verifier.is_configured(provider, SignInChannel::Web));
            assert!(!verifier.is_configured(provider, SignInChannel::App));
        }
    }

    #[test]
    fn apple_on_the_login_page_needs_a_services_id_and_a_usable_return_url() {
        for values in [
            vec![("APPLE_SERVICES_ID", "co.example.web")],
            vec![(
                "APPLE_WEB_REDIRECT_URI",
                "https://login.example/api/oauth/authorize",
            )],
            vec![
                ("APPLE_SERVICES_ID", "co.example.web"),
                ("APPLE_WEB_REDIRECT_URI", "/api/oauth/authorize"),
            ],
            vec![
                ("APPLE_SERVICES_ID", "co.example.web"),
                ("APPLE_WEB_REDIRECT_URI", "intent://login.example/"),
            ],
        ] {
            let settings = SocialLoginSettings::from_lookup(lookup(&values));
            assert!(settings.apple_web.is_none(), "{values:?}");
        }
    }

    #[test]
    fn google_needs_both_audiences_and_authorized_parties() {
        let settings =
            SocialLoginSettings::from_lookup(lookup(&[("GOOGLE_CLIENT_IDS", "server.apps")]));
        assert!(settings.google.is_none());

        let settings = SocialLoginSettings::from_lookup(lookup(&[
            ("GOOGLE_CLIENT_IDS", " server.apps , ,server.apps"),
            ("GOOGLE_AUTHORIZED_PARTIES", "ios.apps,android.apps"),
        ]));
        assert_eq!(
            settings.google,
            Some(GoogleSettings {
                audiences: vec!["server.apps".to_string()],
                authorized_parties: vec!["ios.apps".to_string(), "android.apps".to_string()],
            })
        );
    }

    #[test]
    fn apple_signing_key_needs_every_part_and_unescapes_newlines() {
        let partial = SocialLoginSettings::from_lookup(lookup(&[("APPLE_TEAM_ID", "TEAM")]));
        assert!(partial.apple_signing_key.is_none());

        let full = SocialLoginSettings::from_lookup(lookup(&[
            ("APPLE_CLIENT_IDS", "co.example.app,co.example.app.staging"),
            ("APPLE_TEAM_ID", "TEAM"),
            ("APPLE_KEY_ID", "KEY"),
            ("APPLE_PRIVATE_KEY", "line1\\nline2"),
        ]));
        assert_eq!(full.apple.unwrap().audiences.len(), 2);
        let key = full.apple_signing_key.unwrap();
        assert_eq!(key.private_key_pem.expose_secret(), "line1\nline2");
        assert!(!format!("{key:?}").contains("line1"));
    }

    #[test]
    fn email_verified_accepts_boolean_and_apple_string_forms() {
        assert!(claim_is_true(Some(&serde_json::json!(true))));
        assert!(claim_is_true(Some(&serde_json::json!("true"))));
        assert!(!claim_is_true(Some(&serde_json::json!("false"))));
        assert!(!claim_is_true(Some(&serde_json::json!(1))));
        assert!(!claim_is_true(None));
    }

    #[test]
    fn jwks_parsing_keeps_only_rsa_signing_keys() {
        let set: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [
                {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
                {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
                {"kty": "RSA", "kid": "no-modulus", "e": "AQAB"},
                {"kty": "RSA", "kid": "rs512", "alg": "RS512", "n": "AQAB", "e": "AQAB"}
            ]
        }))
        .unwrap();
        assert!(parse_jwks(&set).is_empty());
    }

    #[test]
    fn audience_match_picks_a_configured_client() {
        let allowed = HashSet::from(["a".to_string(), "b".to_string()]);
        assert_eq!(
            matched_audience(Some(&Audiences::AsString("b".to_string())), &allowed),
            Some("b".to_string())
        );
        assert_eq!(
            matched_audience(
                Some(&Audiences::AsSet(HashSet::from([
                    "x".to_string(),
                    "a".to_string()
                ]))),
                &allowed
            ),
            Some("a".to_string())
        );
        assert_eq!(
            matched_audience(Some(&Audiences::AsString("x".to_string())), &allowed),
            None
        );
        assert_eq!(matched_audience(None, &allowed), None);
    }

    fn apple_client(key_pair: &ES256KeyPair) -> AppleTokenClient {
        let settings = SocialLoginSettings {
            apple_signing_key: Some(AppleSigningKey {
                team_id: "TEAM123".to_string(),
                key_id: "KEY456".to_string(),
                private_key_pem: SecretString::from(key_pair.to_pem().unwrap()),
            }),
            ..Default::default()
        };
        AppleTokenClient::from_settings(&settings).expect("valid signing key")
    }

    #[test]
    fn apple_client_secret_is_an_es256_jwt_for_the_bundle_id() {
        let key_pair = ES256KeyPair::generate();
        let client = apple_client(&key_pair);
        let secret = client.client_secret("co.example.app").unwrap();

        let metadata = Token::decode_metadata(&secret).unwrap();
        assert_eq!(metadata.algorithm(), "ES256");
        assert_eq!(metadata.key_id(), Some("KEY456"));
        let claims: JWTClaims<NoCustomClaims> = key_pair
            .public_key()
            .verify_token(
                &secret,
                Some(VerificationOptions {
                    allowed_issuers: Some(HashSet::from(["TEAM123".to_string()])),
                    allowed_audiences: Some(HashSet::from([APPLE_ISSUER.to_string()])),
                    ..Default::default()
                }),
            )
            .unwrap();
        assert_eq!(claims.subject.as_deref(), Some("co.example.app"));
        let lifetime = claims.expires_at.unwrap().as_secs() - claims.issued_at.unwrap().as_secs();
        assert_eq!(lifetime, APPLE_CLIENT_SECRET_LIFETIME_SECONDS);
    }

    #[test]
    fn unusable_apple_key_disables_the_exchange() {
        let settings = SocialLoginSettings {
            apple_signing_key: Some(AppleSigningKey {
                team_id: "TEAM".to_string(),
                key_id: "KEY".to_string(),
                private_key_pem: SecretString::from("not a key".to_string()),
            }),
            ..Default::default()
        };
        assert!(AppleTokenClient::from_settings(&settings).is_none());
    }

    async fn serve_token_endpoint(
        status: axum::http::StatusCode,
        body: serde_json::Value,
    ) -> (String, Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>) {
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = received.clone();
        let app = axum::Router::new().route(
            "/auth/token",
            axum::routing::post(
                move |axum::Form(form): axum::Form<HashMap<String, String>>| {
                    let seen = seen.clone();
                    let body = body.clone();
                    async move {
                        seen.lock().unwrap().push(form);
                        (status, axum::Json(body))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/auth/token"), received)
    }

    #[tokio::test]
    async fn apple_code_exchange_posts_the_code_and_returns_the_refresh_token() {
        let (url, received) = serve_token_endpoint(
            axum::http::StatusCode::OK,
            serde_json::json!({
                "access_token": "access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-123",
                "id_token": "ignored"
            }),
        )
        .await;
        let key_pair = ES256KeyPair::generate();
        let client = apple_client(&key_pair).with_token_url(url);

        let refresh = client
            .exchange_code("co.example.app", "one-time-code", None)
            .await
            .unwrap()
            .expect("refresh token");
        assert_eq!(refresh.refresh_token.expose_secret(), "refresh-123");

        let forms = received.lock().unwrap();
        let form = forms.first().expect("token endpoint called");
        assert_eq!(form["client_id"], "co.example.app");
        assert_eq!(form["code"], "one-time-code");
        assert_eq!(form["grant_type"], "authorization_code");
        assert!(!form.contains_key("redirect_uri"), "app codes carry none");
        assert!(key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&form["client_secret"], None)
            .is_ok());
    }

    #[tokio::test]
    async fn apple_code_exchange_repeats_the_web_return_url() {
        let (url, received) = serve_token_endpoint(
            axum::http::StatusCode::OK,
            serde_json::json!({"refresh_token": "refresh-web", "id_token": "identity-web"}),
        )
        .await;
        let key_pair = ES256KeyPair::generate();
        let client = apple_client(&key_pair).with_token_url(url);

        let refresh = client
            .exchange_code(
                "co.example.web",
                "web-code",
                Some("https://login.example/api/oauth/authorize"),
            )
            .await
            .unwrap()
            .expect("refresh token");
        assert_eq!(refresh.refresh_token.expose_secret(), "refresh-web");

        let forms = received.lock().unwrap();
        let form = forms.first().expect("token endpoint called");
        assert_eq!(form["client_id"], "co.example.web");
        assert_eq!(
            form["redirect_uri"],
            "https://login.example/api/oauth/authorize"
        );
        let claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&form["client_secret"], None)
            .unwrap();
        assert_eq!(claims.subject.as_deref(), Some("co.example.web"));
    }

    #[tokio::test]
    async fn apple_code_exchange_reports_rejected_codes() {
        let (url, _) = serve_token_endpoint(
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_grant"}),
        )
        .await;
        let client = apple_client(&ES256KeyPair::generate()).with_token_url(url);

        let error = client
            .exchange_code("co.example.app", "used-code", None)
            .await
            .err()
            .expect("rejected code");
        assert!(error.to_string().contains("invalid_grant"), "{error}");
    }
}
