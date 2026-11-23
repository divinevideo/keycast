// ABOUTME: "Continue with Google / Apple" for native apps and Keycast's hosted login page
// ABOUTME: Verifies a provider ID token, signs in, links or creates the account, then issues a code or a session

use axum::{
    extract::{rejection::JsonRejection, State},
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse, Response},
    Extension, Json,
};
use chrono::{Duration, Utc};
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    OAuthCodeRepository, PersonalKeysRepository, PolicyRepository, RepositoryError,
    StoreOAuthCodeParams, UserIdentityRepository, UserRepository,
};
use keycast_core::social_login::{
    resolve_social_account, SocialAccountResolution, SocialLoginError, SocialLoginRefusal,
    SocialProvider, VerifiedSocialIdentity,
};
use rand::Rng;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::auth::{generate_ucan_token, LOGIN_RATE_LIMIT_MESSAGE, TOO_MANY_ATTEMPTS_CODE};
use super::auth_observability::{record_auth_event_and_log, AuthEvent};
use super::oauth::{extract_origin, parse_policy_scope};
use crate::email_service::EmailSender;
use crate::login_attempt_limiter::{LoginAttemptAdmission, LoginAttemptLimiter};
use crate::replay_reservation::{
    reservation_ttl_seconds, reserve_shared, SharedReservationOutcome,
};
use crate::social_identity::{
    sha256_hex, AppleWebSettings, SignInChannel, SocialLoginProviders, SocialTokenError,
    VerifiedIdToken, CLOCK_SKEW_SECONDS, MAX_AUTHORIZATION_CODE_BYTES,
};

pub const SOCIAL_LOGIN_ENDPOINT: &str = "/api/headless/social-login";
pub const WEB_SOCIAL_LOGIN_ENDPOINT: &str = "/api/oauth/social-login";
/// Cookie holding the raw nonce of the hosted login page. The page only sees its SHA-256.
pub const SOCIAL_NONCE_COOKIE: &str = "keycast_social_nonce";
/// Covers the login page (`/api/oauth/authorize`) and `/api/oauth/social-login`.
const SOCIAL_NONCE_COOKIE_PATH: &str = "/api/oauth";
/// A login page can be left open this long before its Google and Apple buttons stop working.
const SOCIAL_NONCE_MAX_AGE_SECONDS: u32 = 60 * 60;
/// Raw nonces are 32 random bytes, hex.
const SOCIAL_NONCE_BYTES: usize = 32;
/// Same lifetime as the session `POST /api/oauth/login` sets.
const SESSION_COOKIE_MAX_AGE_SECONDS: u32 = 24 * 60 * 60;
const LOGIN_PAGE_EXPIRED_MESSAGE: &str = "This sign-in page has expired. Reload it and try again.";
const AUTH_EVENT_TYPE: &str = "login";
/// Same lifetime as the code `POST /api/headless/login` issues.
const AUTH_CODE_LIFETIME_MINUTES: i64 = 10;
/// Replay reservations never outlive this, whatever `exp` a token claims.
const MAX_REPLAY_WINDOW_SECONDS: i64 = 24 * 60 * 60;
const APPLE_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
const MAX_APP_VERSION_CHARS: usize = 64;

/// Not `Debug`: it carries the ID token and Apple's one-time code, which must never be logged.
#[derive(Deserialize)]
pub struct HeadlessSocialLoginRequest {
    /// `google` or `apple`.
    pub provider: String,
    /// ID token the provider returned to the app.
    pub id_token: String,
    /// Nonce the app generated. The token's `nonce` claim must be its lowercase hex SHA-256.
    pub raw_nonce: String,
    /// Apple only: one-time authorization code, exchanged for a refresh token so the grant can be
    /// revoked when the account is deleted.
    #[serde(default)]
    pub authorization_code: Option<String>,
    pub client_id: String,
    pub redirect_uri: String,
    /// OAuth scope, `policy:full` when absent.
    #[serde(default)]
    pub scope: Option<String>,
    /// PKCE challenge. Required, unlike password login: this endpoint is new.
    #[serde(default)]
    pub code_challenge: Option<String>,
    /// Must be `S256`.
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// Client app version, recorded with the audit event.
    #[serde(default)]
    pub app_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeadlessSocialLoginResponse {
    pub success: bool,
    /// Authorization code to exchange via `POST /api/oauth/token`.
    pub code: String,
    /// Nostr public key (hex).
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// `true` when this request created the account.
    pub created: bool,
}

#[derive(Debug)]
pub enum SocialLoginHttpError {
    InvalidRequest(String),
    InvalidToken,
    AccountLinkRequired,
    EmailMissing(SocialProvider),
    EmailNotVerified(SocialProvider),
    ProviderUnavailable {
        provider: SocialProvider,
        retry_after: Option<u32>,
    },
    TooManyRequests {
        retry_after: u32,
    },
    ServiceUnavailable {
        message: String,
        retry_after: Option<u32>,
    },
    Internal(String),
}

impl IntoResponse for SocialLoginHttpError {
    fn into_response(self) -> Response {
        let (status, message, code, retry_after) = match self {
            Self::InvalidRequest(message) => {
                (StatusCode::BAD_REQUEST, message, "INVALID_REQUEST", None)
            }
            Self::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "We couldn't confirm that sign-in. Please try again.".to_string(),
                "INVALID_TOKEN",
                None,
            ),
            Self::AccountLinkRequired => (
                StatusCode::CONFLICT,
                "You already have a Divine account with this email. Sign in with your email and \
                 password instead."
                    .to_string(),
                "ACCOUNT_LINK_REQUIRED",
                None,
            ),
            Self::EmailMissing(provider) => (
                StatusCode::BAD_REQUEST,
                format!(
                    "{} didn't share an email address, and Divine needs one for your account.",
                    provider.display_name()
                ),
                "EMAIL_MISSING",
                None,
            ),
            Self::EmailNotVerified(provider) => (
                StatusCode::FORBIDDEN,
                format!(
                    "{} hasn't verified this email address yet. Verify it there, then try again.",
                    provider.display_name()
                ),
                "EMAIL_NOT_VERIFIED",
                None,
            ),
            Self::ProviderUnavailable {
                provider,
                retry_after,
            } => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Sign in with {} isn't available right now. Please try again shortly.",
                    provider.display_name()
                ),
                "PROVIDER_UNAVAILABLE",
                retry_after,
            ),
            Self::TooManyRequests { retry_after } => (
                StatusCode::TOO_MANY_REQUESTS,
                LOGIN_RATE_LIMIT_MESSAGE.to_string(),
                TOO_MANY_ATTEMPTS_CODE,
                Some(retry_after),
            ),
            Self::ServiceUnavailable {
                message,
                retry_after,
            } => (
                StatusCode::SERVICE_UNAVAILABLE,
                message,
                "SERVICE_UNAVAILABLE",
                retry_after,
            ),
            Self::Internal(message) => {
                tracing::error!("Social login internal error: {message}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "INTERNAL_ERROR",
                    None,
                )
            }
        };

        let mut response = (
            status,
            Json(serde_json::json!({ "error": message, "code": code })),
        )
            .into_response();
        if let Some(seconds) = retry_after {
            if let Ok(value) = seconds.to_string().parse() {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        response
    }
}

fn login_unavailable() -> SocialLoginHttpError {
    SocialLoginHttpError::ServiceUnavailable {
        message: "Login is temporarily unavailable. Please try again shortly.".to_string(),
        retry_after: Some(1),
    }
}

/// Audit context that fills in as the request is understood.
struct Audit<'a> {
    pool: &'a sqlx::PgPool,
    headers: &'a HeaderMap,
    tenant_id: i64,
    /// Which endpoint is answering: the native apps' or the hosted login page's.
    channel: SignInChannel,
    client_id: Option<String>,
    redirect_origin: Option<String>,
    email: Option<String>,
    pubkey: Option<String>,
    metadata: serde_json::Map<String, serde_json::Value>,
}

impl<'a> Audit<'a> {
    fn new(
        pool: &'a sqlx::PgPool,
        headers: &'a HeaderMap,
        tenant_id: i64,
        channel: SignInChannel,
    ) -> Self {
        Self {
            pool,
            headers,
            tenant_id,
            channel,
            client_id: None,
            redirect_origin: None,
            email: None,
            pubkey: None,
            metadata: serde_json::Map::new(),
        }
    }

    fn endpoint(&self) -> &'static str {
        match self.channel {
            SignInChannel::App => SOCIAL_LOGIN_ENDPOINT,
            SignInChannel::Web => WEB_SOCIAL_LOGIN_ENDPOINT,
        }
    }

    /// Log event name.
    fn event(&self) -> &'static str {
        match self.channel {
            SignInChannel::App => "headless_social_login",
            SignInChannel::Web => "web_social_login",
        }
    }

    fn note(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        self.metadata.insert(key.to_string(), value.into());
    }

    async fn invalid_body(&mut self, rejection: &JsonRejection) -> SocialLoginHttpError {
        let message = format!("Invalid request body: {}", rejection.body_text());
        self.fail(
            "invalid_request",
            Some("invalid_body"),
            SocialLoginHttpError::InvalidRequest(message),
        )
        .await
    }

    /// Parse the requested provider and note it.
    async fn provider(
        &mut self,
        value: &str,
        client_id: &str,
    ) -> Result<SocialProvider, SocialLoginHttpError> {
        let Some(provider) = SocialProvider::parse(value) else {
            return Err(self
                .fail(
                    "invalid_request",
                    Some("unknown_provider"),
                    SocialLoginHttpError::InvalidRequest(
                        "provider must be \"google\" or \"apple\"".to_string(),
                    ),
                )
                .await);
        };
        self.note("provider", provider.as_str());
        tracing::info!(
            event = self.event(),
            tenant_id = self.tenant_id,
            provider = provider.as_str(),
            client_id = %client_id,
            "Social login attempt"
        );
        Ok(provider)
    }

    async fn record(&self, outcome: &'static str, reason_code: Option<&str>, http_status: i32) {
        record_auth_event_and_log(
            self.pool,
            self.headers,
            None,
            AuthEvent {
                tenant_id: self.tenant_id,
                endpoint: self.endpoint(),
                event_type: AUTH_EVENT_TYPE,
                outcome,
                reason_code,
                http_status,
                email: self.email.as_deref(),
                pubkey: self.pubkey.as_deref(),
                client_id: self.client_id.as_deref(),
                redirect_origin: self.redirect_origin.as_deref(),
                metadata_json: serde_json::Value::Object(self.metadata.clone()),
            },
        )
        .await;
    }

    async fn fail(
        &mut self,
        reason_code: &str,
        detail: Option<&str>,
        error: SocialLoginHttpError,
    ) -> SocialLoginHttpError {
        if let Some(detail) = detail {
            self.note("detail", detail);
        }
        let status = error_status(&error);
        self.record("failure", Some(reason_code), status).await;
        tracing::warn!(
            event = self.event(),
            tenant_id = self.tenant_id,
            success = false,
            reason = reason_code,
            detail = detail.unwrap_or(""),
            "Social login failed"
        );
        error
    }
}

fn error_status(error: &SocialLoginHttpError) -> i32 {
    let status = match error {
        SocialLoginHttpError::InvalidRequest(_) | SocialLoginHttpError::EmailMissing(_) => {
            StatusCode::BAD_REQUEST
        }
        SocialLoginHttpError::InvalidToken => StatusCode::UNAUTHORIZED,
        SocialLoginHttpError::AccountLinkRequired => StatusCode::CONFLICT,
        SocialLoginHttpError::EmailNotVerified(_) => StatusCode::FORBIDDEN,
        SocialLoginHttpError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
        SocialLoginHttpError::ProviderUnavailable { .. }
        | SocialLoginHttpError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
        SocialLoginHttpError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    i32::from(status.as_u16())
}

/// POST /api/headless/social-login
///
/// Sign in with a Google or Apple ID token and get an authorization code, exactly like
/// `POST /api/headless/login` returns for email and password.
///
/// 1. A provider subject already linked to an account signs in to it.
/// 2. Otherwise an account whose verified email matches, when the provider is authoritative for
///    the address, is linked and signed in, and its owner is emailed about the new sign-in method.
/// 3. Otherwise a new account is created with a fresh Nostr key and no password.
///
/// Matching accounts that cannot be linked safely answer `409 ACCOUNT_LINK_REQUIRED`.
pub async fn headless_social_login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Extension(providers): Extension<Arc<SocialLoginProviders>>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    headers: HeaderMap,
    payload: Result<Json<HeadlessSocialLoginRequest>, JsonRejection>,
) -> Result<Json<HeadlessSocialLoginResponse>, SocialLoginHttpError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;
    let mut audit = Audit::new(pool, &headers, tenant_id, SignInChannel::App);

    let req = match payload {
        Ok(Json(req)) => req,
        Err(rejection) => return Err(audit.invalid_body(&rejection).await),
    };
    audit.client_id = Some(req.client_id.clone());
    if let Some(version) = req.app_version.as_deref() {
        audit.note(
            "app_version",
            version
                .chars()
                .take(MAX_APP_VERSION_CHARS)
                .collect::<String>(),
        );
    }

    let provider = audit.provider(&req.provider, &req.client_id).await?;

    let scope = req.scope.as_deref().unwrap_or("policy:full").to_string();
    match validate_request(pool, &req, &scope).await {
        Ok(origin) => audit.redirect_origin = Some(origin),
        Err(error) => {
            let reason = match error {
                SocialLoginHttpError::Internal(_) => "service_unavailable",
                _ => "invalid_request",
            };
            return Err(audit.fail(reason, None, error).await);
        }
    }

    let verified = verify_token(
        &mut audit,
        &providers,
        provider,
        &req.id_token,
        &req.raw_nonce,
    )
    .await?;
    let resolution = admit_and_resolve(&mut audit, &auth_state, provider, &verified).await?;

    let code =
        match issue_authorization_code(pool, tenant_id, &req, &scope, resolution.pubkey()).await {
            Ok(code) => code,
            Err(message) => {
                return Err(audit
                    .fail(
                        "service_unavailable",
                        Some("code_store_failed"),
                        SocialLoginHttpError::Internal(message),
                    )
                    .await);
            }
        };

    complete_sign_in(
        &mut audit,
        &auth_state,
        &providers,
        email_sender.as_ref(),
        &verified,
        &resolution,
        req.authorization_code.as_deref(),
    )
    .await;

    Ok(Json(HeadlessSocialLoginResponse {
        success: true,
        code,
        pubkey: resolution.pubkey().to_string(),
        state: req.state,
        created: matches!(resolution, SocialAccountResolution::Created { .. }),
    }))
}

/// Not `Debug`: it carries the ID token and Apple's one-time code, which must never be logged.
#[derive(Deserialize)]
pub struct WebSocialLoginRequest {
    /// `google` or `apple`.
    pub provider: String,
    /// ID token Google Identity Services or Sign in with Apple JS returned to the login page.
    pub id_token: String,
    /// Apple only: one-time authorization code, exchanged for a refresh token.
    #[serde(default)]
    pub authorization_code: Option<String>,
    /// The OAuth client the login page was opened for.
    pub client_id: String,
    /// The OAuth redirect URI the login page was opened for.
    pub redirect_uri: String,
}

#[derive(Debug, Serialize)]
pub struct WebSocialLoginResponse {
    pub success: bool,
    /// Nostr public key (hex).
    pub pubkey: String,
    /// `true` when this request created the account.
    pub created: bool,
}

/// POST /api/oauth/social-login
///
/// "Continue with Google / Apple" on the hosted login page (`GET /api/oauth/authorize`). The
/// account is found exactly as for `POST /api/headless/social-login`. Like `POST /api/oauth/login`
/// it then sets the session cookie, and the page reloads the authorize URL, which asks for consent
/// and sends the code to the client's `redirect_uri` with its `state`.
///
/// The token's `nonce` must be the SHA-256 of the raw nonce the login page stored in its
/// `keycast_social_nonce` cookie; the raw value never reaches the page's script.
pub async fn web_social_login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Extension(providers): Extension<Arc<SocialLoginProviders>>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    headers: HeaderMap,
    payload: Result<Json<WebSocialLoginRequest>, JsonRejection>,
) -> Result<Response, SocialLoginHttpError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;
    let mut audit = Audit::new(pool, &headers, tenant_id, SignInChannel::Web);

    let req = match payload {
        Ok(Json(req)) => req,
        Err(rejection) => return Err(audit.invalid_body(&rejection).await),
    };
    audit.client_id = Some(req.client_id.clone());
    let provider = audit.provider(&req.provider, &req.client_id).await?;
    // Answered before the nonce check: the page shows no button for this provider anyway.
    if !providers
        .verifier
        .is_configured(provider, SignInChannel::Web)
    {
        return Err(audit
            .fail(
                "provider_unavailable",
                Some("not_configured"),
                SocialLoginHttpError::ProviderUnavailable {
                    provider,
                    retry_after: None,
                },
            )
            .await);
    }

    let redirect_origin = match validate_web_request(&req) {
        Ok(origin) => origin,
        Err(error) => return Err(audit.fail("invalid_request", None, error).await),
    };
    audit.redirect_origin = Some(redirect_origin.clone());

    let Some(raw_nonce) = social_nonce_from_headers(&headers) else {
        return Err(audit
            .fail(
                "invalid_request",
                Some("missing_nonce_cookie"),
                SocialLoginHttpError::InvalidRequest(LOGIN_PAGE_EXPIRED_MESSAGE.to_string()),
            )
            .await);
    };

    let verified =
        verify_token(&mut audit, &providers, provider, &req.id_token, &raw_nonce).await?;
    let resolution = admit_and_resolve(&mut audit, &auth_state, provider, &verified).await?;

    let session = match session_cookie(
        &auth_state,
        tenant_id,
        resolution.pubkey(),
        &redirect_origin,
    )
    .await
    {
        Ok(cookie) => cookie,
        Err((detail, error)) => {
            return Err(audit.fail("service_unavailable", Some(detail), error).await);
        }
    };

    complete_sign_in(
        &mut audit,
        &auth_state,
        &providers,
        email_sender.as_ref(),
        &verified,
        &resolution,
        req.authorization_code.as_deref(),
    )
    .await;

    Ok((
        AppendHeaders([
            (SET_COOKIE, session),
            (SET_COOKIE, clear_social_nonce_cookie()),
        ]),
        Json(WebSocialLoginResponse {
            success: true,
            pubkey: resolution.pubkey().to_string(),
            created: matches!(resolution, SocialAccountResolution::Created { .. }),
        }),
    )
        .into_response())
}

/// Verify the provider token for the audit's channel, answering failures.
async fn verify_token(
    audit: &mut Audit<'_>,
    providers: &SocialLoginProviders,
    provider: SocialProvider,
    id_token: &str,
    raw_nonce: &str,
) -> Result<VerifiedIdToken, SocialLoginHttpError> {
    let verified = match providers
        .verifier
        .verify(provider, audit.channel, id_token, raw_nonce)
        .await
    {
        Ok(verified) => verified,
        Err(SocialTokenError::Invalid(detail)) => {
            return Err(audit
                .fail(
                    "invalid_token",
                    Some(detail),
                    SocialLoginHttpError::InvalidToken,
                )
                .await);
        }
        Err(SocialTokenError::NotConfigured(_)) => {
            return Err(audit
                .fail(
                    "provider_unavailable",
                    Some("not_configured"),
                    SocialLoginHttpError::ProviderUnavailable {
                        provider,
                        retry_after: None,
                    },
                )
                .await);
        }
        Err(SocialTokenError::ProviderUnavailable) => {
            return Err(audit
                .fail(
                    "provider_unavailable",
                    Some("keys_unavailable"),
                    SocialLoginHttpError::ProviderUnavailable {
                        provider,
                        retry_after: Some(30),
                    },
                )
                .await);
        }
    };
    audit.email = verified.identity.email.clone();
    Ok(verified)
}

/// Accept the token once, admit one attempt for the provider account, and find, link or create
/// the Keycast account.
async fn admit_and_resolve(
    audit: &mut Audit<'_>,
    auth_state: &super::routes::AuthState,
    provider: SocialProvider,
    verified: &VerifiedIdToken,
) -> Result<SocialAccountResolution, SocialLoginHttpError> {
    let pool = &auth_state.state.db;
    let tenant_id = audit.tenant_id;
    let Some(redis) = auth_state.state.redis.clone() else {
        // Without shared replay protection a stolen token could be used twice. Fail closed.
        return Err(audit
            .fail(
                "service_unavailable",
                Some("replay_store_unavailable"),
                login_unavailable(),
            )
            .await);
    };
    if let Err((reason, detail, error)) = reserve_token(&redis, verified).await {
        return Err(audit.fail(reason, Some(detail), error).await);
    }

    let limiter = LoginAttemptLimiter::new(redis);
    let limiter_subject = format!("social:{}:{}", provider.as_str(), verified.identity.subject);
    match limiter.check(tenant_id, &limiter_subject).await {
        Ok(Some(retry_after)) => {
            return Err(audit
                .fail(
                    "rate_limited",
                    None,
                    SocialLoginHttpError::TooManyRequests { retry_after },
                )
                .await);
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!("Social-login limiter check failed: {error}");
            return Err(audit
                .fail("service_unavailable", Some("limiter"), login_unavailable())
                .await);
        }
    }
    let reservation = match limiter.reserve(tenant_id, &limiter_subject).await {
        Ok(LoginAttemptAdmission::Reserved(reservation)) => reservation,
        Ok(LoginAttemptAdmission::Limited { retry_after }) => {
            return Err(audit
                .fail(
                    "rate_limited",
                    None,
                    SocialLoginHttpError::TooManyRequests { retry_after },
                )
                .await);
        }
        Err(error) => {
            tracing::error!("Social-login limiter admission failed: {error}");
            return Err(audit
                .fail("service_unavailable", Some("limiter"), login_unavailable())
                .await);
        }
    };

    let key_manager = auth_state.state.key_manager.as_ref().as_ref();
    let resolution =
        match resolve_social_account(pool, key_manager, tenant_id, &verified.identity).await {
            Ok(resolution) => {
                if let Err(error) = reservation.clear().await {
                    // The account state already changed; failing now would only strand the user.
                    tracing::warn!("Social-login limiter reset failed: {error}");
                }
                resolution
            }
            Err(SocialLoginError::Refused(refusal)) => {
                if let Err(error) = reservation.record_failure().await {
                    tracing::warn!("Social-login failure recording failed: {error}");
                }
                let (reason, detail, error) = refusal_response(provider, refusal);
                return Err(audit.fail(reason, detail, error).await);
            }
            Err(error) => {
                if let Err(release_error) = reservation.release().await {
                    tracing::warn!("Social-login reservation release failed: {release_error}");
                }
                let (detail, error) = resolution_failure(error);
                return Err(audit.fail("service_unavailable", Some(detail), error).await);
            }
        };
    audit.pubkey = Some(resolution.pubkey().to_string());
    audit.note("outcome", resolution.label());
    Ok(resolution)
}

/// After the caller handed out a code or a session: tell the owner about a new link, keep Apple's
/// refresh token, and record the success.
async fn complete_sign_in(
    audit: &mut Audit<'_>,
    auth_state: &super::routes::AuthState,
    providers: &SocialLoginProviders,
    email_sender: &dyn EmailSender,
    verified: &VerifiedIdToken,
    resolution: &SocialAccountResolution,
    apple_authorization_code: Option<&str>,
) {
    let provider = verified.identity.provider;
    if let SocialAccountResolution::Linked { email, .. } = resolution {
        notify_link(email_sender, email, provider).await;
    }
    if provider == SocialProvider::Apple {
        if let Some(authorization_code) = apple_authorization_code {
            // Codes Sign in with Apple JS issued must be exchanged with the page's return URL.
            let redirect_uri = match audit.channel {
                SignInChannel::App => None,
                SignInChannel::Web => providers
                    .verifier
                    .settings()
                    .apple_web
                    .as_ref()
                    .map(|apple| apple.redirect_uri.as_str()),
            };
            let stored = store_apple_refresh_token(
                providers,
                &auth_state.state.db,
                auth_state.state.key_manager.as_ref().as_ref(),
                audit.tenant_id,
                verified,
                authorization_code,
                redirect_uri,
            )
            .await;
            audit.note("apple_refresh_token_stored", stored);
        }
    }

    METRICS.inc_login();
    if matches!(resolution, SocialAccountResolution::Created { .. }) {
        METRICS.inc_registration();
    }
    audit.record("success", None, 200).await;
    tracing::info!(
        event = audit.event(),
        tenant_id = audit.tenant_id,
        provider = provider.as_str(),
        outcome = resolution.label(),
        success = true,
        "Social login successful"
    );
}

/// Check the OAuth parameters before touching the provider token. Returns the redirect origin.
async fn validate_request(
    pool: &sqlx::PgPool,
    req: &HeadlessSocialLoginRequest,
    scope: &str,
) -> Result<String, SocialLoginHttpError> {
    let origin = extract_origin(&req.redirect_uri).map_err(|error| {
        SocialLoginHttpError::InvalidRequest(format!("Invalid redirect_uri: {error:?}"))
    })?;
    if req.client_id.trim().is_empty() {
        return Err(SocialLoginHttpError::InvalidRequest(
            "client_id is required".to_string(),
        ));
    }
    if req
        .code_challenge
        .as_deref()
        .is_none_or(|challenge| challenge.is_empty())
        || req.code_challenge_method.as_deref() != Some("S256")
    {
        return Err(SocialLoginHttpError::InvalidRequest(
            "code_challenge with code_challenge_method S256 is required".to_string(),
        ));
    }
    if req
        .authorization_code
        .as_deref()
        .is_some_and(|code| code.len() > MAX_AUTHORIZATION_CODE_BYTES)
    {
        return Err(SocialLoginHttpError::InvalidRequest(
            "authorization_code is too long".to_string(),
        ));
    }
    if scope.starts_with("policy:") {
        let policy_slug = parse_policy_scope(scope)
            .map_err(|error| SocialLoginHttpError::InvalidRequest(format!("{error:?}")))?;
        PolicyRepository::new(pool.clone())
            .find_by_slug(&policy_slug)
            .await
            .map_err(|error| match error {
                RepositoryError::NotFound(_) => {
                    SocialLoginHttpError::InvalidRequest(format!("Unknown policy '{policy_slug}'"))
                }
                other => SocialLoginHttpError::Internal(format!(
                    "Failed to look up policy '{policy_slug}': {other}"
                )),
            })?;
    }
    Ok(origin)
}

/// Check the login page's OAuth parameters. Returns the redirect origin.
///
/// No code is issued here, so scope and PKCE are checked later, when the reloaded authorize page
/// issues the code.
fn validate_web_request(req: &WebSocialLoginRequest) -> Result<String, SocialLoginHttpError> {
    let origin = extract_origin(&req.redirect_uri).map_err(|error| {
        SocialLoginHttpError::InvalidRequest(format!("Invalid redirect_uri: {error:?}"))
    })?;
    if req.client_id.trim().is_empty() {
        return Err(SocialLoginHttpError::InvalidRequest(
            "client_id is required".to_string(),
        ));
    }
    if req
        .authorization_code
        .as_deref()
        .is_some_and(|code| code.len() > MAX_AUTHORIZATION_CODE_BYTES)
    {
        return Err(SocialLoginHttpError::InvalidRequest(
            "authorization_code is too long".to_string(),
        ));
    }
    Ok(origin)
}

/// The session cookie `POST /api/oauth/login` sets, for a signed-in social account.
async fn session_cookie(
    auth_state: &super::routes::AuthState,
    tenant_id: i64,
    pubkey: &str,
    redirect_origin: &str,
) -> Result<String, (&'static str, SocialLoginHttpError)> {
    let pool = &auth_state.state.db;
    let repository_failure = |detail: &'static str, error: RepositoryError| match error {
        RepositoryError::Unavailable(message) => {
            tracing::warn!("Social login database unavailable: {message}");
            (detail, login_unavailable())
        }
        other => (
            detail,
            SocialLoginHttpError::Internal(format!("Social login session setup failed: {other}")),
        ),
    };

    let account = UserRepository::new(pool.clone())
        .get_account_status(pubkey, tenant_id)
        .await
        .map_err(|error| repository_failure("account_lookup_failed", error))?
        .ok_or((
            "account_missing",
            SocialLoginHttpError::Internal("Signed-in account no longer exists".to_string()),
        ))?;
    let encrypted_secret = PersonalKeysRepository::new(pool.clone())
        .find_encrypted_key_for_tenant(pubkey, tenant_id)
        .await
        .map_err(|error| repository_failure("key_lookup_failed", error))?
        // Same answer as `POST /api/oauth/login` for an account whose registration never
        // reached the token exchange.
        .ok_or((
            "key_missing",
            SocialLoginHttpError::InvalidRequest(
                "Account setup incomplete. Please complete the OAuth flow to finalize your \
                 account."
                    .to_string(),
            ),
        ))?;
    let secret = auth_state
        .state
        .key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|error| {
            tracing::error!("Social login key decryption failed: {error}");
            ("decryption_failed", login_unavailable())
        })?;
    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&secret).map_err(|error| {
        (
            "invalid_key",
            SocialLoginHttpError::Internal(format!("Stored key is unusable: {error}")),
        )
    })?;
    let keys = nostr_sdk::Keys::new(secret_key.into());

    let status = (!account.status.is_active()).then_some(&account.status);
    let email = account.email.unwrap_or_default();
    let token = generate_ucan_token(&keys, tenant_id, &email, redirect_origin, None, status)
        .await
        .map_err(|error| {
            (
                "session_failed",
                SocialLoginHttpError::Internal(format!("UCAN generation failed: {error:?}")),
            )
        })?;
    Ok(format!(
        "keycast_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={SESSION_COOKIE_MAX_AGE_SECONDS}"
    ))
}

// ============================================================================
// Hosted login page
// ============================================================================

/// What the hosted login page needs to offer Google and Apple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPageSocialConfig {
    /// Web client ID for Google Identity Services, when Google is offered.
    pub google_client_id: Option<String>,
    /// Services ID and return URL for Sign in with Apple JS, when Apple is offered.
    pub apple: Option<AppleWebSettings>,
    /// Lowercase hex SHA-256 of the raw nonce: what the page hands Google and Apple.
    pub nonce_hash: String,
    /// `Set-Cookie` value that stores the raw nonce for `POST /api/oauth/social-login`.
    pub nonce_cookie: String,
}

/// The login page's Google and Apple setup, or `None` when neither is configured for the web.
///
/// A raw nonce the browser already holds is kept, so several open login pages share one and each
/// can still finish. Tokens are single-use, so sharing a nonce does not let one be replayed.
pub fn login_page_social_config(
    providers: &SocialLoginProviders,
    headers: &HeaderMap,
) -> Option<LoginPageSocialConfig> {
    let settings = providers.verifier.settings();
    let google_client_id = settings
        .google_web
        .as_ref()
        .map(|google| google.client_id.clone());
    let apple = settings.apple_web.clone();
    if google_client_id.is_none() && apple.is_none() {
        return None;
    }
    let raw_nonce = social_nonce_from_headers(headers).unwrap_or_else(new_social_nonce);
    Some(LoginPageSocialConfig {
        google_client_id,
        apple,
        nonce_hash: sha256_hex(&raw_nonce),
        nonce_cookie: social_nonce_cookie(&raw_nonce),
    })
}

fn new_social_nonce() -> String {
    let mut bytes = [0u8; SOCIAL_NONCE_BYTES];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// The raw nonce from the login page's cookie, when it holds a well-formed one.
pub fn social_nonce_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .filter(|(name, _)| *name == SOCIAL_NONCE_COOKIE)
        .map(|(_, value)| value)
        .find(|value| {
            value.len() == SOCIAL_NONCE_BYTES * 2
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(str::to_string)
}

fn social_nonce_cookie(raw_nonce: &str) -> String {
    format!(
        "{SOCIAL_NONCE_COOKIE}={raw_nonce}; HttpOnly; Secure; SameSite=Lax; \
         Path={SOCIAL_NONCE_COOKIE_PATH}; Max-Age={SOCIAL_NONCE_MAX_AGE_SECONDS}"
    )
}

fn clear_social_nonce_cookie() -> String {
    format!(
        "{SOCIAL_NONCE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; \
         Path={SOCIAL_NONCE_COOKIE_PATH}; Max-Age=0"
    )
}

type ReplayFailure = (&'static str, &'static str, SocialLoginHttpError);

/// Accept each ID token once. Keyed by the token hash, not the nonce: Google keeps one nonce for
/// the life of the app process, so several distinct tokens legitimately share it.
async fn reserve_token(
    redis: &crate::PrefixedRedis,
    verified: &VerifiedIdToken,
) -> Result<(), ReplayFailure> {
    let now = Utc::now().timestamp();
    let expires_at = i64::try_from(verified.expires_at).unwrap_or(i64::MAX);
    let ttl = reservation_ttl_seconds(
        expires_at,
        now,
        MAX_REPLAY_WINDOW_SECONDS,
        CLOCK_SKEW_SECONDS as i64,
    );
    let key = format!("social_login:id_token:{}", verified.token_hash);
    match reserve_shared(Some(redis), &key, ttl, "1").await {
        SharedReservationOutcome::Reserved => Ok(()),
        SharedReservationOutcome::Replay => Err((
            "replayed_token",
            "replayed_token",
            SocialLoginHttpError::InvalidToken,
        )),
        SharedReservationOutcome::Unavailable(error) => {
            if let Some(error) = error {
                tracing::error!("Social-login replay reservation failed: {error}");
            }
            Err((
                "service_unavailable",
                "replay_store_unavailable",
                login_unavailable(),
            ))
        }
    }
}

fn refusal_response(
    provider: SocialProvider,
    refusal: SocialLoginRefusal,
) -> (&'static str, Option<&'static str>, SocialLoginHttpError) {
    match refusal {
        SocialLoginRefusal::EmailMissing => (
            "email_missing",
            None,
            SocialLoginHttpError::EmailMissing(provider),
        ),
        SocialLoginRefusal::EmailNotVerified => (
            "email_not_verified",
            None,
            SocialLoginHttpError::EmailNotVerified(provider),
        ),
        SocialLoginRefusal::AccountLinkRequired(reason) => (
            "account_link_required",
            Some(reason.label()),
            SocialLoginHttpError::AccountLinkRequired,
        ),
    }
}

fn resolution_failure(error: SocialLoginError) -> (&'static str, SocialLoginHttpError) {
    match error {
        SocialLoginError::Encryption(message) => {
            tracing::error!("Social login key encryption failed: {message}");
            (
                "encryption_failed",
                SocialLoginHttpError::ServiceUnavailable {
                    message: "Account setup is temporarily unavailable. Please try again shortly."
                        .to_string(),
                    retry_after: Some(1),
                },
            )
        }
        SocialLoginError::Repository(RepositoryError::Unavailable(message)) => {
            tracing::warn!("Social login database unavailable: {message}");
            ("database_unavailable", login_unavailable())
        }
        SocialLoginError::Repository(other) => (
            "database_error",
            SocialLoginHttpError::Internal(format!("Social login resolution failed: {other}")),
        ),
        SocialLoginError::Refused(_) => unreachable!("refusals are answered before this point"),
    }
}

/// Store a one-time authorization code exactly like `POST /api/headless/login`.
async fn issue_authorization_code(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    req: &HeadlessSocialLoginRequest,
    scope: &str,
    pubkey: &str,
) -> Result<String, String> {
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    OAuthCodeRepository::new(pool.clone())
        .store(StoreOAuthCodeParams {
            tenant_id,
            code: &code,
            user_pubkey: pubkey,
            client_id: &req.client_id,
            redirect_uri: &req.redirect_uri,
            scope,
            code_challenge: req.code_challenge.as_deref(),
            code_challenge_method: req.code_challenge_method.as_deref(),
            expires_at: Utc::now() + Duration::minutes(AUTH_CODE_LIFETIME_MINUTES),
            previous_auth_id: None,
            state: req.state.as_deref(),
            is_headless: true,
        })
        .await
        .map_err(|error| format!("Failed to store authorization code: {error}"))?;
    Ok(code)
}

/// Best effort: a failed notification must not undo a sign-in that already linked the account.
async fn notify_link(email_sender: &dyn EmailSender, email: &str, provider: SocialProvider) {
    if let Err(error) = email_sender
        .send_social_account_linked(email, provider.display_name())
        .await
    {
        METRICS.inc_auth_email_send_failure("social_account_linked");
        tracing::warn!(
            provider = provider.as_str(),
            "Failed to send the provider-linked notification: {error}"
        );
    }
}

/// Best effort: exchange Apple's one-time code and keep the refresh token, encrypted, so the
/// grant can be revoked when the account is deleted. Returns whether a token was stored.
async fn store_apple_refresh_token(
    providers: &SocialLoginProviders,
    pool: &sqlx::PgPool,
    key_manager: &dyn keycast_core::encryption::KeyManager,
    tenant_id: i64,
    verified: &VerifiedIdToken,
    authorization_code: &str,
    redirect_uri: Option<&str>,
) -> bool {
    let Some(apple_tokens) = providers.apple_tokens.as_ref() else {
        tracing::warn!("Apple code exchange is not configured; no refresh token stored");
        return false;
    };
    let identity: &VerifiedSocialIdentity = &verified.identity;
    // The code was issued to the client the ID token is addressed to: a bundle ID or the
    // Services ID.
    let exchanged = tokio::time::timeout(
        APPLE_EXCHANGE_TIMEOUT,
        apple_tokens.exchange_code(&verified.audience, authorization_code, redirect_uri),
    )
    .await;
    let refresh_token = match exchanged {
        Ok(Ok(Some(token))) => token,
        Ok(Ok(None)) => {
            tracing::warn!("Apple code exchange returned no refresh token");
            return false;
        }
        Ok(Err(error)) => {
            tracing::warn!("Apple code exchange failed: {error}");
            return false;
        }
        Err(_) => {
            tracing::warn!("Apple code exchange timed out");
            return false;
        }
    };
    let encrypted = match key_manager
        .encrypt(refresh_token.expose_secret().as_bytes())
        .await
    {
        Ok(encrypted) => encrypted,
        Err(error) => {
            tracing::warn!("Apple refresh token encryption failed: {error}");
            return false;
        }
    };
    match UserIdentityRepository::new(pool.clone())
        .store_apple_refresh_token(tenant_id, &identity.subject, &encrypted, &verified.audience)
        .await
    {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!("Apple refresh token could not be stored: {error}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn errors_use_the_documented_status_and_code() {
        let cases = [
            (
                SocialLoginHttpError::InvalidRequest("bad".to_string()),
                400,
                "INVALID_REQUEST",
            ),
            (SocialLoginHttpError::InvalidToken, 401, "INVALID_TOKEN"),
            (
                SocialLoginHttpError::AccountLinkRequired,
                409,
                "ACCOUNT_LINK_REQUIRED",
            ),
            (
                SocialLoginHttpError::EmailMissing(SocialProvider::Apple),
                400,
                "EMAIL_MISSING",
            ),
            (
                SocialLoginHttpError::EmailNotVerified(SocialProvider::Google),
                403,
                "EMAIL_NOT_VERIFIED",
            ),
            (
                SocialLoginHttpError::ProviderUnavailable {
                    provider: SocialProvider::Google,
                    retry_after: None,
                },
                503,
                "PROVIDER_UNAVAILABLE",
            ),
            (
                SocialLoginHttpError::TooManyRequests { retry_after: 5 },
                429,
                "TOO_MANY_ATTEMPTS",
            ),
        ];
        for (error, status, code) in cases {
            let expected_status = error_status(&error);
            let response = error.into_response();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(i32::from(response.status().as_u16()), expected_status);
            assert_eq!(body(response).await["code"], code);
        }
    }

    #[test]
    fn rate_limit_carries_retry_after() {
        let response = SocialLoginHttpError::TooManyRequests { retry_after: 7 }.into_response();
        assert_eq!(response.headers()["Retry-After"], "7");
    }
}
