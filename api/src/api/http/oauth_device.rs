//! Device authorization for Divine TV. Phone approval uses the Keycast browser session.

use axum::{
    extract::{rejection::FormRejection, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use chrono::Utc;
use keycast_core::{
    repositories::{
        oauth_device::{
            generate_user_code, normalize_user_code, DeviceAuthorizationRepository, DevicePoll,
            DeviceSession, DEVICE_CLIENT_ID, DEVICE_LIFETIME_SECONDS, DEVICE_POLL_INTERVAL_SECONDS,
            DEVICE_SCOPE, DEVICE_TOKEN_ORIGIN,
        },
        UserRepository,
    },
    types::refresh_token::{generate_refresh_token, hash_refresh_token, REFRESH_TOKEN_EXPIRY_DAYS},
};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{api::tenant::TenantExtractor, state::KeycastState, ucan_auth::validate_device_ucan};

use super::{
    atproto_oauth_metadata::{app_origin, endpoint},
    auth::{extract_ucan_from_cookie, sign_server_ucan},
    html_safety::{escape_attr, escape_html},
    routes::AuthState,
};

pub const VERIFICATION_PATH: &str = "/device";
pub const AUTHORIZATION_PATH: &str = "/oauth/device_authorization";
pub const SESSION_PATH: &str = "/oauth/device_session";
pub const REVOCATION_PATH: &str = "/oauth/device_revoke";
pub const REFRESH_PREFIX: &str = "tv1_";
const ACCESS_LIFETIME_SECONDS: i64 = 900;
const INCREMENT_WITH_TTL: &str = "
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    return count
";

#[derive(Debug, Clone, Copy)]
pub enum DeviceError {
    InvalidRequest,
    InvalidScope,
    InvalidClient,
    InvalidGrant,
    Pending,
    SlowDown,
    Denied,
    Expired,
    InvalidToken,
    RateLimited(u32),
    Unavailable,
}

impl IntoResponse for DeviceError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::InvalidScope => (StatusCode::BAD_REQUEST, "invalid_scope"),
            Self::InvalidClient => (StatusCode::BAD_REQUEST, "invalid_client"),
            Self::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant"),
            Self::Pending => (StatusCode::BAD_REQUEST, "authorization_pending"),
            Self::SlowDown => (StatusCode::BAD_REQUEST, "slow_down"),
            Self::Denied => (StatusCode::BAD_REQUEST, "access_denied"),
            Self::Expired => (StatusCode::BAD_REQUEST, "expired_token"),
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
            Self::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        };
        let mut response = no_store((status, Json(json!({"error": error}))).into_response());
        if let Self::RateLimited(seconds) = self {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.into());
        }
        if let Self::InvalidToken = self {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
        }
        response
    }
}

impl From<sqlx::Error> for DeviceError {
    fn from(error: sqlx::Error) -> Self {
        // Database errors can include bound column values.
        tracing::error!(kind = ?std::mem::discriminant(&error), "TV authorization database error");
        Self::Unavailable
    }
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}

async fn admission(
    state: &KeycastState,
    subject: String,
    limit: u64,
    window: u32,
) -> Result<(), DeviceError> {
    let redis = state.redis.as_ref().ok_or(DeviceError::Unavailable)?;
    let count: u64 = redis
        .invoke_script(INCREMENT_WITH_TTL, &[subject], &[window.to_string()])
        .await
        .map_err(|_| DeviceError::Unavailable)?;
    if count > limit {
        return Err(DeviceError::RateLimited(window));
    }
    Ok(())
}

fn validate_client_id(client_id: &str) -> Result<(), DeviceError> {
    if client_id != DEVICE_CLIENT_ID {
        return Err(DeviceError::InvalidClient);
    }
    Ok(())
}

fn format_user_code(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

#[derive(Deserialize)]
pub struct DeviceAuthorizationRequest {
    client_id: String,
    scope: Option<String>,
}

#[derive(Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i32,
}

pub async fn authorize(
    TenantExtractor(tenant): TenantExtractor,
    State(auth): State<AuthState>,
    form: Result<Form<DeviceAuthorizationRequest>, FormRejection>,
) -> Result<Response, DeviceError> {
    let Form(request) = form.map_err(|_| DeviceError::InvalidRequest)?;
    validate_client_id(&request.client_id)?;
    let origin = app_origin();
    let verification_url = reqwest::Url::parse(&origin).map_err(|_| DeviceError::Unavailable)?;
    if verification_url.host_str() != Some(tenant.domain.as_str()) {
        return Err(DeviceError::InvalidClient);
    }
    if request
        .scope
        .as_deref()
        .is_some_and(|scope| scope != DEVICE_SCOPE)
    {
        return Err(DeviceError::InvalidScope);
    }
    admission(
        &auth.state,
        format!("oauth_device:create:{}", tenant.id),
        600,
        60,
    )
    .await?;
    let repo = DeviceAuthorizationRepository::new(&auth.state.db);

    for _ in 0..3 {
        let device_code = generate_refresh_token();
        let user_code = generate_user_code();
        if repo
            .create_grant(
                tenant.id,
                &hash_refresh_token(&device_code),
                &hash_refresh_token(&user_code),
            )
            .await?
        {
            let user_code = format_user_code(&user_code);
            let verification_uri = endpoint(&origin, VERIFICATION_PATH);
            let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
            return Ok(no_store(
                Json(DeviceAuthorizationResponse {
                    device_code,
                    user_code,
                    verification_uri,
                    verification_uri_complete,
                    expires_in: DEVICE_LIFETIME_SECONDS,
                    interval: DEVICE_POLL_INTERVAL_SECONDS,
                })
                .into_response(),
            ));
        }
    }

    Err(DeviceError::Unavailable)
}

#[derive(Serialize)]
struct DeviceTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: &'static str,
    pubkey: String,
    refresh_token: String,
}

async fn issue_access_token(
    tenant_id: i64,
    auth: &AuthState,
    session: DeviceSession,
    refresh_token: String,
) -> Result<Response, DeviceError> {
    let pubkey = PublicKey::from_hex(&session.user_pubkey).map_err(|_| DeviceError::Unavailable)?;
    let expires_in = (session.expires_at - Utc::now())
        .num_seconds()
        .min(ACCESS_LIFETIME_SECONDS);
    if expires_in <= 0 {
        return Err(DeviceError::InvalidGrant);
    }
    let access_token = sign_server_ucan(
        &pubkey,
        &auth.state.server_keys,
        json!({
            "tenant_id": tenant_id,
            "redirect_origin": DEVICE_TOKEN_ORIGIN,
            "device_session": session.id,
        }),
        expires_in as u64,
    )
    .await
    .map_err(|_| DeviceError::Unavailable)?;

    Ok(no_store(
        Json(DeviceTokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            scope: DEVICE_SCOPE,
            pubkey: pubkey.to_hex(),
            refresh_token,
        })
        .into_response(),
    ))
}

pub async fn exchange(
    tenant_id: i64,
    auth: AuthState,
    client_id: &str,
    device_code: Option<&str>,
) -> Result<Response, DeviceError> {
    validate_client_id(client_id)?;
    let code = device_code.ok_or(DeviceError::InvalidRequest)?;
    if code.len() != 64 || !code.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(DeviceError::InvalidGrant);
    }

    let session_id = Uuid::new_v4().to_string();
    let refresh_token = format!("{REFRESH_PREFIX}{}", generate_refresh_token());
    let repo = DeviceAuthorizationRepository::new(&auth.state.db);
    match repo
        .poll(
            tenant_id,
            &hash_refresh_token(code),
            &session_id,
            &hash_refresh_token(&refresh_token),
            REFRESH_TOKEN_EXPIRY_DAYS,
        )
        .await?
    {
        DevicePoll::Pending => Err(DeviceError::Pending),
        DevicePoll::SlowDown => Err(DeviceError::SlowDown),
        DevicePoll::Denied => Err(DeviceError::Denied),
        DevicePoll::Expired => Err(DeviceError::Expired),
        DevicePoll::Invalid => Err(DeviceError::InvalidGrant),
        DevicePoll::Approved(session) => {
            issue_access_token(tenant_id, &auth, session, refresh_token).await
        }
    }
}

pub async fn refresh(
    tenant_id: i64,
    auth: AuthState,
    client_id: &str,
    current_token: &str,
) -> Result<Response, DeviceError> {
    validate_client_id(client_id)?;
    if !current_token
        .strip_prefix(REFRESH_PREFIX)
        .is_some_and(|token| token.len() == 64 && token.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(DeviceError::InvalidGrant);
    }

    let refresh_token = format!("{REFRESH_PREFIX}{}", generate_refresh_token());
    let repo = DeviceAuthorizationRepository::new(&auth.state.db);
    let session = repo
        .rotate_refresh_token(
            tenant_id,
            &hash_refresh_token(current_token),
            &hash_refresh_token(&refresh_token),
        )
        .await?
        .ok_or(DeviceError::InvalidGrant)?;
    issue_access_token(tenant_id, &auth, session, refresh_token).await
}

async fn authenticate(
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<(String, String), DeviceError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(DeviceError::InvalidToken)?;
    validate_device_ucan(bearer, tenant_id)
        .await
        .map_err(|_| DeviceError::InvalidToken)
}

pub async fn session(
    TenantExtractor(tenant): TenantExtractor,
    State(auth): State<AuthState>,
    headers: HeaderMap,
) -> Result<Response, DeviceError> {
    let (pubkey, session_id) = authenticate(&headers, tenant.id).await?;
    if !DeviceAuthorizationRepository::new(&auth.state.db)
        .active(tenant.id, &session_id, &pubkey)
        .await?
    {
        return Err(DeviceError::InvalidToken);
    }
    Ok(no_store(Json(json!({"pubkey": pubkey})).into_response()))
}

pub async fn revoke(
    TenantExtractor(tenant): TenantExtractor,
    State(auth): State<AuthState>,
    headers: HeaderMap,
) -> Result<Response, DeviceError> {
    let (pubkey, session_id) = authenticate(&headers, tenant.id).await?;
    DeviceAuthorizationRepository::new(&auth.state.db)
        .revoke(tenant.id, &session_id, &pubkey)
        .await?;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

fn verification_html(status: StatusCode, content: &str) -> Response {
    no_store((
        status,
        [
            // Form POSTs need a same-origin Origin header. Limit the Referer to its origin.
            (header::REFERRER_POLICY, "strict-origin"),
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ],
        Html(include_str!("oauth_device_page.html").replace("<!-- content -->", content)),
    ).into_response())
}

fn code_prompt(invalid: bool) -> Response {
    let error = if invalid {
        "<p role=\"alert\">That code is invalid or has expired. Check the code on your TV or request a new one.</p>"
    } else {
        ""
    };
    verification_html(
        if invalid {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::OK
        },
        &format!(
            r#"<h1>Sign in to Divine TV</h1>
        <p>Enter the code shown on your TV.</p>
        {error}
        <form action="{VERIFICATION_PATH}" method="get">
            <label for="user_code">TV code</label>
            <input id="user_code" name="user_code" type="text" autocomplete="off"
                autocapitalize="characters" spellcheck="false" maxlength="12" required>
            <button>Continue</button>
        </form>"#
        ),
    )
}

fn browser_error(error: DeviceError) -> Response {
    match error {
        DeviceError::RateLimited(retry) => {
            let mut response = verification_html(
                StatusCode::TOO_MANY_REQUESTS,
                "<h1>Too many attempts</h1><p>Wait a few minutes and try again.</p>",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry.into());
            response
        }
        _ => verification_html(
            StatusCode::SERVICE_UNAVAILABLE,
            "<h1>Sign-in is temporarily unavailable</h1><p>Try again in a moment.</p>",
        ),
    }
}

fn login_link(code: &str) -> String {
    let path = format!("{VERIFICATION_PATH}?user_code={code}");
    format!("/login?redirect={}", urlencoding::encode(&path))
}

async fn browser_identity(headers: &HeaderMap, tenant_id: i64) -> Option<String> {
    let cookie = extract_ucan_from_cookie(headers)?;
    let (pubkey, _, bunker_pubkey, _) =
        crate::ucan_auth::validate_ucan_token(&format!("Bearer {cookie}"), tenant_id)
            .await
            .ok()?;
    bunker_pubkey.is_none().then_some(pubkey)
}

#[derive(Deserialize)]
pub struct VerificationQuery {
    user_code: Option<String>,
}

pub async fn verify_page(
    TenantExtractor(tenant): TenantExtractor,
    State(auth): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<VerificationQuery>,
) -> Response {
    let Some(input) = query.user_code else {
        return code_prompt(false);
    };
    let Some(code) = normalize_user_code(&input) else {
        return code_prompt(true);
    };
    let formatted_code = format_user_code(&code);
    let login = login_link(&formatted_code);
    let Some(pubkey) = browser_identity(&headers, tenant.id).await else {
        let mut response = no_store(Redirect::to(&login).into_response());
        response.headers_mut().insert(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("no-referrer"),
        );
        return response;
    };
    if let Err(error) = approval_admission(&auth.state, tenant.id, &pubkey).await {
        return browser_error(error);
    }
    let repo = DeviceAuthorizationRepository::new(&auth.state.db);
    match repo.is_pending(tenant.id, &hash_refresh_token(&code)).await {
        Ok(true) => {}
        Ok(false) => return code_prompt(true),
        Err(error) => return browser_error(error.into()),
    }

    let users = UserRepository::new(auth.state.db.clone());
    let account = match users.get_account_status(&pubkey, tenant.id).await {
        Ok(Some(account))
            if account.status.is_active()
                && (account.email.is_some() && account.email_verified == Some(true)) =>
        {
            account
        }
        Ok(_) => {
            return verification_html(
                StatusCode::FORBIDDEN,
                &format!(
                    r#"<h1>Use an active account</h1><p><a href="{}">Return to Keycast sign-in</a></p>"#,
                    escape_attr(&login)
                ),
            )
        }
        Err(_) => return browser_error(DeviceError::Unavailable),
    };
    let identity = account.email.as_deref().unwrap_or(&pubkey);

    verification_html(
        StatusCode::OK,
        &format!(
            r#"<h1>Sign in to Divine TV</h1>
        <p>Make sure this code matches the one shown on your own TV.</p>
        <p class="code">{formatted_code}</p>
        <p>Continue as <strong>{}</strong>. Divine TV can read public account information, including your follows.</p>
        <p><a href="{}">Use a different account</a></p>
        <form action="{VERIFICATION_PATH}" method="post">
            <input type="hidden" name="user_code" value="{formatted_code}">
            <input type="hidden" name="account" value="{}">
            <button name="decision" value="approve">Allow</button>
            <button class="secondary" name="decision" value="deny">Deny</button>
        </form>"#,
            escape_html(identity),
            escape_attr(&login),
            escape_attr(&pubkey)
        ),
    )
}

async fn approval_admission(
    state: &KeycastState,
    tenant_id: i64,
    pubkey: &str,
) -> Result<(), DeviceError> {
    admission(
        state,
        format!("oauth_device:verify:{tenant_id}:{pubkey}"),
        20,
        600,
    )
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Approve,
    Deny,
}

#[derive(Deserialize)]
pub struct VerificationDecision {
    user_code: String,
    decision: Decision,
    account: String,
}

pub async fn verify_decision(
    TenantExtractor(tenant): TenantExtractor,
    State(auth): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<VerificationDecision>, FormRejection>,
) -> Response {
    if headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok())
        != Some(app_origin().as_str())
    {
        return verification_html(
            StatusCode::FORBIDDEN,
            "<h1>Open the TV sign-in page again</h1>",
        );
    }
    let Ok(Form(form)) = form else {
        return code_prompt(true);
    };
    let Some(code) = normalize_user_code(&form.user_code) else {
        return code_prompt(true);
    };
    let Some(pubkey) = browser_identity(&headers, tenant.id).await else {
        return verification_html(
            StatusCode::UNAUTHORIZED,
            &format!(
                r#"<h1>Sign in to finish</h1><p><a href="{}">Continue to Keycast sign-in</a></p>"#,
                escape_attr(&login_link(&format_user_code(&code)))
            ),
        );
    };
    if form.account != pubkey {
        return verification_html(
            StatusCode::CONFLICT,
            &format!(
                r#"<h1>Your signed-in account changed</h1><p><a href="{VERIFICATION_PATH}?user_code={}">Review the TV sign-in again</a></p>"#,
                format_user_code(&code)
            ),
        );
    }
    if let Err(error) = approval_admission(&auth.state, tenant.id, &pubkey).await {
        return browser_error(error);
    }

    let approved = matches!(form.decision, Decision::Approve);
    let repo = DeviceAuthorizationRepository::new(&auth.state.db);
    match repo
        .decide(tenant.id, &hash_refresh_token(&code), &pubkey, approved)
        .await
    {
        Ok(true) if approved => verification_html(
            StatusCode::OK,
            "<h1>TV sign-in approved</h1><p>Return to your TV to keep watching.</p>",
        ),
        Ok(true) => verification_html(
            StatusCode::OK,
            "<h1>TV sign-in denied</h1><p>You can close this page.</p>",
        ),
        Ok(false) => code_prompt(true),
        Err(error) => browser_error(error.into()),
    }
}
