// ABOUTME: Account claim flow for preloaded users to set email/password
// ABOUTME: Used when Vine-imported users claim their Keycast accounts

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Form,
};
use chrono::{DateTime, Duration, Utc};
use nostr_sdk::Keys;
use secrecy::SecretString;
use serde::Deserialize;

use super::html_safety::{escape_attr, escape_html};
use super::routes::AuthState;
use crate::brand::BRAND_NAME;
use keycast_core::{
    bcrypt_admission::{BcryptAdmissionError, BcryptWorkload},
    repositories::{ClaimTokenRepository, UserRepository},
};

fn password_visibility_toggle_html(field_id: &str) -> String {
    format!(
        r#"<button type="button" class="password-toggle" data-password-target="{}" aria-label="Show password" title="Show password" onclick="togglePasswordVisibility(this)">Show</button>"#,
        escape_attr(field_id)
    )
}

/// Get server keys from SERVER_NSEC environment variable, for signing the
/// session UCAN issued when a claim confirmation completes.
fn get_server_keys() -> Result<Keys, ClaimError> {
    let server_nsec = std::env::var("SERVER_NSEC")
        .map_err(|_| ClaimError::Internal("SERVER_NSEC not configured".to_string()))?;
    Keys::parse(&server_nsec)
        .map_err(|e| ClaimError::Internal(format!("Invalid SERVER_NSEC: {}", e)))
}

/// Query parameters for GET /claim
#[derive(Debug, Deserialize)]
pub struct ClaimQuery {
    pub token: String,
}

/// Form data for POST /claim
#[derive(Debug, Deserialize)]
pub struct ClaimForm {
    pub token: String,
    pub email: String,
    pub password: String,
    pub password_confirmation: String,
}

/// GET /claim?token=...
/// Shows HTML form for user to set email/password
pub async fn claim_get(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Query(params): Query<ClaimQuery>,
) -> Result<Response, ClaimError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Classify token into one of the five terminal states so we can render a
    // state-specific error page when it's not valid.
    use keycast_core::types::claim_token::ClaimTokenState;
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let claim_token = match claim_token_repo
        .classify(&params.token, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        ClaimTokenState::Valid(ct) => ct,
        ClaimTokenState::Unrecognized => return Err(ClaimError::TokenUnrecognized),
        ClaimTokenState::AlreadyClaimed(_) => return Err(ClaimError::TokenAlreadyClaimed),
        ClaimTokenState::AdminInvalidated(_) => return Err(ClaimError::TokenAdminInvalidated),
        ClaimTokenState::Replaced { .. } => return Err(ClaimError::TokenReplaced),
        ClaimTokenState::Expired(_) => return Err(ClaimError::TokenExpired),
    };

    // Get user info (username, display_name)
    let user_repo = UserRepository::new(pool.clone());
    let (username, display_name) = user_repo
        .get_claim_info(&claim_token.user_pubkey, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
        .ok_or(ClaimError::UserNotFound)?;

    let display_name_str = display_name.unwrap_or_else(|| username.clone().unwrap_or_default());
    let username_str = username.unwrap_or_default();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Claim Your Account</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: #072218;
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: #0F2E23;
            border: 1px solid #1C4033;
            border-radius: 12px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            box-shadow: 0 8px 32px rgba(39, 197, 139, 0.08);
        }}
        h1 {{
            margin: 0 0 8px 0;
            color: #F9F7F6;
            font-size: 22px;
            font-weight: 600;
        }}
        .welcome {{
            color: #BEB3A7;
            font-size: 14px;
            margin: 0 0 28px 0;
            line-height: 1.5;
        }}
        .user-info {{
            background: #072218;
            border: 1px solid #1C4033;
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 24px;
        }}
        .user-info .name {{
            font-weight: 600;
            color: #F9F7F6;
            font-size: 16px;
        }}
        .user-info .username {{
            color: #9CA3AF;
            font-size: 13px;
            margin-top: 2px;
        }}
        label {{
            display: block;
            margin-bottom: 6px;
            color: #BEB3A7;
            font-size: 13px;
            font-weight: 500;
        }}
        input {{
            width: 100%;
            padding: 11px 14px;
            background: #072218;
            border: 1px solid #1C4033;
            border-radius: 8px;
            font-size: 15px;
            color: #F9F7F6;
            margin-bottom: 18px;
            transition: border-color 0.2s;
        }}
        input::placeholder {{
            color: #9CA3AF;
        }}
        input:focus {{
            outline: none;
            border-color: #27C58B;
            box-shadow: 0 0 0 3px rgba(39, 197, 139, 0.1);
        }}
        .password-input {{
            position: relative;
            margin-bottom: 18px;
        }}
        .password-input input {{
            padding-right: 92px;
            margin-bottom: 0;
        }}
        .password-toggle {{
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            width: auto;
            padding: 6px 10px;
            background: transparent;
            color: #27C58B;
            border: 1px solid #1C4033;
            border-radius: 6px;
            font-size: 12px;
            margin: 0;
        }}
        .password-toggle:hover {{
            background: rgba(39, 197, 139, 0.1);
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #27C58B;
            color: #072218;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 4px;
        }}
        button:hover {{
            background: #1AA575;
        }}
        .error {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #EF4444;
            padding: 10px 14px;
            border-radius: 8px;
            margin-bottom: 18px;
            display: none;
            font-size: 14px;
        }}
        .requirements {{
            font-size: 12px;
            color: #9CA3AF;
            margin-top: -14px;
            margin-bottom: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Claim Your Account</h1>
        <p class="welcome">Set up your login credentials to access your account.</p>

        <div class="user-info">
            <div class="name">{display_name}</div>
            <div class="username">@{username}</div>
        </div>

        <div class="error" id="error"></div>

        <form method="POST" action="/api/claim" onsubmit="return validateForm()">
            <input type="hidden" name="token" value="{token}">

            <label for="email">Email</label>
            <input type="email" id="email" name="email" required placeholder="your@email.com">

            <label for="password">Password</label>
            <div class="password-input">
                <input type="password" id="password" name="password" required placeholder="••••••••" minlength="8">
                {password_toggle}
            </div>
            <p class="requirements">At least 8 characters</p>

            <label for="password_confirmation">Confirm Password</label>
            <div class="password-input">
                <input type="password" id="password_confirmation" name="password_confirmation" required placeholder="••••••••">
                {password_confirmation_toggle}
            </div>

            <button type="submit">Claim Account</button>
        </form>
    </div>

    <script>
        function togglePasswordVisibility(button) {{
            const input = document.getElementById(button.dataset.passwordTarget);
            if (!input) return;

            const showing = input.type === 'text';
            input.type = showing ? 'password' : 'text';
            const label = showing ? 'Show password' : 'Hide password';
            button.textContent = showing ? 'Show' : 'Hide';
            button.setAttribute('aria-label', label);
            button.setAttribute('title', label);
        }}

        function validateForm() {{
            const password = document.getElementById('password').value;
            const confirmation = document.getElementById('password_confirmation').value;
            const error = document.getElementById('error');

            if (password.length < 8) {{
                error.textContent = 'Password must be at least 8 characters';
                error.style.display = 'block';
                return false;
            }}

            if (password !== confirmation) {{
                error.textContent = 'Passwords do not match';
                error.style.display = 'block';
                return false;
            }}

            return true;
        }}
    </script>
</body>
</html>"#,
        display_name = escape_html(&display_name_str),
        username = escape_html(&username_str),
        token = escape_html(&params.token),
        password_toggle = password_visibility_toggle_html("password"),
        password_confirmation_toggle = password_visibility_toggle_html("password_confirmation"),
    );

    Ok(Html(html).into_response())
}

/// POST /claim
/// Process claim - sets email/password, marks token as used, redirects to dashboard
pub async fn claim_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Form(mut form): Form<ClaimForm>,
) -> Result<Response, ClaimError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    form.email = form.email.to_lowercase();

    // Classify token into one of the five terminal states; on anything but
    // Valid, bail with the state-specific error page.
    use keycast_core::types::claim_token::ClaimTokenState;
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let claim_token = match claim_token_repo
        .classify(&form.token, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        ClaimTokenState::Valid(ct) => ct,
        ClaimTokenState::Unrecognized => return Err(ClaimError::TokenUnrecognized),
        ClaimTokenState::AlreadyClaimed(_) => return Err(ClaimError::TokenAlreadyClaimed),
        ClaimTokenState::AdminInvalidated(_) => return Err(ClaimError::TokenAdminInvalidated),
        ClaimTokenState::Replaced { .. } => return Err(ClaimError::TokenReplaced),
        ClaimTokenState::Expired(_) => return Err(ClaimError::TokenExpired),
    };

    // Validate passwords match
    if form.password != form.password_confirmation {
        return Err(ClaimError::PasswordMismatch);
    }

    // Validate password length
    if form.password.len() < 8 {
        return Err(ClaimError::WeakPassword);
    }

    // Validate email format (basic check)
    if !form.email.contains('@') || !form.email.contains('.') {
        return Err(ClaimError::InvalidEmail);
    }

    // Check email not already in use
    let user_repo = UserRepository::new(pool.clone());
    if user_repo
        .email_exists(&form.email, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        return Err(ClaimError::EmailExists);
    }

    let password_hash = auth_state
        .state
        .bcrypt
        .hash(
            BcryptWorkload::Claim,
            SecretString::from(form.password.clone()),
            bcrypt::DEFAULT_COST,
        )
        .await
        .map_err(|error| match error {
            BcryptAdmissionError::AtCapacity | BcryptAdmissionError::ShuttingDown => {
                ClaimError::ServiceUnavailable
            }
            BcryptAdmissionError::WorkerFailed | BcryptAdmissionError::Bcrypt(_) => {
                ClaimError::Internal("Password hashing failed".to_string())
            }
        })?;

    // Stage the pending claim instead of completing it: email, password hash,
    // and a fresh confirmation token sit on the claim-token row until the
    // claimer proves control of the address via the emailed confirmation link
    // (claim_confirm_get, Task 7). The guarded write re-checks validity under
    // the row lock, same as the old consume did, so a concurrent admin
    // invalidation (e.g. clear-verified-minor revoking this account's
    // outstanding link) still cannot land a claim.
    let confirmation_token = super::auth::generate_secure_token();
    let confirmation_expires_at = Utc::now()
        + Duration::hours(keycast_core::types::claim_token::CLAIM_CONFIRMATION_EXPIRY_HOURS);

    use keycast_core::repositories::StagePendingOutcome;
    match claim_token_repo
        .stage_pending_claim(
            &form.token,
            tenant_id,
            &form.email,
            &password_hash,
            &confirmation_token,
            confirmation_expires_at,
        )
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        StagePendingOutcome::Staged => {}
        StagePendingOutcome::TokenNotStageable => {
            // Token died between classification and staging (e.g. an admin
            // invalidation landed in between) - re-classify so the user gets
            // the state-specific error page.
            return Err(reclassify_to_error(&claim_token_repo, &form.token, tenant_id).await?);
        }
    }

    // Best-effort send; a send failure should not strand a staged claim
    // silently, so surface it to the claimer instead of showing a
    // "check your email" page for an email that was never sent.
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_claim_confirmation(&form.email, &confirmation_token)
                .await
            {
                tracing::error!(
                    "Failed to send claim confirmation to {}: {}",
                    &form.email,
                    e
                );
                return Err(ClaimError::Internal(
                    "Could not send confirmation email".to_string(),
                ));
            }
        }
        Err(e) => {
            tracing::error!("Email service unavailable: {}", e);
            return Err(ClaimError::Internal(
                "Could not send confirmation email".to_string(),
            ));
        }
    }

    tracing::info!(
        "Claim staged: pubkey={}, confirmation email sent",
        &claim_token.user_pubkey
    );

    Ok(Html(claim_confirmation_sent_html(Some(&form.email), &form.token)).into_response())
}

/// Re-classify a claim token that failed a guarded write (stage_pending_claim
/// now; claim_account_consuming_token previously) between the initial
/// `classify` call and the write itself, most commonly an admin invalidation
/// landing in between. Maps the token's current terminal state to the
/// state-specific error page so the claimer isn't shown a generic failure.
/// Shared by `claim_post` and (Task 7) `claim_confirm_get`.
async fn reclassify_to_error(
    claim_token_repo: &ClaimTokenRepository,
    token: &str,
    tenant_id: i64,
) -> Result<ClaimError, ClaimError> {
    use keycast_core::types::claim_token::ClaimTokenState;
    Ok(
        match claim_token_repo
            .classify(token, tenant_id)
            .await
            .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
        {
            ClaimTokenState::AlreadyClaimed(_) => ClaimError::TokenAlreadyClaimed,
            ClaimTokenState::AdminInvalidated(_) => ClaimError::TokenAdminInvalidated,
            ClaimTokenState::Replaced { .. } => ClaimError::TokenReplaced,
            ClaimTokenState::Expired(_) => ClaimError::TokenExpired,
            ClaimTokenState::Unrecognized => ClaimError::TokenUnrecognized,
            // A token that failed the guarded write cannot classify Valid
            // (used/invalidated/expired are one-way); treat as internal.
            ClaimTokenState::Valid(_) => {
                ClaimError::Internal("Token write failed but token classifies as valid".to_string())
            }
        },
    )
}

/// GET /api/claim/confirm?token=<confirmation_token>
/// Completes a staged claim when the claimer clicks the emailed confirmation
/// link: consumes the confirmation token (writing the staged email/password
/// onto the user atomically, per `confirm_claim_consuming_token`), issues the
/// session UCAN, and renders the "Account Claimed!" success page. This is
/// the second half of the flow `claim_post` starts.
pub async fn claim_confirm_get(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Query(params): Query<ClaimQuery>,
) -> Result<Response, ClaimError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let user_repo = UserRepository::new(pool.clone());

    use keycast_core::repositories::ClaimConsumeOutcome;
    let user_pubkey_hex = match user_repo
        .confirm_claim_consuming_token(&params.token, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        ClaimConsumeOutcome::Claimed { user_pubkey } => user_pubkey,
        ClaimConsumeOutcome::EmailTaken => return Err(ClaimError::EmailExists),
        ClaimConsumeOutcome::UserNotClaimable => return Err(ClaimError::TokenAlreadyClaimed),
        // No consumable row for this confirmation token: unknown or already
        // consumed, the 24h confirmation window itself expired, or the
        // underlying claim token died (admin-invalidated/replaced/expired)
        // during that window. classify_confirmation_failure (R6) tells these
        // apart for a precise error page.
        ClaimConsumeOutcome::TokenNotConsumable => {
            return Err(classify_confirmation_failure(pool, &params.token, tenant_id).await?);
        }
    };

    // Session + success page: relocated (verbatim, aside from being split into
    // named helpers) from the pre-Task-6 one-step claim_post tail --
    // git show 3c69839:api/src/api/http/claim.rs.
    let user_pubkey = nostr_sdk::PublicKey::from_hex(&user_pubkey_hex)
        .map_err(|e| ClaimError::Internal(format!("Invalid pubkey: {}", e)))?;

    // confirm_claim_consuming_token already wrote the staged email onto the
    // user row; read it back rather than threading a second copy through,
    // so the UCAN's email fact and the DB can never disagree.
    let email = user_repo
        .get_email(&user_pubkey_hex, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?;

    // Fetch account status for the UCAN fact (normally active at claim time).
    let claim_user_status = user_repo
        .get_user_status(&user_pubkey_hex, tenant_id)
        .await
        .ok()
        .flatten()
        .map(|(s, _, _)| s);

    let server_keys = get_server_keys()?;

    let session_token = super::auth::generate_server_signed_ucan(
        &user_pubkey,
        tenant_id,
        &email,
        "claim",
        None,
        &server_keys,
        false, // Account claim is not first-party OAuth
        None,
        claim_user_status.as_ref(),
    )
    .await
    .map_err(|e| ClaimError::Internal(format!("Failed to generate session: {:?}", e)))?;

    let cookie_value = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        session_token,
        60 * 60 * 24 * 7 // 7 days
    );

    let (username, display_name) = user_repo
        .get_claim_info(&user_pubkey_hex, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
        .unwrap_or((None, None));
    let display_name_str = display_name.unwrap_or_else(|| username.unwrap_or_default());

    tracing::info!("Claim confirmed: pubkey={}", &user_pubkey_hex);

    Ok((
        [(header::SET_COOKIE, cookie_value)],
        Html(claim_success_html(&display_name_str)),
    )
        .into_response())
}

/// Classify a `TokenNotConsumable` outcome from `confirm_claim_consuming_token`
/// into a precise error page (R6). That outcome collapses three distinct
/// causes: the confirmation token is unknown, or was already consumed (a
/// successful consume nulls `confirmation_token`, so a re-click of the same
/// link lands here too -- the intended idempotent behavior); the 24h
/// confirmation window itself expired; or the underlying claim token died
/// (admin-invalidated, replaced, or expired) sometime during that window.
async fn classify_confirmation_failure(
    pool: &sqlx::PgPool,
    confirmation_token: &str,
    tenant_id: i64,
) -> Result<ClaimError, ClaimError> {
    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT token, confirmation_expires_at FROM account_claim_tokens \
         WHERE confirmation_token = $1 AND tenant_id = $2",
    )
    .bind(confirmation_token)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?;

    let Some((claim_token, confirmation_expires_at)) = row else {
        // No row: unrecognized token, or already consumed. Idempotent re-click
        // behavior for the already-consumed case is intentional.
        return Ok(ClaimError::ConfirmationUnrecognized);
    };

    let confirmation_expired = match confirmation_expires_at {
        Some(expires_at) => expires_at <= Utc::now(),
        // Defensive: stage_pending_claim always sets confirmation_expires_at
        // alongside confirmation_token, so this shouldn't happen. Treat a
        // missing expiry as expired rather than falling through to a claim
        // token that may still classify as Valid.
        None => true,
    };
    if confirmation_expired {
        return Ok(ClaimError::ConfirmationExpired);
    }

    // The confirmation window is still valid, so the failure must be the
    // underlying claim token itself. Re-classify it for a precise page.
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    reclassify_to_error(&claim_token_repo, &claim_token, tenant_id).await
}

/// Success page shown after `claim_confirm_get` completes a claim. Relocated
/// verbatim from the pre-Task-6 one-step `claim_post` tail, extracted into
/// its own function so the handler above stays readable.
fn claim_success_html(display_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Claimed!</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: #072218;
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: #0F2E23;
            border: 1px solid #1C4033;
            border-radius: 12px;
            padding: 40px;
            max-width: 440px;
            width: 100%;
            text-align: center;
            box-shadow: 0 8px 32px rgba(39, 197, 139, 0.08);
        }}
        .checkmark {{
            width: 56px;
            height: 56px;
            background: rgba(39, 197, 139, 0.15);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 28px;
        }}
        h1 {{
            margin: 0 0 8px 0;
            color: #F9F7F6;
            font-size: 22px;
            font-weight: 600;
        }}
        .subtitle {{
            color: #BEB3A7;
            font-size: 14px;
            margin: 0 0 28px 0;
            line-height: 1.5;
        }}
        .steps {{
            text-align: left;
            margin-bottom: 28px;
        }}
        .step {{
            display: flex;
            gap: 14px;
            align-items: flex-start;
            margin-bottom: 18px;
        }}
        .step-num {{
            flex-shrink: 0;
            width: 28px;
            height: 28px;
            background: rgba(39, 197, 139, 0.15);
            color: #27C58B;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            font-weight: 700;
        }}
        .step-content {{
            flex: 1;
        }}
        .step-title {{
            color: #F9F7F6;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 3px;
        }}
        .step-desc {{
            color: #9CA3AF;
            font-size: 13px;
            line-height: 1.4;
        }}
        .app-links {{
            display: flex;
            gap: 10px;
            margin-top: 8px;
        }}
        .app-link {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 8px 14px;
            background: #072218;
            border: 1px solid #1C4033;
            border-radius: 8px;
            color: #F9F7F6;
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
            transition: border-color 0.2s;
        }}
        .app-link:hover {{
            border-color: #27C58B;
        }}
        .divider {{
            border-top: 1px solid #1C4033;
            margin: 0 0 20px 0;
        }}
        .web-link {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 24px;
            background: #27C58B;
            color: #072218;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
            transition: background 0.2s;
        }}
        .web-link:hover {{
            background: #1AA575;
        }}
        .note {{
            color: #9CA3AF;
            font-size: 12px;
            margin-top: 16px;
            line-height: 1.4;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">&#10003;</div>
        <h1>Account Claimed!</h1>
        <p class="subtitle">Welcome, {display_name}. Your credentials have been set.</p>

        <div class="steps">
            <div class="step">
                <div class="step-num">1</div>
                <div class="step-content">
                    <div class="step-title">Get the App</div>
                    <div class="step-desc">Download {brand} for the best experience.</div>
                    <div class="app-links">
                        <a class="app-link" href="https://apps.apple.com/app/divine-video/id6744577425" target="_blank">
                            &#63743; App Store
                        </a>
                        <a class="app-link" href="https://play.google.com/store/apps/details?id=com.openvine.divine" target="_blank">
                            &#9654; Google Play
                        </a>
                    </div>
                </div>
            </div>
            <div class="step">
                <div class="step-num">2</div>
                <div class="step-content">
                    <div class="step-title">Sign In</div>
                    <div class="step-desc">Use the email and password you just set to sign in.</div>
                </div>
            </div>
            <div class="step">
                <div class="step-num">3</div>
                <div class="step-content">
                    <div class="step-title">Your Content is Waiting</div>
                    <div class="step-desc">Your videos and profile are ready to go.</div>
                </div>
            </div>
        </div>

        <div class="divider"></div>

        <a class="web-link" href="https://divine.video" target="_blank">
            Open {brand} on Web
        </a>
        <p class="note">You can also access your account at divine.video</p>
    </div>
</body>
</html>"#,
        display_name = escape_html(display_name),
        brand = BRAND_NAME,
    )
}

/// Interstitial shown after a claim is staged (POST /claim) or after a resend
/// request (POST /claim/resend, Task 8). `email` is the destination address
/// to display; `None` renders enumeration-safe generic copy so the resend
/// endpoint never reveals whether a given address has a pending claim.
/// `token` is the original claim token, always available at both call sites,
/// and is threaded into the resend form's hidden field so the resend request
/// has something to act on.
fn claim_confirmation_sent_html(email: Option<&str>, token: &str) -> String {
    let message = match email {
        Some(address) => format!(
            "We sent a confirmation link to <strong>{}</strong>. Click the link in that email to finish claiming your account.",
            escape_html(address)
        ),
        None => "If a pending claim exists for that address, we've sent another confirmation link. Check your email.".to_string(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Your Email</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: #072218;
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: #0F2E23;
            border: 1px solid #1C4033;
            border-radius: 12px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            text-align: center;
            box-shadow: 0 8px 32px rgba(39, 197, 139, 0.08);
        }}
        .icon {{
            width: 56px;
            height: 56px;
            background: rgba(39, 197, 139, 0.15);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 28px;
        }}
        h1 {{
            margin: 0 0 8px 0;
            color: #F9F7F6;
            font-size: 22px;
            font-weight: 600;
        }}
        p {{
            color: #BEB3A7;
            font-size: 14px;
            margin: 0 0 24px 0;
            line-height: 1.5;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: transparent;
            color: #27C58B;
            border: 1px solid #1C4033;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: border-color 0.2s;
        }}
        button:hover {{
            border-color: #27C58B;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#9993;</div>
        <h1>Check Your Email</h1>
        <p>{message}</p>
        <form method="POST" action="/api/claim/resend">
            <input type="hidden" name="token" value="{token}">
            <button type="submit">Resend Confirmation Email</button>
        </form>
    </div>
</body>
</html>"#,
        message = message,
        token = escape_attr(token),
    )
}

/// Claim-specific errors
#[derive(Debug)]
pub enum ClaimError {
    /// No row matches the token string.
    TokenUnrecognized,
    /// Token row exists and `used_at IS NOT NULL`.
    TokenAlreadyClaimed,
    /// Token row exists and `invalidated_at IS NOT NULL` (admin-killed).
    TokenAdminInvalidated,
    /// Token is past `expires_at` and a newer valid token exists for same user.
    TokenReplaced,
    /// Token is past `expires_at`, no newer valid token, no admin invalidation.
    TokenExpired,
    /// No `account_claim_tokens` row matches the confirmation token: unknown,
    /// or already consumed (a successful confirm nulls it, so a re-click of
    /// the same link intentionally lands here too).
    ConfirmationUnrecognized,
    /// A row matches the confirmation token but its 24h confirmation window
    /// has passed.
    ConfirmationExpired,
    UserNotFound,
    PasswordMismatch,
    WeakPassword,
    InvalidEmail,
    EmailExists,
    ServiceUnavailable,
    Internal(String),
}

impl IntoResponse for ClaimError {
    fn into_response(self) -> Response {
        let (title, message) = match self {
            ClaimError::TokenUnrecognized => (
                "Link not recognized",
                "We don't recognize this claim link. Double-check the URL you received, or contact the person who sent it for help.",
            ),
            ClaimError::TokenAlreadyClaimed => (
                "Account already claimed",
                "This account has already been claimed. If you set it up, sign in at divine.video. If you didn't, contact support — someone else may have used this link.",
            ),
            ClaimError::TokenAdminInvalidated => (
                "Link has been deactivated",
                "This claim link was deactivated by Divine support. Contact the person who sent it, or email support@divine.video, to learn more.",
            ),
            ClaimError::TokenReplaced => (
                "Link has been replaced",
                "A newer claim link has been issued for this account. Check your email for the most recent message from Divine support, or contact the person who sent it for the current link.",
            ),
            ClaimError::TokenExpired => (
                "Link has expired",
                "Claim links are valid for 7 days. This one is past its expiration. Contact the person who sent it, or email support@divine.video, for a fresh link.",
            ),
            ClaimError::ConfirmationUnrecognized => (
                "Link not recognized",
                "We don't recognize this confirmation link. It may have already been used. If you set up your account, sign in at divine.video.",
            ),
            ClaimError::ConfirmationExpired => (
                "Confirmation link expired",
                "Confirmation links are valid for 24 hours. Open your original claim link again to restart, or email support@divine.video for a fresh one.",
            ),
            ClaimError::UserNotFound => (
                "Account Not Found",
                "The account associated with this link could not be found. Please contact support.",
            ),
            ClaimError::PasswordMismatch => (
                "Passwords Don't Match",
                "The passwords you entered don't match. Please go back and try again.",
            ),
            ClaimError::WeakPassword => (
                "Password Too Short",
                "Your password must be at least 8 characters. Please go back and try again.",
            ),
            ClaimError::InvalidEmail => (
                "Invalid Email",
                "Please enter a valid email address.",
            ),
            ClaimError::EmailExists => (
                "Email Already Registered",
                "This email address is already associated with another account. Please use a different email or contact support.",
            ),
            ClaimError::ServiceUnavailable => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("Retry-After", "1")],
                    Html("Password service is busy. Please try again shortly."),
                )
                    .into_response();
            }
            ClaimError::Internal(ref msg) => {
                tracing::error!("Claim error: {}", msg);
                (
                    "Something Went Wrong",
                    "An unexpected error occurred. Please try again or contact support.",
                )
            }
        };

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: #072218;
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: #0F2E23;
            border: 1px solid #1C4033;
            border-radius: 12px;
            padding: 40px;
            max-width: 400px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(39, 197, 139, 0.08);
        }}
        h1 {{
            color: #EF4444;
            margin: 0 0 12px 0;
            font-size: 20px;
            font-weight: 600;
        }}
        p {{
            color: #BEB3A7;
            line-height: 1.6;
            font-size: 14px;
            margin: 0;
        }}
        a {{
            display: inline-block;
            margin-top: 24px;
            color: #27C58B;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            transition: color 0.2s;
        }}
        a:hover {{
            color: #1AA575;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>{message}</p>
        <a href="javascript:history.back()">Go Back</a>
    </div>
</body>
</html>"#,
            // All current title/message values are hardcoded string literals,
            // but route every interpolation through escape_html() to match the
            // escape-everywhere pattern established in PR #67 and applied in
            // claim_get's success-page template above. This defends against a
            // future dev adding dynamic content to a ClaimError variant
            // without remembering to escape it at the call site.
            title = escape_html(title),
            message = escape_html(message),
        );

        (axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcrypt_capacity_maps_to_retryable_service_unavailable() {
        let response = ClaimError::ServiceUnavailable.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["Retry-After"], "1");
    }

    #[test]
    fn password_visibility_controls_target_claim_fields() {
        let password_toggle = password_visibility_toggle_html("password");
        let confirmation_toggle = password_visibility_toggle_html("password_confirmation");

        for markup in [&password_toggle, &confirmation_toggle] {
            assert!(markup.contains("type=\"button\""));
            assert!(markup.contains("aria-label=\"Show password\""));
            assert!(markup.contains("onclick=\"togglePasswordVisibility(this)\""));
        }

        assert!(password_toggle.contains("data-password-target=\"password\""));
        assert!(confirmation_toggle.contains("data-password-target=\"password_confirmation\""));
    }
}
