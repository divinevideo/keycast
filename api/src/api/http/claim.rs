// ABOUTME: Account claim flow for preloaded users to set email/password
// ABOUTME: Used when Vine-imported users claim their Keycast accounts

use axum::{
    extract::{Query, State},
    http::header,
    response::{Html, IntoResponse, Response},
    Form,
};
use nostr_sdk::Keys;
use serde::Deserialize;

use super::routes::AuthState;
use keycast_core::repositories::{ClaimTokenRepository, UserRepository};

/// Get server keys from SERVER_NSEC environment variable
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

    // Validate token
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let claim_token = claim_token_repo
        .find_valid(&params.token)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
        .ok_or(ClaimError::InvalidToken)?;

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
            <input type="password" id="password" name="password" required placeholder="••••••••" minlength="8">
            <p class="requirements">At least 8 characters</p>

            <label for="password_confirmation">Confirm Password</label>
            <input type="password" id="password_confirmation" name="password_confirmation" required placeholder="••••••••">

            <button type="submit">Claim Account</button>
        </form>
    </div>

    <script>
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
        display_name = html_escape(&display_name_str),
        username = html_escape(&username_str),
        token = html_escape(&params.token),
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

    // Validate token
    let claim_token_repo = ClaimTokenRepository::new(pool.clone());
    let claim_token = claim_token_repo
        .find_valid(&form.token)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
        .ok_or(ClaimError::InvalidToken)?;

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

    // Hash password (synchronous bcrypt for claim flow - simpler)
    let password_hash = bcrypt::hash(&form.password, bcrypt::DEFAULT_COST)
        .map_err(|e| ClaimError::Internal(format!("Password hashing failed: {}", e)))?;

    // Update user with email and password_hash
    user_repo
        .claim_account(
            &claim_token.user_pubkey,
            tenant_id,
            &form.email,
            &password_hash,
        )
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?;

    // Mark token as used
    claim_token_repo
        .mark_used(&form.token)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?;

    tracing::info!(
        "Account claimed: pubkey={}, email={}",
        &claim_token.user_pubkey[..8],
        &form.email
    );

    // Generate session UCAN and set cookie
    let user_pubkey = nostr_sdk::PublicKey::from_hex(&claim_token.user_pubkey)
        .map_err(|e| ClaimError::Internal(format!("Invalid pubkey: {}", e)))?;

    // Load server keys for UCAN signing
    let server_keys = get_server_keys()?;

    let token = super::auth::generate_server_signed_ucan(
        &user_pubkey,
        tenant_id,
        &form.email,
        "claim",
        None,
        &server_keys,
        false, // Account claim is not first-party OAuth
        None,
    )
    .await
    .map_err(|e| ClaimError::Internal(format!("Failed to generate session: {:?}", e)))?;

    // Set session cookie and redirect to dashboard
    let cookie_value = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        token,
        60 * 60 * 24 * 7 // 7 days
    );

    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    Ok((
        [
            (header::SET_COOKIE, cookie_value),
            (header::LOCATION, format!("{}/", app_url)),
        ],
        axum::http::StatusCode::SEE_OTHER,
    )
        .into_response())
}

/// HTML-escape a string to prevent XSS
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Claim-specific errors
#[derive(Debug)]
pub enum ClaimError {
    InvalidToken,
    UserNotFound,
    PasswordMismatch,
    WeakPassword,
    InvalidEmail,
    EmailExists,
    Internal(String),
}

impl IntoResponse for ClaimError {
    fn into_response(self) -> Response {
        let (title, message) = match self {
            ClaimError::InvalidToken => (
                "Invalid or Expired Link",
                "This claim link is invalid or has already been used. Please contact support for a new link.",
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
            title = title,
            message = message,
        );

        (axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response()
    }
}
