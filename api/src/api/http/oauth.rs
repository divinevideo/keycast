// ABOUTME: OAuth 2.0 authorization flow handlers for third-party app access
// ABOUTME: Implements authorization code flow that issues bunker URLs for NIP-46 remote signing

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response, Html},
    Form, Json,
};
use base64::Engine;
use bcrypt::verify;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use nostr_sdk::{Keys, ToBech32};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{Duration as StdDuration, Instant};

// Import constants and helpers from auth module
use super::auth::{TOKEN_EXPIRY_HOURS, EMAIL_VERIFICATION_EXPIRY_HOURS, generate_secure_token};

/// Polling cache for iOS PWA OAuth flow
/// Maps state token → (authorization code, expiry time)
/// TTL: 5 minutes for security
static POLLING_CACHE: Lazy<DashMap<String, (String, Instant)>> = Lazy::new(DashMap::new);

const POLLING_TTL: StdDuration = StdDuration::from_secs(300); // 5 minutes

/// Extract optional nsec from PKCE code_verifier
/// Format: "{random}.{nsec}" where nsec is either nsec1... (bech32) or 64-char hex
/// Returns None if no nsec embedded (standard PKCE flow)
pub fn extract_nsec_from_verifier_public(verifier: &str) -> Option<String> {
    if let Some((_random, nsec)) = verifier.split_once('.') {
        // Check if it looks like an nsec (starts with nsec1) or hex (64 chars)
        if nsec.starts_with("nsec1") || (nsec.len() == 64 && nsec.chars().all(|c| c.is_ascii_hexdigit())) {
            return Some(nsec.to_string());
        }
    }
    None
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,  // OAuth 2.0 prompt parameter: "login", "consent", "none"
    pub byok_pubkey: Option<String>,  // BYOK: force registration with this pubkey
    pub default_register: Option<bool>,  // Legacy: show register form by default
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub approved: bool,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,  // "authorization_code" only
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,  // For PKCE
}

/// Generate UCAN token signed by user's key
/// Note: Currently using auth::generate_ucan_token instead, but keeping this for potential future use
#[allow(dead_code)]
async fn generate_ucan_token(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
) -> Result<String, OAuthError> {
    use crate::ucan_auth::{NostrKeyMaterial, nostr_pubkey_to_did};
    use ucan::builder::UcanBuilder;
    use serde_json::json;

    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());

    // Create facts as a single JSON object
    let facts = json!({
        "tenant_id": tenant_id,
        "email": email,
    });

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)  // Self-issued
        .with_lifetime((TOKEN_EXPIRY_HOURS * 3600) as u64)  // 24 hours in seconds
        .with_fact(facts)
        .build()
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to build UCAN: {}", e)))?
        .sign()
        .await
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to sign UCAN: {}", e)))?;

    ucan.encode()
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to encode UCAN: {}", e)))
}

/// RFC 6749 Section 5.1 - Successful Response (Keycast variant)
///
/// Returns bunker URL for NIP-46 remote signing (no admin access token)
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.1>
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub bunker_url: String,           // Keycast extension - NIP-46 credential
    pub token_type: String,            // RFC 6749 required - "Bearer"
    pub expires_in: i64,               // RFC 6749 recommended - bunker doesn't expire (0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,         // RFC 6749 optional - granted permissions
}

#[derive(Debug)]
pub enum OAuthError {
    Unauthorized,
    InvalidRequest(String),
    Database(sqlx::Error),
    Encryption(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            OAuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password. Please check your credentials and try again.".to_string()
            ),
            OAuthError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid request: {}", msg)
            ),
            OAuthError::Database(e) => {
                // Log the real error but return generic message to user
                tracing::error!("OAuth database error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            OAuthError::Encryption(e) => {
                // Log the real error but return generic message to user
                tracing::error!("OAuth encryption error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(e: sqlx::Error) -> Self {
        OAuthError::Database(e)
    }
}

/// Validate PKCE code_verifier against stored code_challenge
/// Implements RFC 7636 validation for both S256 and plain methods
fn validate_pkce(
    code_verifier: &str,
    code_challenge: &str,
    code_challenge_method: &str,
) -> Result<(), OAuthError> {
    match code_challenge_method {
        "S256" => {
            // Compute SHA256 hash of code_verifier
            let hash = sha256::digest(code_verifier);

            // Convert hex to bytes then base64url encode
            let hash_bytes = hex::decode(&hash)
                .map_err(|e| OAuthError::InvalidRequest(format!("Hash decode error: {}", e)))?;

            // Base64 URL-safe encoding (no padding)
            let computed_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&hash_bytes);

            if computed_challenge != code_challenge {
                tracing::warn!("PKCE validation failed: computed {} != stored {}",
                    &computed_challenge[..16], &code_challenge[..16]);
                return Err(OAuthError::InvalidRequest(
                    "Invalid code_verifier: PKCE validation failed".to_string()
                ));
            }
            Ok(())
        }
        "plain" => {
            if code_verifier != code_challenge {
                return Err(OAuthError::InvalidRequest(
                    "Invalid code_verifier: plain PKCE validation failed".to_string()
                ));
            }
            Ok(())
        }
        _ => Err(OAuthError::InvalidRequest(
            format!("Unsupported code_challenge_method: {}", code_challenge_method)
        )),
    }
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// GET /oauth/auth-status
/// Check if user has a valid session cookie
pub async fn auth_status(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, OAuthError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    if let Some(user_pubkey) = super::auth::extract_ucan_from_cookie(&headers).and_then(|token| {
        // Parse UCAN from string using ucan_auth helper
        crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id).ok().map(|(pubkey, _)| pubkey)
    }) {
        // Query user email info from database
        let user_info: Option<(Option<String>, Option<bool>)> = sqlx::query_as(
            "SELECT email, email_verified FROM users WHERE tenant_id = $1 AND public_key = $2"
        )
        .bind(tenant_id)
        .bind(&user_pubkey)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

        let (email, email_verified) = user_info.unwrap_or((None, None));

        Ok(Json(AuthStatusResponse {
            authenticated: true,
            pubkey: Some(user_pubkey),
            email,
            email_verified,
        }))
    } else {
        Ok(Json(AuthStatusResponse {
            authenticated: false,
            pubkey: None,
            email: None,
            email_verified: None,
        }))
    }
}

/// GET /oauth/authorize
/// Shows login form if not authenticated, or auto-approves if already authorized, or shows approval page
pub async fn authorize_get(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeRequest>,
) -> Result<Response, OAuthError> {
    use axum::response::Html;

    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Check if user is authenticated via cookie and extract user data
    let user_data = super::auth::extract_ucan_from_cookie(&headers)
        .and_then(|token| {
            // Parse UCAN from string using ucan_auth helper (tenant validation done later)
            crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id)
                .ok()
                .map(|(pubkey, ucan)| {
                    // Extract relays from UCAN facts
                    let relays: Vec<String> = ucan.facts()
                        .iter()
                        .filter_map(|fact| {
                            fact.get("relays")
                                .and_then(|r| r.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                        })
                        .next()
                        .unwrap_or_default();

                    (pubkey, relays)
                })
        });

    let user_pubkey = user_data.as_ref().map(|(pk, _)| pk.clone());
    let user_relays = user_data.as_ref().map(|(_, relays)| relays.clone()).unwrap_or_default();

    // Handle prompt=login: force fresh login by clearing cookie
    let force_login = params.prompt.as_deref() == Some("login");
    let force_consent = params.prompt.as_deref() == Some("consent");
    let has_byok_pubkey = params.byok_pubkey.is_some();

    // Validate that the user actually exists in the database
    let (user_pubkey, clear_cookie) = if let Some(ref pubkey) = user_pubkey {
        // If prompt=login or byok_pubkey present, ignore existing session and force fresh registration
        if force_login {
            tracing::info!("prompt=login: forcing fresh login, clearing cookie");
            (None, true)
        } else if has_byok_pubkey {
            tracing::info!("byok_pubkey present: forcing registration, clearing cookie");
            (None, true)
        } else {
            // Check if user exists
            let exists: Option<(String,)> = sqlx::query_as(
                "SELECT public_key FROM users WHERE public_key = $1 AND tenant_id = $2"
            )
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;

            if exists.is_none() {
                tracing::warn!("UCAN cookie has pubkey {} but user doesn't exist in tenant {}, clearing stale cookie", pubkey, tenant_id);
                (None, true)  // User was deleted, clear the cookie
            } else {
                (user_pubkey, false)
            }
        }
    } else {
        (None, false)
    };

    // If authenticated, check if they've already authorized this app
    if let Some(ref pubkey) = user_pubkey {
        // Get application ID
        let app_id: Option<i32> = sqlx::query_scalar(
            "SELECT id FROM oauth_applications WHERE tenant_id = $1 AND client_id = $2"
        )
        .bind(tenant_id)
        .bind(&params.client_id)
        .fetch_optional(pool)
        .await?;

        tracing::info!("Auto-approve check: client_id={}, app_id={:?}, user_pubkey={}",
            params.client_id, app_id, pubkey);

        if let Some(app_id) = app_id {
            // Check if user has already authorized this app
            let existing_auth: Option<(i32,)> = sqlx::query_as(
                "SELECT id FROM oauth_authorizations
                 WHERE tenant_id = $1 AND user_public_key = $2 AND application_id = $3"
            )
            .bind(tenant_id)
            .bind(pubkey)
            .bind(app_id)
            .fetch_optional(pool)
            .await?;

            tracing::info!("Existing authorization check: found={}", existing_auth.is_some());

            // Skip auto-approve if prompt=consent (always show approval screen)
            if existing_auth.is_some() && !force_consent {
                tracing::info!("Auto-approving: user has already authorized this app");
                // Auto-approve: generate code and send directly to parent window
                let code: String = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(32)
                    .map(char::from)
                    .collect();

                let expires_at = Utc::now() + Duration::minutes(10);

                sqlx::query(
                    "INSERT INTO oauth_codes (tenant_id, code, user_public_key, application_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
                )
                .bind(tenant_id)
                .bind(&code)
                .bind(pubkey)
                .bind(app_id)
                .bind(&params.redirect_uri)
                .bind(params.scope.as_deref().unwrap_or("sign_event"))
                .bind(&params.code_challenge)
                .bind(&params.code_challenge_method)
                .bind(expires_at)
                .bind(Utc::now())
                .execute(pool)
                .await?;

                // Auto-approve: redirect to redirect_uri with code (standard OAuth pattern)
                return Ok(Redirect::to(&format!(
                    "{}?code={}",
                    params.redirect_uri,
                    code
                )).into_response());
            } else if existing_auth.is_some() && force_consent {
                tracing::info!("prompt=consent: skipping auto-approve, showing approval screen");
            }
        }
    }

    let html = if let Some(pubkey) = user_pubkey {
        // Convert pubkey to npub for display
        let npub = nostr_sdk::PublicKey::from_hex(&pubkey)
            .ok()
            .and_then(|pk| pk.to_bech32().ok())
            .unwrap_or_else(|| pubkey.clone());

        // Use user's relays or fallback to default popular relays
        let relays_for_profile = if user_relays.is_empty() {
            vec![
                "wss://relay.damus.io".to_string(),
                "wss://nos.lol".to_string(),
                "wss://relay.nostr.band".to_string(),
            ]
        } else {
            user_relays
        };

        let relays_json = serde_json::to_string(&relays_for_profile)
            .unwrap_or_else(|_| "[]".to_string());

        // User is authenticated - show approval screen (Bluesky-inspired design)
        format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Authorize {}</title>
    <script src="https://unpkg.com/nostr-tools@2.7.2/lib/nostr.bundle.js"
            integrity="sha384-xf02s8T/9FVjKBW2IA0yLDYKsosKPVCYxGwQskHkNKZ/LpB9oM7yZdP5lqQ0ZC2f"
            crossorigin="anonymous"></script>
    <style>
        :root {{
            --divine-green: #00B488;
            --divine-green-dark: #009A72;
            --bg: hsl(0 0% 100%);
            --surface: hsl(0 0% 100%);
            --border: hsl(214.3 31.8% 91.4%);
            --text: hsl(222.2 84% 4.9%);
            --text-secondary: hsl(215.4 16.3% 46.9%);
            --muted: hsl(210 40% 96.1%);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: hsl(222.2 84% 4.9%);
                --surface: hsl(222.2 84% 4.9%);
                --border: hsl(217.2 32.6% 17.5%);
                --text: hsl(210 40% 98%);
                --text-secondary: hsl(215 20.2% 65.1%);
                --muted: hsl(217.2 32.6% 17.5%);
            }}
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .logo {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--divine-green);
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
        }}
        .logo svg {{
            width: 32px;
            height: 32px;
        }}
        .header h1 {{
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.25rem;
        }}
        .header p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
        }}
        .app_header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1rem;
        }}
        .app_icon {{
            width: 48px;
            height: 48px;
            background: var(--divine-green);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: white;
            flex-shrink: 0;
        }}
        .app_info h2 {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.125rem;
        }}
        .app_domain {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        .permissions_list {{
            margin-bottom: 1rem;
        }}
        .permission_item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 0;
        }}
        .permission_icon {{
            width: 36px;
            height: 36px;
            background: color-mix(in srgb, var(--divine-green) 15%, transparent);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            flex-shrink: 0;
        }}
        .permission_content {{
            flex: 1;
        }}
        .permission_content h3 {{
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 0.125rem;
        }}
        .permission_content p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }}
        .disclaimer {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
            line-height: 1.5;
            text-align: center;
        }}
        .disclaimer a {{
            color: var(--divine-green);
            text-decoration: none;
        }}
        .disclaimer a:hover {{
            text-decoration: underline;
        }}
        .buttons {{
            display: flex;
            gap: 0.75rem;
        }}
        button {{
            flex: 1;
            padding: 0.875rem 1.25rem;
            border-radius: 9999px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }}
        .btn_deny {{
            background: var(--muted);
            color: var(--text);
            border: 1px solid var(--border);
        }}
        .btn_deny:hover {{
            background: var(--border);
        }}
        .btn_approve {{
            background: var(--divine-green);
            color: #fff;
        }}
        .btn_approve:hover {{
            background: var(--divine-green-dark);
        }}
        #npub_fallback {{
            display: none;
        }}
        .nostr-link {{
            color: var(--divine-green);
            text-decoration: none;
        }}
        .nostr-link:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" fill="currentColor">
                    <path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
                </svg>
                diVine ID
            </div>
            <h1>Authorize App</h1>
            <p>Grant access to your account</p>
        </div>

        <div class="card">
            <div class="app_header">
                <div class="app_icon">
                    <span id="app_icon_letter">{}</span>
                </div>
                <div class="app_info">
                    <h2 id="app_name">{}</h2>
                    <div class="app_domain" id="app_domain"></div>
                </div>
            </div>

            <div class="permissions_list" id="permissions_list">
                <!-- Permissions will be populated by JavaScript -->
            </div>

            <p class="disclaimer">
                By authorizing, you grant this app access per its <a href="https://divine.video/terms" target="_blank">terms</a> and <a href="https://divine.video/privacy" target="_blank">privacy policy</a>.
            </p>

            <div class="buttons">
                <button class="btn_deny" onclick="deny()">Deny</button>
                <button class="btn_approve" onclick="approve()">Authorize</button>
            </div>
        </div>
    </div>

    <div id="npub_fallback">{}</div>

    <script>
        const clientId = '{}';
        const redirectUri = '{}';
        const scope = '{}';
        const codeChallenge = '{}';
        const codeChallengeMethod = '{}';
        const userPubkey = '{}';
        const userRelays = {};

        // Permission descriptions for each scope
        const permissionMeta = {{
            'sign_event': {{
                icon: '✍️',
                title: 'Act on your behalf',
                description: 'Post and interact as you on <a href="https://nostr.how" target="_blank" class="nostr-link">Nostr</a>'
            }},
            'encrypt': {{
                icon: '🔒',
                title: 'Send private messages',
                description: 'Encrypt messages to other users'
            }},
            'decrypt': {{
                icon: '🔓',
                title: 'Read private messages',
                description: 'Decrypt messages sent to you'
            }},
            'nip04_encrypt': {{
                icon: '🔐',
                title: 'Send DMs (legacy)',
                description: 'Encrypt direct messages'
            }},
            'nip04_decrypt': {{
                icon: '🔑',
                title: 'Read DMs (legacy)',
                description: 'Decrypt direct messages'
            }},
            'nip44_encrypt': {{
                icon: '🛡️',
                title: 'Send private messages',
                description: 'Encrypt messages securely'
            }},
            'nip44_decrypt': {{
                icon: '🔏',
                title: 'Read private messages',
                description: 'Decrypt messages sent to you'
            }}
        }};

        // Build permissions list
        function buildPermissionsList() {{
            const scopes = scope.split(/\\s+/).filter(s => s);
            const container = document.getElementById('permissions_list');

            scopes.forEach(s => {{
                const meta = permissionMeta[s] || {{
                    icon: '📋',
                    title: s.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase()),
                    description: `Permission: ${{s}}`
                }};

                const item = document.createElement('div');
                item.className = 'permission_item';
                item.innerHTML = `
                    <div class="permission_icon">${{meta.icon}}</div>
                    <div class="permission_content">
                        <h3>${{meta.title}}</h3>
                        <p>${{meta.description}}</p>
                    </div>
                    <div class="help_icon">?</div>
                `;
                container.appendChild(item);
            }});
        }}

        // Extract first letter for app icon
        function setAppIcon() {{
            const name = clientId.replace(/[-_]/g, ' ');
            const firstLetter = name.charAt(0).toUpperCase();
            document.getElementById('app_icon_letter').textContent = firstLetter;
        }}

        // Extract and display domain from redirect URI
        function setAppDomain() {{
            try {{
                const url = new URL(redirectUri);
                document.getElementById('app_domain').textContent = url.host;
            }} catch (e) {{
                // Invalid URL, hide domain
                document.getElementById('app_domain').style.display = 'none';
            }}
        }}

        // Load profile from Nostr relays
        // Shows display_name if available, otherwise just "your account" (hides npub for newcomers)
        async function loadProfile() {{
            // Log npub for power users who want to verify their identity
            const npub = document.getElementById('npub_fallback').textContent;
            console.log('Authorizing as:', npub);

            try {{
                if (!window.NostrTools) {{
                    console.warn('nostr-tools not loaded, skipping profile fetch');
                    document.getElementById('display_name').textContent = 'your account';
                    return;
                }}

                const {{ SimplePool }} = window.NostrTools;
                const pool = new SimplePool();

                console.log('Fetching profile for', userPubkey, 'from', userRelays);

                const events = await Promise.race([
                    pool.querySync(userRelays, {{
                        kinds: [0],
                        authors: [userPubkey],
                        limit: 1
                    }}),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
                ]);

                pool.close(userRelays);

                if (events && events.length > 0) {{
                    const profile = JSON.parse(events[0].content);
                    console.log('Profile loaded:', profile);

                    const displayName = profile.display_name || profile.name;
                    if (displayName) {{
                        document.getElementById('display_name').textContent = displayName;
                    }} else {{
                        // No name in profile - show friendly fallback (npub logged above)
                        document.getElementById('display_name').textContent = 'your account';
                    }}
                }} else {{
                    // No profile found - show friendly fallback (npub logged above)
                    document.getElementById('display_name').textContent = 'your account';
                }}
            }} catch (e) {{
                console.warn('Could not load profile:', e);
                // Error fetching profile - show friendly fallback (npub logged above)
                document.getElementById('display_name').textContent = 'your account';
            }}
        }}

        // Initialize on page load
        window.addEventListener('load', () => {{
            buildPermissionsList();
            setAppIcon();
            setAppDomain();
            loadProfile();
        }});

        async function approve() {{
            try {{
                const response = await fetch('/api/oauth/authorize', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    credentials: 'include',
                    body: JSON.stringify({{
                        client_id: clientId,
                        redirect_uri: redirectUri,
                        scope: scope,
                        approved: true,
                        code_challenge: codeChallenge || undefined,
                        code_challenge_method: codeChallengeMethod || undefined
                    }})
                }});

                const data = await response.json();
                if (data.code) {{
                    window.location.href = `${{redirectUri}}?code=${{data.code}}`;
                }} else {{
                    alert('Error: ' + (data.error || 'Unknown error'));
                }}
            }} catch (e) {{
                alert('Request failed: ' + e.message);
            }}
        }}

        function deny() {{
            window.location.href = `${{redirectUri}}?error=access_denied`;
        }}
    </script>
</body>
</html>
        "#,
            params.client_id,  // <title>
            params.client_id.chars().next().unwrap_or('A').to_uppercase(),  // app icon letter
            params.client_id,  // app name
            npub,  // npub_fallback display (hidden)
            params.client_id,  // JS clientId
            params.redirect_uri,  // JS redirectUri
            params.scope.as_deref().unwrap_or("sign_event"),  // JS scope
            params.code_challenge.as_deref().unwrap_or(""),  // JS codeChallenge
            params.code_challenge_method.as_deref().unwrap_or(""),  // JS codeChallengeMethod
            pubkey,  // JS userPubkey (hex)
            relays_json,  // JS userRelays (JSON array)
        )
    } else {
        // User not authenticated - show login/register form (divine.video-inspired design)
        format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Sign in - diVine ID</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Bricolage+Grotesque:wght@600;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/nostr-tools@2.7.2/lib/nostr.bundle.js"
            integrity="sha384-xf02s8T/9FVjKBW2IA0yLDYKsosKPVCYxGwQskHkNKZ/LpB9oM7yZdP5lqQ0ZC2f"
            crossorigin="anonymous"></script>
    <style>
        :root {{
            --divine-green: #00B488;
            --divine-green-dark: #009A72;
            --divine-green-light: #33C49F;
            --divine-purple: #8B5CF6;
            --bg: hsl(0 0% 100%);
            --surface: hsl(0 0% 100%);
            --border: hsl(214.3 31.8% 91.4%);
            --text: hsl(222.2 84% 4.9%);
            --text-secondary: hsl(215.4 16.3% 46.9%);
            --muted: hsl(210 40% 96.1%);
            --error: #EF4444;
            --shadow-sm: 0 2px 8px rgba(0, 180, 136, 0.08);
            --shadow-md: 0 4px 16px rgba(0, 180, 136, 0.12);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: hsl(222.2 84% 4.9%);
                --surface: hsl(222.2 84% 4.9%);
                --border: hsl(217.2 32.6% 17.5%);
                --text: hsl(210 40% 98%);
                --text-secondary: hsl(215 20.2% 65.1%);
                --muted: hsl(217.2 32.6% 17.5%);
            }}
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .logo {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }}
        .logo svg {{
            width: 32px;
            height: 32px;
        }}
        .logo span {{
            font-family: 'Bricolage Grotesque', system-ui, sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--divine-green);
        }}
        .header h1 {{
            font-family: 'Bricolage Grotesque', system-ui, sans-serif;
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }}
        .header p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
        }}
        .app_header {{
            display: flex;
            align-items: center;
            gap: 0.875rem;
            padding-bottom: 1.25rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.25rem;
        }}
        .app_icon {{
            width: 44px;
            height: 44px;
            background: var(--divine-green);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            font-weight: 600;
            color: white;
            flex-shrink: 0;
        }}
        .app_info h2 {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.125rem;
        }}
        .app_domain {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        .form_group {{
            margin-bottom: 1rem;
        }}
        label {{
            display: block;
            margin-bottom: 0.375rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }}
        input {{
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            background: var(--muted);
            color: var(--text);
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        input:focus {{
            outline: none;
            border-color: var(--divine-green);
            box-shadow: 0 0 0 2px rgba(0, 180, 136, 0.2);
        }}
        input::placeholder {{
            color: var(--text-secondary);
            opacity: 0.6;
        }}
        .btn_primary {{
            width: 100%;
            padding: 0.75rem 1.5rem;
            border-radius: 9999px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            background: var(--divine-green);
            color: white;
            margin-top: 0.5rem;
        }}
        .btn_primary:hover {{
            background: var(--divine-green-dark);
            box-shadow: var(--shadow-sm);
        }}
        .btn_primary:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .form_view {{
            display: none;
        }}
        .form_view.active {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(5px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .toggle_link {{
            text-align: center;
            margin-top: 1rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        .toggle_link a {{
            color: var(--divine-green);
            text-decoration: none;
            cursor: pointer;
            font-weight: 500;
        }}
        .toggle_link a:hover {{
            text-decoration: underline;
        }}
        .error {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--error);
            color: var(--error);
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            display: none;
            font-size: 0.875rem;
            text-align: center;
        }}
        .advanced_section {{
            margin: 1rem 0;
        }}
        .advanced_toggle {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--divine-green);
            font-size: 0.875rem;
            cursor: pointer;
            text-decoration: none;
            user-select: none;
        }}
        .advanced_toggle:hover {{
            text-decoration: underline;
        }}
        .advanced_icon {{
            display: inline-block;
            transition: transform 0.2s;
            font-size: 0.65rem;
        }}
        .advanced_icon.expanded {{
            transform: rotate(90deg);
        }}
        .advanced_content {{
            display: none;
            margin-top: 0.75rem;
            padding: 1rem;
            background: var(--muted);
            border-radius: 0.75rem;
            border: 1px solid var(--border);
        }}
        .advanced_content.show {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}
        .help_text {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-top: 0.375rem;
            line-height: 1.4;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--divine-green)">
                    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
                </svg>
                <span>diVine ID</span>
            </div>
            <h1>Sign in</h1>
            <p>to continue to <strong id="app_name_display">{}</strong></p>
        </div>

        <div class="card">
            <div class="app_header">
                <div class="app_icon">
                    <span id="app_icon_letter">{}</span>
                </div>
                <div class="app_info">
                    <h2 id="app_name">{}</h2>
                    <div class="app_domain" id="app_domain"></div>
                </div>
            </div>

            <div id="error" class="error"></div>

            <div id="login_view" class="form_view">
                <form onsubmit="handleLogin(event)">
                    <div class="form_group">
                        <label for="login_email">Email</label>
                        <input type="email" id="login_email" placeholder="Enter your email" autocomplete="username" required>
                    </div>
                    <div class="form_group">
                        <label for="login_password">Password</label>
                        <input type="password" id="login_password" placeholder="Enter your password" autocomplete="current-password" required>
                    </div>
                    <button type="submit" class="btn_primary">Sign in</button>
                </form>
                <div class="toggle_link">
                    <a href="/forgot-password">Forgot password?</a>
                </div>
                <div class="toggle_link">
                    Don't have an account? <a onclick="showForm('register')">Create one</a>
                </div>
            </div>

            <div id="register_view" class="form_view">
                <form onsubmit="handleRegister(event)">
                    <div class="form_group">
                        <label for="register_email">Email</label>
                        <input type="email" id="register_email" placeholder="Enter your email" autocomplete="username" required>
                    </div>
                    <div class="form_group">
                        <label for="register_password">Password</label>
                        <input type="password" id="register_password" placeholder="Create a password" autocomplete="new-password" required minlength="8">
                    </div>
                    <div class="form_group">
                        <label for="register_password-confirm">Confirm Password</label>
                        <input type="password" id="register_password-confirm" placeholder="Confirm your password" autocomplete="new-password" required minlength="8">
                    </div>
                    <div class="advanced_section" id="advanced_section">
                        <a class="advanced_toggle" onclick="toggleAdvanced()">
                            <span class="advanced_icon" id="advanced_icon">▶</span>
                            Import existing Nostr key
                        </a>
                        <div id="advanced_content" class="advanced_content">
                            <div class="form_group" style="margin-bottom: 0;">
                                <label for="register_nsec">Nostr Secret Key</label>
                                <input type="password" id="register_nsec" placeholder="nsec1... or hex format" autocomplete="off">
                                <p class="help_text">
                                    Optional: Import your existing Nostr identity. Leave empty to create a new one.
                                </p>
                            </div>
                        </div>
                    </div>
                    <button type="submit" class="btn_primary">Create account</button>
                </form>
                <div class="toggle_link">
                    Already have an account? <a onclick="showForm('login')">Sign in</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        const clientId = '{}';
        const redirectUri = '{}';
        const scope = '{}';
        const codeChallenge = '{}';
        const codeChallengeMethod = '{}';
        const defaultRegister = new URLSearchParams(window.location.search).get('default_register') === 'true';
        const byokPubkey = new URLSearchParams(window.location.search).get('byok_pubkey');

        // Set app icon letter
        document.getElementById('app_icon_letter').textContent = clientId.charAt(0).toUpperCase();

        // Set app domain from redirect URI
        try {{
            const url = new URL(redirectUri);
            document.getElementById('app_domain').textContent = url.host;
        }} catch (e) {{
            document.getElementById('app_domain').style.display = 'none';
        }}

        function showForm(form) {{
            document.querySelectorAll('.form_view').forEach(v => v.classList.remove('active'));

            if (form === 'login') {{
                document.getElementById('login_view').classList.add('active');
            }} else {{
                document.getElementById('register_view').classList.add('active');
            }}

            hideError();
        }}

        // Initialize form: show register if BYOK or explicitly requested
        if (defaultRegister || byokPubkey) {{
            showForm('register');
        }} else {{
            showForm('login');
        }}

        // Hide advanced nsec input if byok_pubkey is present (nsec will come via code_verifier)
        if (byokPubkey) {{
            const advancedSection = document.getElementById('advanced_section');
            if (advancedSection) {{
                advancedSection.style.display = 'none';
            }}
        }}

        function showError(message) {{
            const errorEl = document.getElementById('error');
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }}

        function hideError() {{
            document.getElementById('error').style.display = 'none';
        }}

        function toggleAdvanced() {{
            const content = document.getElementById('advanced_content');
            const icon = document.getElementById('advanced_icon');
            content.classList.toggle('show');
            icon.classList.toggle('expanded');
        }}

        async function handleLogin(e) {{
            e.preventDefault();
            hideError();

            const email = document.getElementById('login_email').value;
            const password = document.getElementById('login_password').value;

            try {{
                const response = await fetch('/api/oauth/login', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    credentials: 'include',
                    body: JSON.stringify({{
                        email,
                        password,
                        client_id: clientId,
                        redirect_uri: redirectUri,
                        scope: scope,
                        code_challenge: codeChallenge || undefined,
                        code_challenge_method: codeChallengeMethod || undefined
                    }})
                }});

                if (!response.ok) {{
                    const data = await response.json().catch(() => ({{}}));
                    showError(data.error || 'Login failed');
                    return;
                }}

                // Cookie is set, reload to show approval screen
                const url = new URL(window.location.href);
                url.searchParams.delete('prompt');
                url.searchParams.delete('byok_pubkey');
                url.searchParams.delete('default_register');
                window.location.href = url.toString();
            }} catch (e) {{
                showError('Request failed: ' + e.message);
            }}
        }}

        async function handleRegister(e) {{
            e.preventDefault();
            hideError();

            const email = document.getElementById('register_email').value;
            const password = document.getElementById('register_password').value;
            const passwordConfirm = document.getElementById('register_password-confirm').value;
            const nsecInput = document.getElementById('register_nsec').value.trim();

            if (password !== passwordConfirm) {{
                showError('Passwords do not match');
                return;
            }}

            let finalNsec = nsecInput || null;
            let finalPubkey = byokPubkey || null;

            try {{
                const response = await fetch('/api/oauth/register', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    credentials: 'include',
                    body: JSON.stringify({{
                        email,
                        password,
                        nsec: finalNsec || undefined,
                        pubkey: finalPubkey || undefined,
                        client_id: clientId,
                        redirect_uri: redirectUri,
                        scope: scope,
                        code_challenge: codeChallenge || undefined,
                        code_challenge_method: codeChallengeMethod || undefined
                    }})
                }});

                const data = await response.json().catch(() => ({{}}));

                if (!response.ok) {{
                    showError(data.error || 'Registration failed');
                    return;
                }}

                if (data.code) {{
                    window.location.href = `${{redirectUri}}?code=${{data.code}}`;
                }} else {{
                    showError('Registration succeeded but no authorization code received');
                }}
            }} catch (e) {{
                showError('Request failed: ' + e.message);
            }}
        }}
    </script>
</body>
</html>
        "#,
            params.client_id,  // app_name_display in header
            params.client_id.chars().next().unwrap_or('A').to_uppercase(),  // app icon letter
            params.client_id,  // app name in card
            params.client_id,  // JS clientId
            params.redirect_uri,  // JS redirectUri
            params.scope.as_deref().unwrap_or("sign_event"),  // JS scope
            params.code_challenge.as_deref().unwrap_or(""),  // JS codeChallenge
            params.code_challenge_method.as_deref().unwrap_or(""),  // JS codeChallengeMethod
        )
    };

    // If we detected a stale cookie, clear it
    if clear_cookie {
        let clear_cookie_header = "keycast_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
        Ok((
            [(axum::http::header::SET_COOKIE, clear_cookie_header)],
            Html(html)
        ).into_response())
    } else {
        Ok(Html(html).into_response())
    }
}

/// POST /oauth/authorize
/// User approves authorization, creates code and redirects back to app OR returns code directly
pub async fn authorize_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Response, OAuthError> {
    if !req.approved {
        return Ok(Redirect::to(&format!(
            "{}?error=access_denied",
            req.redirect_uri
        ))
        .into_response());
    }

    let tenant_id = tenant.0.id;

    // Extract user public key from UCAN cookie
    let user_public_key = super::auth::extract_ucan_from_cookie(&headers).and_then(|token| {
        // Parse UCAN from string using ucan_auth helper
        crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", token), tenant_id).ok().map(|(pubkey, _)| pubkey)
    })
        .ok_or(OAuthError::Unauthorized)?;

    // Generate authorization code
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store authorization code (expires in 10 minutes)
    let expires_at = Utc::now() + Duration::minutes(10);

    // Get or create application
    let app_id: Option<i32> =
        sqlx::query_scalar("SELECT id FROM oauth_applications WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant_id)
            .bind(&req.client_id)
            .fetch_optional(&auth_state.state.db)
            .await?;

    let app_id = if let Some(id) = app_id {
        id
    } else {
        // Create test application
        sqlx::query_scalar(
            "INSERT INTO oauth_applications (tenant_id, client_id, client_secret, name, redirect_uris, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
        )
        .bind(tenant_id)
        .bind(&req.client_id)
        .bind("test_secret")
        .bind(&req.client_id)
        .bind(format!("[\"{}\"]", req.redirect_uri))
        .bind(Utc::now())
        .bind(Utc::now())
        .fetch_one(&auth_state.state.db)
        .await?
    };

    // Store authorization code with PKCE support
    sqlx::query(
        "INSERT INTO oauth_codes (tenant_id, code, user_public_key, application_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(tenant_id)
    .bind(&code)
    .bind(&user_public_key)
    .bind(app_id)
    .bind(&req.redirect_uri)
    .bind(&req.scope)
    .bind(&req.code_challenge)
    .bind(&req.code_challenge_method)
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&auth_state.state.db)
    .await?;

    // For JavaScript clients, return code directly instead of redirecting
    // Check if this is an XHR/fetch request by looking for Accept: application/json
    // For now, just return JSON with the code - client can handle it
    Ok(Json(serde_json::json!({
        "code": code,
        "redirect_uri": req.redirect_uri
    })).into_response())
}

/// POST /oauth/token
/// Exchange authorization code for bunker URL (authorization_code grant ONLY)
/// This is the standard OAuth 2.0 token endpoint for third-party apps
pub async fn token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<TokenRequest>,
) -> Result<Response, OAuthError> {
    let tenant_id = tenant.0.id;

    // Only accept authorization_code grant (ROPC removed)
    let grant_type = req.grant_type.as_deref().unwrap_or("authorization_code");

    if grant_type != "authorization_code" {
        return Err(OAuthError::InvalidRequest(
            format!("Invalid grant_type '{}'. This endpoint only accepts 'authorization_code'.", grant_type)
        ));
    }

    handle_authorization_code_grant(tenant_id, auth_state, req).await
}

/// Handle authorization code grant (standard OAuth flow)
async fn handle_authorization_code_grant(
    tenant_id: i64,
    auth_state: super::routes::AuthState,
    req: TokenRequest,
) -> Result<Response, OAuthError> {
    let pool = &auth_state.state.db;

    // Fetch and validate authorization code with PKCE fields
    type AuthCodeRow = (String, i32, String, String, Option<String>, Option<String>);
    let auth_code: Option<AuthCodeRow> = sqlx::query_as(
        "SELECT user_public_key, application_id, redirect_uri, scope, code_challenge, code_challenge_method
         FROM oauth_codes
         WHERE tenant_id = $1 AND code = $2 AND expires_at > $3"
    )
    .bind(tenant_id)
    .bind(&req.code)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;

    let (user_public_key, application_id, stored_redirect_uri, scope, code_challenge, code_challenge_method) =
        auth_code.ok_or(OAuthError::Unauthorized)?;

    // Validate redirect_uri matches
    if stored_redirect_uri != req.redirect_uri {
        return Err(OAuthError::InvalidRequest("redirect_uri mismatch".to_string()));
    }

    // PKCE validation (if code_challenge was provided during authorization)
    if let Some(challenge) = code_challenge {
        let method = code_challenge_method.as_deref().unwrap_or("plain");
        let verifier = req.code_verifier.as_ref().ok_or_else(|| {
            OAuthError::InvalidRequest("code_verifier required for PKCE flow".to_string())
        })?;

        validate_pkce(verifier, &challenge, method)?;
        tracing::debug!("PKCE validation successful for code: {}", &req.code[..8]);
    }

    // Delete the authorization code (one-time use)
    sqlx::query("DELETE FROM oauth_codes WHERE tenant_id = $1 AND code = $2")
        .bind(tenant_id)
        .bind(&req.code)
        .execute(pool)
        .await?;

    // Get user's email for UCAN
    let email: String = sqlx::query_scalar(
        "SELECT email FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(&user_public_key)
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    // Extract optional nsec from code_verifier
    let nsec_from_verifier = req.code_verifier.as_ref()
        .and_then(|v| extract_nsec_from_verifier_public(v));

    tracing::info!(
        "Token exchange for user {}: has code_verifier: {}, has nsec in verifier: {}",
        user_public_key,
        req.code_verifier.is_some(),
        nsec_from_verifier.is_some()
    );

    // Create OAuth authorization and generate token response
    create_oauth_authorization_and_token(
        tenant_id,
        &user_public_key,
        &email,
        application_id,
        &scope,
        nsec_from_verifier,
        auth_state,
    ).await
}

// handle_password_grant() removed - ROPC grant type deprecated and removed

/// Common function to create OAuth authorization and generate TokenResponse
/// Creates personal_keys if missing (first token exchange with optional nsec from code_verifier)
async fn create_oauth_authorization_and_token(
    tenant_id: i64,
    user_public_key: &str,
    _email: &str,
    application_id: i32,
    scope: &str,
    nsec_from_verifier: Option<String>,
    auth_state: super::routes::AuthState,
) -> Result<Response, OAuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Check if personal_keys exist
    let encrypted_user_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE user_public_key = $1"
    )
    .bind(user_public_key)
    .fetch_optional(pool)
    .await
    .map_err(OAuthError::Database)?;

    let (encrypted_user_key, _keys_just_created) = if let Some(existing_key) = encrypted_user_key {
        // Keys already exist
        if nsec_from_verifier.is_some() {
            tracing::warn!("User {} already has personal_keys, ignoring nsec from code_verifier", user_public_key);
        }
        (existing_key, false)
    } else {
        // Create personal_keys from code_verifier nsec or auto-generate
        tracing::info!("Creating personal_keys for user {} during token exchange", user_public_key);

        let keys = if let Some(nsec_str) = nsec_from_verifier {
            tracing::info!("Using nsec from code_verifier (BYOK)");
            let keys = Keys::parse(&nsec_str)
                .map_err(|e| OAuthError::InvalidRequest(format!("Invalid nsec in code_verifier: {}", e)))?;

            // Verify nsec matches user's registered pubkey
            if keys.public_key().to_hex() != user_public_key {
                return Err(OAuthError::InvalidRequest(format!(
                    "nsec in code_verifier doesn't match registered pubkey. Expected: {}, got: {}",
                    user_public_key,
                    keys.public_key().to_hex()
                )));
            }

            keys
        } else {
            // No nsec provided - check if user expects BYOK (has no keys) or auto-generate
            // If user was registered without keys, they MUST provide nsec
            tracing::error!("User {} has no personal_keys but no nsec in code_verifier", user_public_key);
            return Err(OAuthError::InvalidRequest(
                "Missing nsec in code_verifier. BYOK flow requires nsec to be embedded.".to_string()
            ));
        };

        // Store secret key as raw bytes (32 bytes) - matches regular registration
        let secret_bytes = keys.secret_key().to_secret_bytes();

        let encrypted_secret = key_manager
            .encrypt(&secret_bytes)
            .await
            .map_err(|e| OAuthError::Encryption(e.to_string()))?;

        // Insert personal_keys
        sqlx::query(
            "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, created_at, updated_at)
             VALUES ($1, $2, $3, $4)"
        )
        .bind(user_public_key)
        .bind(&encrypted_secret)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(pool)
        .await
        .map_err(OAuthError::Database)?;

        (encrypted_secret, true)
    };

    // OAuth apps don't get UCAN tokens (no admin API access needed)
    // They only need bunker URL for NIP-46 remote signing

    // Parse the user's public key to use as bunker public key
    let bunker_public_key = nostr_sdk::PublicKey::from_hex(user_public_key)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?;

    // Generate connection secret for NIP-46 authentication
    let connection_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();

    // Create authorization in database - use relay that supports NIP-46
    let relay_url = "wss://relay.damus.io";
    let relays_json = serde_json::to_string(&vec![relay_url])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    // Get default policy if not specified by application
    let policy_id: Option<i32> = sqlx::query_scalar(
        "SELECT policy_id FROM oauth_applications WHERE id = $1"
    )
    .bind(application_id)
    .fetch_one(pool)
    .await?;

    let policy_id = if let Some(pid) = policy_id {
        pid
    } else {
        sqlx::query_scalar::<_, i32>(
            "SELECT id FROM policies WHERE name = 'Standard Social (Default)' AND tenant_id = $1 LIMIT 1"
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?
    };

    // Use ON CONFLICT to avoid duplicates per user/app combination
    sqlx::query(
        "INSERT INTO oauth_authorizations (tenant_id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, policy_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (user_public_key, application_id)
         DO UPDATE SET secret = $6, relays = $7, policy_id = $8, updated_at = $10"
    )
    .bind(tenant_id)
    .bind(user_public_key)
    .bind(application_id)
    .bind(bunker_public_key.to_hex())
    .bind(&encrypted_user_key)      // bunker_secret = encrypted user key (BLOB)
    .bind(&connection_secret)        // secret = connection secret (TEXT)
    .bind(&relays_json)
    .bind(policy_id)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(pool)
    .await?;

    // Signal signer daemon to reload via channel (instant notification)
    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx.send(AuthorizationCommand::Upsert {
            bunker_pubkey: bunker_public_key.to_hex(),
            tenant_id,
            is_oauth: true,
        }).await {
            tracing::error!("Failed to send authorization upsert command: {}", e);
        } else {
            tracing::info!("Sent authorization upsert command to signer daemon");
        }
    }

    // Build bunker URL with deployment-wide relay list
    let relays = keycast_core::types::authorization::Authorization::get_bunker_relays();
    let relay_params: String = relays
        .iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect::<Vec<_>>()
        .join("&");

    let bunker_url = format!(
        "bunker://{}?{}&secret={}",
        bunker_public_key.to_hex(),
        relay_params,
        connection_secret
    );

    // Return bunker URL (no cookie - SSO cookie already set during oauth_register/oauth_login)
    Ok(Json(TokenResponse {
        bunker_url,
        token_type: "Bearer".to_string(),
        expires_in: 0,
        scope: Some(scope.to_string()),
    }).into_response())
}

// ============================================================================
// OAuth Popup Login/Register Handlers (return approval HTML directly)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct OAuthLoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// POST /oauth/login
/// Login endpoint for OAuth popup - sets UCAN cookie and returns success
/// Page will reload to show approval screen
pub async fn oauth_login(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<OAuthLoginRequest>,
) -> Result<impl IntoResponse, OAuthError> {
    use super::auth::generate_ucan_token;
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;

    tracing::info!("OAuth popup login for email: {} in tenant: {}", req.email, tenant_id);

    // Validate credentials
    let user: Option<(String, String)> = sqlx::query_as(
        "SELECT public_key, password_hash FROM users WHERE email = $1 AND tenant_id = $2 AND password_hash IS NOT NULL"
    )
    .bind(&req.email)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let (public_key, password_hash) = user.ok_or(OAuthError::Unauthorized)?;

    let valid = verify(&req.password, &password_hash)
        .map_err(|_| OAuthError::InvalidRequest("Password verification failed".to_string()))?;

    if !valid {
        return Err(OAuthError::Unauthorized);
    }

    // Get user's keys for UCAN generation
    let encrypted_secret: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE user_public_key = $1"
    )
    .bind(&public_key)
    .fetch_optional(pool)
    .await
    .map_err(OAuthError::Database)?;

    let encrypted_secret = encrypted_secret.ok_or_else(|| {
        tracing::warn!("User {} has no personal_keys - they registered via OAuth but haven't completed token exchange yet", public_key);
        OAuthError::InvalidRequest("Account setup incomplete. Please complete the OAuth flow to finalize your account.".to_string())
    })?;

    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| OAuthError::Encryption(e.to_string()))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    // Generate UCAN token (OAuth popup doesn't set relays, uses defaults)
    let ucan_token = generate_ucan_token(&keys, tenant_id, &req.email, None).await
        .map_err(|e| OAuthError::InvalidRequest(format!("UCAN generation failed: {:?}", e)))?;

    // OAuth popup login: bunker authorization will be created manually by user if needed

    tracing::info!("OAuth popup login successful for user: {}", public_key);

    // Set cookie and return success - page will reload to show approval
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "success": true,
            "pubkey": public_key
        }))
    ).into_response())
}

#[derive(Debug, Deserialize)]
pub struct OAuthRegisterRequest {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub pubkey: Option<String>,  // Optional: for BYOK flow (hex), nsec will come in code_verifier
    pub nsec: Option<String>,  // Optional: direct nsec input (nsec1... or hex), creates keys immediately
    pub relays: Option<Vec<String>>,  // Optional: preferred relays
    pub state: Option<String>,  // Optional: for iOS PWA polling pattern
}

/// POST /oauth/register
/// Registration endpoint for OAuth popup - sets UCAN cookie and returns success
/// Page will reload to show approval screen
pub async fn oauth_register(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<OAuthRegisterRequest>,
) -> Result<impl IntoResponse, OAuthError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    tracing::info!(
        "OAuth popup registration for email: {} in tenant: {}, nsec: {}, pubkey: {}, client_id: {}",
        req.email,
        tenant_id,
        req.nsec.is_some(),
        req.pubkey.as_deref().unwrap_or("none"),
        req.client_id
    );

    // Check if email already exists
    let existing: Option<(String,)> = sqlx::query_as("SELECT public_key FROM users WHERE email = $1 AND tenant_id = $2")
        .bind(&req.email)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(OAuthError::Database)?;

    if existing.is_some() {
        return Err(OAuthError::InvalidRequest("Email already registered".to_string()));
    }

    // Hash password
    let password_hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|_| OAuthError::InvalidRequest("Password hashing failed".to_string()))?;

    // Priority: nsec (direct input) → pubkey (BYOK via code_verifier) → auto-generate
    let (public_key, generated_keys) = if let Some(ref nsec_str) = req.nsec {
        // Direct nsec input: parse nsec and create keys immediately
        let keys = Keys::parse(nsec_str)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid nsec: {}", e)))?;
        let pubkey = keys.public_key();
        tracing::info!("OAuth registration with direct nsec input for pubkey: {}", pubkey.to_hex());
        (pubkey, Some(keys))  // Keys provided by user
    } else if let Some(ref pubkey_hex) = req.pubkey {
        // BYOK flow: client provides pubkey, nsec will come in code_verifier
        let pubkey = nostr_sdk::PublicKey::from_hex(pubkey_hex)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid pubkey: {}", e)))?;
        tracing::info!("OAuth registration BYOK flow for pubkey: {}", pubkey.to_hex());
        (pubkey, None)  // No keys generated, wait for token exchange
    } else {
        // Auto-generate flow: server generates keys immediately
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        tracing::info!("OAuth registration auto-generate flow for email: {}", req.email);
        (pubkey, Some(keys))  // Keys generated now
    };

    // Check if user with this pubkey already exists
    let existing_user: Option<(String,)> = sqlx::query_as(
        "SELECT email FROM users WHERE public_key = $1 AND tenant_id = $2"
    )
    .bind(public_key.to_hex())
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(OAuthError::Database)?;

    if existing_user.is_some() {
        return Err(OAuthError::InvalidRequest(
            "This Nostr key is already registered. Please sign in instead.".to_string()
        ));
    }

    // Check if email is already taken
    let existing_email: Option<(String,)> = sqlx::query_as(
        "SELECT public_key FROM users WHERE email = $1 AND tenant_id = $2"
    )
    .bind(&req.email)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(OAuthError::Database)?;

    if existing_email.is_some() {
        return Err(OAuthError::InvalidRequest(
            "This email is already registered. Please sign in instead.".to_string()
        ));
    }

    // Generate email verification token
    let verification_token = generate_secure_token();
    let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

    // Start transaction for user + optional keys creation
    let mut tx = pool.begin().await.map_err(OAuthError::Database)?;

    // Insert user with email verification token
    sqlx::query(
        "INSERT INTO users (public_key, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(public_key.to_hex())
    .bind(tenant_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(false)
    .bind(&verification_token)
    .bind(verification_expires)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await
    .map_err(OAuthError::Database)?;

    // If auto-generate flow, create personal_keys immediately
    if let Some(ref keys) = generated_keys {
        let secret_bytes = keys.secret_key().to_secret_bytes();
        let encrypted_secret = auth_state.state.key_manager.encrypt(&secret_bytes)
            .await
            .map_err(|e| OAuthError::Encryption(e.to_string()))?;

        sqlx::query(
            "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, created_at, updated_at)
             VALUES ($1, $2, $3, $4)"
        )
        .bind(public_key.to_hex())
        .bind(&encrypted_secret)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&mut *tx)
        .await
        .map_err(OAuthError::Database)?;

        tracing::info!("Created personal_keys for auto-generate flow: {}", public_key.to_hex());
    } else {
        tracing::info!("BYOK flow - personal_keys will be created during token exchange: {}", public_key.to_hex());
    }

    tx.commit().await.map_err(OAuthError::Database)?;

    // Send verification email (optional - don't fail if email service unavailable)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service.send_verification_email(&req.email, &verification_token).await {
                tracing::error!("Failed to send verification email to {}: {}", req.email, e);
            } else {
                tracing::info!("Sent verification email to {}", req.email);
            }
        },
        Err(e) => {
            tracing::warn!("Email service unavailable, skipping verification email: {}", e);
        }
    }

    // Auto-approve: first-time registration implies consent
    // Generate authorization code immediately
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_at = Utc::now() + Duration::minutes(10);

    // Get or create application
    let app_id: Option<i32> =
        sqlx::query_scalar("SELECT id FROM oauth_applications WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant_id)
            .bind(&req.client_id)
            .fetch_optional(pool)
            .await?;

    let app_id = if let Some(id) = app_id {
        id
    } else {
        // Create application
        sqlx::query_scalar(
            "INSERT INTO oauth_applications (tenant_id, client_id, client_secret, name, redirect_uris, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
        )
        .bind(tenant_id)
        .bind(&req.client_id)
        .bind("test_secret")
        .bind(&req.client_id)
        .bind(format!("[\"{}\"]", req.redirect_uri))
        .bind(Utc::now())
        .bind(Utc::now())
        .fetch_one(pool)
        .await?
    };

    // Store authorization code with PKCE support
    sqlx::query(
        "INSERT INTO oauth_codes (tenant_id, code, user_public_key, application_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(tenant_id)
    .bind(&code)
    .bind(&public_key.to_hex())
    .bind(app_id)
    .bind(&req.redirect_uri)
    .bind(req.scope.as_deref().unwrap_or("sign_event"))
    .bind(&req.code_challenge)
    .bind(&req.code_challenge_method)
    .bind(expires_at)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    tracing::info!("OAuth auto-approve for new registration: user {}, app {}", public_key.to_hex(), req.client_id);

    // Generate UCAN for SSO
    let ucan_token = if let Some(ref keys) = generated_keys {
        // Auto-generate flow: user-signed UCAN (user has keys)
        super::auth::generate_ucan_token(keys, tenant_id, &req.email, req.relays.as_deref()).await
            .map_err(|e| OAuthError::InvalidRequest(format!("UCAN generation failed: {:?}", e)))?
    } else {
        // BYOK flow: server-signed UCAN (user doesn't have keys yet)
        super::auth::generate_server_signed_ucan(&public_key, tenant_id, &req.email, &auth_state.state.server_keys).await
            .map_err(|e| OAuthError::InvalidRequest(format!("UCAN generation failed: {:?}", e)))?
    };

    // Set UCAN cookie for SSO across OAuth apps
    let cookie = format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        ucan_token
    );

    tracing::info!("Set server-signed UCAN cookie for user {} (SSO enabled)", public_key.to_hex());

    // If state provided (iOS PWA polling flow), store code in polling cache
    if let Some(ref state) = req.state {
        let expiry = Instant::now();  // Will be checked with elapsed()
        POLLING_CACHE.insert(state.clone(), (code.clone(), expiry));
        tracing::info!("Stored code in polling cache for state: {}", state);
    }

    // Return code with cookie (auto-approve)
    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "code": code,
            "redirect_uri": req.redirect_uri
        }))
    ).into_response())
}

// generate_auto_approve_html_with_cookie() and generate_approval_page_html() removed
// Now using reload pattern - /oauth/authorize GET renders these directly

// ============================================================================
// nostr-login Integration Handlers
// ============================================================================

/// Nostr Connect parameters from nostrconnect:// URI
#[derive(Debug, Deserialize)]
pub struct NostrConnectParams {
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
    pub image: Option<String>,
}

/// Form data for connect approval
#[derive(Debug, Deserialize)]
pub struct ConnectApprovalForm {
    pub client_pubkey: String,
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub approved: bool,
}

/// Parse nostrconnect:// URI from path
/// Format: nostrconnect://CLIENT_PUBKEY?relay=RELAY&secret=SECRET&perms=...
fn parse_nostrconnect_uri(uri: &str) -> Result<(String, NostrConnectParams), OAuthError> {
    // Remove nostrconnect:// prefix
    let uri = uri.strip_prefix("nostrconnect://")
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid nostrconnect URI".to_string()))?;

    // Split pubkey and query params
    let parts: Vec<&str> = uri.split('?').collect();
    if parts.len() != 2 {
        return Err(OAuthError::InvalidRequest("Missing query params".to_string()));
    }

    let client_pubkey = parts[0].to_string();

    // Validate pubkey format (64 hex chars)
    if client_pubkey.len() != 64 || !client_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OAuthError::InvalidRequest("Invalid client public key format".to_string()));
    }

    let query = parts[1];

    // Parse query params manually (serde_urlencoded not available)
    let mut relay = String::new();
    let mut secret = String::new();
    let mut perms = None;
    let mut name = None;
    let mut url = None;
    let mut image = None;

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            let decoded_value = urlencoding::decode(value)
                .map_err(|e| OAuthError::InvalidRequest(format!("Invalid URL encoding: {}", e)))?
                .into_owned();

            match key {
                "relay" => relay = decoded_value,
                "secret" => secret = decoded_value,
                "perms" => perms = Some(decoded_value),
                "name" => name = Some(decoded_value),
                "url" => url = Some(decoded_value),
                "image" => image = Some(decoded_value),
                _ => {} // Ignore unknown params
            }
        }
    }

    if relay.is_empty() || secret.is_empty() {
        return Err(OAuthError::InvalidRequest("Missing required params: relay and secret".to_string()));
    }

    let params = NostrConnectParams {
        relay,
        secret,
        perms,
        name,
        url,
        image,
    };

    // Validate relay URL
    if !params.relay.starts_with("wss://") && !params.relay.starts_with("ws://") {
        return Err(OAuthError::InvalidRequest("Invalid relay URL".to_string()));
    }

    Ok((client_pubkey, params))
}

/// GET /connect/*nostrconnect
/// Entry point from nostr-login popup - shows authorization page
pub async fn connect_get(
    State(_auth_state): State<super::routes::AuthState>,
    axum::extract::Path(nostrconnect_uri): axum::extract::Path<String>,
) -> Result<Response, OAuthError> {
    // Parse the nostrconnect:// URI
    let (client_pubkey, params) = parse_nostrconnect_uri(&nostrconnect_uri)?;

    tracing::info!(
        "nostr-login connect request - client: {}..., app: {}, relay: {}",
        &client_pubkey[..8],
        params.name.as_deref().unwrap_or("Unknown"),
        params.relay
    );

    // TODO: Check if user is logged in via session/UCAN
    // For now, show a simple auth form

    let app_name = params.name.as_deref().unwrap_or("Unknown App");
    let permissions = params.perms.as_deref().unwrap_or("sign_event");

    let html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Authorize Nostr Connection - Keycast</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            width: 100%;
            max-width: 500px;
            background: transparent;
            margin: auto; /* Allows scrolling */
        }}
        h1 {{
            color: #bb86fc;
            font-size: 24px;
            margin-bottom: 16px;
            text-align: center;
        }}
        p {{
            text-align: center;
            margin-bottom: 24px;
            color: #aaa;
        }}
        .app_info {{
            background: #2a2a2a;
            padding: 24px;
            border-radius: 12px;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .info_row {{
            margin: 12px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #333;
            padding-bottom: 12px;
        }}
        .info_row:last-child {{
            border-bottom: none;
            padding-bottom: 0;
            margin-bottom: 0;
        }}
        .label {{
            color: #888;
            font-size: 14px;
        }}
        .value {{
            color: #e0e0e0;
            font-weight: 500;
            text-align: right;
        }}
        .buttons {{
            display: flex;
            gap: 12px;
            margin-top: 24px;
        }}
        button {{
            flex: 1;
            padding: 14px 20px;
            font-size: 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: opacity 0.2s;
        }}
        .approve {{
            background: #bb86fc;
            color: #000;
        }}
        .approve:hover {{
            opacity: 0.9;
        }}
        .deny {{
            background: #333;
            color: #e0e0e0;
        }}
        .deny:hover {{
            background: #444;
        }}
        .warning {{
            background: rgba(255, 179, 0, 0.1);
            border-left: 4px solid #ffb300;
            padding: 16px;
            margin: 24px 0;
            font-size: 14px;
            color: #ffb300;
            border-radius: 0 8px 8px 0;
            line-height: 1.5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 Authorize Nostr Connection</h1>
        <p>An application wants to connect to your Keycast account</p>

        <div class="app_info">
            <div class="info_row">
                <span class="label">Application</span>
                <span class="value">{app_name}</span>
            </div>
            <div class="info_row">
                <span class="label">Permissions</span>
                <span class="value">{permissions}</span>
            </div>
            <div class="info_row">
                <span class="label">Relay</span>
                <span class="value">{relay}</span>
            </div>
        </div>

        <div class="warning">
            ⚠️ This will allow the application to sign events on your behalf using your Keycast-managed keys.
        </div>

        <form method="POST" action="/api/oauth/connect">
            <input type="hidden" name="client_pubkey" value="{client_pubkey}">
            <input type="hidden" name="relay" value="{relay}">
            <input type="hidden" name="secret" value="{secret}">
            <input type="hidden" name="perms" value="{perms}">
            <div class="buttons">
                <button type="submit" name="approved" value="false" class="deny">Deny</button>
                <button type="submit" name="approved" value="true" class="approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>
    "#,
        app_name = app_name,
        permissions = permissions,
        relay = params.relay,
        client_pubkey = client_pubkey,
        secret = params.secret,
        perms = params.perms.as_deref().unwrap_or("")
    );

    Ok(Html(html).into_response())
}

/// POST /oauth/connect
/// User approves/denies the nostr-login connection
pub async fn connect_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ConnectApprovalForm>,
) -> Result<Response, OAuthError> {
    let tenant_id = tenant.0.id;

    tracing::info!(
        "nostr-login connect approval - client: {}..., approved: {}",
        &form.client_pubkey[..8],
        form.approved
    );

    if !form.approved {
        return Ok(Html(r#"
<html>
<head>
    <title>Authorization Denied</title>
    <style>
        body {
            font-family: sans-serif;
            text-align: center;
            padding: 50px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        h1 { color: #f44336; }
    </style>
    <script>
        setTimeout(() => window.close(), 2000);
    </script>
</head>
<body>
    <h1>✗ Authorization Denied</h1>
    <p>You can close this window.</p>
</body>
</html>
        "#).into_response());
    }

    // Extract user public key from JWT token in Authorization header
    let user_public_key = super::auth::extract_user_from_token(&headers)
        .map_err(|_| OAuthError::Unauthorized)?;

    // Get user's encrypted key
    let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = $1 AND user_public_key = $2"
    )
    .bind(tenant_id)
    .bind(&user_public_key)
    .fetch_one(&auth_state.state.db)
    .await?;

    // Parse user's public key
    let bunker_public_key = nostr_sdk::PublicKey::from_hex(&user_public_key)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?;

    // Create or get application - use client pubkey as identifier
    let app_name = format!("nostr-login-{}", &form.client_pubkey[..12]);

    let app_id: i32 = match sqlx::query_scalar::<_, i32>(
        "SELECT id FROM oauth_applications WHERE tenant_id = $1 AND client_id = $2"
    )
    .bind(tenant_id)
    .bind(&form.client_pubkey)
    .fetch_optional(&auth_state.state.db)
    .await? {
        Some(id) => id,
        None => {
            sqlx::query_scalar(
                "INSERT INTO oauth_applications (tenant_id, client_id, client_secret, name, redirect_uris, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, '[]', $5, $6) RETURNING id"
            )
            .bind(tenant_id)
            .bind(&form.client_pubkey)
            .bind("") // No client secret for nostr-login
            .bind(&app_name)
            .bind(Utc::now())
            .bind(Utc::now())
            .fetch_one(&auth_state.state.db)
            .await?
        }
    };

    // Create authorization
    let relays_json = serde_json::to_string(&vec![form.relay.clone()])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (tenant_id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, client_public_key, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(tenant_id)
    .bind(&user_public_key)
    .bind(app_id)
    .bind(bunker_public_key.to_hex())
    .bind(&encrypted_user_key)
    .bind(&form.secret)
    .bind(&relays_json)
    .bind(&form.client_pubkey)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&auth_state.state.db)
    .await?;

    // Signal signer daemon to reload via channel (instant notification)
    if let Some(tx) = &auth_state.auth_tx {
        use keycast_core::authorization_channel::AuthorizationCommand;
        if let Err(e) = tx.send(AuthorizationCommand::Upsert {
            bunker_pubkey: bunker_public_key.to_hex(),
            tenant_id,
            is_oauth: true,
        }).await {
            tracing::error!("Failed to send authorization upsert command (nostr-login): {}", e);
        } else {
            tracing::info!("Sent authorization upsert command to signer daemon (nostr-login)");
        }
    }

    Ok(Html(r#"
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            text-align: center;
            padding: 50px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        h1 {
            color: #4CAF50;
            font-size: 32px;
        }
        p {
            font-size: 18px;
            color: #888;
        }
        .checkmark {
            font-size: 64px;
            margin-bottom: 20px;
        }
    </style>
    <script>
        setTimeout(() => window.close(), 3000);
    </script>
</head>
<body>
    <div class="checkmark">✓</div>
    <h1>Authorization Successful</h1>
    <p>You can close this window.</p>
    <p style="font-size: 14px; margin-top: 20px;">(Closing automatically in 3 seconds...)</p>
</body>
</html>
    "#).into_response())
}

// ============================================================================
// Polling Endpoint for iOS PWA OAuth Flow
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PollRequest {
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct PollResponse {
    pub code: String,
}

/// GET /oauth/poll?state={state}
/// Polling endpoint for iOS PWA OAuth flow (where redirect doesn't work)
/// Returns HTTP 200 with code when ready, HTTP 202 if pending, HTTP 404 if not found/expired
pub async fn poll(
    Query(req): Query<PollRequest>,
) -> Result<Response, OAuthError> {
    // Clean up expired entries lazily
    POLLING_CACHE.retain(|_, (_, expiry)| expiry.elapsed() < POLLING_TTL);

    // Check if code is ready
    if let Some(entry) = POLLING_CACHE.get(&req.state) {
        let (code, expiry) = entry.value();

        // Check if expired
        if expiry.elapsed() >= POLLING_TTL {
            POLLING_CACHE.remove(&req.state);
            return Err(OAuthError::InvalidRequest("State expired".to_string()));
        }

        // Code ready - return and remove from cache (one-time use)
        let code = code.clone();
        drop(entry);  // Release lock before removing
        POLLING_CACHE.remove(&req.state);

        Ok((
            StatusCode::OK,
            Json(PollResponse { code })
        ).into_response())
    } else {
        // Code not ready yet - return 202 Accepted
        Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending" }))
        ).into_response())
    }
}
