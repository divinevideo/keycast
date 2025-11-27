# Keycast Integration with nostr-login

## Executive Summary

This document outlines the implementation needed to make Keycast compatible with the nostr-login library, allowing any application using nostr-login to add Keycast as a bunker provider option alongside nsec.app, highlighter.com, and other NIP-46 signers.

## Background

### What is nostr-login?

nostr-login (https://github.com/nostrband/nostr-login) is a popular authentication library that provides a turnkey UI for Nostr authentication. It supports multiple login methods including:
- Nostr Connect (NIP-46) bunkers like nsec.app, highlighter.com
- Browser extensions
- Read-only login
- Account switching

Applications can add nostr-login with a simple script tag:
```html
<script
  src='https://www.unpkg.com/nostr-login@latest/dist/unpkg.js'
  data-bunkers="nsec.app,highlighter.com"
></script>
```

### How nostr-login Discovers Bunkers

When a user clicks on a bunker provider (e.g., "Login with nsec.app"), nostr-login:

1. **Fetches NIP-05 Discovery**: Queries `https://<domain>/.well-known/nostr.json?name=_`
2. **Extracts Connection Template**: Gets the `nostrconnect_url` field
3. **Generates Client Keys**: Creates a local keypair for the client
4. **Builds Connection URI**: Creates a `nostrconnect://` URI with client pubkey, relay, secret, permissions
5. **Opens Popup**: Substitutes the `<nostrconnect>` placeholder in the template URL and opens it
6. **Waits for Connection**: The bunker handles auth and connects back via NIP-46

### Example: nsec.app Discovery

Query: `https://nsec.app/.well-known/nostr.json?name=_`

Response:
```json
{
  "nip46": {
    "relay": "wss://relay.nsec.app",
    "nostrconnect_url": "https://use.nsec.app/<nostrconnect>"
  }
}
```

Flow:
1. nostr-login generates: `nostrconnect://abc123...?relay=wss://relay.damus.io&secret=xyz...&perms=sign_event:1`
2. Opens popup to: `https://use.nsec.app/nostrconnect://abc123...?relay=wss://relay.damus.io&secret=xyz...&perms=sign_event:1`
3. User logs into nsec.app in the popup
4. nsec.app connects back to client via NIP-46 protocol
5. Popup closes, authentication complete

## Keycast Current State

### What Keycast Already Has ✅

1. **OAuth 2.0 Authorization Flow** (`/api/oauth/*`)
   - User registration/login
   - Authorization code flow
   - Token exchange for bunker URLs

2. **NIP-46 Signer Daemon**
   - Handles remote signing requests
   - Monitors oauth_authorizations table
   - Spawns signer processes for each authentication
   - Supports NIP-04 and NIP-44 encryption

3. **Bunker URL Generation**
   - Format: `bunker://<pubkey>?relay=<url>&secret=<secret>`
   - Uses user's personal Nostr key
   - Stores authorizations in database
   - Signals signer daemon to reload

### OAuth Flow (Current Implementation)

Example clients show this flow (see `nostr-oauth-sign-working.html`):

1. User registers/logs in → gets JWT
2. OAuth authorize → gets authorization code
3. Token exchange → gets bunker URL
4. Client connects via NIP-46
5. Signs events remotely

## Required Implementation

To make Keycast work with nostr-login, we need to add two components:

### 1. NIP-05 Discovery Endpoint

**Endpoint**: `/.well-known/nostr.json`

**Query Parameter**: `name=_` (underscore for service discovery)

**Response Format**:
```json
{
  "nip46": {
    "relay": "wss://relay3.openvine.co",
    "nostrconnect_url": "https://login.divine.video/connect/<nostrconnect>"
  }
}
```

**Implementation Notes**:
- This is a static JSON response (no database queries needed)
- The relay URL should match what's used in `oauth.rs:223`
- The `<nostrconnect>` placeholder is literal - nostr-login will replace it
- CORS must be enabled (nostr-login fetches from different origins)

**Location**: Add to `api/src/api/http/routes.rs`

```rust
// In routes.rs
async fn nostr_discovery() -> impl IntoResponse {
    let discovery = serde_json::json!({
        "nip46": {
            "relay": "wss://relay3.openvine.co",
            "nostrconnect_url": "https://login.divine.video/connect/<nostrconnect>"
        }
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(discovery)
    )
}

// Add route
Router::new()
    .route("/.well-known/nostr.json", get(nostr_discovery))
```

### 2. Nostr Connect Endpoint

**Endpoint**: `/connect/<nostrconnect>`

**Purpose**: Handle the popup flow from nostr-login

**URL Structure**:
```
https://login.divine.video/connect/nostrconnect://CLIENT_PUBKEY?relay=RELAY_URL&secret=SECRET&perms=PERMISSIONS&name=APP_NAME
```

**Flow**:

1. **Parse nostrconnect:// URI from path**
   - Extract client pubkey (hex)
   - Extract relay URL
   - Extract secret
   - Extract permissions (optional)
   - Extract app name/metadata (optional)

2. **Show OAuth UI**
   - If user not logged in: show login/register form
   - If logged in: show authorization approval page
   - Display what permissions the app is requesting
   - Show app name/icon if provided

3. **On Authorization Approval**:
   - Get user's public key from session
   - Get user's encrypted personal key from `personal_keys` table
   - Generate authorization in `oauth_authorizations` table with:
     - `user_public_key`: from session
     - `application_id`: create or get based on client metadata
     - `bunker_public_key`: user's pubkey (hex)
     - `bunker_secret`: user's encrypted secret key (BLOB)
     - `secret`: the connection secret from nostrconnect:// URI
     - `relays`: array with relay from nostrconnect:// URI
     - `client_public_key`: client pubkey from nostrconnect:// URI (NEW FIELD - see below)

4. **Signal Signer Daemon**:
   - Create reload signal file (already implemented in `oauth.rs:243-245`)
   - Signer daemon picks up new authorization
   - Signer connects to the relay and waits for client's connect request

5. **Show Success Page**:
   - Display "Authorization successful"
   - Show "You can close this window" message
   - Optionally auto-close after 2 seconds with JavaScript

**Key Difference from Current OAuth Flow**:

Current OAuth flow:
- Client → OAuth authorize → gets code → exchanges code for bunker URL
- Client then connects to bunker URL

nostr-login flow:
- Client generates `nostrconnect://` URI first (includes relay, secret)
- User → Keycast popup → approves
- Keycast creates authorization using the client-provided relay and secret
- Signer daemon connects to client (client is waiting on that relay)
- No bunker URL needs to be returned to client (client already has the connection info)

**Database Schema Addition**:

The current `oauth_authorizations` table needs a new field:

```sql
ALTER TABLE oauth_authorizations
ADD COLUMN client_public_key TEXT;
```

This stores the client's public key so the signer daemon knows who to connect to.

**Implementation Location**: Add to `api/src/api/http/oauth.rs`

```rust
// In oauth.rs

#[derive(Debug, Deserialize)]
pub struct NostrConnectParams {
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
    pub image: Option<String>,
}

/// Parse nostrconnect:// URI from path
/// Format: nostrconnect://CLIENT_PUBKEY?relay=RELAY&secret=SECRET&perms=...
fn parse_nostrconnect_uri(uri: &str) -> Result<(String, NostrConnectParams), OAuthError> {
    // Remove nostrconnect:// prefix
    let uri = uri.strip_prefix("nostrconnect://")
        .ok_or(OAuthError::InvalidRequest("Invalid nostrconnect URI".to_string()))?;

    // Split pubkey and query params
    let parts: Vec<&str> = uri.split('?').collect();
    if parts.len() != 2 {
        return Err(OAuthError::InvalidRequest("Missing query params".to_string()));
    }

    let client_pubkey = parts[0].to_string();
    let query = parts[1];

    // Parse query params
    let params: NostrConnectParams = serde_urlencoded::from_str(query)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid params: {}", e)))?;

    Ok((client_pubkey, params))
}

/// GET /connect/<nostrconnect>
/// Entry point from nostr-login popup
pub async fn connect_get(
    State(auth_state): State<super::routes::AuthState>,
    axum::extract::Path(nostrconnect_uri): axum::extract::Path<String>,
) -> Result<Response, OAuthError> {
    // Parse the nostrconnect:// URI
    let (client_pubkey, params) = parse_nostrconnect_uri(&nostrconnect_uri)?;

    // Store in session/state for POST handler
    // For now, return HTML form with hidden fields

    let html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authorize Nostr Connection</title>
    <style>
        body {{ font-family: sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }}
        button {{ padding: 10px 20px; font-size: 16px; margin: 10px; }}
        .approve {{ background: #4CAF50; color: white; border: none; cursor: pointer; }}
        .deny {{ background: #f44336; color: white; border: none; cursor: pointer; }}
    </style>
</head>
<body>
    <h1>🔑 Authorize Connection</h1>
    <p>App: {app_name}</p>
    <p>Permissions: {permissions}</p>
    <p>Relay: {relay}</p>

    <form method="POST" action="/api/oauth/connect">
        <input type="hidden" name="client_pubkey" value="{client_pubkey}">
        <input type="hidden" name="relay" value="{relay}">
        <input type="hidden" name="secret" value="{secret}">
        <input type="hidden" name="perms" value="{perms}">
        <button type="submit" name="approved" value="true" class="approve">Approve</button>
        <button type="submit" name="approved" value="false" class="deny">Deny</button>
    </form>
</body>
</html>
    "#,
        app_name = params.name.as_deref().unwrap_or("Unknown App"),
        permissions = params.perms.as_deref().unwrap_or("sign_event"),
        relay = params.relay,
        client_pubkey = client_pubkey,
        secret = params.secret,
        perms = params.perms.as_deref().unwrap_or("")
    );

    Ok(Html(html).into_response())
}

/// POST /connect
/// User approves/denies the connection
pub async fn connect_post(
    State(auth_state): State<super::routes::AuthState>,
    Form(form): Form<ConnectApprovalForm>,
) -> Result<Response, OAuthError> {
    if !form.approved {
        return Ok(Html("<h1>Authorization Denied</h1><p>You can close this window.</p>").into_response());
    }

    // TODO: Get user from session/JWT
    // For now, get most recent user
    let user_public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM users ORDER BY created_at DESC LIMIT 1")
            .fetch_optional(&auth_state.state.db)
            .await?;

    let user_public_key = user_public_key.ok_or(OAuthError::Unauthorized)?;

    // Get user's encrypted key
    let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE user_public_key = ?1"
    )
    .bind(&user_public_key)
    .fetch_one(&auth_state.state.db)
    .await?;

    // Parse public key
    let bunker_public_key = nostr_sdk::PublicKey::from_hex(&user_public_key)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?;

    // Create or get application
    let app_name = format!("nostr-login-{}", &form.client_pubkey[..8]);
    let app_id: i64 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, '[]', ?4, ?5)
         ON CONFLICT(client_id) DO UPDATE SET updated_at = ?5
         RETURNING id"
    )
    .bind(&form.client_pubkey)
    .bind("") // No client secret needed for nostr-login flow
    .bind(&app_name)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&auth_state.state.db)
    .await?;

    // Create authorization
    let relays_json = serde_json::to_string(&vec![form.relay])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, client_public_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
    )
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

    // Signal signer daemon
    let signal_file = std::path::Path::new("database/.reload_signal");
    let _ = std::fs::File::create(signal_file);
    tracing::info!("Created reload signal for signer daemon");

    Ok(Html(r#"
<html>
<head>
    <title>Success</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; }
        h1 { color: #4CAF50; }
    </style>
    <script>
        setTimeout(() => window.close(), 2000);
    </script>
</head>
<body>
    <h1>✓ Authorization Successful</h1>
    <p>You can close this window.</p>
</body>
</html>
    "#).into_response())
}
```

### 3. Database Migration

**File**: Create `migrations/YYYYMMDDHHMMSS_add_client_pubkey_to_oauth_authorizations.sql`

```sql
-- Add client_public_key to oauth_authorizations
ALTER TABLE oauth_authorizations
ADD COLUMN client_public_key TEXT;

-- Index for lookups
CREATE INDEX idx_oauth_authorizations_client_pubkey
ON oauth_authorizations(client_public_key);
```

### 4. Update Routes

**File**: `api/src/api/http/routes.rs`

Add the new routes:

```rust
// In routes() function

// NIP-05 discovery (no auth required)
let discovery_routes = Router::new()
    .route("/.well-known/nostr.json", get(nostr_discovery));

// Nostr Connect routes (no auth initially, auth happens in popup)
let connect_routes = Router::new()
    .route("/connect/*nostrconnect", get(oauth::connect_get))
    .route("/connect", post(oauth::connect_post))
    .with_state(auth_state.clone());

// Update Router merge
Router::new()
    .merge(root_route)
    .merge(discovery_routes)  // Add this
    .merge(auth_routes)
    .merge(oauth_routes)
    .merge(connect_routes)    // Add this
    .merge(user_routes)
    .merge(team_routes)
```

### 5. CORS Configuration

**Critical**: The discovery endpoint MUST have CORS enabled for cross-origin requests from nostr-login.

**File**: `api/src/main.rs` (or wherever CORS is configured)

Ensure `.well-known/nostr.json` allows all origins:

```rust
use tower_http::cors::{CorsLayer, Any};

let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods(Any)
    .allow_headers(Any);

app.layer(cors)
```

## Testing Plan

### 1. Manual Testing

**Test Discovery Endpoint**:
```bash
curl https://login.divine.video/.well-known/nostr.json?name=_
```

Expected response:
```json
{
  "nip46": {
    "relay": "wss://relay3.openvine.co",
    "nostrconnect_url": "https://login.divine.video/connect/<nostrconnect>"
  }
}
```

**Test Connect Endpoint**:
```bash
# This would normally come from nostr-login, but you can test manually
open "https://login.divine.video/connect/nostrconnect://abc123...?relay=wss://relay.damus.io&secret=test&name=TestApp"
```

Should show authorization page.

### 2. Integration Test with nostr-login

Create `examples/nostr-login-test.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Keycast + nostr-login Test</title>
    <script
      src='https://www.unpkg.com/nostr-login@latest/dist/unpkg.js'
      data-bunkers="login.divine.video"
      data-perms="sign_event:1"
    ></script>
</head>
<body>
    <h1>Test Keycast with nostr-login</h1>
    <button onclick="testSign()">Sign Test Event</button>
    <pre id="output"></pre>

    <script>
        async function testSign() {
            const output = document.getElementById('output');
            try {
                // This will trigger nostr-login if not authed
                const event = await window.nostr.signEvent({
                    kind: 1,
                    created_at: Math.floor(Date.now() / 1000),
                    tags: [],
                    content: "Hello from Keycast via nostr-login!"
                });
                output.textContent = JSON.stringify(event, null, 2);
            } catch (e) {
                output.textContent = "Error: " + e.message;
            }
        }
    </script>
</body>
</html>
```

**Test Flow**:
1. Open `nostr-login-test.html`
2. Click "Sign Test Event"
3. nostr-login shows login modal
4. Click "Login with login.divine.video"
5. Popup opens to Keycast
6. Login/register and approve
7. Popup closes
8. Event gets signed
9. Success!

### 3. Automated Tests

Add integration test in `api/tests/nostr_login_integration_test.rs`:

```rust
#[tokio::test]
async fn test_nostr_discovery_endpoint() {
    // Test /.well-known/nostr.json returns correct format
}

#[tokio::test]
async fn test_connect_endpoint_parsing() {
    // Test /connect/<nostrconnect> parses URI correctly
}

#[tokio::test]
async fn test_full_nostr_login_flow() {
    // Test complete flow from discovery to authorization
}
```

## Deployment Checklist

- [ ] Add database migration for `client_public_key` field
- [ ] Implement `/.well-known/nostr.json` endpoint
- [ ] Implement `/connect/<nostrconnect>` GET handler
- [ ] Implement `/connect` POST handler
- [ ] Update routes configuration
- [ ] Enable CORS for discovery endpoint
- [ ] Test discovery endpoint
- [ ] Test connect endpoint manually
- [ ] Create nostr-login test HTML
- [ ] Test full integration with nostr-login
- [ ] Update signer daemon if needed (may need to handle client-initiated flow)
- [ ] Deploy to login.divine.video
- [ ] Test on production
- [ ] Document in main README

## Future Enhancements

### Session Management
Currently the implementation uses "most recent user" for testing. In production, you need:
- JWT-based session management
- Cookie-based auth for the popup flow
- Proper user lookup from session

### UI/UX
- Branded authorization page matching Keycast design
- Show app icon/metadata
- Remember approved apps
- Revocation UI

### Security
- Rate limiting on connect endpoint
- CSRF protection
- Validate client pubkey format
- Validate relay URLs (whitelist?)

### Signer Daemon Updates
The current signer daemon expects bunker-initiated flow (client has bunker URL). For nostr-login, the flow is client-initiated (signer connects to client). You may need to update the signer daemon to:
- Read `client_public_key` from authorizations
- Initiate connection to client instead of waiting for connection
- Handle both flow types

Check `signer/src/signer_daemon.rs` and `signer/src/signer_manager.rs` to see if updates are needed.

## Success Metrics

When complete, users should be able to:

1. ✅ Add `data-bunkers="login.divine.video"` to any nostr-login script tag
2. ✅ See "Login with login.divine.video" (or "Keycast") in the nostr-login modal
3. ✅ Click it and get Keycast OAuth popup
4. ✅ Login/register in popup
5. ✅ Approve authorization
6. ✅ Popup closes automatically
7. ✅ App can now sign events via `window.nostr`
8. ✅ No manual bunker URL copy/paste needed

This makes Keycast as easy to use as nsec.app for any nostr-login enabled application!

## Questions / Clarifications Needed

1. **Domain**: Should we use `login.divine.video` or a different domain?
2. **Branding**: What name should appear in nostr-login? "Keycast"? "login.divine.video"?
3. **Relay**: Confirm `wss://relay3.openvine.co` is the correct relay to use
4. **Session Management**: How do you want to handle user sessions in the popup? JWT in cookie?
5. **Signer Daemon**: Need to verify if signer daemon handles client-initiated connections or if updates needed

## References

- nostr-login: https://github.com/nostrband/nostr-login
- NIP-46 (Nostr Connect): https://github.com/nostr-protocol/nips/blob/master/46.md
- NIP-05 (DNS-based verification): https://github.com/nostr-protocol/nips/blob/master/05.md
- nsec.app discovery: https://nsec.app/.well-known/nostr.json?name=_
- Existing Keycast OAuth: `examples/OAUTH_NOSTR_README.md`
- Working OAuth client: `examples/nostr-oauth-sign-working.html`
