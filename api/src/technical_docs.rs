// ABOUTME: Technical documentation page explaining Keycast architecture in depth
// ABOUTME: Covers NIP-46, OAuth flow, encryption, relay architecture, and security model

use axum::response::Html;

pub async fn technical_docs() -> Html<&'static str> {
    Html(r##"
<!DOCTYPE html>
<html>
<head>
    <title>Keycast Technical Documentation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 1000px; margin: 0 auto; padding: 20px;
            background: #1a1a1a; color: #e0e0e0;
            line-height: 1.7;
        }
        h1 { color: #bb86fc; margin-top: 20px; font-size: 2.5em; }
        h2 { color: #03dac6; margin-top: 50px; border-bottom: 2px solid #333; padding-bottom: 10px; }
        h3 { color: #03dac6; margin-top: 30px; font-size: 1.3em; }
        h4 { color: #bb86fc; margin-top: 25px; font-size: 1.1em; }
        a { color: #03dac6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background: #2a2a2a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; color: #bb86fc; }
        pre { background: #2a2a2a; padding: 15px; border-radius: 8px; overflow-x: auto; border-left: 3px solid #bb86fc; }
        pre code { background: none; padding: 0; color: #e0e0e0; }
        .info-box { background: #2a2a2a; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #03dac6; }
        .warning-box { background: #2a2a2a; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #f59e0b; }
        .architecture-diagram { background: #2a2a2a; padding: 20px; margin: 20px 0; border-radius: 8px; font-family: monospace; font-size: 0.9em; }
        .toc { background: #2a2a2a; padding: 20px; border-radius: 8px; margin: 30px 0; }
        .toc ul { list-style: none; padding-left: 0; }
        .toc li { margin: 8px 0; }
        .toc a { color: #bb86fc; }
        .back-link { display: inline-block; margin-bottom: 30px; color: #03dac6; }
        .footer { margin-top: 80px; padding-top: 20px; border-top: 1px solid #333; font-size: 0.9em; color: #888; }
    </style>
</head>
<body>
    <a href="/" class="back-link">← Back to Home</a>

    <h1>🔐 Keycast Technical Documentation</h1>
    <p style="font-size: 1.2em; color: #aaa;">Deep dive into the architecture, protocols, and security model</p>

    <div class="toc">
        <strong style="color: #bb86fc; font-size: 1.1em;">Table of Contents</strong>
        <ul>
            <li><a href="#overview">System Overview</a></li>
            <li><a href="#architecture">Architecture Components</a></li>
            <li><a href="#nip46">NIP-46 Remote Signing Protocol</a></li>
            <li><a href="#oauth">OAuth 2.0 Authorization Flow</a></li>
            <li><a href="#encryption">Encryption & Key Management</a></li>
            <li><a href="#relay">Relay Architecture & Scaling</a></li>
            <li><a href="#security">Security Model & Trust</a></li>
            <li><a href="#api">API Reference</a></li>
        </ul>
    </div>

    <h2 id="overview">System Overview</h2>
    <p>
        Keycast is a custodial NIP-46 remote signer that provides OAuth 2.0 authorization flows for Nostr applications.
        It consists of three main components working together to enable passwordless Nostr authentication.
    </p>

    <div class="architecture-diagram">
<pre>
┌─────────────┐
│ Nostr App   │ (Web/Mobile Client)
└──────┬──────┘
       │ 1. OAuth Authorization Request
       ▼
┌─────────────────┐
│   API Server    │ (Port 3000)
│  - Auth/Login   │
│  - OAuth Flow   │
│  - User Mgmt    │
└────────┬────────┘
         │
         │ 2. Creates OAuth Authorization
         │    (stored encrypted in DB)
         │
         ▼
┌────────────────────┐
│ SQLite Database    │
│  - Users           │
│  - OAuth Auths     │
│  - Encrypted Keys  │
└────────┬───────────┘
         │
         │ 3. Signer loads auths & subscribes to relays
         │
         ▼
┌────────────────────┐         ┌──────────────┐
│  Signer Daemon     │◄────────┤ Nostr Relays │
│  - Loads 74 auths  │         │  - damus.io  │
│  - Single sub to   │ 4. Sign │  - nos.lol   │
│    kind 24133      │ Request │  - nsec.app  │
│  - Signs w/ GCP    │────────►│              │
│    KMS encrypted   │ 5. Sign │              │
│    keys            │ Response│              │
└────────────────────┘         └──────────────┘
         ▲
         │
         │ 6. Decrypts keys via GCP KMS
         │
         ▼
┌────────────────────┐
│  Google Cloud KMS  │
│  - Key Encryption  │
│  - 300ms per key   │
└────────────────────┘
</pre>
    </div>

    <h2 id="architecture">Architecture Components</h2>

    <h3>1. API Server (Rust/Axum)</h3>
    <div class="info-box">
        <strong>Role:</strong> HTTP API for user authentication and OAuth authorization<br>
        <strong>Port:</strong> 3000<br>
        <strong>Database:</strong> SQLite (production-ready with proper indexing)<br>
        <strong>Key Operations:</strong>
        <ul>
            <li>User registration/login with JWT tokens</li>
            <li>OAuth 2.0 authorization code flow</li>
            <li>Bunker URL generation and management</li>
            <li>NIP-05 identifier resolution</li>
        </ul>
    </div>

    <h3>2. Signer Daemon (Rust/nostr-sdk)</h3>
    <div class="info-box">
        <strong>Role:</strong> Remote signing service listening on Nostr relays<br>
        <strong>Relays:</strong> relay.damus.io, nos.lol, relay.nsec.app<br>
        <strong>Key Features:</strong>
        <ul>
            <li><strong>Single Subscription:</strong> One kind 24133 filter for ALL users (scales to millions)</li>
            <li><strong>Fast Reload:</strong> Only decrypts last 5 new authorizations (~1.5s reload time)</li>
            <li><strong>Dual Encryption:</strong> Supports both NIP-44 (new) and NIP-04 (fallback)</li>
            <li><strong>Relay Redundancy:</strong> 3 relays for high availability</li>
        </ul>
    </div>

    <h3>3. Key Management (GCP KMS)</h3>
    <div class="info-box">
        <strong>Encryption Method:</strong> Google Cloud Key Management Service<br>
        <strong>Performance:</strong> ~300ms per key decryption<br>
        <strong>Alternative:</strong> File-based encryption for development (USE_GCP_KMS=false)<br>
        <strong>Storage:</strong> Encrypted keys stored in SQLite, decrypted on-demand
    </div>

    <h2 id="nip46">NIP-46 Remote Signing Protocol</h2>

    <h3>What is NIP-46?</h3>
    <p>
        NIP-46 (Nostr Connect) is a protocol for remote event signing. Instead of giving apps direct access to your private keys,
        apps send signing requests through Nostr relays to a remote signer, which signs and returns the result.
    </p>

    <h3>Bunker URL Format</h3>
    <pre><code>bunker://&lt;bunker-pubkey&gt;?relay=wss://relay.example.com&amp;secret=&lt;connection-secret&gt;</code></pre>

    <p><strong>Components:</strong></p>
    <ul>
        <li><code>bunker-pubkey</code>: The signer's public key (ephemeral per authorization)</li>
        <li><code>relay</code>: Relay URL where signing requests should be sent</li>
        <li><code>secret</code>: Shared secret for authorization validation</li>
    </ul>

    <h3>Event Flow</h3>
    <div class="architecture-diagram">
<pre>
1. App creates unsigned event:
{
  "kind": 1,
  "content": "Hello Nostr!",
  "tags": [],
  "created_at": 1234567890
}

2. App encrypts JSON-RPC request with bunker pubkey:
{
  "id": "req-123",
  "method": "sign_event",
  "params": ["&lt;unsigned-event-json&gt;"]
}

3. App publishes kind 24133 event to relay:
{
  "kind": 24133,
  "content": "&lt;encrypted-request&gt;",
  "tags": [["p", "&lt;bunker-pubkey&gt;"]],
  "pubkey": "&lt;app-pubkey&gt;",
  ...
}

4. Signer daemon receives event (single subscription):
   - Checks if bunker-pubkey matches one we manage
   - If yes: decrypts request with bunker private key
   - Validates secret
   - Decrypts user's key from GCP KMS
   - Signs the event
   - Encrypts response
   - Publishes kind 24133 response

5. App receives signed event and can publish it
</pre>
    </div>

    <h3>Supported Methods</h3>
    <ul>
        <li><code>connect</code> - Initial connection handshake</li>
        <li><code>get_public_key</code> - Returns user's public key</li>
        <li><code>sign_event</code> - Signs a Nostr event</li>
        <li><code>nip04_encrypt</code> - Legacy DM encryption</li>
        <li><code>nip04_decrypt</code> - Legacy DM decryption</li>
        <li><code>nip44_encrypt</code> - Modern DM encryption (preferred)</li>
        <li><code>nip44_decrypt</code> - Modern DM decryption (preferred)</li>
    </ul>

    <h2 id="oauth">OAuth 2.0 Authorization Flow</h2>

    <h3>Why OAuth for Nostr?</h3>
    <p>
        OAuth 2.0 provides a familiar authorization flow for users ("Login with Keycast" similar to "Login with Google").
        Instead of sharing keys, apps request specific permissions and receive a bunker URL for remote signing.
    </p>

    <h3>Authorization Code Flow</h3>
    <div class="architecture-diagram">
<pre>
1. App redirects to authorization endpoint:
   GET /api/oauth/authorize?
       response_type=code&
       client_id=my-app&
       redirect_uri=https://app.example.com/callback&
       scope=sign_event

2. User logs in (if not already) and approves request

3. Server redirects back with authorization code:
   https://app.example.com/callback?code=AUTH_CODE_123

4. App exchanges code for bunker URL:
   POST /api/oauth/token
   {
     "grant_type": "authorization_code",
     "code": "AUTH_CODE_123",
     "client_id": "my-app",
     "redirect_uri": "https://app.example.com/callback"
   }

5. Server responds with connection credentials:
   {
     "bunker_url": "bunker://abc123...?relay=wss://relay.damus.io&secret=xyz789",
     "pubkey": "user-pubkey-hex"
   }

6. App connects to bunker URL and can now request signatures
</pre>
    </div>

    <h3>Security Features</h3>
    <ul>
        <li><strong>Authorization codes expire:</strong> Single-use codes prevent replay attacks</li>
        <li><strong>State parameter:</strong> CSRF protection (recommended for apps)</li>
        <li><strong>Redirect URI validation:</strong> Prevents authorization code theft</li>
        <li><strong>Per-app bunker keys:</strong> Each authorization gets unique ephemeral keys</li>
    </ul>

    <h2 id="encryption">Encryption & Key Management</h2>

    <h3>Key Hierarchy</h3>
    <div class="info-box">
        <strong>Master Encryption Key (GCP KMS)</strong><br>
        └── Encrypts all user private keys in database<br>
        &nbsp;&nbsp;&nbsp;&nbsp;├── User Private Key (Nostr keypair)<br>
        &nbsp;&nbsp;&nbsp;&nbsp;│&nbsp;&nbsp;&nbsp;└── Used for signing events<br>
        &nbsp;&nbsp;&nbsp;&nbsp;└── Bunker Private Keys (ephemeral per OAuth auth)<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;└── Used for NIP-46 encryption with apps
    </div>

    <h3>Database Encryption</h3>
    <p>All sensitive data is encrypted before storage:</p>
    <ul>
        <li><strong>User private keys:</strong> Nostr secret keys encrypted with GCP KMS</li>
        <li><strong>Bunker secrets:</strong> OAuth connection secrets encrypted</li>
        <li><strong>Authorization data:</strong> Bunker private keys encrypted</li>
    </ul>

    <h3>Dual NIP-04/NIP-44 Support</h3>
    <p>
        The signer supports both encryption standards for maximum compatibility:
    </p>
    <ul>
        <li><strong>NIP-44 (preferred):</strong> Modern encryption standard, tried first</li>
        <li><strong>NIP-04 (fallback):</strong> Legacy encryption, used if NIP-44 fails</li>
        <li><strong>Auto-detection:</strong> Responses use same encryption as request</li>
    </ul>

    <pre><code>// Decryption attempt order
let (decrypted, use_nip44) = match nip44::decrypt(key, pubkey, content) {
    Ok(d) => (d, true),  // NIP-44 success
    Err(_) => {
        // Fallback to NIP-04
        nip04::decrypt(key, pubkey, content)?
        (d, false)
    }
};</code></pre>

    <h2 id="relay">Relay Architecture & Scaling</h2>

    <h3>Single Subscription Optimization</h3>
    <div class="info-box">
        <strong>Problem:</strong> With 1M users, subscribing to each user's bunker pubkey = 1M relay subscriptions (impossible)<br><br>
        <strong>Solution:</strong> Single subscription to ALL kind 24133 events, filter in handler
    </div>

    <h4>Before (Doesn't Scale):</h4>
    <pre><code>// One subscription per user (74 subscriptions for 74 users)
for bunker_pubkey in user_pubkeys {
    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(bunker_pubkey);
    client.subscribe(vec![filter], None).await?;
}</code></pre>

    <h4>After (Scales to Millions):</h4>
    <pre><code>// Single subscription for ALL kind 24133 events
let filter = Filter::new().kind(Kind::NostrConnect);
client.subscribe(vec![filter], None).await?;

// Filter in handler
let bunker_pubkey = event.tags.find_p_tag()?;
if let Some(handler) = handlers.get(bunker_pubkey) {
    // This is for us, process it
    handler.sign_event(event).await?;
} else {
    // Not our bunker, ignore
}</code></pre>

    <div class="info-box">
        <strong>Result:</strong> 3 relay connections total (for redundancy) regardless of user count!<br>
        <strong>Performance:</strong> HashMap lookup is O(1), minimal overhead
    </div>

    <h3>Fast Reload Optimization</h3>
    <p>
        When new users register, the signer daemon needs to load new authorizations without restarting.
        Decrypting ALL keys with GCP KMS took 18-21 seconds for 67 users.
    </p>

    <h4>Optimization:</h4>
    <pre><code>// Only check last 5 authorization IDs (new ones are sequential)
let check_start = all_auths.len().saturating_sub(5);
let recent_auths = all_auths.skip(check_start);

for auth_id in recent_auths {
    if !already_loaded.contains(auth_id) {
        // Decrypt and load only this new one
        load_authorization(auth_id).await?;
    }
}

// Result: ~1.5 second reload time!</code></pre>

    <h3>Relay Selection</h3>
    <p>Current relay configuration:</p>
    <ul>
        <li><strong>relay.damus.io</strong> - Large, well-established relay</li>
        <li><strong>nos.lol</strong> - Fast, reliable relay</li>
        <li><strong>relay.nsec.app</strong> - Purpose-built for NIP-46</li>
    </ul>

    <div class="warning-box">
        <strong>Important:</strong> Not all relays support kind 24133 events! Check relay's supported_nips list for NIP-46 support.
    </div>

    <h2 id="security">Security Model & Trust</h2>

    <h3>What You're Trusting Keycast With</h3>
    <ul>
        <li>✓ <strong>Key custody:</strong> We hold your encrypted private keys</li>
        <li>✓ <strong>Signing authority:</strong> We can sign any event you authorize</li>
        <li>✓ <strong>Metadata visibility:</strong> We can see which apps you authorize and when you sign</li>
        <li>✗ <strong>Message content:</strong> We cannot read your encrypted DMs (NIP-04/44)</li>
        <li>✗ <strong>Key theft without GCP access:</strong> Database theft alone doesn't reveal keys</li>
    </ul>

    <h3>Threat Model</h3>

    <h4>Protected Against:</h4>
    <ul>
        <li>Database compromise alone (keys encrypted with GCP KMS)</li>
        <li>App compromises stealing keys (apps never see private keys)</li>
        <li>Relay surveillance of signing requests (encrypted with NIP-44)</li>
        <li>MITM attacks on OAuth flow (redirect URI validation, HTTPS)</li>
    </ul>

    <h4>NOT Protected Against:</h4>
    <ul>
        <li>Compromised GCP credentials + database access</li>
        <li>Malicious server operator (custodial by design)</li>
        <li>Government seizure of servers</li>
        <li>Compromised OAuth callback (app vulnerability)</li>
    </ul>

    <h3>When NOT to Use Keycast</h3>
    <div class="warning-box">
        <strong>Don't use Keycast if you need:</strong>
        <ul>
            <li>Complete key sovereignty (use Alby, nos2x, or hardware signers)</li>
            <li>Plausible deniability (we have logs of your activity)</li>
            <li>Protection from government seizure (use local signers)</li>
            <li>Air-gapped signing (use hardware wallets)</li>
            <li>Multi-signature schemes (use custom solutions)</li>
        </ul>
    </div>

    <h2 id="api">API Reference</h2>

    <h3>Authentication Endpoints</h3>

    <h4>POST /api/auth/register</h4>
    <p>Create a new user account and generate Nostr keys.</p>
    <pre><code>Request:
{
  "email": "user@example.com",
  "password": "secure-password"
}

Response:
{
  "token": "ucan-token",
  "pubkey": "npub1...",
  "bunker_url": "bunker://..."
}</code></pre>

    <h4>POST /api/auth/login</h4>
    <p>Authenticate existing user.</p>
    <pre><code>Request:
{
  "email": "user@example.com",
  "password": "secure-password"
}

Response:
{
  "token": "ucan-token"
}</code></pre>

    <h4>GET /api/user/bunker</h4>
    <p>Get personal bunker URL (requires Authorization: Bearer token).</p>
    <pre><code>Response:
{
  "bunker_url": "bunker://...?relay=wss://relay.damus.io&secret=xyz"
}</code></pre>

    <h3>OAuth 2.0 Endpoints</h3>

    <h4>GET /api/oauth/authorize</h4>
    <p>Start OAuth authorization flow.</p>
    <pre><code>Parameters:
  response_type: "code" (required)
  client_id: application identifier (required)
  redirect_uri: callback URL (required)
  scope: "sign_event" (optional)
  state: CSRF token (recommended)

Redirects to login/approval page, then:
  {redirect_uri}?code={authorization_code}&state={state}</code></pre>

    <h4>POST /api/oauth/token</h4>
    <p>Exchange authorization code for bunker URL.</p>
    <pre><code>Request:
{
  "grant_type": "authorization_code",
  "code": "auth-code-from-callback",
  "client_id": "my-app",
  "redirect_uri": "https://app.example.com/callback"
}

Response:
{
  "bunker_url": "bunker://...?relay=wss://relay.damus.io&secret=xyz",
  "pubkey": "user-npub"
}</code></pre>

    <h3>NIP-05 Discovery</h3>

    <h4>GET /.well-known/nostr.json?name=username</h4>
    <p>Resolve NIP-05 identifier to pubkey.</p>
    <pre><code>Response:
{
  "names": {
    "username": "user-pubkey-hex"
  }
}</code></pre>

    <h2>Performance Metrics</h2>
    <ul>
        <li><strong>OAuth authorization:</strong> ~500ms (includes DB write)</li>
        <li><strong>Sign event (cached key):</strong> ~100ms</li>
        <li><strong>Sign event (GCP decrypt):</strong> ~400ms</li>
        <li><strong>Reload check (5 auths):</strong> ~1.5s</li>
        <li><strong>Relay reconnection:</strong> ~1-2s</li>
    </ul>

    <h2>Source Code</h2>
    <p>
        Keycast is open source! Explore the implementation:
    </p>
    <ul>
        <li><strong>API Server:</strong> <code>api/src/main.rs</code>, <code>api/src/api/</code></li>
        <li><strong>Signer Daemon:</strong> <code>signer/src/signer_daemon.rs</code></li>
        <li><strong>Core Types:</strong> <code>core/src/types/</code></li>
        <li><strong>Encryption:</strong> <code>core/src/encryption/</code></li>
    </ul>

    <div class="footer">
        <p><a href="/">← Back to Keycast Home</a></p>
        <p>Questions? Issues? Check the code or reach out!</p>
    </div>
</body>
</html>
    "##)
}
