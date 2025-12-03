# Authorization Handle: Silent Re-Authentication for Public OAuth Clients

## Problem Statement

Keycast's OAuth implementation has two issues with re-authentication flows:

### 1. Auto-Approve Ignores Revocation Status (Bug)

Current auto-approve query:
```sql
SELECT id FROM oauth_authorizations
WHERE tenant_id = $1 AND user_pubkey = $2 AND redirect_origin = $3
```

**Missing**: `AND revoked_at IS NULL`

This means:
1. User authorizes app → creates authorization
2. User revokes in settings UI → sets `revoked_at`
3. App initiates new OAuth flow
4. **BUG**: Query finds the revoked row → auto-approves anyway
5. User never sees consent screen despite having revoked access

### 2. Unbounded Authorization Growth

With multi-device support, each "Approve" creates a NEW authorization:

```
Login 1 → creates auth #1
Login 2 → creates auth #2
Login 3 → creates auth #3
...
```

The `oauth_authorizations` table grows indefinitely. There's no mechanism to clean up old authorizations from the same device/app instance.

---

## Proposed Solution: Authorization Handle

An `authorization_handle` is a **server-issued bearer token** that:
1. Identifies the specific authorization grant a client holds
2. Enables silent re-authorization (skip consent screen)
3. Allows cleanup of the old authorization when creating a new one
4. Provides precise validation (only auto-approve if that specific grant is still active)

### Standards Positioning

> No OAuth/OIDC standard provides this pattern for public clients. OAuth Grant Management defines the right abstraction (`grant_id`) but explicitly restricts it to confidential clients. The `authorization_handle` extends this pattern to public clients by treating the handle itself as a bearer credential that proves the grant relationship.

| Standard | What It Does | Why It Doesn't Fit |
|----------|--------------|-------------------|
| **Grant Management (`grant_id`)** | Server-issued handle identifying a grant | Excludes public clients (requires client auth) |
| **OIDC Native SSO (`device_secret`)** | Device-bound secret for cross-app SSO | For cross-app SSO, not single-app continuation |
| **DPoP (RFC 9449)** | Cryptographic proof-of-possession | Overkill for our use case |
| **Refresh Tokens** | Get new access tokens | Doesn't address consent UI or grant identification |
| **`prompt=none` (OIDC)** | Skip consent if session exists | Relies on browser cookies, not app instance |

---

## Credential Model

Clients store three credentials, each with different purposes and exposure profiles:

| Credential | Purpose | Channel | Lifecycle |
|------------|---------|---------|-----------|
| `bunker_url` | NIP-46 signing requests | Relay traffic | Rotates on re-auth |
| `access_token` (UCAN) | REST API authentication | Every HTTP request | Expires (24h) |
| `authorization_handle` | OAuth re-authentication | Re-auth flow only (HTTPS) | Same as authorization `expires_at`, rotates on re-auth |

**Why separate credentials?**

- **Minimum exposure**: Each credential is only sent where needed
- **Blast radius**: Compromising one doesn't automatically compromise others
- **Defense in depth**: `authorization_handle` has lowest exposure (only during OAuth flow)

### Why Not Reuse Existing Credentials?

| Credential | Why Not Use as Handle |
|------------|-----------------------|
| `bunker_url` / `secret` | High exposure (relay traffic); compromising it AND handle doubles blast radius |
| `access_token` (UCAN) | Expires in 24h; sent with every API call (high exposure); decodable JWT reveals user info |

---

## How It Works

### Authorization Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                   Authorization Lifecycle                    │
├─────────────────────────────────────────────────────────────┤
│  created_at                                    expires_at   │
│      │                                              │       │
│      ▼                                              ▼       │
│      ├──────────── VALID WINDOW ────────────────────┤       │
│      │                                              │       │
│      │  bunker_url works: ✅                        │       │
│      │  authorization_handle works: ✅              │       │
│      │  Can silently re-auth (rotate) anytime       │       │
│      │                                              │       │
│      └──────────────────────────────────────────────┘       │
│                                                     │       │
│                                          AFTER EXPIRY:      │
│                                          bunker_url: ❌     │
│                                          handle: ❌         │
│                                          Must re-consent    │
└─────────────────────────────────────────────────────────────┘
```

The `authorization_handle` is valid for the same duration as the authorization itself. This provides a security benefit for a signing service: users must periodically re-consent, ensuring they're reminded what apps have access to their keys.

### First Authorization (No handle)

1. Client initiates OAuth without `authorization_handle`
2. Server shows consent screen
3. User approves
4. Token exchange creates `oauth_authorization` with generated handle
5. Token response includes all three credentials
6. Client stores credentials in secure storage (Keychain/Keystore)

### Re-Authorization (With handle)

1. Client initiates OAuth with stored `authorization_handle`
2. Server validates: "Is this handle's authorization still active and not expired?"
   - **If valid** → Auto-approve, track old auth ID for cleanup
   - **If revoked/expired/invalid/missing** → Show consent screen
3. Token exchange:
   - Revoke old authorization
   - Create new authorization with NEW handle (fresh `expires_at`)
   - Return new credentials (all three rotate)
4. Client replaces stored credentials with new ones

### Flow Summary

| Scenario | authorization_handle | Action |
|----------|---------------------|--------|
| First login | None | Consent → create auth → return handle |
| Re-login (valid) | Valid, active, not expired | Auto-approve → revoke old → create new → return new handle |
| Re-login (revoked) | Exists but revoked | Consent → create new → return handle |
| Re-login (expired) | Authorization expired | Consent → create new → return handle |
| Re-login (invalid) | No match | Consent → create new → return handle |
| App reinstall | None (lost) | Consent → create new → return handle |

---

## Security Model

### Threat Model

> The `authorization_handle` is a bearer secret: if exfiltrated, an attacker could silently re-authorize as that app instance. Mitigations:

| Mitigation | Effect |
|------------|--------|
| **Secure storage required** | Keychain/Keystore raises exfiltration bar |
| **Rotation on each re-auth** | Leaked handle becomes invalid after one use |
| **Binding to redirect_origin** | Attacker needs handle AND domain control |
| **Authorization expiry** | Handle invalid after authorization expires (periodic re-consent) |
| **Low exposure** | Only sent during OAuth flow over HTTPS |

### Credential Comparison

| If Compromised... | Attacker Can | Mitigation |
|-------------------|--------------|------------|
| `bunker_url` | Sign events until rotation | Rotates on re-auth |
| `access_token` (UCAN) | Call REST API until expiry | Expires in 24h |
| `authorization_handle` | Trigger re-auth (gets new creds, invalidates victim's) | Rotation limits to one window; expires with authorization |

---

## Schema Changes

```sql
-- Add authorization_handle to oauth_authorizations (reuses existing expires_at)
ALTER TABLE oauth_authorizations
ADD COLUMN authorization_handle CHAR(64);

-- Partial unique index for fast lookups of active handles
CREATE UNIQUE INDEX idx_oauth_auth_handle
ON oauth_authorizations(authorization_handle)
WHERE authorization_handle IS NOT NULL AND revoked_at IS NULL;

-- Add previous_auth_id to oauth_codes (pass through the flow)
ALTER TABLE oauth_codes
ADD COLUMN previous_auth_id INTEGER;
```

---

## API Changes

### Authorization Request

```
GET /api/oauth/authorize
  ?client_id=my-app
  &redirect_uri=https://app.example.com/callback
  &code_challenge=...
  &code_challenge_method=S256
  &authorization_handle=abc123...  # Optional, for re-auth
```

### Token Response

```json
{
  "bunker_url": "bunker://pubkey?relay=...&secret=...",
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "policy:social",
  "authorization_handle": "def456..."
}
```

---

## Implementation

### Authorization Endpoint (auto-approve check)

```rust
let previous_auth_id: Option<i32> = if let Some(ref handle) = params.authorization_handle {
    // Look up by handle (must be active and not expired)
    // Reuses existing expires_at column
    sqlx::query_scalar(
        "SELECT id FROM oauth_authorizations
         WHERE authorization_handle = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())"
    )
    .bind(handle)
    .fetch_optional(pool)
    .await?
} else {
    None
};

if previous_auth_id.is_some() && !force_consent {
    // Auto-approve: generate code with previous_auth_id for cleanup
    store_oauth_code_with_previous_auth(..., previous_auth_id).await?;
    return Ok(Redirect::to(...));
}
// Otherwise: show consent screen
```

### Token Exchange (rotation + cleanup)

```rust
// 1. Generate new authorization_handle
let authorization_handle = generate_secure_random_hex(32); // 256-bit

// 2. Calculate authorization expiry (e.g., 90 days)
let expires_at = Utc::now() + Duration::days(90);

// 3. Create new authorization with handle
sqlx::query(
    "INSERT INTO oauth_authorizations (..., authorization_handle, expires_at)
     VALUES (..., $1, $2)"
)
.bind(&authorization_handle)
.bind(expires_at)
.execute(pool)
.await?;

// 4. Revoke old authorization if this was a re-auth
if let Some(old_auth_id) = oauth_code.previous_auth_id {
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1")
        .bind(old_auth_id)
        .execute(pool)
        .await?;
}

// 5. Return all credentials
TokenResponse {
    bunker_url,
    access_token: Some(ucan),
    authorization_handle: Some(authorization_handle),
    // ...
}
```

---

## Client Implementation (Flutter Example)

```dart
class KeycastCredentials {
  final String bunkerUrl;
  final String? accessToken;
  final String? authorizationHandle;
}

// Store all credentials after token exchange
Future<void> storeCredentials(KeycastCredentials creds) async {
  await secureStorage.write(key: 'bunker_url', value: creds.bunkerUrl);
  if (creds.accessToken != null) {
    await secureStorage.write(key: 'access_token', value: creds.accessToken);
  }
  if (creds.authorizationHandle != null) {
    await secureStorage.write(key: 'authorization_handle', value: creds.authorizationHandle);
  }
}

// Build authorization URL with handle for re-auth
Future<String> getAuthorizationUrl() async {
  final handle = await secureStorage.read(key: 'authorization_handle');

  final params = {
    'client_id': config.clientId,
    'redirect_uri': config.redirectUri,
    'code_challenge': generateChallenge(verifier),
    'code_challenge_method': 'S256',
    if (handle != null) 'authorization_handle': handle,
  };

  return Uri.parse('${config.serverUrl}/api/oauth/authorize')
      .replace(queryParameters: params)
      .toString();
}
```

---

## Migration Notes

- Existing authorizations will have `authorization_handle = NULL`
- Clients without handle support always see consent screen (backwards compatible)
- No breaking changes to existing OAuth flows
- Gradual adoption as clients update

---

## Summary

The `authorization_handle` transforms the auto-approve question from:

> "Has this user ever approved this origin?" (current, broken)

to:

> "Does this client hold a valid credential from a prior authorization?" (correct)

This fixes the revocation bug, enables cleanup of old authorizations, and provides defense-in-depth through credential separation. Handle validity is tied to authorization expiry, ensuring periodic re-consent for this sensitive signing service.
