# Silent Re-Authentication Implementation

This document outlines implementing standard OAuth 2.0 refresh tokens for seamless re-authentication.

## Problem

- JWT access tokens expire after 24 hours
- Current re-auth requires OAuth redirect (page navigation)
- Users experience interruption when token expires

## Background: authorization_handle vs refresh_token

Keycast already has `authorization_handle` which serves a **different purpose**:

| Feature | `authorization_handle` | `refresh_token` (OAuth standard) |
|---------|----------------------|--------------------------------|
| Purpose | Skip consent screen during OAuth redirect | Get new access token directly via API |
| Flow | Still requires redirect to `/authorize` | Single POST to `/token` endpoint |
| UX | User sees brief redirect | Completely invisible to user |
| Standard | Keycast-specific | RFC 6749, RFC 9700 |

**We need both:**
- `authorization_handle` - for re-authorization when refresh token expires (skip consent)
- `refresh_token` - for silent background token refresh (no redirect)

## Solution: Standard OAuth Refresh Tokens

Add `grant_type=refresh_token` support to the existing `/api/oauth/token` endpoint per [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-6).

### OAuth Token Endpoint Format (RFC 6749 §6)

```
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=xyz123...&client_id=divine-web

Response (200 OK):
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "new_refresh_xyz...",  // Rotated per RFC 9700
  "authorization_handle": "abc..."        // Still included for consent-skip
}

Response (400 Bad Request):
{
  "error": "invalid_grant",
  "error_description": "Refresh token is invalid, expired, or revoked"
}
```

### Design Decisions

1. **Refresh token rotation** (per [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/) best practices) - issue new refresh token on each use, invalidate old one
2. **One-time use** - each refresh token can only be used once (AIP pattern)
3. **Separate storage** - refresh tokens stored in dedicated table, not reusing authorization_handle
4. **Same endpoint** - use existing `/api/oauth/token` with `grant_type=refresh_token`

---

## Implementation

### 1. Database Migration

**File:** `database/migrations/XXXX_add_refresh_tokens.sql`

```sql
-- Refresh tokens for OAuth token refresh (separate from authorization_handle)
CREATE TABLE oauth_refresh_tokens (
    id SERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 hash of token
    authorization_id INTEGER NOT NULL REFERENCES oauth_authorizations(id) ON DELETE CASCADE,
    user_pubkey VARCHAR(64) NOT NULL,
    tenant_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,  -- e.g., 30 days from creation
    consumed_at TIMESTAMPTZ,  -- NULL = valid, set = used (one-time use)

    -- Index for token lookup
    INDEX idx_refresh_token_hash (token_hash),
    INDEX idx_refresh_auth_id (authorization_id)
);
```

### 2. Refresh Token Type

**File:** `core/src/types/refresh_token.rs`

```rust
use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct RefreshToken {
    pub id: i32,
    pub token_hash: String,
    pub authorization_id: i32,
    pub user_pubkey: String,
    pub tenant_id: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Generate a cryptographically random refresh token (256 bits)
pub fn generate_refresh_token() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Hash refresh token for storage (never store plaintext)
pub fn hash_refresh_token(token: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
```

### 3. Refresh Token Repository

**File:** `core/src/repositories/refresh_token.rs`

```rust
use crate::types::refresh_token::{RefreshToken, hash_refresh_token};
use sqlx::PgPool;

pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new refresh token
    pub async fn create(
        &self,
        token: &str,  // Plaintext token (will be hashed)
        authorization_id: i32,
        user_pubkey: &str,
        tenant_id: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<RefreshToken, sqlx::Error> {
        let token_hash = hash_refresh_token(token);

        sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth_refresh_tokens
             (token_hash, authorization_id, user_pubkey, tenant_id, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *"
        )
        .bind(&token_hash)
        .bind(authorization_id)
        .bind(user_pubkey)
        .bind(tenant_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
    }

    /// Consume a refresh token (atomic: find + mark as consumed)
    /// Returns None if token invalid, expired, or already consumed
    pub async fn consume(&self, token: &str) -> Result<Option<RefreshToken>, sqlx::Error> {
        let token_hash = hash_refresh_token(token);

        // Atomic operation: find valid token AND mark as consumed
        let result = sqlx::query_as::<_, RefreshToken>(
            "UPDATE oauth_refresh_tokens
             SET consumed_at = NOW()
             WHERE token_hash = $1
               AND consumed_at IS NULL
               AND expires_at > NOW()
             RETURNING *"
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Revoke all refresh tokens for an authorization
    pub async fn revoke_for_authorization(
        &self,
        authorization_id: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE oauth_refresh_tokens
             SET consumed_at = NOW()
             WHERE authorization_id = $1 AND consumed_at IS NULL"
        )
        .bind(authorization_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
```

### 4. Update Token Endpoint

**File:** `api/src/api/http/oauth.rs`

Add refresh token support to existing `handle_token_request`:

```rust
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,  // "authorization_code" or "refresh_token"
    pub code: Option<String>,        // For authorization_code grant
    pub client_id: String,
    pub redirect_uri: Option<String>, // Required for authorization_code
    pub code_verifier: Option<String>, // PKCE for authorization_code
    pub refresh_token: Option<String>, // For refresh_token grant
}

pub async fn handle_token_request(
    State(state): State<AuthState>,
    Form(req): Form<TokenRequest>,
) -> Result<impl IntoResponse, OAuthError> {
    let grant_type = req.grant_type.as_deref().unwrap_or("authorization_code");

    match grant_type {
        "authorization_code" => handle_authorization_code_grant(state, req).await,
        "refresh_token" => handle_refresh_token_grant(state, req).await,
        _ => Err(OAuthError::InvalidRequest(format!(
            "Unsupported grant_type '{}'. Supported: authorization_code, refresh_token",
            grant_type
        ))),
    }
}

async fn handle_refresh_token_grant(
    state: AuthState,
    req: TokenRequest,
) -> Result<impl IntoResponse, OAuthError> {
    let pool = &state.pool;
    let tenant_id = state.tenant_id;

    // 1. Validate request
    let refresh_token = req.refresh_token.ok_or_else(|| {
        OAuthError::InvalidRequest("Missing refresh_token parameter".into())
    })?;

    // 2. Consume refresh token (atomic: validates + marks as used)
    let refresh_repo = RefreshTokenRepository::new(pool.clone());
    let token_record = refresh_repo
        .consume(&refresh_token, tenant_id)
        .await
        .map_err(|e| OAuthError::Database(e))?
        .ok_or_else(|| {
            tracing::warn!("Refresh token invalid or already consumed");
            OAuthError::InvalidGrant("Invalid or expired refresh token".into())
        })?;

    // 3. Get the authorization (for user info and tenant)
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let auth = OAuthAuthorization::find(pool, token_record.tenant_id, token_record.authorization_id)
        .await
        .map_err(|_| OAuthError::InvalidGrant("Authorization not found".into()))?;

    // 4. Check authorization is still valid
    if auth.revoked_at.is_some() {
        return Err(OAuthError::InvalidGrant("Authorization has been revoked".into()));
    }

    // 5. Get user's signing keys
    let personal_keys_repo = PersonalKeyRepository::new(pool.clone());
    let personal_key = personal_keys_repo
        .find_by_pubkey(&auth.user_pubkey)
        .await
        .map_err(|_| OAuthError::InvalidGrant("User keys not found".into()))?;

    let user_keys = personal_key
        .to_keys(&state.encryption_key)
        .map_err(|e| OAuthError::Encryption(format!("Failed to decrypt keys: {}", e)))?;

    // 6. Generate new access token (UCAN JWT)
    let access_token = generate_ucan_token(
        &user_keys,
        auth.tenant_id,
        &personal_key.email.unwrap_or_default(),
        &auth.redirect_origin,
    )
    .await?;

    // 7. Generate new refresh token (rotation per RFC 9700)
    let new_refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(30);

    refresh_repo
        .create(
            &new_refresh_token,
            auth.id,
            &auth.user_pubkey,
            auth.tenant_id,
            refresh_expires_at,
        )
        .await
        .map_err(|e| OAuthError::Database(e))?;

    tracing::info!(
        "Token refreshed for user {} (auth_id={})",
        auth.user_pubkey,
        auth.id
    );

    // 8. Return new tokens
    Ok(Json(TokenResponse {
        access_token: Some(access_token),
        token_type: "Bearer".to_string(),
        expires_in: TOKEN_EXPIRY_HOURS * 3600,
        scope: None,
        policy: None,
        refresh_token: Some(new_refresh_token),
        authorization_handle: auth.authorization_handle,  // Still include for consent-skip
    }))
}
```

### 5. Update Token Response

**File:** `api/src/api/http/oauth.rs`

Add `refresh_token` to the response:

```rust
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<TokenPolicyInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,  // NEW: for silent refresh
}
```

### 6. Issue Refresh Token on Initial Login

In the authorization_code grant handler, issue a refresh token:

```rust
// After generating access_token, also generate refresh_token
let refresh_token = generate_refresh_token();
let refresh_expires_at = Utc::now() + Duration::days(30);

let refresh_repo = RefreshTokenRepository::new(pool.clone());
refresh_repo
    .create(
        &refresh_token,
        auth.id,
        &auth.user_pubkey,
        auth.tenant_id,
        refresh_expires_at,
    )
    .await?;

// Include in response
Ok(Json(TokenResponse {
    access_token: Some(access_token),
    // ...
    refresh_token: Some(refresh_token),
    authorization_handle: Some(authorization_handle),
}))
```

---

## Client Implementation (divine-web)

### 1. Store Refresh Token

**File:** `src/hooks/useKeycastSession.ts`

```typescript
const REFRESH_TOKEN_KEY = 'keycast_refresh_token';

// In saveSession, also save refresh_token
const saveSession = useCallback((
  token: string,
  email: string,
  pubkey: string,
  rememberMe: boolean,
  refreshToken?: string,
  authorizationHandle?: string,
) => {
  // ... existing logic ...
  if (refreshToken) {
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
  if (authorizationHandle) {
    setAuthHandle(authorizationHandle);
  }
}, []);

const getRefreshToken = useCallback(() => {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}, []);
```

### 2. Update Refresh Function

**File:** `src/lib/keycast.ts`

Use standard OAuth token endpoint with `grant_type=refresh_token`:

```typescript
export async function refreshToken(refreshToken: string): Promise<TokenExchangeResponse> {
  const response = await fetch(`${KEYCAST_API_URL}/api/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: OAUTH_CLIENT_ID,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error_description || 'Token refresh failed');
  }

  const data = await response.json();

  // Get pubkey from API
  const pubkey = await getUserPubkey(data.access_token);

  return {
    token: data.access_token,
    pubkey,
    refreshToken: data.refresh_token,           // Rotated
    authorizationHandle: data.authorization_handle,
  };
}
```

### 3. Update Session Monitor

**File:** `src/components/KeycastSessionMonitor.tsx`

Use refresh token instead of authorization handle:

```typescript
async function attemptBackgroundRefresh() {
  const refreshToken = getRefreshToken();
  if (!refreshToken || isRefreshing.current) return;

  isRefreshing.current = true;

  try {
    console.log('[KeycastSessionMonitor] Refreshing token in background...');
    const result = await refreshToken(refreshToken);

    // Save new tokens (including rotated refresh token)
    saveSession(
      result.token,
      email,
      result.pubkey,
      true,
      result.refreshToken,          // Save rotated refresh token
      result.authorizationHandle,
    );

    console.log('[KeycastSessionMonitor] Token refreshed successfully');
  } catch (error) {
    console.error('[KeycastSessionMonitor] Background refresh failed:', error);
    // Refresh token expired/invalid - fall back to OAuth redirect
    // Use authorization_handle to skip consent screen
    showReloginToast();
  } finally {
    isRefreshing.current = false;
  }
}
```

---

## Token Lifecycle

```
Initial Login (OAuth code flow):
  User → Consent Screen → Authorization Code → Token Exchange
  ↓
  Returns: access_token (24h) + refresh_token (30d) + authorization_handle (30d)

Silent Refresh (background, invisible):
  Client detects access_token expiring → POST /token with refresh_token
  ↓
  Returns: new access_token + new refresh_token (rotated)

Re-authorization (when refresh_token expires):
  Client redirects to /authorize with authorization_handle
  ↓
  Auto-approves (no consent screen) → new tokens
```

## Security Considerations

1. **Refresh token rotation** (RFC 9700) - new token issued on each use, old invalidated
2. **One-time use** - each refresh token can only be used once
3. **Hashed storage** - refresh tokens stored as SHA256 hashes
4. **30-day expiration** - hard limit on refresh token lifetime
5. **Authorization revocation** - revoking auth also invalidates all refresh tokens
6. **Separate from auth_handle** - refresh tokens and authorization handles serve different purposes

## Testing

```bash
# Initial token exchange (returns refresh_token)
curl -X POST http://localhost:3000/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=xxx&client_id=divine-web&redirect_uri=...&code_verifier=..."

# Refresh token (returns new access_token + new refresh_token)
curl -X POST http://localhost:3000/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=xyz123&client_id=divine-web"

# Using old refresh token again should fail (one-time use)
curl -X POST http://localhost:3000/api/oauth/token \
  -d "grant_type=refresh_token&refresh_token=xyz123&client_id=divine-web"
# → {"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}
```

## References

- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) - Core specification
- [RFC 6749 §6 - Refreshing an Access Token](https://datatracker.ietf.org/doc/html/rfc6749#section-6)
- [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/rfc9700/) - Recommends refresh token rotation
- [AIP Implementation](https://github.com/graze-social/aip) - Reference implementation with rotation
