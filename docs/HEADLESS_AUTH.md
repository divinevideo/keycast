# Headless Authentication API

Pure JSON API for native mobile apps (Flutter, React Native, etc.) that want to handle their own UI.

## Endpoints

### POST /api/headless/register

Register a new user. Returns `device_code` for email verification polling.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "client_id": "My Flutter App",
  "redirect_uri": "https://myapp.example.com/callback",
  "scope": "policy:social",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "state": "random-csrf-token",
  "nsec": "nsec1..."  // Optional: import existing Nostr key
}
```

**Response:**
```json
{
  "success": true,
  "pubkey": "abc123...",
  "verification_required": true,
  "device_code": "secret-polling-token",
  "email": "user@example.com"
}
```

### POST /api/headless/login

Login existing user. Returns authorization code directly.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "client_id": "My Flutter App",
  "redirect_uri": "https://myapp.example.com/callback",
  "scope": "policy:social",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "state": "random-csrf-token"
}
```

**Response:**
```json
{
  "success": true,
  "code": "authorization-code-here",
  "pubkey": "abc123...",
  "state": "random-csrf-token"
}
```

### POST /api/headless/social-login

"Continue with Google" (iOS, Android) and "Continue with Apple" (iOS). The app gets an ID token
from Google or Apple natively and hands it to Keycast. Keycast verifies it and returns an
authorization code, exactly like `POST /api/headless/login`. The provider is only another way into
the same custodial account: the account's email, Nostr key and permissions do not change.

**Request:**
```json
{
  "provider": "google",
  "id_token": "<ID token from Google or Apple>",
  "raw_nonce": "<nonce the app generated>",
  "authorization_code": "<Apple only, optional>",
  "client_id": "Divine Video",
  "redirect_uri": "https://login.divine.video/app/callback",
  "scope": "policy:full",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "state": "random-csrf-token",
  "app_version": "1.2.3"
}
```

**Response:**
```json
{
  "success": true,
  "code": "authorization-code-here",
  "pubkey": "abc123...",
  "state": "random-csrf-token",
  "created": false
}
```

`created` is `true` only when this request created the account.

How the token is checked:
- RS256 signature by a current Google or Apple signing key (fetched from the provider's JWKS,
  cached for an hour, refetched at most once a minute for an unknown key id, and kept when a
  refresh fails).
- `iss` is Google's or Apple's issuer. `aud` is a configured client: for Google the server (web)
  client ID, with `azp` one of the configured iOS/Android client IDs; for Apple a bundle ID.
- `exp`, `iat` and `nonce` are present, and `nonce` is the lowercase hex SHA-256 of `raw_nonce`.
- Each token is accepted once: a SHA-256 of the token is reserved in Redis until it expires.
  Without Redis the endpoint fails closed with `503 SERVICE_UNAVAILABLE`.

How the account is found:
1. The provider account (`sub`) is already linked: sign in to that account.
2. Otherwise the provider must report a verified email (`400 EMAIL_MISSING`,
   `403 EMAIL_NOT_VERIFIED`).
3. No Keycast account uses that email (compared ignoring case): create one with a fresh Nostr key,
   the verified email and no password.
4. Exactly one account uses it, that account verified its email, and the provider is
   authoritative for the address: link and sign in, and email the account owner that the sign-in
   method was added. Google is authoritative for `@gmail.com` / `@googlemail.com` addresses and
   for Google Workspace accounts (`hd` claim); Apple for every address it reports as verified.
5. Anything else (unverified Keycast email, a Google address on another domain, several accounts
   that differ only in letter case) answers `409 ACCOUNT_LINK_REQUIRED`: the person signs in with
   their password instead.

An account created this way has no password. Password-protected operations (export key, change
password, email or key) answer `409 PASSWORD_NOT_SET` until the person sets one through
"Forgot password".

When Apple sends `authorization_code` and the Apple signing key is configured, Keycast exchanges it
for a refresh token and stores it encrypted, so the grant can be revoked when the account is
deleted. Failures there never fail the sign-in.

#### On the hosted login page

Web clients (divine-web and other apps that redirect to `GET /api/oauth/authorize`) get the same
buttons on Keycast's login page, above the email form: "Continue with Apple" through Sign in with
Apple JS and a Services ID, and "Continue with Google" through Google Identity Services and the
web client ID. A button only appears when its provider is configured for the web.

The page posts the provider's ID token to `POST /api/oauth/social-login`
(`{"provider", "id_token", "authorization_code"?, "client_id", "redirect_uri"}`). The account is
found exactly as above, with the same errors. On success the endpoint sets the session cookie,
exactly like `POST /api/oauth/login`, and the page reloads the authorize URL, which shows the
consent screen and sends the code to the client's `redirect_uri` with its `state`. Nothing changes
for the client.

The nonce is generated by the server: the login page stores the raw nonce in the HttpOnly
`keycast_social_nonce` cookie (path `/api/oauth`, one hour) and hands only its SHA-256 to Google and
Apple. Tokens the apps obtain are not accepted there, and login-page tokens are not accepted by
`POST /api/headless/social-login`: Google's `azp` and Apple's `aud` tell them apart.

### POST /api/headless/authorize

Create authorization for already-authenticated user (requires Bearer token).

**Headers:**
```
Authorization: Bearer <ucan-token>
```

**Request:**
```json
{
  "client_id": "Another App",
  "redirect_uri": "https://another-app.example.com/callback",
  "scope": "policy:readonly",
  "code_challenge": "...",
  "code_challenge_method": "S256",
  "state": "..."
}
```

**Response:**
```json
{
  "success": true,
  "code": "authorization-code-here",
  "state": "..."
}
```

## Complete Flows

### New User Registration

```
┌─────────────┐                              ┌─────────────┐
│ Flutter App │                              │   Keycast   │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │ POST /api/headless/register                │
       │ {email, password, client_id, ...}          │
       │───────────────────────────────────────────>│
       │                                            │
       │ {device_code, pubkey, verification_required}
       │<───────────────────────────────────────────│
       │                                            │
       │         (User clicks email link)           │
       │                                            │
       │ GET /api/oauth/poll?device_code=xxx        │
       │───────────────────────────────────────────>│
       │                                            │
       │ HTTP 202 {status: "pending"}               │
       │<───────────────────────────────────────────│
       │                                            │
       │ GET /api/oauth/poll?device_code=xxx        │
       │───────────────────────────────────────────>│
       │                                            │
       │ HTTP 200 {code: "auth-code"}               │
       │<───────────────────────────────────────────│
       │                                            │
       │ POST /api/oauth/token                      │
       │ {code, code_verifier, client_id, ...}      │
       │───────────────────────────────────────────>│
       │                                            │
       │ {bunker_url, access_token}                 │
       │<───────────────────────────────────────────│
       │                                            │
```

### Existing User Login

```
┌─────────────┐                              ┌─────────────┐
│ Flutter App │                              │   Keycast   │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │ POST /api/headless/login                   │
       │ {email, password, client_id, ...}          │
       │───────────────────────────────────────────>│
       │                                            │
       │ {code, pubkey}                             │
       │<───────────────────────────────────────────│
       │                                            │
       │ POST /api/oauth/token                      │
       │ {code, code_verifier, client_id, ...}      │
       │───────────────────────────────────────────>│
       │                                            │
       │ {bunker_url, access_token}                 │
       │<───────────────────────────────────────────│
       │                                            │
```

## Flutter Example

```dart
import 'package:http/http.dart' as http;
import 'dart:convert';

class KeycastAuth {
  final String baseUrl;
  final String clientId;
  final String redirectUri;
  
  KeycastAuth({
    required this.baseUrl,
    required this.clientId,
    required this.redirectUri,
  });
  
  // Generate PKCE challenge
  String _generateCodeVerifier() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64UrlEncode(bytes).replaceAll('=', '');
  }
  
  String _generateCodeChallenge(String verifier) {
    final bytes = utf8.encode(verifier);
    final digest = sha256.convert(bytes);
    return base64UrlEncode(digest.bytes).replaceAll('=', '');
  }
  
  // Register new user
  Future<RegisterResult> register(String email, String password) async {
    final codeVerifier = _generateCodeVerifier();
    final codeChallenge = _generateCodeChallenge(codeVerifier);
    
    final response = await http.post(
      Uri.parse('$baseUrl/api/headless/register'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'email': email,
        'password': password,
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': 'policy:social',
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
      }),
    );
    
    final data = jsonDecode(response.body);
    return RegisterResult(
      deviceCode: data['device_code'],
      pubkey: data['pubkey'],
      codeVerifier: codeVerifier,
    );
  }
  
  // Poll for email verification
  Future<String?> pollForCode(String deviceCode) async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/oauth/poll?device_code=$deviceCode'),
    );
    
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      return data['code'];
    }
    return null; // Still pending
  }
  
  // Login existing user
  Future<LoginResult> login(String email, String password) async {
    final codeVerifier = _generateCodeVerifier();
    final codeChallenge = _generateCodeChallenge(codeVerifier);
    
    final response = await http.post(
      Uri.parse('$baseUrl/api/headless/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'email': email,
        'password': password,
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': 'policy:social',
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
      }),
    );
    
    final data = jsonDecode(response.body);
    return LoginResult(
      code: data['code'],
      pubkey: data['pubkey'],
      codeVerifier: codeVerifier,
    );
  }
  
  // Exchange code for bunker URL
  Future<TokenResult> exchangeCode(String code, String codeVerifier) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/oauth/token'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'code_verifier': codeVerifier,
      }),
    );
    
    final data = jsonDecode(response.body);
    return TokenResult(
      bunkerUrl: data['bunker_url'],
      accessToken: data['access_token'],
    );
  }
}
```

## Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | INVALID_REQUEST | Missing or invalid parameters |
| 400 | EMAIL_MISSING | Social login: the provider shared no usable email |
| 401 | INVALID_CREDENTIALS | Wrong email or password |
| 401 | INVALID_TOKEN | Social login: the ID token failed verification or was already used |
| 403 | EMAIL_NOT_VERIFIED | User needs to verify email first (social login: the provider did not verify it) |
| 409 | CONFLICT | Email or Nostr key already registered |
| 409 | ACCOUNT_LINK_REQUIRED | Social login: an account with this email exists and must be signed in with its password |
| 409 | PASSWORD_NOT_SET | The account signs in through Google or Apple only; set a password via "Forgot password" first |
| 429 | TOO_MANY_ATTEMPTS | Too many attempts; retry after `Retry-After` seconds |
| 503 | PROVIDER_UNAVAILABLE | Social login: the provider is not configured or its keys cannot be fetched |
| 503 | SERVICE_UNAVAILABLE | Server at capacity, retry later |

## Policies

Available scopes:
- `policy:social` - Post notes, reactions, follows
- `policy:readonly` - Read-only access
- `policy:full` - Full access to all operations

Get available policies: `GET /api/policies`
