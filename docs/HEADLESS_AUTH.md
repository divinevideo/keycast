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
| 401 | INVALID_CREDENTIALS | Wrong email or password |
| 403 | EMAIL_NOT_VERIFIED | User needs to verify email first |
| 409 | CONFLICT | Email or Nostr key already registered |
| 503 | SERVICE_UNAVAILABLE | Server at capacity, retry later |

## Policies

Available scopes:
- `policy:social` - Post notes, reactions, follows
- `policy:readonly` - Read-only access
- `policy:full` - Full access to all operations

Get available policies: `GET /api/policies`
