# Keycast

OAuth 2.0 remote signing for Nostr. Users authenticate once, apps get signing access via REST API or NIP-46.

## What is Keycast?

Keycast is a managed key custody service for Nostr apps. Users create an account (or import their nsec), and apps request signing permission via OAuth. Keys are encrypted server-side; signing happens via HTTP RPC or NIP-46 bunker URL.

**For mobile apps**: No browser extensions, no relay infrastructure to manage. One OAuth flow, then sign events via HTTPS or connect with the returned bunker URL.

**For users**: One identity across all apps. Revoke access per-app anytime. Import existing keys or let Keycast generate one.

## Client Libraries

| Platform | Package | Docs |
|----------|---------|------|
| Flutter/Dart | keycast_flutter | [Demo + Guide](https://github.com/divinevideo/keycast_flutter_demo) |
| JS/TS | keycast-login | [README](./keycast-login) |

## Quick Start

### Flutter/Dart

```dart
import 'package:keycast_flutter/keycast_flutter.dart';

final oauth = KeycastOAuth(
  config: OAuthConfig(
    serverUrl: 'https://login.divine.video',
    clientId: 'your-app',
    redirectUri: 'https://login.divine.video/app/callback',
  ),
  storage: SecureKeycastStorage(), // Auto-saves credentials
);

// 1. Start OAuth flow (auto-includes authorization_handle for silent re-auth)
final (url, verifier) = await oauth.getAuthorizationUrl(scope: 'policy:social');
await launchUrl(Uri.parse(url));

// 2. Handle Universal Link callback, exchange code (auto-saves session)
final tokens = await oauth.exchangeCode(code: code, verifier: verifier);

// 3. Sign events via HTTP RPC
final session = await oauth.getSession(); // Load from storage
final rpc = KeycastRpc.fromSession(oauth.config, session!);
final signed = await rpc.signEvent(myEvent);
```

Requires Universal Links (iOS) / App Links (Android). See [keycast_flutter_demo](https://github.com/divinevideo/keycast_flutter_demo) for complete setup including deep link configuration.

### JavaScript/TypeScript

```typescript
import { createKeycastClient } from 'keycast-login';

const client = createKeycastClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'your-app',
  redirectUri: window.location.origin + '/callback',
  storage: localStorage, // Auto-saves credentials (optional, defaults to in-memory)
});

// 1. Start OAuth flow (auto-includes authorization_handle for silent re-auth)
const { url, pkce } = await client.oauth.getAuthorizationUrl({
  scopes: ['policy:social'],
});
sessionStorage.setItem('pkce_verifier', pkce.verifier);
window.location.href = url;

// 2. Handle callback (auto-saves session to storage)
const code = new URLSearchParams(location.search).get('code');
const verifier = sessionStorage.getItem('pkce_verifier');
const tokens = await client.oauth.exchangeCode(code, verifier);

// 3. Sign events via HTTP RPC
const rpc = client.createRpc(tokens);
const signed = await rpc.signEvent({
  kind: 1,
  content: 'Hello Nostr!',
  tags: [],
  created_at: Math.floor(Date.now() / 1000),
  pubkey: await rpc.getPublicKey(),
});

// On page reload, restore session from storage
const session = client.oauth.getSession();
if (session) {
  // User is already authenticated
}
```

See [keycast-login README](./keycast-login/README.md) for full API reference including BYOK (Bring Your Own Key) flows.

### HTTP API

For other languages, use the REST API directly:

```bash
# Exchange authorization code for credentials
curl -X POST https://login.divine.video/api/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "code": "<authorization_code>",
    "client_id": "your-app",
    "redirect_uri": "https://yourapp.com/callback",
    "code_verifier": "<pkce_verifier>"
  }'

# Response includes both bunker_url (NIP-46) and access_token (HTTP RPC)
```

```bash
# Sign an event via HTTP RPC
curl -X POST https://login.divine.video/api/nostr \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "sign_event",
    "params": [{
      "kind": 1,
      "content": "Hello Nostr!",
      "created_at": 1234567890,
      "tags": []
    }]
  }'
```

## How It Works

**OAuth flow**: App redirects to Keycast. User authenticates (or registers). App receives access token and bunker URL.

**Two signing transports**:

| Transport | Latency | Use Case |
|-----------|---------|----------|
| HTTP RPC | ~50ms | Direct HTTPS with access token |
| NIP-46 | ~200-500ms | Standard Nostr protocol via relays |

Both return the same signed events. Use HTTP RPC for lower latency; use NIP-46 bunker URL with existing nostr-tools/NDK integrations.

**Key encryption**: AES-256-GCM at rest in PostgreSQL. Production uses GCP KMS (keys never leave hardware).

## API Reference

### OAuth Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/oauth/authorize` | GET | Start OAuth flow (redirect user here) |
| `/api/oauth/token` | POST | Exchange code for access_token + bunker_url |

### RPC Methods

POST to `/api/nostr` with `Authorization: Bearer <access_token>`:

| Method | Description |
|--------|-------------|
| `get_public_key` | Get user's public key (hex) |
| `sign_event` | Sign an unsigned event |
| `nip44_encrypt` / `nip44_decrypt` | NIP-44 encryption |
| `nip04_encrypt` / `nip04_decrypt` | NIP-04 encryption |

## Self-Hosting

```bash
git clone https://github.com/ArcadeLabsInc/keycast.git
cd keycast
bun install

# Generate encryption key
bun run key:generate

# Configure environment
cp .env.example .env
# Edit DATABASE_URL, SERVER_NSEC, ALLOWED_ORIGINS

# Run with Docker
docker compose up -d --build
```

See [DEVELOPMENT.md](./docs/DEVELOPMENT.md) for local development setup.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `SERVER_NSEC` | Server's Nostr secret key for signing tokens |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) |
| `BUNKER_RELAYS` | NIP-46 relay URLs |
| `MASTER_KEY_PATH` | Path to encryption key file |
| `USE_GCP_KMS` | Use GCP KMS instead of file-based key |

## History & Team Key Management

Keycast started as a team-based key management system, forked from [erskingardner/keycast](https://github.com/erskingardner/keycast). That original functionality—shared team keys with role-based access and custom permission policies—is still available but works via manual bunker URL distribution rather than OAuth.

See [docs/TEAMS.md](./docs/TEAMS.md) for team key management documentation.

## License

[MIT](LICENSE)
