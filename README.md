# Keycast

Secure Nostr key custody with OAuth 2.0 access for apps.

## What is Keycast?

Keycast lets users store their Nostr private key (nsec) securely on a server and grant apps permission to sign events on their behalf. Apps integrate via standard OAuth 2.0 and receive credentials for remote signing.

**Use cases:**
- Mobile apps that need signing without storing nsec locally
- Web apps that want to offer "Login with Nostr" without browser extensions
- Multi-device access to the same Nostr identity

## Quick Start for App Developers

### TypeScript/JavaScript (Recommended)

Install the official client:

```bash
npm install keycast-login
# or
bun add keycast-login
```

```typescript
import { createKeycastClient, KeycastRpc } from 'keycast-login';

// 1. Create client
const client = createKeycastClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'your-app-id',
  redirectUri: window.location.origin + '/callback',
});

// 2. Start OAuth flow
// Option A: Let Keycast generate a new identity for the user
const { url, pkce } = await client.oauth.getAuthorizationUrl({
  scopes: ['policy:social'],
  defaultRegister: true,  // Auto-generate new nsec if user doesn't have one
});

// Option B: Bring Your Own Key - import user's existing nsec
// const { url, pkce } = await client.oauth.getAuthorizationUrl({
//   scopes: ['policy:social'],
//   nsec: 'nsec1...',  // User's existing key (pubkey derived automatically)
// });

sessionStorage.setItem('pkce_verifier', pkce.verifier);
window.location.href = url;

// 3. Handle callback (on /callback page)
const code = new URLSearchParams(location.search).get('code');
const verifier = sessionStorage.getItem('pkce_verifier');
const tokens = await client.oauth.exchangeCode(code, verifier);
// tokens.bunker_url    - NIP-46 bunker URL (for nostr-tools)
// tokens.access_token  - UCAN token (for REST RPC API)

// 4. Sign events via REST RPC
const rpc = client.createRpc(tokens);

const pubkey = await rpc.getPublicKey();
const signed = await rpc.signEvent({
  kind: 1,
  content: 'Hello Nostr!',
  tags: [],
  created_at: Math.floor(Date.now() / 1000),
  pubkey,
});

// 5. Publish to relays (using nostr-tools or your preferred library)
// await pool.publish(['wss://relay.example.com'], signed);
```

See [`keycast-login/README.md`](./keycast-login/README.md) for full API reference.

### Other Languages (HTTP API)

#### 1. OAuth Authorization Flow

Redirect users to Keycast's authorization endpoint:

```
GET /api/oauth/authorize?
  client_id=your-app-id&
  redirect_uri=https://yourapp.com/callback&
  scope=sign_event&
  code_challenge=<PKCE_CHALLENGE>&
  code_challenge_method=S256
```

User logs in (or registers), approves your app, and gets redirected back with an authorization code.

#### 2. Exchange Code for Credentials

```bash
POST /api/oauth/token
Content-Type: application/json

{
  "code": "<authorization_code>",
  "client_id": "your-app-id",
  "redirect_uri": "https://yourapp.com/callback",
  "code_verifier": "<PKCE_VERIFIER>"
}
```

Response:
```json
{
  "bunker_url": "bunker://abc123...?relay=wss://relay.example.com&secret=xyz",
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

You get **two ways to sign**:

| Credential | Transport | Use Case |
|------------|-----------|----------|
| `bunker_url` | NIP-46 via Nostr relays | Standard Nostr clients, works with nostr-tools |
| `access_token` | HTTP REST API | Low-latency signing, simpler integration |

#### 3a. Sign via NIP-46 (Bunker URL)

Use `bunker_url` with any NIP-46 compatible library.

#### 3b. Sign via HTTP RPC (Access Token)

```bash
POST /api/nostr
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "method": "sign_event",
  "params": [{
    "kind": 1,
    "content": "Hello Nostr!",
    "created_at": 1234567890,
    "tags": []
  }]
}
```

**Available RPC methods:**
- `get_public_key` - Get user's public key
- `sign_event` - Sign an unsigned event
- `nip04_encrypt` / `nip04_decrypt` - NIP-04 encryption
- `nip44_encrypt` / `nip44_decrypt` - NIP-44 encryption

## Live Demo

Visit `/demo` on your Keycast instance to test the full OAuth flow interactively. The demo shows both key generation modes (server-generated and BYOK) and all RPC operations (signing, encryption, decryption).

## Architecture

```
┌─────────────────┐                              ┌─────────────────┐
│                 │────── 1. OAuth 2.0 ─────────►│                 │
│   Your App      │                              │    Keycast      │
│  (Flutter/Web)  │◄───── 2. bunker_url ────────│     Server      │
│                 │◄───── 2. access_token ──────│                 │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  Sign Requests (two options):                  │
         │                                                │
         │  A) HTTP RPC (access_token)                    │
         │     ──────────────────────────────────────────►│
         │                                                │
         │  B) NIP-46 (bunker_url)                        │
         │     ─────────►┌──────────────┐◄────────────────┤
         │               │ Nostr Relays │                 │
         │     ◄─────────└──────────────┘────────────────►│
         │                                                │
         │                                                ▼
         │                                       ┌─────────────────┐
         │                                       │   PostgreSQL    │
         │                                       │ (encrypted keys)│
         │                                       └────────┬────────┘
         │                                                │
         │                                                ▼
         │                                       ┌─────────────────┐
         │                                       │  GCP KMS or     │
         │                                       │  master.key     │
         │                                       └─────────────────┘
```

**Two signing transports:**
- **HTTP RPC**: App → Keycast (direct, ~50ms latency)
- **NIP-46**: App ↔ Nostr Relays ↔ Keycast (standard protocol, ~200-500ms)

**Key encryption:**
- Private keys are AES-256-GCM encrypted in PostgreSQL
- **Production (GCP KMS)**: Master key never leaves KMS hardware - even with DB access, keys cannot be decrypted without KMS permissions
- **Development (master.key)**: File-based AES key for local testing

## Hosting Your Own Instance

### Prerequisites

- Docker and Docker Compose
- PostgreSQL (included in docker-compose)
- A domain with HTTPS (for production)

### Quick Start

```bash
git clone https://github.com/ArcadeLabsInc/keycast.git
cd keycast
bun install

# Generate encryption key
bun run key:generate

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run with Docker
docker compose up -d --build
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `SERVER_NSEC` | Server's Nostr secret key for signing tokens |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) |
| `BUNKER_RELAYS` | NIP-46 relay URLs (default: several public relays) |
| `MASTER_KEY_PATH` | Path to encryption key file |
| `USE_GCP_KMS` | Use GCP KMS instead of file-based key (production) |

### Development

```bash
# Run dev server (API + NIP-46 signer)
bun run dev

# Run web admin UI
bun run dev:web

# Run tests
cargo test
```

## Team Key Management (Original Keycast)

Keycast was originally built for team-based Nostr key management. This functionality is still available and works via NIP-46 bunker URLs (not yet integrated with OAuth/HTTP RPC).

**Team features:**
- Create teams with shared Nostr keys
- Role-based access control (admin/member)
- Custom permission policies:
  - `allowed_kinds` - Restrict which event kinds can be signed
  - `content_filter` - Filter events by content patterns
  - `encrypt_to_self` - Restrict encryption to user's own pubkey
- NIP-46 remote signing for team keys

Access the web admin at your Keycast URL to manage teams. See the [original Keycast repository](https://github.com/erskingardner/keycast) for the team-focused implementation.

## License

[MIT](LICENSE)
