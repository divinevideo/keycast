# Keycast

Keycast is the authentication and remote-signing service for [Divine](https://divine.video). Users sign in once, and apps get permission to sign Nostr events on their behalf — over a plain HTTPS API or over NIP-46 — without ever handling a raw private key. Keys are encrypted server-side; signing happens in Keycast. It runs in production at [login.divine.video](https://login.divine.video).

## Features

- **OAuth 2.0 with PKCE** — standard authorization-code flow. Apps redirect users to Keycast, users authenticate or register, and apps receive an access token plus a NIP-46 bunker URL.
- **Two signing transports** — sign via HTTP RPC (`POST /api/nostr` with a bearer token) for low latency, or via a NIP-46 bunker URL over relays for compatibility with existing Nostr tooling. Both produce identical signed events.
- **UCAN-based sessions** — access is carried by UCAN capability tokens, presented as a bearer token or a `keycast_session` cookie. There is a single auth path, not parallel token schemes.
- **Server-side key custody** — private keys are encrypted at rest with AES-256-GCM. The master key lives in a pluggable key manager: a local file, Google Cloud KMS, or AWS KMS.
- **Email/password accounts with key import** — users can let Keycast generate a Nostr key or import an existing `nsec`. Email verification and password reset are built in.
- **Fine-grained permissions** — each authorization references a policy built from reusable permission templates (allowed event kinds, encryption targets, and so on). The signer checks the policy before every signature.
- **Multi-tenant** — one deployment serves multiple domains, isolating users, OAuth clients, and policies per tenant.
- **Team key management** — shared team keys with role-based access, inherited from the project's origins (see [History](#history--team-key-management)).
- **Horizontal scale** — instances coordinate through a Redis/Valkey consistent hashring so NIP-46 relay traffic is distributed without duplicate signing.

## Client Libraries

| Platform | Package | Docs |
|----------|---------|------|
| Flutter/Dart | keycast_flutter | [Demo + Guide](https://github.com/divinevideo/keycast_flutter_demo) |
| JS/TS | keycast-login | [README](./keycast-login) |

For other languages, call the [HTTP API](#http-api) directly.

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

See the [keycast-login README](./keycast-login/README.md) for the full API reference, including BYOK (Bring Your Own Key) flows.

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

`POST /api/nostr` also supports `sign_canonical` for C2PA creator-binding payloads.
Pass a single base64-encoded creator-binding JSON payload; Keycast validates the
payload shape and authorization policy before returning a deterministic BIP-340
signature as lowercase hex.

An OpenAPI description is served at `/docs/openapi.json` and lives at [`api/openapi.yaml`](./api/openapi.yaml).

## Architecture

Keycast is a Rust [Cargo workspace](./Cargo.toml) plus a SvelteKit web frontend. Everything runs from one binary — the API server and the NIP-46 signer share a process so decrypted keys can be cached in memory and reused across both signing paths.

### Crates

| Crate | Role |
|-------|------|
| [`keycast`](./keycast) | The unified binary ([`keycast/src/main.rs`](./keycast/src/main.rs)). Boots the Axum HTTP server and the signer daemon in one process, wires up the database, key manager, and cluster coordinator, and handles graceful shutdown. Also runs migrations with `keycast --migrate`. |
| [`api`](./api) | Axum HTTP layer (`keycast_api`): OAuth endpoints, email/password auth, sessions, user and profile management, the `/api/nostr` HTTP RPC signing path, admin tooling, teams, policies, and ATProto provisioning. UCAN/DPoP verification lives in [`api/src/ucan_auth/`](./api/src/ucan_auth). Handlers stay thin and defer to `core`. |
| [`core`](./core) | Shared business logic (`keycast_core`): database models, the encryption/key-manager abstractions, UCAN and session handling, OAuth state, signing handlers, and the `CustomPermission` trait. Treated as the source of truth; encrypted key material only leaves `core`'s key-manager abstractions while actively signing. |
| [`signer`](./signer) | The NIP-46 signer daemon (`keycast_signer`): subscribes to the configured relays, routes incoming kind-24133 requests by recipient pubkey, and drives a work queue that decrypts, checks policy, signs, and replies. |
| [`cluster-hashring`](./cluster-hashring) | Redis/Valkey-backed cluster coordination: instance registration, heartbeats, and a consistent hashring (with Valkey IAM support) that assigns each bunker pubkey to exactly one instance so relay traffic is not signed twice. |
| [`tools/loadtest`](./tools/loadtest) | Load-testing tool for the signing paths. |

The SvelteKit frontend lives in [`web/`](./web) (Bun for package management). Database migrations live in [`database/migrations/`](./database/migrations).

### How OAuth, UCAN, and NIP-46 fit together

1. An app sends the user to `/api/oauth/authorize` with its `client_id` and a PKCE challenge.
2. The user authenticates (or registers) and approves the request. Keycast issues a short-lived authorization code.
3. The app exchanges the code at `/api/oauth/token` and receives two things: an **access token** (a UCAN capability token) and a **bunker URL** (`bunker://<pubkey>?relay=…&secret=…`).
4. From there the app can sign either way:
   - **HTTP RPC** — `POST /api/nostr` with `Authorization: Bearer <access_token>`. The unified binary signs from its in-memory key cache for low latency.
   - **NIP-46** — connect to the bunker URL over the configured relays. The signer daemon picks up the request, checks the authorization's policy, signs, and replies on the relay.

Every authorization carries a policy, and the signer enforces it before producing a signature. Revocation is a soft delete (`revoked_at`), so a user can approve the same app on multiple devices and revoke any one of them independently.

### Where it fits in the Divine platform

Keycast is Divine's login and signing service. Divine apps — web and mobile — send users through Keycast's OAuth flow to get a Divine identity, then sign Nostr events through it rather than shipping key material into each client. It can also provision ATProto/Bluesky handles for those identities when a control plane is configured. Because keys stay in Keycast, the rest of the platform never has to hold a user's private key.

For a deeper walkthrough of the data model and flows, see [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md).

## Getting Started

### Prerequisites

- Rust (the toolchain is pinned in [`rust-toolchain.toml`](./rust-toolchain.toml))
- [Bun](https://bun.sh) for the web app and the dev scripts
- Docker (Postgres and Redis are provided via [`docker-compose.deps.yml`](./docker-compose.deps.yml))
- For the full test/dev loop: `sqlx-cli`, `cargo-nextest`, and `cargo-watch`

### Local development

```bash
git clone https://github.com/divinevideo/keycast.git
cd keycast

bun install

# Generate a local master encryption key
bun run key:generate

# Configure environment
cp .env.example .env
# Edit at least DATABASE_URL, SERVER_NSEC, ALLOWED_ORIGINS, BUNKER_RELAYS, REDIS_URL

# Start Postgres + Redis, the Rust API + signer (cargo watch), and the web app
bun run dev
```

`bun run dev` runs the API and signer (the `keycast` binary) alongside the SvelteKit frontend. Common tasks:

```bash
bun run build        # cargo build --release --bin keycast
bun run db:migrate   # apply database migrations
bun run db:reset     # recreate the local dev database
bun run test         # full workspace + integration test suite (spins up Postgres + Redis)
bun run check        # cargo fmt --check, clippy, and cargo test --workspace
```

See [`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md) for the full local setup, and [`AGENTS.md`](./AGENTS.md) / [`CONTRIBUTING.md`](./CONTRIBUTING.md) for workflow and contribution guidelines.

### Self-hosting with Docker

```bash
cp .env.example .env
# Edit DATABASE_URL, SERVER_NSEC, ALLOWED_ORIGINS, BUNKER_RELAYS, REDIS_URL, etc.

bun run key:generate       # generate the master encryption key
docker compose up -d --build
```

## Configuration

Configuration is read from the environment (a `.env` file works locally). The binary validates required variables at startup and exits with a clear error if any are missing. See [`.env.example`](./.env.example) for the fully annotated list.

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis/Valkey URL for cluster coordination |
| `SERVER_NSEC` | Server's Nostr secret key, used to sign UCAN session tokens (hex or `nsec`) |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins (wildcard subdomains supported) |
| `BUNKER_RELAYS` | Comma-separated NIP-46 relay URLs the signer connects to (no default) |
| `MASTER_KEY_PATH` | Path to the master key file — required when `KMS_PROVIDER=file` |

### Encryption / KMS

| Variable | Default | Description |
|----------|---------|-------------|
| `KMS_PROVIDER` | `file` | Master-key backend: `file`, `gcp`, or `aws` |
| `MASTER_KEY_PATH` | `./master.key` | Required when `KMS_PROVIDER=file` |
| `GCP_PROJECT_ID` | *(none)* | Required when `KMS_PROVIDER=gcp` |
| `AWS_KMS_KEY_ID` | *(none)* | Required when `KMS_PROVIDER=aws` (key ID, ARN, or alias) |
| `AWS_REGION` | `us-east-1` | AWS KMS region when `KMS_PROVIDER=aws` |
| `USE_GCP_KMS` | *(legacy)* | Backward compatibility only; if `KMS_PROVIDER` is also set, `KMS_PROVIDER` wins |

Build with AWS support when using `KMS_PROVIDER=aws`: `cargo build --release --bin keycast --features aws`. The key needs `kms:Encrypt`, `kms:Decrypt`, and `kms:DescribeKey`.

### Multi-tenancy

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_TENANT_DOMAINS` | *(none)* | Restricts serving to these domains (recommended for production) |
| `ENABLE_TENANT_AUTO_PROVISIONING` | `false` | Auto-create a tenant for unknown domains (development only) |

If neither is set, requests from unknown domains are rejected.

### Email (SendGrid)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDGRID_API_KEY` | *(none)* | If set, sends via SendGrid; required in production unless `DISABLE_EMAILS=true` |
| `DISABLE_EMAILS` | *(none)* | Set to `true` to explicitly disable email delivery |
| `FROM_EMAIL` | — | Sender email address |
| `FROM_NAME` | `Divine` | Sender display name |
| `BASE_URL` | — | Base URL used in email verification links |
| `EMAIL_DELIVERY_DESTINATION_COOLDOWN_SECONDS` | `300` | Minimum interval per normalized destination |
| `EMAIL_DELIVERY_DESTINATION_LIMIT` | `5` | Deliveries allowed per purpose and destination window |
| `EMAIL_DELIVERY_DESTINATION_WINDOW_SECONDS` | `3600` | Per-purpose destination rolling-window length |
| `EMAIL_DELIVERY_ACCOUNT_LIMIT` | `6` | Email-change deliveries allowed per authenticated account window |
| `EMAIL_DELIVERY_ACCOUNT_WINDOW_SECONDS` | `3600` | Authenticated-account rolling-window length |
| `EMAIL_DELIVERY_SOURCE_LIMIT` | `50` | Secondary coarse-source delivery budget |
| `EMAIL_DELIVERY_SOURCE_WINDOW_SECONDS` | `3600` | Coarse-source rolling-window length |
| `EMAIL_DELIVERY_SOURCE_TRUSTED_PROXY_HOPS` | `1` | Trusted addresses after the client in a multi-value `X-Forwarded-For`; single-value chains use their sole value |
| `EMAIL_DELIVERY_GLOBAL_LIMIT` | `1000` | Process-cluster delivery budget per global window |
| `EMAIL_DELIVERY_GLOBAL_WINDOW_SECONDS` | `60` | Global rolling-window length |
| `EMAIL_PROVIDER_MAX_IN_FLIGHT` | `20` | Cluster and per-instance provider concurrency bound |
| `EMAIL_PROVIDER_CONNECT_TIMEOUT_MS` | `3000` | Provider connection deadline |
| `EMAIL_PROVIDER_REQUEST_TIMEOUT_MS` | `10000` | Total provider request deadline |

### Other common variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_URL` | `https://login.divine.video` | Fallback URL for OAuth callbacks / frontend runtime config |
| `ALLOWED_PUBKEYS` | *(none)* | Comma-separated admin pubkey allowlist |
| `DPOP_REPLAY_FAIL_OPEN` | `false` | DPoP replay-cache outage mode (`false` = fail-closed) |
| `DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL` | *(none)* | ATProto provisioning control plane; endpoints fail closed if unset |
| `SHOW_TEAMS_FUNCTIONALITY` | `false` | Show the team-management UI in the frontend |
| `RUST_LOG` | `info` | Log filter |

## Deployment

Production runs on Google Cloud in `us-central1`. The deploy pipeline is a single command:

```bash
bun run deploy   # gcloud builds submit --config=cloudbuild.yaml
```

[`cloudbuild.yaml`](./cloudbuild.yaml) builds the container image, runs database migrations as a job (`keycast --migrate`, using SQLx's embedded migrator), and rolls out the new revision. Migrations run before the new revision takes traffic so the schema always matches the running code.

Because decrypted keys are cached per instance and the NIP-46 signer holds long-lived relay connections, the service runs with a minimum instance count and session affinity, and the binary implements a phased graceful shutdown sized to the platform's SIGTERM grace period. For the full production topology, resources, and operational runbook, see [`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md).

## History & Team Key Management

Keycast started as a team-based key management system, forked from [erskingardner/keycast](https://github.com/erskingardner/keycast). That original functionality — shared team keys with role-based access and custom permission policies — is still available but works via manual bunker URL distribution rather than OAuth.

See [`docs/TEAMS.md`](./docs/TEAMS.md) for team key management documentation.

## License

[MIT](LICENSE)

---

Part of [Divine](https://divine.video) — your playground for human creativity · [Brand guidelines](https://github.com/divinevideo/brand-guidelines)
</content>
</invoke>
