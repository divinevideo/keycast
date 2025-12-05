# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Keycast is a secure remote signing and permissions system for teams using Nostr. It provides NIP-46 remote signing, team-based key management, and flexible permissions policies. The project consists of:

**Rust workspace crates:**
- **keycast**: Unified binary (main.rs) - runs API + Signer in single process
- **api**: HTTP API library - team management, authentication, OAuth 2.0 (library only, no binary)
- **core**: Shared business logic, database models, encryption, permissions system
- **signer**: NIP-46 signer library - handles multiple bunker connections

**Client libraries:**
- **keycast-login**: TypeScript/JavaScript OAuth client with storage abstraction
- **keycast_flutter**: Dart/Flutter OAuth client (separate repo: keycast_flutter_demo)

**Frontend:**
- **web**: SvelteKit frontend application (uses Bun for package management)

## Development Commands

### Prerequisites

1. **PostgreSQL** - Install locally or use Docker:
   ```bash
   docker run -d --name postgres -p 5432:5432 \
     -e POSTGRES_PASSWORD=password \
     -e POSTGRES_DB=keycast \
     postgres:16
   ```

2. **Master encryption key**:
   ```bash
   bun run key:generate
   ```

3. **Database setup**:
   ```bash
   bun run db:reset  # Creates tables and runs migrations
   ```

### Running Dev Server

```bash
# Run unified binary (API + Signer) with hot reload
bun run dev          # http://localhost:3000

# Run web frontend separately
bun run dev:web      # https://localhost:5173
```

**Note:** The unified binary runs both the HTTP API and NIP-46 signer in a single process for optimal performance.

### Building

```bash
# Build unified binary
bun run build        # Produces: target/release/keycast

# Build web frontend
bun run build:web    # Produces: web/build/
```

### Testing

```bash
# Run Rust tests (OAuth integration tests)
cd api && cargo test

# Run individual test files
cd api && cargo test --test oauth_integration_test
cd api && cargo test --test oauth_unit_test
```

## Architecture

### Multi-Authentication System

The web admin supports three authentication methods, all converging to unified NIP-98 request signing:

1. **NIP-07 Browser Extension**: For whitelisted team admins with browser extension (nos2x, Alby, etc.)
2. **Email/Password**: For personal users, sets UCAN session cookie (bunker created separately)
3. **NIP-46 Bunker URL**: For power users with existing bunker URLs (dogfooding)

**Unified Flow**: All methods → Bunker URL credential → BunkerSigner → NIP-98 signed requests

**Authentication Architecture**:
- Email login/register creates user in `users` table and stores encrypted keys in `personal_keys`
- Returns UCAN session token (set as `keycast_session` HttpOnly cookie)
- UCAN contains: tenant_id, email, redirect_origin (no oauth_authorization created yet)
- OAuth authorizations (`oauth_authorizations`) are created later via:
  - Third-party OAuth flow: `/api/oauth/token` creates authorization when app exchanges code
  - Manual bunker creation: User explicitly creates bunker via `/user/bunker/create`
- Each authorization has its own bunker keypair (derived via HKDF) and connection secret
- Frontend uses nostr-tools BunkerSigner to sign NIP-98 auth headers
- All authenticated API requests include NIP-98 signature in Authorization header
- Backend extracts pubkey from NIP-98 event, validates signature

**Permission Model**:
- **Whitelist** (VITE_ALLOWED_PUBKEYS): Can create teams, full admin access
- **Team Membership**: Can view teams they belong to, role-based permissions (admin/member)
- **Personal Keys**: Can manage their own OAuth authorizations

**Key Types**:
- Regular `Authorization`: Team-managed keys with separate bunker keypair and user signing key
- `OAuthAuthorization`: Personal user keys where the user's own keypair acts as both bunker and signer

### Database & Encryption

- PostgreSQL database with SQLx for compile-time query verification
- AES-256-GCM row-level encryption for all private keys (encrypted at rest, decrypted only when used)
- Supports file-based key manager (default) or GCP KMS (`USE_GCP_KMS=true`)
- Database migrations in `database/migrations/`

Key tables:
- `users`: Nostr public keys
- `teams`: Team containers
- `team_users`: Team membership with roles (admin/member)
- `stored_keys`: Encrypted Nostr keypairs managed by teams
- `policies`: Named permission sets
- `permissions`: Custom permission configurations (JSON)
- `policy_permissions`: Links policies to permissions
- `authorizations`: NIP-46 remote signing credentials for team keys
- `oauth_authorizations`: OAuth-based personal auth with NIP-46 support (supports multi-device: each approval creates new authorization, uses `revoked_at` for soft-delete)

### Custom Permissions System

Custom permissions implement the `CustomPermission` trait (`core/src/traits.rs`) with three methods:
- `can_sign(&self, event: &UnsignedEvent) -> bool`
- `can_encrypt(&self, plaintext: &str, pubkey: &str) -> bool`
- `can_decrypt(&self, ciphertext: &str, pubkey: &str) -> bool`

When adding a new custom permission:
1. Create implementation in `core/src/custom_permissions/`
2. Add to `AVAILABLE_PERMISSIONS` in `core/src/custom_permissions/mod.rs`
3. Add to `AVAILABLE_PERMISSIONS` in `web/src/lib/types.ts`
4. Add case to `to_custom_permission()` in `core/src/types/permission.rs`

Existing permissions:
- `allowed_kinds`: Restrict signing/encryption by Nostr event kind
- `content_filter`: Filter events by content regex patterns
- `encrypt_to_self`: Restrict encryption/decryption to user's own pubkey

### Signer Daemon Architecture

The unified binary (`keycast/src/main.rs`) runs both the HTTP API and NIP-46 signer daemon:
- Single process handles all active authorizations (both team and OAuth)
- Loads all authorizations on startup into in-memory HashMap (bunker_pubkey -> handler)
- Connects to all configured relays for all authorizations
- Routes incoming NIP-46 requests to appropriate authorization based on recipient pubkey
- Validates requests against policy permissions before signing/encrypting/decrypting
- Supports both regular team authorizations and OAuth personal authorizations

### API Routes Structure

Key endpoints (see `api/src/api/http/routes.rs`):

**Authentication (First-Party)**:
- `/api/auth/register`: Register with email/password, optional nsec import, sets UCAN session cookie
- `/api/auth/login`: Login with email/password, sets UCAN session cookie
- `/api/auth/logout`: Clears session cookie
- CORS: Restrictive (ALLOWED_ORIGINS env var)

**OAuth (Third-Party)**:
- `/api/oauth/authorize`: OAuth authorization flow (GET shows approval page, POST processes approval)
- `/api/oauth/token`: Exchange authorization code for bunker URL with PKCE
- `/api/oauth/poll?state={state}`: Poll for authorization code (iOS PWA pattern). Returns HTTP 200 with code when ready, HTTP 202 if pending, HTTP 404 if expired
- CORS: Permissive (any origin)

**User Management (NIP-98 Auth Required)**:
- `/api/user/oauth-authorizations`: List personal OAuth authorizations
- `/api/user/oauth-authorizations/:id`: Revoke authorization
- `/api/user/bunker`: Get personal NIP-46 bunker URL (legacy)

**Team Management (NIP-98 Auth Required)**:
- `/api/teams/*`: Team CRUD, member management, key management, policies
- Requires whitelist or team membership

### Environment Variables

Required (set in `.env` or docker-compose):
- `DATABASE_URL`: PostgreSQL connection string (e.g., `postgres://postgres:password@localhost/keycast`)
- `POSTGRES_PASSWORD`: PostgreSQL password (for docker-compose)
- `ALLOWED_ORIGINS`: Comma-separated CORS origins (e.g., `https://app.keycast.com,http://localhost:5173`)
- `SERVER_NSEC`: Server Nostr secret key for signing UCANs (hex 64 chars or nsec bech32). Generate with `openssl rand -hex 32`. Used for server-signed session tokens for users without personal keys yet.
- `DOMAIN`: Domain name for production deployment (docker-compose only)

Optional:
- `MASTER_KEY_PATH`: Path to master encryption key file (default: `./master.key`)
- `USE_GCP_KMS`: Use Google Cloud KMS instead of file-based encryption (default: `false`)
- `BUNKER_RELAYS`: Comma-separated relay URLs for NIP-46 communication (default: `wss://relay.divine.video,wss://relay.primal.net,wss://relay.nsec.app,wss://nos.lol`)
- `RUST_LOG`: Log level configuration (default: `info,keycast_signer=debug`)
- `VITE_ALLOWED_PUBKEYS`: Comma-separated pubkeys for whitelist access (web frontend)
- `ENABLE_EXAMPLES`: Enable `/examples` directory serving (default: `false`, set to `true` for development)

Development (`.env` in `/web`):
- `VITE_ALLOWED_PUBKEYS`: Comma-separated pubkeys for dev access

## Nostr Protocol Integration

- Uses `nostr-sdk` crate (from git, specific revision) with NIP-04, NIP-44, NIP-46, NIP-49, NIP-59 support
- NIP-46 remote signing: Clients connect via bunker URLs (`bunker://<pubkey>?relay=<relay>&secret=<secret>`)
- NIP-98 HTTP Auth: Web app signs HTTP requests with Nostr events for API authentication

## Deployment

Production runs on Google Cloud Run as service `keycast` with `min-instances=1` to ensure the NIP-46 signer runs continuously.

### Deploy to Production

```bash
bun run deploy  # or: pnpm run deploy:gcp
```

This runs Cloud Build which:
1. Builds Docker image
2. Pushes to Artifact Registry
3. Deploys to Cloud Run
4. Runs smoke tests

### Architecture

- **Service:** `keycast` (Cloud Run, us-central1)
- **URL:** https://login.divine.video
- **Database:** Cloud SQL PostgreSQL (`keycast-db`)
- **Secrets:** GCP Secret Manager

### View Logs

```bash
# View recent logs
pnpm run logs

# Stream logs continuously
pnpm run logs:watch

# Or via gcloud directly
gcloud logging read 'resource.type=cloud_run_revision AND resource.labels.service_name=keycast' \
  --limit=50 --project=openvine-co --format='value(jsonPayload.fields.message)'
```

## Notes

- All sensitive keys are encrypted at rest with AES-256-GCM
- Master encryption key must be generated before first run (`bun run key:generate`)
- Database uses PostgreSQL with automatic migrations on startup
- Signer daemon monitors database for new/removed authorizations and adjusts connections accordingly
- Build issues on low-memory VMs: Need 2GB+ RAM for Vite build; may require swap space or retries
