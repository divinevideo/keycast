# Team Key Management

Keycast includes team-based key management functionality, originally developed by [@erskingardner](https://github.com/erskingardner/keycast). This allows organizations to share Nostr keys with role-based access control and custom signing policies.

## History

This codebase is a fork of [erskingardner/keycast](https://github.com/erskingardner/keycast), which was built for team key management. The fork added OAuth 2.0 and personal key custody for broader app integration. The original team functionality remains fully supported.

## How It Works

Team keys use NIP-46 remote signing with manually distributed bunker URLs (no OAuth flow). Admins create teams, add members, and generate bunker URLs that members paste into their Nostr clients.

```
Team Admin                           Team Member
    │                                     │
    ├─ Create team in web admin           │
    ├─ Add stored key                     │
    ├─ Create authorization               │
    ├─ Copy bunker URL ──────────────────►│
    │                                     ├─ Paste into Nostr client
    │                                     ├─ Client connects via NIP-46
    │◄────────────────────────────────────┤
    │         Sign requests               │
```

## Features

### Roles

- **Admin**: Full access to team settings, keys, members, and policies
- **Member**: Can use authorized keys according to assigned policies

### Custom Permission Policies

Policies restrict what team members can do with shared keys:

| Policy | Description |
|--------|-------------|
| `allowed_kinds` | Restrict which event kinds can be signed (e.g., only kind 1 notes) |
| `content_filter` | Filter events by content regex patterns |
| `encrypt_to_self` | Restrict encryption/decryption to user's own pubkey |

Policies are composable—assign multiple policies to an authorization for fine-grained control.

### Key Storage

Team keys are encrypted at rest with AES-256-GCM. Production deployments use GCP KMS; development uses a local `master.key` file.

## Usage

### Creating a Team

1. Access the web admin at your Keycast instance
2. Sign in with an allowed pubkey (via NIP-07 extension or bunker URL)
3. Create a new team
4. Add team members by their Nostr pubkey

### Adding a Shared Key

1. Navigate to your team's Keys section
2. Add a new stored key (generate or import nsec)
3. The key is encrypted and stored server-side

### Creating Authorizations

1. Select a stored key
2. Create an authorization with a descriptive name
3. Assign permission policies
4. Copy the generated bunker URL
5. Share the bunker URL with the team member (securely!)

### Connecting as a Team Member

1. Receive bunker URL from admin
2. Paste into any NIP-46 compatible client (Coracle, Nostrudel, etc.)
3. The client connects to Keycast's signer via Nostr relays
4. Sign events according to your assigned policies

## Adding Custom Permissions

To add a new permission type:

1. Implement the `CustomPermission` trait in `core/src/custom_permissions/`
2. Add to `AVAILABLE_PERMISSIONS` in `core/src/custom_permissions/mod.rs`
3. Add to `AVAILABLE_PERMISSIONS` in `web/src/lib/types.ts`
4. Add case to `to_custom_permission()` in `core/src/types/permission.rs`

See [DEVELOPMENT.md](./DEVELOPMENT.md) for more details.

## Comparison: Teams vs Personal OAuth

| Feature | Team Keys | Personal OAuth |
|---------|-----------|----------------|
| Key ownership | Organization | Individual user |
| Access control | Manual bunker URL distribution | OAuth consent flow |
| Multi-user | Yes (role-based) | No (single user per key) |
| App integration | NIP-46 only | OAuth + NIP-46 + HTTP RPC |
| Use case | Shared brand accounts, bots | Mobile apps, web apps |
