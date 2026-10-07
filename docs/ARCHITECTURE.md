# Keycast Architecture Overview

High-level explanation of how Keycast works based on database schema and code structure.

## Core Concept

Keycast is a **remote signing service** for Nostr that provides:
- Email/password authentication → Nostr keypair management
- NIP-46 remote signing via bunker URLs
- Team-based key management with granular permissions
- Multi-tenant isolation (different deployments/domains)

## Database Schema Overview

### 1. Multi-Tenancy (`tenants`)

**Purpose:** Isolate data by deployment domain

```
tenants
  ├─ id, domain (login.divine.video, localhost, etc.)
  ├─ settings (JSON: relay URLs, email config)
  └─ All other tables have tenant_id FK
```

**Flow:**
- HTTP request arrives with Host header
- Extract domain from Host
- Auto-provision tenant if doesn't exist
- All queries scoped by tenant_id

**Example:**
- `login.divine.video` → tenant_id: 1
- `keycast.example.com` → tenant_id: 2 (auto-created)
- Same email can exist in both with different keys

---

### 2. Personal Authentication (`users`, `personal_keys`)

**Purpose:** Email/password authentication for individual users

```
users
  ├─ public_key (Nostr pubkey, PRIMARY)
  ├─ email, password_hash
  ├─ email_verified, verification tokens
  └─ tenant_id

personal_keys
  ├─ user_public_key → users(public_key)
  ├─ encrypted_secret_key (AES-256-GCM)
  ├─ bunker_secret (for NIP-46 connection)
  └─ tenant_id
```

**Registration Flow:**
1. User provides email + password (+ optional nsec to import)
2. Create key pair (or parse provided nsec)
3. Hash password with bcrypt
4. Encrypt private key with master key/KMS
5. Insert into `users` and `personal_keys`
6. Create OAuth authorization for "keycast-login" app
7. Return JWT token

**Login Flow:**
1. User provides email + password
2. Lookup user by email + tenant_id
3. Verify password hash
4. Generate JWT token (contains user pubkey)
5. Return token + pubkey

---

### 3. Team Management (`teams`, `team_users`, `stored_keys`)

**Purpose:** Organizations can manage shared Nostr keys

```
teams
  ├─ id, name, description
  └─ tenant_id

team_users
  ├─ team_id → teams(id)
  ├─ user_public_key → users(public_key)
  ├─ role (admin/member)
  └─ tenant_id

stored_keys
  ├─ team_id, name
  ├─ public_key, encrypted_secret_key
  └─ tenant_id
```

**Use Case:**
- Company creates team "Marketing"
- Adds users as admins/members
- Creates shared Nostr key "marketing_account"
- Team members can authorize apps to sign with team key
- Permissions control what each member can do

---

### 4. OAuth Applications (`oauth_applications`, `oauth_codes`, `oauth_authorizations`)

**Purpose:** Third-party apps request authorization to sign on user's behalf

```
oauth_applications
  ├─ client_id (e.g., "myapp")
  ├─ client_secret, name, redirect_uris
  ├─ policy_id (default permissions)
  └─ tenant_id

oauth_codes (short-lived)
  ├─ code (one-time use)
  ├─ user_public_key, application_id
  ├─ expires_at
  └─ tenant_id

oauth_authorizations (long-lived)
  ├─ user_public_key, application_id
  ├─ bunker_public_key, bunker_secret (encrypted keypair for this auth)
  ├─ secret (NIP-46 connection secret)
  ├─ relays (JSON array)
  ├─ policy_id (permissions for this authorization)
  └─ tenant_id
```

**OAuth Flow (Third-Party Apps):**
1. App redirects to `/api/oauth/authorize?client_id=myapp`
2. User logs in and approves
3. Keycast creates `oauth_code`
4. Redirects back to app with code
5. App exchanges code for bunker URL at `/api/oauth/token`
6. Creates `oauth_authorization` with unique bunker keypair
7. Returns bunker URL: `bunker://pubkey?relay=...&secret=...`

**ROPC Flow (First-Party Apps like Peek):**
1. Peek collects email + password directly
2. Calls `/api/auth/register` with optional nsec
3. Creates `oauth_authorization` for "keycast-login" app
4. Uses **user's key** as bunker key (dogfooding pattern)
5. Calls `/api/user/bunker` to get bunker URL
6. Returns bunker URL with user's pubkey

**Key Difference:**
- **OAuth:** Separate bunker keypair per authorization
- **Personal (keycast-login):** User's key IS the bunker key

---

### 5. Regular Authorizations (`authorizations`, `user_authorizations`)

**Purpose:** Team-managed bunker authorizations

```
authorizations
  ├─ bunker_public_key, bunker_secret (separate keypair)
  ├─ signing_key_id → stored_keys(id) (team's key)
  ├─ secret (NIP-46 connection)
  ├─ policy_id
  └─ tenant_id

user_authorizations
  ├─ authorization_id → authorizations(id)
  ├─ user_public_key (who can redeem this)
  ├─ redeemed (claimed flag)
  └─ tenant_id
```

**Team Authorization Flow:**
1. Team admin creates authorization for team key
2. Assigns to specific user
3. User redeems authorization (first NIP-46 connect)
4. Bunker uses **team's key** to sign, not user's key

---

### 6. Permissions System (`permissions`, `policies`, `policy_permissions`)

**Purpose:** Fine-grained control over what authorizations can do

```
permissions (global templates)
  ├─ identifier (e.g., "allowed_kinds_social_messaging")
  └─ config (JSON: {"allowed_kinds": [0, 1, 3, 4, 7, 44, 1059, 9735, 22242, 10011]})

policies (per-tenant)
  ├─ name (e.g., "Standard Social (Default)")
  ├─ team_id (NULL for global policies)
  └─ tenant_id

policy_permissions (many-to-many)
  ├─ policy_id → policies(id)
  └─ permission_id → permissions(id)
```

**How It Works:**
1. Permissions are reusable templates (no tenant_id)
2. Policies are per-tenant, link to permissions
3. Authorizations reference a policy
4. When a signing request arrives (NIP-46, HTTP RPC, or session signing):
   - Signer checks authorization's policy
   - Evaluates all linked permissions
   - Allows only if every linked permission allows the event

**Example:**
- Permission: `allowed_kinds_social_messaging` = [0, 1, 3, 4, 7, 44, 1059, 9735, 22242, 10011]
- Policy: "Standard Social" links to that one permission
- Authorization has policy_id = Standard Social
- Can sign those kinds, including 10011 (linked accounts)
- Cannot sign kind 5 (deletions) ❌

---

### 7. Signing Activity (`signing_activity`)

**Purpose:** Audit log of all signing operations

```
signing_activity
  ├─ user_public_key, application_id
  ├─ bunker_secret (which authorization)
  ├─ event_kind, event_content (truncated)
  ├─ event_id (signed event)
  ├─ client_public_key (NIP-46 client)
  └─ tenant_id, created_at
```

**Logged When:**
- Any NIP-46 sign_event request
- Fast-path HTTP signing (/api/user/sign)
- Shows who signed what, when

---

### 8. Email Features (`email_verification_tokens`, `password_reset_tokens`)

**Purpose:** Traditional web account features

```
email_verification_tokens
  └─ Standard verification flow

password_reset_tokens
  └─ Forgot password flow
```

**Not enforced** - users can use service without verifying email.

---

## Data Flow Examples

### Example 1: Peek User Secures Account

```
1. Peek: POST /api/auth/register
   Body: {email, password, nsec: "user's local key"}

2. Keycast creates:
   users:
     - public_key: "abc123..."
     - email: "user@example.com"
     - password_hash: bcrypt(password)
     - tenant_id: 2 (localhost)

   personal_keys:
     - encrypted_secret_key: AES(nsec)
     - bunker_secret: AES(nsec) ← Same key!

   oauth_authorizations:
     - application_id: keycast-login app
     - bunker_public_key: "abc123..." ← User's pubkey
     - secret: random 48 chars
     - policy_id: Standard Social

3. Returns: JWT token

4. Peek: GET /api/user/bunker
   Header: Bearer <JWT>

5. Returns: bunker://abc123...?relay=wss://relay.damus.io&secret=xyz...

6. Peek stores bunker URL, uses for NIP-46 signing
```

### Example 2: Third-Party App OAuth

```
1. ThirdApp: Redirect to /api/oauth/authorize?client_id=thirdapp

2. User logs in, sees consent screen

3. Keycast creates:
   oauth_codes:
     - code: random
     - user_public_key: "abc123..."
     - application_id: thirdapp
     - expires_at: +10 minutes

4. Redirects: https://thirdapp.com/callback?code=xyz

5. ThirdApp: POST /api/oauth/token
   Body: {code: "xyz"}

6. Keycast creates:
   oauth_authorizations:
     - bunker_public_key: "def456..." ← NEW separate keypair
     - bunker_secret: AES(new bunker secret key)
     - user signs with "abc123..." original key
     - policy_id: from application default

7. Returns: bunker://def456...?relay=...&secret=...

8. ThirdApp connects via NIP-46, signs as "abc123..." (user's key)
   but bunker pubkey is "def456..." (ephemeral)
```

### Example 3: Team Key Management

```
1. Company creates team "Marketing"
   teams: {name: "Marketing", tenant_id: 1}

2. Add key to team
   stored_keys:
     - team_id: marketing team
     - public_key: "team123..."
     - encrypted_secret_key: AES(team private key)

3. Create authorization for team key
   authorizations:
     - bunker_public_key: "bunker789..." ← Separate
     - signing_key_id: team123 stored key
     - policy_id: Team permissions

   user_authorizations:
     - user_public_key: "member_abc..."
     - redeemed: false

4. Team member redeems (first NIP-46 connect)
   - Mark redeemed: true
   - Bunker signs with team's key, not member's key
```

---

## Key Architecture Decisions

### 1. Two Types of Bunker Keys

**Personal OAuth** (`oauth_authorizations` for keycast-login):
- `bunker_pubkey` = `user_pubkey` (same key)
- Simplifies: one keypair for everything
- Used for: ROPC flow with first-party apps

**Third-Party OAuth** (`oauth_authorizations` for other apps):
- `bunker_pubkey` ≠ `user_pubkey` (separate ephemeral key)
- Security: can revoke without changing user's key
- Client sees `bunker_pubkey` but signs as `user_pubkey`

### 2. Permissions are Global, Policies are Per-Tenant

**Permissions:** Reusable templates (no tenant_id)
- `allowed_kinds_social`
- `allowed_kinds_messaging`
- `encrypt_to_self`

**Policies:** Per-tenant collections of permissions
- "Standard Social (Default)" for tenant 1
- "Standard Social (Default)" for tenant 2
- Different tenants can customize same-named policies

### 3. Encryption Layers

**At Rest:**
- Private keys: AES-256-GCM encrypted in DB
- Master key: File-based or GCP KMS

**In Transit:**
- NIP-46: NIP-44 encryption over relay
- HTTP: TLS

**In Memory:**
- Signer daemon keeps decrypted keys cached
- API shares handlers for fast-path signing

### 4. Signing Paths

**Fast Path** (unified binary only):
- HTTP request → Cached handler → Sign → Return
- ~10ms (no DB/KMS hit)

**Slow Path:**
- NIP-46 request → Query DB → Decrypt with KMS → Sign → Return
- ~50-100ms

**NIP-46 Path:**
- Request on relay → Signer daemon → Decrypt → Sign → Reply on relay
- Variable latency (relay dependent)

---

## Table Relationships

```
tenants (1)
  └─→ users (many)
       ├─→ personal_keys (1) [encrypted user key]
       ├─→ user_profiles (1) [display name, etc.]
       ├─→ oauth_authorizations (many) [bunker URLs for user]
       └─→ team_users (many)
            └─→ teams (many)
                 └─→ stored_keys (many) [team keys]
                      └─→ authorizations (many) [team bunker URLs]
                           └─→ user_authorizations (many) [who can use]

policies (per-tenant)
  ├─→ policy_permissions (many)
  │    └─→ permissions (global templates)
  └─← authorizations.policy_id
  └─← oauth_authorizations.policy_id

oauth_applications (per-tenant)
  └─→ oauth_authorizations (many)
       ├─ For personal: bunker_pubkey = user_pubkey
       └─ For third-party: bunker_pubkey ≠ user_pubkey

signing_activity (audit log)
  ← All signing operations logged here
```

---

## User Journeys

### Journey 1: Peek User (ROPC)

1. **Anonymous** → Peek auto-generates local nsec
2. **Secure Account** → Peek calls keycast registration with nsec
3. **Account Created** → `users` + `personal_keys` + `oauth_authorization`
4. **Get Bunker URL** → `/api/user/bunker` returns bunker URL
5. **Use Everywhere** → Paste bunker URL into any NIP-46 client
6. **Sign Events** → Signer daemon handles NIP-46 requests

### Journey 2: Third-Party App OAuth

1. **App Integration** → Developer registers OAuth app
2. **User Connects** → OAuth authorization flow
3. **Authorization Created** → Separate bunker keypair generated
4. **Bunker URL** → App gets bunker URL, stores it
5. **Sign Events** → App sends NIP-46 requests via relay
6. **Permissions** → Signer checks policy before signing

### Journey 3: Team Key Management

1. **Create Team** → Organization makes team
2. **Add Key** → Import or generate team Nostr key
3. **Create Authorization** → Make bunker URL for team key
4. **Assign to Users** → Team members can use authorization
5. **Redeem** → User claims authorization (NIP-46 connect)
6. **Sign as Team** → Signs with team's key, not personal key

---

## Security Model

### Encryption

**Private Keys:**
- Encrypted at rest: AES-256-GCM
- Decrypted only when signing
- Master key: File or GCP KMS

**Connection Secrets:**
- Random per authorization
- Required for NIP-46 authentication
- 32-48 character alphanumeric

### Authentication

**Personal:**
- Email + password → JWT token
- JWT contains user pubkey
- Token expires in 24 hours
- No refresh tokens (must re-login)

**NIP-46:**
- Client proves knowledge of connection secret
- First `connect` request validates secret
- Subsequent requests encrypted with NIP-44

### Permissions

**Policy-Based:**
- Each authorization has a policy
- Policy contains multiple permissions
- Permissions checked before signing
- Can restrict: event kinds, content patterns, encryption targets

**Example Policy:**
```json
{
  "Standard Social": [
    {"allowed_kinds": [0, 1, 3, 4, 7, 44, 1059, 9735, 22242, 10011]}
  ]
}
```

Every permission must allow an event, so a policy's allowed kinds go in one
permission: two `allowed_kinds` permissions would only allow kinds on both lists.

Request to sign kind 9734 (zap) → ❌ Denied

---

## Multi-Tenant Isolation

**Tenant Scoping:**
- All queries filter by `tenant_id`
- Email uniqueness: per-tenant
- OAuth client_id uniqueness: per-tenant
- Policies: per-tenant (can customize)

**Auto-Provisioning:**
- New domain → Auto-create tenant
- Seed default policies
- Ready for first user

**Isolation Guarantees:**
- Tenant A cannot see Tenant B's users
- Same email can exist in multiple tenants
- Different keys, different authorizations
- Complete data isolation

---

## Key Insights

1. **One User, Many Bunker URLs:**
   - Personal auth: bunker URL with user's pubkey
   - OAuth apps: separate bunker URL per app
   - Team keys: bunker URLs for team keypairs

2. **Policy Reuse:**
   - Permissions are global templates
   - Policies combine permissions per-tenant
   - Authorizations reference policies
   - Change policy → affects all using it

3. **Unified Binary Performance:**
   - Signer and API share process
   - Decrypted keys cached in memory
   - Fast-path signing without DB hits
   - ~5-10x faster than separate processes

4. **Two Authentication Models:**
   - ROPC: First-party apps (peek) get user's key directly
   - OAuth: Third-party apps get ephemeral bunker key
   - Both use same NIP-46 protocol

5. **Multi-Tenancy Enables:**
   - SaaS deployment (many customers, one instance)
   - Data isolation by domain
   - Per-tenant customization
   - Different policies/relays per tenant

---

## Common Operations

**Register User:**
```
users ← INSERT
personal_keys ← INSERT (encrypted key)
oauth_applications ← ENSURE "keycast-login" exists
oauth_authorizations ← INSERT (for keycast-login)
```

**Get Bunker URL:**
```
oauth_authorizations ← SELECT WHERE user_pubkey AND app="keycast-login"
Format: bunker://{bunker_pubkey}?relay={relay}&secret={secret}
```

**Sign Event (NIP-46):**
```
NIP-46 request → Signer daemon
oauth_authorizations ← SELECT WHERE bunker_pubkey
Decrypt bunker_secret
Check policy permissions
Sign with user_keys
signing_activity ← INSERT (audit)
NIP-46 response → Relay
```

**Auto-Provision Tenant:**
```
tenants ← INSERT
policies ← INSERT × 3 (Standard Social, Read Only, Wallet Only)
policy_permissions ← INSERT (link to global permissions)
```

---

This schema supports both simple personal use (peek) and complex team/organization scenarios with fine-grained access control.
