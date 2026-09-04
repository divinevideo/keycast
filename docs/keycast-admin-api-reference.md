# Keycast Admin API Reference

Base URL: `https://login.divine.video` (production) or `http://localhost:3000` (local)

## Authentication

All admin endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <token>
```

Two token types:
- **Admin Token**: For admin operations (preload-user, claim-tokens). Get via `/api/admin/token`
- **User Token**: For signing on behalf of a user. Returned by `/api/admin/preload-user`

---

## Admin Endpoints

### GET /api/admin/status

Check if the current user is an admin.

**Request:**
```http
GET /api/admin/status
Authorization: Bearer <any_valid_token>
```

**Response:**
```json
{
  "is_admin": true
}
```

---

### GET /api/admin/token

Generate a long-lived admin API token (30 days).

**Request:**
```http
GET /api/admin/token
Authorization: Bearer <session_token>
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
  "expires_at": "2025-02-18T12:00:00Z"
}
```

**Errors:**
| Status | Description |
|--------|-------------|
| 403 | Caller pubkey not in ALLOWED_PUBKEYS whitelist |

---

### POST /api/admin/preload-user

Create a preloaded user account (no email/password required).

**Request:**
```http
POST /api/admin/preload-user
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "vine_id": "12345",
  "username": "alice",
  "display_name": "Alice Smith"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| vine_id | string | Yes | Unique Vine user identifier |
| username | string | Yes | Unique username |
| display_name | string | No | Display name |

**Response:**
```json
{
  "pubkey": "abc123def456789...",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."
}
```

| Field | Description |
|-------|-------------|
| pubkey | 64-character hex Nostr public key |
| token | UCAN token for signing events (valid 30 days) |

**Errors:**
| Status | Description |
|--------|-------------|
| 403 | Caller is not an admin |
| 409 | User with this vine_id or username already exists |

---

### POST /api/admin/claim-tokens

Generate a claim link for a preloaded user to set email/password.

**Request:**
```http
POST /api/admin/claim-tokens
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "vine_id": "12345"
}
```

**Response:**
```json
{
  "claim_url": "https://login.divine.video/api/claim?token=abc123xyz...",
  "expires_at": "2025-02-18T12:00:00Z"
}
```

**Errors:**
| Status | Description |
|--------|-------------|
| 403 | Caller is not an admin |
| 404 | No user found with this vine_id |
| 409 | User has already claimed their account |

---

## Signing Endpoint (HTTP RPC)

### POST /api/nostr

Execute NIP-46 RPC methods via HTTP (lower latency than relay-based NIP-46).

**Request:**
```http
POST /api/nostr
Authorization: Bearer <user_token>
Content-Type: application/json

{
  "method": "<method_name>",
  "params": [<param1>, <param2>, ...]
}
```

### Methods

#### sign_event

Sign a Nostr event.

**Request:**
```json
{
  "method": "sign_event",
  "params": [{
    "kind": 1,
    "content": "Hello world",
    "created_at": 1705000000,
    "tags": []
  }]
}
```

**Response:**
```json
{
  "result": {
    "id": "abc123...",
    "pubkey": "def456...",
    "created_at": 1705000000,
    "kind": 1,
    "tags": [],
    "content": "Hello world",
    "sig": "789xyz..."
  }
}
```

#### get_public_key

Get the user's public key.

**Request:**
```json
{
  "method": "get_public_key",
  "params": []
}
```

**Response:**
```json
{
  "result": "abc123def456..."
}
```

#### sign_canonical

Sign a base64-encoded C2PA creator-binding payload. The payload must be a
creator-binding JSON object for the signing pubkey. Authorizations must permit
profile/identity signing.

**Request:**
```json
{
  "method": "sign_canonical",
  "params": ["<base64 creator-binding JSON bytes>"]
}
```

**Response:**
```json
{
  "result": "9baed2647e5f9d059b68eb03c6e3e6dcdf53cbe94fb143af70fb6e7332ee9997cc7ba5ac9cdb9049a0e47c8c20e2031843e88c59dcba3c3ff8fc34eeae4a565f"
}
```

#### nip44_encrypt

Encrypt a message using NIP-44.

**Request:**
```json
{
  "method": "nip44_encrypt",
  "params": ["recipient_pubkey_hex", "plaintext message"]
}
```

**Response:**
```json
{
  "result": "encrypted_ciphertext"
}
```

#### nip44_decrypt

Decrypt a NIP-44 encrypted message.

**Request:**
```json
{
  "method": "nip44_decrypt",
  "params": ["sender_pubkey_hex", "ciphertext"]
}
```

**Response:**
```json
{
  "result": "decrypted plaintext"
}
```

---

## Claim Flow (User-facing)

### GET /api/claim

Display the claim form for a user to set email/password.

**Request:**
```http
GET /api/claim?token=abc123xyz...
```

**Response:** HTML form

### POST /api/claim

Process the claim - sets email/password and logs user in.

**Request:**
```http
POST /api/claim
Content-Type: application/x-www-form-urlencoded

token=abc123xyz&email=user@example.com&password=secret123&password_confirmation=secret123
```

**Response:** Redirect to dashboard with session cookie set

**Errors:**
| Status | Description |
|--------|-------------|
| 400 | Invalid/expired token, passwords don't match, weak password, invalid email |
| 409 | Email already registered |

---

## Nostr Event Kinds Reference

| Kind | Description | NIP |
|------|-------------|-----|
| 0 | Profile metadata | NIP-01 |
| 1 | Text note | NIP-01 |
| 34235 | Normal video (longer, horizontal) | NIP-71 |
| 34236 | Short video (short-form, vertical/square) | NIP-71 |

### Kind 0 - Profile

```json
{
  "kind": 0,
  "content": "{\"name\":\"Alice\",\"about\":\"Bio\",\"picture\":\"https://...\",\"banner\":\"https://...\",\"nip05\":\"alice@example.com\",\"lud16\":\"alice@getalby.com\"}",
  "created_at": 1705000000,
  "tags": []
}
```

### Kind 1 - Text Note

```json
{
  "kind": 1,
  "content": "Hello Nostr!",
  "created_at": 1705000000,
  "tags": [
    ["p", "mentioned_pubkey_hex"],
    ["e", "replied_event_id", "relay_url", "reply"]
  ]
}
```

### Kind 34236 - Short Video (NIP-71)

Use 34236 for Vine videos (6-second square loops = short-form content).

```json
{
  "kind": 34236,
  "content": "Video description/caption",
  "created_at": 1705000000,
  "tags": [
    ["d", "unique-identifier"],
    ["title", "Video Title"],
    ["url", "https://cdn.example.com/video.mp4"],
    ["m", "video/mp4"],
    ["thumb", "https://cdn.example.com/thumbnail.jpg"],
    ["image", "https://cdn.example.com/poster.jpg"],
    ["duration", "6"],
    ["dim", "480x480"],
    ["published_at", "1420070400"],
    ["t", "hashtag1"],
    ["t", "hashtag2"]
  ]
}
```

---

## Error Response Format

All errors return JSON:

```json
{
  "error": "Error message description"
}
```

Common HTTP status codes:
- `400` - Bad request (invalid input)
- `401` - Unauthorized (missing/invalid token)
- `403` - Forbidden (not an admin, or not authorized)
- `404` - Not found
- `409` - Conflict (duplicate resource)
- `500` - Internal server error

---

## Email marketing consent (service token)

Six endpoints used by the marketing consent sync worker. They authenticate with
`KEYCAST_SERVICE_TOKEN` (constant-time bearer check), not with an admin UCAN, and every statement
is tenant-scoped.

keycast never calls the email platform. It records what happened; the sync worker acts on it.

### Two different facts, deliberately kept apart

- **The consent event** (`email_marketing_consent`, `_at`, `_source`, `_app_version`) is what
  somebody answered, when, from where, and under which app version. It is **immutable**. No
  endpoint here can write it: the observations endpoint's statement does not name those columns, so
  the guarantee holds structurally rather than by convention. Overwriting it would destroy the
  evidence that consent was validly obtained.
- **The suppression floor** (`email_marketing_global_optout`, `_observed_at`) records that somebody
  opted out of all email. It is **nullable, and NULL means never observed**, which is not the same
  as "not opted out". It exists because the email platform forgets an opt-out as soon as an address
  changes, so this is the only place that remembers. Any Divine system that sends marketing email
  must respect it, whatever CRM it uses.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/admin/email-marketing-consents` | Read consent by cursor |
| POST | `/api/admin/email-marketing-consents/observed` | Write the suppression floor |
| GET | `/api/admin/email-marketing-deletions` | Addresses whose account was deleted |
| POST | `/api/admin/email-marketing-deletions/ack` | Clear deletions once acted on |
| GET | `/api/admin/email-marketing-email-changes` | Addresses that moved |
| POST | `/api/admin/email-marketing-email-changes/ack` | Clear email changes once acted on |

### Cursor

`GET /api/admin/email-marketing-consents?since=<timestamp>&since_pubkey=<pubkey>&limit=<n>`

The cursor is the pair `(updated_at, pubkey)`, not a timestamp alone. Two accounts can share an
`updated_at`, and a timestamp-only cursor would either skip one or loop on it forever. A response
returns `next` only when the page was full; its absence means the caller has reached the end.
Omitting `since` starts from the beginning, which is how a backfill or a reconciliation sweep
enumerates everyone.

### Read then acknowledge

Deletions and email changes are read and cleared in **separate calls**. A worker that crashes
between the two replays the row rather than losing it. Losing a deletion means continuing to email
somebody who deleted their account; losing an email change means a duplicate contact with the old
address still subscribed. Acknowledging an unknown id is harmless.

### Why email changes are recorded at all

keycast overwrites `users.email` in place, so a changed row carries only the new address. The sync
worker needs the old one to find and move the existing contact. Without it, it would create a
second contact and leave the previous address subscribed indefinitely. The row is written inside the
same transaction that finalizes the change, capturing the outgoing address **before** the update
overwrites it.

Deletion and email-change rows are transient: they exist only until the worker has acted, which
bounds how long an address is retained past account deletion. Both are written only for accounts
whose consent state is `opted_in`, since those are the only contacts the sync created.
