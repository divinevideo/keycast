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

Claiming an account is a two-step, email-confirmed flow: submitting the claim
form stages the entered email/password and sends a confirmation link, and the
claim only completes when that link is clicked.

### GET /api/claim

Display the claim form for a user to set email/password.

**Request:**
```http
GET /api/claim?token=abc123xyz...
```

**Response:** HTML form

### POST /api/claim

Stage the claim: validates the token and inputs, checks the email isn't
already taken, and stores the entered email/password hash on the claim-token
row pending confirmation. Sends a confirmation email to the entered address.

**Request:**
```http
POST /api/claim
Content-Type: application/x-www-form-urlencoded

token=abc123xyz&email=user@example.com&password=secret123&password_confirmation=secret123
```

**Response:** 200, HTML "Check your email" interstitial. No session cookie is set at this step.

**Errors:**
| Status | Description |
|--------|-------------|
| 400 | Invalid/expired token, passwords don't match, weak password, invalid email |
| 409 | Email already registered |

### GET /api/claim/confirm

Complete the claim: consumes the confirmation token from the emailed link,
writes the staged email/password onto the user account, and issues the
session.

**Request:**
```http
GET /api/claim/confirm?token=<confirmation_token>
```

**Response:** 200, HTML "Account Claimed" success page, with `Set-Cookie: keycast_session=...` establishing the session.

**Errors:**
| Status | Description |
|--------|-------------|
| 400 | Confirmation link unrecognized/expired, staged email taken by another account, or the underlying claim token died before confirmation |

### POST /api/claim/resend

Re-send the confirmation email for a staged claim. Cooldown-gated (5
minutes) and enumeration-safe: the response is always the same generic
"check your email" interstitial regardless of whether the token is unknown,
has no staged claim, is within cooldown, or a fresh email was just sent, so a
caller cannot use the response to probe for a pending claim.

**Request:**
```http
POST /api/claim/resend
Content-Type: application/x-www-form-urlencoded

token=abc123xyz
```

**Response:** 200, HTML "Check your email" interstitial.

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

Six endpoints used by the marketing consent sync worker. They authenticate with the dedicated
`KEYCAST_EMAIL_MARKETING_SERVICE_TOKEN` (constant-time bearer check), not with an admin UCAN and
not with the broader `KEYCAST_SERVICE_TOKEN`, and every statement is tenant-scoped.

This credential is deliberately separate from `KEYCAST_SERVICE_TOKEN`, the same way
`KEYCAST_DELETION_SERVICE_TOKEN` is kept separate for the account-deletion endpoint (see
`docs/SERVICE_ACCOUNT_DELETION.md`): the broader service credential also authorizes unrelated
administration and signing operations, while the marketing sync worker needs authority only over
these six endpoints. The marketing credential cannot authorize unrelated service-admin routes, and
the broader service credential cannot authorize these endpoints.

keycast never calls the email platform. It records what happened; the sync worker acts on it.

### Two different facts, deliberately kept apart

- **The consent event** (`email_marketing_consent`, `_at`, `_source`, `_app_version`) is what
  somebody answered, when, from where, and under which app version. It is **immutable**. No
  endpoint here can write it: the observations endpoint's statement does not name those columns, so
  the guarantee holds structurally rather than by convention. Overwriting it would destroy the
  evidence that consent was validly obtained. `consent_at` is the time the account materialized
  (after email verification), not the time the checkbox was shown.
- **The suppression floor** (`email_marketing_global_optout`, `_observed_at`) records that somebody
  opted out of all email. It is **nullable, and NULL means no floor recorded**. A false observation
  writes nothing, so the column never holds FALSE and NULL covers both "never checked" and "checked
  and not opted out". The migration comment still describes an unreachable tri-state; it is left
  alone deliberately, because editing an applied migration changes its sqlx checksum and breaks any
  environment that already ran it. It exists because the email platform forgets an opt-out as soon as an address
  changes, so this is the only place that remembers. Any Divine system that sends marketing email
  must respect it, whatever CRM it uses. The observations endpoint is write-once to `true`: a
  `global_optout: false` observation is a no-op (`updated: 0`) and does not lift a recorded floor.
  An observation batch is capped at 1,000 rows and must contain unique pubkeys. Its response
  separates changed accounts (`updated`) from expected no-ops (`unchanged`) and missing live
  accounts (`not_found`); consumers must surface `not_found` rather than silently discarding it.

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

The cursor is the pair `(email_marketing_consent_at, pubkey)`, not `updated_at` and not a
timestamp alone. A consent answer is immutable, so each one is read exactly once. Ordering on
`updated_at` re-triggered a subscribe after any unrelated account change and could reverse a
granular unsubscribe. Two accounts can share a consent timestamp, and a timestamp-only cursor
would either skip one or loop on it forever. A response returns `next` only when the page was
full; its absence means the caller has reached the end. Omitting `since` starts from the
beginning and enumerates accounts that have a consent event (`consent_at IS NOT NULL`), not
accounts nobody asked.

### The floor snapshot on email changes

An email-change row carries `global_optout`: the suppression floor as it stood when the change was
finalized. It is a **second source, not a replacement** for asking the email platform. A consumer
should treat somebody as opted out if **either** says so.

The value served is the account's live floor where one is recorded, falling back to the row's snapshot. The snapshot is frozen at insert time, so a withdrawal recorded after the row was written would otherwise be invisible on a replay of that row, exactly when the consumer's own lookup has stopped working too. The live column is write-once-true, so preferring it can only be more suppressive.

The snapshot covers what a lookup cannot. If somebody changes address twice before the drain runs,
the row reads `B -> C` while the platform no longer knows `B`, so a lookup returns nothing and an
opt-out becomes invisible.

The lookup covers what the snapshot cannot. The value is copied from
`users.email_marketing_global_optout`, which only the reconciliation sweep maintains, a page of
accounts at a time. It is therefore as old as that account's last sweep, which on a large tenant is
days. `false` means "not opted out when we last looked", never "not opted out", and NULL means never
observed. Only `true` settles the question alone, because `true` is permanent.

### Read then acknowledge

Deletions and email changes are read and cleared in **separate calls**. A worker that crashes
between the two replays the row rather than losing it. Losing a deletion means continuing to email
somebody who deleted their account; losing an email change means a duplicate contact with the old
address still subscribed. Acknowledging an unknown id is harmless.

The optional `since=<id>` parameter on both queue reads is only for paging within one drain pass.
Start each new pass without `since`, then advance it while that pass has more rows. Do not persist
the high-water id between passes: reclaimed-address guards can temporarily withhold an older row,
and it must become visible again if the address is later released. Acknowledgement, not `since`, is
what permanently removes completed work.

Deleting an account **folds its undrained email changes into the deletion**. Any pending
`email_marketing_email_changes` row for that pubkey contributes a tombstone for its `old_email`, and
the change rows are removed in the same transaction. The queue therefore names every address the
email platform may hold for that person, so no drain order can produce a wrong answer.

This replaces an earlier rule requiring consumers to drain email-changes before deletions. That rule
was correct and still insufficient: it lived only in this document, and the first consumer written
against it ran the two queues concurrently. Where correctness can be established in the data, it
should not depend on a consumer remembering a paragraph.

One ordering still matters, and belongs to the consumer because only it knows what it has read: a
worker that read an email-change row before the account was deleted should apply it before draining
deletions in the same pass. Otherwise it removes the tombstone first (a `DELETE` of an address the
platform does not hold is a success, not a no-op) and then recreates the contact from the row it is
still holding.

Keycast also suppresses a deletion row from the list response when the same tenant has a live
`opted_in` account for that address. The server-side guard prevents an old tombstone from deleting
the current holder's contact; it deliberately does not compare timestamps because either reclaim
order can leave a stale tombstone pointing at somebody else's contact.

A deletion tombstone and a later consent for the same address can coexist: hard-delete frees the
mailbox, so a new account can opt in before the worker drains. **The deletions endpoint withholds
these rows**; a tombstone is not served while a live account holds that address with an opted-in
consent. Acting on one would remove the current holder's contact, and it
would not heal, because the forward cursor has already passed their `consent_at`. The row remains
queued rather than being dropped, so it is served again if the address is released.

Consumers need no rule for this case. `GET /api/admin/email-marketing-consents` returns the account's
current email, not the address at consent time; after an email change the consent row already
shows the new address, so treating an `old → new` email-change as a HubSpot move of a contact
created at `new` is the worker's to make idempotent.

The email-change endpoint applies the same reclaimed-address rule to `old_email`. A queued move is
not served while another live opted-in account holds that address, regardless of whether the reclaim
happened before or after the row was written. The email platform identifies the contact by address,
so serving the stale move would rename the current holder's contact to somebody else's new address.
The row remains queued and becomes eligible again if the address is released. If it is not released
before the retention window closes, the row is purged undrained: the moving account's contact is
never relocated, stays at an address another account now owns, and is overwritten by that account's
next upsert. The moving account then loses the subscription it opted into. Keycast logs a count of
withheld rows on every read so this is visible before the window closes.

### Why email changes are recorded at all

keycast overwrites `users.email` in place, so a changed row carries only the new address. The sync
worker needs the old one to find and move the existing contact. Without it, it would create a
second contact and leave the previous address subscribed indefinitely. The row is written inside the
same transaction that finalizes the change, capturing the outgoing address **before** the update
overwrites it.

Deletion and email-change rows exist until the worker acks them or their 14-day retention window
ends. Keycast's five-minute background cleanup task deletes expired rows independently of reads from
the sync worker. Both queues are written only for accounts whose consent state is `opted_in`, since
those are the only contacts the sync created. If the worker cannot deliver a deletion inside the
window, privacy retention wins: the queued address is removed even though the external contact may
remain until another reconciliation catches it.
