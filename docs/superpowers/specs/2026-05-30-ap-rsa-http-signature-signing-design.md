# Design: RSA / ActivityPub HTTP-Signature signing in Keycast

**Date:** 2026-05-30
**Status:** Approved design → implementation plan
**Author:** rabble + Claude

## Problem

We're building an ActivityPub gateway ("Divine AP Gateway") that projects Divine's Nostr
users into the fediverse as `@user@divine.video` actors. Every ActivityPub actor must sign
its outbound HTTP requests with **RSA HTTP Signatures** (RSA-SHA256, draft-cavage-12). That
RSA key is separate from the user's Nostr (secp256k1) key and must be held in custody —
never exported.

Keycast is already our managed, encrypted, per-user key-custody service. It is currently
**Nostr / secp256k1 / Schnorr only**. We extend it so that, per user, it can additionally
generate, store (encrypted-at-rest), expose the public key for, and sign with an RSA-2048
keypair — without ever exporting the private key.

## Goals

Per user (1:1, scoped to a tenant):
1. **Generate** an RSA-2048 keypair on demand.
2. **Store** the private key encrypted-at-rest, reusing Keycast's existing `KeyManager`
   (AES-256-GCM via file/GCP/AWS KMS). No new encryption scheme.
3. **Expose the public key** as SPKI PEM (`-----BEGIN PUBLIC KEY-----`) for embedding in
   the actor document's `publicKey.publicKeyPem`.
4. **Sign** a caller-supplied signing-string on request, returning a base64 RSA-SHA256
   signature, **without exporting the private key**.

## Non-goals / hard constraints

- **Do NOT change or regress the Nostr signing path** (32-byte / Schnorr / NIP-46 /
  `/api/user/sign`). RSA is added strictly alongside, in new modules and a new table.
- Reuse the existing encryption-at-rest and tenant/authorization machinery.
- Private RSA keys are **never** returned by any endpoint.
- Keycast stays a pure signing oracle — it does **not** learn ActivityPub / AS2. The
  gateway builds the HTTP Signature "signing string" and assembles the final `Signature:`
  header; Keycast only signs bytes.

## Decisions (confirmed with stakeholder)

| Decision | Choice | Rationale |
|---|---|---|
| Schema | **New `ap_actor_keys` table** (mirrors `personal_keys`) | RSA is variable-length DER + a PEM public blob; `personal_keys`/`stored_keys` are secp256k1-shaped (`char(64)` pubkey, 32-byte secret). A separate table keeps the Nostr path literally untouched (hard constraint) rather than widening a hot, type-specific table. Justified on **shape mismatch**, not taste. |
| Key identity | **1:1 with `(tenant_id, user_pubkey)`** | "One user → their Nostr key AND their AP key." The request "actor id" resolves to a `user_pubkey`. Matches the existing `personal_keys` identity model exactly. |
| API shape | **Sign the blob only** | Keycast signs the exact signing-string bytes; the gateway owns draft-cavage/AS2 details. Mirrors the Nostr signer (sign a blob for a key). |
| Auth | **Both**: `KEYCAST_SERVICE_TOKEN` (service) **and** UCAN (user) | The gateway is backend infra acting for many actors → service token (matches `service_admin_routes` / relay-manager precedent). A user-facing path may also act on its own key via UCAN. |

## Crypto specifics (interop-critical — easy to get subtly wrong)

These must match Mastodon/Pixelfed exactly; a self-only round-trip will NOT catch a miss:

- **Public PEM = SPKI** (`-----BEGIN PUBLIC KEY-----`, X.509 SubjectPublicKeyInfo), via the
  `rsa` crate's `EncodePublicKey::to_public_key_pem()`. **Not** PKCS#1
  (`-----BEGIN RSA PUBLIC KEY-----`) — that silently fails interop.
- **Signature = RSASSA-PKCS1-v1_5 + SHA-256** (`rsa::pkcs1v15::SigningKey<Sha256>`).
  **Not** PSS — PSS verifies in our own round-trip but the fediverse rejects it.
- Signature is **base64-encoded** (standard, not URL-safe) — what goes in the `signature="…"`
  field of the header.
- Private key stored as **PKCS#8 DER** (`EncodePrivateKey::to_pkcs8_der()`), then handed to
  `KeyManager::encrypt(&[u8])` and persisted as `bytea`. Decrypt → `DecodePrivateKey` to sign.

## Architecture

```
                       ┌─────────────────────────────────────────┐
  Divine AP Gateway    │  Keycast                                 │
  (backend service) ──▶│  POST /api/ap/keys     ┐                 │
   service token       │  GET  /api/ap/keys/:pk ├─ api/.../ap.rs   │
   + user_pubkey       │  POST /api/ap/sign     ┘   (handlers)     │
                       │           │                               │
                       │           ▼                               │
                       │   ApActorKeysRepository (core/repos)      │
                       │           │            │                  │
                       │           ▼            ▼                  │
                       │   ap_actor_keys     KeyManager            │
                       │   (Postgres bytea)  (AES-256-GCM / KMS)   │
                       │           ▲                               │
                       │   ap_signing.rs (pure RSA crypto,         │
                       │   keygen / SPKI PEM / PKCS1v15-SHA256,     │
                       │   spawn_blocking)                         │
                       └─────────────────────────────────────────┘
```

### Components / module layout

1. **`core/src/ap_signing.rs`** — pure RSA crypto, the RSA analogue of `signing_session.rs`.
   - `generate_rsa_2048() -> RsaKeyMaterial` — generate keypair; return PKCS#8 DER (private,
     zeroizing) + SPKI PEM (public).
   - `public_pem_from_pkcs8_der(der: &[u8]) -> Result<String>` — utility to re-derive SPKI
     PEM from a decrypted private key (used by tests / backfill; the GET path serves the
     stored `public_key_pem` column and does **not** decrypt).
   - `sign_pkcs1v15_sha256(der: &[u8], message: &[u8]) -> Result<Vec<u8>>` — load PKCS#8 DER,
     sign, return raw signature bytes. CPU-bound RSA runs on `spawn_blocking` (mirrors the
     Nostr path). Base64 encoding happens in the handler.
   - `ApSigningError` (thiserror).
   - Does **not** touch `nostr_sdk` / `Keys` / Schnorr — fully isolated from the Nostr path.

2. **`core/src/repositories/ap_actor_keys.rs`** — `ApActorKeysRepository`, mirrors
   `PersonalKeysRepository`:
   - `find_for_tenant(tenant_id, user_pubkey) -> Option<ApActorKeyRow>` (encrypted private +
     public PEM).
   - `find_public_pem(tenant_id, user_pubkey) -> Option<String>`.
   - `create(tenant_id, user_pubkey, encrypted_private_key, public_key_pem)`.
   - `exists(tenant_id, user_pubkey) -> bool`.
   - Tenant-scoped queries throughout.

3. **`database/migrations/<timestamp>_add_ap_actor_keys.sql`** — new table (see Schema).
   **Note:** the task example `0009_*` is stale; the repo switched to `YYYYMMDDHHMMSS_*`
   naming (every migration since `20260328…`). We follow the repo convention and use a
   timestamped filename.

4. **`api/src/api/http/ap.rs`** — three handlers + a small auth resolver. Registered in
   `routes.rs` under a new `ap_routes` group with **public CORS** (server-to-server; not
   browser-credentialed) and `with_state(auth_state)`.

5. **`api/openapi.yaml`** — document the three endpoints + schemas.

6. **Cargo:** add `rsa = "0.9"` to the workspace and `core/Cargo.toml`. `sha2`, `base64`,
   `rand`, `zeroize` are already present. `subtle`/`blake3` (service-token compare) already
   used in `admin.rs`.

### Schema

```sql
CREATE TABLE public.ap_actor_keys (
    id                     bigserial PRIMARY KEY,
    user_pubkey            character(64) NOT NULL,
    tenant_id              bigint NOT NULL DEFAULT 1,
    encrypted_private_key  bytea NOT NULL,   -- PKCS#8 DER, AES-256-GCM via KeyManager
    public_key_pem         text  NOT NULL,   -- SPKI PEM, public, safe at rest
    key_type               text  NOT NULL DEFAULT 'rsa-2048',
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_pubkey)
);
CREATE INDEX idx_ap_actor_keys_tenant_user ON public.ap_actor_keys (tenant_id, user_pubkey);
```

- `public_key_pem` stored in plaintext (it is public) so GET and key creation never need a
  KMS decrypt. `key_type` is a forward-compat discriminator (default `rsa-2048`).
- No FK to `users` is strictly required (matches the loose coupling of `personal_keys`'
  tenant queries via JOIN); the `UNIQUE (tenant_id, user_pubkey)` enforces 1:1.

### API surface

All paths nested under `/api`. Request `pubkey` is the hex Nostr `user_pubkey` (the "actor
id" in our system). Tenant comes from `TenantExtractor` (host-based), as everywhere else.

**`POST /api/ap/keys`** — create-or-return (idempotent).
```jsonc
// request
{ "pubkey": "<hex user pubkey>" }   // pubkey REQUIRED for service-token caller;
                                    // for UCAN caller, omitted/derived from token
// 200
{ "pubkey": "<hex>", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n…", "key_type": "rsa-2048", "created": true }
```
If a key already exists, returns the existing public PEM with `"created": false` (idempotent,
never regenerates — regeneration would orphan the published actor key).

**`GET /api/ap/keys/{pubkey}`** — return public PEM.
```jsonc
// 200
{ "pubkey": "<hex>", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n…", "key_type": "rsa-2048" }
// 404 if no key exists for (tenant, pubkey)
```

**`POST /api/ap/sign`** — sign the exact signing-string bytes.
```jsonc
// request
{ "pubkey": "<hex>", "signing_string": "(request-target): post /inbox\nhost: …\ndate: …\ndigest: SHA-256=…" }
// 200
{ "pubkey": "<hex>", "signature": "<base64 RSA-SHA256>", "algorithm": "rsa-sha256" }
```
- `signing_string` is signed as its **exact UTF-8 bytes**. The gateway is responsible for
  building it per draft-cavage (newline-joined `header: value` lines, `(request-target)`
  lowercased method + path).
- 404 if no AP key exists for the actor (caller should `POST /api/ap/keys` first).

### Auth resolver (`ap.rs`)

A single helper resolves the acting `(user_pubkey, tenant_id)` from **either** auth mode:

```text
resolve_ap_principal(headers, tenant_id, body_pubkey) -> user_pubkey
  1. If Authorization bearer == KEYCAST_SERVICE_TOKEN (constant-time compare,
     reuse the admin.rs pattern: blake3 + subtle::ct_eq):
        require body_pubkey present  -> acting = body_pubkey
        (service is trusted to act for any actor in the tenant)
  2. Else attempt UCAN via extract_user_from_token(headers, tenant_id):
        acting = token pubkey
        if body_pubkey present AND != token pubkey -> 403 Forbidden
  3. Else -> 401.
```

- Account-status gate: before signing, check `UserRepository::get_user_status` and reject if
  not active — mirrors `sign_event` (`auth.rs:3151`). (Service token does not bypass this; a
  suspended user must not get fediverse signatures.)
- The `authorize_service_token` constant-time comparison logic is factored so both `ap.rs`
  and `admin.rs` share it (move to a small shared helper, or duplicate the ~10 lines if
  sharing introduces awkward coupling — decided at implementation time, no behavior change to
  admin).

## Data flow

**Create key (service token):** gateway `POST /api/ap/keys {pubkey}` → resolve principal →
if exists, return stored PEM → else `generate_rsa_2048()` (spawn_blocking) → `KeyManager::
encrypt(pkcs8_der)` → `repo.create(...)` → return SPKI PEM.

**Sign:** gateway builds signing string → `POST /api/ap/sign {pubkey, signing_string}` →
resolve principal → status check → `repo.find_for_tenant` → `KeyManager::decrypt` →
`sign_pkcs1v15_sha256(der, signing_string.as_bytes())` (spawn_blocking) → base64 → return.

## Error handling

- Reuse the established `AuthError` / `ApiError` enums in `api/`. New variants only if needed
  (e.g. an `ApKeyNotFound` → 404; RSA failures → 500 `Internal`, never leak key material in
  messages).
- `core` errors via a new `ApSigningError` (thiserror), mapped at the handler boundary.
- Decryption / DER-parse failures are 500s with generic messages.

## Testing

1. **Unit (`core/src/ap_signing.rs`):**
   - keygen produces a parseable PKCS#8 DER and an SPKI PEM beginning `-----BEGIN PUBLIC KEY-----`.
   - sign-then-verify round-trip using the `rsa` crate's verifier (library self-consistency).
2. **Interop (the real test — round-trip alone is insufficient):**
   - Verify a produced (PEM, signature) pair against an **independent implementation**:
     `openssl dgst -sha256 -verify pub.pem -signature sig.bin msg.txt` from a test/shell
     harness. This catches SPKI-vs-PKCS1 and PKCS1v15-vs-PSS mistakes that a self round-trip
     cannot.
   - If sourceable, assert against a **known-good draft-cavage-12 vector** (fixed key +
     signing string → fixed base64 signature).
3. **Storage round-trip:** encrypt PKCS#8 DER via `FileKeyManager`, decrypt, re-parse, sign —
   proves the existing `KeyManager` carries RSA bytes intact.
4. **API (integration, gated like existing oauth tests):** create→get→sign happy path under
   both service-token and UCAN auth; 403 when UCAN pubkey ≠ requested pubkey; 404 sign with
   no key; idempotent create.
5. **Regression — Nostr path intact:** the existing `signing_session.rs` and
   `oauth_integration_test` suites must pass unchanged. Add an explicit assertion that
   `/api/user/sign` (Schnorr) is untouched (no shared code path with `ap.rs`).

## CI / supply-chain note

`rsa` crate carries RUSTSEC-2023-0071 ("Marvin" timing sidechannel) — it is a **decryption**
sidechannel and **does not apply to signing**, which is all we do. If the repo has a
`cargo-audit`/`cargo-deny` gate, add an allowlist entry citing that rationale; if no such
gate exists, no action needed. This must not silently block CI.

## Integration with `divine-activity-pub` (the consuming service)

Cross-checked against the AP gateway's own design docs
(`divine-activity-pub/PLAN.md`, `wire-format.md`, dated 2026-05-30). The gateway's
plan explicitly lists this Keycast workstream as its dependency
(`PLAN.md` §Workstream handoffs: *"create/store RSA key per actor, return public PEM,
RSA-SHA256 sign endpoint"*) — the three endpoints here match that handoff exactly.
The following are the concrete contract points that make the two services line up:

1. **Key identity is the stable Nostr pubkey, not the username.** The gateway's `actors`
   table maps `nostr_pubkey` (hex) → `username` → `ap_actor_url` → `rsa_key_id` (a "keycast
   ref"). Usernames are mutable and the AP actor URL embeds the username, but a federated
   `publicKeyPem` is cached by every remote server that has seen it — so the key **must** be
   bound to the immutable identity. Keying by `(tenant_id, user_pubkey)` does exactly that.
   The gateway's `rsa_key_id` ref **is** the `user_pubkey` (hex) — no separate opaque key id
   is needed; the create/get responses echo `pubkey` for that purpose. (If the gateway
   prefers an opaque handle we can also return the row id, but pubkey is the natural join
   key and the default.)

2. **Idempotent create is load-bearing — never silently rotate.** Because remote servers
   cache the actor's public key, regenerating it would break signature verification for
   every existing follower until they refetch. `POST /api/ap/keys` therefore returns the
   existing key (`"created": false`) and **never** regenerates. (Key rotation, if ever
   needed, is a deliberate separate operation, out of scope here.)

3. **Keycast signs only; it does NOT verify.** The gateway's Phase 3 also needs to *verify*
   inbound HTTP Signatures from remote actors (`Follow`, etc.) — but that uses the **remote**
   actor's public key, which Keycast never holds. The gateway does inbound verification
   itself (its docs note WebCrypto if it ships as a CF Worker). **No verify endpoint is added
   to Keycast**, by design — stating this so nobody expects one.

4. **The gateway owns all HTTP-Signature/AS2 structure; Keycast supplies two opaque values.**
   - `publicKey.id` (`<actorUrl>#main-key`), `publicKey.owner` (the actor URL), and the
     `keyId` in the `Signature:` header are all constructed by the gateway. Keycast supplies
     only `publicKeyPem`.
   - For each outbound request the gateway builds the draft-cavage signing string —
     `(request-target) host date digest` for POST (`digest` = `SHA-256=base64(sha256(body))`),
     `(request-target) host date` for GET — and passes that exact multi-line string as
     `signing_string`. Keycast signs its UTF-8 bytes and returns base64. The gateway pastes
     the result into `signature="…"`. This is why the "sign the blob" shape (not
     "build the header") is correct: the gateway already knows the method/target/host/date
     from the request it is about to make.

5. **Auth: the gateway will use the service token.** The gateway is trusted backend infra
   signing on behalf of every Divine actor (its runtime is leaning toward a CF Worker, which
   holds `KEYCAST_SERVICE_TOKEN` as a secret and acts for all actors) — so in practice it
   uses the service-token path with an explicit `pubkey` in each request body. The UCAN path
   we also build is for any future user-facing caller; the gateway itself will not use it.

6. **Tenant is resolved from the `Host` header — the gateway must address the right host.**
   `TenantExtractor` derives the tenant from `Host`/`x-forwarded-host` (`tenant.rs:87`),
   and this applies even to service-token routes. The gateway must therefore call Keycast at
   the tenant-appropriate host (e.g. `https://login.divine.video/api/ap/...`) so it lands on
   the `divine.video` tenant; the service token authenticates *who* is calling, the host
   selects *which tenant's* keyspace. (Calling a wrong/missing host would resolve the wrong
   tenant and 404 on the actor's key — a likely first-integration footgun, called out here.)

7. **Scope: Divine-origin (outbound) actors only.** The gateway's `RESEARCH.md` (§inbound)
   notes a *second*, deferred custodial concern: minting **surrogate Nostr identities** for
   remote AP actors (`@alice@mastodon.social`) so inbound Follow/Like/Comment can map into
   Nostr. That is unrelated to this work — remote actors keep their own RSA keys on their
   home servers; Keycast never signs for them. Keycast RSA custody here is exclusively for
   **Divine-origin actors signing their own outbound requests**. If a future surrogate
   identity is itself given a Divine Nostr pubkey, it would slot into the same
   `(tenant_id, user_pubkey)` model for free, but no design accommodation is made for it now.

## Rollout

- Pure additive: new table, new modules, new routes, one new dependency. No change to
  existing tables, handlers, or the Nostr signer.
- Migration runs via the existing `sqlx::migrate!` path (`keycast --migrate` Cloud Run Job in
  `cloudbuild.yaml`).
- `KEYCAST_SERVICE_TOKEN` already provisioned for relay-manager/COOP; the AP gateway reuses it.
```
