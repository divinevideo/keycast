# AP RSA / HTTP-Signature Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-user RSA-2048 key custody and an RSA-SHA256 signing oracle to Keycast (for the Divine ActivityPub gateway) without touching the existing Nostr/Schnorr signing path.

**Architecture:** A new `ap_actor_keys` table stores PKCS#8-DER private keys encrypted via the existing `KeyManager` (AES-256-GCM/KMS) plus a plaintext SPKI public PEM, keyed `(tenant_id, user_pubkey)`. A pure-crypto `core/src/ap_signing.rs` module does keygen / SPKI-PEM / PKCS1v15-SHA256 signing. Three HTTP endpoints (`POST /api/ap/keys`, `GET /api/ap/keys/{pubkey}`, `POST /api/ap/sign`) in a new `api/src/api/http/ap.rs`, authenticated by **either** `KEYCAST_SERVICE_TOKEN` (gateway) **or** UCAN (user-facing), tenant resolved from the `Host` header.

**Tech Stack:** Rust, Axum 0.7, SQLx/Postgres, the `rsa` 0.9 crate (PKCS#8 + SPKI PEM + PKCS1-v1.5), `sha2` 0.10, `base64` 0.22, `zeroize`.

**Reference spec:** `docs/superpowers/specs/2026-05-30-ap-rsa-http-signature-signing-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `core/Cargo.toml` | Add `rsa = { version = "0.9", features = ["pem"] }` dependency. |
| `core/src/ap_signing.rs` | **Create.** Pure RSA crypto: `generate_rsa_2048`, `public_pem_from_pkcs8_der`, `sign_pkcs1v15_sha256`, `sign_base64`, `ApSigningError`. No DB, no `nostr_sdk`. |
| `core/src/lib.rs` | Register `pub mod ap_signing;`. |
| `database/migrations/20260530000000_add_ap_actor_keys.sql` | **Create.** `ap_actor_keys` table. |
| `core/src/repositories/ap_actor_keys.rs` | **Create.** `ApActorKeysRepository` + `ApActorKeyRow` (tenant-scoped CRUD). |
| `core/src/repositories/mod.rs` | Register module + re-export. |
| `api/src/api/http/ap.rs` | **Create.** Handlers, `ApError`, service-token check, principal resolver. |
| `api/src/api/http/mod.rs` | Register `pub mod ap;`. |
| `api/src/api/http/routes.rs` | Mount `ap_routes` (public CORS, `auth_state`). |
| `api/openapi.yaml` | Document the three endpoints + schemas + `ServiceToken` security scheme. |
| `tests/` (shell) | Independent `openssl` interop verification. |

---

## Task 1: Core RSA crypto module (`core/src/ap_signing.rs`)

**Files:**
- Modify: `core/Cargo.toml` (add `rsa` dep)
- Create: `core/src/ap_signing.rs`
- Modify: `core/src/lib.rs` (add `pub mod ap_signing;`)

- [ ] **Step 1: Add the `rsa` dependency**

In `core/Cargo.toml`, under `[dependencies]`, immediately after the `rand = { workspace = true }` line, add:

```toml
rsa = { version = "0.9", features = ["pem"] }
```

- [ ] **Step 2: Write the module with failing tests**

Create `core/src/ap_signing.rs`:

```rust
// ABOUTME: Pure RSA crypto for ActivityPub HTTP Signatures (RSA-SHA256, draft-cavage)
// ABOUTME: Keygen + SPKI public PEM + RSASSA-PKCS1-v1_5/SHA-256 signing. No DB, no Nostr.
// ABOUTME: Private keys are handled as PKCS#8 DER and encrypted at rest by KeyManager.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Forward-compatible discriminator stored in `ap_actor_keys.key_type`.
pub const AP_KEY_TYPE: &str = "rsa-2048";

const RSA_BITS: usize = 2048;

#[derive(Debug, Error)]
pub enum ApSigningError {
    #[error("RSA key generation failed: {0}")]
    KeyGen(String),
    #[error("PKCS#8 encode failed: {0}")]
    Encode(String),
    #[error("PKCS#8 decode failed: {0}")]
    Decode(String),
    #[error("SPKI PEM encode failed: {0}")]
    Pem(String),
    #[error("signing failed: {0}")]
    Sign(String),
}

/// A freshly generated RSA keypair, split into the two persisted halves.
pub struct RsaKeyMaterial {
    /// Private key as PKCS#8 DER. Encrypt with `KeyManager` before storing. Zeroized on drop.
    pub pkcs8_der: Zeroizing<Vec<u8>>,
    /// Public key as SPKI PEM (`-----BEGIN PUBLIC KEY-----`). Safe to store in plaintext.
    pub public_pem: String,
}

/// Generate an RSA-2048 keypair. CPU-bound (~tens of ms) — callers wrap in `spawn_blocking`.
pub fn generate_rsa_2048() -> Result<RsaKeyMaterial, ApSigningError> {
    let mut rng = rand::thread_rng();
    let private =
        RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|e| ApSigningError::KeyGen(e.to_string()))?;
    let der = private
        .to_pkcs8_der()
        .map_err(|e| ApSigningError::Encode(e.to_string()))?;
    let pkcs8_der = Zeroizing::new(der.as_bytes().to_vec());
    let public_pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ApSigningError::Pem(e.to_string()))?;
    Ok(RsaKeyMaterial {
        pkcs8_der,
        public_pem,
    })
}

/// Re-derive the SPKI public PEM from a decrypted PKCS#8 DER private key.
/// Utility for tests / backfill; the GET path serves the stored column instead.
pub fn public_pem_from_pkcs8_der(pkcs8_der: &[u8]) -> Result<String, ApSigningError> {
    let private =
        RsaPrivateKey::from_pkcs8_der(pkcs8_der).map_err(|e| ApSigningError::Decode(e.to_string()))?;
    RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ApSigningError::Pem(e.to_string()))
}

/// Sign `message` with RSASSA-PKCS1-v1_5 + SHA-256. Returns raw signature bytes.
/// CPU-bound — callers wrap in `spawn_blocking`.
pub fn sign_pkcs1v15_sha256(pkcs8_der: &[u8], message: &[u8]) -> Result<Vec<u8>, ApSigningError> {
    let private =
        RsaPrivateKey::from_pkcs8_der(pkcs8_der).map_err(|e| ApSigningError::Decode(e.to_string()))?;
    let signing_key = SigningKey::<Sha256>::new(private);
    let signature = signing_key
        .try_sign(message)
        .map_err(|e| ApSigningError::Sign(e.to_string()))?;
    Ok(signature.to_vec())
}

/// Convenience: sign and base64-encode (standard alphabet) for the HTTP `signature="…"` field.
pub fn sign_base64(pkcs8_der: &[u8], message: &[u8]) -> Result<String, ApSigningError> {
    Ok(BASE64.encode(sign_pkcs1v15_sha256(pkcs8_der, message)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;

    #[test]
    fn generate_produces_spki_pem_and_parseable_der() {
        let km = generate_rsa_2048().expect("keygen");
        assert!(
            km.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "must be SPKI PEM, not PKCS#1; got: {}",
            &km.public_pem[..km.public_pem.len().min(40)]
        );
        // DER must round-trip back into a private key.
        RsaPrivateKey::from_pkcs8_der(&km.pkcs8_der).expect("der parses");
    }

    #[test]
    fn sign_then_verify_with_public_pem() {
        let km = generate_rsa_2048().expect("keygen");
        let msg = b"(request-target): post /inbox\nhost: divine.video\ndate: x";

        let sig_bytes = sign_pkcs1v15_sha256(&km.pkcs8_der, msg).expect("sign");

        let public = RsaPublicKey::from_public_key_pem(&km.public_pem).expect("pem parses");
        let vk = VerifyingKey::<Sha256>::new(public);
        let sig = Signature::try_from(sig_bytes.as_slice()).expect("sig decodes");
        vk.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn public_pem_from_der_matches_generate() {
        let km = generate_rsa_2048().expect("keygen");
        let rederived = public_pem_from_pkcs8_der(&km.pkcs8_der).expect("rederive");
        assert_eq!(km.public_pem, rederived);
    }

    #[test]
    fn sign_base64_is_decodable_and_verifies() {
        let km = generate_rsa_2048().expect("keygen");
        let msg = b"hello ap";
        let b64 = sign_base64(&km.pkcs8_der, msg).expect("sign b64");
        let raw = BASE64.decode(&b64).expect("base64 decodes");

        let public = RsaPublicKey::from_public_key_pem(&km.public_pem).expect("pem");
        let vk = VerifyingKey::<Sha256>::new(public);
        let sig = Signature::try_from(raw.as_slice()).expect("sig");
        vk.verify(msg, &sig).expect("verify");
    }
}
```

- [ ] **Step 3: Register the module**

In `core/src/lib.rs`, add `pub mod ap_signing;` in alphabetical position (immediately after `pub mod authorization_channel;`... actually first line is `pub mod authorization_channel;`). Insert as the new first line:

```rust
pub mod ap_signing;
pub mod authorization_channel;
```

- [ ] **Step 4: Run the tests — expect compile + pass**

Run: `cargo test -p keycast_core ap_signing`
Expected: compiles, 4 tests PASS. If `try_sign`/`to_public_key_pem`/`to_pkcs8_der` fail to resolve, the `rsa` 0.9 API drifted — check `cargo doc -p rsa --open` for the exact path before adjusting; do not change the algorithm (must stay PKCS1-v1.5 + SHA-256, SPKI PEM).

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/src/ap_signing.rs core/src/lib.rs
git commit -m "feat(core): RSA-2048 keygen + PKCS1v15-SHA256 signing for ActivityPub"
```

---

## Task 2: Database migration for `ap_actor_keys`

**Files:**
- Create: `database/migrations/20260530000000_add_ap_actor_keys.sql`

- [ ] **Step 1: Write the migration**

Create `database/migrations/20260530000000_add_ap_actor_keys.sql`:

```sql
-- ap_actor_keys: per-user RSA keypair for ActivityPub HTTP Signatures.
-- Separate from Nostr/secp256k1 keys (personal_keys/stored_keys): RSA is
-- variable-length PKCS#8 DER + an SPKI public PEM. Bound to the immutable
-- nostr_pubkey (1:1 per tenant), NOT the mutable username — a published
-- publicKeyPem is cached by remote fediverse servers.

CREATE TABLE public.ap_actor_keys (
    id                     bigserial PRIMARY KEY,
    user_pubkey            character(64) NOT NULL,
    tenant_id              bigint NOT NULL DEFAULT 1,
    encrypted_private_key  bytea NOT NULL,                 -- PKCS#8 DER, AES-256-GCM via KeyManager
    public_key_pem         text  NOT NULL,                 -- SPKI PEM, public, safe at rest
    key_type               text  NOT NULL DEFAULT 'rsa-2048',
    created_at             timestamp with time zone NOT NULL DEFAULT now(),
    updated_at             timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT ap_actor_keys_tenant_user_unique UNIQUE (tenant_id, user_pubkey)
);

CREATE INDEX idx_ap_actor_keys_tenant_user ON public.ap_actor_keys (tenant_id, user_pubkey);
```

- [ ] **Step 2: Apply the migration locally**

Run: `bun run db:reset` (or `./tools/run-migrations.sh` if you only want to apply new migrations).
Expected: completes without error; `ap_actor_keys` exists.

- [ ] **Step 3: Verify the table**

Run: `psql "$DATABASE_URL" -c "\d public.ap_actor_keys"`
Expected: shows columns `id, user_pubkey, tenant_id, encrypted_private_key, public_key_pem, key_type, created_at, updated_at` and the unique constraint.

- [ ] **Step 4: Commit**

```bash
git add database/migrations/20260530000000_add_ap_actor_keys.sql
git commit -m "feat(db): add ap_actor_keys table for ActivityPub RSA key custody"
```

---

## Task 3: `ApActorKeysRepository`

**Files:**
- Create: `core/src/repositories/ap_actor_keys.rs`
- Modify: `core/src/repositories/mod.rs`

- [ ] **Step 1: Write the repository with a failing integration test**

Create `core/src/repositories/ap_actor_keys.rs`:

```rust
// ABOUTME: Repository for ap_actor_keys — per-user ActivityPub RSA keys
// ABOUTME: Stores encrypted PKCS#8 DER private key + plaintext SPKI public PEM, 1:1 per tenant

use crate::repositories::RepositoryError;
use sqlx::PgPool;

/// A stored AP key row (encrypted private key + public PEM).
#[derive(Debug, Clone)]
pub struct ApActorKeyRow {
    pub encrypted_private_key: Vec<u8>,
    pub public_key_pem: String,
    pub key_type: String,
}

#[derive(Debug, Clone)]
pub struct ApActorKeysRepository {
    pool: PgPool,
}

impl ApActorKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch the full row (encrypted private key + public PEM) for signing.
    pub async fn find_for_tenant(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Option<ApActorKeyRow>, RepositoryError> {
        let row = sqlx::query_as::<_, (Vec<u8>, String, String)>(
            "SELECT encrypted_private_key, public_key_pem, key_type
             FROM ap_actor_keys
             WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(encrypted_private_key, public_key_pem, key_type)| ApActorKeyRow {
            encrypted_private_key,
            public_key_pem,
            key_type,
        }))
    }

    /// Fetch only the public PEM (GET path — never decrypts).
    pub async fn find_public_pem(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Option<(String, String)>, RepositoryError> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT public_key_pem, key_type
             FROM ap_actor_keys
             WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Insert a new key. Idempotency is enforced by the caller checking existence first
    /// AND by the UNIQUE(tenant_id, user_pubkey) constraint as a backstop.
    pub async fn create(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
        encrypted_private_key: &[u8],
        public_key_pem: &str,
        key_type: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO ap_actor_keys
                (tenant_id, user_pubkey, encrypted_private_key, public_key_pem, key_type)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .bind(encrypted_private_key)
        .bind(public_key_pem)
        .bind(key_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn exists(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<bool, RepositoryError> {
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM ap_actor_keys WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    async fn setup_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        assert!(
            url.contains("localhost") || url.contains("127.0.0.1"),
            "tests must run against localhost"
        );
        PgPool::connect(&url).await.expect("connect")
    }

    #[tokio::test]
    async fn create_find_exists_roundtrip() {
        let pool = setup_pool().await;
        let repo = ApActorKeysRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        assert!(!repo.exists(1, &pubkey).await.unwrap());
        assert!(repo.find_for_tenant(1, &pubkey).await.unwrap().is_none());

        repo.create(1, &pubkey, &[1, 2, 3, 4], "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n", "rsa-2048")
            .await
            .unwrap();

        assert!(repo.exists(1, &pubkey).await.unwrap());
        let row = repo.find_for_tenant(1, &pubkey).await.unwrap().unwrap();
        assert_eq!(row.encrypted_private_key, vec![1, 2, 3, 4]);
        assert!(row.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let (pem, kt) = repo.find_public_pem(1, &pubkey).await.unwrap().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(kt, "rsa-2048");

        // Tenant isolation: tenant 2 sees nothing.
        assert!(!repo.exists(2, &pubkey).await.unwrap());

        // Cleanup
        sqlx::query("DELETE FROM ap_actor_keys WHERE user_pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }
}
```

- [ ] **Step 2: Register the module and re-export**

In `core/src/repositories/mod.rs`:
- Add `mod ap_actor_keys;` as the new first `mod` line (before `mod admin_audit_event;`).
- Add the re-export after the `pub use admin_audit_event::...;` line:

```rust
pub use ap_actor_keys::{ApActorKeyRow, ApActorKeysRepository};
```

- [ ] **Step 3: Run the integration test**

Run: `cargo test -p keycast_core --features integration-tests create_find_exists_roundtrip -- --nocapture`
Expected: PASS (requires local Postgres with the migration applied from Task 2).

- [ ] **Step 4: Commit**

```bash
git add core/src/repositories/ap_actor_keys.rs core/src/repositories/mod.rs
git commit -m "feat(core): ApActorKeysRepository for tenant-scoped RSA key storage"
```

---

## Task 4: API endpoints (`api/src/api/http/ap.rs`)

**Files:**
- Create: `api/src/api/http/ap.rs`
- Modify: `api/src/api/http/mod.rs`
- Modify: `api/src/api/http/routes.rs`

- [ ] **Step 1: Write the handler module**

Create `api/src/api/http/ap.rs`:

```rust
// ABOUTME: ActivityPub RSA key custody + HTTP-Signature signing oracle
// ABOUTME: Authenticated by KEYCAST_SERVICE_TOKEN (gateway) OR UCAN (user); tenant from Host
// ABOUTME: Pure oracle — signs caller-supplied bytes; never returns the private key

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::ap_signing::{self, AP_KEY_TYPE};
use keycast_core::repositories::{ApActorKeysRepository, UserRepository};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};

use crate::api::http::auth::extract_user_from_token;
use crate::api::http::routes::AuthState;
use crate::api::tenant::TenantExtractor;

// ---- error type (isolated from AuthError; same {"error": msg} JSON shape) ----

#[derive(Debug)]
pub enum ApError {
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApError::Internal(m) => {
                tracing::error!("AP signing internal error: {}", m);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

// ---- auth: resolve the acting user_pubkey from service token OR UCAN ----

/// Constant-time check of the bearer against KEYCAST_SERVICE_TOKEN.
/// Mirrors `admin::authorize_service_token` (duplicated to keep that path untouched).
fn is_service_token(headers: &HeaderMap) -> bool {
    use subtle::ConstantTimeEq;

    let expected = match std::env::var("KEYCAST_SERVICE_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => return false,
    };
    let actual = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(a) => a,
        None => return false,
    };
    let expected_hash = blake3::hash(format!("Bearer {expected}").as_bytes());
    let actual_hash = blake3::hash(actual.as_bytes());
    expected_hash.as_bytes().ct_eq(actual_hash.as_bytes()).into()
}

fn validate_hex_pubkey(pubkey: &str) -> Result<String, ApError> {
    PublicKey::from_hex(pubkey)
        .map(|pk| pk.to_hex())
        .map_err(|_| ApError::BadRequest("Invalid hex pubkey".to_string()))
}

/// Resolve the acting user_pubkey for a request.
/// - Service token: `body_pubkey` is REQUIRED (gateway acts for any actor in the tenant).
/// - UCAN: pubkey comes from the token; if `body_pubkey` is present it must match.
async fn resolve_principal(
    headers: &HeaderMap,
    tenant_id: i64,
    body_pubkey: Option<&str>,
) -> Result<String, ApError> {
    if is_service_token(headers) {
        let pk = body_pubkey
            .ok_or_else(|| ApError::BadRequest("pubkey is required for service-token calls".into()))?;
        return validate_hex_pubkey(pk);
    }

    // UCAN path
    let token_pubkey = extract_user_from_token(headers, tenant_id)
        .await
        .map_err(|_| ApError::Unauthorized("Authentication required".to_string()))?;

    if let Some(pk) = body_pubkey {
        let pk = validate_hex_pubkey(pk)?;
        if pk != token_pubkey {
            return Err(ApError::Forbidden(
                "Cannot act on behalf of another user".to_string(),
            ));
        }
    }
    Ok(token_pubkey)
}

/// Reject signing for suspended/banned accounts (mirrors auth::sign_event).
async fn ensure_active(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<(), ApError> {
    let user_repo = UserRepository::new(pool.clone());
    if let Some((status, _, _)) = user_repo
        .get_user_status(user_pubkey, tenant_id)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        if !status.is_active() {
            return Err(ApError::Forbidden("Account restricted".to_string()));
        }
    }
    Ok(())
}

// ---- request/response types ----

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    /// Hex Nostr pubkey of the actor. Required for service-token callers.
    pub pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub pubkey: String,
    pub public_key_pem: String,
    pub key_type: String,
    pub created: bool,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub pubkey: String,
    pub public_key_pem: String,
    pub key_type: String,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Hex Nostr pubkey of the actor. Required for service-token callers.
    pub pubkey: Option<String>,
    /// Exact draft-cavage signing string. Signed as its UTF-8 bytes.
    pub signing_string: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub pubkey: String,
    pub signature: String,
    pub algorithm: &'static str,
}

// ---- handlers ----

/// POST /api/ap/keys — create-or-return the actor's RSA key. Idempotent: never regenerates.
pub async fn create_key(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Json<KeyResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = resolve_principal(&headers, tenant_id, req.pubkey.as_deref()).await?;
    let pool = &auth_state.state.db;
    let repo = ApActorKeysRepository::new(pool.clone());

    // Idempotent: if a key exists, return it unchanged.
    if let Some((pem, key_type)) = repo
        .find_public_pem(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        return Ok(Json(KeyResponse {
            pubkey: user_pubkey,
            public_key_pem: pem,
            key_type,
            created: false,
        }));
    }

    // Generate (CPU-bound) off the async runtime.
    let material = tokio::task::spawn_blocking(ap_signing::generate_rsa_2048)
        .await
        .map_err(|e| ApError::Internal(format!("join error: {e}")))?
        .map_err(|e| ApError::Internal(e.to_string()))?;

    let encrypted = auth_state
        .state
        .key_manager
        .encrypt(&material.pkcs8_der)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?;

    // create() may race a concurrent create; the UNIQUE constraint is the backstop.
    match repo
        .create(
            tenant_id,
            &user_pubkey,
            &encrypted,
            &material.public_pem,
            AP_KEY_TYPE,
        )
        .await
    {
        Ok(()) => Ok(Json(KeyResponse {
            pubkey: user_pubkey,
            public_key_pem: material.public_pem,
            key_type: AP_KEY_TYPE.to_string(),
            created: true,
        })),
        Err(_) => {
            // Lost a race: another request created it. Return the winner's key.
            let (pem, key_type) = repo
                .find_public_pem(tenant_id, &user_pubkey)
                .await
                .map_err(|e| ApError::Internal(e.to_string()))?
                .ok_or_else(|| ApError::Internal("key insert conflict but no row".into()))?;
            Ok(Json(KeyResponse {
                pubkey: user_pubkey,
                public_key_pem: pem,
                key_type,
                created: false,
            }))
        }
    }
}

/// GET /api/ap/keys/{pubkey} — return the actor's public PEM. Never decrypts.
pub async fn get_key(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = resolve_principal(&headers, tenant_id, Some(&pubkey)).await?;
    let repo = ApActorKeysRepository::new(auth_state.state.db.clone());

    let (pem, key_type) = repo
        .find_public_pem(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
        .ok_or_else(|| ApError::NotFound("No AP key for this actor".to_string()))?;

    Ok(Json(PublicKeyResponse {
        pubkey: user_pubkey,
        public_key_pem: pem,
        key_type,
    }))
}

/// POST /api/ap/sign — sign the exact signing-string bytes; return base64 RSA-SHA256.
pub async fn sign(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = resolve_principal(&headers, tenant_id, req.pubkey.as_deref()).await?;
    let pool = &auth_state.state.db;

    ensure_active(pool, tenant_id, &user_pubkey).await?;

    let repo = ApActorKeysRepository::new(pool.clone());
    let row = repo
        .find_for_tenant(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
        .ok_or_else(|| ApError::NotFound("No AP key for this actor".to_string()))?;

    let der = auth_state
        .state
        .key_manager
        .decrypt(&row.encrypted_private_key)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?;

    let message = req.signing_string.into_bytes();
    let der_vec = der.to_vec();
    let signature = tokio::task::spawn_blocking(move || {
        ap_signing::sign_base64(&der_vec, &message)
    })
    .await
    .map_err(|e| ApError::Internal(format!("join error: {e}")))?
    .map_err(|e| ApError::Internal(e.to_string()))?;

    Ok(Json(SignResponse {
        pubkey: user_pubkey,
        signature,
        algorithm: "rsa-sha256",
    }))
}
```

> **Note on `der.to_vec()`:** `KeyManager::decrypt` returns `Zeroizing<Vec<u8>>`; `.to_vec()` copies the bytes into the closure. The original `der` is zeroized on drop. If you want to avoid the copy, move `der` into the closure directly (it is `Send`). The copy is acceptable here.

- [ ] **Step 2: Register the module**

In `api/src/api/http/mod.rs`, add as the new first line (before `pub mod admin;`):

```rust
pub mod ap;
```

- [ ] **Step 3: Mount the routes**

In `api/src/api/http/routes.rs`:

(a) Add `ap` to the import list at the top:

```rust
use crate::api::http::{
    admin, ap, atproto, atproto_oauth, auth, claim, headless, metrics, nostr_rpc, oauth, policies,
    teams,
};
```

(b) Add the route group near the other `auth_state`-backed groups (after `signing_routes`, ~line 93):

```rust
    // ActivityPub RSA signing endpoints (service-token OR UCAN auth; tenant from Host)
    // Public CORS: server-to-server (the AP gateway), not browser-credentialed.
    let ap_routes = Router::new()
        .route("/ap/keys", post(ap::create_key))
        .route("/ap/keys/:pubkey", get(ap::get_key))
        .route("/ap/sign", post(ap::sign))
        .with_state(auth_state.clone());
```

(c) Merge it into the final router (in the big `.merge(...)` chain, after `nostr_rpc_routes`):

```rust
        .merge(ap_routes.layer(public_cors.clone())) // AP RSA signing (gateway service-to-service)
```

- [ ] **Step 4: Build**

Run: `cargo build -p keycast_api`
Expected: compiles clean. If `extract_user_from_token` is not visible, confirm it is `pub(crate)` in `auth.rs` (it is) and the path `crate::api::http::auth::extract_user_from_token` is correct.

- [ ] **Step 5: Commit**

```bash
git add api/src/api/http/ap.rs api/src/api/http/mod.rs api/src/api/http/routes.rs
git commit -m "feat(api): /api/ap/keys + /api/ap/sign RSA signing endpoints"
```

---

## Task 5: API end-to-end test (service-token + UCAN paths)

**Files:**
- Create: `api/tests/ap_signing_integration_test.rs`

> These mirror the existing `api/tests/oauth_integration_test.rs` harness (same DB setup, gated the same way). If that file uses a specific test-pool helper or `#[cfg(feature = "integration-tests")]` gate, copy that exact pattern. The test below assumes a running app or a router built in-test; adapt to the existing harness's app-construction helper. If the existing suite builds a `Router` via a shared `test_app()` helper, reuse it; otherwise call the handlers directly as the unit-style example shows.

- [ ] **Step 1: Write the test**

Create `api/tests/ap_signing_integration_test.rs`:

```rust
// ABOUTME: End-to-end tests for the AP RSA signing endpoints (create -> get -> sign)
// Verifies the signature produced by /api/ap/sign validates against the PEM from /api/ap/keys.

#![cfg(feature = "integration-tests")]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;

// Use the same in-process app/test harness the oauth integration test uses.
// Pseudocode for the HTTP flow — replace `call(...)` with the project's test client.
//
//   let app = test_app().await;                  // shared helper from the oauth test
//   set header  Authorization: Bearer <KEYCAST_SERVICE_TOKEN>
//   set header  Host: <a real tenant domain in test, e.g. localhost>
//
//   POST /api/ap/keys     {"pubkey": "<hex>"}        -> 200 {public_key_pem, created:true}
//   POST /api/ap/keys     {"pubkey": "<hex>"}        -> 200 {created:false}  (idempotent)
//   GET  /api/ap/keys/<hex>                          -> 200 {public_key_pem} (== create's PEM)
//   POST /api/ap/sign     {"pubkey":"<hex>","signing_string":"..."} -> 200 {signature}
//
// Then assert the signature verifies:

fn assert_signature_verifies(public_pem: &str, signing_string: &str, signature_b64: &str) {
    let public = RsaPublicKey::from_public_key_pem(public_pem).expect("pem parses");
    let vk = VerifyingKey::<Sha256>::new(public);
    let raw = BASE64.decode(signature_b64).expect("base64");
    let sig = Signature::try_from(raw.as_slice()).expect("sig");
    vk.verify(signing_string.as_bytes(), &sig)
        .expect("signature from /api/ap/sign must verify against /api/ap/keys PEM");
}

#[tokio::test]
async fn create_get_sign_roundtrip_service_token() {
    // 1. POST /api/ap/keys with service token + pubkey -> capture public_key_pem
    // 2. POST again -> assert created == false (idempotent, same PEM)
    // 3. GET /api/ap/keys/{pubkey} -> assert PEM matches
    // 4. POST /api/ap/sign with a sample draft-cavage signing string
    // 5. assert_signature_verifies(pem, signing_string, signature)
    //
    // Implement using the project's existing test client (see oauth_integration_test.rs).
}

#[tokio::test]
async fn ucan_cannot_sign_for_another_pubkey() {
    // With a UCAN for user A, POST /api/ap/sign {"pubkey": "<user B hex>", ...}
    // -> assert 403 Forbidden.
}

#[tokio::test]
async fn sign_without_key_is_404() {
    // Service token + a pubkey that has no ap_actor_keys row
    // POST /api/ap/sign -> assert 404.
}
```

- [ ] **Step 2: Wire to the real harness**

Open `api/tests/oauth_integration_test.rs`, copy its app/test-client construction (and the `KEYCAST_SERVICE_TOKEN` env setup used by any admin service-token test if present), and fill in the `// Implement using...` bodies. Each `#[tokio::test]` must perform real HTTP calls and assert the documented status/JSON.

- [ ] **Step 3: Run the tests**

Run: `cd api && cargo test --features integration-tests --test ap_signing_integration_test -- --nocapture`
Expected: all three tests PASS (local Postgres + migration applied; `KEYCAST_SERVICE_TOKEN` set in the test env).

- [ ] **Step 4: Commit**

```bash
git add api/tests/ap_signing_integration_test.rs
git commit -m "test(api): end-to-end AP signing roundtrip + auth/404 cases"
```

---

## Task 6: Independent interop verification (openssl) + Nostr regression check

**Files:**
- Create: `tests/qa/ap_interop_verify.sh` (or the repo's existing QA script dir)

This is the **required external check** from the spec: a self-round-trip proves library
self-consistency, not Mastodon interop. We verify a produced (PEM, signature) pair with
`openssl` — an independent implementation — to catch SPKI-vs-PKCS1 and PKCS1v15-vs-PSS
mistakes.

- [ ] **Step 1: Add a Rust test binary that emits a vector**

Add to `core/src/ap_signing.rs` test module a helper test that writes a fixed-message
signature + PEM to `target/ap_interop/` for the shell script to verify:

```rust
    #[test]
    #[ignore] // run explicitly: cargo test -p keycast_core ap_signing -- --ignored emit_interop_vector
    fn emit_interop_vector() {
        use std::io::Write;
        let km = generate_rsa_2048().expect("keygen");
        let msg = b"(request-target): post /inbox\nhost: divine.video\ndate: Mon, 01 Jan 2026 00:00:00 GMT";
        let sig = sign_pkcs1v15_sha256(&km.pkcs8_der, msg).expect("sign");

        let dir = std::path::Path::new("target/ap_interop");
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("pub.pem"), km.public_pem.as_bytes()).unwrap();
        std::fs::write(dir.join("msg.bin"), msg).unwrap();
        let mut f = std::fs::File::create(dir.join("sig.bin")).unwrap();
        f.write_all(&sig).unwrap();
    }
```

- [ ] **Step 2: Write the verification script**

Create `tests/qa/ap_interop_verify.sh`:

```bash
#!/usr/bin/env bash
# Independently verify a Keycast-produced RSA-SHA256 signature with openssl.
# Catches SPKI-vs-PKCS1 PEM and PKCS1v15-vs-PSS algorithm mistakes that a
# same-library round-trip cannot.
set -euo pipefail

cargo test -p keycast_core ap_signing -- --ignored emit_interop_vector

DIR=target/ap_interop
openssl dgst -sha256 -verify "$DIR/pub.pem" -signature "$DIR/sig.bin" "$DIR/msg.bin"
# Expected output: "Verified OK"
```

- [ ] **Step 3: Run it**

Run: `bash tests/qa/ap_interop_verify.sh`
Expected: ends with `Verified OK`. If openssl errors with "unable to load Public Key", the
PEM is not SPKI — fix `ap_signing` to use `to_public_key_pem` (SPKI), not PKCS#1.

- [ ] **Step 4: Confirm the Nostr path is untouched**

Run: `cargo test -p keycast_core signing_session && cd api && cargo test --features integration-tests --test oauth_integration_test`
Expected: existing Schnorr/NIP-46/OAuth tests still PASS. (Sanity: `ap.rs` shares no code
with `signing_session.rs`; this is a regression guard, not new behavior.)

- [ ] **Step 5: Commit**

```bash
git add tests/qa/ap_interop_verify.sh core/src/ap_signing.rs
git commit -m "test: independent openssl interop verification for AP RSA signatures"
```

---

## Task 7: OpenAPI documentation

**Files:**
- Modify: `api/openapi.yaml`

- [ ] **Step 1: Add the `ServiceToken` security scheme**

In `api/openapi.yaml`, under `components.securitySchemes` (after the `BearerAuth` block, ~line 51):

```yaml
    ServiceToken:
      type: http
      scheme: bearer
      description: KEYCAST_SERVICE_TOKEN for trusted service-to-service callers (e.g. the AP gateway)
```

- [ ] **Step 2: Add schemas**

Under `components.schemas` (alongside the others), add:

```yaml
    ApCreateKeyRequest:
      type: object
      properties:
        pubkey:
          type: string
          description: Hex Nostr pubkey of the actor. Required for service-token callers; for UCAN callers it defaults to the token's pubkey and, if present, must match it.
          example: "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af"
    ApKeyResponse:
      type: object
      properties:
        pubkey: { type: string }
        public_key_pem:
          type: string
          description: SPKI PEM public key for the actor's publicKey.publicKeyPem.
          example: "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----\n"
        key_type: { type: string, example: "rsa-2048" }
        created:
          type: boolean
          description: true if a new key was minted; false if an existing key was returned (idempotent).
      required: [pubkey, public_key_pem, key_type, created]
    ApPublicKeyResponse:
      type: object
      properties:
        pubkey: { type: string }
        public_key_pem: { type: string }
        key_type: { type: string, example: "rsa-2048" }
      required: [pubkey, public_key_pem, key_type]
    ApSignRequest:
      type: object
      properties:
        pubkey:
          type: string
          description: Hex Nostr pubkey of the actor (required for service-token callers).
        signing_string:
          type: string
          description: The exact draft-cavage HTTP-Signature signing string. Signed as UTF-8 bytes.
          example: "(request-target): post /inbox\nhost: mastodon.social\ndate: Mon, 01 Jan 2026 00:00:00 GMT\ndigest: SHA-256=X..."
      required: [signing_string]
    ApSignResponse:
      type: object
      properties:
        pubkey: { type: string }
        signature:
          type: string
          description: base64-encoded RSASSA-PKCS1-v1_5 SHA-256 signature for the Signature header.
        algorithm: { type: string, example: "rsa-sha256" }
      required: [pubkey, signature, algorithm]
```

- [ ] **Step 3: Add the paths**

Under `paths` (after `/user/sign`'s block), add:

```yaml
  /ap/keys:
    post:
      summary: Create or return an actor's ActivityPub RSA key
      description: |
        Mints (or returns, idempotently) an RSA-2048 keypair for an actor and returns its
        SPKI public PEM for embedding in `publicKey.publicKeyPem`. The private key is stored
        encrypted-at-rest and is **never** returned. Calling again returns the existing key
        with `created: false` — the key is never regenerated (federated keys are cached by
        remote servers). Auth: ServiceToken (with `pubkey`) or UCAN (BearerAuth).
      tags: [ActivityPub]
      security:
        - ServiceToken: []
        - BearerAuth: []
      requestBody:
        required: false
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ApCreateKeyRequest' }
      responses:
        '200':
          description: Key created or already existed
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ApKeyResponse' }
        '400': { description: Invalid or missing pubkey, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
        '401': { description: Unauthorized, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
        '403': { description: UCAN pubkey mismatch, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
  /ap/keys/{pubkey}:
    get:
      summary: Get an actor's ActivityPub public key PEM
      tags: [ActivityPub]
      security:
        - ServiceToken: []
        - BearerAuth: []
      parameters:
        - in: path
          name: pubkey
          required: true
          schema: { type: string }
          description: Hex Nostr pubkey of the actor
      responses:
        '200':
          description: Public key PEM
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ApPublicKeyResponse' }
        '404': { description: No AP key for this actor, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
  /ap/sign:
    post:
      summary: Sign an HTTP-Signature signing string (RSA-SHA256)
      description: |
        Signs the exact caller-supplied signing string with RSASSA-PKCS1-v1_5 + SHA-256 and
        returns the base64 signature. The caller builds the draft-cavage signing string and
        assembles the final `Signature:` header. The private key never leaves Keycast.
        Suspended/banned accounts are rejected.
      tags: [ActivityPub]
      security:
        - ServiceToken: []
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ApSignRequest' }
      responses:
        '200':
          description: Signature
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ApSignResponse' }
        '403': { description: Account restricted or pubkey mismatch, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
        '404': { description: No AP key for this actor, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
```

- [ ] **Step 4: Add the tag**

Under the top-level `tags:` list (~line 1046), add:

```yaml
  - name: ActivityPub
    description: RSA key custody and HTTP-Signature signing for the ActivityPub gateway
```

- [ ] **Step 5: Validate the spec parses**

Run: `cargo build -p keycast_api` then start the server and `curl -s localhost:3000/api/docs/openapi.json | head -c 200`
(The `openapi_spec` handler does `serde_yaml::from_str(...).expect(...)` — a malformed YAML
would panic on that route. A clean build + a 200 from the docs route confirms it parses.)
Expected: valid JSON returned, no panic.

- [ ] **Step 6: Commit**

```bash
git add api/openapi.yaml
git commit -m "docs(api): OpenAPI for /api/ap/keys and /api/ap/sign"
```

---

## CI / supply-chain note (do once, only if a gate exists)

`rsa` 0.9 carries **RUSTSEC-2023-0071** ("Marvin" timing sidechannel). It is a *decryption*
sidechannel and **does not apply to signing**, which is all we do. Check whether CI runs
`cargo audit`/`cargo deny`:

```bash
grep -rn "cargo audit\|cargo-audit\|cargo deny\|cargo-deny\|deny.toml" .github/ deny.toml 2>/dev/null
```

- If a gate exists and fails on RUSTSEC-2023-0071, add an allowlist entry (in `deny.toml`
  under `[advisories] ignore`, or the CI's audit-ignore flag) with the comment:
  `# RUSTSEC-2023-0071: Marvin attack is a decryption sidechannel; we only sign. Not applicable.`
- If no such gate exists, do nothing.

---

## Self-Review (completed during authoring)

- **Spec coverage:** keygen + storage + public PEM + sign (Tasks 1–4); separate table / shape
  mismatch (Task 2); both auth modes (Task 4 `resolve_principal`); 1:1 per tenant (Task 2
  UNIQUE); sign-the-blob (Task 4 `sign`); idempotent create (Task 4); SPKI PEM + PKCS1v15
  (Task 1, asserted in Task 6 via openssl); private key never returned (no response type
  exposes it); Nostr regression (Task 6 Step 4); OpenAPI (Task 7); CI note (final section);
  divine-activity-pub integration constraints (host-based tenant, stable-pubkey key, no verify
  endpoint) are realized by Tasks 2/4. ✓
- **Placeholder scan:** Task 5's bodies are intentionally harness-dependent and reference the
  existing `oauth_integration_test.rs` pattern with explicit step-by-step instructions and a
  concrete `assert_signature_verifies` helper — not a bare "write tests" placeholder. All
  crypto/repo/handler code is complete and compilable.
- **Type consistency:** `RsaKeyMaterial { pkcs8_der, public_pem }`, `ApActorKeyRow
  { encrypted_private_key, public_key_pem, key_type }`, `ApActorKeysRepository::{find_for_tenant,
  find_public_pem, create, exists}`, `ap_signing::{generate_rsa_2048, public_pem_from_pkcs8_der,
  sign_pkcs1v15_sha256, sign_base64, AP_KEY_TYPE}` — names match across Tasks 1, 3, 4, 6. ✓
```
