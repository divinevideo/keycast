# verified_minor lifecycle (clear primitive + revocation endpoint) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the missing path that clears `verified_minor`, plus a service-token admin endpoint relay-manager calls on revocation, with a durable audit trail.

**Architecture:** A single-purpose repository method (`clear_verified_minor`) sets the two minor columns false/null and nothing else; a `DELETE` admin endpoint wraps it with service-token auth, optional `actor`/`reason` query params, reason sanitization, and a best-effort `admin_audit_events` row. Clear-only by design so it serves both age-up (status untouched) and revocation (caller sets status separately).

**Tech Stack:** Rust, axum, sqlx (Postgres), tokio, existing keycast test harness (`integration-tests` feature).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-01-verified-minor-lifecycle-design.md`. This plan implements it verbatim.
- No schema migration (`verified_minor`, `verified_minor_at` already exist).
- Multi-tenant: every query is scoped by `tenant_id`.
- Clear-only: the primitive and endpoint MUST NOT alter `status`, `suspended_reason`, or `suspended_at`.
- Idempotent: clearing an already-cleared or never-minor account succeeds; unknown pubkey → 404.
- Audit row is best-effort enrichment: a failed insert logs an error and the clear still succeeds.
- Repo integration tests need `DATABASE_URL` pointing at a localhost Postgres; API tests run under `--features integration-tests` and use `common::setup_test_db()`.

---

### Task 1: Repository primitive `clear_verified_minor`

**Files:**
- Modify: `core/src/repositories/user.rs` (add method near `get_verified_minor`, ~line 1392; add tests in the existing `#[cfg(test)] mod tests`, ~line 1900)

**Interfaces:**
- Produces: `UserRepository::clear_verified_minor(&self, pubkey: &str, tenant_id: i64) -> Result<(), RepositoryError>`

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `core/src/repositories/user.rs`. These mirror the existing `setup_pool()` / `Keys::generate()` pattern already in that module.

```rust
#[tokio::test]
async fn test_clear_verified_minor_clears_flag_and_timestamp() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = Keys::generate().public_key().to_hex();

    // Create a verified-minor user directly.
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, 1, TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .execute(&pool)
    .await
    .unwrap();

    repo.clear_verified_minor(&pubkey, 1).await.unwrap();

    let (verified_minor, verified_minor_at) =
        repo.get_verified_minor(&pubkey, 1).await.unwrap().unwrap();
    assert!(!verified_minor);
    assert!(verified_minor_at.is_none());
}

#[tokio::test]
async fn test_clear_verified_minor_idempotent_on_already_cleared() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = Keys::generate().public_key().to_hex();

    // Plain user, verified_minor already FALSE (column default).
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW())",
    )
    .bind(&pubkey)
    .execute(&pool)
    .await
    .unwrap();

    // Clearing a never-minor / already-cleared account succeeds (no-op).
    repo.clear_verified_minor(&pubkey, 1).await.unwrap();
    repo.clear_verified_minor(&pubkey, 1).await.unwrap();
}

#[tokio::test]
async fn test_clear_verified_minor_unknown_pubkey_not_found() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool);
    let pubkey = Keys::generate().public_key().to_hex();

    let result = repo.clear_verified_minor(&pubkey, 1).await;
    assert!(matches!(result, Err(RepositoryError::NotFound(_))));
}

#[tokio::test]
async fn test_clear_verified_minor_leaves_status_untouched() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = Keys::generate().public_key().to_hex();

    // Suspended verified-minor.
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, status, suspended_reason, suspended_at, created_at, updated_at) \
         VALUES ($1, 1, TRUE, NOW(), 'suspended', 'age_review', NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .execute(&pool)
    .await
    .unwrap();

    repo.clear_verified_minor(&pubkey, 1).await.unwrap();

    let (status, suspended_reason, suspended_at, verified_minor, _) =
        repo.get_full_admin_status(&pubkey, 1).await.unwrap().unwrap();
    assert_eq!(status.as_str(), "suspended");
    assert_eq!(suspended_reason.as_deref(), Some("age_review"));
    assert!(suspended_at.is_some());
    assert!(!verified_minor);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd core && DATABASE_URL="postgres://postgres:postgres@localhost/keycast_test" cargo test clear_verified_minor -- --test-threads=1`
Expected: FAIL to compile with `no method named clear_verified_minor found`.

- [ ] **Step 3: Write the minimal implementation**

Add to `core/src/repositories/user.rs`, immediately after `get_verified_minor` (before `get_full_admin_status`):

```rust
/// Clear the verified_minor designation (age-up or revocation).
/// Idempotent: clearing an already-cleared or never-minor account succeeds.
/// Returns NotFound only when the user does not exist. Touches only the two
/// minor columns plus updated_at; never alters status/suspended_reason/suspended_at.
pub async fn clear_verified_minor(
    &self,
    pubkey: &str,
    tenant_id: i64,
) -> Result<(), RepositoryError> {
    let result = sqlx::query(
        "UPDATE users SET verified_minor = FALSE, verified_minor_at = NULL, updated_at = $3 \
         WHERE pubkey = $1 AND tenant_id = $2",
    )
    .bind(pubkey)
    .bind(tenant_id)
    .bind(Utc::now())
    .execute(&self.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(RepositoryError::NotFound("user not found".to_string()));
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd core && DATABASE_URL="postgres://postgres:postgres@localhost/keycast_test" cargo test clear_verified_minor -- --test-threads=1`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/repositories/user.rs
git commit -m "feat(minor-safety): add clear_verified_minor repository primitive (#265)"
```

---

### Task 2: `DELETE` clear endpoint (auth, clear, 404, response)

**Files:**
- Modify: `api/src/api/http/admin.rs` (add `ClearVerifiedMinorParams`, helper `sanitize_reason`, handler `clear_verified_minor_admin` near `set_user_status_admin`, ~line 1945)
- Modify: `api/src/api/http/routes.rs:238-248` (register the route in `service_admin_routes`)
- Create: `api/tests/clear_verified_minor_test.rs`

**Interfaces:**
- Consumes: `UserRepository::clear_verified_minor` (Task 1); `UserRepository::get_full_admin_status`; `UserStatusResponse`; `authorize_service_token`.
- Produces: `pub async fn clear_verified_minor_admin(tenant, State(auth_state), headers, Path(pubkey), Query(params)) -> ApiResult<Json<UserStatusResponse>>`; `pub struct ClearVerifiedMinorParams { pub actor: Option<String>, pub reason: Option<String> }`; `fn sanitize_reason(Option<String>) -> Option<String>`.

- [ ] **Step 1: Write the failing tests**

Create `api/tests/clear_verified_minor_test.rs`. This reuses the exact harness pattern from `api/tests/user_status_admin_test.rs` (TestKeyManager, `create_test_auth_state`, service-token auth, `common::setup_test_db`).

```rust
// ABOUTME: HTTP-layer tests for the service-token clear-verified_minor endpoint
// ABOUTME: Tests DELETE /admin/users/:pubkey/verified-minor auth, clear, audit

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::delete,
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{
        admin::{clear_verified_minor_admin, ClearVerifiedMinorParams, UserStatusResponse},
        routes::AuthState,
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const SERVICE_TOKEN: &str = "test-service-token-secret";

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }
    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

fn create_test_auth_state(pool: PgPool) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));
    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
        }),
        auth_tx: None,
    }
}

fn build_app(auth_state: AuthState) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};
    let del_state = auth_state.clone();
    Router::new().route(
        "/admin/users/:pubkey/verified-minor",
        delete(
            move |axum::extract::Path(pubkey): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  axum::extract::Query(params): axum::extract::Query<ClearVerifiedMinorParams>| {
                let state = del_state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    clear_verified_minor_admin(
                        tenant,
                        State(state),
                        headers,
                        axum::extract::Path(pubkey),
                        axum::extract::Query(params),
                    )
                    .await
                }
            },
        ),
    )
}

async fn create_verified_minor_user(pool: &PgPool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("create verified minor");
    pubkey
}

#[tokio::test]
async fn test_clear_verified_minor_clears_and_returns_status() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&body).unwrap();
    assert!(!status.verified_minor);
    assert!(status.verified_minor_at.is_none());
}

#[tokio::test]
async fn test_clear_verified_minor_missing_auth() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_clear_verified_minor_wrong_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .header("authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_clear_verified_minor_unknown_pubkey_404() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let fake = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", fake))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd api && cargo test --features integration-tests --test clear_verified_minor_test 2>&1 | head -30`
Expected: FAIL to compile — `clear_verified_minor_admin` and `ClearVerifiedMinorParams` do not exist.

- [ ] **Step 3: Write the minimal implementation**

In `api/src/api/http/admin.rs`, add after `set_user_status_admin` (before `create_minor_account`). `Query` must be imported from `axum::extract` (add to the existing axum use if absent).

```rust
/// Query params for the clear-verified_minor endpoint. Both optional; `actor`
/// (the moderator's hex pubkey) drives the durable audit row.
#[derive(Debug, Deserialize)]
pub struct ClearVerifiedMinorParams {
    pub actor: Option<String>,
    pub reason: Option<String>,
}

/// Bound and strip control characters from a caller-supplied reason before it
/// is logged or persisted (prevents log injection and unbounded audit rows).
/// Returns None when empty after cleaning.
fn sanitize_reason(raw: Option<String>) -> Option<String> {
    let cleaned: String = raw?
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub async fn clear_verified_minor_admin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
    axum::extract::Query(params): axum::extract::Query<ClearVerifiedMinorParams>,
) -> ApiResult<Json<UserStatusResponse>> {
    authorize_service_token(&headers)?;
    let tenant_id = tenant.0.id;

    // Validate the optional actor as a 64-char hex pubkey so a T&S action never
    // silently loses its audit trail to a malformed actor.
    if let Some(actor) = params.actor.as_deref() {
        if actor.len() != 64 || !actor.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request(
                "actor must be a 64-character hex pubkey",
            ));
        }
    }

    let reason_clean = sanitize_reason(params.reason);

    let user_repo = UserRepository::new(auth_state.state.db.clone());
    user_repo.clear_verified_minor(&pubkey, tenant_id).await?;

    tracing::info!(
        event = "verified_minor_cleared",
        pubkey = %pubkey,
        actor = ?params.actor,
        reason = ?reason_clean,
        "Admin cleared verified_minor"
    );

    let (status, suspended_reason, suspended_at, verified_minor, verified_minor_at) = user_repo
        .get_full_admin_status(&pubkey, tenant_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(Json(UserStatusResponse {
        pubkey,
        status: status.as_str().to_string(),
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    }))
}
```

Register the route in `api/src/api/http/routes.rs` inside `service_admin_routes` (after the `/status` route, ~line 242):

```rust
.route(
    "/admin/users/:pubkey/verified-minor",
    delete(admin::clear_verified_minor_admin),
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd api && cargo test --features integration-tests --test clear_verified_minor_test 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add api/src/api/http/admin.rs api/src/api/http/routes.rs api/tests/clear_verified_minor_test.rs
git commit -m "feat(minor-safety): add DELETE clear-verified_minor endpoint (#265)"
```

---

### Task 3: Durable audit row on clear (with actor)

**Files:**
- Modify: `api/src/api/http/admin.rs` (add the best-effort audit write inside `clear_verified_minor_admin`)
- Modify: `api/tests/clear_verified_minor_test.rs` (add audit + sanitization tests)

**Interfaces:**
- Consumes: `AdminAuditEventRepository`, `AdminAuditEventRecord` (already imported in admin.rs at line 17).

- [ ] **Step 1: Write the failing tests**

Append to `api/tests/clear_verified_minor_test.rs`. Add the audit-row reader (mirrors `read_audit_rows` in `registered_clients_audit_test.rs`).

```rust
#[derive(sqlx::FromRow)]
struct AuditRow {
    actor_pubkey: String,
    action: String,
    target_resource_type: String,
    target_resource_id: Option<String>,
    metadata_json: serde_json::Value,
}

async fn read_audit_rows(pool: &PgPool, actor_pubkey: &str) -> Vec<AuditRow> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT actor_pubkey, action, target_resource_type, target_resource_id, metadata_json \
         FROM admin_audit_events WHERE tenant_id = $1 AND actor_pubkey = $2",
    )
    .bind(TENANT_ID)
    .bind(actor_pubkey)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn test_clear_with_actor_writes_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/verified-minor?actor={}&reason=re-review%20denied",
                    pubkey, actor
                ))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "clear_verified_minor");
    assert_eq!(rows[0].actor_pubkey, actor);
    assert_eq!(rows[0].target_resource_type, "user");
    assert_eq!(rows[0].target_resource_id.as_deref(), Some(pubkey.as_str()));
    assert_eq!(rows[0].metadata_json["reason"], "re-review denied");
}

#[tokio::test]
async fn test_clear_without_actor_writes_no_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    // No audit row keyed to any actor for this pubkey (target_resource_id).
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM admin_audit_events WHERE target_resource_id = $1 AND action = 'clear_verified_minor'",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn test_clear_malformed_actor_400_and_flag_intact() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}/verified-minor?actor=not-hex", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Flag must NOT have been cleared (validation happens before the clear).
    let row: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row.0);
}

#[tokio::test]
async fn test_clear_reason_sanitized_in_audit() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let pubkey = create_verified_minor_user(&pool).await;
    let actor = Keys::generate().public_key().to_hex();

    // reason with an embedded newline (control char) + long padding.
    let long = "x".repeat(600);
    let raw_reason = format!("line1%0Aline2{}", long); // %0A = \n url-encoded
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/verified-minor?actor={}&reason={}",
                    pubkey, actor, raw_reason
                ))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    let reason = rows[0].metadata_json["reason"].as_str().unwrap();
    assert!(!reason.contains('\n'), "control chars must be stripped");
    assert!(reason.chars().count() <= 500, "reason must be bounded to 500");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd api && cargo test --features integration-tests --test clear_verified_minor_test 2>&1 | tail -20`
Expected: `test_clear_with_actor_writes_audit_row` and `test_clear_reason_sanitized_in_audit` FAIL (no audit row written); the malformed-actor and no-actor tests already pass from Task 2.

- [ ] **Step 3: Write the minimal implementation**

In `clear_verified_minor_admin` (admin.rs), insert the best-effort audit write between the `tracing::info!` line and the `get_full_admin_status` call:

```rust
    // Durable audit row (best-effort) when an actor is supplied. The table's
    // actor_pubkey is NOT NULL, so no actor -> log-only. A failed insert logs
    // and the clear still succeeds. (keycast#279 raises the same bar for status changes.)
    if let Some(actor) = params.actor.as_deref() {
        let audit_repo = AdminAuditEventRepository::new(auth_state.state.db.clone());
        if let Err(error) = audit_repo
            .record(AdminAuditEventRecord {
                tenant_id,
                actor_pubkey: actor.to_string(),
                action: "clear_verified_minor".to_string(),
                target_resource_type: "user".to_string(),
                target_resource_id: Some(pubkey.clone()),
                target_client_id: None,
                metadata_json: serde_json::json!({ "reason": reason_clean }),
            })
            .await
        {
            tracing::error!(
                pubkey = %pubkey,
                error = %error,
                "Failed to write admin_audit_events row for verified_minor clear"
            );
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd api && cargo test --features integration-tests --test clear_verified_minor_test 2>&1 | tail -20`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add api/src/api/http/admin.rs api/tests/clear_verified_minor_test.rs
git commit -m "feat(minor-safety): durable audit row on verified_minor clear (#265)"
```

---

### Task 4: Full-suite check + lint

**Files:** none (verification only)

- [ ] **Step 1: Clippy + fmt**

Run: `cargo fmt --all && cargo clippy --all-targets --features integration-tests -- -D warnings 2>&1 | tail -20`
Expected: no warnings.

- [ ] **Step 2: Run the touched test suites green**

Run: `cd core && DATABASE_URL="postgres://postgres:postgres@localhost/keycast_test" cargo test clear_verified_minor -- --test-threads=1` then `cd api && cargo test --features integration-tests --test clear_verified_minor_test`
Expected: all PASS.

- [ ] **Step 3: Commit any fmt changes**

```bash
git add -A && git commit -m "style(minor-safety): fmt/clippy for verified_minor lifecycle (#265)" || echo "nothing to commit"
```

## Self-Review

**Spec coverage:** repo primitive (Task 1) ✔; endpoint + auth + 404 + response (Task 2) ✔; actor validation, reason sanitization, durable audit, log-only fallback (Tasks 2-3) ✔; 11 spec tests map to Task1×4 + Task2×4 + Task3×4 (12; the extra splits spec test 6 into missing-auth + wrong-token) ✔; no-migration honored ✔; clear-only / status-untouched enforced + tested (Task1 test 4) ✔. Deferrals (#147, #179, #279) are out-of-scope by design.

**Placeholder scan:** none — every code step carries full code.

**Type consistency:** `clear_verified_minor(&str, i64) -> Result<(), RepositoryError>`, `ClearVerifiedMinorParams { actor, reason }`, `clear_verified_minor_admin(...) -> ApiResult<Json<UserStatusResponse>>`, and the `AdminAuditEventRecord` fields match `admin.rs:1566` usage and the repo signatures verified in the spec.
