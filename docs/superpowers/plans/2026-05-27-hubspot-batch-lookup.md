# HubSpot Batch Lookup Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /api/admin/users/batch-lookup` endpoint to Keycast so divine-invite-sync can enrich HubSpot contacts with account data.

**Architecture:** New service-token-authenticated endpoint that accepts a batch of emails and returns account enrichment data for matches. Follows the existing `authorize_service_token()` pattern used by relay-manager. New repo method queries users by email array using PostgreSQL `ANY()` operator, matching the existing `find_users_for_admin` batch pattern.

**Tech Stack:** Rust, Axum, SQLx, PostgreSQL

**Spec:** `docs/superpowers/specs/2026-05-27-hubspot-batch-lookup-design.md`
**Issue:** divinevideo/support-trust-safety#149

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `core/src/repositories/user.rs` | Add `find_users_by_emails()` batch query |
| Modify | `api/src/api/http/admin.rs` | Add request/response types + handler |
| Modify | `api/src/api/http/routes.rs` | Wire route into `service_admin_routes` |
| Create | `api/tests/batch_lookup_test.rs` | 11 integration tests |

---

### Task 1: Add batch email lookup to UserRepository

**Files:**
- Modify: `core/src/repositories/user.rs` (append after `find_users_for_admin`, ~line 1334)

- [ ] **Step 1: Write the repo method**

Add this method to the `impl UserRepository` block, after the existing `find_users_for_admin` method:

```rust
    /// Look up multiple users by email for enrichment (batch).
    /// Returns AdminUserDetails for each email that matches a user in the tenant.
    pub async fn find_users_by_emails(
        &self,
        emails: &[String],
        tenant_id: i64,
    ) -> Result<Vec<AdminUserDetails>, RepositoryError> {
        if emails.is_empty() {
            return Ok(vec![]);
        }

        let lowered: Vec<String> = emails.iter().map(|e| e.to_lowercase()).collect();

        let rows: Vec<AdminUserDetails> = sqlx::query_as(
            "SELECT
                u.pubkey,
                u.email,
                u.email_verified,
                u.username,
                u.display_name,
                u.vine_id,
                (pk.user_pubkey IS NOT NULL) as \"has_personal_key\",
                u.status,
                u.suspended_reason,
                u.created_at,
                u.updated_at
             FROM users u
             LEFT JOIN personal_keys pk ON pk.user_pubkey = u.pubkey AND pk.tenant_id = u.tenant_id
             WHERE LOWER(u.email) = ANY($1::text[]) AND u.tenant_id = $2",
        )
        .bind(&lowered)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `cd core && cargo check`
Expected: compiles with no errors

- [ ] **Step 3: Commit**

```bash
git add core/src/repositories/user.rs
git commit -m "feat: add find_users_by_emails batch query to UserRepository"
```

---

### Task 2: Add batch-lookup handler and types to admin.rs

**Files:**
- Modify: `api/src/api/http/admin.rs` (append in the service-token section, after `set_user_status_admin`)

- [ ] **Step 1: Add request/response types and handler**

Add these types and the handler function after the existing `set_user_status_admin` function (after ~line 1947, before the "Create approved minor account" comment):

```rust
// --- Batch user lookup by email (for divine-invite-sync HubSpot enrichment) ---

#[derive(Debug, Deserialize)]
pub struct BatchLookupRequest {
    pub emails: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchLookupUser {
    pub email: String,
    pub pubkey: String,
    pub status: String,
    pub email_verified: bool,
    pub has_personal_key: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct BatchLookupResponse {
    pub results: std::collections::HashMap<String, BatchLookupUser>,
    pub not_found: Vec<String>,
}

pub async fn batch_lookup_users(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<BatchLookupRequest>,
) -> ApiResult<Json<BatchLookupResponse>> {
    authorize_service_token(&headers)?;

    if req.emails.len() > 1000 {
        return Err(ApiError::bad_request(
            "Maximum 1000 emails per request",
        ));
    }

    // Deduplicate and lowercase before querying
    let deduped: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        req.emails
            .iter()
            .map(|e| e.to_lowercase())
            .filter(|e| seen.insert(e.clone()))
            .collect()
    };

    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(auth_state.state.db.clone());

    let users = user_repo
        .find_users_by_emails(&deduped, tenant_id)
        .await?;

    let mut results = std::collections::HashMap::new();
    let mut found_emails: std::collections::HashSet<String> = std::collections::HashSet::new();

    for user in users {
        if let Some(email) = &user.email {
            let lower = email.to_lowercase();
            found_emails.insert(lower.clone());
            results.insert(
                lower,
                BatchLookupUser {
                    email: email.clone(),
                    pubkey: user.pubkey,
                    status: user.status.as_str().to_string(),
                    email_verified: user.email_verified.unwrap_or(false),
                    has_personal_key: user.has_personal_key,
                    created_at: user.created_at.to_rfc3339(),
                },
            );
        }
    }

    let not_found: Vec<String> = deduped
        .into_iter()
        .filter(|e| !found_emails.contains(e))
        .collect();

    Ok(Json(BatchLookupResponse { results, not_found }))
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd api && cargo check`
Expected: compiles (handler not wired yet, but types and function compile)

- [ ] **Step 3: Commit**

```bash
git add api/src/api/http/admin.rs
git commit -m "feat: add batch_lookup_users handler for HubSpot enrichment"
```

---

### Task 3: Wire route into service_admin_routes

**Files:**
- Modify: `api/src/api/http/routes.rs:232-237` (the `service_admin_routes` block)

- [ ] **Step 1: Add the route**

Change the `service_admin_routes` block from:

```rust
    let service_admin_routes = Router::new()
        .route(
            "/admin/users/:pubkey/status",
            get(admin::get_user_status_admin).put(admin::set_user_status_admin),
        )
        .with_state(auth_state.clone());
```

To:

```rust
    let service_admin_routes = Router::new()
        .route(
            "/admin/users/:pubkey/status",
            get(admin::get_user_status_admin).put(admin::set_user_status_admin),
        )
        .route(
            "/admin/users/batch-lookup",
            post(admin::batch_lookup_users),
        )
        .with_state(auth_state.clone());
```

- [ ] **Step 2: Verify it compiles**

Run: `cd api && cargo check`
Expected: compiles with no errors

- [ ] **Step 3: Commit**

```bash
git add api/src/api/http/routes.rs
git commit -m "feat: wire batch-lookup route into service admin routes"
```

---

### Task 4: Integration tests

**Files:**
- Create: `api/tests/batch_lookup_test.rs`

- [ ] **Step 1: Check that `uuid` is available as a dev-dependency**

Run: `grep uuid api/Cargo.toml`

If `uuid` is not present, add it:
```bash
cd api && cargo add uuid --features v4 --dev
```

- [ ] **Step 2: Write integration tests**

Create `api/tests/batch_lookup_test.rs`:

```rust
#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{
        admin::{batch_lookup_users, BatchLookupRequest, BatchLookupResponse},
        routes::AuthState,
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::UserRepository,
    secret_pool::SecretPool,
    types::user::UserStatus,
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

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
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

    let state = auth_state.clone();

    Router::new().route(
        "/admin/users/batch-lookup",
        post(
            move |headers: axum::http::HeaderMap, Json(body): Json<BatchLookupRequest>| {
                let state = state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move { batch_lookup_users(tenant, State(state), headers, Json(body)).await }
            },
        ),
    )
}

async fn create_test_user_with_email(pool: &PgPool, email: &str) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, true, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");
    pubkey
}

async fn create_suspended_user_with_email(pool: &PgPool, email: &str) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, status, suspended_reason, suspended_at, created_at, updated_at) \
         VALUES ($1, $2, true, $3, 'suspended', 'age_review', NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");
    pubkey
}

async fn create_user_with_personal_key(pool: &PgPool, email: &str) -> String {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, true, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, tenant_id, encrypted_secret_key, created_at, updated_at) \
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(b"fake-encrypted-key".as_slice())
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    pubkey
}

fn post_batch_lookup(emails: &[&str], token: &str) -> Request<Body> {
    Request::post("/admin/users/batch-lookup")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({ "emails": emails })).unwrap(),
        ))
        .unwrap()
}

fn post_batch_lookup_body(body: Body, token: &str) -> Request<Body> {
    Request::post("/admin/users/batch-lookup")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

async fn parse_response(resp: axum::http::Response<Body>) -> BatchLookupResponse {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

// --- Test 1: Returns matching user with correct fields ---

#[tokio::test]
async fn test_batch_lookup_returns_matching_user() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("lookup-{}@example.com", uuid::Uuid::new_v4());
    let pubkey = create_test_user_with_email(&pool, &email).await;

    let resp = app.oneshot(post_batch_lookup(&[&email], SERVICE_TOKEN)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    assert!(result.not_found.is_empty());

    let user = result.results.get(&email).unwrap();
    assert_eq!(user.pubkey, pubkey);
    assert_eq!(user.status, "active");
    assert!(user.email_verified);
    assert!(!user.has_personal_key);
    assert!(!user.created_at.is_empty());
}

// --- Test 2: Mixed batch — some found, some not_found ---

#[tokio::test]
async fn test_batch_lookup_mixed_found_and_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email_a = format!("mixed-a-{}@example.com", uuid::Uuid::new_v4());
    let email_b = format!("mixed-b-{}@example.com", uuid::Uuid::new_v4());
    let email_missing = format!("mixed-missing-{}@example.com", uuid::Uuid::new_v4());

    let pubkey_a = create_test_user_with_email(&pool, &email_a).await;
    let pubkey_b = create_test_user_with_email(&pool, &email_b).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email_a, &email_missing, &email_b], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 2);
    assert_eq!(result.results.get(&email_a).unwrap().pubkey, pubkey_a);
    assert_eq!(result.results.get(&email_b).unwrap().pubkey, pubkey_b);
    assert_eq!(result.not_found, vec![email_missing]);
}

// --- Test 3: All unknown emails ---

#[tokio::test]
async fn test_batch_lookup_all_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_batch_lookup(&["nobody-a@example.com", "nobody-b@example.com"], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert!(result.results.is_empty());
    assert_eq!(result.not_found.len(), 2);
    assert!(result.not_found.contains(&"nobody-a@example.com".to_string()));
    assert!(result.not_found.contains(&"nobody-b@example.com".to_string()));
}

// --- Test 4: Duplicate emails deduplicated ---

#[tokio::test]
async fn test_batch_lookup_deduplicates_emails() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("dedup-{}@example.com", uuid::Uuid::new_v4());
    create_test_user_with_email(&pool, &email).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email, &email, &email], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    assert!(result.not_found.is_empty());
}

// --- Test 5: Over 1000 emails returns 400 ---

#[tokio::test]
async fn test_batch_lookup_rejects_over_1000_emails() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let emails: Vec<String> = (0..1001).map(|i| format!("email-{}@example.com", i)).collect();
    let body = serde_json::to_string(&serde_json::json!({ "emails": emails })).unwrap();

    let resp = app
        .oneshot(post_batch_lookup_body(Body::from(body), SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- Test 6: Missing auth header ---

#[tokio::test]
async fn test_batch_lookup_rejects_missing_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(
            Request::post("/admin/users/batch-lookup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({ "emails": ["a@b.com"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Test 7: Wrong token ---

#[tokio::test]
async fn test_batch_lookup_rejects_wrong_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_batch_lookup(&["a@b.com"], "wrong-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Test 8: Empty emails array ---

#[tokio::test]
async fn test_batch_lookup_empty_emails() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let resp = app
        .oneshot(post_batch_lookup(&[], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert!(result.results.is_empty());
    assert!(result.not_found.is_empty());
}

// --- Test 9: Case-insensitive email matching ---

#[tokio::test]
async fn test_batch_lookup_case_insensitive() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email_lower = format!("casetest-{}@example.com", uuid::Uuid::new_v4());
    let email_mixed = email_lower.replace("casetest", "CaseTest").replace("example.com", "Example.COM");
    let pubkey = create_test_user_with_email(&pool, &email_lower).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email_mixed], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    let user = result.results.get(&email_lower).unwrap();
    assert_eq!(user.pubkey, pubkey);
}

// --- Test 10: Suspended user returned with correct status ---

#[tokio::test]
async fn test_batch_lookup_returns_suspended_user() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email = format!("suspended-{}@example.com", uuid::Uuid::new_v4());
    let pubkey = create_suspended_user_with_email(&pool, &email).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 1);
    let user = result.results.get(&email).unwrap();
    assert_eq!(user.pubkey, pubkey);
    assert_eq!(user.status, "suspended");
}

// --- Test 11: has_personal_key true vs false in same batch ---

#[tokio::test]
async fn test_batch_lookup_has_personal_key_accuracy() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool.clone()));

    let email_with_key = format!("withkey-{}@example.com", uuid::Uuid::new_v4());
    let email_without_key = format!("nokey-{}@example.com", uuid::Uuid::new_v4());

    create_user_with_personal_key(&pool, &email_with_key).await;
    create_test_user_with_email(&pool, &email_without_key).await;

    let resp = app
        .oneshot(post_batch_lookup(&[&email_with_key, &email_without_key], SERVICE_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_response(resp).await;

    assert_eq!(result.results.len(), 2);
    assert!(result.results.get(&email_with_key).unwrap().has_personal_key);
    assert!(!result.results.get(&email_without_key).unwrap().has_personal_key);
}
```

- [ ] **Step 3: Verify tests compile**

Run: `cd api && cargo test --test batch_lookup_test --features integration-tests --no-run`
Expected: compiles successfully

- [ ] **Step 4: Run tests**

Run: `cd api && cargo test --test batch_lookup_test --features integration-tests -- --test-threads=1`
Expected: all 11 tests pass

- [ ] **Step 5: Run full existing test suite for regressions**

Run: `cd api && cargo test --features integration-tests -- --test-threads=1`
Expected: all existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add api/tests/batch_lookup_test.rs api/Cargo.toml
git commit -m "test: add integration tests for batch-lookup endpoint"
```
