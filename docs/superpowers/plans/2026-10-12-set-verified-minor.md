# Set verified_minor on an existing account — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a service-token `PUT /api/admin/users/:pubkey/verified-minor` that confers `verified_minor` on an existing keycast account, so relay-manager can make an age-review approval durable.

**Architecture:** A single-statement repository method mirrors `clear_verified_minor` in the set direction and reports one of four outcomes. A thin handler mirrors `clear_verified_minor_admin` (auth, actor validation, reason sanitizing, cache invalidation, best-effort audit) and refuses credential-less rows with 409.

**Tech Stack:** Rust, axum, sqlx (Postgres), tokio tests behind the `integration-tests` feature.

**Spec:** relay-manager issue #192 (age-review approval confers durable approved-minor state); the spec lives in that repo's PR.

## Global Constraints

- Work only in the `set-verified-minor` worktree of this repo, on branch `feat/set-verified-minor` (based on `origin/main` `c749054`).
- **Push nothing, open no PR, file no issue.** Matt gives the go for each. Commits are local.
- No `Co-Authored-By` or Claude attribution lines in commits.
- Route: `PUT /api/admin/users/:pubkey/verified-minor`, service-admin group, `KEYCAST_SERVICE_TOKEN` bearer auth.
- 409 body for a credential-less row: `{"error": "account_unclaimed: account has no login credentials"}` (relay-manager matches the substring `account_unclaimed`).
- 404 body for an unknown pubkey stays `{"error": "user not found"}` (relay-manager's `isKeycastUserNotFound` matches it exactly).
- Never touch `status`, `suspended_reason`, `suspended_at`, or claim tokens.
- Never truncate pubkeys in logs or tests.
- Before every commit: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated`.

## Review Focus

- An onboarded, still-unclaimed minor (flag already TRUE, no email or password) must return 200 `AlreadySet`, not 409. The guard only blocks the FALSE→TRUE write.
- A retry after a lost response must not write a second audit row or move `verified_minor_at`.
- Setting the flag must invalidate the account-status cache, or the DM gate keeps the stale `verified_minor: false` until expiry.
- A suspended account stays suspended with its reason after a set (relay-manager composes status separately).
- Another tenant's row with the same pubkey must be untouched.

---

### Task 1: Repository `set_verified_minor`

**Files:**
- Modify: `core/src/repositories/user.rs` (new enum near `VerifiedMinorRow` ~line 412; new method directly after `clear_verified_minor` ~line 2395; tests in the `#[cfg(all(test, feature = "integration-tests"))] mod tests` after `test_clear_verified_minor_leaves_status_untouched` ~line 4868)

**Interfaces:**
- Produces: `pub enum SetVerifiedMinorOutcome { Set, AlreadySet, Unclaimed }` and `pub async fn set_verified_minor(&self, pubkey: &str, tenant_id: i64) -> Result<SetVerifiedMinorOutcome, RepositoryError>`; a missing row is `Err(RepositoryError::NotFound("user not found"))`.

- [ ] **Step 1: Bring up test dependencies and confirm the baseline**

```bash
# from the repository (worktree) root
test -f master.key || ./scripts/generate_key.sh
bun run deps:up
docker exec keycast-postgres psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'keycast_test'" | grep -q 1 || docker exec keycast-postgres createdb -U postgres keycast_test
DATABASE_URL=postgres://postgres:password@localhost:5432/keycast_test cargo run --bin keycast -- --migrate
DATABASE_URL=postgres://postgres:password@localhost:5432/keycast_test cargo test -p keycast_core --features integration-tests --lib verified_minor
```
Expected: the existing `test_clear_verified_minor_*` tests PASS.

- [ ] **Step 2: Write the failing repo tests**

Append inside `mod tests`:

```rust
    async fn insert_user_row(pool: &PgPool, pubkey: &str, tenant_id: i64, minor: bool, with_credentials: bool) {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, verified_minor, verified_minor_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 THEN NOW() - INTERVAL '1 day' END, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day')",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(with_credentials.then(|| format!("{}@example.test", &pubkey[..16])))
        .bind(with_credentials.then(|| "$2b$04$placeholderhashplaceholderhashplaceholderha".to_string()))
        .bind(minor)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_set_verified_minor_sets_flag_and_timestamp() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        insert_user_row(&pool, &pubkey, 1, false, true).await;

        let outcome = repo.set_verified_minor(&pubkey, 1).await.unwrap();
        assert_eq!(outcome, SetVerifiedMinorOutcome::Set);

        let row = repo.get_verified_minor(&pubkey, 1).await.unwrap().unwrap();
        assert!(row.verified_minor);
        assert!(row.verified_minor_at.is_some());
        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_set_verified_minor_already_set_is_noop_and_keeps_timestamp() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        insert_user_row(&pool, &pubkey, 1, true, true).await;
        let (before_at, before_updated): (Option<DateTime<Utc>>, DateTime<Utc>) = sqlx::query_as(
            "SELECT verified_minor_at, updated_at FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

        let outcome = repo.set_verified_minor(&pubkey, 1).await.unwrap();
        assert_eq!(outcome, SetVerifiedMinorOutcome::AlreadySet);

        let (after_at, after_updated): (Option<DateTime<Utc>>, DateTime<Utc>) = sqlx::query_as(
            "SELECT verified_minor_at, updated_at FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(before_at, after_at, "original verified_minor_at must be preserved");
        assert_eq!(before_updated, after_updated, "a no-op must not bump updated_at");
        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_set_verified_minor_refuses_credentialless_row() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        insert_user_row(&pool, &pubkey, 1, false, false).await;

        let outcome = repo.set_verified_minor(&pubkey, 1).await.unwrap();
        assert_eq!(outcome, SetVerifiedMinorOutcome::Unclaimed);
        let row = repo.get_verified_minor(&pubkey, 1).await.unwrap().unwrap();
        assert!(!row.verified_minor, "a credential-less row must not be flagged");
        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_set_verified_minor_onboarded_unclaimed_minor_is_already_set() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        insert_user_row(&pool, &pubkey, 1, true, false).await;

        let outcome = repo.set_verified_minor(&pubkey, 1).await.unwrap();
        assert_eq!(outcome, SetVerifiedMinorOutcome::AlreadySet);
        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_set_verified_minor_is_tenant_scoped() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        insert_user_row(&pool, &pubkey, 1, false, true).await;

        let err = repo.set_verified_minor(&pubkey, 999_999).await.unwrap_err();
        assert!(matches!(err, RepositoryError::NotFound(_)));
        let row = repo.get_verified_minor(&pubkey, 1).await.unwrap().unwrap();
        assert!(!row.verified_minor, "another tenant's set must not touch this row");
        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_set_verified_minor_unknown_pubkey_not_found() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        let err = repo.set_verified_minor(&pubkey, 1).await.unwrap_err();
        assert!(matches!(err, RepositoryError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_set_verified_minor_leaves_status_untouched() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();
        insert_user_row(&pool, &pubkey, 1, false, true).await;
        sqlx::query(
            "UPDATE users SET status = 'suspended', suspended_reason = 'age_review', suspended_at = NOW() \
             WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        repo.set_verified_minor(&pubkey, 1).await.unwrap();

        let (status, reason): (String, Option<String>) = sqlx::query_as(
            "SELECT status, suspended_reason FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "suspended");
        assert_eq!(reason.as_deref(), Some("age_review"));
        cleanup_user(&pool, &pubkey).await;
    }
```

If `users` has a NOT NULL or CHECK constraint the fixture violates (for example on `password_hash` format), adjust the fixture values only, not the assertions.

- [ ] **Step 3: Run to verify failure**

Run: `DATABASE_URL=postgres://postgres:password@localhost:5432/keycast_test cargo test -p keycast_core --features integration-tests --lib set_verified_minor`
Expected: compile error, `set_verified_minor` / `SetVerifiedMinorOutcome` not found.

- [ ] **Step 4: Implement**

Near `VerifiedMinorRow`:

```rust
/// Outcome of [`UserRepository::set_verified_minor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVerifiedMinorOutcome {
    /// The flag went FALSE -> TRUE and `verified_minor_at` was stamped.
    Set,
    /// The flag was already TRUE. Nothing was written.
    AlreadySet,
    /// The row has neither an email nor a password hash. Refused without a write:
    /// keycast reads `verified_minor AND email IS NULL AND password_hash IS NULL` as an
    /// unclaimed minor, and create-minor-account re-issues claim links for those by
    /// username, so flagging a credential-less row would make it claimable.
    Unclaimed,
}
```

After `clear_verified_minor`:

```rust
    /// Confer the verified_minor designation on an existing account (age-review
    /// approval). The set-direction mirror of [`Self::clear_verified_minor`]: one
    /// statement distinguishes a missing user, an already-set flag, a refused
    /// credential-less row, and a real transition. Touches only the two minor columns
    /// plus updated_at, and only on a transition.
    pub async fn set_verified_minor(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<SetVerifiedMinorOutcome, RepositoryError> {
        let (user_exists, already_set, credentialless, transitioned): (bool, bool, bool, bool) =
            sqlx::query_as(
                "WITH existing AS ( \
                     SELECT verified_minor, (email IS NULL AND password_hash IS NULL) AS credentialless \
                     FROM users WHERE pubkey = $1 AND tenant_id = $2 \
                 ), changed AS ( \
                     UPDATE users \
                     SET verified_minor = TRUE, verified_minor_at = $3, updated_at = $3 \
                     WHERE pubkey = $1 AND tenant_id = $2 AND verified_minor = FALSE \
                       AND NOT (email IS NULL AND password_hash IS NULL) \
                     RETURNING 1 \
                 ) \
                 SELECT EXISTS (SELECT 1 FROM existing), \
                        COALESCE((SELECT verified_minor FROM existing), FALSE), \
                        COALESCE((SELECT credentialless FROM existing), FALSE), \
                        EXISTS (SELECT 1 FROM changed)",
            )
            .bind(pubkey)
            .bind(tenant_id)
            .bind(Utc::now())
            .fetch_one(&self.pool)
            .await?;

        if !user_exists {
            return Err(RepositoryError::NotFound("user not found".to_string()));
        }
        // The CTE reads the pre-update snapshot, so `already_set` is the state before
        // this call; `transitioned` is the only signal that a write happened.
        Ok(if transitioned {
            SetVerifiedMinorOutcome::Set
        } else if already_set {
            SetVerifiedMinorOutcome::AlreadySet
        } else if credentialless {
            SetVerifiedMinorOutcome::Unclaimed
        } else {
            // Unreachable under the WHERE clause above; fail loudly rather than
            // report a write that did not happen.
            return Err(RepositoryError::Database(
                "set_verified_minor: no outcome matched a present row".to_string(),
            ));
        })
    }
```

- [ ] **Step 5: Run to verify pass**

Run: `DATABASE_URL=postgres://postgres:password@localhost:5432/keycast_test cargo test -p keycast_core --features integration-tests --lib verified_minor`
Expected: all new and existing `verified_minor` tests PASS.

- [ ] **Step 6: Mutation-check the guard (one guard per mutation)**

Back up the file to a temp location first and restore it by copy (never `git checkout`):
```bash
cp core/src/repositories/user.rs "$TMPDIR/user.rs.bak"
```
Delete only the line `AND NOT (email IS NULL AND password_hash IS NULL) \` from the `changed` CTE, rerun Step 5. Expected: only `test_set_verified_minor_refuses_credentialless_row` fails. Restore with `cp <backup> core/src/repositories/user.rs`. Then change `verified_minor = FALSE` to `TRUE OR verified_minor = FALSE` in the `changed` CTE; expected: only `..._already_set_is_noop_and_keeps_timestamp` fails. Restore and rerun Step 5 green.

- [ ] **Step 7: Lint and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated
git add core/src/repositories/user.rs
git commit -m "feat(minor-safety): repository primitive to set verified_minor on an existing account"
```

---

### Task 2: `PUT /admin/users/:pubkey/verified-minor` handler and route

**Files:**
- Modify: `api/src/api/http/admin.rs` (rename `ClearVerifiedMinorParams` → `VerifiedMinorParams` ~line 2672 and its use in `clear_verified_minor_admin`; add `set_verified_minor_admin` after `clear_verified_minor_admin`)
- Modify: `api/src/api/http/routes.rs:336-339`
- Modify: `api/tests/clear_verified_minor_test.rs` (import rename only)
- Create: `api/tests/set_verified_minor_test.rs`

**Interfaces:**
- Consumes: `UserRepository::set_verified_minor`, `SetVerifiedMinorOutcome` (Task 1).
- Produces: `pub async fn set_verified_minor_admin(tenant: TenantExtractor, State<AuthState>, HeaderMap, Path<String>, Query<VerifiedMinorParams>) -> ApiResult<Json<UserStatusResponse>>`; `pub struct VerifiedMinorParams { pub actor: Option<String>, pub reason: Option<String> }`.

- [ ] **Step 1: Write the failing integration tests**

Create `api/tests/set_verified_minor_test.rs`. Copy lines 1-123 of `api/tests/clear_verified_minor_test.rs` (imports, `TestKeyManager`, `create_test_auth_state`, `build_app`, plus `AuditRow`/`read_audit_rows` from ~line 240) and change: the ABOUTME lines; the import to `admin::{set_verified_minor_admin, VerifiedMinorParams, UserStatusResponse}`; `routing::put`; in `build_app` use `put(` and call `set_verified_minor_admin`. Replace `create_verified_minor_user` with:

```rust
async fn create_user(pool: &PgPool, minor: bool, with_credentials: bool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 THEN NOW() END, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(with_credentials.then(|| format!("{}@example.test", &pubkey[..16])))
    .bind(with_credentials.then(|| "$2b$04$placeholderhashplaceholderhashplaceholderha".to_string()))
    .bind(minor)
    .execute(pool)
    .await
    .expect("create user");
    pubkey
}

async fn put_set(app: Router, pubkey: &str, query: &str, token: Option<&str>) -> axum::response::Response {
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!("/admin/users/{}/verified-minor{}", pubkey, query));
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {}", token));
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}
```

Tests (each begins with `common::assert_test_database_url(); unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) }; let pool = common::setup_test_db().await;`):

```rust
#[tokio::test]
async fn test_set_verified_minor_sets_and_invalidates_cache() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let pubkey = create_user(&pool, false, true).await;
    auth_state.state.account_status_cache.insert(
        (TENANT_ID, pubkey.clone()),
        keycast_api::state::AccountGateState::Present { status: "active".to_string(), verified_minor: false },
    ).await;

    let resp = put_set(build_app(auth_state.clone()), &pubkey, "", Some(SERVICE_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(status.verified_minor);
    assert!(status.verified_minor_at.is_some());
    assert_eq!(status.status, "active");
    assert!(
        auth_state.state.account_status_cache.get(&(TENANT_ID, pubkey)).await.is_none(),
        "setting verified_minor must invalidate the account-status cache so the DM gate sees it"
    );
}

#[tokio::test]
async fn test_set_with_actor_writes_one_audit_row_across_retries() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let actor = Keys::generate().public_key().to_hex();
    let query = format!("?actor={}&reason=age_review_approved", actor);

    let first = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, &query, Some(SERVICE_TOKEN)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let retry = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, &query, Some(SERVICE_TOKEN)).await;
    assert_eq!(retry.status(), StatusCode::OK);

    let rows = read_audit_rows(&pool, &actor).await;
    assert_eq!(rows.len(), 1, "a retry must not append a second audit event");
    assert_eq!(rows[0].action, "set_verified_minor");
    assert_eq!(rows[0].target_resource_type, "user");
    assert_eq!(rows[0].target_resource_id.as_deref(), Some(pubkey.as_str()));
    assert_eq!(rows[0].metadata_json["reason"], "age_review_approved");
}

#[tokio::test]
async fn test_set_without_actor_writes_no_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let resp = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, "", Some(SERVICE_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM admin_audit_events WHERE target_resource_id = $1 AND action = 'set_verified_minor'",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn test_set_credentialless_row_is_409_account_unclaimed() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, false).await;
    let resp = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, "", Some(SERVICE_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert!(body["error"].as_str().unwrap().starts_with("account_unclaimed"));
    let flagged: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert!(!flagged.0);
}

#[tokio::test]
async fn test_set_onboarded_unclaimed_minor_is_200() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, true, false).await;
    let resp = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, "", Some(SERVICE_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_set_unknown_pubkey_is_404_user_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let fake = Keys::generate().public_key().to_hex();
    let resp = put_set(build_app(create_test_auth_state(pool.clone())), &fake, "", Some(SERVICE_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // relay-manager's not_applicable discriminator matches this body exactly.
    assert_eq!(body_json(resp).await["error"], "user not found");
}

#[tokio::test]
async fn test_set_requires_service_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let missing = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, "", None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let wrong = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, "", Some("wrong-token")).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let flagged: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert!(!flagged.0, "an unauthorized request must not set the flag");
}

#[tokio::test]
async fn test_set_malformed_or_empty_actor_is_400_and_flag_untouched() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    for query in ["?actor=not-hex", "?actor="] {
        let resp = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, query, Some(SERVICE_TOKEN)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query}");
    }
    let flagged: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert!(!flagged.0);
}

#[tokio::test]
async fn test_set_reason_sanitized_in_audit() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let actor = Keys::generate().public_key().to_hex();
    // %E2%80%AE is U+202E (right-to-left override); %0A is a newline.
    let query = format!("?actor={}&reason=approved%E2%80%AE%0Aminor", actor);
    let resp = put_set(build_app(create_test_auth_state(pool.clone())), &pubkey, &query, Some(SERVICE_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    assert_eq!(rows[0].metadata_json["reason"], "approvedminor");
}
```

(`?actor=` deserializes to `Some("")`, which `validate_actor` rejects, matching `test_clear_empty_actor_is_400`.)

- [ ] **Step 2: Run to verify failure**

Run: `DATABASE_URL=postgres://postgres:password@localhost:5432/keycast_test cargo test -p keycast_api --features integration-tests --test set_verified_minor_test`
Expected: compile error, `set_verified_minor_admin` / `VerifiedMinorParams` not found.

- [ ] **Step 3: Implement the handler, rename the params, add the route**

In `admin.rs`, rename the struct and its doc comment:

```rust
/// Query params for the set and clear verified_minor endpoints. Both optional;
/// `actor` (the moderator's hex pubkey) drives the durable audit row.
#[derive(Debug, Deserialize)]
pub struct VerifiedMinorParams {
    pub actor: Option<String>,
    pub reason: Option<String>,
}
```
and change `Query(params): Query<ClearVerifiedMinorParams>` in `clear_verified_minor_admin` to `Query<VerifiedMinorParams>`. In `api/tests/clear_verified_minor_test.rs`, replace every `ClearVerifiedMinorParams` with `VerifiedMinorParams`.

Extract the actor check both handlers share (place it above `clear_verified_minor_admin` and call it from both):

```rust
/// A T&S action must never silently lose its audit trail to a malformed actor.
fn validate_actor(actor: Option<&str>) -> Result<(), ApiError> {
    if let Some(actor) = actor {
        if actor.len() != 64 || !actor.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request(
                "actor must be a 64-character hex pubkey",
            ));
        }
    }
    Ok(())
}
```
Replace the inline block in `clear_verified_minor_admin` with `validate_actor(params.actor.as_deref())?;`.

Add after `clear_verified_minor_admin` (import `SetVerifiedMinorOutcome` alongside the existing `UserRepository` import):

```rust
// --- Set verified_minor (service-token auth: age-review approval) ---

/// Confer verified_minor on an existing account. relay-manager calls this when a
/// moderator approves an age-review case as a 13-15 protected minor, so the
/// approval is respected on later reports (DM gate, key-egress gate, auto-clear).
///
/// Unlike clear, this does not touch claim tokens: clearing invalidates them to
/// close a revocation door, and setting opens no door.
pub async fn set_verified_minor_admin(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
    Query(params): Query<VerifiedMinorParams>,
) -> ApiResult<Json<UserStatusResponse>> {
    authorize_service_token(&headers)?;
    let tenant_id = tenant.0.id;
    validate_actor(params.actor.as_deref())?;
    let reason_clean = sanitize_reason(params.reason);

    let user_repo = UserRepository::new(auth_state.state.db.clone());
    let outcome = user_repo.set_verified_minor(&pubkey, tenant_id).await?;
    if outcome == SetVerifiedMinorOutcome::Unclaimed {
        tracing::warn!(
            event = "verified_minor_set_refused",
            pubkey = %pubkey,
            actor = ?params.actor,
            "Refused verified_minor set on a credential-less account"
        );
        return Err(ApiError::conflict(
            "account_unclaimed: account has no login credentials",
        ));
    }
    super::nostr_rpc::invalidate_account_status_cache(
        &auth_state.state.account_status_cache,
        &pubkey,
        tenant_id,
    )
    .await;

    let transitioned = outcome == SetVerifiedMinorOutcome::Set;
    tracing::info!(
        event = "verified_minor_set",
        pubkey = %pubkey,
        actor = ?params.actor,
        reason = ?reason_clean,
        transitioned,
        "Admin set verified_minor"
    );

    // Best-effort audit row, only for a real transition and only with an actor
    // (actor_pubkey is NOT NULL). Same bar as the clear handler: a retry after a
    // lost response must not assert a second state change.
    if transitioned {
        if let Some(actor) = params.actor.as_deref() {
            let audit_repo = AdminAuditEventRepository::new(auth_state.state.db.clone());
            if let Err(error) = audit_repo
                .record(AdminAuditEventRecord {
                    tenant_id,
                    actor_pubkey: actor.to_string(),
                    action: "set_verified_minor".to_string(),
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
                    "Failed to write admin_audit_events row for verified_minor set"
                );
            }
        }
    }

    let FullAdminStatusRow {
        status,
        suspended_reason,
        suspended_at,
        verified_minor,
        verified_minor_at,
    } = user_repo
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

In `routes.rs`:

```rust
        .route(
            "/admin/users/:pubkey/verified-minor",
            put(admin::set_verified_minor_admin).delete(admin::clear_verified_minor_admin),
        )
```

- [ ] **Step 4: Run to verify pass**

```bash
DATABASE_URL=postgres://postgres:password@localhost:5432/keycast_test cargo test -p keycast_api --features integration-tests --test set_verified_minor_test --test clear_verified_minor_test
```
Expected: all PASS (the clear tests prove the rename and `validate_actor` extraction changed nothing).

- [ ] **Step 5: Mutation-check each guard (one per mutation; back up `admin.rs` with `cp`, restore with `cp`)**

1. Remove the `if outcome == SetVerifiedMinorOutcome::Unclaimed { ... }` block → only `test_set_credentialless_row_is_409_account_unclaimed` fails (the repo still refuses the write, so the status assertion is what dies).
2. Remove the `invalidate_account_status_cache` call → only `test_set_verified_minor_sets_and_invalidates_cache` fails.
3. Change `if transitioned {` to `if true {` → only `test_set_with_actor_writes_one_audit_row_across_retries` fails.
4. Remove `authorize_service_token(&headers)?;` → only `test_set_requires_service_token` fails.
Restore after each and rerun Step 4 green.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated
git add api/src/api/http/admin.rs api/src/api/http/routes.rs api/tests/clear_verified_minor_test.rs api/tests/set_verified_minor_test.rs
git commit -m "feat(minor-safety): service endpoint to set verified_minor on an existing account"
```

---

### Task 3: Full-suite verification and docs

**Files:**
- Modify: any doc that lists the service-admin routes (find with `grep -rn "verified-minor" docs/ CLAUDE.md AGENTS.md README.md`); add the `PUT` beside the existing `DELETE` with one line on its purpose and the 409.

- [ ] **Step 1: Update route docs found by the grep above.** If none list the route, make no doc change.
- [ ] **Step 2: Run the CI-equivalent suite**

Run: `bun run test`
Expected: green. Any failure here is caused by this branch (`origin/main` always passes, per AGENTS.md). Record the counts.

- [ ] **Step 3: Commit docs if changed**

```bash
git add docs
git commit -m "docs(minor-safety): document the verified_minor set endpoint"
```
