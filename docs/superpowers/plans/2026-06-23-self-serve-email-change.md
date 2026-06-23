# Self-Serve Email Change Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an email/password user change their email address through a self-serve flow gated by password re-verification and dual (old + new address) email confirmation, with a cancel path for the old-address holder.

**Architecture:** Mirror the existing password-reset / email-verification token flows. Add `pending_email_*` columns on `users`, repository CRUD methods, two new `EmailSender` methods, three handlers (initiate / confirm / cancel), routes, and minimal SvelteKit pages. Finalization is atomic and only fires once both addresses confirm.

**Tech Stack:** Rust (axum, sqlx, bcrypt, chrono, nostr-sdk), PostgreSQL, SvelteKit (Svelte 5 runes, Bun).

Implements GitHub issue #223. Validated against `main` @ 3d36601.

## Global Constraints

- Migrations are forward-only, timestamped `YYYYMMDDHHmmss_name.sql`, run via `sqlx::migrate!` and `tools/run-migrations.sh`. No down migrations.
- `event_type`, `endpoint`, `outcome` in `AuthEvent` are `&'static str`.
- Anti-enumeration: the initiate endpoint always returns HTTP 200 success regardless of outcome.
- Re-use `normalize_registration_email()` for all email normalization (case/dot bypass protection).
- `generate_secure_token()` → 64-char alphanumeric tokens. Token expiry 24h (mirror `EMAIL_VERIFICATION_EXPIRY_HOURS`).
- Email confirm/cancel links are security-sensitive: SendGrid click/open tracking stays disabled (already global in `send_email`).
- No new tech debt; follow existing patterns exactly.

## Decisions (locked with Matt 2026-06-23)

1. **Cancel endpoint included** — `POST /api/auth/cancel-email-change`, token-based on either pending token. Defense-in-depth ("I didn't request this"). Must require the high-entropy token, return generic responses, clear all pending columns atomically.
2. **Frontend in scope** — minimal SvelteKit pages: a Change Email section in `settings/security`, plus `/confirm-email-change` and `/cancel-email-change` pages.
3. **Seventh column `pending_email_sent_at`** — added beyond the spec's six to support the 5-minute resend cooldown cleanly (mirrors `email_verification_sent_at`). Documented divergence.
4. **TOCTOU at finalize** — finalize must handle the unique-constraint violation on `(email, tenant_id)` (someone else registered the pending email between initiate and confirm): clear pending state, return a clear conflict.

## Schema

```
pending_email                  TEXT
pending_email_old_token        TEXT
pending_email_new_token        TEXT
pending_email_expires_at       TIMESTAMPTZ
pending_email_sent_at          TIMESTAMPTZ   -- resend cooldown
pending_email_old_confirmed_at TIMESTAMPTZ
pending_email_new_confirmed_at TIMESTAMPTZ
```
Partial indexes on `pending_email_old_token` and `pending_email_new_token` where not null.

## File Structure

- `database/migrations/20260623120000_add_pending_email_change.sql` — new columns + indexes (create)
- `core/src/repositories/user.rs` — repo methods (modify)
- `api/src/email_service.rs` — 2 trait methods + 2 impls + legacy wrapper (modify)
- `api/src/api/http/auth.rs` — 3 handlers + request/response types + event_type consts (modify)
- `api/src/api/http/routes.rs` — 1 route in `user_routes`, 2 in `email_routes` (modify)
- `api/tests/email_change_test.rs` — integration tests (create)
- `web/src/routes/settings/security/+page.svelte` — Change Email section (modify)
- `web/src/routes/confirm-email-change/+page.svelte` — confirm page (create)
- `web/src/routes/cancel-email-change/+page.svelte` — cancel page (create)

---

### Task 1: Migration

**Files:** Create `database/migrations/20260623120000_add_pending_email_change.sql`

- [ ] **Step 1: Write migration**

```sql
-- Self-serve email change with dual (old + new address) confirmation.
-- Mirrors the per-row token pattern used by password_reset_token / email_verification_token.
ALTER TABLE users
    ADD COLUMN pending_email                  TEXT,
    ADD COLUMN pending_email_old_token        TEXT,
    ADD COLUMN pending_email_new_token        TEXT,
    ADD COLUMN pending_email_expires_at       TIMESTAMPTZ,
    ADD COLUMN pending_email_sent_at          TIMESTAMPTZ,
    ADD COLUMN pending_email_old_confirmed_at TIMESTAMPTZ,
    ADD COLUMN pending_email_new_confirmed_at TIMESTAMPTZ;

CREATE INDEX idx_users_pending_email_old_token
    ON users (pending_email_old_token) WHERE pending_email_old_token IS NOT NULL;
CREATE INDEX idx_users_pending_email_new_token
    ON users (pending_email_new_token) WHERE pending_email_new_token IS NOT NULL;
```

- [ ] **Step 2: Run migration against the test DB**

Run: `tools/run-migrations.sh` (or `sqlx migrate run` against `DATABASE_URL`). Expected: applies cleanly.

- [ ] **Step 3: Commit** — `feat(db): add pending email change columns`

---

### Task 2: Repository methods

**Files:** Modify `core/src/repositories/user.rs` (add near the password-reset methods, ~line 558)

**Interfaces produced:**
- `set_pending_email_change(&self, pubkey, tenant_id, new_email, old_token, new_token, expires_at) -> Result<(), RepositoryError>` — overwrites all pending columns, stamps sent_at, clears confirmed_at.
- `pending_email_last_sent(&self, pubkey, tenant_id) -> Result<Option<DateTime<Utc>>, RepositoryError>` — for cooldown.
- `find_by_pending_email_token(&self, token, tenant_id) -> Result<Option<PendingEmailChange>, RepositoryError>` — matches old OR new token.
- `mark_pending_email_confirmed(&self, pubkey, tenant_id, side: PendingEmailSide) -> Result<(), RepositoryError>`
- `finalize_email_change(&self, pubkey, tenant_id) -> Result<bool, RepositoryError>` — sets `email = pending_email`, `email_verified = true`, clears pending; returns `false` on unique-violation (caller treats as conflict).
- `clear_pending_email_change(&self, pubkey, tenant_id) -> Result<(), RepositoryError>`

Where:
```rust
#[derive(Debug, Clone, Copy)]
pub enum PendingEmailSide { Old, New }

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingEmailChange {
    pub pubkey: String,
    pub pending_email: Option<String>,
    pub pending_email_expires_at: Option<DateTime<Utc>>,
    pub pending_email_old_confirmed_at: Option<DateTime<Utc>>,
    pub pending_email_new_confirmed_at: Option<DateTime<Utc>>,
}
```

- [ ] **Step 1: Write the failing test** in `core/tests/` is not the harness here; repo methods are exercised via the API integration test (Task 8). Skip a separate repo unit test — these are thin SQL wrappers mirroring existing untested methods (`set_password_reset_token` etc. have no unit tests). Proceed to implement.

- [ ] **Step 2: Implement the methods.**

```rust
    /// Store a pending email change (dual-token). Overwrites any existing pending change.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_pending_email_change(
        &self,
        pubkey: &str,
        tenant_id: i64,
        new_email: &str,
        old_token: &str,
        new_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE users
             SET pending_email = $1,
                 pending_email_old_token = $2,
                 pending_email_new_token = $3,
                 pending_email_expires_at = $4,
                 pending_email_sent_at = $5,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $5
             WHERE pubkey = $6 AND tenant_id = $7",
        )
        .bind(new_email)
        .bind(old_token)
        .bind(new_token)
        .bind(expires_at)
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Timestamp of the most recent pending-email-change send (for resend cooldown).
    pub async fn pending_email_last_sent(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<DateTime<Utc>>, RepositoryError> {
        let row: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
            "SELECT pending_email_sent_at FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.0))
    }

    /// Find a pending change by either the old- or new-address token.
    pub async fn find_by_pending_email_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<(PendingEmailChange, PendingEmailSide)>, RepositoryError> {
        let row: Option<PendingEmailChange> = sqlx::query_as(
            "SELECT pubkey, pending_email, pending_email_expires_at,
                    pending_email_old_confirmed_at, pending_email_new_confirmed_at,
                    pending_email_old_token, pending_email_new_token
             FROM users
             WHERE (pending_email_old_token = $1 OR pending_email_new_token = $1)
               AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        // NOTE: PendingEmailChange derives FromRow on the four public fields; the two token
        // columns are selected only to decide the side. Use a tuple query instead (below).
        Ok(row.map(|pc| (pc, PendingEmailSide::Old)))
    }
```

  > Implementation note: `FromRow` will reject extra columns it can't map. Implement `find_by_pending_email_token` with an explicit tuple `query_as` selecting `(pubkey, pending_email, pending_email_expires_at, pending_email_old_confirmed_at, pending_email_new_confirmed_at, pending_email_old_token, pending_email_new_token)` and construct `PendingEmailChange` + derive the side by comparing which token equals the input. Build the struct manually.

```rust
    pub async fn mark_pending_email_confirmed(
        &self,
        pubkey: &str,
        tenant_id: i64,
        side: PendingEmailSide,
    ) -> Result<(), RepositoryError> {
        let col = match side {
            PendingEmailSide::Old => "pending_email_old_confirmed_at",
            PendingEmailSide::New => "pending_email_new_confirmed_at",
        };
        let sql = format!(
            "UPDATE users SET {col} = $1, updated_at = $1 WHERE pubkey = $2 AND tenant_id = $3"
        );
        sqlx::query(&sql)
            .bind(Utc::now())
            .bind(pubkey)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Apply the pending email atomically. Returns Ok(false) if the target email is now taken.
    pub async fn finalize_email_change(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE users
             SET email = pending_email,
                 email_verified = true,
                 pending_email = NULL,
                 pending_email_old_token = NULL,
                 pending_email_new_token = NULL,
                 pending_email_expires_at = NULL,
                 pending_email_sent_at = NULL,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3 AND pending_email IS NOT NULL",
        )
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                // Target email got registered between initiate and confirm. Clear pending so the
                // user can restart with a different address.
                self.clear_pending_email_change(pubkey, tenant_id).await?;
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn clear_pending_email_change(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET pending_email = NULL,
                 pending_email_old_token = NULL,
                 pending_email_new_token = NULL,
                 pending_email_expires_at = NULL,
                 pending_email_sent_at = NULL,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
```

- [ ] **Step 3:** `cargo build -p keycast_core` — expected: compiles.
- [ ] **Step 4: Commit** — `feat(core): pending email change repository methods`

---

### Task 3: EmailSender methods

**Files:** Modify `api/src/email_service.rs`

**Interfaces produced (trait additions):**
- `async fn send_email_change_confirmation(&self, to_new_email: &str, confirm_url: &str) -> Result<(), String>` — to the NEW address.
- `async fn send_email_change_notification(&self, to_old_email: &str, new_email: &str, confirm_url: &str, cancel_url: &str) -> Result<(), String>` — to the OLD address (security alert: confirm or cancel).

- [ ] **Step 1:** Add both methods to the `EmailSender` trait (no default body).
- [ ] **Step 2:** Implement in `DevEmailSender` (log + `eprintln!` + capture into `CapturedEmail`; put the confirm/notification URL into `verification_url`).
- [ ] **Step 3:** Implement in `SendGridEmailSender` (HTML + text, brand-styled like existing emails; reuse `self.send_email`). New address: "Confirm your new email". Old address: "Your {brand} email is being changed" with both Confirm and Cancel links and "If you didn't request this, click Cancel".
- [ ] **Step 4:** Add pass-through wrappers in legacy `EmailService`.
- [ ] **Step 5:** `cargo build -p keycast_api` — compiles. Existing `email_service` tests still pass: `cargo test -p keycast_api --lib email_service`.
- [ ] **Step 6: Commit** — `feat(email): email-change confirmation + notification senders`

---

### Task 4: Initiate handler

**Files:** Modify `api/src/api/http/auth.rs`

Add constants near line 33:
```rust
pub const EMAIL_CHANGE_EXPIRY_HOURS: i64 = 24;
const EMAIL_CHANGE_RESEND_COOLDOWN_MINUTES: i64 = 5;
```

Request/response types:
```rust
#[derive(Debug, Deserialize)]
pub struct ChangeEmailRequest {
    pub new_email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ChangeEmailResponse {
    pub success: bool,
    pub message: String,
}
```

Handler (mirror `change_password` + `forgot_password`):
```rust
/// Initiate a self-serve email change. Authenticated (UCAN) + password re-verification.
/// Always returns 200 (anti-enumeration on the *new* address).
pub async fn change_email(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ChangeEmailRequest>,
) -> Result<Json<ChangeEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = extract_user_from_token(&headers, tenant_id).await?;

    // Validate + normalize the new email (reuse registration normalizer).
    let new_email = normalize_registration_email(&req.new_email)
        .map_err(|_| AuthError::InvalidEmail)?;

    let user_repo = UserRepository::new(pool.clone());

    // Re-verify password.
    let (current_email, password_hash) = user_repo
        .get_credentials(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let password = req.password.clone();
    let hash = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify(&password, &hash))
        .await
        .map_err(|e| AuthError::Internal(format!("Task join error: {}", e)))?
        .map_err(|_| AuthError::Internal("Password verification failed".to_string()))?;
    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    // No-op if unchanged.
    if new_email == current_email {
        return Ok(Json(ChangeEmailResponse {
            success: true,
            message: "That is already your email address.".to_string(),
        }));
    }

    let ok_response = Json(ChangeEmailResponse {
        success: true,
        message: "Check both your current and new email to confirm the change.".to_string(),
    });

    // 5-minute resend cooldown.
    if let Ok(Some(last_sent)) = user_repo.pending_email_last_sent(&user_pubkey, tenant_id).await {
        if Utc::now() - last_sent < Duration::minutes(EMAIL_CHANGE_RESEND_COOLDOWN_MINUTES) {
            return Ok(ok_response);
        }
    }

    // Anti-enumeration: if the new email is taken, return success without sending.
    if user_repo.find_pubkey_by_email(&new_email, tenant_id).await?.is_some() {
        // Record accepted+already_registered for observability.
        record_email_change_event(&pool, &headers, tenant_id, "email_change_request",
            "accepted", Some("email_already_registered"), 200, Some(&new_email), Some(&user_pubkey)).await;
        return Ok(ok_response);
    }

    // Generate tokens, store, send.
    let old_token = generate_secure_token();
    let new_token = generate_secure_token();
    let expires = Utc::now() + Duration::hours(EMAIL_CHANGE_EXPIRY_HOURS);
    user_repo
        .set_pending_email_change(&user_pubkey, tenant_id, &new_email, &old_token, &new_token, expires)
        .await?;

    let base = app_base_url(&headers);
    let confirm_new = format!("{base}/confirm-email-change?token={new_token}");
    let confirm_old = format!("{base}/confirm-email-change?token={old_token}");
    let cancel_old = format!("{base}/cancel-email-change?token={old_token}");

    // Best-effort sends (don't fail the flow).
    if let Ok(svc) = crate::email_service::EmailService::new() {
        let _ = svc.send_email_change_confirmation(&new_email, &confirm_new).await;
        let _ = svc.send_email_change_notification(&current_email, &new_email, &confirm_old, &cancel_old).await;
    }

    record_email_change_event(&pool, &headers, tenant_id, "email_change_request",
        "accepted", None, 200, Some(&new_email), Some(&user_pubkey)).await;

    Ok(ok_response)
}
```

Helpers (add to auth.rs):
```rust
/// Resolve the public base URL for building email links (mirrors nostr_discovery_public).
fn app_base_url(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .map(|host| {
            let proto = headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(if host.contains(":443") || !host.contains(':') { "https" } else { "http" });
            format!("{proto}://{host}")
        })
        .or_else(|| std::env::var("APP_URL").ok())
        .unwrap_or_else(|| "http://localhost:5173".to_string())
}

#[allow(clippy::too_many_arguments)]
async fn record_email_change_event(
    pool: &PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
    event_type: &'static str,
    outcome: &'static str,
    reason_code: Option<&str>,
    http_status: i32,
    email: Option<&str>,
    pubkey: Option<&str>,
) {
    let _ = super::auth_observability::record_auth_event_and_log(
        pool, headers, None,
        super::auth_observability::AuthEvent {
            tenant_id,
            endpoint: "/api/user/change-email",
            event_type,
            outcome,
            reason_code,
            http_status,
            email,
            pubkey,
            client_id: None,
            redirect_origin: None,
            metadata_json: serde_json::json!({}),
        },
    ).await;
}
```
  > Verify `app_base_url` doesn't already exist; if a shared helper exists, reuse it. Confirm the exact `record_auth_event_and_log` signature/fields against `auth_observability.rs` before pasting (the `endpoint` differs per handler — pass it as a param if recording from confirm/cancel too).

- [ ] **Step 1:** Implement the handler + helpers + types + consts.
- [ ] **Step 2:** `cargo build -p keycast_api` — compiles.
- [ ] **Step 3: Commit** — `feat(api): initiate self-serve email change`

---

### Task 5: Confirm handler

**Files:** Modify `api/src/api/http/auth.rs`

```rust
#[derive(Debug, Deserialize)]
pub struct ConfirmEmailChangeRequest { pub token: String }

/// Confirm one side of a pending email change. When both sides confirm, finalize atomically.
pub async fn confirm_email_change(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ConfirmEmailChangeRequest>,
) -> Result<Json<ChangeEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(pool.clone());

    let (pending, side) = user_repo
        .find_by_pending_email_token(&req.token, tenant_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    // Expiry check.
    if pending.pending_email_expires_at.map_or(true, |e| e < Utc::now()) {
        return Err(AuthError::TokenExpired);
    }

    user_repo.mark_pending_email_confirmed(&pending.pubkey, tenant_id, side).await?;

    // Determine if both sides are now confirmed.
    let old_done = matches!(side, PendingEmailSide::Old) || pending.pending_email_old_confirmed_at.is_some();
    let new_done = matches!(side, PendingEmailSide::New) || pending.pending_email_new_confirmed_at.is_some();

    if old_done && new_done {
        let finalized = user_repo.finalize_email_change(&pending.pubkey, tenant_id).await?;
        if !finalized {
            return Err(AuthError::Conflict(
                "That email address is no longer available.".to_string(),
            ));
        }
        record_email_change_event(&pool, &headers, tenant_id, "email_change",
            "success", Some("finalized"), 200,
            pending.pending_email.as_deref(), Some(&pending.pubkey)).await;
        return Ok(Json(ChangeEmailResponse {
            success: true,
            message: "Your email address has been updated.".to_string(),
        }));
    }

    Ok(Json(ChangeEmailResponse {
        success: true,
        message: "Confirmed. Waiting for the other address to confirm.".to_string(),
    }))
}
```
  > `PendingEmailSide` must be imported from `keycast_core::repositories`. Confirm export path. Note the `record_email_change_event` `endpoint` is hard-coded to `/api/user/change-email`; refactor it to accept `endpoint: &'static str` so confirm/cancel log their own paths.

- [ ] **Step 1:** Refactor `record_email_change_event` to take `endpoint: &'static str`; update the initiate call site.
- [ ] **Step 2:** Implement confirm handler.
- [ ] **Step 3:** `cargo build -p keycast_api` — compiles.
- [ ] **Step 4: Commit** — `feat(api): confirm email change`

---

### Task 6: Cancel handler

**Files:** Modify `api/src/api/http/auth.rs`

```rust
/// Cancel a pending email change (old- or new-address holder). Token-bound, generic response.
pub async fn cancel_email_change(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ConfirmEmailChangeRequest>,
) -> Result<Json<ChangeEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let user_repo = UserRepository::new(pool.clone());

    if let Some((pending, _side)) =
        user_repo.find_by_pending_email_token(&req.token, tenant_id).await?
    {
        user_repo.clear_pending_email_change(&pending.pubkey, tenant_id).await?;
        record_email_change_event(&pool, &headers, tenant_id, "/api/auth/cancel-email-change",
            "email_change", "success", Some("cancelled"), 200,
            pending.pending_email.as_deref(), Some(&pending.pubkey)).await;
    }
    // Generic response regardless of whether a pending change existed.
    Ok(Json(ChangeEmailResponse {
        success: true,
        message: "The email change has been cancelled.".to_string(),
    }))
}
```
  > Adjust arg order to match the refactored `record_email_change_event(endpoint, event_type, outcome, ...)`.

- [ ] **Step 1:** Implement cancel handler.
- [ ] **Step 2:** `cargo build -p keycast_api` — compiles.
- [ ] **Step 3: Commit** — `feat(api): cancel email change`

---

### Task 7: Routes

**Files:** Modify `api/src/api/http/routes.rs`

- [ ] **Step 1:** Add to `user_routes` (auth_cors, `State(pool)`), after `/user/change-password`:
```rust
        .route("/user/change-email", post(auth::change_email))
```
- [ ] **Step 2:** Add to `email_routes` (public_cors, `State(pool)`):
```rust
        .route("/auth/confirm-email-change", post(auth::confirm_email_change))
        .route("/auth/cancel-email-change", post(auth::cancel_email_change))
```
- [ ] **Step 3:** `cargo build -p keycast_api` — compiles.
- [ ] **Step 4: Commit** — `feat(api): wire email-change routes`

---

### Task 8: Integration tests

**Files:** Create `api/tests/email_change_test.rs` (mirror `password_reset_observability_test.rs` harness: `#![cfg(feature = "integration-tests")]`, `setup_pool`, `create_test_tenant`, `cleanup_by_email`, build a `Router` with the three handlers + `request_id_middleware`).

Cover the acceptance criteria. Each test seeds a user (register or direct insert with a known pubkey + bcrypt password hash) and drives the handlers, reading `pending_email_*` columns directly to assert state.

- [ ] **Test 1 — happy path / dual confirm finalizes:** initiate with correct password → assert `pending_email` set, both tokens present, `email` unchanged. Confirm with new token → `email` still old. Confirm with old token → `email` == new, `email_verified` true, pending cleared.
- [ ] **Test 2 — partial confirmation does not finalize:** initiate, confirm only one side, assert `email` unchanged and the one `*_confirmed_at` set.
- [ ] **Test 3 — wrong password:** initiate with bad password → `AuthError::InvalidCredentials` (401), no pending row written.
- [ ] **Test 4 — duplicate email (anti-enumeration):** seed a second user owning `new_email`; initiate → 200 success, but assert no pending change was written for the initiator.
- [ ] **Test 5 — expired token rejected:** initiate, then directly `UPDATE users SET pending_email_expires_at = now() - interval '1 hour'`; confirm → `TokenExpired` (401).
- [ ] **Test 6 — cancel clears pending:** initiate, cancel with old token → 200, assert pending cleared.
- [ ] **Test 7 — invalid confirm token:** confirm with garbage token → `InvalidToken` (401).
- [ ] **Test 8 — new change cancels prior:** initiate to email A, initiate to email B → assert `pending_email` == B and tokens differ.

- [ ] **Run:** `cd api && cargo test --features integration-tests --test email_change_test` — expected: all pass. (Requires a running Postgres at `DATABASE_URL`.)
- [ ] **Commit** — `test(api): self-serve email change integration tests`

---

### Task 9: Frontend — Change Email section

**Files:** Modify `web/src/routes/settings/security/+page.svelte`

- [ ] **Step 1:** Add state: `let newEmail = $state(''); let isChangingEmail = $state(false);`
- [ ] **Step 2:** Add `handleChangeEmail()` posting `/user/change-email` with `{ new_email: newEmail, password: mainPassword }`; on success toast "Check both your current and new email to confirm." Gate the section behind `isPasswordVerified` like the other sections.
- [ ] **Step 3:** Add the markup section (input + button) mirroring the Change Password section's styling.
- [ ] **Step 4:** `cd web && bun run check` (svelte-check) — no new errors.
- [ ] **Step 5: Commit** — `feat(web): change email form in security settings`

---

### Task 10: Frontend — confirm page

**Files:** Create `web/src/routes/confirm-email-change/+page.svelte` (mirror `reset-password/+page.svelte` structure)

- [ ] **Step 1:** On mount, read `token` from `$page.url.searchParams`. If missing, show invalid-link message. Otherwise auto-POST `/auth/confirm-email-change` with `{ token }`, show the returned `message` (either "waiting for the other address" or "email updated"), with a link back to settings/login.
- [ ] **Step 2:** `bun run check` — clean.
- [ ] **Step 3: Commit** — `feat(web): confirm-email-change page`

---

### Task 11: Frontend — cancel page

**Files:** Create `web/src/routes/cancel-email-change/+page.svelte`

- [ ] **Step 1:** Read `token`; auto-POST `/auth/cancel-email-change` with `{ token }`; show "The email change has been cancelled." plus guidance to change the password if the user didn't initiate it.
- [ ] **Step 2:** `bun run check` — clean.
- [ ] **Step 3: Commit** — `feat(web): cancel-email-change page`

---

## Final verification

- [ ] `cargo build` (workspace) — compiles.
- [ ] `cargo clippy -p keycast_api -p keycast_core` — no new warnings.
- [ ] `cd api && cargo test --features integration-tests --test email_change_test` — all pass.
- [ ] `cd web && bun run check` — clean.
- [ ] Self-review the full diff for the security checklist: password re-verify, token entropy, anti-enumeration, atomic finalize w/ unique-violation handling, generic cancel response, no secrets logged.
- [ ] Open PR targeting `main`, `Closes #223`. Note the seventh-column divergence and the cancel-endpoint decision in the PR body.
```
