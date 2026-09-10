# Claim Email Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the account-claim flow into submit + email-confirm so a claim completes only after the claimer proves control of the email they entered.

**Architecture:** `POST /api/claim` stops completing the claim; instead it stages the entered email + bcrypt-hashed password + a fresh confirmation token on the `account_claim_tokens` row and emails a confirmation link. `GET /api/claim/confirm?token=...` re-validates under a row lock, atomically consumes the claim token and writes the user (email + password + `email_verified = true`), then issues the session. A cooldown-gated `POST /api/claim/resend` re-sends the link. Business logic lives in `core/` repositories; HTTP handlers in `api/` stay thin.

**Tech Stack:** Rust (axum, sqlx, Postgres), server-rendered HTML, SendGrid (prod) / DevEmailSender (dev/test).

**Spec:** `docs/superpowers/specs/2026-09-10-claim-email-confirmation-design.md`

## Global Constraints

- **Layering:** business logic in `core/`; `api/` handlers thin (AGENTS.md "Architecture And Layering").
- **Transaction-mode pooling:** explicit result columns only, never `SELECT *`; `SET LOCAL` not `SET`; transaction-scoped advisory locks only. No password hashing or network call held across a DB transaction.
- **Never truncate** Nostr pubkeys/event ids/signatures in logs, errors, or test fixtures.
- **No shipped-migration edits:** new schema is a new timestamped migration under `database/migrations/`.
- **Confirmation window:** 24 hours (`CLAIM_CONFIRMATION_EXPIRY_HOURS = 24`), reusing the value/pattern of `EMAIL_VERIFICATION_EXPIRY_HOURS` (`api/src/api/http/auth.rs:43`). Independent of the 14-day `CLAIM_TOKEN_EXPIRY_DAYS`.
- **Resend cooldown:** 5 minutes, mirroring the resend-verification limit at `api/src/api/http/auth.rs:2632`.
- **HTML escaping:** every interpolation into a claim page routes through `escape_html` / `escape_attr` (`api/src/api/http/html_safety.rs`).
- **`email_verified` still gates login** (`auth.rs:1339`, `headless.rs:514`); the session must not be issued before confirmation.
- **No em dashes** in user-facing copy written in Matt's voice.
- **Verification:** `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated` before every commit; targeted tests per task.

## File Structure

- `database/migrations/20260910120000_add_claim_confirmation.sql` — **create.** Adds `pending_email`, `pending_password_hash`, `confirmation_token`, `confirmation_expires_at`, `confirmation_sent_at` to `account_claim_tokens` + partial unique index on `confirmation_token`.
- `core/src/repositories/user.rs` — **modify.** Add `EmailTaken` to `ClaimConsumeOutcome`; add `confirm_claim_consuming_token`; remove `claim_account_consuming_token`.
- `core/src/repositories/claim_token.rs` — **modify.** Add `stage_pending_claim` + a `StagePendingOutcome` enum; add `CLAIM_CONFIRMATION_EXPIRY_HOURS`.
- `api/src/email_service.rs` — **modify.** Add `send_claim_confirmation` to the `EmailSender` trait and both impls; extend `CapturedEmail` usage.
- `api/src/api/http/claim.rs` — **modify.** Restructure `claim_post`; add `claim_confirm_get`, `claim_resend_post`; add interstitial page + `ConfirmationUnrecognized` / `ConfirmationExpired` error variants.
- `api/src/api/http/routes.rs:355` — **modify.** Register `/claim/confirm` (GET) and `/claim/resend` (POST).
- `api/tests/claim_consume_race_test.rs` — **modify.** Re-express the race coverage against the two-step methods.
- `core/tests/pool_nesting_test.rs` — **modify.** Point the claim probe at the new methods.
- `api/tests/claim_confirmation_test.rs` — **create.** End-to-end submit → confirm coverage.

The new `pending_*` / `confirmation_*` columns are **not** added to the `ClaimToken` struct or `claim_token_columns!()` macro. `classify()` is untouched; the new methods query the new columns explicitly.

---

### Task 1: Migration — pending-claim columns

**Files:**
- Create: `database/migrations/20260910120000_add_claim_confirmation.sql`

**Interfaces:**
- Produces: five nullable columns on `account_claim_tokens` (`pending_email TEXT`, `pending_password_hash TEXT`, `confirmation_token TEXT`, `confirmation_expires_at TIMESTAMPTZ`, `confirmation_sent_at TIMESTAMPTZ`) and unique index `idx_claim_tokens_confirmation_token`.

- [ ] **Step 1: Write the migration**

```sql
-- Add pending-claim state so an account claim completes only after the
-- claimer confirms control of the email they entered (see spec
-- 2026-09-10-claim-email-confirmation-design.md). Mirrors the
-- oauth_codes.pending_* / pending_email_change idioms.
ALTER TABLE account_claim_tokens
    ADD COLUMN pending_email            TEXT,
    ADD COLUMN pending_password_hash    TEXT,
    ADD COLUMN confirmation_token       TEXT,
    ADD COLUMN confirmation_expires_at  TIMESTAMPTZ,
    ADD COLUMN confirmation_sent_at     TIMESTAMPTZ;

-- Confirm lookups are by confirmation_token; unique when present.
CREATE UNIQUE INDEX idx_claim_tokens_confirmation_token
    ON account_claim_tokens (confirmation_token)
    WHERE confirmation_token IS NOT NULL;
```

- [ ] **Step 2: Apply against a fresh dev DB**

Run: `bun run db:reset && bun run db:migrate`
Expected: migration applies with no error; `\d account_claim_tokens` shows the five new columns and the partial index.

- [ ] **Step 3: Commit**

```bash
git add database/migrations/20260910120000_add_claim_confirmation.sql
git commit -m "feat(claim): add pending-claim confirmation columns"
```

---

### Task 2: Core outcome types + confirmation constant

**Files:**
- Modify: `core/src/repositories/user.rs` (the `ClaimConsumeOutcome` enum near line 451)
- Modify: `core/src/repositories/claim_token.rs` (near the `CLAIM_TOKEN_EXPIRY_DAYS` re-export / top of impl)

**Interfaces:**
- Produces: `ClaimConsumeOutcome::EmailTaken`; `pub const CLAIM_CONFIRMATION_EXPIRY_HOURS: i64 = 24;`; `pub enum StagePendingOutcome { Staged, TokenNotStageable }`.

- [ ] **Step 1: Add the `EmailTaken` variant**

In `core/src/repositories/user.rs`, extend the enum:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimConsumeOutcome {
    /// Token consumed and account claimed in one transaction.
    Claimed { user_pubkey: String },
    /// Token was used, admin-invalidated, expired, or unknown — nothing mutated.
    TokenNotConsumable,
    /// Token was valid but the user row was not claimable (already has an email).
    UserNotClaimable,
    /// The pending email was taken by another user before confirmation
    /// (unique violation on idx_users_email_tenant). Nothing mutated.
    EmailTaken,
}
```

- [ ] **Step 2: Add the confirmation constant and staging outcome**

In `core/src/types/claim_token.rs`, below `CLAIM_TOKEN_EXPIRY_DAYS`:

```rust
/// Confirmation-link lifetime for a staged claim (24 hours), matching
/// EMAIL_VERIFICATION_EXPIRY_HOURS. Independent of the 14-day token life:
/// the claim token is the long-lived credential support hands out; the
/// confirmation token is a short-lived proof-of-control minted at submit.
pub const CLAIM_CONFIRMATION_EXPIRY_HOURS: i64 = 24;
```

In `core/src/repositories/claim_token.rs`, near the other outcome enums:

```rust
/// Outcome of staging a pending claim against a claim-token row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagePendingOutcome {
    /// Pending email/password/confirmation-token written to the row.
    Staged,
    /// Token was used, admin-invalidated, expired, or unknown — nothing staged.
    TokenNotStageable,
}
```

- [ ] **Step 3: Build**

Run: `cargo build -p keycast_core`
Expected: compiles (a non-exhaustive `match` warning on `ClaimConsumeOutcome` in `claim.rs` is expected and resolved in Task 6).

- [ ] **Step 4: Commit**

```bash
git add core/src/repositories/user.rs core/src/types/claim_token.rs core/src/repositories/claim_token.rs
git commit -m "feat(claim): add staging/confirm outcome types and confirmation window"
```

---

### Task 3: `stage_pending_claim` repository method

**Files:**
- Modify: `core/src/repositories/claim_token.rs`
- Test: `core/tests/` (add `claim_staging_test.rs`, or extend an existing claim-token test module)

**Interfaces:**
- Consumes: `StagePendingOutcome` (Task 2).
- Produces:
  ```rust
  pub async fn stage_pending_claim(
      &self,
      token: &str,
      tenant_id: i64,
      pending_email: &str,
      pending_password_hash: &str,
      confirmation_token: &str,
      confirmation_expires_at: DateTime<Utc>,
  ) -> Result<StagePendingOutcome, RepositoryError>
  ```

- [ ] **Step 1: Write the failing test**

```rust
// core/tests/claim_staging_test.rs
// Stages pending state on a valid token; a used/expired/invalidated token stages nothing.
#[sqlx::test(migrations = "../database/migrations")]
async fn stage_pending_claim_writes_pending_state_on_valid_token(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_valid_claim_token(&pool).await; // helper inserts user + unused, unexpired token

    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    let outcome = repo
        .stage_pending_claim(&token, TENANT_ID, "new@example.com", "hash", "conf-tok-1", expires)
        .await
        .unwrap();

    assert_eq!(outcome, StagePendingOutcome::Staged);

    let row: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT pending_email, pending_password_hash, confirmation_token \
         FROM account_claim_tokens WHERE token = $1 AND tenant_id = $2",
    )
    .bind(&token)
    .bind(TENANT_ID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (Some("new@example.com".into()), Some("hash".into()), Some("conf-tok-1".into())));

    // used_at is NOT set by staging — the token is not yet consumed.
    let used: (Option<DateTime<Utc>>,) =
        sqlx::query_as("SELECT used_at FROM account_claim_tokens WHERE token = $1")
            .bind(&token).fetch_one(&pool).await.unwrap();
    assert!(used.0.is_none());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn stage_pending_claim_refuses_used_token(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_used_claim_token(&pool).await; // used_at set
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    let outcome = repo
        .stage_pending_claim(&token, TENANT_ID, "new@example.com", "hash", "conf-tok-1", expires)
        .await
        .unwrap();
    assert_eq!(outcome, StagePendingOutcome::TokenNotStageable);
}
```

(Reuse or add the `seed_valid_claim_token` / `seed_used_claim_token` helpers alongside the existing claim-token test fixtures; insert a `users` row then an `account_claim_tokens` row with the right `used_at`/`expires_at`/`invalidated_at`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd core && cargo test --test claim_staging_test`
Expected: FAIL — `stage_pending_claim` not found.

- [ ] **Step 3: Implement the method**

```rust
pub async fn stage_pending_claim(
    &self,
    token: &str,
    tenant_id: i64,
    pending_email: &str,
    pending_password_hash: &str,
    confirmation_token: &str,
    confirmation_expires_at: DateTime<Utc>,
) -> Result<StagePendingOutcome, RepositoryError> {
    // Guarded write: only stage when the token is still valid. Re-checks
    // validity under the row lock so an invalidation cannot be overwritten.
    let updated = sqlx::query(
        "UPDATE account_claim_tokens
         SET pending_email = $1,
             pending_password_hash = $2,
             confirmation_token = $3,
             confirmation_expires_at = $4,
             confirmation_sent_at = NOW()
         WHERE token = $5
           AND tenant_id = $6
           AND used_at IS NULL
           AND invalidated_at IS NULL
           AND expires_at > NOW()",
    )
    .bind(pending_email)
    .bind(pending_password_hash)
    .bind(confirmation_token)
    .bind(confirmation_expires_at)
    .bind(token)
    .bind(tenant_id)
    .execute(&self.pool)
    .await?;

    if updated.rows_affected() == 0 {
        Ok(StagePendingOutcome::TokenNotStageable)
    } else {
        Ok(StagePendingOutcome::Staged)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd core && cargo test --test claim_staging_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/repositories/claim_token.rs core/tests/claim_staging_test.rs
git commit -m "feat(claim): stage pending claim state under a validity guard"
```

---

### Task 4: `confirm_claim_consuming_token` + retire single-step consume

**Files:**
- Modify: `core/src/repositories/user.rs` (add method; remove `claim_account_consuming_token` at ~2595)
- Modify: `core/src/repositories/claim_token.rs`, `core/src/repositories/user.rs` doc comments referencing the old method
- Test: `core/tests/claim_confirm_repo_test.rs` (create)

**Interfaces:**
- Consumes: `ClaimConsumeOutcome` incl. `EmailTaken` (Task 2).
- Produces:
  ```rust
  pub async fn confirm_claim_consuming_token(
      &self,
      confirmation_token: &str,
      tenant_id: i64,
  ) -> Result<ClaimConsumeOutcome, RepositoryError>
  ```
  On `Claimed`, the user row has `email`/`password_hash`/`email_verified = true` set and the claim token has `used_at = NOW()` with `pending_*`/`confirmation_*` cleared.

- [ ] **Step 1: Write the failing test**

```rust
// core/tests/claim_confirm_repo_test.rs
#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_completes_claim_and_consumes_token(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    ct_repo
        .stage_pending_claim(&token, TENANT_ID, "new@example.com", "hash", "conf-1", expires)
        .await
        .unwrap();

    let outcome = repo.confirm_claim_consuming_token("conf-1", TENANT_ID).await.unwrap();
    assert_eq!(outcome, ClaimConsumeOutcome::Claimed { user_pubkey: pubkey.clone() });

    let (email, verified, used): (Option<String>, bool, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT u.email, u.email_verified, t.used_at \
         FROM users u JOIN account_claim_tokens t ON t.user_pubkey = u.pubkey \
         WHERE u.pubkey = $1",
    ).bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert_eq!(email.as_deref(), Some("new@example.com"));
    assert!(verified);
    assert!(used.is_some());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_refuses_after_admin_invalidation(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    ct_repo.stage_pending_claim(&token, TENANT_ID, "new@example.com", "hash", "conf-2", expires).await.unwrap();

    // Admin invalidates between staging and confirm.
    sqlx::query("UPDATE account_claim_tokens SET invalidated_at = NOW() WHERE token = $1")
        .bind(&token).execute(&pool).await.unwrap();

    let outcome = repo.confirm_claim_consuming_token("conf-2", TENANT_ID).await.unwrap();
    assert_eq!(outcome, ClaimConsumeOutcome::TokenNotConsumable);

    let email: (Option<String>,) = sqlx::query_as("SELECT email FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert!(email.0.is_none(), "user must not be mutated when the token was invalidated");
}

#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_maps_duplicate_email_to_email_taken(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_valid_claim_token(&pool).await;
    seed_other_user_with_email(&pool, "taken@example.com").await; // occupies the address
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    ct_repo.stage_pending_claim(&token, TENANT_ID, "taken@example.com", "hash", "conf-3", expires).await.unwrap();

    let outcome = repo.confirm_claim_consuming_token("conf-3", TENANT_ID).await.unwrap();
    assert_eq!(outcome, ClaimConsumeOutcome::EmailTaken);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd core && cargo test --test claim_confirm_repo_test`
Expected: FAIL — `confirm_claim_consuming_token` not found.

- [ ] **Step 3: Implement the method**

```rust
/// Confirm a staged claim: consume the claim token and write the pending
/// email/password onto the user, atomically. Re-checks token validity under
/// the row lock (#280) so an invalidation or expiry during the confirmation
/// window cannot complete a claim.
pub async fn confirm_claim_consuming_token(
    &self,
    confirmation_token: &str,
    tenant_id: i64,
) -> Result<ClaimConsumeOutcome, RepositoryError> {
    let mut tx = self.pool.begin().await?;

    // Consume iff the token is still valid AND this confirmation token is the
    // current one. Returns the staged email/hash so the user update needs no
    // second read.
    let consumed: Option<(String, String, String)> = sqlx::query_as(
        "UPDATE account_claim_tokens
         SET used_at = NOW(),
             confirmation_token = NULL,
             pending_email = NULL,
             pending_password_hash = NULL,
             confirmation_expires_at = NULL,
             confirmation_sent_at = NULL
         WHERE confirmation_token = $1
           AND tenant_id = $2
           AND used_at IS NULL
           AND invalidated_at IS NULL
           AND expires_at > NOW()
           AND confirmation_expires_at > NOW()
         RETURNING user_pubkey, pending_email, pending_password_hash",
    )
    .bind(confirmation_token)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((user_pubkey, pending_email, pending_password_hash)) = consumed else {
        tx.rollback().await?;
        return Ok(ClaimConsumeOutcome::TokenNotConsumable);
    };

    let result = sqlx::query(
        "UPDATE users
         SET email = $1, password_hash = $2, email_verified = true, updated_at = $3
         WHERE pubkey = $4 AND tenant_id = $5 AND email IS NULL",
    )
    .bind(&pending_email)
    .bind(&pending_password_hash)
    .bind(Utc::now())
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            tx.rollback().await?;
            Ok(ClaimConsumeOutcome::UserNotClaimable)
        }
        Ok(_) => {
            tx.commit().await?;
            Ok(ClaimConsumeOutcome::Claimed { user_pubkey })
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            tx.rollback().await?;
            Ok(ClaimConsumeOutcome::EmailTaken)
        }
        Err(e) => {
            tx.rollback().await?;
            Err(e.into())
        }
    }
}
```

- [ ] **Step 4: Remove the single-step consume and update references**

Delete `claim_account_consuming_token` (`core/src/repositories/user.rs:2595`). Update the doc-comment references in `core/src/repositories/claim_token.rs:88` and `core/src/repositories/user.rs:449` to name `confirm_claim_consuming_token`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd core && cargo test --test claim_confirm_repo_test`
Expected: PASS. (`claim.rs` and the two old tests won't compile yet — fixed in Tasks 6 and 8.)

- [ ] **Step 6: Commit**

```bash
git add core/src/repositories/user.rs core/src/repositories/claim_token.rs core/tests/claim_confirm_repo_test.rs
git commit -m "feat(claim): atomic confirm-and-consume, replacing single-step claim"
```

---

### Task 5: `send_claim_confirmation` email method

**Files:**
- Modify: `api/src/email_service.rs`
- Test: inline `#[cfg(test)]` module in `api/src/email_service.rs`

**Interfaces:**
- Produces: `async fn send_claim_confirmation(&self, to_email: &str, confirm_token: &str) -> Result<(), String>` on `EmailSender`, `DevEmailSender`, `SendGridEmailSender`, and the legacy `EmailService` shim.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn dev_sender_captures_claim_confirmation() {
    let sender = DevEmailSender::new();
    sender.send_claim_confirmation("user@example.com", "conf-tok").await.unwrap();
    let captured = sender.get_captured_emails();
    assert_eq!(captured.len(), 1);
    assert!(captured[0]
        .verification_url
        .as_deref()
        .is_some_and(|u| u.ends_with("/api/claim/confirm?token=conf-tok")));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api && cargo test --lib email_service::tests::dev_sender_captures_claim_confirmation`
Expected: FAIL — method not found.

- [ ] **Step 3: Implement**

Add to the `EmailSender` trait:

```rust
/// Send a confirmation link that finishes a staged account claim.
async fn send_claim_confirmation(&self, to_email: &str, confirm_token: &str) -> Result<(), String>;
```

`DevEmailSender`: build `format!("{}/api/claim/confirm?token={}", self.base_url, confirm_token)`, log + `eprintln!` it (mirror `send_claim_email` at `email_service.rs:274`), and push a `CapturedEmail { to, subject: format!("Confirm your email to claim your {} account", BRAND_NAME), verification_url: Some(confirm_url), reset_url: None, pin: None }`.

`SendGridEmailSender`: build the same URL, then a subject + HTML/text body mirroring `send_claim_email` (`email_service.rs:594`) but framed as confirming the address to finish claiming, noting the 24-hour expiry, and call `self.send_email(...)`. Copy uses no em dashes.

`EmailService` shim: delegate `self.inner.send_claim_confirmation(to_email, confirm_token).await`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd api && cargo test --lib email_service::tests::dev_sender_captures_claim_confirmation`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/src/email_service.rs
git commit -m "feat(claim): add claim-confirmation email"
```

---

### Task 6: Restructure `claim_post` to stage + send + interstitial

**Files:**
- Modify: `api/src/api/http/claim.rs`
- Test: `api/tests/claim_confirmation_test.rs` (create)

**Interfaces:**
- Consumes: `ClaimTokenRepository::stage_pending_claim` (Task 3), `EmailSender::send_claim_confirmation` (Task 5), `generate_secure_token` (`api/src/api/http/auth.rs:94`), `CLAIM_CONFIRMATION_EXPIRY_HOURS` (Task 2).
- Produces: `claim_post` returns a 200 "Check your email" interstitial after staging; helper `claim_confirmation_sent_html(email: Option<&str>) -> String` (the submit path passes `Some(address)`; the enumeration-safe resend path in Task 8 passes `None` for generic copy).

- [ ] **Step 1: Write the failing test**

```rust
// api/tests/claim_confirmation_test.rs — uses the existing test harness in api/tests/common.
#[tokio::test]
async fn post_claim_stages_and_sends_without_mutating_user() {
    let ctx = TestApp::spawn().await;                 // existing helper
    let (token, pubkey) = ctx.seed_valid_claim_token().await;

    let resp = ctx.post_form("/api/claim", &[
        ("token", token.as_str()),
        ("email", "new@example.com"),
        ("password", "supersecret"),
        ("password_confirmation", "supersecret"),
    ]).await;

    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.contains("Check your email"));

    // User not mutated, token not consumed, no session cookie.
    assert!(ctx.user_email(&pubkey).await.is_none());
    assert!(!ctx.claim_token_used(&token).await);
    // Exactly one confirmation email captured.
    let emails = ctx.captured_emails();
    assert_eq!(emails.len(), 1);
    assert!(emails[0].verification_url.as_deref().unwrap().contains("/api/claim/confirm?token="));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api && cargo test --test claim_confirmation_test post_claim_stages_and_sends_without_mutating_user`
Expected: FAIL (still completes the claim / sets cookie).

- [ ] **Step 3: Rewrite `claim_post`**

Keep the token classification, password match/length, email format, and `email_exists` checks, and the bcrypt hashing (all unchanged, and hashing stays outside any transaction). Replace the consume-and-session tail with:

```rust
let confirmation_token = super::auth::generate_secure_token();
let confirmation_expires_at =
    Utc::now() + Duration::hours(keycast_core::types::claim_token::CLAIM_CONFIRMATION_EXPIRY_HOURS);

use keycast_core::repositories::StagePendingOutcome;
match claim_token_repo
    .stage_pending_claim(
        &form.token, tenant_id, &form.email, &password_hash,
        &confirmation_token, confirmation_expires_at,
    )
    .await
    .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
{
    StagePendingOutcome::Staged => {}
    StagePendingOutcome::TokenNotStageable => {
        // Token died between classification and staging — re-classify for the
        // state-specific error page (mirrors the old TokenNotConsumable arm).
        return Err(reclassify_to_error(&claim_token_repo, &form.token, tenant_id).await?);
    }
}

// Best-effort send; a send failure should not strand a staged claim silently.
if let Err(e) = auth_state.state.email_sender.send_claim_confirmation(&form.email, &confirmation_token).await {
    tracing::error!("Failed to send claim confirmation to {}: {}", &form.email, e);
    return Err(ClaimError::Internal("Could not send confirmation email".to_string()));
}

tracing::info!("Claim staged: pubkey={}, confirmation email sent", &claim_token.user_pubkey[..8]);
Ok(Html(claim_confirmation_sent_html(Some(&form.email))).into_response())
```

Add `claim_confirmation_sent_html(email: Option<&str>)` (reuse the claim page shell/styling; when `Some`, show the escaped destination address, when `None` show generic copy; render a resend button that POSTs `/api/claim/resend` with the claim token in a hidden field). Extract the existing `TokenNotConsumable` re-classify block from the old handler into a shared `reclassify_to_error` helper so both `claim_post` and `claim_confirm_get` use it.

Confirm `AuthState` exposes the email sender (it is constructed in `routes.rs`/app state; if not yet threaded into the claim handler's state, thread `Arc<dyn EmailSender>` through `AuthState`, matching how the auth handlers reach it).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd api && cargo test --test claim_confirmation_test post_claim_stages_and_sends_without_mutating_user`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/src/api/http/claim.rs api/tests/claim_confirmation_test.rs
git commit -m "feat(claim): stage claim and email confirmation instead of completing on submit"
```

---

### Task 7: `claim_confirm_get` handler + route

**Files:**
- Modify: `api/src/api/http/claim.rs` (handler, `ClaimError::ConfirmationUnrecognized`, `ClaimError::ConfirmationExpired`, `ClaimQuery` reuse)
- Modify: `api/src/api/http/routes.rs:355`
- Test: `api/tests/claim_confirmation_test.rs`

**Interfaces:**
- Consumes: `UserRepository::confirm_claim_consuming_token` (Task 4), the existing session-UCAN + success-page tail (moved from `claim_post`), `reclassify_to_error` (Task 6).
- Produces: `pub async fn claim_confirm_get(tenant, State(auth_state), Query(params): Query<ClaimQuery>) -> Result<Response, ClaimError>`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn confirm_completes_claim_and_sets_session() {
    let ctx = TestApp::spawn().await;
    let (token, pubkey) = ctx.seed_valid_claim_token().await;
    ctx.post_form("/api/claim", &[
        ("token", token.as_str()), ("email", "new@example.com"),
        ("password", "supersecret"), ("password_confirmation", "supersecret"),
    ]).await;
    let confirm_token = ctx.last_captured_confirm_token();   // parse token= from captured url

    let resp = ctx.get(&format!("/api/claim/confirm?token={confirm_token}")).await;

    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("set-cookie").unwrap().to_str().unwrap().contains("keycast_session="));
    assert!(resp.text().await.contains("Account Claimed"));
    assert_eq!(ctx.user_email(&pubkey).await.as_deref(), Some("new@example.com"));
    assert!(ctx.user_email_verified(&pubkey).await);
}

#[tokio::test]
async fn confirm_with_unknown_token_is_unrecognized() {
    let ctx = TestApp::spawn().await;
    let resp = ctx.get("/api/claim/confirm?token=does-not-exist").await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.contains("Link not recognized"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api && cargo test --test claim_confirmation_test confirm_`
Expected: FAIL — route/handler missing.

- [ ] **Step 3: Implement the handler**

```rust
/// GET /api/claim/confirm?token=<confirmation_token>
pub async fn claim_confirm_get(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Query(params): Query<ClaimQuery>,
) -> Result<Response, ClaimError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let user_repo = UserRepository::new(pool.clone());

    use keycast_core::repositories::ClaimConsumeOutcome;
    let user_pubkey = match user_repo
        .confirm_claim_consuming_token(&params.token, tenant_id)
        .await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        ClaimConsumeOutcome::Claimed { user_pubkey } => user_pubkey,
        ClaimConsumeOutcome::EmailTaken => return Err(ClaimError::EmailExists),
        ClaimConsumeOutcome::UserNotClaimable => return Err(ClaimError::TokenAlreadyClaimed),
        // No consumable row for this confirmation token: unknown, expired, or
        // already used. Distinguish expired-vs-unknown for a precise message.
        ClaimConsumeOutcome::TokenNotConsumable => {
            return Err(classify_confirmation_failure(pool, &params.token, tenant_id).await?);
        }
    };

    // Session + success page: relocate the existing claim_post tail verbatim
    // (old claim.rs:437-674) — PublicKey::from_hex(&user_pubkey), get_user_status,
    // get_server_keys, generate_server_signed_ucan(.., "claim", ..), the
    // "keycast_session=...; Max-Age=7d" Set-Cookie, and the "Account Claimed!"
    // success HTML. It compiles unchanged here because user_pubkey is in scope.
    let user_pubkey = nostr_sdk::PublicKey::from_hex(&user_pubkey)
        .map_err(|e| ClaimError::Internal(format!("Invalid pubkey: {}", e)))?;
    // ... relocated UCAN issuance + Set-Cookie + success-page render ...
    Ok(([(header::SET_COOKIE, cookie_value)], Html(success_html)).into_response())
}
```

Add a `classify_confirmation_failure` helper: if a row exists for this `confirmation_token` but `confirmation_expires_at <= NOW()`, return `ConfirmationExpired`; otherwise `ConfirmationUnrecognized`. (Because the successful consume nulls the token, a completed claim's re-click finds no row and yields `ConfirmationUnrecognized`, which is the intended idempotent behavior per the spec.)

Add the two `ClaimError` variants and their pages to the `IntoResponse` match:

| Variant | Title | Message |
|---|---|---|
| `ConfirmationUnrecognized` | Link not recognized | We don't recognize this confirmation link. It may have already been used. If you set up your account, sign in at divine.video. |
| `ConfirmationExpired` | Confirmation link expired | Confirmation links are valid for 24 hours. Open your original claim link again to restart, or email support@divine.video for a fresh one. |

Register the route in `routes.rs`:

```rust
.route("/claim/confirm", get(claim::claim_confirm_get))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd api && cargo test --test claim_confirmation_test confirm_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/src/api/http/claim.rs api/src/api/http/routes.rs
git commit -m "feat(claim): confirm handler completes the claim and issues the session"
```

---

### Task 8: `claim_resend_post` + migrate legacy tests

**Files:**
- Modify: `api/src/api/http/claim.rs` (handler + `ClaimResendForm`)
- Modify: `api/src/api/http/routes.rs`
- Modify: `api/tests/claim_consume_race_test.rs`, `core/tests/pool_nesting_test.rs`
- Test: `api/tests/claim_confirmation_test.rs`

**Interfaces:**
- Consumes: a new `ClaimTokenRepository::resend_claim_confirmation(token, tenant_id) -> ResendOutcome` that, under a 5-minute `confirmation_sent_at` cooldown (baked into the SQL), refreshes or regenerates the confirmation token.
- Produces: `POST /api/claim/resend`; the outcome enum
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum ResendOutcome {
      /// A fresh or reused confirmation token to email to `to_email`.
      Sent { to_email: String, confirmation_token: String },
      /// Within the 5-minute cooldown; nothing re-sent.
      Cooldown,
      /// No staged, still-valid pending claim for this token.
      NoPendingClaim,
  }
  ```

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn resend_is_rate_limited_and_enumeration_safe() {
    let ctx = TestApp::spawn().await;
    let (token, _pubkey) = ctx.seed_valid_claim_token().await;
    ctx.post_form("/api/claim", &[
        ("token", token.as_str()), ("email", "new@example.com"),
        ("password", "supersecret"), ("password_confirmation", "supersecret"),
    ]).await;
    ctx.clear_captured_emails();

    // Immediate resend is within cooldown: same interstitial, no new email.
    let resp = ctx.post_form("/api/claim/resend", &[("token", token.as_str())]).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.contains("Check your email"));
    assert_eq!(ctx.captured_emails().len(), 0);

    // Unknown token also returns the same interstitial (no enumeration).
    let resp2 = ctx.post_form("/api/claim/resend", &[("token", "nope")]).await;
    assert_eq!(resp2.status(), 200);
    assert!(resp2.text().await.contains("Check your email"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api && cargo test --test claim_confirmation_test resend_`
Expected: FAIL — route/handler missing.

- [ ] **Step 3: Implement**

Add `resend_claim_confirmation` to `ClaimTokenRepository`: select `confirmation_token`, `confirmation_sent_at`, `confirmation_expires_at` for the token where a pending claim exists (`pending_email IS NOT NULL AND used_at IS NULL AND invalidated_at IS NULL AND expires_at > NOW()`). If `confirmation_sent_at > NOW() - interval '5 minutes'` return `ResendOutcome::Cooldown`. Else if `confirmation_expires_at <= NOW()` mint a fresh `confirmation_token` + new `confirmation_expires_at`; otherwise reuse the current token. Bump `confirmation_sent_at = NOW()` and return `ResendOutcome::Sent { to_email, confirmation_token }`. No pending row → `ResendOutcome::NoPendingClaim`.

`claim_resend_post`: on `Sent`, call `send_claim_confirmation` and render the interstitial; on `Cooldown` / `NoPendingClaim`, render the same interstitial without sending (enumeration-safe). The interstitial cannot show the destination address on the enumeration-safe branches, so the resend interstitial uses generic copy ("If a pending claim exists, we've sent another link.").

Register the route:

```rust
.route("/claim/resend", post(claim::claim_resend_post))
```

- [ ] **Step 4: Migrate the legacy tests**

In `api/tests/claim_consume_race_test.rs`, re-express each `claim_account_consuming_token` call as `stage_pending_claim` + `confirm_claim_consuming_token`, keeping the concurrent-consume assertions (only one confirm wins). Run with `max_connections(1)` where nested acquisition is under test. In `core/tests/pool_nesting_test.rs`, point the claim probe (line ~381) at `confirm_claim_consuming_token` (stage first, then confirm) so the one-connection assertion still covers the claim path.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd api && cargo test --test claim_confirmation_test && cargo test --test claim_consume_race_test && cd ../core && cargo test --test pool_nesting_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api/src/api/http/claim.rs api/src/api/http/routes.rs core/src/repositories/claim_token.rs api/tests/claim_consume_race_test.rs core/tests/pool_nesting_test.rs
git commit -m "feat(claim): cooldown-gated resend and migrate consume tests to two-step"
```

---

### Task 9: Full-suite verification + manual browser check

**Files:** none (verification only).

- [ ] **Step 1: Format + lint**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated`
Expected: clean.

- [ ] **Step 2: Workspace + integration tests**

Run: `bun run test`
Expected: PASS (spins up Postgres + Redis, sets up the test DB, runs the full workspace + integration-feature suite).

- [ ] **Step 3: Manual browser walk-through (dev)**

With `bun run dev` and `DevEmailSender`, seed a claim token, open `/api/claim?token=...`, submit an email + password, confirm the interstitial renders, copy the confirmation URL from the dev-email console output, open it, and confirm the success page renders and login works with the new credentials. Verify an expired confirmation (hand-edit `confirmation_expires_at` in the dev DB) shows the expired page, and a re-clicked completed link shows "Link not recognized". Note these manual checks in the PR.

- [ ] **Step 4: No commit** (verification task; fixes for any failure go into the relevant task's commit).

---

## Notes for the executor

- **`AuthState` / email sender wiring:** the claim handlers must reach the `Arc<dyn EmailSender>`. Check how `auth.rs` handlers obtain it and follow the same path; if the claim route's state does not yet carry it, thread it through in Task 6 rather than constructing a sender inline.
- **`TestApp` harness:** `api/tests/common/mod.rs` holds the existing integration harness and claim-token fixtures. Extend it with the small helpers referenced here (`seed_valid_claim_token`, `user_email`, `user_email_verified`, `claim_token_used`, `captured_emails`, `last_captured_confirm_token`) rather than inventing a parallel harness.
- **Do not** add the new columns to the `ClaimToken` struct or `claim_token_columns!()` macro; `classify()` stays as-is and the new methods query the new columns explicitly.
- **Transaction discipline:** the confirm path does all its mutation in one transaction with the validity guard in the `UPDATE ... WHERE`; do not add a separate pre-read of the token (that reintroduces the race the guard removes).
