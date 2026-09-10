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

## Reuse and shared primitives

This feature is a sibling of the shipped **self-serve email-change** flow. Reuse decisions, so the executor shares what's cleanly shareable and mirrors (rather than bends) what isn't:

- **REUSE `generate_secure_token()`** (`api/src/api/http/auth.rs:94`) for the confirmation token — the one shared generator, already used by verification/reset/email-change. Do not add a new generator.
- **GENERALIZE the email body (Task 5):** introduce a shared `action_email_html(title, intro, button_label, url, footer)` + `action_email_text(...)` builder in `email_service.rs` and build the new claim-confirmation email on it. The four existing hand-rolled bodies (`send_password_reset_email`, `send_claim_email`, `send_email_change_confirmation`, `send_email_change_notification`) are **left byte-for-byte untouched** — retrofitting them onto the builder is a separate, deliberately-scoped cleanup, because reformatting a shipped email's HTML changes its rendered output.
- **GENERALIZE the cooldown check (Task 8):** add a pure `within_cooldown(last_sent: Option<DateTime<Utc>>, minutes: i64) -> bool` helper (in `auth.rs` beside the expiry constants) and use it for the claim resend. The three existing inline copies (`auth.rs:2633` verification, `auth.rs:4282` email-change, `headless.rs:1234` PIN) keep their surrounding policy (enumeration-safety, same-target scoping, atomic re-check); migrating just their boolean check to the helper is a behavior-preserving optional follow-up, not part of this feature.
- **MIRROR, do not share, the pending/confirm repository methods.** The email-change methods (`set_pending_email_change`, `find_by_pending_email_token`, `mark_pending_email_confirmed`, `finalize_email_change_if_ready`, `PendingEmailSide`, `user.rs:1007-1236`) are built around a **dual-token, both-sides** confirmation; a claim confirm is one-sided. Reuse their *shape* (stage token+expiry → guarded atomic apply → clear pending) and name the claim methods as visible siblings, but write claim-specific methods rather than distorting the dual-confirmation ones.
- **MIRROR the confirm-handler skeleton.** There is no generic "look up by confirmation token + validate expiry" helper; `confirm_email_change` (`auth.rs:4373`) is bespoke against its own schema. `claim_confirm_get` follows the same lookup → expiry → atomic-apply → (log) skeleton against the claim columns.
- **MIRROR the page shell.** No server-rendered page-shell helper exists (claim/auth/oauth each embed their own `<style>`); reuse only the `html_safety.rs` escapers (`escape_html`, `escape_attr`), as the existing claim pages do. Extracting a cross-file shell is out of scope.

## File Structure

- `database/migrations/20260910120000_add_claim_confirmation.sql` — **create.** Adds `pending_email`, `pending_password_hash`, `confirmation_token`, `confirmation_expires_at`, `confirmation_sent_at` to `account_claim_tokens` + partial unique index on `confirmation_token`.
- `core/src/repositories/user.rs` — **modify.** Add `EmailTaken` to `ClaimConsumeOutcome`; add `confirm_claim_consuming_token`; remove `claim_account_consuming_token`.
- `core/src/repositories/claim_token.rs` — **modify.** Add `stage_pending_claim` + a `StagePendingOutcome` enum; add `CLAIM_CONFIRMATION_EXPIRY_HOURS`.
- `api/src/email_service.rs` — **modify.** Add a shared `action_email_html`/`action_email_text` builder; add `send_claim_confirmation` to the `EmailSender` trait and both impls (SendGrid body built on the new builder); extend `CapturedEmail` usage. Shipped email bodies untouched.
- `api/src/api/http/auth.rs` — **modify.** Add `pub(crate) fn within_cooldown(last_sent, minutes)` beside the expiry constants (used by the claim resend; existing call sites unchanged).
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
- Pattern: mirrors the guarded pending-state write `set_pending_email_change` (`core/src/repositories/user.rs:1007`) — a sibling, not a shared method.

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
- Pattern: the guarded-atomic-apply shape mirrors `finalize_email_change_if_ready` (`core/src/repositories/user.rs:1158`) — apply only if the guard still holds, mapping the unique violation to `EmailTaken`. One-sided, so it's a claim-specific method, not the dual-token one.

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
- Produces: free functions `action_email_html(title, intro, button_label, url, footer) -> String` and `action_email_text(intro, url, footer) -> String`; `async fn send_claim_confirmation(&self, to_email: &str, confirm_token: &str) -> Result<(), String>` on `EmailSender`, `DevEmailSender`, `SendGridEmailSender`, and the legacy `EmailService` shim.

- [ ] **Step 1: Write the failing test (shared builder + capture)**

```rust
#[test]
fn action_email_html_has_shell_button_and_fallback_link() {
    let url = "https://login.example/api/claim/confirm?token=abc";
    let html = action_email_html("Confirm your email", "Click to finish.", "Confirm", url, "Expires in 24 hours.");
    assert!(html.contains("Confirm your email"));   // title
    assert!(html.contains(">Confirm<"));            // button label
    assert!(html.contains(url));                     // button href + fallback link
    assert!(html.contains("Expires in 24 hours."));  // footer
}

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

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd api && cargo test --lib email_service::tests::action_email_html_has_shell_button_and_fallback_link email_service::tests::dev_sender_captures_claim_confirmation`
Expected: FAIL — builder + method not found.

- [ ] **Step 3: Implement the shared builder**

Add free functions modeled on the shared shell the four inline bodies already use (`#00B488` header, button `<div style="margin: 30px 0;">`, "Or copy and paste this link" fallback). The `title`/`button_label`/`footer`/`intro` are the only things that vary between the existing emails; `BRAND_NAME` is available from `crate::brand`. Do **not** modify the four shipped bodies.

```rust
/// Shared shell for action emails (a titled body with one primary button and a
/// copy-paste fallback link). New emails build on this; shipped bodies are left
/// as-is to preserve their exact rendered output.
fn action_email_html(title: &str, intro: &str, button_label: &str, url: &str, footer: &str) -> String {
    format!(
        r#"
        <html>
        <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00B488;">{title}</h1>
            <p>{intro}</p>
            <div style="margin: 30px 0;">
                <a href="{url}" style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">{button_label}</a>
            </div>
            <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:<br>
                <a href="{url}" style="color: #00B488;">{url}</a></p>
            <p style="color: #666; font-size: 14px; margin-top: 30px;">{footer}</p>
        </body>
        </html>
        "#,
    )
}

fn action_email_text(intro: &str, url: &str, footer: &str) -> String {
    format!("{intro}\n\n{url}\n\n{footer}")
}
```

- [ ] **Step 4: Implement `send_claim_confirmation`**

Add to the `EmailSender` trait:

```rust
/// Send a confirmation link that finishes a staged account claim.
async fn send_claim_confirmation(&self, to_email: &str, confirm_token: &str) -> Result<(), String>;
```

`DevEmailSender`: build `format!("{}/api/claim/confirm?token={}", self.base_url, confirm_token)`, log + `eprintln!` it (mirror `send_claim_email` at `email_service.rs:274`), and push a `CapturedEmail { to, subject: format!("Confirm your email to claim your {} account", BRAND_NAME), verification_url: Some(confirm_url), reset_url: None, pin: None }`.

`SendGridEmailSender`: build the same URL, a subject `format!("Confirm your email to claim your {} account", BRAND_NAME)`, then bodies via the shared builder, and call `self.send_email(...)`. Copy uses no em dashes:

```rust
let confirm_url = format!("{}/api/claim/confirm?token={}", self.base_url, confirm_token);
let subject = format!("Confirm your email to claim your {} account", BRAND_NAME);
let intro = format!("Confirm this email address to finish claiming your {} account.", BRAND_NAME);
let footer = "This link will expire in 24 hours. If you didn't request this, you can safely ignore this email.";
let html = action_email_html("Confirm your email", &intro, "Confirm Email", &confirm_url, footer);
let text = action_email_text(&intro, &confirm_url, footer);
self.send_email(to_email, &subject, &html, &text).await
```

`EmailService` shim: delegate `self.inner.send_claim_confirmation(to_email, confirm_token).await`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd api && cargo test --lib email_service::tests::action_email_html_has_shell_button_and_fallback_link email_service::tests::dev_sender_captures_claim_confirmation`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api/src/email_service.rs
git commit -m "feat(claim): shared action-email builder and claim-confirmation email"
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
- Pattern: mirrors the `confirm_email_change` handler skeleton (`api/src/api/http/auth.rs:4373`) — lookup by token → validate expiry → atomic guarded apply → branch on outcome. No shared validator exists; follow the shape.

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
- Consumes: `within_cooldown` (defined here), `generate_secure_token`, `CLAIM_CONFIRMATION_EXPIRY_HOURS`, `EmailSender::send_claim_confirmation`, `claim_confirmation_sent_html` (Task 6).
- Produces:
  - `pub(crate) fn within_cooldown(last_sent: Option<DateTime<Utc>>, minutes: i64) -> bool` in `auth.rs` (pure; `None` last_sent is not within cooldown).
  - `pub const CLAIM_RESEND_COOLDOWN_MINUTES: i64 = 5;`
  - Repo (mirrors `pending_email_send_state` / the email-change setters, layering-clean: core returns data, the handler applies policy):
    ```rust
    pub struct PendingClaimSendState {
        pub to_email: String,
        pub confirmation_sent_at: Option<DateTime<Utc>>,
        pub confirmation_token: String,
        pub confirmation_expired: bool,
    }
    // None when no staged, still-valid pending claim exists for this token.
    pub async fn pending_claim_send_state(&self, token: &str, tenant_id: i64)
        -> Result<Option<PendingClaimSendState>, RepositoryError>;
    // Bumps confirmation_sent_at = NOW(); when `rotated` is Some, also replaces
    // confirmation_token + confirmation_expires_at (used when the prior one expired).
    pub async fn touch_claim_confirmation(&self, token: &str, tenant_id: i64,
        rotated: Option<(&str, DateTime<Utc>)>) -> Result<(), RepositoryError>;
    ```
  - `POST /api/claim/resend`.

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

- [ ] **Step 3: Implement `within_cooldown` + the repo methods**

Add the shared helper to `auth.rs` beside the expiry constants, and its unit test:

```rust
/// True when `last_sent` is within `minutes` of now. A missing timestamp
/// (never sent) is not within cooldown. Pure; shared by resend paths.
pub(crate) fn within_cooldown(last_sent: Option<DateTime<Utc>>, minutes: i64) -> bool {
    match last_sent {
        Some(sent) => Utc::now() - sent < Duration::minutes(minutes),
        None => false,
    }
}
```

Define `pub const CLAIM_RESEND_COOLDOWN_MINUTES: i64 = 5;` in `auth.rs` beside `EMAIL_CHANGE_RESEND_COOLDOWN_MINUTES` (`auth.rs:46`).

Add `pending_claim_send_state` (SELECT `pending_email`, `confirmation_sent_at`, `confirmation_token`, `(confirmation_expires_at <= NOW())` for the row where `token = $1 AND tenant_id = $2 AND pending_email IS NOT NULL AND used_at IS NULL AND invalidated_at IS NULL AND expires_at > NOW()`; explicit columns) and `touch_claim_confirmation` (one UPDATE: `SET confirmation_sent_at = NOW()`, plus `confirmation_token = $x, confirmation_expires_at = $y` when `rotated` is `Some`, guarded by the same still-valid predicate) to `ClaimTokenRepository`.

- [ ] **Step 4: Implement `claim_resend_post`**

```rust
pub async fn claim_resend_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Form(form): Form<ClaimResendForm>,   // { token: String }
) -> Result<Response, ClaimError> {
    let tenant_id = tenant.0.id;
    let repo = ClaimTokenRepository::new(auth_state.state.db.clone());

    if let Some(state) = repo.pending_claim_send_state(&form.token, tenant_id).await
        .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?
    {
        if !super::auth::within_cooldown(state.confirmation_sent_at, CLAIM_RESEND_COOLDOWN_MINUTES) {
            // Rotate the token only if the previous one expired; otherwise re-send the same one.
            let confirm_token = if state.confirmation_expired {
                let fresh = super::auth::generate_secure_token();
                let expiry = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
                repo.touch_claim_confirmation(&form.token, tenant_id, Some((&fresh, expiry))).await
                    .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?;
                fresh
            } else {
                repo.touch_claim_confirmation(&form.token, tenant_id, None).await
                    .map_err(|e| ClaimError::Internal(format!("Database error: {}", e)))?;
                state.confirmation_token
            };
            if let Err(e) = auth_state.state.email_sender
                .send_claim_confirmation(&state.to_email, &confirm_token).await
            {
                tracing::error!("Failed to resend claim confirmation: {}", e);
            }
        }
    }
    // Enumeration-safe: identical generic interstitial regardless of token state.
    Ok(Html(claim_confirmation_sent_html(None)).into_response())
}
```

Register the route:

```rust
.route("/claim/resend", post(claim::claim_resend_post))
```

- [ ] **Step 5: Migrate the legacy tests**

In `api/tests/claim_consume_race_test.rs`, re-express each `claim_account_consuming_token` call as `stage_pending_claim` + `confirm_claim_consuming_token`, keeping the concurrent-consume assertions (only one confirm wins). Run with `max_connections(1)` where nested acquisition is under test. In `core/tests/pool_nesting_test.rs`, point the claim probe (line ~381) at `confirm_claim_consuming_token` (stage first, then confirm) so the one-connection assertion still covers the claim path.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd api && cargo test --test claim_confirmation_test && cargo test --test claim_consume_race_test && cd ../core && cargo test --test pool_nesting_test`
Expected: PASS.

- [ ] **Step 7: Commit**

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
