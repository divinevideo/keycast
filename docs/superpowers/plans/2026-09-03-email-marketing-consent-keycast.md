# Email Marketing Consent (keycast side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make keycast record email marketing consent in an auditable, tri-state form and expose it to a sync service, including a suppression floor and account-deletion tombstones.

**Architecture:** Consent is an immutable event on the `users` row (state, when, source, app version). A separate nullable flag records the suppression floor observed from HubSpot. Three service-token endpoints let the sync service read consent by cursor, write back the floor, and drain deletion tombstones. keycast never calls HubSpot.

**Tech Stack:** Rust, axum, sqlx, PostgreSQL.

**Spec:** `divine-invite-sync/docs/superpowers/specs/2026-09-03-email-marketing-consent-sync-design.md`

## Global Constraints

- Column naming is `email_marketing_*`, never bare `marketing_*`. A push opt-in is coming in `divine-engagement` and an unqualified name will be misread.
- Consent state is exactly one of `never_asked`, `declined`, `opted_in`.
- `email_marketing_global_optout` is **nullable**. NULL means never observed; it must never default to `false`.
- The consent event is immutable: no endpoint in this plan may write `email_marketing_consent`, `email_marketing_consent_at`, `email_marketing_consent_source`, or `email_marketing_consent_app_version` after materialization.
- All three new endpoints authenticate via the existing `authorize_service_token(&headers)`. Never `is_support_admin`.
- The npub is internal. It appears in these APIs because the sync service writes state back by pubkey; it must never be forwarded to HubSpot.
- Migrations must sort after main's latest (`20260822010000`). Check for prefix collisions before naming a new one.
- No `Co-Authored-By` lines in commits.

## Verified preconditions

- `core/src/repositories/user.rs:1166` bumps `updated_at` when an email change is finalized, so a
  changed address moves the row past the cursor and the sync service sees it. The cursor design
  depends on this; if that ever stops being true, email changes become invisible to the sync.
- `authorize_service_token(&headers)` already exists in `api/src/api/http/admin.rs` and is already
  used by `POST /admin/users/batch-lookup`. No new auth mechanism is introduced here.

## Review

**This needs Daniel's review before it lands.** It is not a self-contained feature: it adds public
surface and writes inside core paths of the authentication service.

Specifically worth his eye:
- Three new service-token endpoints on keycast, and the fact that `KEYCAST_SERVICE_TOKEN` is a
  single shared secret rather than per-service scoped, so a marketing sync service holding it can
  also reach service-provisioning and ActivityPub gateway routes.
- New columns on `users`, on a table central to authentication.
- Statements added inside the account-deletion transaction (Task 4) and the email-change
  finalization transaction (Task 4b). Both are correctness-critical: a write in the wrong place or
  outside the transaction either loses the record or claims something happened that was rolled back.
- Whether the cursor index `(updated_at, pubkey)` on `users` is acceptable on a table of this size
  and write frequency.

## Prerequisite

This plan amends the migration on **divinevideo/keycast#404 before that PR merges**. Nothing has shipped, so the migration file is rewritten in place rather than superseded. Work on branch `feat/marketing-consent-registration`.

## Companion change, not in this plan

`divine-mobile` PR #8452 must send `app_version` on `POST /api/headless/register`. Without it, `email_marketing_consent_app_version` is always NULL. Task 2 makes the field optional so the two PRs can land in either order.

## File Structure

| File | Responsibility |
|---|---|
| `database/migrations/20260823120000_add_marketing_consent.sql` | Rewritten: tri-state consent event, suppression floor, renamed columns |
| `database/migrations/20260903120000_email_marketing_deletions.sql` | New: deletion tombstones |
| `database/migrations/20260903120100_email_marketing_email_changes.sql` | New: email-change rows |
| `core/src/repositories/email_marketing.rs` | New: the `EmailMarketingConsent` enum and its conversions |
| `core/src/repositories/oauth_code.rs` | Modified: carry tri-state consent through the three materialization write branches |
| `core/src/repositories/user.rs` | Modified: write a tombstone during account deletion |
| `api/src/api/http/headless.rs` | Modified: accept `app_version`, map `Option<bool>` to tri-state |
| `api/src/api/http/oauth.rs` | Modified: browser path records `never_asked` |
| `api/src/api/http/email_marketing.rs` | New: the three service-token endpoints |
| `api/src/api/http/routes.rs` | Modified: mount the new routes |

---

### Task 1: Rewrite the consent schema

**Files:**
- Modify: `database/migrations/20260823120000_add_marketing_consent.sql` (whole file)

**Interfaces:**
- Consumes: nothing.
- Produces: columns `users.email_marketing_consent`, `users.email_marketing_consent_at`, `users.email_marketing_consent_source`, `users.email_marketing_consent_app_version`, `users.email_marketing_global_optout`, `users.email_marketing_optout_observed_at`, `oauth_codes.pending_email_marketing_consent`, `oauth_codes.pending_email_marketing_app_version`.

- [ ] **Step 1: Replace the migration file contents**

```sql
-- Email-marketing consent captured at account creation (mobile create-account screen).
--
-- Two distinct things live here and must not be conflated:
--
--   1. The consent EVENT. What the person answered, when, from where, and under which app
--      version. Immutable. Never overwritten, because overwriting it destroys the evidence that
--      consent was validly obtained.
--   2. The suppression FLOOR. Observed from the email platform, recording that this person opted
--      out of all email. This is Divine's own signal, not a mirror: HubSpot forgets an opt-out as
--      soon as the address changes, so the floor is the only thing that remembers. Any Divine
--      system that sends marketing email must respect it, whatever CRM it uses.
--
-- Tri-state rather than boolean: (false, NULL) cannot distinguish "asked and declined" from
-- "never asked", and that distinction decides whether it is legitimate to ask again.
--
-- Named email_marketing_* rather than marketing_*: divine-engagement is introducing a push opt-in
-- with its own settings, and an unqualified name would be misread.
ALTER TABLE users
    ADD COLUMN email_marketing_consent TEXT NOT NULL DEFAULT 'never_asked'
        CHECK (email_marketing_consent IN ('never_asked', 'declined', 'opted_in')),
    ADD COLUMN email_marketing_consent_at TIMESTAMPTZ,
    ADD COLUMN email_marketing_consent_source TEXT,
    ADD COLUMN email_marketing_consent_app_version TEXT,
    -- NULL means never observed. Deliberately not NOT NULL DEFAULT FALSE, which would let
    -- "we have never checked" masquerade as "safe to email".
    ADD COLUMN email_marketing_global_optout BOOLEAN,
    ADD COLUMN email_marketing_optout_observed_at TIMESTAMPTZ;

ALTER TABLE oauth_codes
    ADD COLUMN pending_email_marketing_consent TEXT NOT NULL DEFAULT 'never_asked'
        CHECK (pending_email_marketing_consent IN ('never_asked', 'declined', 'opted_in')),
    ADD COLUMN pending_email_marketing_app_version TEXT;

-- The sync service reads consent by cursor, ordered by (updated_at, pubkey).
CREATE INDEX idx_users_email_marketing_cursor ON users (updated_at, pubkey);
```

- [ ] **Step 2: Verify no migration prefix collides with main**

Run:
```bash
git fetch origin main --quiet
git ls-tree --name-only origin/main database/migrations/ | sed 's|.*/||' | cut -d_ -f1 > /tmp/main_versions
ls database/migrations/ | cut -d_ -f1 | sort | uniq -d
comm -12 <(sort -u /tmp/main_versions) <(ls database/migrations/ | cut -d_ -f1 | sort -u)
```
Expected: the second command prints nothing; the third prints only versions that exist on both sides because they are the *same* file. Any version present in both lists under two different filenames is a collision and must be renumbered past `20260822010000`.

- [ ] **Step 3: Commit**

```bash
git add database/migrations/20260823120000_add_marketing_consent.sql
git commit -m "refactor(consent): tri-state email marketing consent and suppression floor"
```

---

### Task 2: The consent enum and its conversions

**Files:**
- Create: `core/src/repositories/email_marketing.rs`
- Modify: `core/src/repositories/mod.rs` (add `pub mod email_marketing;` and re-export)
- Test: inline `#[cfg(test)]` module in `core/src/repositories/email_marketing.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `EmailMarketingConsent` enum with variants `NeverAsked`, `Declined`, `OptedIn`; `EmailMarketingConsent::as_str(&self) -> &'static str`; `EmailMarketingConsent::from_db(&str) -> Result<Self, String>`; `impl From<Option<bool>> for EmailMarketingConsent`.

- [ ] **Step 1: Write the failing test**

Create `core/src/repositories/email_marketing.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_field_means_never_asked() {
        assert_eq!(EmailMarketingConsent::from(None), EmailMarketingConsent::NeverAsked);
    }

    #[test]
    fn explicit_false_means_declined() {
        assert_eq!(EmailMarketingConsent::from(Some(false)), EmailMarketingConsent::Declined);
    }

    #[test]
    fn explicit_true_means_opted_in() {
        assert_eq!(EmailMarketingConsent::from(Some(true)), EmailMarketingConsent::OptedIn);
    }

    #[test]
    fn round_trips_through_the_database_representation() {
        for state in [
            EmailMarketingConsent::NeverAsked,
            EmailMarketingConsent::Declined,
            EmailMarketingConsent::OptedIn,
        ] {
            assert_eq!(EmailMarketingConsent::from_db(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn rejects_an_unknown_database_value() {
        assert!(EmailMarketingConsent::from_db("subscribed").is_err());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p keycast_core email_marketing`
Expected: FAIL to compile, `cannot find type EmailMarketingConsent in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to the same file, above the test module:

```rust
// ABOUTME: The tri-state email-marketing consent event recorded on a keycast account.
// ABOUTME: Distinguishes "never asked" from "asked and declined"; see the 2026-09-03 sync design.

/// What a person answered when asked about marketing email.
///
/// Tri-state on purpose. A boolean collapses "asked and declined" into "never asked", and that
/// distinction decides whether it is legitimate to ask again. It also maps cleanly onto the
/// `Option<bool>` that `POST /api/headless/register` already accepts, so no API change is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailMarketingConsent {
    NeverAsked,
    Declined,
    OptedIn,
}

impl EmailMarketingConsent {
    /// The stored representation. Must match the CHECK constraint in the migration exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailMarketingConsent::NeverAsked => "never_asked",
            EmailMarketingConsent::Declined => "declined",
            EmailMarketingConsent::OptedIn => "opted_in",
        }
    }

    /// Parse a value read from the database. Returns Err rather than defaulting, so a value the
    /// CHECK constraint should have rejected surfaces loudly instead of silently becoming
    /// "never asked" and re-asking someone who already declined.
    pub fn from_db(value: &str) -> Result<Self, String> {
        match value {
            "never_asked" => Ok(EmailMarketingConsent::NeverAsked),
            "declined" => Ok(EmailMarketingConsent::Declined),
            "opted_in" => Ok(EmailMarketingConsent::OptedIn),
            other => Err(format!("unknown email marketing consent state: {other}")),
        }
    }

    pub fn is_opted_in(&self) -> bool {
        matches!(self, EmailMarketingConsent::OptedIn)
    }
}

impl From<Option<bool>> for EmailMarketingConsent {
    /// The client omitting the field means nobody asked; sending `false` means they were shown the
    /// choice and declined.
    fn from(value: Option<bool>) -> Self {
        match value {
            None => EmailMarketingConsent::NeverAsked,
            Some(false) => EmailMarketingConsent::Declined,
            Some(true) => EmailMarketingConsent::OptedIn,
        }
    }
}
```

- [ ] **Step 4: Register the module**

In `core/src/repositories/mod.rs`, add alongside the existing module declarations:

```rust
pub mod email_marketing;
pub use email_marketing::EmailMarketingConsent;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p keycast_core email_marketing`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add core/src/repositories/email_marketing.rs core/src/repositories/mod.rs
git commit -m "feat(consent): add tri-state EmailMarketingConsent type"
```

---

### Task 3: Carry the tri-state through registration and materialization

**Files:**
- Modify: `api/src/api/http/headless.rs` (request struct ~line 53; `store_with_pending_registration` call ~line 262)
- Modify: `api/src/api/http/oauth.rs:230`
- Modify: `core/src/repositories/oauth_code.rs` (params struct ~line 105, data struct ~line 26, INSERT ~line 315, and all three write branches near lines 486, 511, 568)
- Test: `api/tests/oauth_deferred_registration_test.rs`

**Interfaces:**
- Consumes: `EmailMarketingConsent` from Task 2; the columns from Task 1.
- Produces: `StoreOAuthCodeWithRegistrationParams.pending_email_marketing_consent: EmailMarketingConsent` and `.pending_email_marketing_app_version: Option<&'a str>`; `OAuthCodeData.pending_email_marketing_consent: EmailMarketingConsent`.

- [ ] **Step 1: Write the failing test**

Add to `api/tests/oauth_deferred_registration_test.rs`:

```rust
#[tokio::test]
async fn declining_is_recorded_distinctly_from_never_being_asked() {
    let pool = setup_pool().await;
    let repo = OAuthCodeRepository::new(pool.clone());

    // Someone who saw the checkbox and left it unticked.
    let declined_pubkey = register_and_materialize(&repo, &pool, Some(false), None).await;
    // A flow that never showed the checkbox at all.
    let unasked_pubkey = register_and_materialize(&repo, &pool, None, None).await;

    let declined: String = sqlx::query_scalar(
        "SELECT email_marketing_consent FROM users WHERE pubkey = $1",
    )
    .bind(&declined_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    let unasked: String = sqlx::query_scalar(
        "SELECT email_marketing_consent FROM users WHERE pubkey = $1",
    )
    .bind(&unasked_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(declined, "declined");
    assert_eq!(unasked, "never_asked");
}

#[tokio::test]
async fn opting_in_stamps_the_time_source_and_app_version() {
    let pool = setup_pool().await;
    let repo = OAuthCodeRepository::new(pool.clone());

    let pubkey = register_and_materialize(&repo, &pool, Some(true), Some("1.42.0")).await;

    let (state, at, source, app_version): (String, Option<DateTime<Utc>>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT email_marketing_consent, email_marketing_consent_at,
                    email_marketing_consent_source, email_marketing_consent_app_version
             FROM users WHERE pubkey = $1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(state, "opted_in");
    assert!(at.is_some(), "an answer must be timestamped");
    assert_eq!(source.as_deref(), Some("mobile_create_account"));
    assert_eq!(app_version.as_deref(), Some("1.42.0"));
}

#[tokio::test]
async fn declining_is_still_timestamped() {
    // The answer time is stamped whenever they answered, either way. Only never_asked leaves it
    // NULL. Without this, "declined" and "never asked" become indistinguishable again by timestamp.
    let pool = setup_pool().await;
    let repo = OAuthCodeRepository::new(pool.clone());

    let pubkey = register_and_materialize(&repo, &pool, Some(false), None).await;

    let at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT email_marketing_consent_at FROM users WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(at.is_some());
}

#[tokio::test]
async fn the_suppression_floor_starts_unobserved() {
    let pool = setup_pool().await;
    let repo = OAuthCodeRepository::new(pool.clone());

    let pubkey = register_and_materialize(&repo, &pool, Some(true), None).await;

    let floor: Option<bool> = sqlx::query_scalar(
        "SELECT email_marketing_global_optout FROM users WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(floor, None, "never observed must not read as 'not opted out'");
}
```

Add this helper to the same file, modelled on the existing materialization tests:

```rust
/// Register with the given consent answer and app version, then materialize as the email
/// verification would. Returns the pubkey.
async fn register_and_materialize(
    repo: &OAuthCodeRepository,
    pool: &PgPool,
    consent: Option<bool>,
    app_version: Option<&str>,
) -> String {
    use keycast_core::repositories::EmailMarketingConsent;

    let pubkey = nostr_sdk::Keys::generate().public_key().to_hex();
    let email = format!("{}@example.test", &pubkey[..12]);
    let token = format!("tok-{}", &pubkey[..16]);

    repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
        tenant_id: 1,
        code: &format!("code-{}", &pubkey[..16]),
        user_pubkey: &pubkey,
        client_id: "test-client",
        redirect_uri: "https://example.test/cb",
        scope: None,
        code_challenge: None,
        code_challenge_method: None,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        pending_email: &email,
        pending_password_hash: "hash",
        pending_email_verification_token: &token,
        pending_encrypted_secret: None,
        pending_email_marketing_consent: EmailMarketingConsent::from(consent),
        pending_email_marketing_app_version: app_version,
        state: None,
        device_code: None,
        is_headless: true,
        pin_hash: None,
    })
    .await
    .unwrap();

    repo.materialize_pending_registration(1, &token).await.unwrap();
    pubkey
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p keycast_api --test oauth_deferred_registration_test`
Expected: FAIL to compile, `struct StoreOAuthCodeWithRegistrationParams has no field named pending_email_marketing_consent`.

- [ ] **Step 3: Update the parameter and data structs**

In `core/src/repositories/oauth_code.rs`, replace the `pending_marketing_consent` field in `StoreOAuthCodeWithRegistrationParams`:

```rust
    /// The consent answer from the create-account screen. `NeverAsked` for flows that do not show
    /// the choice (browser OAuth, older clients).
    pub pending_email_marketing_consent: EmailMarketingConsent,
    /// Client app version at the moment of the answer, so we can tell which wording was shown.
    /// None when the client does not send it.
    pub pending_email_marketing_app_version: Option<&'a str>,
```

and in `OAuthCodeData`:

```rust
    /// The consent answer carried on the pending row and written onto the materialized user.
    pub pending_email_marketing_consent: EmailMarketingConsent,
    pub pending_email_marketing_app_version: Option<String>,
```

Add the import at the top of the file:

```rust
use crate::repositories::EmailMarketingConsent;
```

`OAuthCodeData` is populated by `sqlx::query_as` against `SELECT_COLUMNS`. Because `EmailMarketingConsent` is not a sqlx type, read it as `String` in the row struct and convert at the boundary: add `pending_email_marketing_consent_raw: String` to the `FromRow` struct and expose the parsed value via `EmailMarketingConsent::from_db(...)` where it is used in Step 5. Add both new column names to `SELECT_COLUMNS`.

- [ ] **Step 4: Update the INSERT**

In `store_with_pending_registration`, add both columns to the column list and the `ON CONFLICT` update clause, and bind them:

```rust
        .bind(params.pending_email_marketing_consent.as_str())
        .bind(params.pending_email_marketing_app_version)
```

- [ ] **Step 5: Update all three materialization write branches**

Near the top of `materialize_pending_registration`, replace the existing consent locals:

```rust
        let consent = EmailMarketingConsent::from_db(&pending.pending_email_marketing_consent_raw)
            .map_err(RepositoryError::Integrity)?;
        let consent_state = consent.as_str();
        // Stamped whenever they answered, either way. Only "never asked" leaves this NULL, which is
        // what keeps "declined" distinguishable from "never offered the choice".
        let consent_at = match consent {
            EmailMarketingConsent::NeverAsked => None,
            _ => Some(now),
        };
        let consent_source = match consent {
            EmailMarketingConsent::NeverAsked => None,
            _ => Some("mobile_create_account"),
        };
        let consent_app_version = pending.pending_email_marketing_app_version.as_deref();
```

Then in **each** of the three write paths (the fresh INSERT, the primary UPDATE, and the `ON CONFLICT DO NOTHING` race-fallback UPDATE), set all four columns and bind all four values. All three must stay symmetric: an earlier review found the race-fallback branch silently dropping consent, and that is exactly the failure this design exists to prevent.

- [ ] **Step 6: Update the two call sites**

In `api/src/api/http/headless.rs`, add to `HeadlessRegisterRequest` beneath the existing `marketing_consent` field:

```rust
    /// Client app version, recorded alongside the consent answer so we can tell which wording the
    /// person was shown. Optional so the mobile change can land independently.
    pub app_version: Option<String>,
```

and change the params construction:

```rust
            pending_email_marketing_consent: req.marketing_consent.into(),
            pending_email_marketing_app_version: req.app_version.as_deref(),
```

In `api/src/api/http/oauth.rs:230`, the browser path never shows the choice:

```rust
        pending_email_marketing_consent: EmailMarketingConsent::NeverAsked,
        pending_email_marketing_app_version: None,
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p keycast_api --test oauth_deferred_registration_test`
Expected: PASS, including the pre-existing materialization tests.

- [ ] **Step 8: Verify the race-fallback branch is genuinely covered**

Temporarily delete the four consent bindings from the race-fallback UPDATE branch only, then run the existing `test_marketing_consent_written_when_materializing_existing_pubkey` test.
Expected: FAIL. Restore the bindings and confirm it passes again. A test that cannot fail is not coverage.

- [ ] **Step 9: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): carry tri-state consent, source and app version through registration"
```

---

### Task 4: Deletion tombstones

**Files:**
- Create: `database/migrations/20260903120000_email_marketing_deletions.sql`
- Modify: `core/src/repositories/user.rs` (`delete_account_in_tx`)
- Test: `core/tests/` alongside the existing account-deletion tests

**Interfaces:**
- Consumes: `users.email_marketing_consent` from Task 1.
- Produces: table `email_marketing_deletions (id BIGSERIAL, email TEXT, deleted_at TIMESTAMPTZ)`.

- [ ] **Step 1: Write the migration**

```sql
-- Account deletion is a hard delete, so a deleted row is invisible to a "what changed since"
-- query and the sync service would never learn the account went away. Without this, someone who
-- deleted their Divine account would keep receiving Divine marketing, which is the worst outcome
-- this design has to prevent.
--
-- Deliberately transient: a row exists only until the sync service has removed the contact from
-- the email platform, then it is cleared. That bounds how long an address is retained past
-- deletion. No pubkey is stored: the account is gone, and the address is all that is needed.
CREATE TABLE email_marketing_deletions (
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- [ ] **Step 2: Write the failing test**

```rust
#[tokio::test]
async fn deleting_an_opted_in_account_leaves_a_tombstone() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = seed_user(&pool, "leaver@example.test", "opted_in").await;

    repo.delete_account(&pubkey, 1).await.unwrap();

    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM email_marketing_deletions WHERE email = $1")
            .bind("leaver@example.test")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(email.as_deref(), Some("leaver@example.test"));
}

#[tokio::test]
async fn deleting_an_account_that_never_opted_in_leaves_no_tombstone() {
    // We only remove contacts we created. Someone who never opted in has no contact of ours to
    // delete, and writing a tombstone would have us act on a record we do not own.
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = seed_user(&pool, "browser@example.test", "never_asked").await;

    repo.delete_account(&pubkey, 1).await.unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_marketing_deletions WHERE email = $1")
            .bind("browser@example.test")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}
```

With this helper:

```rust
async fn seed_user(pool: &PgPool, email: &str, consent: &str) -> String {
    let pubkey = nostr_sdk::Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_marketing_consent, created_at, updated_at)
         VALUES ($1, 1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(consent)
    .execute(pool)
    .await
    .unwrap();
    pubkey
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p keycast_core tombstone`
Expected: FAIL, `relation "email_marketing_deletions" does not exist`.

- [ ] **Step 4: Write the tombstone inside the deletion transaction**

In `delete_account_in_tx`, **before** the statement that removes the `users` row, and inside the same transaction so a failed deletion leaves no tombstone:

```rust
        // Record the address so the sync service can remove the contact from the email platform.
        // Only for accounts that actually opted in: those are the only contacts we created, and we
        // should not act on records we do not own. Inside the transaction deliberately, so a
        // rolled-back deletion cannot leave an orphan tombstone that unsubscribes a live account.
        sqlx::query(
            "INSERT INTO email_marketing_deletions (email, deleted_at)
             SELECT email, NOW() FROM users
             WHERE pubkey = $1 AND tenant_id = $2
               AND email IS NOT NULL
               AND email_marketing_consent = 'opted_in'",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p keycast_core tombstone`
Expected: PASS, 2 tests.

- [ ] **Step 6: Verify the transaction guarantee**

Confirm by reading that the insert sits between the transaction's start and the `users` delete, and uses `&mut *tx` rather than the pool. A tombstone written outside the transaction would survive a rolled-back deletion and unsubscribe a live account.

- [ ] **Step 7: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): write a deletion tombstone for opted-in accounts"
```

---

### Task 4b: Email-change rows

**Files:**
- Create: `database/migrations/20260903120100_email_marketing_email_changes.sql`
- Modify: `core/src/repositories/user.rs` (the email-change finalize path, around line 1166)
- Test: alongside the existing email-change tests

**Interfaces:**
- Consumes: Task 1's consent column.
- Produces: table `email_marketing_email_changes (id BIGSERIAL, pubkey TEXT, old_email TEXT, new_email TEXT, changed_at TIMESTAMPTZ)`.

**Why this exists.** keycast overwrites `users.email` in place, so a changed row reaching the sync
service carries only the new address. Without the old one it cannot find the existing contact in the
email platform: it would create a *second* contact and leave the original subscribed at an address
the person has left, quietly mailing them there forever. This row is how the old address survives
the overwrite.

- [ ] **Step 1: Write the migration**

```sql
-- The old address, captured before it is overwritten.
--
-- `users.email` is updated in place when someone changes their email, so by the time the sync
-- service sees the changed row it knows only the new address. It needs the old one to find and move
-- the existing contact in the email platform. Without this the sync creates a duplicate contact and
-- the previous address stays subscribed indefinitely.
--
-- Transient, like email_marketing_deletions: a row exists only until the sync service has moved the
-- contact, then it is cleared.
CREATE TABLE email_marketing_email_changes (
    id         BIGSERIAL PRIMARY KEY,
    pubkey     TEXT NOT NULL,
    old_email  TEXT NOT NULL,
    new_email  TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- [ ] **Step 2: Write the failing test**

```rust
#[tokio::test]
async fn finalizing_an_email_change_records_the_old_address() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = seed_user_with_pending_change(
        &pool, "old@example.test", "new@example.test", "opted_in", "tok-1",
    ).await;

    repo.finalize_email_change(1, "tok-1").await.unwrap();

    let (old, new): (String, String) = sqlx::query_as(
        "SELECT old_email, new_email FROM email_marketing_email_changes WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(old, "old@example.test");
    assert_eq!(new, "new@example.test");
}

#[tokio::test]
async fn an_account_that_never_opted_in_records_no_email_change() {
    // We only move contacts we created. Someone who never opted in has none of ours to move.
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = seed_user_with_pending_change(
        &pool, "old2@example.test", "new2@example.test", "never_asked", "tok-2",
    ).await;

    repo.finalize_email_change(1, "tok-2").await.unwrap();

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_email_changes WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn the_recorded_old_address_is_the_pre_change_value() {
    // The insert must read `email` BEFORE the UPDATE overwrites it. If the statements are ordered
    // the other way round, old_email and new_email are identical and the sync service has no way to
    // find the original contact.
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = seed_user_with_pending_change(
        &pool, "before@example.test", "after@example.test", "opted_in", "tok-3",
    ).await;

    repo.finalize_email_change(1, "tok-3").await.unwrap();

    let old: String = sqlx::query_scalar(
        "SELECT old_email FROM email_marketing_email_changes WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_ne!(old, "after@example.test", "old_email captured after the overwrite");
    assert_eq!(old, "before@example.test");
}
```

Write `seed_user_with_pending_change` to insert a user with the given email and consent state plus a
matching `pending_email` and `pending_email_verification_token`, mirroring the existing email-change
tests in this file.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p keycast_core email_change`
Expected: FAIL, `relation "email_marketing_email_changes" does not exist`.

- [ ] **Step 4: Record the old address before the overwrite**

In `core/src/repositories/user.rs`, in the transaction that finalizes an email change, **immediately
before** the `UPDATE users SET email = pending_email, ...` statement near line 1166:

```rust
        // Capture the outgoing address before the UPDATE overwrites it. Ordering is load-bearing:
        // after the update, `email` is already the new value and old_email would be meaningless.
        // Inside the transaction so a rolled-back change leaves no row claiming a move happened.
        sqlx::query(
            "INSERT INTO email_marketing_email_changes (pubkey, old_email, new_email, changed_at)
             SELECT pubkey, email, pending_email, NOW() FROM users
             WHERE pubkey = $1 AND tenant_id = $2
               AND email IS NOT NULL
               AND pending_email IS NOT NULL
               AND email IS DISTINCT FROM pending_email
               AND email_marketing_consent = 'opted_in'",
        )
        .bind(user_pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p keycast_core email_change`
Expected: PASS, 3 tests.

- [ ] **Step 6: Verify the ordering guard can fail**

Temporarily move the INSERT to *after* the `UPDATE users SET email = pending_email` statement, then
run `cargo test -p keycast_core the_recorded_old_address_is_the_pre_change_value`.
Expected: FAIL, because `old_email` now equals the new address. Restore the order and confirm it
passes. This ordering is the whole point of the task.

- [ ] **Step 7: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): record the old address when an account email changes"
```

---

### Task 4c: Expose email changes to the sync service

**Files:**
- Modify: `api/src/api/http/email_marketing.rs`, `api/src/api/http/routes.rs`
- Test: `api/tests/email_marketing_endpoints_test.rs`

**Note:** this task depends on Task 5 having created `api/src/api/http/email_marketing.rs`. Do Task 5 first, then return here, or fold this into Task 7 which adds the structurally identical tombstone endpoints.

**Interfaces:**
- Consumes: Task 4b's table; Task 5's module.
- Produces: `GET /admin/email-marketing-email-changes?since=<id>&limit=<n>` returning `{"results":[{"id":n,"pubkey":"...","old_email":"...","new_email":"...","changed_at":"..."}]}`; `POST /admin/email-marketing-email-changes/ack` accepting `{"ids":[n]}` returning `{"cleared": n}`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn lists_then_clears_email_changes_only_when_acknowledged() {
    let pool = setup_pool().await;
    sqlx::query(
        "INSERT INTO email_marketing_email_changes (pubkey, old_email, new_email, changed_at)
         VALUES ($1, $2, $3, NOW())",
    )
    .bind("aa".repeat(32))
    .bind("old@example.test")
    .bind("new@example.test")
    .execute(&pool)
    .await
    .unwrap();

    let listed = get_email_changes(&pool, None, 10).await;
    assert_eq!(listed.results.len(), 1);
    assert_eq!(listed.results[0].old_email, "old@example.test");

    // Unacknowledged rows stay, so a crash between read and act replays rather than loses.
    assert_eq!(get_email_changes(&pool, None, 10).await.results.len(), 1);

    ack_email_changes(&pool, &[listed.results[0].id]).await;
    assert!(get_email_changes(&pool, None, 10).await.results.is_empty());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test email_changes`
Expected: FAIL, route not found (404).

- [ ] **Step 3: Write the handlers**

Structurally identical to the tombstone handlers in Task 7. Add to `api/src/api/http/email_marketing.rs`:

```rust
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EmailChangeRecord {
    pub id: i64,
    pub pubkey: String,
    pub old_email: String,
    pub new_email: String,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EmailChangePage {
    pub results: Vec<EmailChangeRecord>,
}

pub async fn list_email_changes(
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<DeletionPageQuery>,
) -> Result<Json<EmailChangePage>, super::admin::AdminError> {
    authorize_service_token(&headers)?;
    let limit = query.limit.unwrap_or(500).clamp(1, MAX_LIMIT);

    let results: Vec<EmailChangeRecord> = sqlx::query_as(
        "SELECT id, pubkey, old_email, new_email, changed_at FROM email_marketing_email_changes
         WHERE ($1::bigint IS NULL OR id > $1)
         ORDER BY id LIMIT $2",
    )
    .bind(query.since)
    .bind(limit)
    .fetch_all(&auth_state.state.db)
    .await
    .map_err(|e| super::admin::AdminError::Internal(e.to_string()))?;

    Ok(Json(EmailChangePage { results }))
}

pub async fn ack_email_changes(
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<Json<AckResponse>, super::admin::AdminError> {
    authorize_service_token(&headers)?;

    let result = sqlx::query("DELETE FROM email_marketing_email_changes WHERE id = ANY($1)")
        .bind(&req.ids)
        .execute(&auth_state.state.db)
        .await
        .map_err(|e| super::admin::AdminError::Internal(e.to_string()))?;

    Ok(Json(AckResponse { cleared: result.rows_affected() }))
}
```

- [ ] **Step 4: Mount the routes**

```rust
        .route("/admin/email-marketing-email-changes", get(email_marketing::list_email_changes))
        .route("/admin/email-marketing-email-changes/ack", post(email_marketing::ack_email_changes))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): expose email-change rows to the sync service"
```

---

### Task 5: Read consent by cursor

**Files:**
- Create: `api/src/api/http/email_marketing.rs`
- Modify: `api/src/api/http/mod.rs` (declare the module), `api/src/api/http/routes.rs` (mount)
- Test: `api/tests/email_marketing_endpoints_test.rs`

**Interfaces:**
- Consumes: Task 1 columns, Task 2 enum, `authorize_service_token` from `admin.rs`.
- Produces: `GET /admin/email-marketing-consents?since=<updated_at>&since_pubkey=<pubkey>&limit=<n>` returning `{ "results": [ConsentRecord], "next": {"since": "...", "since_pubkey": "..."} | null }` where `ConsentRecord` is `{pubkey, email, consent, consent_at, source, app_version, global_optout, optout_observed_at}`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn rejects_a_request_without_the_service_token() {
    let app = test_app().await;
    let res = app
        .oneshot(Request::builder()
            .uri("/admin/email-marketing-consents")
            .body(Body::empty())
            .unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pages_deterministically_when_timestamps_collide() {
    // Two accounts sharing an updated_at is the case a timestamp-only cursor gets wrong: it either
    // skips one or loops forever. The cursor is (updated_at, pubkey) for exactly this reason.
    let pool = setup_pool().await;
    let shared = Utc::now();
    let a = seed_consent(&pool, "a@example.test", "opted_in", shared).await;
    let b = seed_consent(&pool, "b@example.test", "opted_in", shared).await;
    let (first, second) = if a < b { (a, b) } else { (b, a) };

    let page_one = get_consents(&pool, None, None, 1).await;
    assert_eq!(page_one.results.len(), 1);
    assert_eq!(page_one.results[0].pubkey, first);

    let next = page_one.next.expect("a full page must offer a cursor");
    let page_two = get_consents(&pool, Some(next.since), Some(next.since_pubkey), 1).await;
    assert_eq!(page_two.results.len(), 1);
    assert_eq!(page_two.results[0].pubkey, second);
}

#[tokio::test]
async fn returns_the_floor_as_null_when_never_observed() {
    let pool = setup_pool().await;
    seed_consent(&pool, "fresh@example.test", "opted_in", Utc::now()).await;

    let page = get_consents(&pool, None, None, 10).await;

    assert!(page.results[0].global_optout.is_none());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test`
Expected: FAIL to compile, the module and route do not exist.

- [ ] **Step 3: Write the handler**

```rust
// ABOUTME: Service-token endpoints letting the marketing sync service read consent, write back the
// ABOUTME: suppression floor, and drain deletion tombstones. keycast never calls the email platform.
use axum::{extract::{Query, State}, http::HeaderMap, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admin::authorize_service_token;
use super::routes::AuthState;

#[derive(Debug, Deserialize)]
pub struct ConsentPageQuery {
    /// Cursor: the last `updated_at` processed. Paired with `since_pubkey` to break ties.
    pub since: Option<DateTime<Utc>>,
    pub since_pubkey: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ConsentRecord {
    pub pubkey: String,
    pub email: Option<String>,
    pub consent: String,
    pub consent_at: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub app_version: Option<String>,
    /// NULL means never observed. Not the same as "not opted out".
    pub global_optout: Option<bool>,
    pub optout_observed_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ConsentCursor {
    pub since: DateTime<Utc>,
    pub since_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct ConsentPage {
    pub results: Vec<ConsentRecord>,
    /// Absent when the page was not full, meaning the caller has reached the end.
    pub next: Option<ConsentCursor>,
}

const MAX_LIMIT: i64 = 1000;

pub async fn list_consents(
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<ConsentPageQuery>,
) -> Result<Json<ConsentPage>, super::admin::AdminError> {
    authorize_service_token(&headers)?;

    let limit = query.limit.unwrap_or(500).clamp(1, MAX_LIMIT);

    // Ordered by (updated_at, pubkey) so a shared timestamp cannot skip or repeat a record.
    let rows: Vec<ConsentRecord> = sqlx::query_as(
        "SELECT pubkey, email,
                email_marketing_consent           AS consent,
                email_marketing_consent_at        AS consent_at,
                email_marketing_consent_source    AS source,
                email_marketing_consent_app_version AS app_version,
                email_marketing_global_optout     AS global_optout,
                email_marketing_optout_observed_at AS optout_observed_at,
                updated_at
         FROM users
         WHERE ($1::timestamptz IS NULL OR (updated_at, pubkey) > ($1, $2))
         ORDER BY updated_at, pubkey
         LIMIT $3",
    )
    .bind(query.since)
    .bind(query.since_pubkey.unwrap_or_default())
    .bind(limit)
    .fetch_all(&auth_state.state.db)
    .await
    .map_err(|e| super::admin::AdminError::Internal(e.to_string()))?;

    let next = if rows.len() as i64 == limit {
        rows.last().map(|r| ConsentCursor { since: r.updated_at, since_pubkey: r.pubkey.clone() })
    } else {
        None
    };

    Ok(Json(ConsentPage { results: rows, next }))
}
```

- [ ] **Step 4: Mount the route**

In `api/src/api/http/mod.rs` add `pub mod email_marketing;`. In `routes.rs`, alongside the existing `batch_lookup_route`:

```rust
    let email_marketing_routes = Router::new()
        .route("/admin/email-marketing-consents", get(email_marketing::list_consents))
        .with_state(auth_state.clone());
```

and merge it into the router with the other service-token routes.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test`
Expected: PASS, 3 tests.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): expose a cursor-paged consent read for the sync service"
```

---

### Task 6: Write the suppression floor

**Files:**
- Modify: `api/src/api/http/email_marketing.rs`, `api/src/api/http/routes.rs`
- Test: `api/tests/email_marketing_endpoints_test.rs`

**Interfaces:**
- Consumes: Task 5's module and route setup.
- Produces: `POST /admin/email-marketing-consents/observed` accepting `{"observations":[{"pubkey":"...","global_optout":true,"observed_at":"..."}]}` and returning `{"updated": n}`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn records_the_suppression_floor() {
    let pool = setup_pool().await;
    let pubkey = seed_consent(&pool, "gone@example.test", "opted_in", Utc::now()).await;

    post_observed(&pool, &pubkey, true).await;

    let floor: Option<bool> = sqlx::query_scalar(
        "SELECT email_marketing_global_optout FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert_eq!(floor, Some(true));
}

#[tokio::test]
async fn cannot_alter_the_consent_event() {
    // The consent event is the evidence that consent was validly obtained. No endpoint may rewrite
    // it. If this ever fails, the immutability guarantee has been broken.
    let pool = setup_pool().await;
    let pubkey = seed_consent(&pool, "stable@example.test", "opted_in", Utc::now()).await;

    post_observed(&pool, &pubkey, true).await;

    let consent: String = sqlx::query_scalar(
        "SELECT email_marketing_consent FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();
    assert_eq!(consent, "opted_in", "observing an opt-out must not rewrite the consent event");
}

#[tokio::test]
async fn applying_the_same_observation_twice_is_a_no_op() {
    let pool = setup_pool().await;
    let pubkey = seed_consent(&pool, "twice@example.test", "opted_in", Utc::now()).await;

    post_observed(&pool, &pubkey, true).await;
    let first: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT email_marketing_optout_observed_at FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();

    post_observed(&pool, &pubkey, true).await;
    let second: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT email_marketing_optout_observed_at FROM users WHERE pubkey = $1")
        .bind(&pubkey).fetch_one(&pool).await.unwrap();

    assert_eq!(first, second);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test observed`
Expected: FAIL, route not found (404).

- [ ] **Step 3: Write the handler**

```rust
#[derive(Debug, Deserialize)]
pub struct Observation {
    pub pubkey: String,
    pub global_optout: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ObservationsRequest {
    pub observations: Vec<Observation>,
}

#[derive(Debug, Serialize)]
pub struct ObservationsResponse {
    pub updated: u64,
}

/// Writes only the suppression floor. The consent event columns are deliberately absent from this
/// statement: immutability is enforced by there being no code path that writes them, not by
/// anyone remembering the rule.
pub async fn record_observations(
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<ObservationsRequest>,
) -> Result<Json<ObservationsResponse>, super::admin::AdminError> {
    authorize_service_token(&headers)?;

    let mut updated = 0u64;
    for obs in req.observations {
        // Idempotent: an identical observation changes nothing, so replaying a batch after a crash
        // does not churn timestamps.
        let result = sqlx::query(
            "UPDATE users
             SET email_marketing_global_optout = $2,
                 email_marketing_optout_observed_at = $3
             WHERE pubkey = $1
               AND (email_marketing_global_optout IS DISTINCT FROM $2)",
        )
        .bind(&obs.pubkey)
        .bind(obs.global_optout)
        .bind(obs.observed_at)
        .execute(&auth_state.state.db)
        .await
        .map_err(|e| super::admin::AdminError::Internal(e.to_string()))?;
        updated += result.rows_affected();
    }

    Ok(Json(ObservationsResponse { updated }))
}
```

- [ ] **Step 4: Mount the route**

Add to `email_marketing_routes` in `routes.rs`:

```rust
        .route("/admin/email-marketing-consents/observed", post(email_marketing::record_observations))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test`
Expected: PASS, 6 tests.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): accept suppression-floor observations from the sync service"
```

---

### Task 7: Drain deletion tombstones

**Files:**
- Modify: `api/src/api/http/email_marketing.rs`, `api/src/api/http/routes.rs`
- Test: `api/tests/email_marketing_endpoints_test.rs`

**Interfaces:**
- Consumes: Task 4's table, Task 5's module.
- Produces: `GET /admin/email-marketing-deletions?since=<id>&limit=<n>` returning `{"results":[{"id":n,"email":"...","deleted_at":"..."}]}`; `POST /admin/email-marketing-deletions/ack` accepting `{"ids":[n]}` returning `{"cleared": n}`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn lists_then_clears_tombstones_only_when_acknowledged() {
    // Read and acknowledge are separate calls on purpose: a crash between them replays the
    // deletion rather than losing it, and losing one means emailing someone who deleted their
    // account.
    let pool = setup_pool().await;
    sqlx::query("INSERT INTO email_marketing_deletions (email, deleted_at) VALUES ($1, NOW())")
        .bind("bye@example.test").execute(&pool).await.unwrap();

    let listed = get_deletions(&pool, None, 10).await;
    assert_eq!(listed.results.len(), 1);

    // Still present before acknowledgement.
    let still_there = get_deletions(&pool, None, 10).await;
    assert_eq!(still_there.results.len(), 1);

    ack(&pool, &[listed.results[0].id]).await;

    let after = get_deletions(&pool, None, 10).await;
    assert!(after.results.is_empty());
}

#[tokio::test]
async fn acknowledging_an_unknown_id_is_harmless() {
    let pool = setup_pool().await;
    let cleared = ack(&pool, &[999_999]).await;
    assert_eq!(cleared, 0);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test deletions`
Expected: FAIL, route not found (404).

- [ ] **Step 3: Write the handlers**

```rust
#[derive(Debug, Deserialize)]
pub struct DeletionPageQuery {
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DeletionRecord {
    pub id: i64,
    pub email: String,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct DeletionPage {
    pub results: Vec<DeletionRecord>,
}

#[derive(Debug, Deserialize)]
pub struct AckRequest {
    pub ids: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct AckResponse {
    pub cleared: u64,
}

pub async fn list_deletions(
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<DeletionPageQuery>,
) -> Result<Json<DeletionPage>, super::admin::AdminError> {
    authorize_service_token(&headers)?;
    let limit = query.limit.unwrap_or(500).clamp(1, MAX_LIMIT);

    let results: Vec<DeletionRecord> = sqlx::query_as(
        "SELECT id, email, deleted_at FROM email_marketing_deletions
         WHERE ($1::bigint IS NULL OR id > $1)
         ORDER BY id LIMIT $2",
    )
    .bind(query.since)
    .bind(limit)
    .fetch_all(&auth_state.state.db)
    .await
    .map_err(|e| super::admin::AdminError::Internal(e.to_string()))?;

    Ok(Json(DeletionPage { results }))
}

/// Clearing is a separate call from listing so that a sync service which crashes after reading but
/// before acting replays the deletion instead of dropping it.
pub async fn ack_deletions(
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<Json<AckResponse>, super::admin::AdminError> {
    authorize_service_token(&headers)?;

    let result = sqlx::query("DELETE FROM email_marketing_deletions WHERE id = ANY($1)")
        .bind(&req.ids)
        .execute(&auth_state.state.db)
        .await
        .map_err(|e| super::admin::AdminError::Internal(e.to_string()))?;

    Ok(Json(AckResponse { cleared: result.rows_affected() }))
}
```

- [ ] **Step 4: Mount the routes**

```rust
        .route("/admin/email-marketing-deletions", get(email_marketing::list_deletions))
        .route("/admin/email-marketing-deletions/ack", post(email_marketing::ack_deletions))
```

- [ ] **Step 5: Run the full suite**

Run: `cargo test -p keycast_api --test email_marketing_endpoints_test && cargo test -p keycast_core`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(consent): expose deletion tombstones to the sync service"
```

---

### Task 8: Update the PR and document the API

**Files:**
- Modify: `README.md` or the service-token API docs, wherever `POST /admin/users/batch-lookup` is documented
- Modify: PR #404 description

**Interfaces:**
- Consumes: everything above.
- Produces: nothing code-facing.

- [ ] **Step 1: Document the three endpoints**

Alongside the existing batch-lookup documentation, record: the auth model (service token), the cursor semantics of `(updated_at, pubkey)`, that the consent event is not writable, that NULL floor means never observed, and that read and acknowledge are separate for tombstones.

- [ ] **Step 2: Push and confirm CI**

```bash
git push origin feat/marketing-consent-registration
gh pr checks 404 --repo divinevideo/keycast
```
Expected: all checks pass, including the DB integration tests.

- [ ] **Step 3: Update the PR description**

Replace the "Open decision, worth settling before this merges" section, which described the tri-state question as unresolved. It is now resolved and implemented. State the final schema, that consent is immutable, and that the floor is nullable by design.

- [ ] **Step 4: Commit any doc changes**

```bash
git add -A
git commit -m "docs(consent): document the marketing consent service endpoints"
```

---

## Verification before handing over

- [ ] `cargo test` passes across the workspace
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] No migration version collides with `origin/main`
- [ ] `grep -rn "marketing_consent" api/src core/src` returns no unqualified names outside comments
- [ ] `grep -rn "email_marketing_consent\s*=" api/src` shows the consent event written only during materialization
- [ ] The race-fallback mutation check from Task 3 Step 8 was actually run and observed failing
- [ ] The email-change ordering check from Task 4b Step 6 was actually run and observed failing
- [ ] `SELECT old_email, new_email FROM email_marketing_email_changes` on a test change shows two different addresses
