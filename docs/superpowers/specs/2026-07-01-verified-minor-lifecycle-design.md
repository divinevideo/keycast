# verified_minor lifecycle: clear primitive + revocation endpoint

**Issue:** divinevideo/keycast#265 (part of the protected-minor epic, divinevideo/support-trust-safety#173; equal sibling of divine-relay-manager#141)
**Date:** 2026-07-01
**Status:** design approved, ready for implementation plan

## Problem

`verified_minor` has a three-state lifecycle: SET (`create_minor_account`), READ (admin + `/user/account` responses), and CLEAR. Only SET and READ exist. There is no code path anywhere that clears `verified_minor`, so the flag is a one-way door: once an account is approved as a protected minor, that designation is permanent short of a manual database edit.

The epic requires protections to lift when an approved minor ages up to 16 or has approval revoked. Both transitions reduce to the same missing primitive: clear the flag. This spec builds that primitive and the endpoint relay-manager calls on revocation.

## Scope

**In scope (this ticket, keycast backend only):**
- A repository method that clears `verified_minor` + `verified_minor_at`.
- A service-token admin endpoint relay-manager calls to trigger the clear.
- Tests for both.

**Out of scope (tracked elsewhere, no-stacking keeps them separate):**
- The relay-manager revoke-action wiring that calls this endpoint, including the reason-dependent "re-apply restrictions" status change and passing `actor` + `reason` for the audit trail: divine-relay-manager#147.
- Durable audit for suspend/ban status changes (the same bar-raise applied to `set_user_status_admin`): keycast#279.
- The age-up *trigger* (how we detect someone turned 16): support-trust-safety#179. No birthdate or exact age is captured anywhere by design (verified 2026-07-01: web/mobile collect a parent email + a consent video with a verbal "13 to 15"; relay-manager stores only a coarse `suspected_age_band`; keycast stores only `verified_minor` + `verified_minor_at`). Age-up therefore cannot be auto-computed without a policy decision. This ticket delivers the mechanism that makes the lift automatic-on-clear; the trigger is deferred.

## Fidelity to the issue

Three points where this spec meets #265/#177 through a deliberate split rather than a single-ticket delivery, called out so the scope reads as intentional:

- **"re-apply restrictions" (letter of #265/#177).** The issues say revocation should "clear `verified_minor` *and re-apply restrictions*." This spec delivers the clear, which lifts the protected-minor protections (content lock, DM limits). The reason-dependent *account* restriction (suspend for a policy call, ban for under-13, or nothing for a mistaken approval) is owned by divine-relay-manager#147, which composes `set_user_status(chosen outcome)` + this clear. Clear-only is deliberate (see "Why clear-only" below): the same primitive serves age-up, which must leave status untouched. So the split is intentional, not an omission, but #265 alone does not close the "re-apply restrictions" clause.
- **"protections lift automatically across clients" (spirit).** Delivered by the existing client detection (#174) reacting to `verified_minor` flipping to false. Verified against the mobile seam: `isProtectedMinorProvider` reads `.value`, which retains last-known only during load/error and resolves to `false` on a successful fetch, so a positive false releases enforcement (it does not get swallowed by the fail-safe's persist-last-known behavior). This throughline must be re-verified against #174/#175/#176 before the epic acceptance is claimed; #265 itself only guarantees the flag flips.
- **Scope by construction.** Only accounts that actually carry `verified_minor` (fresh minor-onboarding accounts from `create_minor_account`) are affected. An original account resolved through age-review "Clear" never received the flag, so it is out of scope by construction, not by omission.

## Design

### Why clear-only (not clear-and-suspend)

The same clear primitive must serve both transitions, and they want opposite account-status outcomes:
- **Age-up** (later): clear the flag, status stays `active` (a normal adult account).
- **Revocation**: clear the flag, and the account usually goes *more* restricted, but which status depends on the reason (under-13 leads to ban; mistaken approval leads to active/unsuspend).

Folding a status change into the clear would make it unusable for age-up and would bake a fixed status into revocation that does not fit every reason. So the primitive is clear-only. relay-manager composes revocation as `set_user_status(chosen outcome)` + `clear_verified_minor` (see divine-relay-manager#147). This mirrors keycast's existing style, where `set_user_status` is its own single-purpose primitive. Clearing the flag already lifts the protected-minor protections; the status change is a separate, reason-dependent decision owned by the caller.

### Repository method

`core/src/repositories/user.rs`:

```rust
/// Clear the verified_minor designation (age-up or revocation).
/// Idempotent: clearing an already-cleared or never-minor account succeeds.
/// Returns NotFound only when the user does not exist.
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

Idempotency rests on Postgres counting every WHERE-matched row as affected by an UPDATE even when column values are unchanged: an existing user yields `rows_affected() == 1` regardless of the prior flag value (success no-op when already false), and a missing user yields `0` (NotFound). The method touches only the two minor columns plus `updated_at`; it never alters `status`, `suspended_reason`, or `suspended_at`.

### Endpoint

`api/src/api/http/admin.rs`, registered in `routes.rs` under the existing `service_admin_routes` group (service-token auth, same as the status endpoints):

```
DELETE /api/admin/users/:pubkey/verified-minor
DELETE /api/admin/users/:pubkey/verified-minor?actor=<hex64>&reason=<text>
```

`actor` (the moderator's pubkey) and `reason` are optional `Query` parameters, keeping the DELETE bodyless. `actor` drives the durable audit trail; relay-manager#147 passes both on revocation.

Handler `clear_verified_minor_admin`:
1. `authorize_service_token(&headers)?` (constant-time compare, same as siblings).
2. Extract `tenant_id` from `TenantExtractor`.
3. If `actor` is present, validate it as a 64-char hex pubkey (`len() == 64 && chars().all(|c| c.is_ascii_hexdigit())`, the idiom already used at admin.rs:1475). Reject with 400 on a malformed actor, so a T&S action never silently loses its audit trail.
4. Sanitize `reason` before it is logged or stored: bound to 500 chars and strip control characters (newlines and CR included), per the standing "sanitize caller-supplied values before logging" rule. Call the result `reason_clean`.
5. `user_repo.clear_verified_minor(&pubkey, tenant_id).await?` (maps `RepositoryError::NotFound` to 404 via error.rs:45).
6. Audit the action:
   - Always emit a structured log line: `tracing::info!(event = "verified_minor_cleared", pubkey = %pubkey, actor = ?actor, reason = ?reason_clean, "Admin cleared verified_minor")`.
   - When `actor` is present, also write a durable `admin_audit_events` row, best-effort (log-and-continue on failure, mirroring `record_registered_client_audit` at admin.rs:1554): action `clear_verified_minor`, `actor_pubkey = actor`, `target_resource_type = "user"`, `target_resource_id = Some(pubkey)`, `metadata_json = { "reason": reason_clean }`. The table's `actor_pubkey` is `NOT NULL`, so a durable row is written only when an actor is supplied; without one we fall back to log-only. (keycast#279 raises the same durable-audit bar for suspend/ban so the two enforcement actions match.)
7. `user_repo.get_full_admin_status(&pubkey, tenant_id).await?` and return the existing `UserStatusResponse` (so the caller sees `verified_minor: false`, `verified_minor_at: null`, and the unchanged status). Reusing `UserStatusResponse` keeps the response contract identical to `GET`/`PUT .../status`.

The audit write is best-effort enrichment: a failed `admin_audit_events` insert logs an error and the clear still succeeds. The clear is the primary operation.

Route registration in `routes.rs`:

```rust
.route(
    "/admin/users/:pubkey/verified-minor",
    delete(admin::clear_verified_minor_admin),
)
```

(`delete` is already imported.)

### No migration

`verified_minor` and `verified_minor_at` already exist (migration `20260527120000_add_verified_minor.sql`). No schema change.

## Testing (TDD)

**Repository (integration, Postgres, mirrors existing `user.rs` tests):**
1. Clears a verified minor: after `create_minor_account` then `clear_verified_minor`, `get_verified_minor` returns `(false, None)`.
2. Idempotent: calling `clear_verified_minor` on an already-cleared user returns `Ok(())`.
3. Unknown pubkey returns `RepositoryError::NotFound`.
4. Does not disturb status: a suspended verified-minor keeps `status = suspended` and its `suspended_reason`/`suspended_at` after clearing.

**Endpoint (integration, service-token):**
5. `DELETE` with a valid service token clears the flag and returns `UserStatusResponse` with `verified_minor == false` and `verified_minor_at == None`.
6. `DELETE` with a missing/invalid service token returns 401.
7. `DELETE` on an unknown pubkey returns 404.
8. `DELETE` with a valid `actor` writes an `admin_audit_events` row: action `clear_verified_minor`, `actor_pubkey == actor`, `target_resource_id == pubkey`, `metadata_json.reason == reason_clean`.
9. `DELETE` without `actor` writes no audit row and still succeeds (log-only fallback).
10. `DELETE` with a malformed `actor` (not 64 hex chars) returns 400 and does not clear the flag.
11. `reason` containing control characters or exceeding 500 chars is sanitized (bounded and stripped) in both the log line and the stored `metadata_json`.

## Acceptance

An approved minor account, when cleared through this endpoint, has `verified_minor` set false and `verified_minor_at` set null, with account status untouched, and (when an `actor` is supplied) a durable `admin_audit_events` row recording who cleared it and why, so that via divine-relay-manager#147 revoking approval lifts protections automatically across clients. The "re-apply restrictions" clause and age-up detection are deferred to divine-relay-manager#147 and support-trust-safety#179 respectively.
