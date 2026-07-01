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
- The relay-manager revoke-action wiring that calls this endpoint: divine-relay-manager#147.
- The age-up *trigger* (how we detect someone turned 16): support-trust-safety#179. No birthdate or exact age is captured anywhere by design (verified 2026-07-01: web/mobile collect a parent email + a consent video with a verbal "13 to 15"; relay-manager stores only a coarse `suspected_age_band`; keycast stores only `verified_minor` + `verified_minor_at`). Age-up therefore cannot be auto-computed without a policy decision. This ticket delivers the mechanism that makes the lift automatic-on-clear; the trigger is deferred.

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
DELETE /api/admin/users/:pubkey/verified-minor?reason=<text>   // reason optional
```

Handler `clear_verified_minor_admin`:
1. `authorize_service_token(&headers)?` (constant-time compare, same as siblings).
2. Extract `tenant_id` from `TenantExtractor`.
3. `user_repo.clear_verified_minor(&pubkey, tenant_id).await?` (maps NotFound to 404).
4. Structured audit log, matching the `set_user_status_admin` pattern:
   `tracing::info!(event = "verified_minor_cleared", pubkey = %pubkey, reason = ?reason, "Admin cleared verified_minor")`.
   The durable `admin_audit_events` table requires an `actor_pubkey`, which the service-token boundary does not carry, so this matches the existing service-endpoint logging approach rather than that table.
5. `user_repo.get_full_admin_status(&pubkey, tenant_id).await?` and return the existing `UserStatusResponse` (so the caller sees `verified_minor: false`, `verified_minor_at: null`, and the unchanged status). Reusing `UserStatusResponse` keeps the response contract identical to `GET`/`PUT .../status`.

`reason` is an optional `Query` parameter (keeps DELETE bodyless). It feeds only the audit line; relay-manager#147 will pass a revocation reason.

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
8. `reason` query param is accepted (no 4xx) and the call still succeeds.

## Acceptance

An approved minor account, when cleared through this endpoint, has `verified_minor` set false and `verified_minor_at` set null, with account status untouched, so that (via divine-relay-manager#147) revoking approval lifts protections automatically across clients. Age-up detection is deferred to support-trust-safety#179.
