# Service Account Deletion

Trusted service-to-service endpoint for permanently deleting a hosted Keycast
account. It exists so Divine's deletion coordinator (Funnelcake) can complete a
cross-service account deletion after the user's own signing authority is gone.

This is **not** a general third-party account-deletion API. The ordinary
user-facing path is `DELETE /api/user/account`, which requires a user-signed or
first-party UCAN and is unchanged.

Related: divinevideo/keycast#297, divinevideo/divine-funnelcake#1084,
divinevideo/divine-mobile#7889.

## What Keycast owns, and what it does not

Keycast deletes an account when asked and records that it did. It does **not**
own the deletion timer, the cross-service state machine, NIP-62 publication, or
relay visibility. Those belong to the coordinator.

## Endpoint

```
POST /api/admin/users/{pubkey}/deletion
Authorization: Bearer $KEYCAST_DELETION_SERVICE_TOKEN
Content-Type: application/json

{ "deletion_request_id": "<opaque, stable, caller-chosen>" }
```

`pubkey` is the full 64-character hex Nostr public key. Truncated or malformed
keys are rejected; a prefix is never resolved to an account.

### Authentication

The `KEYCAST_DELETION_SERVICE_TOKEN` bearer, compared in constant time. This is
deliberately separate from both user UCAN/OAuth and the broader
`KEYCAST_SERVICE_TOKEN`: by the time the coordinator calls this, the user's
signer has been destroyed, so no user credential exists to present. The
deletion credential cannot authorize unrelated service-admin routes, and the
broader service credential cannot authorize deletion.

### `deletion_request_id`

Opaque to Keycast, but it is the idempotency key, so it must be:

- stable for the lifetime of one logical deletion request — reuse it on every
  retry of that request, and never for a different one
- 1–200 characters
- printable ASCII with no spaces (`!`–`~`). A UUID is the expected shape.

The id is bound to the account on first use. Reusing it for a different pubkey
is refused (see `deletion_request_id_reused`).

## Success

`200 OK`:

```json
{
  "deletion_request_id": "b8f0c1a2-4d3e-4f5a-9b6c-7d8e9f0a1b2c",
  "pubkey": "<full 64-hex>",
  "outcome": "deleted",
  "replayed": false,
  "completed_at": "2026-08-19T12:00:00Z"
}
```

| Field | Meaning |
|---|---|
| `outcome` | `deleted` — the account existed and was removed. `already_absent` — there was no such account in this tenant. **Both are success**: the coordinator's goal is that the account is gone, and it is. |
| `replayed` | `false` when this call did the work. `true` when it is reporting a previously completed request. |
| `completed_at` | When the deletion committed. Stable across replays. |

### Idempotency and retries

Every completed request writes a row keyed on `deletion_request_id`, **in the
same transaction as the deletion itself**. That is what makes retrying safe:

- Replaying a completed id returns the original `outcome` and `completed_at`
  with `replayed: true`, and performs no deletion.
- A replay reports what the original request did, not what a fresh attempt
  would find now. A request that deleted an account keeps reporting `deleted`,
  never `already_absent`.
- Two concurrent copies of the same request produce exactly one deletion and
  one record; the loser returns the winner's result.
- Because the record and the deletion share one commit, there is no window in
  which an account is deleted but the completion is unprovable.

**On any ambiguous outcome — timeout, dropped connection, 5xx — retry with the
same `deletion_request_id`.** That is always safe and is how the coordinator
learns what happened.

## Failures

All errors have the same shape:

```json
{ "error": "human-readable", "code": "stable_identifier", "retryable": true }
```

Branch on `code`. `retryable` and the status class always agree: every 5xx is
retryable, every 4xx is terminal.

| Status | `code` | Retryable | Meaning |
|---|---|---|---|
| 400 | `invalid_pubkey` | no | Not a valid 64-character hex public key. |
| 400 | `invalid_deletion_request_id` | no | Missing, over 200 characters, or contains spaces/non-printable characters. |
| 401 | `unauthorized` | no | Missing or wrong service token. |
| 409 | `deletion_request_id_reused` | no | This id is already bound to a different account. Neither account is touched. |
| 500 | `database_error` | yes | Unclassified database failure. |
| 500 | `integrity_violation` | yes | Constraint violation. Retry, then escalate if it persists. |
| 500 | `idempotency_record_missing` | yes | A conflict was detected but the record could not be read back. |
| 503 | `database_unavailable` | yes | Pool exhausted, timed out, or closed. |
| 503 | `service_auth_unavailable` | yes | `KEYCAST_DELETION_SERVICE_TOKEN` is not configured on the server. An operator fix; retry after deployment. |

`deletion_request_id_reused` is terminal on purpose. Answering it as success
would let a coordinator bug report an account deleted while it is still live;
deleting the newly named account would honour a request never made for it.
Neither is recoverable, so the request is refused and the conflict does not
disclose which account the id belongs to.

## What deletion removes

The endpoint runs the same account-deletion transaction as the user-facing path:
team memberships, pending OAuth codes, ActivityPub RSA key material, account
claim tokens, and the user row — which cascades to personal keys, OAuth
authorizations and their refresh tokens, email-verification and password-reset
tokens, and the user profile.

After the transaction commits, the signer daemon is told to drop the account's
bunker connections. That notification is best-effort: it cannot fail a deletion
that has already committed.

Deletion is scoped to the calling tenant. An account owned by another tenant
returns `already_absent` and is left completely untouched.

## Audit

Each account actually deleted appends one `admin_audit_events` row:

- `action`: `service_account_deletion`
- `actor_pubkey`: `service:account-deletion` (the caller is a service, not a
  person, and the column is `NOT NULL`)
- `target_resource_id`: the full pubkey, never truncated
- `metadata_json`: `deletion_request_id`, `outcome`, and the counts of teams,
  OAuth authorizations, and bunker notifications

Replays are logged but not written, so the audit table holds one row per account
deleted rather than one per retry. The `service_account_deletions` row committed
with the deletion is the authoritative record regardless, so a failed audit
insert cannot lose the fact that a deletion happened.

No credentials, tokens, encrypted keys, or signed payloads are recorded, in the
audit row or in logs.

## Operational notes

- `KEYCAST_DELETION_SERVICE_TOKEN` must be configured, or every call returns
  `service_auth_unavailable`. It must not reuse `KEYCAST_SERVICE_TOKEN`;
  rotating either credential does not grant the other credential's authority.
- `service_account_deletions` grows one row per deletion request and is never
  pruned automatically. It is the audit and idempotency trail — do not add a
  retention job without deciding how long replayed requests must stay
  answerable.
- The table intentionally has **no** foreign key to `users`: it records that an
  account was removed, so it has to outlive the account it names.
