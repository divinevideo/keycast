# Retry-safe protected-account provisioning

`POST /api/admin/create-minor-account` accepts an optional lowercase UUID in
`provisioning_operation_id`. Coordinated callers use that value as a durable
idempotency key. Initial creation returns `201`; an exact replay returns `200`
with the original pubkey while the account exists.

The complete operation record contains only the tenant, a versioned fingerprint of the
canonical request, the resulting pubkey, outcome, creation time, and the local
account-deletion time when applicable. It contains no
username, display name, claim token, credential, email address, or key material,
and deliberately has no foreign key to `users`. It therefore remains answerable
after the account is claimed or deleted.

Creation, hosted-key storage, the initial claim token, and the operation record
commit in one transaction. PostgreSQL transaction-scoped advisory locks
serialize both the operation ID and target username. KMS encryption happens
before the transaction. Replays lock claim-token rows before checking account
state, matching the claim flow's lock order and ensuring concurrent replay can
mint at most one replacement token.

## Retention

Every successful account-deletion transaction stamps `deleted_at` on applicable
provisioning operations. This includes the user-facing deletion path, so Keycast
does not infer deletion time or rely on an external assertion. Existing operations
whose account was already absent when the migration ran start a conservative new
30-day clock at migration time.

After 30 days, the deletion coordinator may request compaction. Keycast replaces
the complete row transactionally with a tombstone containing the operation ID,
tenant, terminal `account_deleted` outcome, completion time, and versioned keyed
digests of the canonical request fingerprint and account binding. It retains no
result pubkey.

An exact replay after compaction returns `200` with
`account_state: "account_deleted"`, `replayed: true`, and no `pubkey`, claim URL,
or expiry. Different request parameters remain a `409
provisioning_operation_conflict`. The replay never creates an account or claim
credential.

## Rollout compatibility

Requests without `provisioning_operation_id` retain the existing username-based
behavior during the Relay Manager rollout. This path must be removed only in a
coordinated change after all callers durably send operation IDs.
