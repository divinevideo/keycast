# Retry-safe protected-account provisioning

`POST /api/admin/create-minor-account` accepts an optional lowercase UUID in
`provisioning_operation_id`. Coordinated callers use that value as a durable
idempotency key. Initial creation returns `201`; an exact replay returns `200`
with the original pubkey.

The operation record contains only the tenant, a versioned fingerprint of the
canonical request, the resulting pubkey, outcome, and timestamp. It contains no
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

`PROVISIONING_OPERATION_RETENTION_DAYS` defines a conservative two-year policy
marker. No production purge is enabled. Deleting a record while its operation
ID may still be delivered could permit another account to be created, so any
retention job remains gated by the durable-operation policy decision tracked in
`divinevideo/support-trust-safety#204`.

## Rollout compatibility

Requests without `provisioning_operation_id` retain the existing username-based
behavior during the Relay Manager rollout. This path must be removed only in a
coordinated change after all callers durably send operation IDs.
