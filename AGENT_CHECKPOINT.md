# Recoverable group identity backend

## Objective

One current human admin can publish ordinary content as a recoverable hosted group
identity. Optional threshold groups use real BIP-340-compatible FROST; independent
clients can operate without any Keycast dependency.

## Current status

[VERIFIED] Backend implementation, migrations, contracts and local demonstrations
are present on `feat/recoverable-groups`. Implementation anchor: `a9c80d4`.
Local verification is complete. The current branch's pull request is the source
for remote CI/review state; merging and deployment require separate authorization.

## Verification

[VERIFIED] `cargo test --workspace` passed. Integration-enabled library/test suites:
core 378 passed/one existing ignored; API 981 passed/six existing ignored; signer
116 passed. All 12 Redis cluster integration tests passed. Final focused group
suites passed (lifecycle4, backups8, FROST5, real-UCAN HTTP1), including a pre-DKG
pending invitation that cannot alter the completed roster. Account service-deletion
regressions passed9. Workspace all-target/all-feature clippy and formatting passed.

[VERIFIED] `e2e/scripts/group-flow.mjs` exercised actual HTTP registration/email
verification and independent NIP-46 signing through the normal running daemon and
nak test relay. Three admins each signed alone; four public events including a
replacement device passed independent JavaScript verification and relay read-back.
Removal/recovery denied the old devices. See `docs/GROUP_DEMO.md` for reproduction.

[VERIFIED] An isolated PostgreSQL dump/restore and retained file encryption key
recovered the same synthetic group material; removed-admin retry was refused.
Evidence and operational procedure are in `docs/GROUP_RECOVERY.md`.

## Current mental model

- Hosted identities use dedicated teams/stored keys and an explicit all-ordinary-
  operations policy. Human membership and each device grant have durable versions.
  Never replace these with one shared bunker secret or a cached session token.
- Every group operation uses current tenant/human/membership/key/installation state.
  Cached signer requests reread authority; post-sign storage locking/audit happens
  before result release. Group mutations lock the same identity row.
- Account creation/acceptance and deletion share an account advisory transaction
  lock. Deletion locks affected groups in ascending order before the user row,
  tombstones membership and retires grants. Preserve that order to avoid deadlocks
  with backup/FROST operations that lock group before human rows.
- A completed FROST DKG is immutable identity data, not a pending session. Timeout,
  recovery, late duplicate/conflict or removal must not abort it. The completed
  signature is similarly immutable. New invite acceptance cannot change a completed
  cryptographic roster. Access removal cannot erase retained participant material.
- Share backup validation uses the exact confirmed public package and pinned suite
  `frost-secp256k1-tr` 2.2.0, untweaked-v1. Never parse a share as a full Nostr key,
  reconstruct a secret, serialize nonces or add an implicit Keycast participant.
- Native approvals own single-use ephemeral nonces. Coordinator reservations cover
  both public nonce points and survive aborts. A restored participant retains the
  same participant ID; its installation epoch changes, never its quorum weight.
- Legacy team mutation routes deliberately refuse group teams. Group custody uses
  existing account-management UCAN authority; delegated signing tokens cannot
  escalate to enrollment, backup restore or membership management.

## Known integration/operational gaps

[UNVERIFIED] Mobile UI/remote-authentication adapter and physical-device operation
are outside this backend change. Synchronous reference DKG helpers accept local
human authentication Keys; hosted-human clients must adapt existing NIP-46
sign/encrypt/decrypt with explicit protocol permissions, never export personal keys.

[UNVERIFIED] There is no native process-kill/database-rollback end-to-end harness.
The documented recovery contract requires discarding nonce handles and aborting
unfinished coordinator sessions before resuming after rollback. Do not describe a
SQL ledger alone as rollback-resistant client nonce storage.

[UNVERIFIED] Production independent backup storage, scheduling, retention and KMS
key/IAM recovery have not been inspected or changed. Verify through separately
authorized operations before real enrollment; the available recovery drill is local.

## Review handback

[VERIFIED] Independent source reviews and focused re-reviews found no remaining
blocking findings after account-lifecycle, immutable terminal-session and pending-
invitation fixes. Check the current PR's required CI and mapped human review before
merging. Do not deploy, merge or modify live keys/permissions under this task.

## Documents

- `docs/GROUPS.md`: lifecycle, grants, recovery and independent-client contract.
- `docs/GROUP_FROST.md`: exact suite/wire versions, agreement and nonce lifecycle.
- `docs/GROUP_RECOVERY.md`: package bindings and disaster-recovery procedure.
- `docs/GROUP_DEMO.md`: actual normal-server demonstration and reproduction.
- `docs/superpowers/plans/2026-10-16-recoverable-groups.md`: requirements and evidence.
