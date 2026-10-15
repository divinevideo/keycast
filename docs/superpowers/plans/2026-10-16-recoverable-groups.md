# Recoverable group identities implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development for independent crypto/storage work, with coordinated integration and review. Track verification evidence here.

**Goal:** Any current admin can independently sign as a recoverable hosted group; optional threshold groups use ordinary BIP-340 events.
**Architecture:** Reuse tenant-scoped teams, stored_keys, policies and per-device authorizations. Dedicated group membership/version records are checked against durable storage for every group operation, including warm signer requests. A separate FROST coordinator never treats shares as full keys.
**Tech Stack:** Rust, SQLx/Postgres, Axum/UCAN, existing KeyManager, frost-secp256k1-tr exactly 2.2.0.
**Spec:** User implementation brief and divine-mobile docs/superpowers/specs/2026-10-16-group-signed-events-design.md (PR 10218).

## Global constraints

- One authorized human can publish ordinary hosted content. No FROST threshold one or implicit server cosigning.
- Back up actual signing material, scoped to tenant/group/admin/participant/key and roster version/ciphersuite/tweak version. Never persist nonces in backups.
- Current membership governs recovery; new device credentials never revive old grants. No personal-key export.
- Public content lives on relays. Never synthesize list member tags from admins.
- Self-managed clients use no Keycast registration, transport, signing or recovery.
- No production operations or deployment. One combined PR targets main.

## Review focus

- Concurrent removal/re-enrollment must not revive a previously issued grant.
- Retrying creation or backup after a lost response must preserve the identity/package.
- A single-connection pool must support every transaction-owning path without nested acquisition or KMS inside transactions.
- Conflicting FROST transcripts/events, missing peers and cross-worker nonce reuse must fail closed.
- Database rollback must not revive nonce state; clients abort pending sessions after recovery and use fresh sessions/nonces.

## Task 1: Hosted lifecycle and admin signing

**Files:** database/migrations/*_recoverable_groups.sql; core/src/groups/{mod,service}.rs; api/src/api/http/groups.rs; signer/src/signer_daemon.rs; api/src/api/http/{mod,routes,teams}.rs; integration tests.
**Interfaces:** GroupService scoped by pool, KeyManager, tenant and acting admin. `identity_groups` links a dedicated team and optional hosted stored key. `group_memberships` is durable human membership with monotonically increasing version. `group_grants` binds an existing authorization to membership/key versions and a client.
- [x] Test atomic idempotent creation, invitations/acceptance, last-admin protection and tenant isolation.
- [x] Implement dedicated UCAN API; prepare encryption and secrets before transactions; serialize group mutations with row locks.
- [x] Issue one authorization per admin/device, prebound to device; check membership and versions on every request, including warm NIP-46 handlers; audit resulting event IDs.
- [x] Test three admins signing independently, cached revocation and replacement enrollment; preserve personal flows.

## Task 2: Backup and replacement-device recovery

**Files:** core/src/groups/backup.rs; database/migrations/*_group_backups.sql; api/src/api/http/group_backups.rs; core/tests/group_backup_test.rs; docs/GROUP_RECOVERY.md.
**Interfaces:** Read identity_groups and active group_memberships; versioned packages for hosted custody, device full keys and FROST key packages. Encrypted package includes the complete authorization binding and is rechecked on restore.
- [x] Test persistence failure, idempotency conflict, removed/other admin, cross-tenant/group and obsolete version denial.
- [x] Implement strict package parsing excluding nonce/seed/session fields, durable encrypted records and status. Hosted custody uses stored_keys plus active membership.
- [x] Recovery invalidates pending group sessions, retains participant identity, and issues fresh grants through Task 1.
- [x] Document and exercise isolated database and encryption-key restoration; do not call a DB insert an independently durable disaster-recovery backup.

## Task 3: Optional FROST and interoperability

**Files:** core/src/groups/frost/*; database/migrations/*_group_frost.sql; api/src/api/http/group_frost.rs; protocol and integration tests; docs/GROUP_FROST.md.
**Interfaces:** Explicit versioned protocol, immutable roster/threshold mapping, authenticated participant messages and transcript acknowledgments. Only public packages and encrypted recipient DKG envelopes persist; signatures aggregate using the pinned BIP-340 suite. No implicit server participant.
- [x] Test real DKG/2-of-3 through the coordinator, transcript equivocation/abort, altered events, replay/conflict and concurrent commitment reuse.
- [x] Implement authenticated confidential delivery boundary and agreement before round two; bind final public key to all participant confirmations.
- [x] Implement immutable signing proposals and signer sets, durable commitment reservations and partial idempotency; aggregate only valid shares and independently verify final Nostr events.
- [x] Document client nonce ownership, process-death/rollback abort rules and self-managed operation without Keycast.

## Final verification and delivery

- [ ] Run focused tests against isolated local Postgres/Redis/test relay and demonstrate standard event round trips.
- [ ] Run fmt, all-feature workspace clippy, relevant integration suites and personal recovery regressions.
- [ ] Review diff, commit scoped changes, rebase fresh origin/main, push and open conventional-title PR using template; request mapped reviewers once.
- [ ] Inspect required checks to completion. Report each unexercised acceptance gate precisely.

## Evidence and decisions

- Base: df350e30bcca683aa70465036f99eda9b7fab6fb. Shared context read from origin/main because its checkout has an unmerged branch.
- Brain search produced unrelated results; no company-memory claim is used.
- User explicitly authorized implementation and routine choices; no redundant design approval gate.


## Verification evidence (2026-10-16)

- Core integration-enabled library/tests: 378 passed, one pre-existing ignored test.
- API integration-enabled library/tests: 981 passed, six pre-existing ignored tests.
- Signer integration-enabled library/tests: 116 passed; includes independent raw
  secp256k1 verification and stock relay read-back for three independent admins.
- Group-specific suites: lifecycle 4, backup 8, FROST 5, real-UCAN HTTP 1 passed.
  FROST covers every 2-of-3 subset, a real stock relay, current backup prerequisite,
  concurrent nonce exclusion, transcript conflicts, exact proposals, device epochs,
  and immutable completed DKG/signature retries after expiry and membership removal.
- Full base workspace suite passed. All-target/all-feature workspace clippy passed.
  Deployment configuration tests passed. Final formatting/check state tracked at delivery.
- Actual isolated PostgreSQL dump/restore recovered an encrypted synthetic key under
  the same group pubkey with separately retained FileKeyManager key; removed admin
  retry failed. Production backup scheduling and KMS/IAM recovery were not exercised.
- Private scoped reviews found account-deletion/last-eligible-admin and completed-DKG
  lifecycle defects; fixes passed regression tests and re-review.

## Integration and verification limits

The backend wire boundary supports signed protocol envelopes; the synchronous native
reference DKG helper accepts locally held human authentication Keys. Mobile remote
NIP-46 authentication adaptation is client work and must never export unrelated
personal keys. Process termination and database rollback are governed by the explicit
client discard/operator abort procedure; there is no native kill-and-rollback end-to-end
harness in this change. Mobile UI, physical-device builds and another app's visible
rendering are not backend acceptance claims. Self-managed clients have no Keycast
registration/authentication/transport dependency in the documented contract.
