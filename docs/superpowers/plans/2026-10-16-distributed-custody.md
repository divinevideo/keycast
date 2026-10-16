# Distributed Keycast Custody Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is a proposed plan: the current task authorizes research and planning only, not prototype execution or production changes.

**Goal:** Prove, using synthetic identities, that one human can publish through a 2-of-3 service quorum while a compromised coordinator plus one signer cannot enlarge that authority.

**Architecture:** A standalone experimental crate runs three guarded service signers and a keyless coordinator. Independently certified policy, device request proofs, separated share backups and recovery fencing surround an established BIP-340-compatible implementation. FROSTR is selected only after an explicit compatibility/safety gate.

**Tech Stack:** Rust, pinned `frost-secp256k1-tr = "=2.2.0"` reference, candidate Bifrost Rust commit `fe379c98825945a48e87e31360e2e87c6982af32`, Nostr/NIP-44, P-256 proofs, isolated local processes/storage and a real local test relay.

**Spec:** [Distributed custody design](../specs/2026-10-16-distributed-custody-design.md).
**Research:** [Source findings and pins](../../research/2026-10-16-distributed-custody.md).

## Global constraints

- Research/planning is the only work currently authorized. Obtain review of the design and this plan before executing it.
- One authorized human publishes; no mandatory second human admin or threshold-one crypto.
- Infrastructure signing threshold is 2-of-3; policy transitions require all-three durable votes/installation acknowledgments. Prepared transitions can pause signing and never timeout-unlock.
- Reference crypto is exactly `frost-secp256k1-tr = "=2.2.0"`, untweaked BIP-340/Nostr. Never reconstruct the full secret, bypass crypto checks or silently substitute a suite.
- Share packages exclude live nonce state, nonce seeds, pending handles and session/bunker tokens. Replacement retains participant identity and changes installation incarnation.
- Maximum native intent lifetime is 120 seconds; allowed clock skew is 30 seconds. Every secret-bearing type excludes Debug and generic serde export.
- Use synthetic identities and loopback-only services. No live keys, cloud permissions, deployments, new repos, personal-account migrations or silent hosted fallback.
- Preserve standard Nostr output and independent-mode operation. Keep proposed service custody separate from human-participant FROST in PR #435.
- Every implementation PR targets main. The experiment can be self-contained on current main; actual group integration waits for an approved, merged group API or an explicitly combined PR, never a feature-branch stack.

## Review focus

- Coordinator-supplied identities, policy snapshots and recovery assertions must not become trusted authority (Tasks 2, 3 and 6).
- Conflicting policy proposals and removal racing a partial release must fail closed at the documented serialization point (Tasks 3 and 5).
- A cloned worker or restored old snapshot must not resume an incarnation or nonce state (Tasks 5 and 6).
- A valid signature on encrypted NIP-46 traffic must not be mistaken for a signature on API-decoded plaintext (Task 7).
- Shared bootstrap, cloud/deployment, backup or recovery credentials must not collapse independent domains (Tasks 2, 6 and 8).

## File and interface map

Create the experiment in `tools/custody-spike/`, excluded from the root Cargo workspace so it cannot become a serving backend accidentally. It has its own lockfile and local test binaries. Do not add it to production images or startup.

| Proposed file | Responsibility |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `README.md` | Exact dependencies, reproduction and non-production boundary |
| `src/protocol.rs` | Typed bindings, intents, policies and public certificates |
| `src/intent.rs` | Client proof creation/verification and canonical commitment |
| `src/policy.rs`, `src/store.rs` | All-three policy journal, fences, durable public state |
| `src/crypto.rs` | Official-suite DKG/signing reference; opaque secret handles |
| `src/frostr_adapter.rs` | Candidate adapter only after compatibility decision |
| `src/signer.rs` | Guarded participant, commitment/partial state machine |
| `src/recovery.rs` | Bound per-domain share backup and incarnation recovery |
| `src/transport.rs` | Loopback process protocol and optional NIP-46 ingress |
| `src/bin/custody-signer.rs`, `src/bin/custody-coordinator.rs` | Independently launched local services |
| `tests/{intent,policy,interop,signing,recovery,nip46}_test.rs` | Actual assertions and process fault tests |

Public types defined in Task 1: `IdentityBinding`, `DeviceGrant`, `PolicySnapshot`, `PolicyProposal`, `PolicyCertificate`, `IntentV1`, `ClientProof`, `VerifiedAuthorization`, `SigningProposal`, `PublicCommitment`, `PublicPartial`, `RecoveryCase`, `RecoveryEvidence`, `IncarnationCertificate`, `BackupBinding`, `CustodyError`. Task 6 defines `DomainKeyManager` as the per-domain wrapper over the existing
`keycast_core::encryption::KeyManager` trait and the strict `EncryptedShareBackup`
codec. Task 7 defines `TransportCredential` and the second verifier for the same opaque
`VerifiedAuthorization` type. The type retains its proof kind and selection scope;
only a guard-local verifier can construct it. It is never accepted as a serialized
coordinator assertion. Native proof scope is the exact set/session; legacy NIP-46
scope is the explicitly certified service pool plus a guard-verified internal
set/session binding. No conversion may widen native scope or pretend a legacy
client signed the native profile. Public APIs return
`Result<T, CustodyError>`; use `nostr::UnsignedEvent`, `Event`, `PublicKey`. Secrets live only in opaque nonserializable handles except the strict, encrypted share-backup codec.

### Task 1: Pin the native transaction-approval contract

**Files:** Create protocol/intent modules, crate manifest/lock, `tests/intent_test.rs`; modify root Cargo exclude list for the experiment only.
**Produces:** `IntentV1::digest() -> [u8; 32]`; `verify_intent(&IntentV1, &ClientProof, &PolicySnapshot, &UnsignedEvent, now: i64) -> Result<VerifiedAuthorization, CustodyError>`. `VerifiedAuthorization` has private constructors and retains native evidence plus exact selection scope. Binding fields and canonical array order follow the design, in its listed order.

- [ ] Write failing table-driven tests: each tenant/group/pubkey/event field, grant/epoch/device, participant set/session, crypto version and expiry alteration is denied; exact request passes; 121-second lifetime and 31-second skew fail; malformed/unknown fields fail. Include Unicode, escaped content, tag order and JavaScript-safe decimal-string versions.
- [ ] Run `cargo test --manifest-path tools/custody-spike/Cargo.toml --test intent_test`; verify assertions fail before implementation.
- [ ] Implement fixed-order commitment and enrolled P-256 proof validation. UCAN-shaped strings/API issuer signatures do not substitute for a device proof. Emit language-neutral vectors, no secret fixtures.
- [ ] Run the suite; require all cases pass and independent JavaScript verification of vectors.
- [ ] Commit the experiment boundary, contract and tests together.

### Task 2: Select the crypto/runtime adapter with evidence

**Files:** Create crypto module, conditional adapter, `tests/interop_test.rs`, dependency/decision section in experiment README.
**Consumes:** Task 1 identity binding and protocol versions.
**Produces:** `Participant::start_dkg(binding: IdentityBinding, id: u16) -> Result<DkgHandle, CustodyError>` and consuming round operations; `Participant::from_confirmed_package(...) -> Result<Participant, CustodyError>` only after exact binding validation. Secret handle types are defined here and not Clone/serde/Debug.

- [ ] Write failing tests for real 2-of-3 DKG, identical public descriptors, equivocated round-one transcript, wrong recipients, bad participant IDs, threshold one and bootstrap-human mapping substitution. The trusted fixture separately pins the creator/device and service authentication keys; an API UCAN alone cannot bootstrap an existing human's authority.
- [ ] Run `cargo test --manifest-path tools/custody-spike/Cargo.toml --test interop_test`; inspect failures.
- [ ] Implement reference DKG with exact official suite, confidential authenticated peer delivery and complete signed transcript agreement. Coordinator sees only public packages/ciphertext. Verify output independently using secp256k1 BIP-340 verification.
- [ ] In the candidate arm, pin Bifrost source and all crypto transitive packages. Test official-DKG package conversion, parity/tweak rules, each 2-of-3 subset, partial validation and final signature through the candidate boundary. Test an unauthorized inbound peer request is rejected before nonce consumption or any partial.
- [ ] Record pass/fail for each candidate property. If safe pre-sign interception or conversion is unavailable, do not ship that adapter: select the official-suite service protocol and retain a precise interop limitation. Do not call a rejected/untested adapter supported. External TypeScript/Igloo interoperability is a separately pinned test, not implied by the Rust result.
- [ ] Run suite and inspect dependency/lock diff; commit the selected bounded implementation and decision evidence.

### Task 3: Implement the non-forking private policy journal

**Files:** Create policy/store modules and `tests/policy_test.rs`.
**Consumes:** Task 1 types; independent fixture bootstrap from Task 2.
**Produces:** `PolicyJournal::prepare(&mut self, &PolicyProposal) -> Result<PolicyVote, CustodyError>`; `install(&mut self, &PolicyCertificate) -> Result<PolicyAck, CustodyError>`; `current(&self) -> Result<PolicySnapshot, CustodyError>`. `PolicyVote`/`PolicyAck` are per-authority signatures over the exact transition digest.

- [ ] Write failing tests: one malicious node offers different children to the other two, stale parent replay, mutable API membership substitution, unauthorized grant, last admin removal, durable prepare followed by restart, and timeout attempts to discard a fence. No two conflicting all-three certificates may form. One missing vote/ack must not report completion.
- [ ] Run `cargo test --manifest-path tools/custody-spike/Cargo.toml --test policy_test`; inspect failures.
- [ ] Implement append-only durable votes/fences and all-three installation, with single-child locking before vote release. Policy changes require current independently verified human/device authority. Keep stalled transitions fenced; exact retries resume; no unilateral timeout abort.
- [ ] Test one missing node still permits signing at an untouched committed policy, but blocks new mutations. Test a prepared transition pauses affected signing. Record this availability limitation explicitly.
- [ ] Run suite and commit journal plus assertions together. No production consensus claim follows from the test model.

### Task 4: Run one-human service-quorum signing in separate processes

**Files:** Create signer, transport and binary modules plus `tests/signing_test.rs`.
**Consumes:** `VerifiedAuthorization`, `Participant`, `PolicyJournal`.
**Produces:** `GuardedSigner::commit(&mut self, &VerifiedAuthorization) -> Result<PublicCommitment, CustodyError>`; `sign(&mut self, &SigningProposal) -> Result<PublicPartial, CustodyError>`; `aggregate(&SigningProposal, &[PublicPartial]) -> Result<Event, CustodyError>`.

- [ ] Write failing process tests: three distinct human admins each publish alone; one signer offline; coordinator plus one malicious signer proposes an altered event, wrong human/group, expired request or substituted policy; missing quorum and invalid shares fail.
- [ ] Run `cargo test --manifest-path tools/custody-spike/Cargo.toml --test signing_test`; inspect failures.
- [ ] Implement guard-before-crypto on every entry point and exact proposal/set binding. Use separate child processes and directories; never give the coordinator participant files or a general KeyManager capable of decrypting them. Fail instead of falling back to a local key.
- [ ] Independently verify every event with a second implementation, publish to a stock loopback test relay and retrieve the exact event through a separate reader. Record public IDs only and aggregate non-secret outcomes.
- [ ] Run tests, then commit the working process-level demonstration.

### Task 5: Prove partial-release, nonce and removal behavior under failure

**Files:** Extend signer/store modules and signing/policy tests; add child-process barrier hooks gated to the experiment's test configuration.
**Produces:** atomic commitment reservation, durable computed-public-partial/result cache, incarnation/worker fencing. `Participant` holds only live ephemeral signing nonces.

- [ ] Write failing tests with two workers for one participant; simultaneous same-commitment proposals; changed message/set; duplicate/conflicting retry; audit/state write failure; removal immediately before/after release. A revoked/obsolete request cannot release a fresh partial after completed removal.
- [ ] Run targeted tests and inspect failures.
- [ ] Persist spent reservation and computed public partial before release; return cached bytes only on exact retry. Burn uncertain work. Bound CPU admission and resource usage. Do not hold DB transactions across peer/KMS calls; if a SQL implementation is selected, exercise transaction-owning paths with `max_connections(1)`.
- [ ] Use actual process kill barriers before reservation, after reservation, after partial computation, after durable result and after network send. Restart without restoring pending nonce handles. Require fresh incarnation/session or identical cached public output, never nonce recomputation.
- [ ] Test removal concurrent with signing using deterministic barriers, not sleeps. Inspect observed serialization points, run all affected tests and commit with the evidence.

### Task 6: Restore one participant without restoring centralized authority

**Files:** Create recovery module and `tests/recovery_test.rs`.
**Consumes:** policy journal, independent epoch witness and per-domain crypto/store.
**Produces:** async `seal_share(&Participant, &BackupBinding, &DomainKeyManager) -> Result<EncryptedShareBackup, CustodyError>`; async `restore_share(&EncryptedShareBackup, &RecoveryCase, &RecoveryEvidence, &IncarnationCertificate, &DomainKeyManager) -> Result<Participant, CustodyError>`; explicit replacement-device policy proposal. No public API returns plaintext shares. Both operations await KeyManager outside any storage transaction. Service recovery advances the certified policy epoch and invalidates pending internal sessions; old native epoch proofs fail. A still-authorized legacy pool request can remain valid within its 120-second lifetime/30-second skew, but uses a fresh internal session/nonces or cached completed result. Human/device recovery separately revokes the old grant and rotates its certified bunker recipient; old-recipient traffic fails regardless of timestamp. Do not use timestamps as proof of a recovery-epoch commitment.

- [ ] Write failing tests: coordinator credentials plus one domain's KMS access cannot unwrap two shares; wrong tenant/group/participant/key/roster/suite rejected; ciphertext failure not acknowledged; retry preserves participant/pubkey; removed human denied; API-minted recovery proof denied.
- [ ] Run recovery tests and inspect failures.
- [ ] Implement strict encrypted packages and durable acknowledgment. Restore one participant directly inside its domain, retaining ID and fencing its former incarnation. Use synthetic independently held recovery approvals; do not label them a finished user account-recovery flow.
- [ ] Perform real snapshot rollback of signer/policy storage while retaining an independent epoch witness. Old sessions/workers/traffic must fail; restored nodes must obtain all-domain freshness certification before signing. Roll back every authority/witness or make it unavailable and verify fail-closed behavior. Test old native epoch proofs and old internal session packets fail. After human/device recovery, old-recipient NIP-46 traffic fails even with a future-skewed timestamp. After service-only recovery, test the documented bounded legacy request window uses a new internal session and fresh nonces, with current authority rechecked; expired or removed-device requests fail.
- [ ] Test archive plus retained encryption key restores the same public identity, missing/wrong key fails, nonce/session fields are absent, and no participant count increases. Remove disposable archives/keys after recording only non-secret results.
- [ ] Commit implementation, restore demonstration and exact limits.

### Task 7: Establish client compatibility without bypassing the guard

**Files:** Extend transport module, create `tests/nip46_test.rs` and client-contract section in experiment README. Production integration remains a subsequent approved change.
**Consumes:** certified device grant, selected crypto, signer guard and independent per-grant bunker keys.
**Produces:** `verify_nip46_request(&Event, &TransportCredential, &PolicySnapshot) -> Result<VerifiedAuthorization, CustodyError>`; this guard-local verifier retains original-request evidence and the certified pool scope in the same opaque authorization type consumed by Task 4. It validates the internally bound signing proposal without a coordinator-only authorization shortcut or a fabricated native proof.

- [ ] Write failing tests using a real standard client: connect/get_public_key/sign_event; forged outer signature, wrong recipient/client/grant, replay after recovery, altered API-decoded plaintext and supplied author/ID mismatch. Verify legitimate requests with omitted author use the certified identity.
- [ ] Run client tests and inspect failures.
- [ ] Each guard verifies the original signed encrypted request and decrypts it independently. Keep device proof and certified grant as authority; transport key possession alone cannot enroll or sign. Require the independently certified NIP-46 grant to permit the named service pool. At each guard, bind the verified request digest to the exact internal session/set, then recheck both before releasing a partial. Define exact request/result idempotency; native evidence still requires its originally approved exact set/session. Do not pretend legacy clients signed `IntentV1`.
- [ ] Test responses over a real relay and HTTP native-intent path with existing UCAN authentication. Inventory encryption/decryption, raw canonical signing and export paths. Unsupported methods return explicit errors and capabilities; reconstructing a key to fill a gap is forbidden.
- [ ] Commit tested compatibility scope. Before production, approve required operation parity and any client re-enrollment behavior; event-only success is not complete product compatibility.

### Task 8: Review the evidence and prepare a production decision

**Files:** Update experiment README and the design's decision record. Only after approval, prepare separate implementation changes at `core/src/custody/{mod,local,remote}.rs`, `core/src/signing_session.rs`, `core/src/bunker_key.rs`, `signer/src/signer_daemon.rs`, `api/src/handlers/http_rpc_handler.rs` and group integration points from merged PR #435.
**Proposed interface:** `CustodyBackend::public_key(&IdentityBinding) -> Result<PublicKey, CustodyError>` and async `sign_event(&VerifiedAuthorization, &UnsignedEvent) -> Result<Event, CustodyError>`. Retain a local backend for existing identities; persist backend/profile per identity and deny cross-backend fallback. No new serving code is delivered by the current research task.

- [ ] Run all prototype tests, fmt, clippy and the real-relay demo; repeat only when changes/failures justify it. Record p50/p95 and throughput for warm/cold signing, one-node outage, relay loss and recovery; report measured environments rather than inventing a production SLO.
- [ ] Independently review crypto/adapter, client proof, policy-fork safety, recovery and crash evidence. Collect an external security assessment for the exact proposed production dependencies and protocol.
- [ ] Produce a domain-access matrix covering KMS unwrap, DB/storage, backup restore, cloud administrators, deployment credentials, recovery authority and epoch witness. A shared threshold-controlling root fails isolation acceptance. Validate in a separately authorized disposable cloud environment; do not change production IAM here.
- [ ] Ask the product/security owner to choose recovery factors/operators and any delay/veto policy, accept all-three mutation availability or commission a replacement agreement design, and approve client/method compatibility and migration consent. Do not infer answers from the prototype.
- [ ] Only after those gates, write a production implementation plan and propose opt-in new group identities first. Personal identities, historical full-key migration and independent self-managed mode remain separately scoped. No deployment or live-key conversion follows automatically.
- [ ] Commit/push reviewed artifacts with a PR targeting main, required validation and mapped reviewers; inspect checks, report blocked gates, and keep the worktree clean.

## Current research completion record

Source inspection and this proposed plan are complete; all prototype checkboxes
above intentionally remain unchecked. No interoperability, runtime fault,
physical-device or cloud-isolation experiment has been performed by this research
change. Documentation validation and delivery evidence belong to this branch's PR.
