# Distributed Keycast custody: FROSTR research

Date: 2026-10-16. Status: source research and proposed direction, not an approved
custody change. No external signer was installed or executed, no live state was
queried, and no production permissions or keys were accessed.

## Recommendation

Prototype a 2-of-3 **infrastructure** signing backend behind independent
transaction-authorization guards. Keep one-human publishing. Retain the existing
pinned BIP-340-compatible crypto as the reference; evaluate FROSTR through a
version-pinned adapter before selecting its runtime. Do not install three Igloo
servers and treat peer connectivity as application authorization.

The intended guarantee is containment of the public coordinator plus one signer
security domain. It requires independent signing authorization, policy history,
enrollment, recovery and backups, not just a threshold scalar split. It remains
custodial: a threshold of compromised signer domains can sign.

Read the [proposed design](../superpowers/specs/2026-10-16-distributed-custody-design.md)
and [gated plan](../superpowers/plans/2026-10-16-distributed-custody.md).

## Evidence baseline

- Keycast main: `df350e30bcca683aa70465036f99eda9b7fab6fb`, fetched before inspection.
- Group backend: [PR #435](https://github.com/divinevideo/keycast/pull/435), inspected
  at `ac575486dd9022aa787b42e4363886da27f56ea8`. It was open during research and is
  **not in this branch's main baseline**. Its human-participant FROST mode must not
  be confused with the proposed service-participant custody mode.
- Bifrost Rust: `fe379c98825945a48e87e31360e2e87c6982af32`, workspace version 0.5.0.
- Bifrost TypeScript: `5c8348e5d597df459ce0b6960293289a2aabdc60`, package version 2.0.2.
- Igloo server: `918cfa3daf21fd5f49e3379ab1da108145da61aa`, package version 1.2.0.

These are inspected source commits, not a production dependency selection or a
claim that a matching release artifact was verified. Brain search supplied no
relevant evidence; no company-memory conclusion is inferred from it.

## What current Keycast actually requires

| Verified code fact | Consequence for the design |
| --- | --- |
| `SigningSession` owns `nostr_sdk::Keys`, signs events and supports encryption/decryption. | A remote threshold backend cannot be represented as another complete `Keys` value. Introduce an operation boundary rather than reconstructing a secret. |
| The signer loader decrypts personal/team stored keys and caches handlers. | More replicas improve availability but do not separate custody authority. |
| `derive_bunker_keys` uses the identity secret as HKDF input. | New custody grants need independent transport keys. Existing bunker credentials require an explicit migration/re-enrollment strategy. |
| UCAN and DPoP already authenticate HTTP requests; DPoP validates request method/URI, freshness and proof key. | Reuse HTTP authentication. An independently pinned device key and an event/context commitment are additionally needed for signer-side authorization. Do not call an ordinary DPoP proof an exact-body approval. |
| The group proposal stores encrypted signing packages using KeyManager and current human membership. | It provides recoverability, not separation from the service that can decrypt those packages. |

Primary references: [signing session](https://github.com/divinevideo/keycast/blob/df350e30bcca683aa70465036f99eda9b7fab6fb/core/src/signing_session.rs),
[signer](https://github.com/divinevideo/keycast/blob/df350e30bcca683aa70465036f99eda9b7fab6fb/signer/src/signer_daemon.rs),
[bunker derivation](https://github.com/divinevideo/keycast/blob/df350e30bcca683aa70465036f99eda9b7fab6fb/core/src/bunker_key.rs),
[DPoP](https://github.com/divinevideo/keycast/blob/df350e30bcca683aa70465036f99eda9b7fab6fb/api/src/ucan_auth/dpop.rs),
[group recovery](https://github.com/divinevideo/keycast/blob/ac575486dd9022aa787b42e4363886da27f56ea8/docs/GROUP_RECOVERY.md).

Deployment documentation describes multiple replicas within a common custody
boundary. This research does not assert a live instance count or verify deployed
IAM, backup scheduling or KMS access. Runtime placement must be verified separately
before operations; replica count is not the security property under study.

## FROSTR assessment

### Rust runtime

The inspected README labels the Rust stack beta and separates crypto, codecs,
signer, routing, bridge and host storage. That separation is promising for an
adapter. Its manifest uses `frost-secp256k1-tr-unofficial = "2.2.0"`, not the exact
`frost-secp256k1-tr = "=2.2.0"` used by the group proposal. Matching version strings
do not establish matching suites, package encodings or protocol behavior.

The Cargo lock pins the unofficial package checksum to
`e5279a0a375d505f5ec711521284d183ab6fea98edfdf798d65434b16c59a251`.
The crates.io version API reports the official 2.2.0 checksum as
`ff8a25b14bfd5d25deba5edce61ec99c3afb752a1d26630a196bba4cb1c4ca5e`.
Both names and all transitive crypto dependencies need review; this study did not
compare the complete implementations or validate a binary release.

Sources: [README](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/README.md),
[manifest](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/Cargo.toml),
[lock](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/Cargo.lock),
[official package metadata](https://crates.io/api/v1/crates/frost-secp256k1-tr/2.2.0),
[unofficial package metadata](https://crates.io/api/v1/crates/frost-secp256k1-tr-unofficial/2.2.0).

### Authorization boundary

The Rust inbound signing path checks peer method policy, validates the session,
consumes signing nonces and constructs a partial. The inspected branch does not
supply Keycast tenant/admin/device/event-approval semantics. Those are application
responsibilities. A useful integration must enforce them **before** nonce
consumption or partial creation, including inbound peer traffic. Protecting only
the coordinator's outgoing HTTP endpoint would be insufficient.

Source: [inbound signing path](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/crates/bifrost-signer/src/lib.rs#L2018).
This is an integration requirement, not a finding that FROSTR's own peer trust
model is broken.

### Generation, rotation and recovery

`create_keyset` accepts an existing complete key or generates with a dealer.
`rotate_keyset_dealer` calls `recover_key`; recovery reconstructs the signing key
before splitting again. Those convenience paths are excluded from the proposed
new-identity service. New identities need authenticated confidential DKG with
complete round-one agreement. DKG/package conversion into Bifrost is unverified.
Replacing one failed service uses that participant's protected backup and stable
identifier, not full-key recovery or a new quorum vote.

Sources: [keyset helpers](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/crates/frostr-utils/src/keyset.rs),
[reconstruction helper](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/crates/frostr-utils/src/recovery.rs),
[ZF DKG requirements](https://frost.zfnd.org/tutorial/dkg.html).

### Nonce and restoration semantics

The Rust runtime persists device state and nonce bookkeeping through its store
interface. Its host supplies encrypted file persistence and a local file lock.
These are useful local safeguards, but do not establish cross-host fencing or
safety after snapshot rollback. The service must define a fresh installation
incarnation, drop pending nonce state on restart/recovery, and reject old traffic.
Do not use a general runtime-state export as a signing-share backup. The
interaction between FROSTR's nonce derivation and share restoration is a specific
review and crash-test gate, not an assumed compatibility property.

Sources: [nonce lifecycle](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/crates/bifrost-core/src/nonce.rs),
[persisted signer state](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/crates/bifrost-signer/src/lib.rs#L99),
[host store and lock](https://github.com/FROSTR-ORG/bifrost-rs/blob/fe379c98825945a48e87e31360e2e87c6982af32/crates/bifrost-app/src/runtime/store.rs).

### TypeScript and Igloo

The inspected TypeScript library depends on `@vbyte/frost` and provides signing
middleware. The inspected Igloo server instead declares `@frostr/bifrost ^1.0.7`
and `@frostr/igloo-core ^0.2.4`; its peer policies are directional connection
permissions. These are different source/dependency baselines. An Igloo deployment
is not proof of Rust interoperability or per-human Keycast authorization. Keep it
as a separately pinned external-peer test candidate, not a production dependency
selected by this document.

Sources: [TypeScript manifest](https://github.com/FROSTR-ORG/bifrost/blob/5c8348e5d597df459ce0b6960293289a2aabdc60/package.json),
[TypeScript security model](https://github.com/FROSTR-ORG/bifrost/blob/5c8348e5d597df459ce0b6960293289a2aabdc60/docs/SECURITY.md),
[Igloo manifest](https://github.com/FROSTR-ORG/igloo-server/blob/918cfa3daf21fd5f49e3379ab1da108145da61aa/package.json),
[Igloo peer policy](https://github.com/FROSTR-ORG/igloo-server/blob/918cfa3daf21fd5f49e3379ab1da108145da61aa/docs/PEER_POLICIES.md).

No independent audit report covering these exact commits was established by the
reviewed sources. Upstream release checklists and dependency-audit commands are
not evidence of an independent protocol review. Obtain the report/scope or fund
that review before production selection.

## Options

| Option | Benefit | Cost / limitation | Recommendation |
| --- | --- | --- | --- |
| Multiple unchanged Keycast replicas | Availability and load distribution | Each authorized process retains full-key access | Keep operationally useful; no custody-containment claim |
| FROSTR/Igloo nodes with peer allowlists | Existing relay transport and threshold tools | Missing independent human authorization, policy and recovery integration | Do not deploy as a drop-in security fix |
| Guarded 2-of-3 service signers | One human can publish; separates machine custody | Requires independent policy, enrollment, storage and operations | Recommended research prototype |
| Required device share plus service/recovery shares | Stronger user-held custody | Mobile availability and recovery semantics change | Separate opt-in design; not the default proposal |

Selecting the third option does not preselect a FROSTR runtime. Compare a guarded
Bifrost adapter with service workers using the existing official FROST suite.
Prefer the existing suite if safe interception, DKG conversion or recovery
compatibility cannot be demonstrated. Do not implement cryptographic primitives.

## The permission-agreement distinction

This is design reasoning, not an upstream FROSTR claim. A 2-of-3 cryptographic
threshold does not supply Byzantine agreement for mutable permissions: two
certificates can overlap in only one, potentially malicious, authority. Thus a
simple majority certificate must not be advertised as a safe policy log.

The prototype proposes all-three signatures over a non-forking policy transition,
with durable prepare fences. Normal signing remains 2-of-3. Policy changes stop
when one authority is unavailable or refuses; a prepared change can also pause
signing until resolved. If policy availability under one malicious/offline
participant is required, research a separately reviewed Byzantine control plane
with sufficient replicas; do not relabel a three-node majority as consensus.

## Research outcomes versus remaining experiments

Verified here: source versions, complete-key integration points, selected FROSTR
interfaces, dealer/reconstruction paths and package identities. Proposed here:
service topology, guard, all-three policy transitions and separated recovery.

Not executed here: cross-library DKG/package conversion; real Bifrost signing;
malicious-coordinator or crash/rollback harness; passkey/new-device recovery;
independent KMS restore; physical-device operation; deployment benchmarks or a
live permissions audit. The implementation plan makes these explicit gates.
