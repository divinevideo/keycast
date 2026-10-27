# Challenge signing permission foundation

`challenge_actions` is a configurable Keycast permission. Its configuration is exactly
`{}`; other shapes or unknown options are rejected. It can be combined with other
permissions using the existing AND semantics.

It permits marked Divine challenge v1 definitions (31923), entries, withdrawals and
results (1111), and contest include/exclude labels (1985). Contest labels must use
matching `video.divine.contest.<contest-id>` namespaces with a nonempty identifier.
Their content and tag shapes follow the organizer web application's curation contract.
This permission supports contest curation across namespaces; it has no organizer allowlist.

Consent describes creating and managing challenges, entering and withdrawing entries,
announcing results, and curating contests. It grants no private-message access:
all encryption, decryption, and creator-binding requests are denied. Public-key lookup
and token refresh remain available without permitting unrelated signing kinds.

The permission validates bounded unsigned templates, their references and signed
snapshots. It is a signing-family boundary. Consumers must still verify the completed
event's signature and author, apply maintained organizer/admin allowlists, and evaluate
challenge lifecycle eligibility. A caller's unsigned public key does not establish
signer identity. The full resulting signed-record size is limited to 64 KiB.

Configured permission loading is explicit: unknown identifiers or invalid configuration
prevent HTTP handler construction and permission/consent display. Deliberately
unrestricted policies retain their existing empty-permission semantics.

The contest-label `e` relay additionally has the curation reader's 2048 UTF-16-code-unit
limit. Definition `challenge_relay` values retain the full signed-record budget.

## Maintainer behavior

Configured permission errors deliberately fail closed. A bad permission on one entry can
fail the entire public policy list or account permission list rather than displaying an
incomplete authorization. The separate account-session/revocation endpoint remains available.
Consent and token issuance also reject an invalid configured permission. Refresh validates
its display after consuming the one-time refresh token; a configuration or transient loading
error at that point can require the user to authorize the app again. This change does not
introduce token-consumption grace or a new transaction model.

## Release sequence

Stage 1 registers enforcement and display support while holding management creation:
the team-policy API rejects `challenge_actions`, and the management picker omits it.
The factory, registry and configuration renderer remain available for enforcement and
isolated tests. This is a code-only hold, with no environment flag or preset lookup.
It does not create or activate a global `challenges` preset, modify consumers, or deploy.

Before deploying Stage 1, obtain approval for a read-only audit that every existing permission
row linked to a policy converts through the current factory. Repair any invalid configuration
through the approved owner workflow before rollout; passing seed tests is not production-data
evidence. Record the approved audit and its result in the release evidence.

Verify challenge-specific allowed/denied signing, malformed-configuration rejection and
consent on the identical immutable release image against isolated nonproduction services.
Stage 1 creates no production challenge test grant. Its production checks are the approved
read-only conversion audit, exact serving-image/revision inventory, configuration equivalence
and runtime enforcement of existing policies through both transports and consent paths.
Source or catalog inspection alone does not prove runtime enforcement.

Activation requires a separate reviewed, main-targeting Stage 2 PR after an explicitly
authorized Cloud Run Stage 1 rollout completes those checks for every serving revision. Stage 2 must explicitly enable the team-policy API and management picker together
with the public preset activation. Record that additional PR/deployment. Production
challenge-specific allowed/denied signing through both transports remains mandatory after
activation and before scoped web rollout. Its migration may run
before the Stage 2 serving rollout because all serving Stage 1 revisions already understand
the permission while holding management creation.

Whenever any `challenge_actions` permission row or authorization grant exists, record an
approved Stage 1 enforcement revision as the minimum safe rollback floor; do not roll back
below it. This applies regardless of how the permission was created, not only after the public
preset activation. The eventual global preset has `team_id IS NULL`, slug `challenges`, and a
nonempty exact permission link to `challenge_actions` with `{}` configuration. Before serving
consumers, verify that link and the exact `policy:challenges` scope; consumers must never widen
it to `policy:full` as a fallback.

## Read-only linked permission audit tool

Build the standalone tool from the exact source revision being evaluated:

```sh
cargo build --locked -p keycast_core --example audit_policy_permissions
```

After separate authorization for the target database, supply its connection through
`KEYCAST_PERMISSION_AUDIT_DATABASE_URL` using the approved connection workflow, then run:

```sh
./target/debug/examples/audit_policy_permissions --audit-linked-permissions-read-only
```

The flag and dedicated environment variable are required. The tool does not load `.env`,
`DATABASE_URL`, the server, migrations, keys, authorizations, KMS or Redis. This invocation
is tooling guidance, not authorization to access production. A local pass is not Stage 1
release acceptance or production-data evidence.

A dedicated SQLx pool has one connection and a five-second acquisition timeout. Before
reading data, it begins an explicit repeatable-read, read-only transaction, sets local
15-second statement, two-second lock and 30-second idle transaction timeouts, and checks
server-reported `transaction_read_only` and isolation. The whole invocation has a 60-second
async timeout. It rolls back after the audit. Only `public.policy_permissions` and
`public.permissions` are queried; no policy names, account or key tables are read.

One snapshot supplies linked-policy, link and distinct-permission counts and server-side
encoded byte lengths. Before fetching any identifier/config text, it rejects more than 10,000
links or distinct permissions, more than 8 MiB total identifier/config text, or more than
256 KiB for any one identifier/config pair. These fixed conservative budgets have no CLI
override. A budget/timeout/database error or incomplete link set exits nonzero without an
audit report; it never reports success for a truncated set. Larger datasets need a separately
reviewed bounded audit approach. The row query also has a limit of 10,001 and its returned
count must match the snapshot's distinct-permission count.

Each distinct linked permission is decoded through `JsonConfig::try_from`, converted by
`Permission::to_custom_permission`, and passed through the same `.display()` conversion as
consent. Shared permissions are counted once; malformed unlinked permissions are excluded.
Policies without links retain their unrestricted semantics and contribute no linked rows.
Null or missing permission references fail the audit. The tool does not validate policy
behavior, repair data, or activate the challenge preset.

Stdout contains one aggregate JSON object only after a complete scan: `complete`, `passed`,
`totals`, and `conversions`. Conversions include successful/failed counts, successful display
count, and fixed categories `malformed_json`, `unknown_permission`, `invalid_config`, and
`conversion_database`. Invalid linked rows produce a complete aggregate report with
`passed: false` and a nonzero exit. Stderr uses fixed messages only. Identifiers, configuration,
IDs, policy names, display text, connection details and raw errors are never emitted.

Pure tests run with `cargo test --locked -p keycast_core --example audit_policy_permissions`.
The database test additionally requires `--features integration-tests` and
`KEYCAST_PERMISSION_AUDIT_TEST_DATABASE_URL`; it accepts only an explicitly prepared, owned
fixture at `127.0.0.1:55448`, database `keycast_permission_audit_test`. It creates/drops only
synthetic `permissions` and `policy_permissions` fixture tables there. Never point it at an
application database. It verifies shared links, malformed/unknown/invalid conversion,
concurrent snapshot consistency, empty links, byte/row budgets, database failure and
server rejection of writes. It never falls back to `DATABASE_URL` or shared services.

## Runtime versions and upgrade audit

Fixture provenance is recorded in `core/tests/fixtures/challenges/SOURCE.md`. Timezone membership
preserves all 597 chrono-tz 0.10.4/tz2025b names and 40 audited ICU 78.3/tz2026a aliases,
accepting ASCII case variants while retaining signed spelling. That audited timezone-name
compatibility set is distinct from the Rust IDNA data dependency below.

The current resolved artifact is `Cargo.lock`: unicode-segmentation 1.13.2 exposes Unicode
17.0.0 grapheme tables; url 2.5.8 uses idna 1.1.0, idna_adapter 1.2.1, and ICU4X normalizer,
properties and data crates 2.2.0. Build and validate with `--locked`. Manifest caret ranges do
not permanently pin these transitive runtime/data versions. The small in-tree Unicode 17
Extend/title-limit sentinel checks the actual permission boundary; it is not a complete
Unicode segmentation audit or proof of parity with every client's grapheme library.

Relay domains target the canonical nontransitional Unicode 17 UTS #46 profile, including Bidi
and joiner checks: `transitionalProcessing: false`, `checkBidi: true`, `checkJoiners: true`,
`checkHyphens: false`, `useSTD3ASCIIRules: false`, `verifyDNSLength: false`, and
`ignoreInvalidPunycode: false`. The signed canonical relay fixtures and recorded 6391-case
actual-policy comparison cover the audited inputs, not every Unicode string. Browser URL
parsers may impose additional restrictions; no universal browser/runtime parity is asserted.

Any update of url, idna/idna_adapter, ICU data, unicode-segmentation, timezone data, or the
canonical runtime requires a runtime-data/conformance re-audit: inspect the actual locked data
versions, rerun canonical fixtures and the relevant authoritative IDNA/normalization/grapheme
vectors, rerun the actual-policy URL probe, and record compatibility limits. Preserve current
locked packages unless a separately reviewed correctness change requires an update.
