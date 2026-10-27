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

## Immutable image acceptance: two separate gates

The mechanism PR's read-only `.github/workflows/challenge-image-contracts.yaml` runs on
pull requests to main with `contents: read` only and no services, browser download,
registry login or integration execution. Bun 1.3.10 is pinned: its `Bun.YAML.parse` is the
semantic YAML parser for the Python workflow contracts; no production dependency or lock
is added. The Rust startup-gate extraction uses Rust 1.93.0. The PR gate runs:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_challenge_image_acceptance.py' -v
cd e2e
bun install --frozen-lockfile
bun test helpers/challenge-image.test.ts
```

The Bun helper command includes actual list-only collection of the default and dedicated
Playwright configurations and compilation of the dedicated local module graph. Collection
and source contracts are mechanism evidence only. Relevant repository checks and independent
diff review also precede authorized merge. The first candidate run cannot happen before the
mechanism is on main; this is not a missing or waived PR gate. Runtime acceptance is
**pending postmerge** until the separately authorized hosted run and independent inspection.

The manual-only `.github/workflows/challenge-image-acceptance.yaml` runs on ubuntu-24.04
with a 60-minute bound and only `contents: read` / `packages: write`. It neither deploys nor
triggers another workflow. A release owner first verifies the existing GHCR package's
visibility, publish/retain capability for the repository's `GITHUB_TOKEN`, hosted dependency
availability and evidence retention. A CLI read-scope 403 does not establish that the hosted
token cannot publish. Missing capability leaves acceptance incomplete; this mechanism does
not create packages, change visibility/access, add credentials or change IAM.

After authorized merge, the owner selects current main, accounts for every intervening
change since the approved linked-permission read-only audit, and records why that aggregate
audit remains applicable or which separately approved refreshed evidence is required.
Permission/factory, schema, dependencies and build/configuration changes all need review.
Do not retrieve connection material or rerun the audit automatically. The mechanism's main
commit includes all intervening commits; it is not limited to the original Stage 1 changes.
Only after explicit maintainer execution authorization does the owner dispatch this workflow
on main with its full 40-character lowercase `source_sha`.

Before registry access or building, the workflow requires `github.ref == refs/heads/main`,
`source_sha == github.sha == github.workflow_sha`, the repository's acceptance workflow path
on main, checkout HEAD equality, clean tracked source, fetched `origin/main` equality and
ancestry. A main advance between dispatch and checkout's authenticated fetch fails closed.
This is a current-main dispatch contract, not an arbitrary historical main SHA selector.
Source, workflow and tooling SHAs, checkout HEAD, full tree SHA, workflow ref/event, run and
attempt are recorded independently even though their commit identities must agree. The
release owner must independently cross-check GitHub's actual run event, ref, head SHA and
workflow path against the workflow file at the independently selected reviewed main SHA;
uploaded assertions alone do not establish that identity.

A `git archive HEAD` context excludes ignored and untracked local files. Both the normal
release Dockerfile and the separate `e2e/Dockerfile.acceptance` client use this single clean
tree. Both existing Rust Dockerfile builds use `--locked` to reject dependency resolution
that would require changing `Cargo.lock`. The source lock hash is recorded; the later
source-file comparison does not inspect the builder filesystem or prove full reproducibility.
**This also changes the normal production build recipe:
`cloudbuild.yaml` uses the same Dockerfile. Include this disclosure in the mechanism PR.**
Normal web/keycast-login Bun installation and build behavior remains in the release recipe;
it is recorded, including lock hashes, and is not claimed to be fully reproducible.

The one release build targets linux/amd64, enables maximum provenance and pushes only
`ghcr.io/divinevideo/keycast:acceptance-<full-source-sha>-<run-id>-<run-attempt>`.
Neither `latest` nor a commit-only tag is written. Buildx metadata, resolved base identities,
index/platform/provenance manifests, Dockerfiles, Cargo/web/keycast-login/E2E locks,
workflow and canonical fixture/policy hashes are recorded. Missing provenance/base identity
is a failure, not permission to invent it. The exact promotion object is the preserved
**registry index digest**, including every referenced platform/provenance manifest and blob.
Keep the unique tag, index and all referenced content until explicit release-owner disposal;
90-day GitHub artifact retention is separate from registry retention. If evidence expires or
is lost, the candidate has no accepted replacement.

After pulling the preserved index with explicit linux/amd64 selection, the workflow records
the registry platform manifest digest and config digest separately from this daemon's
`docker image inspect` `.Id`. Buildx `containerimage.digest` and
`containerimage.descriptor.digest` must both match the registry index digest, and the
descriptor media type must match the registry index. The config digest is read only from
the registry platform manifest; provenance index metadata may omit the single-manifest
`containerimage.config.digest` key. The Task 1 runner compares migration/server container `.Image`
against that **same-daemon image ID** before and after testing. A config digest is not a
substitute. Every migration/server container uses the preserved index reference with
linux/amd64. All Postgres/Redis/relay discovery tags are resolved and pulled to digest
references before RunSpec construction or internal network creation. The independently
built, loaded client is labelled test tooling; runtime receives no registry credentials,
host credential mounts or production services. Registry login is removed before execution.
The build record captures the actual daemon storage driver and reported driver-type
(containerd snapshotter state, when reported); it neither changes daemon settings nor
establishes hosted image-store compatibility.

### Sanitized evidence and configuration fingerprints

Only the fixed `summary.json` and `artifact.json` under the runner's `challenge-public`
directory are uploaded, with retention 90 days and missing files treated as errors. There
is no artifact glob or raw diagnostic upload. Both Docker build actions explicitly disable
their automatic build-record artifact upload and build summary; only the sanitized evidence
paths are published. A failed/incomplete gate emits no accepted
artifact. Private subprocess output, browser output, ownership journal and raw CLI capture
remain outside the uploaded paths. Before acceptance assertions, the job log prints only
a fixed known failure category, bounded counts, suite exit code, cleanup result, and
failed/missing source-owned case IDs. Failed IDs come from the strict actual recorder
summary retained locally; unknown/malformed diagnostics produce a fixed sanitized error.
There is no failed-run artifact upload or acceptance bypass.

RunSpec schema 1 is unchanged: source/workflow/tooling SHAs, run/attempt, preserved index
reference, platform/config digests, same-daemon release/client IDs, exact digest-pinned
Postgres/Redis/relay dependencies and an absolute evidence directory. The workflow invokes
`python3 scripts/challenge-image-acceptance.py --spec ABSOLUTE_RUN_SPEC_JSON`. An always-step
repeats `--cleanup OWNERSHIP_JSON` using only the runner's recorded ownership; no candidate
is deleted. Failed original cleanup cannot be repaired into an accepted run by the repeat.

The evidence adapter reads actual AcceptanceResult schema 1, rejects unknown fields and
requires the exact current source-owned 106 executed IDs (4 runtime and 102 suite), all 106
passed, zero failures, no missing/duplicate/skipped/aggregate cases, `complete=true`,
`passed=true`, integer `suite_exit_code=0`, and complete original **and** final cleanup.
Acceptance and final cleanup step outcomes must both be success. Summary schema 1 explicitly
maps `complete`, `passed`, runner `configuration_fingerprint`, `expected_case_ids`,
`executed_case_ids`, `counts`, `suite_exit_code`, `cleanup`, `failure`, plus `final_cleanup`.
Artifact schema 1 carries validated `run_spec`, the build/identity record, canonical
nonsecret `configuration`, its SHA-256 `configuration_fingerprint`, and evidence scope.
The runner's fingerprint and artifact's combined release configuration fingerprint have
different named scopes; both are retained rather than silently replacing one another.

The allowlisted settings in both fingerprint inputs are `NODE_ENV`, `DISABLE_EMAILS`,
`KMS_PROVIDER`, `USE_GCP_KMS`, `MASTER_KEY_PATH`, `WEB_BUILD_DIR`, `APP_URL`, `ALLOWED_ORIGINS`,
`ALLOWED_TENANT_DOMAINS`, `BUNKER_RELAYS` and `SHOW_TEAMS_FUNCTIONALITY`. The runner also hashes
platform, namespace, generated-identity mode, dependency references and required cases.
The artifact combines the runner fingerprint with those settings, dependency identities,
fixture/policy hashes and explicit substitutions. JSON uses sorted keys and compact
separators before SHA-256. Credentials, DATABASE_URL/REDIS_URL and all DSNs, private keys and
private-key hashes are excluded, not hashed as a substitute for exclusion. This changes
fingerprint serialization only; actual container environments and ownership are unchanged.

### Evidence inspection, promotion and production gates

The release owner inspects actual build/push/accept/cleanup steps and sanitized files against
independently verified GitHub metadata and the reviewed source/workflow tree. A green job,
collection-only tests or a non-publishing rehearsal is insufficient. A failed run blocks
preproduction acceptance: make a focused reviewed fix PR and authorize a new main candidate;
never weaken the gate or reuse evidence for changed bytes. No manual dispatch, runtime
acceptance, promotion or rollout is authorized by these source changes.

Isolated acceptance substitutes owned ephemeral Postgres/Redis/relay, file KMS, generated
synthetic identities, loopback origin and a single instance. It does not prove production
data compatibility, real KMS/credentials, production origin/relay configuration, multi-instance
coordination or enforcement by every serving revision. Record a corresponding separately
approved production check for each substitution. Keep these remaining gates distinct:

1. Approved aggregate linked-permission audit and explicit source-delta reconciliation.
2. Authorized postmerge exact-image acceptance and independent evidence review.
3. Explicit Stage 1 rollout authority and an approved digest-preserving promotion route.
   Copy/import the complete registry index and all referenced manifests/blobs without
   conversion or rebuilding; verify destination index, linux/amd64 manifest and config
   digests separately. Runtime pull/copy access and retention remain concrete dependencies,
   with no IAM change implied. Compare container IDs only within each daemon. Changed bytes
   require accepting the new artifact again. Existing Cloud Build rebuilds/deploys and cannot
   silently serve as the promotion route; do not dispatch it or build-test-push as a substitute.
4. After authorized rollout, inventory every actual serving Cloud Run revision, traffic
   assignment and exact digest/config equivalence; verify existing-policy allowed/denied
   HTTP/NIP46 signing and consent over each actual serving path. Desired config or tags do
   not prove serving enforcement. Stage 1 creates no production challenge grant.
5. Keep an approved Stage 1 enforcement revision as the rollback floor whenever any
   `challenge_actions` row or grant exists, regardless of how it was created.
6. Stage 2 remains a separate reviewed main PR enabling public preset activation, team-policy
   API and picker together. Verify global `team_id IS NULL`, slug `challenges`, a nonempty
   exact `challenge_actions` `{}` link, challenge-specific HTTP/NIP46 signing and consent
   before scoped web rollout. Consumers request exactly `policy:challenges` without a
   `policy:full` fallback. Link dependent mobile/Funnelcake/consumer work and its actual
   delivery state separately; this mechanism is not end-to-end Challenges delivery.

Local implementation authors commit source only. The coordinating owner handles fresh-main
integration, the combined main-targeting mechanism PR, independent review, one mapped-team
request and required-check inspection. Merge authority, later execution authorization and
production authorization remain separate; no premerge candidate run is required.
