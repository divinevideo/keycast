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
