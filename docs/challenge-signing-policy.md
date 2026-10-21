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

## Release sequence

This Stage 1 change introduces enforcement code and registries only. It does not create
or activate a global `challenges` preset, modify consumers, or deploy a service.

Activation requires a separate reviewed, main-targeting migration PR after an explicitly
authorized Cloud Run code rollout has verified every serving revision enforces the new
permission. That release must record the additional PR/deployment and a minimum safe
rollback revision. The eventual global preset has `team_id IS NULL`, slug `challenges`,
and a nonempty exact permission link to `challenge_actions` with `{}` configuration.
Before serving consumers, verify that link and the exact `policy:challenges` scope;
consumers must never widen it to `policy:full` as a fallback.

Fixture provenance and compatibility pins are recorded in
`core/tests/fixtures/challenges/SOURCE.md`. Definition timezone membership preserves
all 597 chrono-tz 0.10.4/tz2025b names and 40 audited ICU 78.3/tz2026a aliases,
accepting ASCII case variants while retaining signed spelling. Relay domains follow
the canonical nontransitional Unicode 17 UTS #46 profile, including Bidi and joiner
checks. Its settings are `transitionalProcessing: false`, `checkBidi: true`,
`checkJoiners: true`, `checkHyphens: false`, `useSTD3ASCIIRules: false`,
`verifyDNSLength: false`, and `ignoreInvalidPunycode: false`. This is the canonical
signing-contract profile; browser URL parsers may impose additional runtime restrictions.
