# Funnelcake-owned OG Diviner eligibility

Status: proposal for agreement, 2026-10-29. Preparing this proposal was
authorized; implementation, production export/load, deployment and merge were
not. **Keep [Keycast #443](https://github.com/divinevideo/keycast/pull/443) held.**
Accepting or merging this document does not lift that hold.

## Intent and approaches

OG Diviner is a historical fact about a Nostr pubkey, including people who never
created a Keycast account. Serve it with profiles without making public badge
traffic compete with account and signing traffic. Preserve existing eligibility
while adding early app posters, and erase eligibility when an account is deleted.

The approaches considered were:

| Approach | Tradeoff | Disposition |
| --- | --- | --- |
| Keycast account rule plus private poster grants, as in #443 | Small backend change, but retains unrelated pubkeys and public profile load in the signing service | Held by the maintainer |
| Funnelcake-owned private union of the existing cohort and app posters | Requires coordinated migration and deletion handling, then one profile authority | User selected preparing this proposal |
| Leave ownership undecided and document the hold only | No migration work, leaves the blocker unresolved | Not selected |

The direction follows [dcadenas's ownership proposal](https://github.com/divinevideo/keycast/pull/443#issuecomment-6448586951).
It does not imply agreement on every mechanism below. Field names, revision
handling, cache bounds and rollout gates are proposed engineering choices.

Non-goals: NIP-58 award issuance, changing badge appearance, identifying all early
Nostr users, changing moderation eligibility, a public roster, new authentication,
or changes to account custody/signing. No livestream or LiveKit work is involved.

## Evidence inspected

These are repository snapshots, not a claim about deployed versions or live
database contents. No production data was queried or exported for this proposal.

| Source | Current behavior relevant to migration |
| --- | --- |
| [Keycast main user repository](https://github.com/divinevideo/keycast/blob/056daf880ba2b957bb3a47e8797c09a078e64b88/core/src/repositories/user.rs) | Tenant-scoped eligibility from account, claim-token and mobile OAuth facts |
| [Keycast main public handler](https://github.com/divinevideo/keycast/blob/056daf880ba2b957bb3a47e8797c09a078e64b88/api/src/api/http/og_diviner.rs) | `GET /api/public/users/{pubkey}/og-diviner` returns only `eligible`; cache policy allows one day plus seven days stale on error |
| [Held #443 head](https://github.com/divinevideo/keycast/commit/cbb39a24168c0d0e760bb11635c75ee7e10f1b40) | Adds private tenant-scoped poster grants, loader and grant deletion; this is proposed code, not a main-branch dependency |
| [Funnelcake profile and bulk handlers](https://github.com/divinevideo/divine-funnelcake/blob/d8c0ea1d34fbfe9c8614a94e3f48eecdb1ac8155/crates/api/src/handlers.rs) | `GET /api/users/{pubkey}` composes independent fields; `POST /api/users/bulk` accepts at most 100 pubkeys and omits hidden users |
| [Funnelcake response types](https://github.com/divinevideo/divine-funnelcake/blob/d8c0ea1d34fbfe9c8614a94e3f48eecdb1ac8155/crates/clickhouse/src/queries.rs) | `UserData` has optional badges/identities and historical `has_vanish_request`; no OG Diviner field |
| [Funnelcake vanish storage](https://github.com/divinevideo/divine-funnelcake/blob/d8c0ea1d34fbfe9c8614a94e3f48eecdb1ac8155/crates/clickhouse/src/vanish.rs) | `vanished_pubkeys_set` is pending-only; durable history includes requests and boundary tombstones; pubkey-only erasure tables have a separate sweep list |
| [Funnelcake cache middleware](https://github.com/divinevideo/divine-funnelcake/blob/d8c0ea1d34fbfe9c8614a94e3f48eecdb1ac8155/crates/api/src/router.rs) | Overrides profile handler caching with browser max-age 15s, stale-while-revalidate 45s, surrogate max-age 60s and a user purge key |
| [Mobile eligibility service](https://github.com/divinevideo/divine-mobile/blob/fa45d43bd01e246d5de8c56f44ffe6a9cb56ea0e/mobile/lib/services/og_diviner_eligibility_service.dart) | Deduplicates Keycast requests and caches successful booleans for the process lifetime |
| [Mobile Funnelcake client](https://github.com/divinevideo/divine-mobile/blob/fa45d43bd01e246d5de8c56f44ffe6a9cb56ea0e/mobile/packages/funnelcake_api_client/lib/src/funnelcake_api_client.dart) | Parses found/not-published/vanished profile results; ignores unknown response fields today |
| [Mobile client-tag change](https://github.com/divinevideo/divine-mobile/commit/0ed9ea93d6f8c086ac559e580a953a3aa68c3fcb) | Replaced the video publisher's `['client', 'diVine']` with shared NIP-89 attribution and an opt-out preference |

## Ownership and cohort contract

Funnelcake owns the private eligibility relation and its serving/deletion rules.
Keycast remains the source of its historical account facts for an initial
snapshot and any required late-completion deltas, not an online dependency for
new profile reads. Mobile consumes a
boolean, never signup, OAuth, claim or poster evidence.

Define `eligible = (legacy OR early_poster OR approved_exception) AND NOT erased`.
The cutoff is strictly before `2026-08-18T04:00:00Z`, preserving
[issue #440](https://github.com/divinevideo/keycast/issues/440). Use an explicit
Divine cohort namespace mapped to exactly one approved Keycast tenant. Never
union every Keycast tenant or accept a client-supplied tenant selector. Other
deployments/tenants are out of this migration's scope.

The legacy snapshot must reuse the existing predicate exactly, including the
outer tenant-scoped user row and all three alternatives:

- Account created before cutoff, email verified, password hash present,
  `vine_id IS NULL`, and **no claim-token row** for that user/tenant.
- A matching claim token with `used_at < cutoff`.
- A matching `divine-mobile` OAuth authorization created before cutoff.

Preserve the current treatment of revoked authorizations, nulls and multiple
claim tokens; do not introduce a new status/revocation filter. Do not export the
underlying account fields. Ban/suspension does not revoke this historical badge,
although existing profile visibility filters still apply. A cleanup of old claim
records can change today's answer: pin the predicate and snapshot instant, and
compare with the existing endpoint before its source data is retired.

The cutoff does not freeze every branch of today's predicate. A pre-cutoff
web row can become eligible after the snapshot when email verification completes;
a pre-cutoff pubkey-only row can also qualify after later materialization.
Snapshot parity alone therefore cannot establish ongoing legacy parity.
Before implementation, owners must choose explicitly between preserving those
late completions through an idempotent durable delta feed, or changing policy to
freeze legacy eligibility at the snapshot instant. The latter changes today's
rule and requires explicit acceptance, including compatibility behavior.
Until that decision, source retirement and activation are blocked; do not assume
the remaining candidate count is zero or that one export preserves future answers.

The early-poster cohort is original, nonarchive Divine app video received by the
relay before cutoff. Signed `created_at` is not arrival evidence. Historical
client tags are attribution evidence, not cryptographic proof of app use.
Before computing the set, enumerate released client-tag forms from source
history and test legacy `diVine` plus the canonical NIP-89 form. Do not match
arbitrary tags containing the word Divine. An opt-out means no tag is not proof
of ineligibility; the initial automatic set can undercount.

Funnelcake's [original event schema](https://github.com/divinevideo/divine-funnelcake/blob/d8c0ea1d34fbfe9c8614a94e3f48eecdb1ac8155/database/migrations/000001_create_database_and_events.up.sql)
uses `indexed_at DEFAULT now()` and replacement by that version. Reinsertions
can lose an earlier observed time. Verify the deployed schema and retained
arrival evidence before choosing a backfill source. Do not relabel an event-time
or reindex-time column as immutable relay first arrival. Report uncertain/missing
evidence as an aggregate limitation; do not silently widen the cutoff. Approve
manual exceptions privately with recorded reason, actor and revision. Do not
turn exceptions into an unauthenticated self-claim endpoint.

## Private data and storage proposal

Workload: a relatively small eligibility dimension with high-frequency
single/bounded-batch pubkey reads, rare corrections, any legacy completion deltas
required by the policy decision above, and mandatory erasure. No
event-history scan belongs on the request path. No recurring recompute or
refreshable MV is needed for this closed cohort.

Proposed logical records, all private:

| Record | Minimum contents |
| --- | --- |
| Eligibility | Cohort namespace, full lowercase hex pubkey, source class (`legacy`, `early_poster`, `exception`), active/revoked state, monotonic revision, import ID |
| Import manifest | Unique import ID, approved tenant-to-cohort mapping, predicate version, cutoff, snapshot time, source commit/schema versions, private checksum, counts, validation/activation state |
| Exception audit | Actor, reason code, revision and private evidence reference; no account metadata on public API |

Use one eligibility relation for both cohorts with source provenance, deduping
overlaps to one boolean. Reuse existing durable deletion history rather than
making an eligibility roster into another deletion authority. Redis can cache,
but cannot be the only copy of eligibility or erasure state.

The candidate ClickHouse design is versioned replacement state, with the lookup
key beginning `(cohort, pubkey)` and source in the identity if retaining separate
source rows. Reads must select the latest revision explicitly before evaluating
active state, independent of background merges. A primary key does not provide
uniqueness or an atomic upsert. Retries reuse the same import/revision and bytes;
conflicting payloads under the same ID fail. Staged imports are invisible until
their complete manifest is durably acknowledged and activated. Never activate a
partially loaded cohort, truncate the serving relation, or assume a transaction
spans ClickHouse tables. Final DDL and the activation primitive need measured
implementation review, not guessed production SQL in this proposal.

ClickHouse guidance and provenance:

- **Official:** choose sort keys from actual filters; per
  `schema-pk-prioritize-filters`, verify single/bulk prefix pruning with
  [primary-key guidance](https://clickhouse.com/docs/concepts/best-practices/choosing-a-primary-key).
- **Derived:** versioned replacement plus explicit current-state reads is a
  candidate for rare corrections, not a proven latency improvement. Validate
  [ReplacingMergeTree](https://clickhouse.com/docs/guides/replacing-merge-tree)
  semantics before finalizing the engine. A dictionary adds refresh staleness;
  defer it unless measurements justify it and erasure can override it promptly.
- **Official:** per `insert-mutation-avoid-delete`, avoid frequent whole-part
  rewrites; [mutations](https://clickhouse.com/docs/concepts/best-practices/avoid-mutations)
  are asynchronous and do not prevent later inserts. This does **not** waive
  Funnelcake's required physical-erasure procedure.
- **Derived:** batch the private import (per `insert-batch-size`), avoid a
  partition per pubkey, and do not require `OPTIMIZE FINAL` for correctness
  (per `insert-optimize-avoid-final`). Exact batch sizes and query budgets must
  come from the implementation's measurements.

## Export, import and erasure

After separate operational authorization, the responsible maintainers would:

1. Approve the tenant/cohort mapping and pin deployed predicate/schema versions.
   Rehearse with synthetic data first. Export only qualifying pubkeys from one
   consistent Keycast snapshot. Private transfer carries an authenticated
   manifest/checksum and full lowercase hex pubkeys, never passwords, tokens,
   email, signup times or authorization rows. Public reports contain counts only.
2. Establish historical deletion coverage before computing the early-poster
   set. A future outbox cannot recover direct Keycast deletions that already
   happened without NIP-62. Absence from `users` cannot distinguish a never-user
   from a deleted user, and provisioning records do not cover every account.
   Identify an authorized retained deletion evidence source and reconcile its
   coverage privately. If no complete source survives, block activation pending
   an explicit maintainer decision on that gap; do not claim full deletion
   parity or infer consent to regrant from missing data.
3. Compute the early-poster set once using approved arrival evidence and tag
   forms. Keep raw evidence and cohort artifacts in approved private storage
   with access and retention recorded. Do not put them in git, CI artifacts or
   PR attachments. Preserve source overlap counts privately for reconciliation.
4. Stage and validate the union in Funnelcake; reject bad keys, unknown source
   versions, wrong tenant, altered checksums and conflicting retries. Filter
   durable erasure history on both import and serving. A load acknowledgement
   is not activation; verify persisted counts/current-state reads first.
5. Reconcile deletions after the export snapshot and before activation. Continue
   serving-time erasure checks afterward so deletion racing with insertion or a
   delayed import cannot expose an old grant.

Erasure is stronger than an import or exception. Check durable NIP-62 request
history **and** boundary tombstones, not only the pending-only
`vanished_pubkeys_set`. Proposed policy: once erased, pre-cutoff eligibility
does not return automatically if that same pubkey posts again. A new profile may
be live while this historical badge remains false. Maintainers must accept that
policy explicitly before implementation.

Add the eligibility relation to the pubkey-only vanish sweep and completion
verification, including provenance/audit subject references under their approved
retention rules. Do not compare operator import timestamps with signed vanish
boundaries to decide whether the old badge survives. This requires new unbounded
per-pubkey residue verification: the existing completion verifier accepts only
event-boundary tables, not the pubkey-only sweep list. Gate completion on that
new check so a late import cannot escape by carrying a newer operator timestamp.
Purge affected user cache
keys and every cached response embedding the value. Test compaction of request
detail into tombstones, restart, stale imports and restoration from backups.
Restored snapshots must replay subsequent erasures before serving; expire or
erase temporary exports so they cannot later recreate the cohort.

Keycast-only account deletion is a separate gap: not every deletion necessarily
arrives as NIP-62. Before cutover, cover both Funnelcake-coordinated deletion and
direct Keycast deletion. Proposed bridge: a minimal durable deletion outbox
written in the same Keycast transaction as successful deletion, delivered with
the existing authenticated service trust boundary and idempotently acknowledged
by Funnelcake. It carries only the scoped subject and deletion identifier, never
account secrets. Failures retry across restarts. Funnelcake must durably suppress
eligibility before reporting its coordinated deletion complete; direct deletion
delivery lag must be monitored and bounded. Do not add a per-profile Keycast
lookup to compensate. Implementers must confirm the existing service-auth and
deletion paths before selecting transport. This bridge is new proposed work,
not functionality supplied by #443.

Funnelcake must persist direct-deletion suppression in a separate durable,
cohort-scoped deletion ledger before acknowledging delivery, not only as a revoked
eligibility row or an expiring deletion-attempt record. It is not a fabricated
user-signed NIP-62 event and has no signed event-time boundary. Import, delta and
serving checks consult this ledger as well as NIP-62 history. The eligibility
relation remains derived state, not the deletion authority. Restore must replay
ledger entries newer than the restored snapshot before serving, even after the
sender prunes acknowledged outbox rows. Retain the minimal scoped suppression
identity for as long as any retained export, backup or late delta could regrant
it; owners must approve the precise retention and recovery policy before
activation. Sweep eligibility/provenance residue and verify it without deleting
the suppression record needed to prevent recreation.

## API and mobile contract

Add top-level `is_og_diviner` to `UserData` in singleton and existing bounded bulk
profile responses. It is independent of a Kind 0 profile and NIP-58 `badges`.
Do not change hidden-user omissions to expose eligibility or moderation state.
Successful authoritative reads return a boolean; omit the field on an
eligibility/deletion dependency error. Keep such unknown responses briefly
cacheable to preserve profile edge shielding during dependency degradation:
proposed browser and surrogate freshness is at most 5 seconds, with no stale
reuse, subject to measured implementation review. Never reuse a cached true to
fill the omitted field. Apply this error policy through middleware and edge
layers rather than allowing the normal profile cache policy to override it.
Missing means unknown/unsupported, **not false**. Do not publish provenance,
counts, enrollment dates or a roster endpoint.

Illustrative singleton payload fragment (synthetic public identifier):

```json
{
  "pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "profile": null,
  "is_og_diviner": true
}
```

Keep the full existing response shape; this fragment shows only the additive
field. Bulk uses that field on returned user objects, preserving its current
`users`/`missing` envelope and visibility behavior.

Other embeddings of `UserData`, including follower/following profile hydration,
omit the field until their cache keys, purge scope and client semantics are
explicitly covered. Search and GraphQL use explicit projections today; do not
add the field there implicitly when extending the shared storage model.

Mobile changes span the Funnelcake client, shared profile result models and the
eligibility service/provider. Preserve true/false/unknown through parsing,
including profiles not yet published and omitted/hidden bulk entries. Keep the
existing badge rendering. Unknown hides the cosmetic badge temporarily and
retries with bounded exponential backoff and jitter, coalesced per subject;
it must not cache a permanent false or trigger Keycast fallback in
migrated clients. An authoritative false overrides a previous true.

Proposed cache bound for new clients: no badge value beyond 60 seconds without
revalidation, clear on account deletion and service/environment change, and no
stale true on refresh failure. Reuse profile hydration/bulk reads rather than
one extra request for every username. Review the entire cache chain: Funnelcake
middleware overrides handler headers, the API edge is divine-router Compute,
and the current mobile eligibility map never expires. Prove effective freshness
and erasure behavior through those layers rather than inferring it from an
origin header. Browser/app TTLs and purge latency must be measured separately.

## Compatibility, rollout and rollback

1. Agree on this proposal with dcadenas and mbradley, including evidence source,
   direct-deletion bridge, retention and cache bounds. #443 stays held. No roster
   is produced merely because a design is accepted.
2. Implement Funnelcake storage, erasure, API/OpenAPI and synthetic tests in a
   main-targeting PR. Implement Keycast snapshot tooling and deletion bridge in
   a separate main-targeting PR. Neither depends on merging #443. Reserve
   operational cutover for a separately approved runbook with rehearsal evidence.
3. Under that authorization, stage/import, shadow-compare all legacy members and
   representative negatives privately, reconcile erasures, then activate the
   Funnelcake union. Differences must be explained before client cutover.
4. Ship the mobile additive parser and switch badge lookups to Funnelcake in a
   main-targeting mobile PR. Verify feed usernames, profiles and bulk lists,
   external identities, failures and account switching. No new Keycast requests
   from migrated badge paths.
5. Keep the existing Keycast URL for released older clients. Preferred temporary
   compatibility is a bounded server-side adapter to Funnelcake's authoritative
   field that returns the existing `{ "eligible": true }` shape. It preserves
   Keycast input parsing and host-to-cohort mapping, returns a retryable error on
   unknown/unavailable, and never falls back to the old account query. Unmapped
   hosts return an explicit unsupported-cohort response, not an endless retryable
   dependency error; never redirect another tenant into the approved cohort. This is
   a new scoped compatibility PR, not permission to load #443's grant table.
   Test it before directing older clients to the new cohort. Requests still
   reaching Keycast remain an acknowledged transitional availability cost.
6. Replace the legacy endpoint's one-day/seven-day stale policy with the agreed
   short bound, coordinate cache invalidation, and allow existing cached values
   to age out. Old mobile binaries also keep process-lifetime booleans: the
   migration cannot remotely guarantee erasure freshness for those sessions.
   Record that limitation and the supported-version/upgrade policy explicitly.
7. Retire the Keycast endpoint only after release/version telemetry and owners
   establish no supported client requires it. Agree an observation window and
   retirement date at rollout; do not invent one from this repository snapshot.

Rollback can disable the new badge display or return unknown while keeping
profiles available. Keep Funnelcake ownership and erasure state; do not reload
old rosters, re-enable legacy Keycast eligibility as a fallback, or roll back
deletion suppression. A previous mobile binary may require the compatibility
adapter throughout the supported rollback window. Only retire legacy account
eligibility dependencies after that window and reconciliation are complete.

## Acceptance and performance gates for implementation

| Scenario | Required evidence |
| --- | --- |
| Existing eligibility | Synthetic fixtures cover every predicate branch, nulls, late claims, token cleanup, tenant mismatch, revoked OAuth and suspended/banned accounts; private snapshot parity has zero unexplained losses; owner-approved late-completion policy and post-snapshot verification/materialization tests establish ongoing parity or explicitly accepted changes |
| Poster evidence | Strict cutoff boundary, forged old event time received late, archive exclusion, legacy/canonical client tags, opted-out/missing tags and reinserted arrival evidence are tested |
| API contract | Singleton and bulk agree for visible users; no Kind 0 required; missing/error stays unknown; hidden entries do not leak; no roster/provenance in JSON/OpenAPI |
| Import durability | Partial write, process death, ambiguous acknowledgement, duplicate/altered manifest and wrong cohort cannot activate incomplete/conflicting state; retry preserves identity/count |
| Erasure | Historical direct-deletion coverage established or its precise gap explicitly accepted before activation; delete before/during/after import, direct Keycast deletion, completed vanish, tombstone compaction, stale retry, late-completion delta, exception and disaster restore cannot regrant; durable direct-deletion ledger survives outbox pruning and restore; new pubkey-only physical-erasure verification includes new records |
| Cache/client | False replaces true; failures do not stick; unknown responses preserve bounded edge shielding without stale true; retry backoff is bounded under sustained failure; fresh/older client behavior and edge/browser/app expiration measured; new client works with Keycast unavailable |
| Operations | No real roster in logs/git/artifacts; authenticated scoped loader/bridge; alert on failed deletion delivery, failed imports, unknown lookup rate and legacy endpoint traffic |

No DDL, query benchmark or production-scale cost result is supplied here. Before
an implementation PR changes schema/SQL/read handlers, follow Funnelcake's
AGENTS.md and migration guide: inspect live table definitions/filter parity,
measure source row/byte sizes and fully materialized backfill SELECTs, wall time
and query-log peak memory, record credential caps, test failed pruning and 10x
growth, and obtain independent cost derivation. Attach per-statement time/row/
byte/memory/spill limits, verify Cloud replica acknowledgement, migration parser
comment hygiene and ClickHouse guardrails. Prefer an empty additive migration
plus a separately approved resumable backfill; do not put an unmeasured event
scan on the deploy-blocking migration path. No recurring MV means no refresh
slot is requested by this proposal.

Run affected unit/integration tests with isolated ClickHouse/Redis, Rust build,
fmt/clippy, synthetic import/erasure/restart rehearsal and mobile model/service/
widget tests. Implementation tests and production measurements remain future
gates; reviewing this document does not claim they passed.

## Next decision and ownership

Requested next step: dcadenas reviews the Funnelcake storage/arrival/deletion
contract with mbradley reviewing legacy parity and compatibility. Mobile owners
review parsing/cache behavior. Agree the proposed policies above, identify an
acceptable historical arrival source and approve an operational data-retention
plan before a detailed implementation plan or production access request.
Historical direct Keycast deletion coverage is an unresolved activation gate:
the proposed future outbox does not establish it retroactively. Owners must
identify a retained source or explicitly decide what incomplete coverage permits.
If retained arrival evidence is incomplete, report that gap and agree private
exceptions rather than manufacturing certainty from event timestamps.

The original #443 head stays unchanged and held pending that agreement. Its
author decides how to supersede it after the migration direction is accepted;
this proposal neither closes it nor requests a merge.
