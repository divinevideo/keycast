# OG Diviner grants for early app posters — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator grant the OG Diviner chit to a closed, privately computed list of pubkeys that posted through a Divine app before the cutoff but have no Keycast signup record.

**Architecture:** A tenant-scoped `og_diviner_grants` table holds granted pubkeys with a constrained evidence label. `UserRepository::is_og_diviner` ORs a grant lookup beside its existing `users` lookup in the same statement. A thin cargo example reads a roster file, and core does the validation, counting, and idempotent insert.

**Tech Stack:** Rust, sqlx (Postgres), tokio tests behind the `integration-tests` feature.

**Spec:** divinevideo/keycast#440. Prior decisions from #416: tenant scoping, strict `<` cutoff, eligibility is historical (survives suspension or ban), the roster is never public.

## Global Constraints

- Worktree `.worktrees/og-diviner-app-poster-grants`, branch `feat/og-diviner-app-poster-grants`, based on `origin/main` `fe9c646`.
- Push nothing, open no PR, comment nowhere. Local commits only, no `Co-Authored-By`.
- No real pubkeys anywhere. Fixtures use synthetic prefixes `06d2` (eligibility) and `06d3` (loader).
- The loader prints counts and line numbers only. It never prints a pubkey, a line's contents, or the file path.
- Evidence label vocabulary: `pre_cutoff_app_post` only.
- An empty grants table leaves every existing answer unchanged.
- Before every commit: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated`.

## Review Focus

- A granted pubkey with **no `users` row at all** must be eligible. This is most of the cohort, and a branch placed inside the existing `FROM users` lookup would never fire for it.
- A grant in tenant A must not make the same pubkey eligible in tenant B.
- One bad line in the roster must abort the whole load with zero rows written.
- Running the same roster twice must insert nothing the second time and report the rows as already granted.
- Uppercase hex, npub, 63/65-char, and BOM-prefixed lines are rejected, not normalised.
- Deleting an account must remove its grant, including for a grantee Keycast never held an account for. Excluding deleted accounts is one of #440's criteria, and before this change deleting the `users` row ended eligibility.

---

### Task 1: Grants table and eligibility branch

**Files:**
- Create: `database/migrations/20261023120000_add_og_diviner_grants.sql`
- Modify: `core/src/repositories/user.rs` (`is_og_diviner` query and doc comment)
- Test: `core/tests/og_diviner_eligibility_test.rs` (new test fn), `api/tests/og_diviner_route_test.rs` (new case)

**Interfaces:**
- Produces: table `og_diviner_grants (tenant_id BIGINT FK tenants ON DELETE CASCADE, pubkey TEXT CHECK ^[0-9a-f]{64}$, evidence TEXT CHECK IN ('pre_cutoff_app_post'), created_at TIMESTAMPTZ DEFAULT NOW(), PK (tenant_id, pubkey))`. `is_og_diviner` signature unchanged.

- [x] **Step 1:** Add `granted_app_posters_qualify_per_tenant` asserting: granted pubkey with no users row → true; granted pubkey whose users row is post-cutoff (otherwise ineligible) → true; ungranted pubkey with no row → false; tenant-A grant queried in a second test tenant → false. Add route case `reports_true_for_a_granted_pubkey_with_no_account`.
- [x] **Step 2:** Run both; expect failure (relation `og_diviner_grants` does not exist).
- [x] **Step 3:** Write the migration; wrap the query as `SELECT EXISTS (grant lookup) OR EXISTS (existing users lookup)`; document that grants are pre-adjudicated against the cutoff when the roster is built.
- [x] **Step 4:** Run the eligibility and route tests, including the unchanged #416 test; expect pass.
- [x] **Step 5:** Commit.

### Task 2: Roster parsing and idempotent load

**Files:**
- Create: `core/src/repositories/og_diviner_grant.rs`; register in `core/src/repositories/mod.rs`
- Test: unit tests in that module; `core/tests/og_diviner_grant_loader_test.rs`

**Interfaces:**
- Produces: `enum OgDivinerGrantEvidence { PreCutoffAppPost }` with `as_str()` and `FromStr`; `fn parse_grant_roster(input: &str) -> Result<GrantRoster, GrantRosterError>`; `GrantRoster { entries: usize, pubkeys: Vec<String> /* unique, input order */ }` with `duplicates()`; `GrantRosterError::{InvalidLines { count, first: Vec<usize> }, Empty}` whose `Display` holds line numbers only; `OgDivinerGrantRepository::new(pool)` and `load(tenant_id, evidence, &GrantRoster, apply: bool) -> Result<GrantLoadReport, RepositoryError>`; `GrantLoadReport { unique, newly_granted, already_granted, applied }`; unknown tenant → `RepositoryError::NotFound`.

- [x] **Step 1:** Unit tests: blank lines and surrounding whitespace/CRLF skipped; duplicates collapsed and counted; uppercase, npub, wrong length, non-hex, BOM rejected with their line numbers; error `Display` contains no line content; empty input → `Empty`. Integration: apply twice (second run `newly_granted == 0`, `already_granted == unique`); dry run writes nothing but reports what would be new; unknown tenant errors without writing.
- [x] **Step 2:** Run; expect compile failure.
- [x] **Step 3:** Implement. Apply is a single `INSERT ... SELECT unnest($2::text[]) ON CONFLICT DO NOTHING`; dry run is a read-only count of existing grants.
- [x] **Step 4:** Run; expect pass.
- [x] **Step 5:** Commit.

### Task 3: Operator loader

**Files:**
- Create: `core/examples/load-og-diviner-grants.rs` (follows `core/examples/migrate-vine-users.rs`)

- [x] **Step 1:** CLI: `DATABASE_URL=... cargo run -p keycast_core --example load-og-diviner-grants -- --tenant-id <id> --evidence pre_cutoff_app_post [--apply] <roster-file>`. Dry run by default, matching the precedent. Prints counts only.
- [x] **Step 2:** Run it against the local test database with a synthetic roster: dry run, apply, apply again, a bad file. Confirm the output carries no pubkeys.
- [x] **Step 3:** Commit.

### Task 4: Grants do not outlive account deletion (added after review)

**Files:**
- Modify: `core/src/repositories/user.rs` (`delete_account_in_tx`)
- Test: `core/tests/og_diviner_eligibility_test.rs`, `api/tests/service_account_deletion_test.rs`

The account-deletion coordinator calls service deletion for every account deleted in the Divine app, including people who manage their own key, and Keycast answers `already_absent` for anyone it never held an account for. The grant delete therefore runs before the ownership check, so it also covers grantees with no `users` row. It is tenant-scoped, so the cross-tenant risk the ownership check guards against does not apply.

- [x] **Step 1:** Tests: a granted pubkey with an account is deleted and is no longer eligible; a granted pubkey with no account goes through service deletion, gets `already_absent`, and its grant is gone once the commit lands; a grant for the same pubkey in another tenant survives.
- [x] **Step 2:** Delete the grant in `delete_account_in_tx`, ahead of the ownership check.
- [x] **Step 3:** Commit.

### Task 5: Never grant a pubkey whose deletion is recorded (added after review)

**Files:**
- Modify: `core/src/repositories/og_diviner_grant.rs` (`load`, `GrantLoadReport`), `core/src/groups/service.rs` (`lock_og_diviner_grants_shared`/`_exclusive`), `core/src/repositories/user.rs` (`delete_account_in_tx`), `core/examples/load-og-diviner-grants.rs`
- Test: `core/tests/og_diviner_grant_loader_test.rs`; `lock_tests` in `core/src/repositories/og_diviner_grant.rs`

A load could grant someone who had already deleted their account, and nothing would remove that grant, since the coordinator never calls Keycast again for a completed deletion. The load now excludes roster pubkeys with a `service_account_deletions` row in the tenant and revokes a grant such a pubkey already holds. One tenant-scoped advisory lock, taken shared by account deletion (after its group-account lock) and exclusive by the load (its only lock), keeps a deletion and a load running together from each missing the other's uncommitted rows. A dry run takes no lock. While a load runs, account deletions in that tenant wait for it. Deletion records can be compacted 30 days after the deletion, so the roster is built right before it is loaded.

- [x] **Step 1:** Tests: a recorded deletion excludes the pubkey in the dry run and the apply with matching counts and no row written; a deletion in another tenant does not exclude it; a load revokes an existing grant whose pubkey has a recorded deletion; both race orders through the real deletion path: a deletion held open makes the load wait and the load then excludes the pubkey, and a load holding the lock makes the deletion wait and the deletion then removes the grant. Mutation-check the exclusion, its tenant filters, the sweep, and each side of the lock.
- [x] **Step 2:** Exclude, sweep and count in one locked transaction; report `excluded_deleted` and `revoked_deleted`; take the shared lock in `delete_account_in_tx`. One tenant lock rather than one per pubkey, so a large roster cannot exhaust Postgres's server-wide lock table.
- [x] **Step 3:** Commit.

### Task 6: Compaction honours the grant lock (added after review)

**Files:**
- Modify: `core/src/repositories/service_account_deletion.rs` (`compact`), lock and load comments, `docs/DEPLOYMENT.md`, `docs/SERVICE_ACCOUNT_DELETION.md`
- Test: `lock_tests` in `core/src/repositories/og_diviner_grant.rs`

Retention compaction deleted a deletion record under only its per-request lock, so it could land between the load's statements. The load then counted that pubkey as already granted and could skip revoking its grant. Compaction now takes the grant lock shared, after its deletion lock. The runbook also says the roster builder must still drop NIP-62-vanished pubkeys, because Keycast's records miss compacted deletions and self-deletions through `DELETE /api/user/account`.

- [x] **Step 1:** Test: a load holding the exclusive lock makes compaction wait, and compaction then completes. Seen red before the fix.
- [x] **Step 2:** Take `lock_og_diviner_grants_shared` in `compact`.
- [x] **Step 3:** Commit.

### Task 7: Bound the load's lock and name its database (added after review)

**Files:**
- Modify: `core/src/repositories/og_diviner_grant.rs` (`load`), `core/src/groups/service.rs` (lock doc), `core/examples/load-og-diviner-grants.rs`, `docs/DEPLOYMENT.md`
- Test: `core/tests/og_diviner_grant_loader_test.rs`

Nothing limited how long an applied load could hold, or wait for, the exclusive lock, and while it does every account deletion in the tenant waits; an operator's stalled session would block them indefinitely. The load now sets transaction-local lock, statement and idle-in-transaction timeouts, and sends the roster once, in a single statement whose parts share one snapshot. It pins READ COMMITTED, because a REPEATABLE READ default would take its snapshot before the lock wait and miss deletions committed during it. The loader names its session and prints the database, user and server address, since tenant 1 is `login.divine.video` in every database.

- [x] **Step 1:** Tests: a load facing a deletion that never commits gives up on its own and writes nothing; a load on a connection whose default isolation is REPEATABLE READ still excludes a deletion that commits while it waits. Both seen red first. Mutation-check the isolation pin, the lock timeout, the exclusion, its tenant filter and the revoke.
- [x] **Step 2:** Implement; check by hand that the idle timeout ends a stalled session and frees the lock.
- [x] **Step 3:** Commit.

### Task 8: Drop the grant lock (added after review)

**Files:**
- Modify: `core/src/repositories/og_diviner_grant.rs` (`load`), `core/src/groups/service.rs`, `core/src/repositories/service_account_deletion.rs` (`compact`), `core/src/repositories/user.rs` (`delete_account_in_tx`), `docs/DEPLOYMENT.md`, `docs/SERVICE_ACCOUNT_DELETION.md`
- Test: `core/tests/og_diviner_grant_loader_test.rs`

Tasks 5 to 7 kept a one-time load and account deletion from missing each other with a tenant lock, then bounded that lock with timeouts and an isolation pin. That put every account deletion behind a job that runs once, which is a worse failure than the one it prevented: a grant left on an account deleted during the few seconds a load writes. The lock, its timeouts, the isolation pin and the compaction lock are gone. The runbook instead has the operator run the dry run straight after the load and apply once more if it shows anything under `would revoke`; the existing revoke step removes those grants. Account deletion still removes the grant. The dry run now shares the load's definition of "deleted" as one set it joins against; a per-row EXISTS in each count scanned the deletion records once per roster row per count and took minutes on a full-size roster.

- [x] **Step 1:** Remove the lock, its callers, its tests and the stall runbook.
- [x] **Step 2:** Rewrite the dry run as a join against the deleted set.
- [x] **Step 3:** Commit.

### Task 9: Pin the revoke's tenant scope and duplicate deletion records (added after review)

**Files:**
- Test: `core/tests/og_diviner_grant_loader_test.rs`
- Modify: `docs/DEPLOYMENT.md`, `core/src/repositories/user.rs` (doc wrap)

No test failed if the load's revoke lost its tenant filter, which would delete other tenants' grants. Nothing covered a pubkey with two deletion records, which a refactor of `deleted` into a join would double-count. The runbook's post-load re-check, which re-applied the roster, is replaced by a cleanup that only revokes: re-applying could re-grant an account whose grant a self-deletion had removed without leaving a record. It runs straight after the load and again the next day, and the runbook says it cannot see a self-deletion that raced the load.

- [x] **Step 1:** Tests: a load revokes only its own tenant's grant; two deletion records for one pubkey count it once in the dry run and the apply. Mutation-check the revoke's tenant filter.
- [x] **Step 2:** Docs.
- [x] **Step 3:** Commit.
