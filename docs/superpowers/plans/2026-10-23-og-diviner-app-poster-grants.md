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

- [x] **Step 1:** Add `granted_app_posters_qualify_per_tenant` asserting: granted pubkey with no users row → true; granted pubkey whose users row is post-cutoff (otherwise ineligible) → true; ungranted pubkey with no row → false; tenant-A grant queried in a second test tenant → false. Add route case `reports_true_for_a_granted_pubkey_without_an_account`.
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
