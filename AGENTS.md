# Repository Guidelines

## Divine Context And Brain

Before broad product, architecture, protocol, cross-repo, or service-boundary work, read the shared Divine context primer.

Use `DIVINE_CONTEXT_ROOT` if set; otherwise look for `../divine-context`. If it is missing, try:

`gh repo clone divinevideo/divine-context ../divine-context`

The `divine-context` repo is private, so cloning requires GitHub access. If clone, network, or auth fails, continue from the local repo docs and avoid cross-repo assumptions.

Before updating an existing context checkout, verify it is clean and on its default branch. If it is clean and on the default branch, update it with `git -C <context-dir> pull --ff-only`. If it is dirty, on another branch, cannot fast-forward, or network/auth fails, leave it untouched and say the context may be stale.

Read `<context-dir>/AGENT_CONTEXT.md` and follow its instructions. If unavailable, continue from the local repo docs and avoid cross-repo assumptions.

If a Divine Brain search or ask tool is available, you may use it for company memory. Treat it as optional and credentialed: tool names vary by client, and work must continue when Brain is unavailable. When Brain results influence work, cite the returned document ids. Never commit Brain credentials or expose Brain-derived sensitive content in public PRs, issues, branch names, commit messages, code comments, logs, screenshots, release notes, or externally shared agent transcripts.

## Repo Shape And Source Of Truth

- This is a Rust workspace plus a SvelteKit frontend. The unified server binary is `keycast/src/main.rs`; HTTP routes live in `api/`, shared business logic in `core/`, the NIP-46 signer in `signer/`, and Redis-backed cluster coordination in `cluster-hashring/`.
- The web app lives in `web/` and uses SvelteKit with Bun for package management.
- Database migrations live in `database/migrations/`. End-to-end and integration coverage lives in `e2e/` and `tests/`.
- Operational and design notes live in `docs/` (start with `ARCHITECTURE.md`, `DEVELOPMENT.md`, `DEPLOYMENT.md`, `SECURITY.md`, and the OAuth/signer-specific guides). `CLAUDE.md` is also kept current and is the fastest orientation read.
- Older docs can drift. If documentation conflicts, trust the current implementation, targeted tests, and the newest focused doc over historical notes.

## Worktree-First Task Workflow

- Start every new task in a **new worktree branched from `origin/main`** — never from local `main` (often stale), never from another branch or worktree.
- Fetch first, then create the worktree:
  - `git fetch origin`
  - `git worktree add .worktrees/<task-name> -b <branch-name> origin/main`
- Keep one task per worktree. Do not mix unrelated fixes, reviews, or experiments in the same tree.
- If the current checkout is dirty, do not start new work there. Commit it, stash it intentionally, or discard it intentionally first.
- **Rebase onto fresh `origin/main` before every push**, even on a branch you've already pushed:
  - `git fetch origin && git rebase origin/main`
  - `git push --force-with-lease` (never `--force` without `--lease`)
- Never merge `main` into a feature branch — always rebase.

## PR Guardrails

- Every PR title must use Conventional Commit format: `type(scope): summary` or `docs: summary` for docs-only PRs. The semantic PR check (`.github/workflows/semantic_pr.yml`) enforces this.
- Set the semantic title when creating the PR. Do not rely on editing it afterward; if you must, verify the semantic check reruns successfully.
- **Every PR targets `main`. Never stack PRs.** When features are interdependent, ship them as **one combined PR** with clearly delineated commits and a description that calls out each feature separately. Never `gh pr create --base <other-branch>`.
- A task is not complete if the intended changes are still uncommitted.
- Stage only the files that belong to the task. Avoid broad staging when the worktree contains unrelated changes.
- End each task with a clean `git status` except for changes that are explicitly still in progress and clearly called out.
- Open a pull request once the change is ready for review. Do not leave finished work sitting only in a local branch or worktree.
- Use `.github/pull_request_template.md` and fill out summary, motivation, related issue, testing, and visuals sections.
- For `web/` or other UI-facing changes, attach screenshots/video or explicitly state that there is no visual change.
- Do not name corporate partners, customers, brands, or campaign names in public issue titles, PR titles, branch names, screenshots, or descriptions unless a maintainer explicitly approves it. Use generic descriptors such as "partner account", "creator page", or "external partner".

## No Technical Debt, No Failing Tests

- Do not accumulate technical debt. Fix issues in the PR that touches them; do not defer with TODOs, follow-up issues, skipped tests, or commented-out code. The only acceptable TODO is a transitional-code TODO with a tracking-issue link: `TODO(#issue): ...`.
- **`origin/main` always passes.** Any failing test on a feature branch is caused by that branch's diff. Never claim flakiness, never `#[ignore]` to silence a failure, never push red "to see what CI says." Run the affected targeted tests plus `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated` before every push.
- Do not continue speculative feature work after exploratory implementation if maintainer alignment on scope or UX is still missing.

## Architecture And Layering

- HTTP handlers in `api/` should stay thin. Push business logic into `core/` so it stays testable and reusable from the signer, the HTTP RPC path, and tests.
- Treat `core/` as the source of truth for database models, encryption, UCAN/session handling, OAuth state, and the custom permissions trait.
- Encrypted secrets (stored keys, OAuth keypairs, master key material) only ever leave `core/`'s key-manager abstractions when actively in use. Do not log, serialize, or persist plaintext key material.
- New custom permissions implement `CustomPermission` (`core/src/traits.rs`) and must be registered in both `core/src/custom_permissions/mod.rs` (`AVAILABLE_PERMISSIONS`), `core/src/types/permission.rs` (`to_custom_permission()`), and `web/src/lib/types.ts` (`AVAILABLE_PERMISSIONS`).
- The signer routes incoming NIP-46 requests by recipient pubkey; preserve that contract when adding handlers and avoid global state that conflates authorizations.
- Keep frontend changes aligned with the existing SvelteKit/Bun setup. Reuse existing components and stores rather than adding parallel patterns.

## OAuth, Signing, And Identity Rules

- Treat OAuth client configuration, session handling, UCAN issuance, relay configuration, and production identity settings as sensitive operational context. Call out changes that affect them explicitly in the PR body.
- Authentication uses UCAN tokens (Bearer or `keycast_session` cookie). Do not introduce parallel auth schemes; extend the UCAN path instead.
- OAuth authorizations support multi-device — each approval creates a new authorization and revocation is soft-delete via `revoked_at`. Preserve that semantic when touching authorization lifecycle code.
- Server-side keys are encrypted at rest with the configured `KMS_PROVIDER` (`file`, `gcp`, or `aws`). Do not bypass `core/`'s key-manager abstractions.
- Never truncate Nostr pubkeys, event IDs, or signatures in logs, error messages, analytics, or test fixtures. Use full values and let UI handle overflow.

## Verification

Run the smallest relevant verification first, then broaden if the change is cross-cutting.

- Format and lint:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated`
- Rust tests:
  - `cargo test --workspace --verbose` for a quick pass.
  - `bun run test` to spin up Postgres + Redis via `docker-compose.deps.yml`, set up the test database, and run the full workspace + integration-feature test suite (matches what CI runs via `bun run test:ci`).
  - Targeted test commands (e.g. `cd api && cargo test --test oauth_integration_test`) when a change is scoped to a single crate or path. Record that scope in the PR.
- Combined gate: `bun run check` runs fmt, clippy, and `cargo test --workspace` together.
- Optional pre-push parity with CI: `bun run setup:hooks` installs `scripts/hooks/pre-push`.
- For `web/` changes, manually verify the affected path in the browser and document the manual checks in the PR.

When touching OAuth, auth/session behavior, NIP-05/profile behavior, signer flows, encryption, or cluster coordination, run the most relevant targeted tests and document which ones were used.

## Database And Migrations

- New schema changes live in `database/migrations/` as a new timestamped migration. Do not edit shipped migrations.
- Use SQLx for queries so compile-time verification stays meaningful. If you change a query, regenerate `sqlx-data.json` (where applicable) and commit it with the source change.
- Locally, `bun run db:reset` recreates the dev database; `bun run db:migrate` applies new migrations. Production migrations are run via `tools/run-migrations.sh` from the deploy pipeline.

## Secrets, Local Stack, And Deployment

- Do not commit secrets, real credentials, master keys, or production `.env` files. The dev master key is generated locally via `bun run key:generate`.
- Local development uses `docker-compose.deps.yml` for Postgres and Redis. The dev `SERVER_NSEC` and `ALLOWED_PUBKEYS` values in `package.json` scripts are intentionally non-secret development values; do not reuse them for any deployed environment.
- Production runs on Google Cloud Run as service `keycast` (us-central1) with `min-instances=3` so the NIP-46 signer stays connected. Be careful with changes that affect startup, signer connection lifecycle, or Redis/cluster coordination — those have outsized blast radius.
- Deploys are gated behind `bun run deploy` (Cloud Build). Do not deploy on someone else's behalf without explicit confirmation.

## Clean Workspace Expectations

- Do not leave untracked or modified files around after a task unless they are part of the intentional diff.
- Delete temporary debugging artifacts (scratch scripts, throwaway logs, ad-hoc fixtures) before commit.
- If a generated file must be committed, make sure it is reproducible and relevant to the change.
- Before opening the PR, review the diff and remove stray edits, generated junk, logs, scratch files, and half-finished experiments.
- After opening or updating a PR, inspect GitHub checks and rerun stale semantic jobs if needed.
- After a branch is merged or abandoned, prune the worktree and branch so stale task state does not accumulate.
