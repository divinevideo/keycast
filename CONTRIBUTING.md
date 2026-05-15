# Contributing To Keycast

Status: Current
Validated against: `AGENTS.md`, `CLAUDE.md`, `package.json` scripts, `.github/`
templates and workflows, and current workspace layout on 2026-05-14.

This guide is the source of truth for outside contributors.

## Current Contribution Status

We appreciate the time and care people put into this project. Right now,
however, we are **not accepting outside implementation PRs by default** while
we tighten our contributor guidance and clarify product ownership boundaries
around OAuth, signer behavior, and tenant identity.

What this means in practice:

- A well-intentioned PR may still be closed if it lands in an area where
  product, UX, security, or sequencing is not explicitly approved.
- Large feature branches are especially likely to be closed even if they
  contain real effort and test coverage, because the review and cleanup cost is
  too high for the current team size.
- We are working toward clearer issue labels and contribution lanes. Until that
  is in place, assume implementation work needs maintainer buy-in **before**
  code is written.

If you want to help right now, the safest path is to start with issues that a
maintainer has explicitly marked as ready for outside contribution.

## Good First Contributions

These are the kinds of changes most likely to be reviewable and mergeable:

- Small bug fixes with a clear reproduction and narrow diff.
- Targeted tests that improve coverage around existing behavior — especially
  around OAuth, UCAN sessions, the NIP-46 signer, and custom permissions.
- Documentation fixes that align `docs/`, `README.md`, or `CLAUDE.md` with
  current code.
- Small refactors requested by a maintainer.
- Clearly scoped UI polish in `web/` where the intended behavior and visual
  direction are already settled.

These are **not** good first contributions unless a maintainer has explicitly
asked for them:

- New features or feature revivals from old issues, designs, or dormant PRs.
- Broad UX or information architecture changes in `web/`.
- New auth flows, token formats, session models, or changes to how UCANs are
  issued or validated.
- New storage, encryption, key-manager, or cluster coordination patterns.
- New custom permission types without a maintainer-confirmed shape.
- "I implemented the whole issue" PRs opened without prior maintainer
  confirmation.

## Before You Start

Before writing code, make sure the answer to all of these is yes:

1. A maintainer has indicated the work is wanted **now**, not just eventually.
2. The intended product behavior and security posture are already clear.
3. The change can be delivered as a small, focused PR.
4. You know which crate or layer owns the change (`api/`, `core/`, `signer/`,
   `cluster-hashring/`, `keycast/`, or `web/`).
5. You are prepared to run the relevant tests and migrations locally.

If any of those are unclear, start a discussion first instead of opening a PR.

## Templates And Agent Compliance

We enforce our repository templates and agent instructions.

Before starting work:

- Read [AGENTS.md](AGENTS.md).
- Read [CLAUDE.md](CLAUDE.md) for the architectural overview, environment
  variables, and operational context.
- If you use Codex, Claude, ChatGPT, Cursor, Copilot, or any other coding
  agent, make sure that agent has reviewed those files before it writes code,
  opens an issue, or opens a PR.

When opening issues and PRs:

- Use the appropriate GitHub issue template under
  [.github/ISSUE_TEMPLATE](.github/ISSUE_TEMPLATE) and fill it out completely.
- Follow the issue title prefixes from the templates: `fix:` for bug reports
  and `feat:` for feature requests.
- Use the PR template in [.github/pull_request_template.md](.github/pull_request_template.md).
- Use a semantic PR title that matches our checks. The repo enforces this via
  [.github/workflows/semantic_pr.yml](.github/workflows/semantic_pr.yml).

Submissions that ignore the templates, semantic formatting, or repo
instructions may be closed or sent back for correction before review starts.

## Technical Debt Standard

In the age of agentic programming, we expect a higher bar, not a lower one.
We enforce a standard of:

- No new technical debt in submitted PRs.
- Elimination of as much relevant prior technical debt as is reasonably
  possible within the scope of the change.

That means:

- Do not add TODOs, compatibility shims, temporary hacks, commented-out code,
  partial migrations, or "we'll fix this later" scaffolding unless a maintainer
  has explicitly approved a transitional step. The only acceptable TODO is
  `TODO(#issue): ...` with a tracking-issue link.
- Do not leave migrations half-applied, queries with stale `sqlx-data.json`,
  tests red, or known cleanup deferred just to get the branch over the line.
- If your change touches an area with existing debt, clean up the parts you are
  already in unless doing so would turn the PR into a different project.
- If a proposed fix would require introducing new mess to ship now and repair
  later, stop and rescope the change instead.

Using an agent is not an excuse to produce larger diffs with lower standards.
If anything, agent assistance means we expect contributors to arrive with
cleaner structure, better test coverage, stronger adherence to repo rules, and
less leftover cleanup for maintainers.

## Why PRs Get Closed

We want to be direct about this because it saves everyone time.

A PR may be closed without merge if any of the following are true:

- The work was started without maintainer alignment.
- The feature direction is still unsettled across product, security, or
  architecture.
- The branch is too large or spans too many concerns to review safely.
- The implementation solves the wrong problem, even if the code quality is
  solid.
- The branch mixes feature work with unrelated cleanup, dependency churn, or
  architecture experiments.
- The branch introduces new technical debt or avoids cleanup that should have
  been handled in the touched area.
- The change touches OAuth, signing, encryption, UCAN issuance, or
  multi-tenant identity without explicit maintainer approval.
- The change creates more review, rework, or coordination cost than the team
  can absorb right now.

Closure in those cases is usually a sequencing decision, not a judgment on
effort or intent.

## Repository Setup

Prerequisites:

- Rust toolchain pinned by `rust-toolchain.toml` (installed automatically by
  rustup).
- [Bun](https://bun.sh/) for the web frontend and the npm-style scripts in the
  root `package.json`.
- Docker (for local Postgres and Redis via `docker-compose.deps.yml`).
- `sqlx-cli` for migrations (`cargo install sqlx-cli --no-default-features --features rustls,postgres`).

Initial setup:

```bash
git clone https://github.com/<org>/keycast.git
cd keycast
bun install
bun run key:generate     # generates ./master.key for local dev
bun run deps:up          # starts Postgres + Redis containers
bun run db:reset         # creates the dev database and runs migrations
```

Optional but recommended:

```bash
bun run setup:hooks      # installs the pre-push hook (fmt + clippy + tests)
```

## Worktree-First Workflow

Start every task from a fresh branch created from `origin/main`:

```bash
git fetch origin
git worktree add .worktrees/<task-name> -b <branch-name> origin/main
```

Rules:

- Never start new work in a dirty checkout.
- Keep one task per worktree.
- Rebase onto fresh `origin/main` before every push.
- Never merge `main` into a feature branch. Always rebase.
- Never stack PRs. Every PR targets `main`.

## Where To Work

- **`api/`** — HTTP routes, request/response shapes, middleware. Keep handlers
  thin; push logic into `core/`.
- **`core/`** — Database models, encryption, key managers, UCAN/session
  handling, OAuth state, custom permissions trait. Source of truth for
  business logic.
- **`signer/`** — NIP-46 signer that handles bunker connections and routes
  requests to the right authorization.
- **`cluster-hashring/`** — Redis-backed cluster coordination (Pub/Sub +
  consistent hashing) used to balance signer ownership across instances.
- **`keycast/`** — The unified binary that runs the API and signer in a single
  process.
- **`web/`** — SvelteKit frontend.
- **`database/migrations/`** — Add new timestamped migrations here. Never edit
  shipped migrations.
- **`docs/`** — Architectural and operational notes. Start with
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md),
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/SECURITY.md](docs/SECURITY.md),
  and [CLAUDE.md](CLAUDE.md).

Trust current implementation and focused tests over stale historical docs.

## Architecture Expectations

- Keep the layering `HTTP route -> core service -> database/key manager`. Do
  not call the database directly from `api/` handlers.
- Treat encrypted secrets as untouchable outside `core/`'s key-manager
  abstractions. Do not log, serialize, or persist plaintext key material.
- Authentication is UCAN-based (Bearer token or `keycast_session` cookie). Do
  not introduce parallel auth schemes; extend the UCAN path instead.
- OAuth authorizations are multi-device: each approval creates a new
  authorization row, and revocation is soft-delete via `revoked_at`. Preserve
  that contract.
- New custom permissions implement `CustomPermission` (`core/src/traits.rs`)
  and must be registered in three places (see [CLAUDE.md](CLAUDE.md) for the
  full checklist).
- Reuse existing SvelteKit components and stores in `web/src/lib/` rather than
  introducing parallel patterns.

## Product, Security, And Design Boundaries

Do not assume that an old issue, mockup, comment thread, or dormant branch is
enough authorization to implement a feature. For contribution purposes, the
source of truth is current maintainer direction.

If the change affects any of the following, get explicit maintainer
confirmation first:

- OAuth flow shape, scope semantics, or token issuance.
- UCAN issuance, session cookie handling, or `SERVER_NSEC` usage.
- Encryption, key managers, or master key handling.
- NIP-46 signer connection lifecycle, relay configuration, or request routing.
- Cluster coordination behavior in `cluster-hashring/`.
- New storage models, table additions, or migrations beyond a single column
  change.
- New custom permission types.
- Multi-tenant identity behavior (NIP-05, profile, `/.well-known/nostr.json`).
- UI flows that need design fidelity rather than engineering approximation.

If direction is unresolved, stop and ask first. Do not fill in the blanks
yourself and hope review will sort it out later.

## Day-To-Day Commands

Local dev (API + signer + web concurrently):

```bash
bun run dev          # http://localhost:3000 (API + signer)
bun run dev:web      # https://localhost:5173 (web frontend)
```

Build:

```bash
bun run build        # cargo build --release --bin keycast
bun run build:web    # SvelteKit production build into web/build/
```

Database:

```bash
bun run db:reset     # drop, recreate, and migrate the dev database
bun run db:migrate   # apply new migrations
```

Logs from production Cloud Run:

```bash
bun run logs         # recent logs
bun run logs:watch   # streaming
```

## Testing Expectations

Start with the smallest relevant verification, then broaden when the diff is
cross-cutting.

Core checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated
cargo test --workspace --verbose
```

Combined gate (matches what the pre-push hook runs):

```bash
bun run check
```

Full test suite with Postgres + Redis brought up via Docker (matches
`bun run test:ci`):

```bash
bun run test
```

Targeted examples:

```bash
cd api && cargo test --test oauth_integration_test
cd api && cargo test --test oauth_unit_test
```

Additional expectations:

- Add or update tests next to the changed crate or feature.
- Do not push red tests "to see what CI says."
- For `web/` changes, manually verify the affected path in the browser and
  document the manual checks in the PR.
- When touching OAuth, UCAN/session behavior, NIP-05/profile behavior, signer
  flows, encryption, or cluster coordination, run the most relevant targeted
  tests and document which ones were used.

## Scope Discipline

Keep PRs focused and reviewable.

Do:

- Change only what is required for the agreed task.
- Stage only task-related files.
- Keep dependency changes justified and narrow.
- Split truly independent work into separate PRs targeting `main`.

Do not:

- Mix feature work with unrelated cleanup or version bumps.
- Add speculative architecture while solving a smaller problem.
- Land partial work with TODOs instead of finishing or scoping down.
- Introduce new technical debt with the expectation that maintainers will clean
  it up later.
- Leave the branch dirty at handoff.

## Pull Requests

Requirements:

- Use a Conventional Commit PR title such as
  `feat(api): add per-app revocation endpoint` or
  `fix(signer): drop stale relay subscriptions on reconnect`.
- Make sure the PR title is semantic when the PR is opened. Editing the title
  later does not reliably retrigger the semantic check.
- Target `main`.
- Fill out [.github/pull_request_template.md](.github/pull_request_template.md)
  completely, including summary, motivation, related issue, testing checklist,
  and visuals section.
- Include a clear description of what changed, what is out of scope, and how
  you verified it. For changes that touch OAuth, signing, encryption, UCAN, or
  multi-tenant identity, call that out explicitly.
- End with a clean `git status`.
- Rebase on `origin/main` before pushing.

Before opening a PR, ask yourself:

1. Is this branch small enough for a maintainer to review without
   reconstructing product intent?
2. Does it stay inside a clearly approved scope?
3. Did I avoid mixing in unrelated files or concerns?
4. Did I run the relevant tests locally?
5. Did I avoid naming corporate partners, customers, or sensitive external
   brands in the title, branch name, screenshots, or description?

If the answer to any of those is no, the PR is not ready yet.

## Secrets And Sensitive Data

- Never commit secrets, real credentials, master keys, production `.env`
  files, or live `SERVER_NSEC` values.
- The dev `SERVER_NSEC` and `ALLOWED_PUBKEYS` values in `package.json` scripts
  are intentionally non-secret development values; do not reuse them for any
  deployed environment.
- Never truncate Nostr pubkeys, event IDs, or signatures in logs, tests, or
  analytics output. Use full values and let UI handle overflow visually.
- Do not include user-identifying or tenant-identifying data in test fixtures
  unless the test specifically requires it.

## Documentation Rules

- Current architectural and operational docs belong in `docs/` (or `CLAUDE.md`
  when the audience is coding agents).
- Historical plans and completed investigations should be preserved under
  `docs/archive/` or clearly marked historical, not silently deleted.
- Before adding a new top-level doc, check whether the content fits inside an
  existing doc instead. New docs should have a clear audience and a stated
  status (Current vs. Historical) at the top.
