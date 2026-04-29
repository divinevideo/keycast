# Repository Guidelines

## Project Structure & Module Organization
- This repo is a Rust workspace with core crates under `api/`, `core/`, `signer/`, `cluster-hashring/`, and the unified binary under `keycast/`.
- Web assets live under `web/` and use SvelteKit with Bun-based workflows.
- Database migrations live under `database/migrations/`.
- End-to-end and integration coverage lives in `e2e/` and `tests/`.
- Operational and design notes live in `docs/`.

## Build, Test, and Development Commands
- `bun run dev`: run the unified binary locally with hot reload.
- `bun run dev:web`: run the web frontend locally.
- `cargo test --workspace --verbose`: run workspace Rust tests.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated`: match CI lint expectations.
- `cargo fmt --all -- --check`: verify formatting before review.
- Use targeted test commands when a change is scoped to one crate or one e2e path, but record that scope clearly in the PR.

## Coding Style & Naming Conventions
- Keep Rust changes idiomatic and formatted with `rustfmt`.
- Keep frontend changes aligned with the current SvelteKit/Bun setup rather than introducing new tooling casually.
- Prefer small, task-scoped changes over wide refactors.

## Commit & Pull Request Guidelines
- PR titles must use Conventional Commit format: `type(scope): summary` or `type: summary`.
- Set the correct PR title when opening the PR instead of relying on title edits afterward.
- If a PR title must be fixed after opening, verify that the semantic PR title check reruns successfully.
- Keep PRs tightly scoped to the task. Do not include unrelated formatting churn, lockfile noise, drive-by refactors, or incidental cleanup.
- Temporary or transitional code must include `TODO(#issue):` with a tracking issue for later removal.
- PR descriptions should include a concise summary, motivation, linked issue, and manual test plan.
- For `web/` or other UI-facing changes, include screenshots/video in the PR or explicitly state that there is no visual change.
- Do not mention corporate partners, customers, brands, campaign names, or other sensitive external identities in public issue titles, PR titles, branch names, screenshots, or descriptions unless a maintainer explicitly approves it. Use generic descriptors instead, such as "partner account", "creator page", or "external partner".
- Do not continue speculative feature work after exploratory implementation if maintainer alignment on scope or UX is still missing.

## Testing Expectations
- Run `cargo test --workspace --verbose`, `cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated`, and `cargo fmt --all -- --check` before requesting review.
- When touching OAuth, auth/session behavior, NIP-05 behavior, or signer flows, run the most relevant targeted tests and document which ones were used.
- When changing `web/` behavior, manually verify the affected path and document the manual checks in the PR.

## Security & Deployment Notes
- Do not commit secrets or real credentials.
- Treat OAuth client configuration, session handling, relay configuration, and production identity settings as sensitive operational context.
- Be careful with changes that affect signing, token issuance, encryption, or multi-tenant identity semantics; call those out explicitly in the PR body.
