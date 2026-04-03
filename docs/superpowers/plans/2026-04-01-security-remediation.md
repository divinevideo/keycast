# Red Team Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reproduce, contain, and remediate the confirmed red-team findings across OAuth HTML injection, tenant isolation, DPoP token binding, OAuth client admission, operational email safety, and dependency exposure.

**Architecture:** Ship this in risk order as six independent chunks. Each chunk starts by turning the finding into an automated regression test, then lands the smallest code/config change that closes the bug, then reruns the targeted regressions plus the relevant audits. Tenant fixes are staged as immediate route/repository containment first; deeper schema hardening is documented as a follow-up once the live exploit paths are closed.

**Tech Stack:** Rust/Axum/SQLx/PostgreSQL backend, SvelteKit frontend, Playwright e2e tests, UCAN/DPoP/OAuth, `cargo audit`, `npm audit`.

---

## File Map

- `api/src/api/http/oauth.rs`
  OAuth authorize/login/register/connect HTML rendering, token exchange, DPoP-bound token issuance.
- `api/src/api/http/auth.rs`
  Session auth helpers, bunker creation, key export, account deletion, password verification.
- `api/src/api/http/atproto_oauth.rs`
  Entryway metadata, pushed auth requests, DPoP proof parsing.
- `api/src/api/http/nostr_rpc.rs`
  Bearer-token RPC surface and on-demand handler loading.
- `api/src/api/extractors.rs`
  Shared UCAN bearer/cookie extractor used by authenticated routes.
- `api/src/api/tenant.rs`
  Host-header to tenant resolution and auto-provisioning behavior.
- `api/src/ucan_auth/mod.rs`
  Shared UCAN auth exports.
- `api/src/ucan_auth/validation.rs`
  UCAN signature validation, tenant enforcement, issuer checks.
- `core/src/repositories/oauth_authorization.rs`
  OAuth authorization lookups, including bunker-public-key lookup.
- `core/src/repositories/personal_keys.rs`
  Personal-key lookup helpers; currently contains both tenantless and tenant-scoped methods.
- `core/src/repositories/registered_client.rs`
  OAuth client redirect validation policy.
- `keycast/src/main.rs`
  Runtime env validation and CORS/bootstrap configuration.
- `api/src/email_service.rs`
  Production/dev email sender selection and token-bearing email links.
- `e2e/helpers/oauth.ts`
  Playwright helpers for authorize/exchange flows; extend for DPoP and malicious payload tests.
- `e2e/tests/oauth.spec.ts`
  Browser coverage for OAuth authorize/connect/token behavior.
- `e2e/tests/sessions.spec.ts`
  Session and bunker lifecycle coverage.
- `e2e/tests/auth.spec.ts`
  Email/password auth regressions and startup-sensitive behavior.
- `web/package.json`
  Svelte/Vite dependency versions driving the current npm audit output.
- `web/src/routes/docs/+page.svelte`
  Swagger UI settings, including persisted browser authorization.
- `.env.example`
  Local/deployment env defaults and security expectations.
- `docs/DEPLOYMENT.md`
  Production bootstrap/runbook; update every new required security env here.
- `cloudbuild.yaml`
  Production deployment env wiring.

## Chunk 1: OAuth HTML Injection

### Task 1: Add Regression Coverage and Escape Every OAuth HTML Sink

**Files:**
- Create: `api/src/api/http/html_safety.rs`
- Modify: `api/src/api/http/mod.rs`
- Modify: `api/src/api/http/oauth.rs`
- Modify: `api/src/api/http/claim.rs`
- Modify: `e2e/tests/oauth.spec.ts`
- Test: `e2e/tests/oauth.spec.ts`
- Test: `api/src/api/http/oauth.rs`

- [ ] **Step 1: Write the failing browser regressions**

Add Playwright coverage in `e2e/tests/oauth.spec.ts` for malicious query parameters and connect values:

```ts
test("authorize page escapes client-controlled query values", async ({ page }) => {
  const payload = `x');window.__oauthXss=1;//`;
  const url = `/api/oauth/authorize?client_id=${encodeURIComponent(payload)}&redirect_uri=${encodeURIComponent("http://localhost:3456/callback.html")}&scope=${encodeURIComponent("policy:full")}`;

  await page.goto(url);

  expect(await page.evaluate(() => (window as any).__oauthXss)).toBeUndefined();
  await expect(page.locator("body")).toContainText(payload);
});

test("connect page escapes hidden input values", async ({ page }) => {
  const payload = `" autofocus onfocus="window.__connectXss=1`;
  const url = `/api/connect/nostrconnect://foo?client_pubkey=${encodeURIComponent("0".repeat(64))}&relay=${encodeURIComponent(payload)}&secret=${encodeURIComponent(payload)}&perms=${encodeURIComponent(payload)}`;

  await page.goto(url);

  expect(await page.evaluate(() => (window as any).__connectXss)).toBeUndefined();
});
```

- [ ] **Step 2: Run the focused e2e test and verify it fails**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "escapes"
```

Expected: FAIL because `oauth.rs` currently interpolates raw values into HTML, JS string literals, and hidden inputs.

- [ ] **Step 3: Introduce shared HTML/attribute/JS escaping and refactor the renderers**

Create `api/src/api/http/html_safety.rs` with a single responsibility:

```rust
pub fn escape_html(value: &str) -> String { /* &, <, >, ", ' */ }

pub fn escape_attr(value: &str) -> String {
    escape_html(value)
}

pub fn js_string_literal<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serializable JS literal")
}
```

Then refactor every HTML renderer in `api/src/api/http/oauth.rs` to:

```rust
let safe_client_name = escape_html(&params.client_id);
let js_client_id = js_string_literal(&params.client_id);
let js_redirect_uri = js_string_literal(&params.redirect_uri);
let safe_secret = escape_attr(&secret);
```

Use the shared helper in `claim.rs` too so the repo has one escaping implementation.

- [ ] **Step 4: Re-run the targeted tests plus existing OAuth unit coverage**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "escapes"
cargo test -p keycast_api --lib oauth::tests -- --nocapture
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add api/src/api/http/html_safety.rs api/src/api/http/mod.rs api/src/api/http/oauth.rs api/src/api/http/claim.rs e2e/tests/oauth.spec.ts
git commit -m "fix: escape oauth html and script output"
```

## Chunk 2: Tenant Boundary Containment

### Task 2: Remove Every Tenantless UCAN Validation Path

**Files:**
- Modify: `api/src/api/http/auth.rs`
- Modify: `api/src/api/extractors.rs`
- Modify: `api/src/api/http/nostr_rpc.rs`
- Modify: `api/src/ucan_auth/validation.rs`
- Test: `api/src/ucan_auth/validation.rs`
- Test: `api/src/api/http/auth.rs`
- Test: `api/src/api/http/nostr_rpc.rs`

- [ ] **Step 1: Write the failing tenant-isolation tests**

Add unit coverage that encodes the current bug:

```rust
#[tokio::test]
async fn test_tenant_bound_validation_rejects_other_tenant_tokens() {
    let auth_header = issue_test_ucan(/* tenant_id = 1 */).await;
    let result = validate_ucan_token(&auth_header, 2).await;
    assert!(result.is_err());
}
```

Add a DB-backed test in `api/src/api/http/auth.rs` for the bunker path:

```rust
#[tokio::test]
async fn test_manual_bunker_lookup_uses_request_tenant() {
    // seed user/personal_keys in tenant 1 only
    // call the new tenant-aware extraction + lookup path under tenant 2
    // expect UserNotFound / no authorization inserted
}
```

- [ ] **Step 2: Run the focused cargo tests and verify the new assertions fail**

Run:

```bash
cargo test -p keycast_api --lib validation::tests -- --nocapture
cargo test -p keycast_api --lib auth::tests -- --nocapture
```

Expected: FAIL because authenticated helpers still validate with `expected_tenant_id = 0`.

- [ ] **Step 3: Replace the helper API with tenant-aware extraction everywhere**

Refactor `auth.rs` to expose tenant-aware helpers:

```rust
pub(crate) async fn extract_user_from_token_for_tenant(
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<String, AuthError> { /* ... */ }

pub(crate) async fn extract_user_and_origin_from_token_for_tenant(
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<(String, String, Option<String>), AuthError> { /* ... */ }
```

In `api/src/api/extractors.rs`, resolve tenant before validating the UCAN instead of passing `0`:

```rust
let tenant = crate::api::tenant::TenantExtractor::from_request_parts(parts, state).await?;
let tenant_id = tenant.0.id;
let (pubkey, _, _, ucan) = crate::ucan_auth::validate_ucan_token(auth_str, tenant_id).await?;
```

Update `auth.rs` and `nostr_rpc.rs` call sites so no authenticated request path passes `0` unless it is explicitly system-internal and documented.

- [ ] **Step 4: Re-run the focused tests plus auth/session regressions**

Run:

```bash
cargo test -p keycast_api --lib validation::tests -- --nocapture
cargo test -p keycast_api --lib auth::tests -- --nocapture
cargo test -p keycast_api --lib nostr_rpc::tests -- --nocapture
cd e2e && npm test -- tests/auth.spec.ts tests/sessions.spec.ts tests/oauth.spec.ts
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add api/src/api/http/auth.rs api/src/api/extractors.rs api/src/api/http/nostr_rpc.rs api/src/ucan_auth/validation.rs e2e/tests/auth.spec.ts e2e/tests/sessions.spec.ts e2e/tests/oauth.spec.ts
git commit -m "fix: enforce tenant checks on all ucan auth paths"
```

### Task 3: Make Repository Lookups Tenant-Scoped and Close Host Admission Loopholes

**Files:**
- Modify: `core/src/repositories/oauth_authorization.rs`
- Modify: `core/src/repositories/personal_keys.rs`
- Modify: `api/src/api/http/auth.rs`
- Modify: `api/src/api/http/nostr_rpc.rs`
- Modify: `api/src/api/tenant.rs`
- Modify: `keycast/src/main.rs`
- Modify: `.env.example`
- Modify: `docs/DEPLOYMENT.md`
- Modify: `cloudbuild.yaml`
- Test: `core/src/repositories/oauth_authorization.rs`
- Test: `core/src/repositories/personal_keys.rs`
- Test: `api/src/api/tenant.rs`

- [ ] **Step 1: Write the failing repository and tenant-admission tests**

Add repository tests for tenant-scoped auth lookup:

```rust
#[tokio::test]
async fn test_find_by_bunker_pubkey_for_tenant_does_not_cross_tenants() {
    // same bunker key in tenant A lookup must not resolve tenant B auth rows
}
```

Add tenant config tests in `api/src/api/tenant.rs` for explicit auto-provision gating:

```rust
#[test]
#[serial]
fn test_validate_domain_requires_allowlist_or_explicit_autoprovision_flag() {
    std::env::remove_var("ALLOWED_TENANT_DOMAINS");
    std::env::set_var("ENABLE_TENANT_AUTO_PROVISIONING", "false");
    assert!(validate_domain("example.com").is_err());
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p keycast_core --lib oauth_authorization::tests -- --nocapture
cargo test -p keycast_core --lib personal_keys::tests -- --nocapture
cargo test -p keycast_api --lib tenant::tests -- --nocapture
```

Expected: FAIL because the current repository helpers and tenant admission flow still allow cross-tenant resolution / auto-provision fallback.

- [ ] **Step 3: Introduce tenant-scoped methods and production-safe tenant admission**

Implement repository methods like:

```rust
pub async fn find_by_bunker_pubkey_for_tenant(
    &self,
    bunker_pubkey: &str,
    tenant_id: i64,
) -> Result<Option<...>, RepositoryError> { /* WHERE bunker_public_key = $1 AND tenant_id = $2 */ }
```

Then replace the remaining tenantless usages on sensitive paths.

In `api/src/api/tenant.rs` and `keycast/src/main.rs`, change admission policy to:

```rust
// production/default: require ALLOWED_TENANT_DOMAINS
// local/dev: allow auto-provision only when ENABLE_TENANT_AUTO_PROVISIONING=true
```

Document the new env contract in `.env.example`, `docs/DEPLOYMENT.md`, and `cloudbuild.yaml`.

- [ ] **Step 4: Re-run targeted tests and the session/OAuth regressions**

Run:

```bash
cargo test -p keycast_core --lib oauth_authorization::tests -- --nocapture
cargo test -p keycast_core --lib personal_keys::tests -- --nocapture
cargo test -p keycast_api --lib tenant::tests -- --nocapture
cd e2e && npm test -- tests/sessions.spec.ts tests/oauth.spec.ts
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add core/src/repositories/oauth_authorization.rs core/src/repositories/personal_keys.rs api/src/api/http/auth.rs api/src/api/http/nostr_rpc.rs api/src/api/tenant.rs keycast/src/main.rs .env.example docs/DEPLOYMENT.md cloudbuild.yaml
git commit -m "fix: scope tenant lookups and require explicit tenant admission"
```

## Chunk 3: DPoP Enforcement

### Task 4: Enforce DPoP Binding at Token Exchange and Resource Access

**Files:**
- Create: `api/src/ucan_auth/dpop.rs`
- Modify: `api/src/ucan_auth/mod.rs`
- Modify: `api/src/api/http/atproto_oauth.rs`
- Modify: `api/src/ucan_auth/validation.rs`
- Modify: `api/src/api/http/auth.rs`
- Modify: `api/src/api/http/nostr_rpc.rs`
- Modify: `e2e/helpers/oauth.ts`
- Modify: `e2e/tests/oauth.spec.ts`
- Test: `api/src/api/http/atproto_oauth.rs`
- Test: `api/src/ucan_auth/validation.rs`
- Test: `e2e/tests/oauth.spec.ts`

- [ ] **Step 1: Write the failing DPoP tests**

Add unit tests for proof validation:

```rust
#[test]
fn test_dpop_proof_requires_iat_and_jti() { /* build JWT missing each claim */ }

#[test]
fn test_dpop_bound_ucan_requires_matching_thumbprint() { /* cnf.jkt mismatch => error */ }
```

Add an e2e regression for leaked-token replay:

```ts
test("dpop token is rejected on /api/nostr without a matching proof", async ({ request }) => {
  const { access_token, dpop } = await completeDpopOAuthFlow(request);
  const res = await request.post("/api/nostr", {
    headers: { Authorization: `Bearer ${access_token}` },
    data: { method: "get_public_key", params: [] },
  });
  expect(res.status()).toBe(401);
});
```

- [ ] **Step 2: Run the DPoP tests and verify they fail**

Run:

```bash
cargo test -p keycast_api --lib atproto_oauth::tests -- --nocapture
cargo test -p keycast_api --lib validation::tests -- --nocapture
cd e2e && npm test -- tests/oauth.spec.ts -g "dpop"
```

Expected: FAIL because the current implementation only binds `cnf.jkt` at issuance and does not enforce it later.

- [ ] **Step 3: Create a reusable DPoP verifier and enforce it on bearer-token resource paths**

Move DPoP verification into `api/src/ucan_auth/dpop.rs`:

```rust
pub struct VerifiedDpop {
    pub thumbprint: String,
    pub jti: String,
    pub iat: i64,
}

pub async fn verify_dpop_proof(
    headers: &HeaderMap,
    method: &str,
    htu: &str,
    expected_jkt: Option<&str>,
) -> Result<Option<VerifiedDpop>> { /* typ/alg/htu/htm/iat/jti/signature/thumbprint */ }
```

Then:

- reuse it from `atproto_oauth.rs` for token exchange
- call it from shared bearer-token validation when a UCAN contains `cnf.jkt`
- use existing URL builders in `auth.rs` / `nostr_rpc.rs` so the expected `htu` matches the real request URL
- reject replayed `jti` values with a short-lived in-memory cache first, and leave a Redis-backed follow-up note if cross-instance replay remains a concern

- [ ] **Step 4: Re-run the targeted tests and OAuth/session smoke coverage**

Run:

```bash
cargo test -p keycast_api --lib atproto_oauth::tests -- --nocapture
cargo test -p keycast_api --lib validation::tests -- --nocapture
cd e2e && npm test -- tests/oauth.spec.ts tests/sessions.spec.ts
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add api/src/ucan_auth/dpop.rs api/src/ucan_auth/mod.rs api/src/api/http/atproto_oauth.rs api/src/ucan_auth/validation.rs api/src/api/http/auth.rs api/src/api/http/nostr_rpc.rs e2e/helpers/oauth.ts e2e/tests/oauth.spec.ts
git commit -m "fix: enforce dpop-bound ucan proofs on resource access"
```

## Chunk 4: OAuth Client Trust

### Task 5: Require Registered OAuth Clients Outside Development

**Files:**
- Modify: `core/src/repositories/registered_client.rs`
- Modify: `api/src/api/http/oauth.rs`
- Modify: `.env.example`
- Modify: `docs/DEPLOYMENT.md`
- Modify: `cloudbuild.yaml`
- Test: `core/src/repositories/registered_client.rs`
- Test: `e2e/tests/oauth.spec.ts`

- [ ] **Step 1: Write the failing policy tests**

Add unit coverage for strict mode:

```rust
#[tokio::test]
async fn test_unregistered_client_is_rejected_when_strict_mode_enabled() {
    std::env::set_var("REQUIRE_REGISTERED_OAUTH_CLIENTS", "true");
    let result = repo.validate_redirect_uri("unknown-client", "https://app.example/callback", 1).await;
    assert!(result.is_err());
}
```

Add a matching e2e request test:

```ts
test("strict mode rejects unknown oauth clients", async ({ request }) => {
  const res = await request.get(`/api/oauth/authorize?client_id=unknown-client&redirect_uri=${encodeURIComponent(CALLBACK_URL)}`);
  expect(res.status()).toBe(400);
});
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p keycast_core --lib registered_client::tests -- --nocapture
cd e2e && npm test -- tests/oauth.spec.ts -g "strict mode"
```

Expected: FAIL because unregistered clients are currently accepted.

- [ ] **Step 3: Implement strict client admission with an explicit dev escape hatch**

Update the repository and authorize flow so:

```rust
let strict_clients = std::env::var("REQUIRE_REGISTERED_OAUTH_CLIENTS")
    .map(|v| v == "true")
    .unwrap_or(cfg!(not(debug_assertions)));
```

In strict mode:

- unknown `client_id` values are rejected
- docs/env explain how to seed first-party and staging clients into `registered_clients`
- local development can opt out explicitly

- [ ] **Step 4: Re-run the targeted tests and standard OAuth e2e flow**

Run:

```bash
cargo test -p keycast_core --lib registered_client::tests -- --nocapture
cd e2e && npm test -- tests/oauth.spec.ts
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add core/src/repositories/registered_client.rs api/src/api/http/oauth.rs .env.example docs/DEPLOYMENT.md cloudbuild.yaml e2e/tests/oauth.spec.ts
git commit -m "fix: require registered oauth clients in strict environments"
```

## Chunk 5: Operational Safeguards

### Task 6: Fail Closed on Production Email Configuration

**Files:**
- Modify: `api/src/email_service.rs`
- Modify: `keycast/src/main.rs`
- Modify: `.env.example`
- Modify: `docs/DEPLOYMENT.md`
- Test: `api/src/email_service.rs`
- Test: `keycast/src/main.rs`

- [ ] **Step 1: Write the failing startup/config tests**

Add tests that encode the production expectation:

```rust
#[test]
fn test_production_requires_real_email_sender_or_explicit_disable() {
    std::env::set_var("NODE_ENV", "production");
    std::env::remove_var("SENDGRID_API_KEY");
    std::env::remove_var("DISABLE_EMAILS");
    assert!(validate_environment().is_err());
}
```

Add an email-sender test:

```rust
#[test]
fn test_dev_email_sender_not_selected_in_production_by_default() {
    std::env::set_var("NODE_ENV", "production");
    std::env::remove_var("SENDGRID_API_KEY");
    assert!(create_email_sender().is_err());
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p keycast -- --nocapture
cargo test -p keycast_api --lib email_service -- --nocapture
```

Expected: FAIL because production currently falls back to the dev sender and logs live tokens.

- [ ] **Step 3: Make email sender selection explicit and production-safe**

Refactor `create_email_sender` into a fallible constructor:

```rust
pub fn create_email_sender() -> Result<Arc<dyn EmailSender>, String> {
    if let Ok(api_key) = env::var("SENDGRID_API_KEY").filter(|v| !v.is_empty()) {
        return Ok(Arc::new(SendGridEmailSender::new(api_key)));
    }

    let node_env = env::var("NODE_ENV").unwrap_or_else(|_| "development".to_string());
    if node_env == "production" && env::var("DISABLE_EMAILS").is_err() {
        return Err("SENDGRID_API_KEY required in production".to_string());
    }

    Ok(Arc::new(DevEmailSender::new()))
}
```

Update `keycast/src/main.rs` env validation and docs to match.

- [ ] **Step 4: Re-run the focused tests**

Run:

```bash
cargo test -p keycast -- --nocapture
cargo test -p keycast_api --lib -- --nocapture
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add api/src/email_service.rs keycast/src/main.rs .env.example docs/DEPLOYMENT.md
git commit -m "fix: require explicit email configuration in production"
```

## Chunk 6: Dependency Triage and Audit Closure

### Task 7: Upgrade the Web Dependency Stack and Remove Stored Swagger Auth

**Files:**
- Modify: `web/package.json`
- Modify: `web/package-lock.json`
- Modify: `web/src/routes/docs/+page.svelte`
- Test: `web/package.json`
- Test: `e2e/tests/oauth.spec.ts`
- Test: `e2e/tests/auth.spec.ts`

- [ ] **Step 1: Update the failing dependency baseline and browser hardening**

Change:

```ts
persistAuthorization: false
```

in `web/src/routes/docs/+page.svelte`.

Upgrade the vulnerable packages in `web/package.json` to the first non-vulnerable versions supported by the app:

- `vite` -> `6.4.1` or newer
- `svelte` -> first fixed `5.x`
- refresh the lockfile so `rollup` and `devalue` resolve to fixed builds

- [ ] **Step 2: Run frontend validation and verify any breakage before fixing**

Run:

```bash
cd web && npm install
cd web && npm run check
cd web && npm audit --omit=dev
```

Expected: `npm audit` should still FAIL until the final version set is correct; `npm run check` may reveal API changes from the upgrades.

- [ ] **Step 3: Apply the minimum compatibility fixes required by the upgraded stack**

Keep this small and local. If the upgrades surface Svelte/Vite breakage, fix only the directly affected code paths and avoid unrelated refactors.

- [ ] **Step 4: Re-run frontend validation plus the auth/OAuth e2e suite**

Run:

```bash
cd web && npm run check
cd web && npm audit --omit=dev
cd e2e && npm test -- tests/oauth.spec.ts tests/auth.spec.ts tests/sessions.spec.ts
```

Expected: PASS and `found 0 vulnerabilities`

- [ ] **Step 5: Commit the slice**

```bash
git add web/package.json web/package-lock.json web/src/routes/docs/+page.svelte
git commit -m "build: upgrade web deps and stop persisting swagger auth"
```

### Task 8: Triage and Reduce RustSec Exposure

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `api/Cargo.toml`
- Modify: `core/Cargo.toml`
- Modify: `keycast/Cargo.toml`
- Create: `docs/security/rustsec-2026-04-01.md`
- Test: `Cargo.lock`

- [ ] **Step 1: Record the current RustSec state before changing versions**

Create `docs/security/rustsec-2026-04-01.md` with three buckets:

- direct/runtime patchable now (`bytes`, `crossbeam-channel`, `ring`, `rustls-webpki`, `time`, `tracing-subscriber`)
- transitive but patchable with direct dependency bumps or `cargo update`
- upstream-blocked/unmaintained chains (`ucan`, `did-key`, related unmaintained crates)

Include the exact `cargo audit` output date and the chosen remediation per advisory.

- [ ] **Step 2: Upgrade the directly patchable crates and refresh the lockfile**

Use the smallest possible direct bumps and lockfile updates first:

```bash
cargo update -p bytes --precise 1.11.1
cargo update -p crossbeam-channel --precise 0.5.15
cargo update -p ring --precise 0.17.12
cargo update -p rustls-webpki --precise 0.103.10
cargo update -p time --precise 0.3.47
cargo update -p tracing-subscriber --precise 0.3.20
```

If a crate is only reachable through a direct version pin in `api/Cargo.toml` or `core/Cargo.toml`, bump the direct dependency instead of forcing the lockfile.

- [ ] **Step 3: Decide the short-term path for `ucan` / `did-key`**

If the audit still reports the unmaintained chain after direct upgrades:

- first check whether newer compatible releases exist
- if not, pin a vetted fork via `[patch.crates-io]`
- if that is too risky for the same branch, leave the code untouched but keep the triage doc updated and open a dedicated follow-up branch immediately

Do not silently ignore these; the plan requires an explicit decision.

- [ ] **Step 4: Run the full Rust verification pass**

Run:

```bash
cargo test --workspace
cargo audit
```

Expected: all tests PASS, and `cargo audit` is either clean or reduced to only the explicitly documented upstream-blocked items in `docs/security/rustsec-2026-04-01.md`

- [ ] **Step 5: Commit the slice**

```bash
git add Cargo.toml Cargo.lock api/Cargo.toml core/Cargo.toml keycast/Cargo.toml docs/security/rustsec-2026-04-01.md
git commit -m "build: reduce rustsec exposure and document remaining blockers"
```

Plan complete and saved to `docs/superpowers/plans/2026-04-01-security-remediation.md`. Ready to execute?
