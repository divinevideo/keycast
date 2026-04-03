# Security Remediation Fix & Merge Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix critical/important issues found in the comprehensive review, then merge all 5 worktrees + main branch changes into a single coherent branch.

**Architecture:** Three phases — fix criticals first (EdDSA rejection, DISABLE_EMAILS tightening), then merge worktrees in dependency order resolving conflicts, then update deployment docs. All work happens on the `feat/atproto-opt-in-lifecycle` branch.

**Tech Stack:** Rust/Axum, SvelteKit, git worktree merging

---

## File Map

- `api/src/ucan_auth/dpop.rs` — DPoP proof verifier (EdDSA fix)
- `api/src/api/extractors.rs` — UCAN auth extractor (tenant_id=0 fix via merge)
- `api/src/api/http/nostr_rpc.rs` — NIP-46 HTTP RPC (tenant_id=0 fix post-merge)
- `api/src/api/http/auth.rs` — Auth helpers (tenant_id=0 fix via merge)
- `api/src/email_service.rs` — Email sender (DISABLE_EMAILS tightening)
- `keycast/src/main.rs` — Startup validation (Box::leak fix)
- `docs/DEPLOYMENT.md` — Deployment guide (new env vars)

## Worktree Locations

| Worktree | Branch | Task | Key files |
|----------|--------|------|-----------|
| `.claude/worktrees/agent-a0fd0bcf` | `worktree-agent-a0fd0bcf` | Task 2: Tenant UCAN | extractors.rs, auth.rs, validation.rs, nostr_rpc.rs |
| `.claude/worktrees/agent-a111fd86` | `worktree-agent-a111fd86` | Task 1: HTML escape | html_safety.rs, oauth.rs, claim.rs |
| `.claude/worktrees/agent-abdae1ea` | `worktree-agent-abdae1ea` | Task 5: OAuth clients | registered_client.rs, oauth.rs |
| `.claude/worktrees/agent-aa38523d` | `worktree-agent-aa38523d` | Task 6: Email config | email_service.rs, main.rs |
| `.claude/worktrees/agent-ae631cba` | `worktree-agent-ae631cba` | Task 7: Web deps | web/package.json, web/bun.lockb |

Main branch already has: Task 3 (tenant repos), Task 4 (DPoP), Task 8 (RustSec)

---

## Chunk 1: Fix Critical and Important Issues

### Task 1: Reject EdDSA DPoP proofs until verification is implemented

**Files:**
- Modify: `api/src/ucan_auth/dpop.rs:156-161`
- Test: `api/src/ucan_auth/dpop.rs` (existing tests)

- [ ] **Step 1: Write the failing test**

Add to the existing test module in `api/src/ucan_auth/dpop.rs`:

```rust
#[test]
fn test_eddsa_proofs_rejected_until_verification_implemented() {
    // Build a DPoP proof header claiming EdDSA algorithm
    let header = base64_url_encode(r#"{"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#);
    let payload = base64_url_encode(&format!(
        r#"{{"htm":"POST","htu":"https://example.com/api/nostr","iat":{},"jti":"eddsa-test-reject"}}"#,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    let fake_sig = base64_url_encode("fakesignature");
    let proof = format!("{}.{}.{}", header, payload, fake_sig);

    let mut headers = HeaderMap::new();
    headers.insert("DPoP", HeaderValue::from_str(&proof).unwrap());

    let result = verify_dpop_proof(&headers, "POST", "https://example.com/api/nostr", None);
    assert!(result.is_err(), "EdDSA proofs should be rejected until verification is implemented");
}
```

- [ ] **Step 2: Run test and verify it fails**

Run: `cargo test -p keycast_api --lib dpop::tests::test_eddsa_proofs_rejected -- --nocapture`
Expected: FAIL because EdDSA proofs currently pass without verification.

- [ ] **Step 3: Reject EdDSA in verify_dpop_proof**

In `api/src/ucan_auth/dpop.rs`, replace lines 156-160:

```rust
    // Verify signature BEFORE inserting JTI into replay cache
    // This prevents an attacker from poisoning the cache with a forged JTI
    if alg == "ES256" {
        verify_es256_signature(parts[0], parts[1], parts[2], jwk)?;
    }
    // Note: EdDSA signature verification would require ed25519-dalek dependency
    // For now, EdDSA proofs are parsed but not cryptographically verified
```

With:

```rust
    // Verify signature BEFORE inserting JTI into replay cache
    // This prevents an attacker from poisoning the cache with a forged JTI
    if alg == "ES256" {
        verify_es256_signature(parts[0], parts[1], parts[2], jwk)?;
    } else {
        // EdDSA verification requires ed25519-dalek dependency — reject until implemented
        return Err(anyhow!("DPoP algorithm '{}' is not yet supported (only ES256)", alg));
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p keycast_api --lib dpop::tests -- --nocapture`
Expected: All DPoP tests pass.

- [ ] **Step 5: Commit**

```bash
git add api/src/ucan_auth/dpop.rs
git commit -m "security: reject unsupported DPoP algorithms until verification implemented"
```

### Task 2: Tighten DISABLE_EMAILS check

**Files:**
- Modify: `.claude/worktrees/agent-aa38523d/api/src/email_service.rs:490`

- [ ] **Step 1: Fix the check in the Task 6 worktree**

In `.claude/worktrees/agent-aa38523d/api/src/email_service.rs`, replace:

```rust
    if env_mode == "production" && env::var("DISABLE_EMAILS").is_err() {
```

With:

```rust
    if env_mode == "production"
        && env::var("DISABLE_EMAILS")
            .ok()
            .filter(|v| v == "true")
            .is_none()
    {
```

- [ ] **Step 2: Update the test that checks DISABLE_EMAILS**

Find the test `test_production_with_disable_emails_ok` and ensure it sets `DISABLE_EMAILS=true` (not just any value).

- [ ] **Step 3: Add a test for empty DISABLE_EMAILS**

```rust
#[test]
fn test_empty_disable_emails_does_not_bypass_production_check() {
    // ... set RUST_ENV=production, DISABLE_EMAILS="" (empty), no SENDGRID_API_KEY
    let result = create_email_sender();
    assert!(result.is_err());
}
```

- [ ] **Step 4: Run tests in the worktree**

Run: `cd .claude/worktrees/agent-aa38523d && cargo test -p keycast_api --lib email_service -- --nocapture`
Expected: All email tests pass.

- [ ] **Step 5: Amend the worktree commit**

```bash
cd .claude/worktrees/agent-aa38523d
git add api/src/email_service.rs
git commit --amend --no-edit
```

## Chunk 2: Merge Worktrees in Dependency Order

The merge order matters because some changes depend on others. Merge order:

1. Task 2 (tenant UCAN) — foundational, changes API signatures
2. Task 1 (HTML escape) — touches oauth.rs templates
3. Task 5 (OAuth clients) — touches oauth.rs authorization checks
4. Task 6 (email config) — touches main.rs validation
5. Task 7 (web deps) — fully independent, web/ only

After each merge, run `cargo check -p keycast_api` to catch conflicts early.

### Task 3: Merge Task 2 worktree (Tenant UCAN)

**Files:**
- All files in `api/src/api/extractors.rs`, `api/src/api/http/auth.rs`, `api/src/api/http/nostr_rpc.rs`, `api/src/ucan_auth/validation.rs`, + callers

- [ ] **Step 1: Cherry-pick Task 2's commit onto the main branch**

```bash
git cherry-pick worktree-agent-a0fd0bcf --no-commit
```

- [ ] **Step 2: Resolve merge conflicts**

Expected conflicts in:
- `api/src/api/http/nostr_rpc.rs` — Task 4 added DPoP code around the `validate_ucan_token` call. Resolution: keep Task 4's DPoP code but replace ALL `validate_ucan_token(auth_header, 0)` with `validate_ucan_token(auth_header, tenant_id)`. There are TWO calls: one on the cache-hit DPoP path (~line 470) and one on the cache-miss path (~line 504). Both must use `tenant_id`.
- `api/src/api/http/auth.rs` — Task 3 changed `find_encrypted_key` to `find_encrypted_key_for_tenant`. Task 2 changed function signatures to accept `tenant_id`. Keep both changes.
- `api/src/api/extractors.rs` — Task 4 added `enforce_dpop_if_bound`. Task 2 added `resolve_tenant_id_from_parts`. Keep both: resolve tenant first, then validate UCAN with tenant_id, then enforce DPoP.

- [ ] **Step 3: Run cargo check**

Run: `cargo check -p keycast_api`
Expected: Clean compilation.

- [ ] **Step 4: Verify no remaining tenant_id=0 in production code**

Run: `grep -rn 'validate_ucan_token.*0)' api/src/ --include='*.rs' | grep -v test | grep -v '#\[cfg(test'`
Expected: ZERO matches (only test files should have literal 0).

- [ ] **Step 5: Run tests**

Run: `cargo test -p keycast_api --lib -- --nocapture`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git commit -m "security: merge tenant UCAN enforcement (resolve conflicts with DPoP/repos)"
```

### Task 4: Merge Task 1 worktree (HTML escape)

- [ ] **Step 1: Cherry-pick**

```bash
git cherry-pick worktree-agent-a111fd86 --no-commit
```

- [ ] **Step 2: Resolve conflicts**

Expected: `oauth.rs` — Task 3 changed `find_encrypted_key` calls, Task 1 changed template rendering. These are in different functions so conflicts should be positional only. Keep both changes.

- [ ] **Step 3: Run cargo check and commit**

```bash
cargo check -p keycast_api
git commit -m "security: merge OAuth HTML escaping"
```

### Task 5: Merge Task 5 worktree (OAuth clients)

- [ ] **Step 1: Cherry-pick**

```bash
git cherry-pick worktree-agent-abdae1ea --no-commit
```

- [ ] **Step 2: Resolve conflicts**

Expected: `oauth.rs` — Task 5 adds `require_registered_client` blocks. After merging Tasks 1 and 3 into oauth.rs, positions may have shifted. `.env.example` — positional only.

- [ ] **Step 3: Run cargo check and commit**

```bash
cargo check -p keycast_api
git commit -m "security: merge registered OAuth client enforcement"
```

### Task 6: Merge Task 6 worktree (Email config)

- [ ] **Step 1: Cherry-pick**

```bash
git cherry-pick worktree-agent-aa38523d --no-commit
```

- [ ] **Step 2: Resolve conflicts**

Expected: `keycast/src/main.rs` — Task 3 added tenant env validation block, Task 6 adds email validation block. Both are additive to `validate_environment()`. `.env.example` — positional only.

- [ ] **Step 3: Run cargo check and commit**

```bash
cargo check -p keycast_api && cargo check -p keycast
git commit -m "security: merge fail-closed email configuration"
```

### Task 7: Merge Task 7 worktree (Web deps)

- [ ] **Step 1: Cherry-pick**

```bash
git cherry-pick worktree-agent-ae631cba --no-commit
```

- [ ] **Step 2: Commit (no conflicts expected — web/ only)**

```bash
git commit -m "security: merge web dependency upgrades"
```

## Chunk 3: Post-Merge Verification and Docs

### Task 8: Full verification pass

- [ ] **Step 1: Cargo check workspace**

Run: `cargo check --workspace`
Expected: Clean.

- [ ] **Step 2: Run all tests**

Run: `cargo test --workspace`
Expected: All pass (except pre-existing Redis/DB connection tests).

- [ ] **Step 3: Verify no tenant_id=0 bypass remains**

Run: `grep -rn 'validate_ucan_token.*\b0\b' api/src/ --include='*.rs' | grep -v '#\[test' | grep -v '#\[cfg(test' | grep -v '// test'`
Expected: Zero matches in production code.

- [ ] **Step 4: Verify HTML escaping is complete**

Run: `grep -n 'format!.*client_id\|format!.*redirect_uri\|format!.*secret\|format!.*relay' api/src/api/http/oauth.rs | grep -v escape | grep -v js_string`
Expected: Zero matches (all user values should go through escape helpers).

- [ ] **Step 5: Verify DPoP EdDSA rejection**

Run: `cargo test -p keycast_api --lib dpop::tests::test_eddsa -- --nocapture`
Expected: Pass.

### Task 9: Update deployment documentation

**Files:**
- Modify: `docs/DEPLOYMENT.md`

- [ ] **Step 1: Add security environment variables section**

Add to `docs/DEPLOYMENT.md`:

```markdown
### Security Environment Variables (added 2026-04-04)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SENDGRID_API_KEY` | Production | — | Email delivery. Production fails to start without this unless `DISABLE_EMAILS=true`. |
| `DISABLE_EMAILS` | No | — | Set to `true` to explicitly disable email delivery in production. |
| `ALLOWED_TENANT_DOMAINS` | Production | — | Comma-separated list of allowed tenant domains. |
| `ENABLE_TENANT_AUTO_PROVISIONING` | No | `false` | Set to `true` to allow automatic tenant creation for unknown domains (dev only). |
| `REQUIRE_REGISTERED_OAUTH_CLIENTS` | No | `true` (release) | Set to `false` to allow unregistered OAuth clients (dev only). |
```

- [ ] **Step 2: Commit**

```bash
git add docs/DEPLOYMENT.md
git commit -m "docs: add security environment variables to deployment guide"
```

### Task 10: Clean up worktrees

- [ ] **Step 1: Remove merged worktrees**

```bash
git worktree remove .claude/worktrees/agent-a0fd0bcf --force
git worktree remove .claude/worktrees/agent-a111fd86 --force
git worktree remove .claude/worktrees/agent-abdae1ea --force
git worktree remove .claude/worktrees/agent-aa38523d --force
git worktree remove .claude/worktrees/agent-ae631cba --force
```

- [ ] **Step 2: Prune stale worktree refs**

```bash
git worktree prune
```

Plan complete and saved to `docs/superpowers/plans/2026-04-04-security-fix-and-merge.md`. Ready to execute?
