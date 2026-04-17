# Keycast Auth Observability Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add durable auth auditing, request correlation, engineer lookup tooling, and production monitoring so engineers can diagnose Keycast auth failures with user-level evidence.

**Architecture:** Add an append-only `auth_events` table in Keycast Postgres, instrument auth handlers through a shared observability helper, expose an engineer-only debug endpoint and CLI wrapper, and add Keycast-specific alerts, dashboard panels, and retention automation in `divine-iac-coreconfig`.

**Tech Stack:** Rust, Axum, SQLx/Postgres, Prometheus/VictoriaMetrics, Grafana, Kubernetes CronJob, Kustomize

---

## Chunk 1: Keycast Persistence And Runtime Instrumentation

### Task 1: Add `auth_events` persistence and repository support

**Files:**
- Create: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/database/migrations/20260418100000_add_auth_events.sql`
- Create: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/core/src/repositories/auth_event.rs`
- Modify: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/core/src/repositories/mod.rs`
- Test: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/core/src/repositories/auth_event.rs`

- [ ] **Step 1: Write repository tests first**

Add unit tests around insert and query helpers in `auth_event.rs` using the existing repository test style:

```rust
#[tokio::test]
async fn records_auth_event_with_lookup_fields() {
    let repo = AuthEventRepository::new(pool.clone());
    repo.record(AuthEventRecord { /* ... */ }).await.unwrap();

    let rows = repo.list_recent_by_email(tenant_id, "user@example.com", 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason_code.as_deref(), Some("user_not_found"));
}
```

- [ ] **Step 2: Run the repository test to confirm it fails**

Run: `cargo test -p keycast_core auth_event --quiet`

Expected: FAIL because `AuthEventRepository` and the migration do not exist yet.

- [ ] **Step 3: Add the SQL migration**

Create `20260418100000_add_auth_events.sql` with:

- `auth_events` table
- indexes on `occurred_at`, `request_id`, `(tenant_id, email)`, `(tenant_id, pubkey)`, `(tenant_id, endpoint, occurred_at)`
- text fields for `endpoint`, `event_type`, `outcome`, `reason_code`
- JSONB `metadata_json default '{}'::jsonb`

- [ ] **Step 4: Add the repository implementation**

Implement:

- `AuthEventRecord`
- `AuthEventRow`
- `AuthEventRepository::record`
- `AuthEventRepository::list_recent_by_email`
- `AuthEventRepository::list_recent_by_pubkey`
- `AuthEventRepository::list_recent_by_request_id`
- `AuthEventRepository::delete_older_than`

- [ ] **Step 5: Re-export the repository**

Update `core/src/repositories/mod.rs` so API/admin code can import the new repository cleanly.

- [ ] **Step 6: Re-run the repository test**

Run: `cargo test -p keycast_core auth_event --quiet`

Expected: PASS

- [ ] **Step 7: Commit**

Run:

```bash
git -C /Users/rabble/code/divine/keycast/.worktrees/auth-observability add \
  database/migrations/20260418100000_add_auth_events.sql \
  core/src/repositories/auth_event.rs \
  core/src/repositories/mod.rs
git -C /Users/rabble/code/divine/keycast/.worktrees/auth-observability commit -m "feat: add auth event persistence"
```

### Task 2: Add request IDs and canonical auth observability helpers

**Files:**
- Create: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/src/api/http/auth_observability.rs`
- Modify: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/src/api/http/mod.rs`
- Modify: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/keycast/src/main.rs`
- Modify: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/core/src/metrics.rs`
- Test: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/tests/headless_auth_test.rs`

- [ ] **Step 1: Write a failing request-ID propagation test**

Extend `headless_auth_test.rs` with a case that sends `x-trace-id` and asserts `x-request-id` is echoed back on failure.

```rust
assert_eq!(response.headers()["x-request-id"], "test-trace-id");
```

- [ ] **Step 2: Run the new test to confirm it fails**

Run: `cargo test -p keycast_api --test headless_auth_test --quiet`

Expected: FAIL because responses do not yet set `x-request-id`.

- [ ] **Step 3: Add shared request-context helpers**

Implement `auth_observability.rs` with:

- request ID extraction/generation
- stable email hashing helper
- pubkey prefix helper
- `record_auth_event_and_log(...)`
- latency timing support

- [ ] **Step 4: Thread request IDs through the HTTP stack**

Update `keycast/src/main.rs` so the request trace span continues to exist, but responses also expose `x-request-id`. Keep the existing `x-trace-id` compatibility behavior.

- [ ] **Step 5: Add richer auth metrics**

Extend `core/src/metrics.rs` to emit:

- `keycast_auth_requests_total{endpoint,outcome,reason_code}`
- `keycast_auth_request_duration_seconds{endpoint,outcome}`
- `keycast_auth_audit_write_failures_total{endpoint}`
- `keycast_auth_email_send_failures_total{template}`

Use bounded labels only.

- [ ] **Step 6: Instrument representative auth handlers first**

Update:

- `api/src/api/http/auth.rs`
- `api/src/api/http/headless.rs`
- `api/src/api/http/claim.rs`
- `api/src/api/http/oauth.rs`

to call the shared helper for canonical outcome logging and auth event recording.

- [ ] **Step 7: Re-run the request-ID/auth tests**

Run: `cargo test -p keycast_api --test headless_auth_test --quiet`

Expected: PASS

- [ ] **Step 8: Commit**

Run:

```bash
git -C /Users/rabble/code/divine/keycast/.worktrees/auth-observability add \
  api/src/api/http/auth_observability.rs \
  api/src/api/http/mod.rs \
  api/src/api/http/auth.rs \
  api/src/api/http/headless.rs \
  api/src/api/http/claim.rs \
  api/src/api/http/oauth.rs \
  core/src/metrics.rs \
  keycast/src/main.rs \
  api/tests/headless_auth_test.rs
git -C /Users/rabble/code/divine/keycast/.worktrees/auth-observability commit -m "feat: instrument auth requests and outcomes"
```

### Task 3: Add engineer lookup surface and CLI wrapper

**Files:**
- Modify: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/src/api/http/admin.rs`
- Modify: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/src/api/http/routes.rs`
- Create: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/scripts/auth-debug.sh`
- Test: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/tests/admin_token_test.rs`
- Test: `/Users/rabble/code/divine/keycast/.worktrees/auth-observability/api/tests/admin_preload_test.rs`

- [ ] **Step 1: Write a failing admin lookup test**

Add a test for a new support-admin endpoint such as `/api/admin/auth-debug` that returns:

- current user/account state
- recent auth events
- derived login diagnosis

- [ ] **Step 2: Run the admin test to confirm it fails**

Run: `cargo test -p keycast_api --test admin_token_test --quiet`

Expected: FAIL because the route and response type do not exist yet.

- [ ] **Step 3: Add the admin endpoint**

In `admin.rs`:

- define query params for `email`, `pubkey`, `npub`, or `request_id`
- require support-admin or full-admin auth
- query `UserRepository`, `OAuthAuthorizationRepository`, and `AuthEventRepository`
- build a compact diagnosis string such as `"no users row found"` or `"email_not_verified"`

In `routes.rs`:

- mount `GET /admin/auth-debug`

- [ ] **Step 4: Add the engineer CLI wrapper**

Create `scripts/auth-debug.sh` that:

- accepts `--email`, `--pubkey`, `--npub`, or `--request-id`
- calls the new admin endpoint with an existing admin token
- prints compact JSON for engineers

- [ ] **Step 5: Re-run the admin tests**

Run:

```bash
cargo test -p keycast_api --test admin_token_test --quiet
cargo test -p keycast_api --test admin_preload_test --quiet
```

Expected: PASS

- [ ] **Step 6: Commit**

Run:

```bash
git -C /Users/rabble/code/divine/keycast/.worktrees/auth-observability add \
  api/src/api/http/admin.rs \
  api/src/api/http/routes.rs \
  scripts/auth-debug.sh \
  api/tests/admin_token_test.rs \
  api/tests/admin_preload_test.rs
git -C /Users/rabble/code/divine/keycast/.worktrees/auth-observability commit -m "feat: add engineer auth debug surface"
```

## Chunk 2: Infrastructure Monitoring And Retention

### Task 4: Add retention CronJob to Keycast Kubernetes manifests

**Files:**
- Create: `/Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/applications/keycast/base/auth-events-retention-cronjob.yaml`
- Modify: `/Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/applications/keycast/base/kustomization.yaml`

- [ ] **Step 1: Add the retention job manifest**

Create a CronJob that:

- runs in `identity`
- uses `postgres:16-alpine`
- reads `DATABASE_URL` from `keycast-db-credentials`
- executes `DELETE FROM auth_events WHERE occurred_at < NOW() - INTERVAL '30 days'`

- [ ] **Step 2: Include it in the base kustomization**

Update the Keycast base kustomization so every environment gets the retention job.

- [ ] **Step 3: Validate the manifest**

Run:

```bash
kubeconform -strict \
  /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/applications/keycast/base/auth-events-retention-cronjob.yaml
```

Expected: PASS

- [ ] **Step 4: Commit**

Run:

```bash
git -C /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability add \
  k8s/applications/keycast/base/auth-events-retention-cronjob.yaml \
  k8s/applications/keycast/base/kustomization.yaml
git -C /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability commit -m "feat: retain keycast auth events for 30 days"
```

### Task 5: Add Keycast alerts and dashboard

**Files:**
- Create: `/Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/vmrule-keycast.yaml`
- Create: `/Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/dashboard-keycast.yaml`
- Modify: `/Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/kustomization.yaml`

- [ ] **Step 1: Add Keycast VMRule alerts**

Create alerts for:

- high auth failure rate
- auth audit write failures
- reset email send failures
- auth 5xx spikes
- root-route 5xx spikes

- [ ] **Step 2: Add Keycast Grafana dashboard**

Create panels for:

- auth request rate by endpoint
- success/failure ratio
- failure reasons
- forgot-password/reset funnel
- auth latency
- audit write failures

- [ ] **Step 3: Register both resources**

Update the VictoriaMetrics base kustomization to include the new VMRule and dashboard ConfigMap.

- [ ] **Step 4: Validate the manifests**

Run:

```bash
kubeconform -strict \
  /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/vmrule-keycast.yaml \
  /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/dashboard-keycast.yaml
```

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git -C /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability add \
  k8s/victoria-metrics/base/vmrule-keycast.yaml \
  k8s/victoria-metrics/base/dashboard-keycast.yaml \
  k8s/victoria-metrics/base/kustomization.yaml
git -C /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability commit -m "feat: monitor keycast auth health"
```

### Task 6: Final verification and handoff

**Files:**
- Modify as needed: both worktrees

- [ ] **Step 1: Run focused Rust tests**

Run:

```bash
cargo test -p keycast_core auth_event --quiet
cargo test -p keycast_api --test headless_auth_test --quiet
cargo test -p keycast_api --test admin_token_test --quiet
cargo test -p keycast_api --test admin_preload_test --quiet
```

Expected: PASS

- [ ] **Step 2: Run formatter and lints**

Run:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Expected: PASS

- [ ] **Step 3: Validate the K8s manifests**

Run:

```bash
kubeconform -strict \
  /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/applications/keycast/base/auth-events-retention-cronjob.yaml \
  /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/vmrule-keycast.yaml \
  /Users/rabble/code/divine/divine-iac-coreconfig/.worktrees/keycast-auth-observability/k8s/victoria-metrics/base/dashboard-keycast.yaml
```

Expected: PASS

- [ ] **Step 4: Smoke-test the engineer lookup**

Run the new script against staging or a local admin token once deployed:

```bash
/Users/rabble/code/divine/keycast/.worktrees/auth-observability/scripts/auth-debug.sh --email user@example.com
```

Expected: JSON summary with account state and recent auth events.

- [ ] **Step 5: Prepare rollout notes**

Document:

- migration requirement
- staging-first deployment
- post-deploy smoke checks
- expected Grafana and alert names

