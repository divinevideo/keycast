# Keycast Auth Observability Design

Date: 2026-04-18

## Goal

Make Keycast supportable for authentication incidents by adding a durable engineer-facing auth audit trail, consistent request correlation, structured auth outcome logs, actionable metrics, and production alerts/dashboard coverage.

## Problem

Recent production debugging showed three operational gaps:

1. Auth request logs are inconsistent and difficult to query by user or request.
2. Metrics are global counters with little breakdown by endpoint, outcome, or reason.
3. There is no persistent per-user auth history once logs are missing, sparse, or aged out.

The result is that engineers cannot reliably answer basic incident questions such as:

- Did the password reset request hit the server?
- Did a reset token get stored and later consumed?
- Did the password hash change?
- Why did login fail for this user at this time?
- Is the client failing before it reaches the auth endpoint?

## Design Summary

The first implementation uses Postgres as the system of record for hot auth history. Keycast will write append-only `auth_events` rows for all auth-related flows, return a stable request identifier to clients, emit canonical structured auth outcome logs, and expose richer Prometheus metrics. Engineers will get a CLI lookup tool that joins current account state with recent auth events. Infrastructure will gain Keycast-specific alert rules, a Grafana dashboard, and a retention job that deletes auth events older than 30 days.

ClickHouse remains a good follow-up for longer retention and aggregate analysis, but it is not part of the first ship.

## Architecture

### Request correlation

Every auth request gets a `request_id`:

- Accept incoming `x-trace-id` if present.
- Otherwise generate a new UUID-derived ID.
- Attach it to the request context and current tracing span.
- Return it to the client in an `x-request-id` response header.

This ID becomes the join key across:

- HTTP responses
- structured logs
- `auth_events`
- engineer lookup output

### Audit trail

Add a new append-only `auth_events` table in Keycast Postgres. This is the engineer-facing source of truth for user-level auth history.

The table stores:

- `id`
- `occurred_at`
- `request_id`
- `tenant_id`
- `endpoint`
- `event_type`
- `outcome`
- `reason_code`
- `http_status`
- `email`
- `email_hash`
- `pubkey`
- `pubkey_prefix`
- `client_id`
- `redirect_origin`
- `user_agent`
- `metadata_json`

Raw `email` and `pubkey` are allowed in the table because the table is for engineer support workflows. Logs and metrics will not expose raw identifiers.

`metadata_json` stores flow-specific details without adding table churn for each new auth path. Examples:

- reset token fingerprint
- OAuth client metadata
- claim token ID
- admin role
- verification method

Secrets and credentials are never stored:

- no raw passwords
- no raw reset tokens
- no bearer tokens
- no cookies
- no decrypted secrets

### Event coverage

The audit trail covers broader auth flows, not only password reset:

- login
- headless login
- register
- forgot password
- reset password
- verify email
- logout
- OAuth authorize/token/poll flows where auth state changes or rejects occur
- claim flows
- admin/support auth flows

Each flow writes lifecycle events such as:

- request received
- token or authorization created
- state transition completed
- external side effect attempted or failed
- request rejected with reason
- response completed

### Logging

Add a canonical structured auth outcome log shape with consistent field names:

- `request_id`
- `endpoint`
- `event_type`
- `outcome`
- `reason_code`
- `http_status`
- `tenant_id`
- `email_hash`
- `pubkey_prefix`
- `latency_ms`

Handlers should stop hand-rolling inconsistent auth logs. Instead, they provide outcome data to a shared helper which emits the final structured log and writes the audit event.

### Metrics

Keep existing global counters, but add auth-specific labeled metrics:

- `keycast_auth_requests_total{endpoint,outcome,reason_code}`
- `keycast_auth_request_duration_seconds{endpoint,outcome}`
- `keycast_auth_audit_write_failures_total{endpoint}`
- `keycast_auth_email_send_failures_total{template}`

Label cardinality must stay bounded:

- no raw email
- no raw pubkey
- no request IDs

### Engineer tooling

Add engineer-facing lookup tooling in the Keycast repo. The first pass is CLI-only.

The lookup script should support:

- email
- pubkey
- npub
- request ID

It should output:

- matching user row(s)
- current account state
- recent `auth_events`
- a short derived summary of why login would fail right now

### Retention

Retain auth events for 30 days in Postgres.

Retention will be enforced by a cleanup job that deletes rows older than 30 days. The initial implementation will use Kubernetes CronJob infrastructure in `divine-iac-coreconfig`.

## Failure handling

Auth observability must not make auth less reliable.

- If the main auth transaction fails, auth still fails as normal.
- If the audit write fails independently, the request should fail open from the user perspective.
- On audit write failure, Keycast must:
  - emit an error log
  - increment `keycast_auth_audit_write_failures_total`

This keeps supportability from becoming an auth availability dependency.

## Data model details

### `auth_events` constraints and indexes

Required indexes:

- `occurred_at`
- `request_id`
- `(tenant_id, email)`
- `(tenant_id, pubkey)`
- `(tenant_id, endpoint, occurred_at)`

Recommended conventions:

- `event_type` and `outcome` should be stored as constrained text values
- `reason_code` should be machine-oriented and stable
- `metadata_json` should default to empty JSON

### Normalization rules

Keycast currently lowercases emails for login and forgot-password lookup, but does not trim whitespace. This implementation should not silently redesign auth semantics. It should record current behavior and make failures visible.

Follow-up work can tighten canonical-email normalization and uniqueness constraints once the support signal is in place.

## Infra and monitoring

`divine-iac-coreconfig` will add:

- a dedicated Keycast VMRule
- a dedicated Keycast Grafana dashboard
- an auth event retention CronJob

Initial alerts:

- high auth failure rate
- audit write failures
- password reset email send failures
- auth 5xx spikes
- root-route 5xx spikes

Initial dashboard views:

- auth request volume by endpoint
- auth success and failure rates
- failure reason breakdown
- forgot-password and reset funnel
- login funnel
- audit write failure count
- auth latency

## Verification strategy

Staging verification must cover:

- forgot-password for existing and nonexistent emails
- reset-password success
- reset-password invalid token
- login success
- login invalid password
- login user not found
- login email not verified
- headless login success and failure reasons
- at least one representative OAuth, claim, and admin flow
- response headers include `x-request-id`
- corresponding log rows and `auth_events` rows exist
- retention cleanup works on expired sample rows

## Rollout

1. Ship schema and code to staging.
2. Run migrations.
3. Exercise representative auth flows in staging.
4. Confirm dashboard panels and alerts populate.
5. Deploy to production during a low-risk window.
6. Run one real engineer lookup in production to confirm the support path.

## Non-goals

- no end-user support UI
- no ClickHouse pipeline yet
- no permanent retention/archive design
- no broad client rewrite in this change

## Follow-up

After the Postgres-backed hot path is working, mirror `auth_events` into ClickHouse for longer retention, aggregate analysis, and historical auth-funnel reporting.
