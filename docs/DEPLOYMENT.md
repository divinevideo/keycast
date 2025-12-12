# Keycast Deployment & Operations Guide

## Architecture Overview

**Current Status:** Fully hosted on Google Cloud Platform (GCP).
**Region:** `us-central1` (Primary)

Keycast is a Nostr key custody service. Users store their cryptographic keys here; apps request signing operations.

**System Components:**

| Component | What it does | Why it exists |
|-----------|--------------|---------------|
| **PostgreSQL** | Stores encrypted user keys | Keys encrypted at rest (AES-256-GCM) |
| **Cloud KMS** | Holds the master encryption key | Hardware-backed, keys never exported |
| **Redis** | Cluster coordination only | Hashring for distributing NIP-46 relay requests across instances |
| **Instance Cache** | Per-instance memory cache for decrypted keys | Avoids repeated KMS decryption; why session affinity matters |

**Two request paths:**
1. **HTTP RPC** - REST API calls. Session affinity routes repeat users to same instance for cache hits.
2. **NIP-46 Relays** - WebSocket connections to Nostr relays. All instances subscribe to same relays; Redis hashring determines which instance processes which request (others ignore).

**Key security point:** Decrypted keys exist only in instance memory. Redis is NOT used for secrets - only for cluster coordination. This is intentional.

---

## Current GCP Resources

The system currently relies on these specific GCP managed services.

| Resource | Name | Region/Location |
|----------|------|-----------------|
| Cloud Run | `keycast` | us-central1 |
| Cloud SQL | `keycast-db-plus` | us-central1 |
| Cloud KMS | `keycast-keys/master-key` | global |
| Memorystore | `keycast-redis` | us-central1 |
| Artifact Registry | `docker` | us-central1 |

### Cloud Run Service
*The application runtime environment.*
```
Service: keycast
Image: us-central1-docker.pkg.dev/openvine-co/docker/keycast:latest

Current settings (testing - will need adjustment for production):
  CPU: 4 vCPU
  Memory: 4 GiB
  Min instances: 3
  Max instances: 200
  Concurrency: 10
  Session affinity: enabled (CRITICAL)
  Execution: Gen2 + CPU boost
  VPC egress: all-traffic
```

### Cloud SQL
*Managed PostgreSQL.*
```
Instance: keycast-db-plus
Connection: openvine-co:us-central1:keycast-db-plus
Version: PostgreSQL 15
Tier: db-perf-optimized-N-4
max_connections: 250
Data cache: enabled
Connection pooling: Managed PgBouncer (max_pool_size: 200, max_client_connections: 2000, transaction mode)
```

### Cloud KMS
*Master Key Encryption Key (KEK).*
```
Key ring: global/keycast-keys
Key: master-key
Purpose: ENCRYPT_DECRYPT
Note: Code uses GCP-specific libraries (GcpKeyManager) to access this.
```

### Redis (Memorystore)
*Cluster Coordination.*
```
Instance: keycast-redis
Memory: 1 GB (BASIC tier)
Purpose: Cluster coordination (hashring, heartbeats)
```

---

## Connection Pool Math

```
PostgreSQL max_connections: 250
Cloud Run concurrency: 10 per instance
SQLX_POOL_SIZE: 10 per instance

Why pool_size = concurrency:
  - Worst case: all 10 concurrent requests need DB simultaneously
  - In practice, fewer connections needed because:
    - CPU-bound crypto runs off-pool (spawn_blocking)
    - Connections released between queries (except in transactions)
  - PgBouncer multiplexes: 200 instances × 10 = 2000 client connections → 200 backend

Rule: Start with pool_size = concurrency. Lower only if measured.
```

---

## Environment Variables

### Secrets (Secret Manager → env vars)

| Secret | Variable | Purpose |
|--------|----------|---------|
| `keycast-database-url` | `DATABASE_URL` | PostgreSQL connection with pooler |
| `keycast-ucan-secret` | `SERVER_NSEC` | Server nsec for token signing |
| `keycast-sendgrid-api-key` | `SENDGRID_API_KEY` | Email (disabled: `DISABLE_EMAILS=true`) |
| `keycast-redis-url` | `REDIS_URL` | Redis connection |

### Plain Variables (cloudbuild.yaml)

| Variable | Value |
|----------|-------|
| `USE_GCP_KMS` | `true` |
| `GCP_PROJECT_ID` | `openvine-co` |
| `ALLOWED_ORIGINS` | `https://login.divine.video` |
| `RUST_LOG` | `info` |
| `SQLX_POOL_SIZE` | `10` |
| `SQLX_STATEMENT_CACHE` | `100` |

---

## DNS

```
login.divine.video → CNAME → ghs.googlehosted.com (Cloudflare)
```

---

## Deployment Workflow

**Current state:** Manual only via `bun run deploy`. Git push triggers not configured.

**What happens:**
1. Cloud Build runs on E2_HIGHCPU_8 (~20 min)
2. Multi-stage Docker build (Rust + Bun frontend)
3. Push to Artifact Registry
4. Deploy to Cloud Run
5. Smoke tests (health check, CORS preflight)

---

## Database Migrations

Migrations do NOT run automatically. Manual process:

```bash
# Requires: cloud-sql-proxy, sqlx-cli
./tools/run-migrations.sh
```

Migration files: `database/migrations/NNNN_*.sql`

---

## Service Account

`972941478875-compute@developer.gserviceaccount.com`

Required roles:
- `roles/secretmanager.secretAccessor`
- `roles/cloudkms.cryptoKeyEncrypterDecrypter`
- `roles/cloudsql.client`

Redis access via VPC (no IAM needed for Memorystore BASIC).

---

## Backup & Recovery

### Database Backups
Cloud SQL automated backups are configured:
```
Automated backups: Enabled (daily)
Retention: 15 backups
Point-in-time recovery (PITR): Enabled
Transaction log retention: 14 days
```

**Restore options:**
1. **Point-in-time:** Restore to any timestamp within the last 14 days
2. **Backup snapshot:** Restore from any of the last 15 daily backups

```bash
# List available backups
gcloud sql backups list --instance=keycast-db-plus --project=openvine-co

# Restore to point in time (creates new instance)
gcloud sql instances clone keycast-db-plus keycast-db-restored \
  --point-in-time="2024-01-15T10:00:00Z" --project=openvine-co
```

### Application Rollback
Cloud Run maintains revision history for quick rollback:

```bash
# List recent revisions
gcloud run revisions list --service=keycast --region=us-central1 --project=openvine-co

# Rollback to previous revision
gcloud run services update-traffic keycast \
  --to-revisions=keycast-00150-abc=100 \
  --region=us-central1 --project=openvine-co
```

---

## Monitoring & Alerting

**Current state:** No custom alert policies or dashboards configured. Uses default Cloud Run metrics only.

**TODO:** Set up alerts for:
- Error rate spikes (5xx responses)
- Latency P95 thresholds
- Instance count approaching max (200)
- Database connection exhaustion
- KMS decryption failures

---

## Application Behavior Under Failure

| Dependency | At Startup | During Runtime |
|------------|------------|----------------|
| **Redis unreachable** | Hard failure, app exits | Exponential backoff retry (heartbeat), 1s reconnect loop (Pub/Sub). Hashring uses stale data until reconnected. App continues but may misroute NIP-46 requests. |
| **KMS unavailable** | Hard failure if `USE_GCP_KMS=true` | Cached keys still work. New decryptions retry 3x with exponential backoff (100ms, 200ms, 400ms), then fail. |
| **PostgreSQL down** | 5 retries with exponential backoff (1s, 2s, 4s, 8s), then exits | Immediate 500 error per request. No circuit breaker. Pool auto-reconnects when DB returns. |

**Key insight:** The app degrades gracefully for Redis/KMS partial failures but has no circuit breaker for database issues.

---

## Secrets and Config Reload

**No hot reload.** All configuration is read at startup from environment variables.

- Changing any secret or env var requires a **new Cloud Run revision** (redeploy)
- Secret rotation procedure: Update Secret Manager → trigger deploy → new instances pick up new values
- Live updates that DON'T require redeploy:
  - OAuth authorization creation/revocation (API→Signer channel)
  - Cluster membership changes (Redis Pub/Sub)

---

## Logging

**Format:**
- Production (`NODE_ENV=production`): Structured JSON (GCP Cloud Logging native)
- Development: Plain text

**Request Tracing:**
Each HTTP request gets a `trace_id` (8-char UUID) automatically attached to all logs within that request.
- Clients can pass `x-trace-id` header for correlation across services
- If not provided, server generates one automatically

**TODO:** Integrate trace_id from mobile (keycast_flutter) and web (keycast-login) clients:
- Clients should generate trace_id on request initiation
- Pass via `x-trace-id` header for full request correlation
- Enables tracing from UI action → API → signer daemon

**Key fields in structured logs:**
```json
{"level":"INFO","span":{"name":"request","trace_id":"a1b2c3d4","method":"GET","uri":"/api/user"},"message":"Processing request"}
```

**What's logged:**
- Instance lifecycle events (startup, shutdown)
- Error details with stack context
- NIP-46 request flow (received, rejected, processed)
- Cache hit/miss events (at debug level)
- Request trace_id for correlation

**What's NOT logged:**
- User identifiers in HTTP request logs
- Secrets are never logged

**Log queries (Cloud Logging):**
```bash
# Errors only
resource.type="cloud_run_revision" severity>=ERROR

# Specific instance
resource.labels.revision_name="keycast-00151-abc"

# NIP-46 activity
jsonPayload.message=~"NIP-46"

# Trace a specific request (use trace_id from x-trace-id header or log output)
jsonPayload.span.trace_id="a1b2c3d4"
```

---

## Metrics & Observability

**Prometheus endpoint:** `GET /api/metrics`

Returns Prometheus text format, no auth required. Safe to scrape frequently (in-memory counters, no DB queries).

**Available metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `keycast_cache_hits_total` | counter | Handler found in memory cache |
| `keycast_cache_misses_total` | counter | Handler loaded from DB |
| `keycast_cache_size` | gauge | Current handlers in cache |
| `keycast_nip46_requests_total` | counter | Total NIP-46 requests received |
| `keycast_nip46_rejected_hashring_total` | counter | Requests assigned to different instance |
| `keycast_nip46_processed_total` | counter | Successfully processed |
| `keycast_nip46_queue_dropped_total` | counter | Dropped due to backpressure |
| `keycast_http_rpc_requests_total` | counter | HTTP RPC requests to `/api/nostr` |
| `keycast_http_rpc_auth_errors_total` | counter | Auth failures |
| `keycast_registrations_total` | counter | User registrations |
| `keycast_logins_total` | counter | Successful logins |
| `keycast_login_failures_total` | counter | Failed login attempts |

**Alert recommendations:**
- `keycast_nip46_queue_dropped_total` increasing → system overloaded, scale up
- `keycast_cache_misses_total` high relative to hits → session affinity may be broken
- `keycast_http_rpc_auth_errors_total` spike → possible attack or client misconfiguration

**Metrics aggregation:**

Cloud Run provides **built-in aggregated metrics** automatically (request count, latency, CPU, memory, instance count). These are sufficient for scaling decisions and basic alerting—no setup required.

The custom Prometheus metrics at `/metrics` (cache hits, NIP-46 stats, auth errors) are **per-instance only**. Options for aggregating these:

1. **Log-based metrics** (simplest) - Create custom metrics from structured logs in Cloud Logging. No code changes, works now.
2. **Managed Prometheus** - Google Cloud Managed Service for Prometheus can scrape all instances. More infrastructure.
3. **Push to Cloud Monitoring** - Add OTLP/Cloud Monitoring client to push metrics. Requires code changes.

For a test environment, Cloud Run's built-in metrics + log queries for custom data is probably sufficient.

---

## Performance Characteristics

**Mixed workload.** Crypto operations are CPU-bound, but significant I/O exists throughout the request paths.

```
CPU-bound:
  - secp256k1 signing, NIP-44/NIP-04 encrypt/decrypt
  - Uses spawn_blocking to avoid blocking async runtime

I/O-bound (Network):
  - NIP-46 relay WebSocket traffic (receive requests, send responses)
  - Redis Pub/Sub for hashring coordination + heartbeats
  - KMS API calls on cache miss

I/O-bound (Database):
  - OAuth flow queries, authorization lookups on cache miss
  - Cold start loads all authorizations

Workers: 2× CPU cores (min 8), Queue: 4096 items with backpressure
```

**Scaling recommendation:** Cloud Run autoscales based on per-instance CPU utilization and request concurrency. Requests are routed away from high-CPU instances even if concurrency limit isn't reached. Session affinity is broken when an instance hits max CPU—requests go to other instances. Crypto signing dominates CPU under sustained load. However, significant I/O-bound work exists:
- NIP-46: WebSocket relay traffic + Redis hashring lookups
- Cold caches: DB queries + KMS decryption
- OAuth flows: DB session/authorization lookups

Monitor **P95 latency** and **cache miss rate** alongside CPU. High latency with low CPU suggests I/O saturation—check Redis, relays, or session affinity (cache misses).

- Current concurrency: 10 requests/instance
- If `keycast_nip46_queue_dropped_total` increases, add instances
- Memory is not typically the bottleneck (4 GiB); primary consumer is the handler cache (decrypted keys, auth metadata)

**Latency expectations:**
- HTTP RPC signing: Fast (cache hit) to slower (cache miss requires KMS decrypt)
- NIP-46 relay signing: Above + network RTT to relays (varies by relay latency)

Actual latencies depend on network conditions, KMS region, and relay performance.
Cache hits are typically an order of magnitude faster than cache misses.

---

## Operational Requirements (Platform Agnostic)

The current GCP Cloud Run deployment satisfies these requirements through native configuration. If migrating to another provider or orchestrator, these architectural constraints must be manually replicated.

### Health Checks & Probes
The application exposes standard endpoints suitable for Liveness and Readiness probes:

- **Startup/Liveness:** `/health` or `/healthz/startup` (Returns 200 OK)
- **Readiness:** `/healthz/ready` (Returns 200 OK)

### Graceful Shutdown
The application handles `SIGTERM` and `SIGINT` signals to ensure zero-downtime deployments:
- **Stop Signal:** Listens for `SIGTERM`.
- **Drain Logic:**
  - Stops accepting new connections.
  - Waits up to **15 seconds** for API requests to drain.
  - Waits up to **10 seconds** for background tasks (Signer relay connections) to finish.
  - Closes DB connections.
- **Requirement:** Ensure the platform's termination grace period is at least **30s** to accommodate this 25s max drain sequence.

### Session Affinity (Sticky Sessions)
**CRITICAL:** The application uses an in-memory cache for decrypted keys to reduce KMS costs and latency.
- **Requirement:** You **MUST** enable Session Affinity (Sticky Sessions) at the Load Balancer / Ingress level.
- **Why:** Without it, requests for the same user might land on different instances, causing frequent cache misses and expensive re-decryption calls to Cloud KMS.
- *Current GCP Implementation:* Enabled in Cloud Run service settings.

### Resources
Minimum resource requirements per instance:
- **CPU:** 1-4 vCPU (current: 4 vCPU for testing)
- **Memory:** 2-4 GiB (current: 4 GiB for testing)

### Encryption Dependency
The application code (`GcpKeyManager`) currently has a hard dependency on **Google Cloud KMS** for the master key.
- **Migration Note:** If moving compute off GCP, you must either:
    1. Continue using GCP KMS (ensure credentials/connectivity allow it).
    2. Rewrite the `KeyManager` implementation to use a different provider (AWS KMS, Vault, etc.).

---

## Quick Reference

| Situation | What to check |
|-----------|---------------|
| High latency, low CPU | Redis, relay connectivity, or cache misses (session affinity) |
| High CPU | Expected under signing load; scale horizontally |
| `queue_dropped` increasing | System overloaded, add instances |
| `cache_misses` high vs hits | Session affinity broken at LB |
| Auth errors spiking | Possible attack or client misconfiguration |
| Config change needed | Requires redeploy (no hot reload) |
| DB failures cascading | No circuit breaker; expect immediate 500s |

**Critical settings:**
- Session affinity: **mandatory** (cache efficiency)
- Termination grace period: **≥30s** (25s drain sequence)
- All config via env vars at startup (no hot reload)
