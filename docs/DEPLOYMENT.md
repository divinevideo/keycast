# Keycast Deployment & Operations Guide

Keycast is mid-migration from the current production Cloud Run service to the shared GKE/ArgoCD platform.

| Environment | Current runtime | Deploy path |
|-------------|-----------------|-------------|
| production (`login.divine.video`) | Cloud Run service `keycast` in `openvine-co`, `us-central1` | `bun run deploy` -> Cloud Build -> Cloud Run |
| staging (`login.staging.divine.video`) | GKE | GitHub Actions -> `divine-iac-coreconfig` dispatch/PR -> ArgoCD |
| poc (`login.poc.dvines.org`) | GKE | GitHub Actions -> `divine-iac-coreconfig` dispatch/PR -> ArgoCD |

The `divine-iac-coreconfig` repo has a staged production overlay for Keycast, but Cloud Run remains authoritative for production traffic until the migration is explicitly completed. Do not use the production overlay's pinned image tag as proof of what is serving `login.divine.video` today.

The former test environment has been decommissioned in the current GKE workflow. Older docs that mention `dv-platform-test` or a `test` overlay are historical unless the IaC repo reintroduces that environment.

---

## System shape

| Component | Purpose | Notes |
|-----------|---------|-------|
| PostgreSQL | Stores encrypted user keys and auth state | Cloud Run production uses Cloud SQL; GKE envs use the platform database setup from IaC. |
| KMS provider | Holds the master encryption key | Production uses GCP KMS through `USE_GCP_KMS=true`; the binary also supports explicit `KMS_PROVIDER=file`, `gcp`, or `aws`. |
| Redis | Cluster coordination | Used for hashring membership, heartbeats, and Pub/Sub. Redis is not used for plaintext secrets. |
| In-memory handler cache | Caches decrypted handlers per instance/pod | Session affinity materially improves cache hit rate and KMS latency/cost. |

Two request paths matter operationally:

1. HTTP API/RPC requests land on the web/API server and use the per-instance handler cache.
2. NIP-46 signer traffic arrives through relay connections; all instances subscribe to the relay set, and the Redis-backed hashring decides which instance processes each request.

Plaintext key material must stay inside the `core` key-manager abstractions and live process memory only.

---

## Production: Cloud Run

Production is deployed with:

```bash
bun run deploy
```

That script submits `cloudbuild.yaml` to project `openvine-co`.

### Cloud Build sequence

Current `cloudbuild.yaml` does the following:

1. Builds the Docker image with `BUILD_VERSION=${BUILD_ID}` and tags it as `us-central1-docker.pkg.dev/${PROJECT_ID}/docker/keycast:latest`.
2. Pushes the `:latest` image.
3. Runs database migrations by executing the Cloud Run Job `keycast-migrate` with `gcloud run jobs execute keycast-migrate --wait`.
4. Deploys the Cloud Run service `keycast`.
5. Runs smoke checks:
   - `GET /healthz/ready`
   - CORS preflight for `/api/auth/register`
   - CORS preflight for `/api/headless/login`

Cloud Build only publishes `:latest` for the Cloud Run path. It does not push a separate `:$BUILD_ID` tag in this pipeline.

### Cloud Run service settings

| Setting | Value |
|---------|-------|
| Service | `keycast` |
| Image | `us-central1-docker.pkg.dev/openvine-co/docker/keycast:latest` |
| Region | `us-central1` |
| Port | `3000` |
| CPU / memory | `4` vCPU / `4Gi` |
| Timeout | `300s` request timeout |
| Min / max instances | `3` / `200` |
| Concurrency | `50` |
| Execution environment | Gen2, CPU boost, no CPU throttling |
| Session affinity | enabled |
| HTTP/2 | enabled |
| Startup probe | `GET /healthz/startup` on port 3000 |
| Liveness probe | `GET /livez` on port 3000 |
| Cloud SQL | `openvine-co:us-central1:keycast-db-plus` |
| VPC egress | private ranges only |

Cloud Run does not have readiness-probe-driven endpoint removal during shutdown. The production Cloud Run env vars set the shutdown budget to fit Cloud Run's shorter SIGTERM-to-SIGKILL window.

### Production secrets

| Secret Manager secret | Env var |
|-----------------------|---------|
| `keycast-database-url` | `DATABASE_URL` |
| `keycast-ucan-secret` | `SERVER_NSEC` |
| `keycast-sendgrid-api-key` | `SENDGRID_API_KEY` |
| `keycast-redis-url` | `REDIS_URL` |
| `keycast-service-token` | `KEYCAST_SERVICE_TOKEN` |

There is no Cloud Run Sentry secret or `sentry-cli` release step in the current Cloud Build file.

### Production plain env

These are set by `cloudbuild.yaml --set-env-vars`:

| Variable | Value |
|----------|-------|
| `NODE_ENV` | `production` |
| `USE_GCP_KMS` | `true` |
| `GCP_PROJECT_ID` | `${PROJECT_ID}` (`openvine-co` when deployed by `bun run deploy`) |
| `ALLOWED_ORIGINS` | `https://login.divine.video,https://divine.video,https://*.openvine-app.pages.dev` |
| `ALLOWED_TENANT_DOMAINS` | `login.divine.video` |
| `APP_URL` | `https://login.divine.video` |
| `FROM_EMAIL` | `noreply@divine.video` |
| `RUST_LOG` | `info` |
| `ENABLE_EXAMPLES` | `true` |
| `SQLX_STATEMENT_CACHE` | `100` |
| `SQLX_POOL_SIZE` | `50` |
| `ALLOWED_PUBKEYS` | configured in `cloudbuild.yaml` |
| `BUNKER_RELAYS` | `wss://relay.divine.video,wss://relay.primal.net,wss://relay.nsec.app,wss://nos.lol` |
| `ENABLE_DIVINE_NAMES` | `true` |
| `SHOW_TEAMS_FUNCTIONALITY` | `true` |
| `SHUTDOWN_GRACE_PERIOD_CEILING_SECS` | `10` |
| `SHUTDOWN_PRE_DRAIN_SECS` | `0` |
| `SHUTDOWN_HTTP_DRAIN_SECS` | `3` |
| `SHUTDOWN_SIGNER_DRAIN_SECS` | `3` |
| `SHUTDOWN_TEARDOWN_MARGIN_SECS` | `4` |

Relay NIP-46 admission has optional per-instance tuning controls. Defaults are
used when these variables are unset or invalid:

| Variable | Default | Purpose |
|----------|---------|---------|
| `RELAY_WORKER_COUNT` | `max(CPUs, 4) * 2` | Concurrent relay request workers |
| `RELAY_QUEUE_CAPACITY` | `4096` | Total queued relay requests |
| `RELAY_FLOW_QUEUE_LIMIT` | `64` | Maximum queued requests for one target or client pubkey |
| `NIP46_LOOKUP_CONCURRENCY` | `16` | Concurrent cache-miss authorization lookups |
| `NIP46_NEGATIVE_CACHE_SIZE` | `10000` | Maximum cached unknown bunker pubkeys |
| `NIP46_NEGATIVE_CACHE_TTL_SECS` | `30` | Unknown-bunker cache lifetime |

### Production GCP resources

| Resource | Name |
|----------|------|
| Cloud Run service | `keycast` |
| Cloud SQL | `keycast-db-plus`; connection configured by Cloud Build, engine details managed outside this repo |
| Cloud KMS | key ring `keycast-keys`, key `master-key`, location `global` |
| Redis | URL injected from the `keycast-redis-url` Secret Manager secret; instance details managed outside this repo |
| Artifact Registry | `us-central1-docker.pkg.dev/openvine-co/docker` |
| Runtime service account | `972941478875-compute@developer.gserviceaccount.com` |

The service account needs Secret Manager access for runtime secrets, Cloud KMS encrypt/decrypt, and Cloud SQL client access. Redis access is through the VPC path.

### Production rollback

Cloud Run keeps revision history:

```bash
gcloud run revisions list \
  --service=keycast \
  --region=us-central1 \
  --project=openvine-co

gcloud run services update-traffic keycast \
  --to-revisions=<revision-name>=100 \
  --region=us-central1 \
  --project=openvine-co
```

### Production logs

```bash
bun run logs
bun run logs:watch

gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="keycast"' \
  --limit=50 \
  --project=openvine-co
```

---

## Non-production: GKE and ArgoCD

POC and staging currently run on GKE through `divine-iac-coreconfig`. The production GKE overlay exists, but it is staged until production traffic moves off Cloud Run.

### Build and dispatch flow

`.github/workflows/build-test-push.yaml` handles the shared GKE image flow:

1. On PRs, run Rust tests, clippy, and format checks.
2. On pushes to `main` and release tags, build one local Docker image with Buildx.
3. Push to Artifact Registry:
   - POC registry on `main`
   - staging registry on `main`
   - production registry only on `v*` tags or `workflow_dispatch` with `include_production=true`
4. Dispatch `image-deploy` to `divine-iac-coreconfig` with the short source SHA.
5. IaC automation updates the matching overlays and ArgoCD applies the merged IaC change.

The former test push is intentionally removed from this workflow because that GCP project/environment is decommissioned.

### Current GKE manifests

Keycast manifests live under `divine-iac-coreconfig/k8s/applications/keycast/`. The table below is the full set: the eight resources listed in `base/kustomization.yaml`, plus each overlay and the extra manifests its `resources:` list pulls in.

| Path | Purpose |
|------|---------|
| `base/namespace.yaml` | `Namespace` `identity`, ArgoCD-managed, annotated `linkerd.io/inject: enabled` |
| `base/serviceaccount.yaml` | `ServiceAccount` `keycast`, annotated `iam.gke.io/gcp-service-account` for Workload Identity; the GCP service account is patched per overlay |
| `base/deployment.yaml` | `Deployment` in namespace `identity`, sync wave 2 |
| `base/service.yaml` | `ClusterIP` Service on port 3000 |
| `base/httproute.yaml` | HTTP-to-HTTPS redirects and HTTPS routes for login and entryway hosts |
| `base/db-migrate.yaml` | ArgoCD Sync hook, sync wave 1, for DB bootstrap and `./keycast --migrate` |
| `base/external-secret.yaml` | ExternalSecret for `KEYCAST_ATPROTO_TOKEN` |
| `base/auth-events-retention-cronjob.yaml` | Daily 03:17 CronJob that prunes `auth_events` older than 30 days |
| `overlays/poc/kustomization.yaml` | POC project, hostnames, KMS key ring, image tag, relays, Redis |
| `overlays/staging/kustomization.yaml` | staging project, hostnames, KMS key ring, image tag, relays, Redis, resources |
| `overlays/staging/legacy-hostname-redirects.yaml` | Additive HTTPRoutes claiming `login.staging.dvines.org` and `entryway.staging.dvines.org`, 301 to the matching `.staging.divine.video` hosts |
| `overlays/production/kustomization.yaml` | staged production GKE config; not live for prod traffic |
| `overlays/production/hpa.yaml` | `HorizontalPodAutoscaler` for `keycast`, 3-20 replicas at 70% CPU / 75% memory |
| `overlays/production/pdb.yaml` | `PodDisruptionBudget` for `keycast` with `minAvailable: 2` |

### GKE probes

Current IaC config:

| Probe | Path | Notes |
|-------|------|-------|
| startup | `/healthz/startup` | Fast startup endpoint. |
| liveness | `/health` | Current IaC still uses `/health` with an inline note to move to `/livez` after all overlays are on images that contain `/livez`. |
| readiness | `/healthz/ready` | Checks DB readiness and returns 503 during shutdown pre-drain. |

The runtime also exposes `/livez`; Cloud Run already uses it for liveness. Do not use `/health` as readiness. `/health` returns a general 200 OK and does not participate in readiness-based draining.

### GKE shutdown requirement

The binary's built-in GKE-sized shutdown defaults are:

```text
pre_drain 15s + http_drain 40s + signer_drain 10s + teardown_margin 10s = 75s
```

That default is intended to fit a Kubernetes `terminationGracePeriodSeconds: 75`. The current base `Deployment` does not set `terminationGracePeriodSeconds`, so Kubernetes defaults it to 30s. Before moving production traffic to GKE, the IaC overlay must either:

- set `terminationGracePeriodSeconds: 75`, or
- set explicit `SHUTDOWN_*` env vars whose total budget fits the actual pod grace period.

Leaving the current pod default at 30s while using the binary's 75s default risks SIGKILL during a rollout drain.

### GKE session affinity gap

The current GKE `Service` is `ClusterIP` and does not set `spec.sessionAffinity`. Cloud Run has session affinity enabled. Before moving production traffic to GKE, choose and configure the GKE equivalent, such as `Service.spec.sessionAffinity: ClientIP` or a Gateway/backend policy appropriate for the platform.

Without stickiness, Keycast still works, but the in-memory decrypted-handler cache has a lower hit rate. That increases KMS decrypts and can add latency on cache misses.

### GKE overlay summary

Verified from the current IaC repo:

| Env | GCP project | Hosts | Replicas | KMS key ring | Image registry |
|-----|-------------|-------|----------|--------------|----------------|
| poc | `rich-compiler-479518-d2` | `login.poc.dvines.org`, `entryway.poc.dvines.org` | 1 | `app-keys-poc` | `containers-poc` |
| staging | `dv-platform-staging` | `login.staging.divine.video`, `entryway.staging.divine.video` | 2 | `app-keys-staging` | `containers-staging` |
| production (staged) | `dv-platform-prod` | `login.divine.video`, `entryway.divine.video` | 3, HPA 3-20 | `app-keys-production` | `containers-production` |

Base resources are `128Mi`/`100m` requests and `512Mi`/`500m` limits. Staging patches to `256Mi`/`200m` requests and `1Gi`/`1000m` limits. Staged production patches to `2Gi`/`2000m` requests and `4Gi`/`4000m` limits and adds an HPA with min 3, max 20.

### GKE environment variables and secrets

The base deployment reads these secrets:

| Kubernetes Secret | Env var |
|-------------------|---------|
| `keycast-db-credentials` | `DATABASE_URL` |
| `keycast-server-nsec` | `SERVER_NSEC` |
| `keycast-sendgrid-api-key` | `SENDGRID_API_KEY` |
| `keycast-atproto-runtime` | `KEYCAST_ATPROTO_TOKEN` |

The migration job also reads:

| Kubernetes Secret | Env var | Scope |
|-------------------|---------|-------|
| `postgres-superuser-credentials` | `SUPERUSER_URL` | bootstrap init container only |
| `keycast-db-credentials` | `DATABASE_URL_DIRECT` | migration container |

The Deployment sets or patches these runtime env vars:

| Variable | Notes |
|----------|-------|
| `USE_GCP_KMS` | `true` |
| `GCP_PROJECT_ID` | patched per environment |
| `GCP_KMS_LOCATION` | `us-central1` |
| `GCP_KMS_KEY_RING` | patched per environment |
| `GCP_KMS_KEY_NAME` | `keycast-master-key` |
| `ALLOWED_ORIGINS` | patched per environment |
| `BUNKER_RELAYS` | patched per environment |
| `FROM_EMAIL`, `FROM_NAME`, `BASE_URL`, `APP_URL` | patched per environment |
| `VITE_DOMAIN`, `VITE_NDK_EXPLICIT_RELAYS`, `VITE_NDK_BUNKER_RELAYS` | frontend runtime injection |
| `ALLOWED_PUBKEYS` | patched per environment |
| `ALLOWED_TENANT_DOMAINS` | base value is `login.divine.video`; POC and staging patch it |
| `RUST_LOG` | `info` |
| `NODE_ENV` | `production` |
| `SQLX_POOL_SIZE` | `50` |
| `SQLX_STATEMENT_CACHE` | `100` |
| `DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL` | in-cluster control plane URL |
| `DIVINE_HANDLE_DOMAIN` | `divine.video` |
| `ATPROTO_ENTRYWAY_ENABLED` | `true` in current IaC; not currently consumed by the server |
| `ATPROTO_ENTRYWAY_ORIGIN` | patched per environment; used by server metadata |
| `ATPROTO_ENTRYWAY_HOSTS` | patched per environment; not currently consumed by the server |
| `REDIS_URL` | added by overlays, points at in-cluster Redis DB 1 |
| `ENABLE_DIVINE_NAMES` | staged production overlay only |

Current GKE manifests do not set Sentry env vars.

### GKE migrations

The GKE path runs migrations as an ArgoCD Sync hook before the Deployment rolls:

- `keycast-db-migrate` Job, sync wave 1
- `keycast` Deployment, sync wave 2
- bootstrap init container uses `postgres:16-alpine` and `SUPERUSER_URL`
- migration container runs `./keycast --migrate`

If the migration job fails, ArgoCD should not roll the wave-2 Deployment.

### GKE rollback

Rollback is a GitOps operation:

1. Revert or edit the image tag in the relevant `divine-iac-coreconfig/k8s/applications/keycast/overlays/<env>/kustomization.yaml`.
2. Merge the IaC change.
3. Let ArgoCD sync the overlay.

For a manual pod recycle after config/secret changes:

```bash
kubectl rollout restart deployment/keycast -n identity
```

---

## Database backups

Production Cloud SQL has automated backups and PITR configured outside this repo. Useful commands:

```bash
gcloud sql backups list \
  --instance=keycast-db-plus \
  --project=openvine-co

gcloud sql instances clone keycast-db-plus keycast-db-restored \
  --point-in-time="2024-01-15T10:00:00Z" \
  --project=openvine-co
```

---

## Config and secret rotation

Configuration is read at startup. There is no hot reload.

- Cloud Run: update Secret Manager or env config, then run `bun run deploy` so a new revision starts with the new values.
- GKE: update the source secret/config in the platform, wait for External Secrets where applicable, then roll the Deployment if the pods do not restart automatically.

Live updates that do not require a process restart:

- OAuth authorization create/revoke through the API/signer channel
- cluster membership changes through Redis Pub/Sub

---

## Failure modes

| Dependency | Startup behavior | Runtime behavior |
|------------|------------------|------------------|
| Redis unavailable | Hard failure, app exits | Heartbeat and Pub/Sub reconnect loops retry; stale hashring data can misroute NIP-46 requests while HTTP may continue. |
| KMS unavailable | Hard failure when using `gcp` or `aws` provider | Cached keys still work; cache misses retry and then fail. |
| Postgres unavailable | startup retries then exits | Requests needing DB return errors; pool reconnects when the database recovers. |
| ATProto control plane unavailable | invalid/missing URL logs a warning and Keycast still starts | ATProto enablement endpoints fail closed with 503; other routes continue. |

---

## ATProto entryway

ATProto OAuth entryway routes are registered unconditionally by the server. The only entryway env var the server currently reads is `ATPROTO_ENTRYWAY_ORIGIN`, which is used when generating OAuth authorization-server metadata. If unset, metadata generation falls back to `APP_URL` or `VITE_DOMAIN`.

Current IaC also sets `ATPROTO_ENTRYWAY_ENABLED` and `ATPROTO_ENTRYWAY_HOSTS`, but those values are not consumed by the server today. Changing them does not gate the routes or host matching in Keycast.

PAR state is stored in shared Postgres in `atproto_oauth_sessions` with a unique `request_uri`, so PAR lookup is replica-safe.

The current per-replica safety gap is replay protection: DPoP and client assertion replay caches are in-memory `DashMap`s. A replay that reaches a different pod inside the replay window may not be caught. Before production GKE cutover, decide whether that risk is acceptable or move those replay caches to shared storage.

---

## Logging

Production (`NODE_ENV=production`) emits structured JSON logs. Development emits plain text logs.

Every HTTP request gets a request/trace id, either from the client `x-trace-id` header or generated server-side.

Useful Cloud Logging queries:

```text
# Cloud Run production
resource.type="cloud_run_revision"
resource.labels.service_name="keycast"
severity>=ERROR

# GKE
resource.type="k8s_container"
resource.labels.namespace_name="identity"
resource.labels.container_name="keycast"
severity>=ERROR

# Request trace
jsonPayload.span.trace_id="a1b2c3d4"
```

Never log secrets, plaintext key material, or plaintext Nostr private keys.

---

## Metrics

Prometheus metrics are exposed at:

```text
GET /api/metrics
```

The endpoint is unauthenticated and reads only in-process state, so a scrape does no database or Redis work. It emits counters, gauges, and one histogram. The table below is the full set of families. Every family's `# HELP`/`# TYPE` lines are written on every scrape; the four label-keyed families at the end of the table carry no samples until the matching code path has run.

| Metric | Type | Description |
|--------|------|-------------|
| `keycast_cache_hits_total` | counter | Handler found in memory cache |
| `keycast_cache_misses_total` | counter | Handler loaded from DB |
| `keycast_cache_size` | gauge | Current handlers in cache |
| `keycast_nip46_requests_total` | counter | NIP-46 requests received |
| `keycast_nip46_rejected_hashring_total` | counter | Requests assigned to another instance |
| `keycast_nip46_rejected_hashring_prequeue_total` | counter | Peer-owned requests rejected before local queue admission |
| `keycast_nip46_handler_not_found_total` | counter | Requests whose authorization was not found |
| `keycast_nip46_processed_total` | counter | Requests processed successfully |
| `keycast_nip46_queue_dropped_total` | counter | Requests dropped under backpressure |
| `keycast_nip46_queue_closed_total` | counter | Requests rejected because the queue is closed during graceful shutdown |
| `keycast_nip46_tombstone_responses_total` | counter | Error responses sent for revoked or expired authorizations |
| `keycast_nip46_queue_depth` / `keycast_nip46_queue_capacity` | gauge | Current and configured relay queue occupancy |
| `keycast_nip46_queue_wait_seconds` | summary | Relay queue wait time |
| `keycast_nip46_workers_active` | gauge | Relay workers currently processing requests |
| `keycast_nip46_worker_duration_seconds` | summary | Relay worker processing time |
| `keycast_nip46_noisy_flow_shed_total` | counter | Requests shed at target/client flow limits, labelled `flow` |
| `keycast_nip46_lookup_in_flight` / `keycast_nip46_lookup_limit` | gauge | Current and configured authorization lookup concurrency |
| `keycast_nip46_lookup_database_total` / `keycast_nip46_lookup_errors_total` | counter | Coalesced authorization DB lookups and failures |
| `keycast_nip46_negative_cache_hits_total` / `keycast_nip46_negative_cache_size` | counter / gauge | Unknown-target cache use and occupancy |
| `keycast_nip46_activity_queued_total` | counter | Relay activity updates accepted by the coalescing writer |
| `keycast_nip46_activity_dropped_total` | counter | Activity updates lost at bounded writer boundaries, labelled `reason` |
| `keycast_nip46_activity_write_failures_total` / `keycast_nip46_activity_pending` | counter / gauge | Activity writer failures and retained authorization IDs |
| `keycast_http_rpc_requests_total` | counter | HTTP RPC requests to `/api/nostr` |
| `keycast_http_rpc_auth_errors_total` | counter | HTTP RPC auth failures |
| `keycast_http_rpc_cache_hits_total` | counter | HTTP RPC handler found in memory cache |
| `keycast_http_rpc_cache_misses_total` | counter | HTTP RPC handler loaded from DB |
| `keycast_http_rpc_cache_size` | gauge | Current HTTP RPC handlers in cache |
| `keycast_http_rpc_success_total` | counter | HTTP RPC requests processed successfully |
| `keycast_registrations_total` | counter | User registrations |
| `keycast_logins_total` | counter | Successful logins |
| `keycast_login_failures_total` | counter | Failed logins |
| `keycast_account_deletions_total` | counter | Account deletions |
| `keycast_oauth_authorizations_created_total` | counter | OAuth authorizations created |
| `keycast_oauth_authorizations_revoked_total` | counter | OAuth authorizations revoked |
| `keycast_auth_requests_total` | counter | Auth request outcomes, labelled `endpoint`, `outcome`, `reason_code` |
| `keycast_auth_request_duration_seconds` | histogram | Auth request latency, labelled `endpoint` and `outcome`; exposed as `_bucket`/`_sum`/`_count` series |
| `keycast_auth_audit_write_failures_total` | counter | Auth audit writes that failed without failing the user request, labelled `endpoint` |
| `keycast_auth_email_send_failures_total` | counter | Auth email send failures, labelled `template` |

High `keycast_cache_misses_total` relative to hits usually points at session affinity or cold-cache behavior. Increasing `keycast_nip46_queue_dropped_total` means the signer path is overloaded.

Relay NIP-46 traffic arrives over WebSockets and does not pass through Keycast's
HTTP ingress controls. Diagnose it separately from HTTP pressure. Queue depth and
wait show backlog; noisy-flow shedding shows isolated target/client bursts;
lookup concurrency, errors, and negative-cache metrics show unknown-target
pressure; activity metrics show whether best-effort usage accounting is being
coalesced or lost. During launch, high CPU or sustained relay shedding should be
handled first by dashboard-level CPU inspection and manual instance scaling.
Change the tuning controls only after measurements show which bounded stage is
the bottleneck.

---

## Performance characteristics

CPU-bound work:

- secp256k1 signing
- NIP-44/NIP-04 encrypt/decrypt
- login bcrypt verification through `spawn_blocking`
- registration bcrypt hashing in the background queue

I/O-bound work:

- relay WebSocket traffic
- Redis Pub/Sub and heartbeats
- KMS API calls on cache miss
- database queries for auth/session/OAuth/user flows

Cloud Run currently targets 50 concurrent requests per instance and `SQLX_POOL_SIZE=50`. Use cache hit rate, p95 latency, CPU, and queue drops together when evaluating scaling.

---

## Quick reference

| Situation | Check |
|-----------|-------|
| Which platform serves production | Cloud Run service `keycast` in `openvine-co` |
| Current Cloud Run revision | `gcloud run services describe keycast --region=us-central1 --project=openvine-co --format='value(status.latestReadyRevisionName)'` |
| Current GKE image | `kubectl -n identity get deployment keycast -o jsonpath='{.spec.template.spec.containers[0].image}'` |
| ArgoCD sync state | ArgoCD app for the relevant keycast overlay in `divine-iac-coreconfig` |
| High latency, low CPU | cache misses, Redis, relay health, KMS latency |
| `keycast_nip46_queue_dropped_total` increasing | signer path overloaded; scale or reduce load |
| Noisy-flow shedding increasing with low queue depth | one target or client is being isolated; unrelated work retains headroom |
| Lookup errors increasing | Postgres/KMS cache-miss path is failing; misses are not cached as absence |
| Relay activity drops increasing | activity accounting is shedding or shutdown flush failed; signing remains bounded |
| Cache misses high vs hits | session affinity or cold-cache problem |
| Config or secret changed | roll Cloud Run revision or GKE pods |
| Before production GKE cutover | fix/verify 75s shutdown budget, session affinity, probe paths, ATProto entryway multi-replica behavior, production overlay tag |
