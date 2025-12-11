# Keycast Deployment Guide

## Production Services

### Current Active Service

- **`keycast`** (PRODUCTION - login.divine.video)
  - Runs both API + Signer daemon in one container
  - Domain: https://login.divine.video
  - Memory: 4Gi, CPU: 4
  - Port: 3000
  - Instance concurrency: 10
  - Min instances: 3, Max instances: 200

### Deprecated Services (DO NOT USE)

- **`keycast-unified`** - Old service name, replaced by `keycast`
- **`keycast-oauth`** - Old API-only service
- **`keycast-oauth-server`** - Duplicate/abandoned service
- **`keycast-signer`** - Old standalone signer

## Deployment Process

### Via cloudbuild.yaml (Automated)

```bash
gcloud builds submit --config=cloudbuild.yaml .
# Or via bun:
bun run deploy
```

This builds the Docker image and deploys to `keycast` service.

### Manual Deployment

```bash
gcloud run deploy keycast \
  --image=us-central1-docker.pkg.dev/openvine-co/docker/keycast:latest \
  --region=us-central1 \
  [... other flags from cloudbuild.yaml]
```

## Database Configuration

### Cloud SQL PostgreSQL

Production uses Cloud SQL PostgreSQL with PgBouncer connection pooling:
- **Instance**: `openvine-co:us-central1:keycast-db-plus`
- **Connection**: Via Cloud SQL Auth Proxy (automatic in Cloud Run)
- **Pooling**: Built-in Cloud SQL connection pooler with transaction mode
- **Pool size per instance**: 10 (configured via `SQLX_POOL_SIZE`)

### Database Migrations

Migrations are run manually before deployment:
```bash
./tools/run-migrations.sh
```

This avoids `pg_advisory_lock` thundering herd when many instances start simultaneously.

## Service Architecture

```
login.divine.video (DNS)
    ↓
Cloud Load Balancer / Domain Mapping
    ↓
keycast (Cloud Run, 3-200 instances)
    ├── API Server (port 3000)
    │   ├── /api/auth/*
    │   ├── /api/user/*
    │   ├── /api/oauth/*
    │   └── / (static web files)
    ├── Signer Daemon
    │   └── NIP-46 relay listener
    └── Cluster Coordinator
        └── Redis Pub/Sub for hashring membership
    ↓
Cloud SQL (PostgreSQL)
    └── keycast-db-plus
    ↓
Redis Memorystore
    └── Cluster coordination
```

## Environment Variables

See `cloudbuild.yaml` for the full list of required environment variables:
- `NODE_ENV=production`
- `USE_GCP_KMS=true`
- `ALLOWED_ORIGINS=https://login.divine.video`
- `APP_URL=https://login.divine.video`
- `RUST_LOG=info`
- `SQLX_POOL_SIZE=10`
- `SQLX_STATEMENT_CACHE=100`
- etc.

## Secrets (Google Secret Manager)

- `DATABASE_URL` - Cloud SQL connection string
- `SERVER_NSEC` - Server Nostr secret key for UCAN signing
- `SENDGRID_API_KEY` - Email service
- `REDIS_URL` - Redis Memorystore connection

## Smoke Tests

cloudbuild.yaml includes automated smoke tests:
- Health endpoint check
- CORS preflight validation

## Troubleshooting

### Deployment went to wrong service
- Check `cloudbuild.yaml` - service name should be `keycast`

### Database connection issues
- Check Cloud SQL instance status
- Verify `DATABASE_URL` secret is correct
- Check `SQLX_POOL_SIZE` matches instance concurrency (10)
- Review connection logs for `PoolTimedOut` errors

### Service not updating
- Check which revision is serving traffic: `gcloud run services describe keycast --region=us-central1`
- Verify latest image was deployed

### High latency under load
- Instance concurrency is set to 10 for CPU-bound crypto operations
- Check if autoscaling is keeping up with demand
- Review Redis cluster coordination for hashring membership
