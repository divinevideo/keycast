# Keycast Development Guide

## Quick Start

### Prerequisites
```bash
bun install              # Install dependencies
bun run key:generate     # Generate master encryption key
```

### Development (Recommended)
```bash
bun run deps:up          # Start postgres + redis
bun run db:migrate       # Run migrations (first time)
bun run dev              # Start API + Web with hot reload
```

- API: http://localhost:3000
- Web: http://localhost:5173

### Integration Testing
```bash
docker-compose -f docker-compose.dev.yml up -d --build  # Build & run full stack
./tests/integration/test-api.sh
```

This builds the Docker image and runs the full stack (API + Web + Postgres) in containers, matching the production environment.

### Local Production Stack
```bash
docker compose up --build
```

Runs the full production stack locally: Postgres, Redis, migrations, and the unified keycast service. Requires `.env` with `POSTGRES_PASSWORD`, `DOMAIN`, `ALLOWED_ORIGINS`, `SERVER_NSEC`. Good for testing the complete deployment before pushing.

### Deploy
- Push to `main`/`master` → auto-deploys to dev (poc/test/staging)
- Version tags (`v*`) → auto-deploys to production
- Manual dispatch via GitHub Actions UI

**Legacy:** `gcloud builds submit --config=cloudbuild.yaml --project=openvine-co`

## Testing

```bash
cargo test --workspace                    # Unit tests
./tests/integration/test-api.sh           # API integration tests
./tests/e2e/test-frontend.sh              # E2E frontend tests
```

**Production testing:**
```bash
API_URL=https://login.divine.video ./tests/integration/test-api.sh
BASE_URL=https://login.divine.video ./tests/e2e/test-frontend.sh
```

## Development Modes

| Aspect | `bun run dev` | `docker-compose.dev.yml` |
|--------|---------------|-------------------------|
| Startup | ~5 seconds | ~2-3 minutes |
| Hot reload | ✅ Yes | ❌ No |
| Production match | ❌ No | ✅ Yes |
| Use case | Daily development | Integration testing |

## Known Issues

### Critical (Being Fixed)
- ✅ CORS configuration (now reads from env)
- ✅ Build args for VITE_DOMAIN
- ✅ Deployment smoke tests

### High Priority
- No structured logging
- No error monitoring
- No rate limiting

## Troubleshooting

**Password authentication failed:**
```bash
docker compose -f docker-compose.deps.yml down -v
docker volume rm keycast_postgres_data keycast_postgres_dev_data 2>/dev/null || true
bun run deps:up && bun run db:migrate && bun run dev
```

## Architecture

- **API (Port 3000)**: Rust/Axum, PostgreSQL, NIP-46 bunker
- **Web (Port 5173)**: SvelteKit, Bun

### Configuration

**Runtime (environment variables):**
- `ALLOWED_ORIGINS` - CORS origins
- `APP_URL` - Application base URL
- `USE_GCP_KMS` - Use GCP Key Management
- `SENDGRID_API_KEY` - Email service

## Deployment Checklist

**Before:**
- [ ] `cargo test --workspace`
- [ ] `docker-compose -f docker-compose.dev.yml up -d --build`
- [ ] `./tests/integration/test-api.sh`

**After:**
- [ ] Check CI/CD logs
- [ ] Verify smoke tests pass
- [ ] Test registration flow
