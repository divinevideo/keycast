# Keycast Development Guide

## Quick Start

### Active Development (Recommended - Fast)

**For day-to-day coding with hot reload** (~5 seconds startup):

**Prerequisites:**
```bash
# Install dependencies (first time only)
bun install

# Generate master encryption key (first time only)
bun run key:generate
```

**Start development:**
```bash
# Clean up any orphan containers from previous runs
docker compose -f docker-compose.deps.yml down --remove-orphans
docker compose -f docker-compose.dev.yml down --remove-orphans 2>/dev/null || true

# Start dependencies (postgres + redis) in Docker
bun run deps:up

# Run migrations (first time only)
bun run db:migrate

# Start API + Web with hot reload (native, no Docker build)
bun run dev
```

**If you see "password authentication failed" errors:**
```bash
# This usually happens if postgres volume was initialized with a different password
# (e.g., from docker-compose.yml which reads POSTGRES_PASSWORD from .env)

# Stop all containers and remove volumes (clears old passwords)
docker compose -f docker-compose.deps.yml down -v
docker compose -f docker-compose.dev.yml down -v 2>/dev/null || true
docker compose -f docker-compose.yml down -v 2>/dev/null || true

# Remove any orphaned volumes
docker volume rm keycast_postgres_data keycast_postgres_dev_data 2>/dev/null || true

# Restart fresh (docker-compose.deps.yml uses hardcoded 'password')
bun run deps:up
bun run db:migrate
bun run dev
```

**Note:** `docker-compose.deps.yml` hardcodes `POSTGRES_PASSWORD: password`, but if you previously ran `docker-compose.yml` (which reads from `.env`), the postgres volume may have been initialized with a different password. Postgres volumes persist passwords, so you must remove the volume to change it.

This approach:
- ✅ **Fast**: No Docker image builds, native Rust incremental compilation
- ✅ **Hot reload**: Rust API auto-rebuilds on changes, Web has Vite HMR
- ✅ **Fast startup**: ~5 seconds vs ~2+ minutes for Docker builds
- ✅ **Better debugging**: Native processes, easier to attach debuggers

Services available at:
- API: http://localhost:3000
- Web: http://localhost:5173

### Integration Testing (Before Deploy)

**For testing in production-like environment** (matches Cloud Run):

```bash
# Clean start
docker-compose -f docker-compose.dev.yml down -v

# Start full stack in Docker (includes postgres + keycast)
docker-compose -f docker-compose.dev.yml up -d --build

# Run database migrations (if needed)
bun run db:migrate

# Run integration tests
./tests/integration/test-api.sh
```

This approach:
- ✅ **Production-like**: Matches Cloud Run environment
- ✅ **Isolated**: Clean state for testing
- ⚠️ **Slower**: Docker builds take 2+ minutes
- ⚠️ **No hot reload**: Must rebuild image for changes

### Deploy to Production

**Only deploy after local tests pass:**

```bash
gcloud builds submit --config=cloudbuild.yaml --project=openvine-co
```

## Testing Strategy

### Development Workflow

**During active development:**
```bash
# Terminal 1: Start dependencies once
bun run deps:up

# Terminal 2: Run dev server (auto-restarts on changes)
bun run dev
```

**Before committing/deploying:**
```bash
# Run unit tests (fast, no Docker needed)
cargo test --workspace

# Run integration tests (requires Docker Compose)
docker-compose -f docker-compose.dev.yml up -d --build
./tests/integration/test-api.sh
```

### Local Integration Tests (~2-3 min with Docker build)
```bash
# Start full stack in Docker (production-like)
docker-compose -f docker-compose.dev.yml up -d --build

# Run integration tests
./tests/integration/test-api.sh
```
- Builds and starts full stack with Docker Compose
- Tests health endpoints, CORS, API connectivity
- **Always run before deploying** to catch production issues

### API Integration Tests
```bash
# Local
./tests/integration/test-api.sh

# Production
API_URL=https://login.divine.video FRONTEND_URL=https://login.divine.video \
  ./tests/integration/test-api.sh
```
Tests:
- Health & infrastructure (health endpoint, CORS)
- Teams API authentication
- API structure & error handling
- Security headers & CORS restrictions

### E2E Frontend Tests
```bash
# Local
./tests/e2e/test-frontend.sh

# Production (when frontend is deployed)
BASE_URL=https://login.divine.video API_URL=https://login.divine.video \
  ./tests/e2e/test-frontend.sh
```
Tests:
- Page loading & rendering
- Frontend-API integration
- Static assets
- Security headers
- Performance (load time, page size)

### Unit Tests
```bash
# Run all unit tests
cargo test --workspace

# Or use the test service in docker-compose.dev.yml
docker-compose -f docker-compose.dev.yml run --rm test
```

## Development Approaches Comparison

### `bun run dev` (Native Development)

**What runs where:**
- ✅ **Postgres + Redis**: Docker containers (via `docker-compose.deps.yml`)
- ✅ **Rust API**: Native process (`cargo run --bin keycast`)
- ✅ **Web Frontend**: Native process (`bun run dev` with Vite)

**How it works:**
```bash
bun run dev
  ├─> bun run deps:up          # Starts postgres + redis in Docker
  └─> concurrently
      ├─> cargo run --bin keycast  # Native Rust (incremental compilation)
      └─> bun run dev              # Native Vite (HMR)
```

**Characteristics:**
- ✅ **Fast startup**: ~5 seconds (no Docker build)
- ✅ **Hot reload**: Rust auto-rebuilds, Vite HMR
- ✅ **Fast iteration**: Incremental compilation (~1-2s per change)
- ✅ **Easy debugging**: Native processes, attach debuggers easily
- ✅ **Lower resource usage**: No Docker overhead for app
- ❌ **Not production-like**: Different environment than Cloud Run

### `docker-compose.dev.yml` (Docker Everything)

**What runs where:**
- ✅ **Postgres**: Docker container
- ✅ **Rust API**: Docker container (built from Dockerfile)
- ✅ **Web Frontend**: Docker container (built from Dockerfile)

**How it works:**
```bash
docker-compose -f docker-compose.dev.yml up -d --build
  ├─> Builds Docker image for keycast (Rust + Web)
  ├─> Starts postgres container
  └─> Starts keycast container (runs unified binary)
```

**Characteristics:**
- ⚠️ **Slow startup**: ~2-3 minutes (Docker build every time)
- ❌ **No hot reload**: Must rebuild image for changes
- ⚠️ **Slow iteration**: Full Docker rebuild (~2-3 min per change)
- ⚠️ **Harder debugging**: Must use `docker exec` or logs
- ⚠️ **Higher resource usage**: Docker overhead
- ✅ **Production-like**: Matches Cloud Run environment exactly

### Side-by-Side Comparison

| Aspect | `bun run dev` | `docker-compose.dev.yml` |
|--------|---------------|-------------------------|
| **Startup time** | ~5 seconds | ~2-3 minutes |
| **Hot reload** | ✅ Yes (Rust + Vite) | ❌ No (rebuild required) |
| **Change iteration** | ~1-2 seconds | ~2-3 minutes |
| **Debugging** | ✅ Easy (native) | ⚠️ Harder (containers) |
| **Resource usage** | Lower | Higher |
| **Production match** | ❌ Different | ✅ Identical |
| **Use case** | **99% of development** | **Integration testing** |

**Recommendation:**
- Use `bun run dev` for 99% of development work
- Use `docker-compose.dev.yml` only when:
  - Testing production-like behavior
  - Running integration tests before deploying
  - Debugging Docker-specific issues

## Architecture

### API (Port 3000)
- Rust/Axum
- PostgreSQL database
- NIP-46 bunker implementation

### Web (Port 5173)
- SvelteKit
- Bun for development (package management & dev server)
- Built as static files in production
- Connects to API

### Configuration

#### Build-time (baked into image)
- `VITE_DOMAIN` - API URL for frontend

#### Runtime (environment variables)
- `ALLOWED_ORIGINS` - Frontend origins for CORS (comma-separated)
- `APP_URL` - Application base URL
- `USE_GCP_KMS` - Use GCP Key Management (production)
- `SENDGRID_API_KEY` - Email service

## Known Issues

See the comprehensive analysis for 26 production-readiness issues.

### Critical (Being Fixed)
- ✅ CORS configuration (now reads from env)
- ✅ Build args for VITE_DOMAIN
- ✅ Deployment smoke tests
- ⏳ Cloud Build compilation errors

### High Priority
- No integration/e2e tests (test infrastructure created)
- No structured logging
- No error monitoring
- Master key baked into image
- No rate limiting

## Deployment Checklist

Before deploying:
- [ ] Run unit tests: `cargo test --workspace`
- [ ] Start Docker stack: `docker-compose -f docker-compose.dev.yml up -d --build`
- [ ] Run integration tests: `./tests/integration/test-api.sh`
- [ ] Check git status is clean
- [ ] Review changed files
- [ ] Update CHANGELOG (if exists)

After deploying:
- [ ] Check Cloud Build logs
- [ ] Verify smoke tests pass
- [ ] Test registration flow manually
- [ ] Check logs for errors
