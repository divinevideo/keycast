# Keycast Load Testing Tool

A Rust-based load testing tool for benchmarking Keycast's HTTP RPC endpoint (`POST /api/nostr`).

## Quick Start

```bash
# Build the tool
cargo build --release -p keycast-loadtest

# Create test users (against running server)
./target/release/keycast-loadtest setup \
  --url http://localhost:3000 \
  --users 100 \
  --output ./test-users.json

# Run load test
./target/release/keycast-loadtest run \
  --url http://localhost:3000 \
  --users-file ./test-users.json \
  --concurrency 50 \
  --duration 60 \
  --scenario warm-cache \
  --method get-public-key \
  --output ./results.json
```

## Commands

### `setup` - Create Test Users

Creates users via HTTP registration API with full OAuth flow (register + authorize + token exchange).

```bash
keycast-loadtest setup \
  --url <server-url> \
  --users <count> \
  --output <json-file>
```

**What happens:**
1. Registers user with email/password
2. Approves OAuth authorization (with PKCE)
3. Exchanges code for access token (UCAN with `bunker_pubkey`)
4. Saves credentials to JSON file

**Important:** Users are created against a specific `SERVER_NSEC`. If the server restarts with a different key, you need to recreate users.

### `run` - Execute Load Test

Sends concurrent RPC requests and measures performance.

```bash
keycast-loadtest run \
  --url <server-url> \
  --users-file <json-file> \
  --concurrency <num> \
  --duration <seconds> \
  --scenario <warm-cache|cold-start|mixed> \
  --method <get-public-key|sign-event> \
  --output <results.json>
```

**Scenarios:**
| Scenario | Behavior | Use Case |
|----------|----------|----------|
| `warm-cache` | Cycles through users (cache gets warm) | Steady-state performance |
| `cold-start` | Each request uses different user | Cache miss impact |
| `mixed` | 80% repeat / 20% new users | Realistic traffic |

**Methods:**
| Method | What it does | CPU Cost |
|--------|--------------|----------|
| `get-public-key` | Returns user's pubkey | Minimal |
| `sign-event` | Schnorr signature | ~1-3ms |

### `report` - View Results

```bash
keycast-loadtest report --input ./results.json
```

## Architecture Context

### Request Flow

```
Client Request
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ POST /api/nostr                                         │
│   Authorization: Bearer <UCAN with bunker_pubkey>       │
│   Body: {"method": "get_public_key", "params": []}      │
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ UCAN Token Verification                                 │
│   - Verify signature against SERVER_NSEC pubkey         │
│   - Extract: user_pubkey, redirect_origin, bunker_pubkey│
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ Handler Cache Lookup (Moka LRU)                         │
│   Key: bunker_pubkey (32 bytes)                         │
│   Capacity: 1,000,000 (configurable via HANDLER_CACHE_SIZE)
│   TTL: 1 hour idle timeout                              │
│                                                         │
│   HIT  ──► Return cached HttpRpcHandler                 │
│   MISS ──► Load from DB, cache, return                  │
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ Execute RPC Method                                      │
│   - Validate authorization (cached: expires_at, revoked)│
│   - Check permissions (cached: policy rules)            │
│   - Perform operation (sign/encrypt/decrypt)            │
└─────────────────────────────────────────────────────────┘
```

### What's Cached

The `HttpRpcHandler` caches everything needed to process requests without DB hits:
- User's signing keys (decrypted)
- Authorization metadata (expires_at, revoked_at)
- Permission rules (from policy)
- Cache keys (bunker_pubkey, authorization_handle)

### Latency Breakdown

| Component | Typical Latency |
|-----------|-----------------|
| Network (local) | <1ms |
| Network (Cloud Run) | ~200ms |
| Cache hit | <1ms |
| Cache miss (DB load) | 20-100ms |
| Schnorr signing | 1-3ms |
| NIP-44 encrypt/decrypt | <1ms |

## Metrics

After running tests, check metrics at `/api/metrics`:

```bash
curl http://localhost:3000/api/metrics | grep http_rpc
```

Key metrics:
- `keycast_http_rpc_requests_total` - Total requests
- `keycast_http_rpc_cache_hits_total` - Cache hits
- `keycast_http_rpc_cache_misses_total` - Cache misses (DB loads)
- `keycast_http_rpc_success_total` - Successful requests
- `keycast_http_rpc_auth_errors_total` - Auth failures

## Production Testing

### Against Cloud Run

```bash
# Create users (takes ~1 min per 1000 users at 200 concurrency)
./target/release/keycast-loadtest setup \
  --url https://login.divine.video \
  --users 1000 \
  --concurrency 200 \
  --output ./prod-users.json

# Run test
./target/release/keycast-loadtest run \
  --url https://login.divine.video \
  --users-file ./prod-users.json \
  --concurrency 500 \
  --duration 60 \
  --scenario warm-cache \
  --method get-public-key \
  --output ./prod-results.json
```

### Configuration Risk: Load Skew & Metric Dilution

**CRITICAL AUTOSCALING HAZARD** when combining **Session Affinity (Sticky Sessions)** with a high **`min-instances`** count.

Because the Cloud Run Autoscaler triggers scale-out events based strictly on *cluster-wide averages*, a large pool of idle reserved instances causes **Metric Dilution**, dragging down the global average. This results in **Load Skew**, where specific instances become saturated ("hot") due to sticky user traffic, yet fail to trigger a scale-out because the diluted cluster average incorrectly signals that the system is underutilized.

**Example:**
- `min-instances=10`, Session Affinity enabled
- 1 instance handling 100% of traffic (due to sticky sessions from single client)
- That instance at 95% CPU saturation
- Other 9 instances idle at ~1% CPU
- **Cluster average: ~10.4% CPU** → No scale-out triggered (target is 60%)

**Mitigations:**
1. Lower the `concurrency` limit to force spillover to new instances
2. Reduce `min-instances` to unmask true load metrics
3. Use multiple client IPs for load testing (different IPs = different sticky targets)
4. Monitor per-instance metrics, not just cluster averages

### Known Bottlenecks

1. **Cloud SQL Connection Pool** (db-g1-small: ~25 max connections)
   - Each Cloud Run instance uses ~2-5 connections
   - Under load, instances scale up → connection exhaustion
   - Fix: Upgrade DB tier or use Cloud SQL Proxy pooler

2. **Cold Instance Caches**
   - New Cloud Run instances have empty handler caches
   - All requests hit DB until cache warms
   - Mitigated by: session affinity, min instances

3. **Network Latency**
   - ~200ms baseline to Cloud Run (geographic)
   - Not reducible without edge deployment

## Example Results

```
Keycast Load Test Results
=========================
Target:        http://localhost:3000/api/nostr
Scenario:      WarmCache
Method:        GetPublicKey
Concurrency:   50
Duration:      25.0s
Users:         20

Summary:
  Requests:      21933
  Throughput:    877.2 req/s
  Success Rate:  100.0%

Latency (ms):
  Min:   0.8
  p50:   44.0
  p95:   49.3
  p99:   58.4
  Max:   178.4
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HANDLER_CACHE_SIZE` | 1,000,000 | Max handlers in cache per instance |

## Profiling with Flamegraph

Use the included script to profile CPU usage with flamegraph:

```bash
# Basic usage (requires sudo for dtrace on macOS)
sudo ./tools/loadtest/flamegraph.sh

# Custom parameters
sudo ./tools/loadtest/flamegraph.sh \
  --users 100 \
  --concurrency 100 \
  --duration 60 \
  --scenario warm-cache \
  --method sign-event

# Reuse existing users (faster iteration)
sudo ./tools/loadtest/flamegraph.sh --skip-setup --duration 30
```

**Options:**
| Option | Default | Description |
|--------|---------|-------------|
| `--users` | 50 | Number of test users to create |
| `--concurrency` | 50 | Concurrent requests |
| `--duration` | 30 | Test duration (seconds) |
| `--scenario` | warm-cache | warm-cache, cold-start, mixed |
| `--method` | get-public-key | get-public-key, sign-event |
| `--output` | /tmp | Output directory |
| `--skip-setup` | false | Reuse existing users file |

**Output:**
- `keycast-flamegraph-TIMESTAMP.svg` - Interactive flamegraph (open in browser)
- `flamegraph-results-TIMESTAMP.json` - Load test results
- `flamegraph-users.json` - Reusable test users

**Prerequisites:**
```bash
# Install flamegraph
cargo install flamegraph

# Build with debug symbols (done automatically by script)
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --bin keycast
```

## Performance Debugging Checklist

**IMPORTANT:** When investigating performance issues, always check these FIRST before building synthetic benchmarks:

### 1. Check SQL Queries (Most Common Bottleneck)

```bash
# Enable SQLx query logging
RUST_LOG=sqlx=debug ./target/release/keycast

# Or check PostgreSQL directly
psql -c "SELECT query, calls, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
```

**What to look for:**
- Queries running on every request that should be cached
- INSERT/UPDATE statements in read-heavy paths
- Missing indexes (high `mean_exec_time`)
- N+1 query patterns

**Real example:** The `TenantExtractor` was doing `INSERT ... ON CONFLICT` on every request instead of caching the tenant lookup. This caused ~160x slowdown (1.8k → 623k req/s after fix).

### 2. Check Application Metrics

```bash
curl http://localhost:3000/api/metrics | grep -E "cache|rpc|latency"
```

Verify cache hit rates match expectations. 99%+ cache hits with high latency = bottleneck is elsewhere (not cache misses).

### 3. Check Tokio Runtime

```bash
# Enable tokio-console (if configured)
RUSTFLAGS="--cfg tokio_unstable" cargo build --release

# Or use tracing to spot blocking operations
RUST_LOG=tokio=trace ./target/release/keycast
```

Look for:
- `spawn_blocking` overload
- Blocking operations on async threads
- Task starvation

### 4. Profile with Flamegraph

Only after ruling out obvious issues:

```bash
sudo ./tools/loadtest/flamegraph.sh --duration 30
```

### Common Performance Pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| **DB query per request** | High latency, low CPU | Add caching layer |
| **Uncached extractor** | Middleware runs on every request | Cache in global state |
| **Blocking in async** | Low throughput, thread starvation | Use `spawn_blocking` |
| **Lock contention** | High CPU, low throughput | Use lock-free structures (dashmap, Moka) |
| **Serialization overhead** | High CPU in serde | Use zero-copy or pre-serialize |

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -p keycast-loadtest -- setup --url http://localhost:3000 --users 10

# Run tests
cargo test -p keycast-loadtest
```
