# pg-hashring

PostgreSQL-backed cluster membership with consistent hashing for Rust.

## Overview

`pg-hashring` provides distributed work partitioning for applications that share a PostgreSQL database but can't form a direct network mesh (e.g., Cloud Run, Heroku, serverless).

**Key features:**
- **Consistent hashing** via AnchorHash (optimal minimal disruption on membership changes)
- **Near-instant membership updates** via PostgreSQL LISTEN/NOTIFY (~5-20ms)
- **Crash detection** via heartbeat fallback (30s)
- **Graceful shutdown** with drain period (no dropped events)

## Quick Start

```rust
use pg_hashring::ClusterCoordinator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::PgPool::connect("postgres://localhost/mydb").await?;

    // Ensure schema exists (safe to call multiple times)
    pg_hashring::setup(&pool).await?;

    // Start coordinator - registers with cluster, begins listening
    let coordinator = ClusterCoordinator::start(pool).await?;
    coordinator.wait_for_established().await;

    // Check if this instance should handle a key
    if coordinator.should_handle("user-123").await {
        // Process the request - only one instance in the cluster will return true
    }

    // Graceful shutdown - notifies peers, drains for 100ms, then stops
    coordinator.shutdown().await?;
    Ok(())
}
```

## How It Works

### Membership Discovery

```
┌─────────────────────────────────────────────────────────────┐
│  PostgreSQL                                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  signer_instances table                               │  │
│  │  ┌─────────────────┬─────────────┬─────────────────┐  │  │
│  │  │ instance_id     │ started_at  │ last_heartbeat  │  │  │
│  │  ├─────────────────┼─────────────┼─────────────────┤  │  │
│  │  │ abc-123...      │ 2024-01-01  │ 2024-01-01      │  │  │
│  │  │ def-456...      │ 2024-01-01  │ 2024-01-01      │  │  │
│  │  └─────────────────┴─────────────┴─────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  LISTEN/NOTIFY channel: "cluster_membership"                │
│    • "joined:<uuid>" - new instance registered              │
│    • "left:<uuid>" - instance deregistered                  │
└─────────────────────────────────────────────────────────────┘
```

### Consistent Hashing

Each instance maintains an identical hash ring (via sorted instance IDs + AnchorHash):

```
hash("user-123") → bucket 2 → instance "def-456"

All instances agree on ownership without coordination.
```

### Failure Detection

| Scenario | Detection Time | Mechanism |
|----------|---------------|-----------|
| Graceful shutdown | ~5-20ms | LISTEN/NOTIFY |
| Crash (SIGKILL, OOM) | 30-60s | Heartbeat timeout |

### Shutdown Drain

To prevent dropped events during graceful shutdown:

```
Instance A                              Instance B
    │                                       │
    │  1. sends "left:" notification        │
    │         │                             │
    │         └─── ~10ms latency ───────────►
    │                                       │ receives, updates ring
    │  2. keeps processing for 100ms        │ starts handling A's keys
    │     (overlap - both handle A's keys)  │
    │                                       │
    │  3. stops                             │
    ╳                                       │
```

## API Reference

### `ClusterCoordinator`

The main entry point for cluster coordination.

```rust
// Start and register with the cluster
let coordinator = ClusterCoordinator::start(pool).await?;

// Wait for LISTEN to be established (useful in tests)
coordinator.wait_for_established().await;

// Check if this instance owns a key
if coordinator.should_handle("some-key").await {
    // Handle it
}

// Get instance count in the cluster
let count = coordinator.instance_count().await;

// Force refresh from database (useful after crash recovery)
coordinator.refresh().await?;

// Graceful shutdown with drain period
coordinator.shutdown().await?;
```

### `setup()`

Creates the required database table (idempotent):

```rust
pg_hashring::setup(&pool).await?;
```

### Constants

```rust
// Duration to continue processing after "left:" notification
pg_hashring::SHUTDOWN_DRAIN_MS // 100ms
```

## Database Schema

The crate uses a single table (created by `setup()`):

```sql
CREATE TABLE IF NOT EXISTS signer_instances (
    instance_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signer_instances_heartbeat
ON signer_instances(last_heartbeat);
```

## Scale and Limitations

**Appropriate for:**
- Small to medium clusters (3-100 instances)
- Infrequent membership changes
- Environments sharing a database but without direct networking

**Not suitable for:**
- Very large clusters (1000+ nodes) - use gossip protocols
- High-frequency membership churn
- Sub-second crash detection requirements

## Running the Demo

Interactive CLI demo showing cluster coordination:

```bash
# Terminal 1
cargo run -p pg-hashring --example demo

# Terminal 2
cargo run -p pg-hashring --example demo

# Terminal 3
cargo run -p pg-hashring --example demo
```

Type messages and see which instance claims ownership. Try:
- `/status` - Show cluster status and key distribution
- `/refresh` - Force sync ring from database
- `/quit` or Ctrl+C - Graceful shutdown

## Testing

```bash
# Unit tests
cargo test -p pg-hashring --lib

# Simulation tests (requires PostgreSQL)
cargo test -p pg-hashring --test simulation -- --test-threads=1
```

## License

MIT
