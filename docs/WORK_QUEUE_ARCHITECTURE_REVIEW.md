# Keycast Work Queue Architecture Review

**Date:** December 5, 2024
**Reviewer:** Based on production debugging experience from groups_relay
**Status:** Action Items Identified

---

## Executive Summary

After reviewing the two-queue architecture against patterns we've seen cause production outages in groups_relay (32+ hour deadlock, runtime freeze), I've identified **2 critical issues** and **3 moderate concerns** that should be addressed before this architecture handles production load.

The most serious issue: **crypto operations run directly on async runtime threads**, which will cause the exact "stuck task" pattern we've documented in `docs/debugging_production_issues.md`.

---

## Issue #1: Crypto Operations Block Async Runtime

**Severity: CRITICAL**

### The Problem

In `signer_daemon.rs`, CPU-bound cryptographic operations execute directly in async context:

```rust
// Lines 966-994 - Decryption runs on async thread
let (decrypted, use_nip44) = match nip44::decrypt(
    bunker_secret,
    &event.pubkey,
    &event.content,
) {
    Ok(d) => (d, true),
    Err(nip44_err) => {
        // Falls back to NIP-04 - also blocks
        match nip04::decrypt(bunker_secret, &event.pubkey, &event.content) { ... }
    }
};

// Lines 1093-1098 - Encryption runs on async thread
let ciphertext = nip44::encrypt(
    handler.user_keys.secret_key(),
    &third_party_pubkey,
    plaintext,
    nip44::Version::V2,
)?;

// Lines 1347-1355 - Signing runs on async thread
let signed_event = EventBuilder::new(unsigned_event.kind, &unsigned_event.content)
    .tags(tags)
    .custom_created_at(Timestamp::from(created_at))
    .sign(&self.user_keys)  // <-- CPU-bound operation!
    .await?;
```

### Why This Is Critical

From our production debugging (see `docs/debugging_production_issues.md`):

> **Stuck Task Pattern:**
> - State: `▶ Running` for extended period
> - High busy time
> - Not making progress
> - **Diagnosis:** CPU-bound work blocking async runtime

When a crypto operation takes 10-100ms (common for Schnorr signing + NIP-44 encryption), the async worker thread is **completely blocked**. Other tasks waiting on that worker cannot progress.

With only `num_cpus` workers (2 on Cloud Run), a burst of sign requests can block ALL workers simultaneously, causing:
- Accept queue overflow
- Health check timeouts
- Cascading failures

### tokio-console Pattern

When this happens, you'll see in tokio-console:
```
Task ID: 456
State: ▶ Running
Total: 500ms
Busy: 495ms      ← Almost 100% busy (CPU-bound)
Polls: 3         ← Low poll count (not yielding)
Location: signer_daemon.rs:1350
```

### Fix Required

Wrap all crypto operations in `spawn_blocking`:

```rust
// Encryption
let ciphertext = {
    let secret = handler.user_keys.secret_key().clone();
    let pubkey = third_party_pubkey;
    let plaintext = plaintext.to_string();
    tokio::task::spawn_blocking(move || {
        nip44::encrypt(&secret, &pubkey, &plaintext, nip44::Version::V2)
    }).await??
};

// Signing
let signed_event = {
    let keys = self.user_keys.clone();
    let kind = unsigned_event.kind;
    let content = unsigned_event.content.clone();
    let tags = tags.clone();
    let created_at = created_at;

    tokio::task::spawn_blocking(move || {
        // Note: sign() is async, but the actual crypto is sync
        // We need to block_in_place or restructure
        EventBuilder::new(kind, &content)
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&keys)  // Use sync version if available
    }).await??
};
```

**Alternative:** If nostr-sdk doesn't have sync signing, use `block_in_place`:
```rust
let signed_event = tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current().block_on(async {
        EventBuilder::new(kind, &content)
            .sign(&self.user_keys)
            .await
    })
})?;
```

---

## Issue #2: Worker Count Insufficient for I/O-Heavy Workload

**Severity: HIGH**

### The Problem

From `docs/keycast_work_queue_architecture.md`:
```rust
let num_workers = num_cpus::get();  // One worker per CPU core
```

On Cloud Run with 2 CPUs → only 2 workers.

### Why This Is Wrong

Each request involves multiple async I/O operations (from `signer_daemon.rs`):

```rust
// Database queries in handle_nip46_request:
let auth_opt = sqlx::query_as::<_, OAuthAuthorization>(...)  // Line 790-800
    .fetch_optional(pool).await?;

let encrypted_user_key: Vec<u8> = sqlx::query_scalar(...)    // Line 808-814
    .fetch_one(pool).await?;

// Network I/O:
client.send_event(&response_event).await?;                    // Line 1211
```

With only 2 workers:
1. Worker 1 waits on DB query
2. Worker 2 waits on relay send
3. **No workers available to process new requests**
4. Queue fills up → requests dropped

### Production Pattern We've Seen

This is EXACTLY what caused our 32-hour outage in groups_relay:

> "The tokio runtime was configured with the default number of worker threads (= num_cpus). With only 2 workers, any race in park/wake coordination could freeze the entire runtime."

We fixed it by setting `worker_threads(8)` explicitly. Same principle applies here.

### Fix Required

```rust
// In spawn_workers call site (likely main.rs or similar):
let num_workers = num_cpus::get().max(4) * 2;  // At least 8 workers

// Better: Make it configurable
let num_workers = std::env::var("RPC_WORKER_COUNT")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or_else(|| num_cpus::get().max(4) * 2);
```

---

## Issue #3: Backpressure Drops Without Client Feedback

**Severity: MODERATE**

### The Problem

From `work_queue.rs:101-110`:
```rust
pub fn try_send(&self, item: Nip46RpcItem) -> Result<(), RpcQueueError> {
    match self.tx.try_send(item) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            METRICS.inc_queue_dropped();
            Err(RpcQueueError::QueueFull)  // Dropped silently!
        }
        ...
    }
}
```

When this error propagates up to `signer_daemon.rs:563`:
```rust
if let Err(e) = sender.try_send(item) {
    tracing::warn!("Failed to enqueue NIP-46 request: {}", e);
    // Client never knows their request was dropped!
}
```

### Consequences

1. **Client retry storms** - Client doesn't know to back off
2. **Silent failures** - User sees "signing failed" with no explanation
3. **No adaptive behavior** - System can't signal overload to clients

### NIP-46 Error Response

NIP-46 supports error responses. When queue is full, we should still send one:

```rust
if let Err(RpcQueueError::QueueFull) = sender.try_send(item) {
    // Send NIP-46 error response
    let error_response = serde_json::json!({
        "id": extract_request_id(&event),
        "error": "Service temporarily overloaded, please retry"
    });

    // Encrypt and send error back to client
    // (simplified - need bunker keys)
    send_error_response(&client, &event, error_response).await;
}
```

### Metrics to Add

```rust
// Current: only counting drops
METRICS.inc_queue_dropped();

// Should also track:
METRICS.set_queue_depth(sender.len());        // Current depth
METRICS.set_queue_capacity(QUEUE_CAPACITY);   // For utilization %
METRICS.inc_queue_wait_time(elapsed);         // Time in queue
```

---

## Issue #4: spawn_blocking per recv() Creates Overhead

**Severity: LOW**

### The Problem

From `work_queue.rs:146-160`:
```rust
loop {
    let item = {
        let rx = rx.clone();
        match tokio::task::spawn_blocking(move || rx.recv()).await {
            // ...
        }
    };
    process_nip46_item(&item, ...).await
}
```

Every iteration:
1. Clones the receiver
2. Spawns a new blocking task
3. Waits for it to complete
4. Then processes

### Overhead Analysis

- `spawn_blocking` has scheduling overhead (~1-5μs)
- Creating new blocking task per request
- Not a problem at low volume, but at 1000 req/sec = 1-5ms overhead/sec

### Alternative: Use tokio::sync::mpsc

```rust
use tokio::sync::mpsc;

// In RpcQueue::new():
let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);

// In worker loop - no spawn_blocking needed:
loop {
    let item = match rx.recv().await {
        Some(item) => item,
        None => break,  // Channel closed
    };
    process_nip46_item(&item, ...).await
}
```

Benefits:
- Native async channel - no blocking thread pool overhead
- Better integration with tokio runtime
- Cleaner cancellation semantics

Trade-off:
- crossbeam-channel has better MPMC performance
- tokio::sync::mpsc is MPSC (need separate receiver per worker or use broadcast)

### Recommendation

Keep crossbeam for now (it works), but consider switching to `async-channel` crate which provides async MPMC:
```rust
let (tx, rx) = async_channel::bounded(QUEUE_CAPACITY);
// rx.recv().await - no spawn_blocking needed
// Multiple workers can share rx (MPMC)
```

---

## Issue #5: Cache Contention Under Load

**Severity: LOW**

### The Problem

From `signer_daemon.rs:325`:
```rust
handlers: Cache<String, Nip46Handler>,  // moka::future::Cache
```

Moka cache uses internal synchronization for:
- Entry insertion (`handlers.insert(...).await`)
- Eviction (background task)
- Entry lookup (fast path is lock-free, but...)

### When It Matters

Under high load with many cache misses:
1. Multiple workers lookup same bunker_pubkey simultaneously
2. All miss cache, all query database
3. All try to insert at the same time
4. Contention on cache internals

### Mitigation Already Present

The code does handle this gracefully - duplicate inserts just overwrite:
```rust
handlers.insert(bunker_pubkey.to_string(), handler.clone()).await;
```

### Optional Improvement: Deduplicate Concurrent Loads

```rust
use tokio::sync::Mutex;
use std::collections::HashMap;

struct LoadingGuard {
    loading: Mutex<HashMap<String, tokio::sync::broadcast::Sender<Nip46Handler>>>,
}

// When loading:
let mut loading = guard.loading.lock().await;
if let Some(tx) = loading.get(bunker_pubkey) {
    // Another task is loading - wait for their result
    drop(loading);
    let handler = tx.subscribe().recv().await?;
    return Ok(handler);
}

// We're the first - insert placeholder and load
let (tx, _) = tokio::sync::broadcast::channel(1);
loading.insert(bunker_pubkey.to_string(), tx.clone());
drop(loading);

// Load from DB...
let handler = load_from_db(...).await?;

// Broadcast to waiters
let _ = tx.send(handler.clone());
guard.loading.lock().await.remove(bunker_pubkey);

handlers.insert(bunker_pubkey.to_string(), handler.clone()).await;
```

This is optional - only implement if you see high DB load from duplicate queries.

---

## Summary: Action Items

### Must Fix Before Production

| Issue | Severity | Effort | Fix |
|-------|----------|--------|-----|
| Crypto blocks async | CRITICAL | Medium | Wrap in `spawn_blocking` |
| Insufficient workers | HIGH | Low | `num_workers = num_cpus * 2` |

### Should Fix Soon

| Issue | Severity | Effort | Fix |
|-------|----------|--------|-----|
| Silent drops | MODERATE | Medium | Send NIP-46 error response |

### Nice to Have

| Issue | Severity | Effort | Fix |
|-------|----------|--------|-----|
| spawn_blocking overhead | LOW | Medium | Consider `async-channel` |
| Cache contention | LOW | High | Deduplicate concurrent loads |

---

## Verification with tokio-console

After implementing fixes, verify with tokio-console:

1. **No stuck tasks** during signing bursts
   - All tasks should show reasonable busy/total ratio (<50%)

2. **spawn_blocking tasks** for crypto
   - Should see blocking tasks for encrypt/decrypt/sign
   - Main workers stay responsive

3. **Queue depth monitoring**
   - Add metric: `keycast_rpc_queue_depth`
   - Alert if consistently >50% capacity

4. **Worker utilization**
   - All workers should show activity
   - No single worker bottleneck

---

## Related Documentation

- `docs/debugging_production_issues.md` - Patterns and diagnosis
- `docs/keycast_work_queue_architecture.md` - Original design doc
- groups_relay commit `795121a` - worker_threads(8) fix that resolved 32-hour outage

---

## Appendix: Code Locations

| File | Line | Issue |
|------|------|-------|
| `signer/src/work_queue.rs` | 49-83 | Worker spawning |
| `signer/src/work_queue.rs` | 144-160 | spawn_blocking for recv |
| `signer/src/work_queue.rs` | 101-110 | Queue full handling |
| `signer/src/signer_daemon.rs` | 966-994 | Decrypt (blocks async) |
| `signer/src/signer_daemon.rs` | 1093-1098 | Encrypt (blocks async) |
| `signer/src/signer_daemon.rs` | 1347-1355 | Sign (blocks async) |
| `signer/src/signer_daemon.rs` | 325 | Cache definition |
