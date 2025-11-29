# Pseudo-Relay Architecture Proposal

Remove the signer daemon, external relay dependency, and hashring complexity by making Keycast act as its own NIP-46 relay.

## Summary

**Current:** Client → External Relay → Signer Daemon → External Relay → Client
**Proposed:** Client → Keycast WebSocket → Client

Keycast exposes `wss://login.divine.video/nip46` — a WebSocket endpoint that speaks standard Nostr relay protocol but only handles NIP-46 (kind 24133) events. The signer daemon, external relay dependencies, and hashring coordination are eliminated.

### Key Benefits

| Aspect | Current (Relay-Based) | Proposed (Pseudo-Relay) |
|--------|----------------------|-------------------------|
| Latency | 110-230ms | 30-90ms |
| External dependencies | 4 relays | None |
| Code complexity | ~3,500 lines | ~100 lines |
| Hashring needed | Yes (deduplication) | No (direct routing) |
| Autoscaling | Complex | Native Cloud Run |

## The Problem

### Unnecessary Indirection

The current architecture routes NIP-46 requests through external relays:

```
┌─────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Client    │────────►│  External Relay │◄────────│  Signer Daemon  │
│ (nostr app) │◄────────│ (relay.primal.net)│────────►│    (Keycast)    │
└─────────────┘         └─────────────────┘         └─────────────────┘
```

This indirection exists in NIP-46 to solve a real problem: allowing signers behind NAT/firewalls to receive requests. Both client and signer connect outbound to the relay, which acts as a meeting point.

### Why This Doesn't Apply to Keycast

Keycast is an OAuth-based service. The client already:
1. Connects to `https://login.divine.video` for the OAuth flow
2. Receives a bunker URL from Keycast's token endpoint
3. Trusts Keycast as the signing authority

The external relay solves none of these problems:
- **NAT traversal** — Keycast is a public server, always reachable
- **Self-hosting** — Keycast is a managed service, not self-hosted
- **Discovery** — Client already knows Keycast's URL from OAuth
- **Privacy** — Client already revealed itself during OAuth

The relay adds only latency and failure modes.

### Latency Cost

Every NIP-46 request currently requires:

| Step | Latency |
|------|---------|
| Client → Relay (publish request) | ~30-50ms |
| Relay → Signer (deliver event) | ~20-40ms |
| Signer processing | ~10-50ms |
| Signer → Relay (publish response) | ~30-50ms |
| Relay → Client (deliver event) | ~20-40ms |
| **Total** | **~110-230ms** |

With a direct connection:

| Step | Latency |
|------|---------|
| Client → Keycast (WebSocket) | ~10-20ms |
| Signing | ~10-50ms |
| Keycast → Client (WebSocket) | ~10-20ms |
| **Total** | **~30-90ms** |

**3-4x faster.**

## The Solution: Pseudo-Relay

### Concept

Keycast exposes a WebSocket endpoint that speaks standard Nostr relay protocol (NIP-01) but:
- Only accepts kind 24133 (NostrConnect) events
- Doesn't persist events
- Doesn't forward to other clients
- Signs inline and responds immediately

From the client's perspective, it's connecting to a relay. From Keycast's perspective, it's a direct RPC channel wearing a relay costume.

### Why "Pseudo-Relay" Instead of Custom Protocol

Standard NIP-46 client libraries (nostr-tools, nostr-sdk, etc.) expect relay protocol. By speaking relay protocol, Keycast gets:

- **Zero client changes** — `Nip46RemoteSigner` from nostr-tools works unmodified
- **Standard tooling** — `nak bunker` and other tools work
- **Ecosystem compatibility** — Any NIP-46 implementation works

The alternative (custom HTTP/WebSocket protocol) would require custom client code and fragment the ecosystem.

### Protocol Details

The pseudo-relay implements a minimal NIP-01 subset:

```
Client                              Keycast
   │                                   │
   │─── ["REQ", "sub1", {filter}] ────►│  Store sub_id only (ignore filter)
   │◄── ["EOSE", "sub1"] ──────────────│  Immediate EOSE (nothing stored)
   │                                   │
   │─── ["EVENT", nip46_request] ─────►│  Validate & process
   │◄── ["OK", event_id, true, ""] ────│  Acknowledge
   │◄── ["EVENT", "sub1", response] ───│  Immediate response
   │                                   │
   │     ... idle for 1 minute ...     │
   │                                   │
   │◄── ["CLOSED", "sub1", "idle"] ────│  Server closes idle connection
   │                                   │
   │     [client auto-reconnects]      │
```

### Simplified State Model

The pseudo-relay is **not a real relay** — it's an RPC endpoint in relay protocol clothing. We enforce correct protocol behavior at the boundary but simplify internally:

```rust
struct Nip46Connection {
    sub_id: Option<String>,  // Just the subscription ID, no filter storage
}
```

**Why no filter matching?**
- We know exactly what we're sending: NIP-46 responses to requests we just received
- Responses are immediate, not stored for later
- Clients use standard filters but we don't need to parse them

### Protocol Enforcement

Clients don't know we're a pseudo-relay. We enforce correct behavior so clients remain compatible with real relays:

```rust
match message {
    ["REQ", sub_id, ..._filters] => {
        // Enforce: valid subscription ID per NIP-01
        if sub_id.is_empty() || sub_id.len() > 64 {
            return send(["CLOSED", sub_id, "error: invalid subscription id"]);
        }
        state.sub_id = Some(sub_id.clone());
        send(["EOSE", sub_id]);
    }

    ["EVENT", event] => {
        // Enforce: must have active subscription first
        if state.sub_id.is_none() {
            return send(["OK", event.id, false, "error: send REQ first"]);
        }

        // Enforce: only kind 24133
        if event.kind != 24133 {
            return send(["OK", event.id, false, "blocked: only kind 24133"]);
        }

        // Enforce: valid event signature
        if event.verify().is_err() {
            return send(["OK", event.id, false, "invalid: signature failed"]);
        }

        // Process and respond...
    }

    ["CLOSE", sub_id] => {
        if state.sub_id.as_ref() == Some(&sub_id) {
            state.sub_id = None;
        }
    }

    _ => send(["NOTICE", "error: unrecognized message"])
}
```

**Handled messages:**
- `REQ` — Store subscription ID (ignore filters), send EOSE immediately
- `EVENT` — Validate kind=24133, require active subscription, process NIP-46
- `CLOSE` — Clear subscription ID

**Not implemented (by design):**
- Filter parsing/matching
- Event persistence
- Historical queries
- Multiple event kinds
- Forwarding to other subscribers

### NIP-11 Relay Information

The endpoint responds to HTTP GET with relay metadata:

```json
{
  "name": "Keycast NIP-46 Pseudo-Relay",
  "description": "Internal relay for Keycast remote signing",
  "supported_nips": [1, 11, 46],
  "software": "keycast",
  "limitation": {
    "auth_required": false,
    "max_message_length": 65536,
    "max_subscriptions": 1,
    "max_event_tags": 100,
    "created_at_lower_limit": 0
  }
}
```

### Bunker URL Change

The OAuth token response changes from:

```
bunker://<pubkey>?relay=wss://relay.divine.video&relay=wss://relay.primal.net&secret=<secret>
```

To:

```
bunker://<pubkey>?relay=wss://login.divine.video/nip46&secret=<secret>
```

NIP-46 specifies that the signer chooses the relay. Keycast generates bunker URLs, so this is entirely within spec.

## Architecture Comparison

### Current (Signer Daemon)

```
┌─────────────────────────────────────────────────────────────────┐
│                         Keycast Server                          │
│                                                                 │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │  OAuth/API  │    │  Signer Daemon   │    │ SigningHandler│  │
│  │   (Axum)    │    │ (relay subscriber)│───►│    Cache      │  │
│  └─────────────┘    └────────┬─────────┘    └───────────────┘  │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │ subscribes
                               ▼
                      External Relay(s)
                               ▲
                               │ publishes
                    ┌──────────┴──────────┐
                    │      Client         │
                    └─────────────────────┘
```

**Components:**
- Signer daemon process (~2,000 lines)
- nostr-sdk relay connections
- External relay dependency
- Subscription management
- Event routing through relays

### Proposed (Pseudo-Relay)

```
┌─────────────────────────────────────────────────────────────────┐
│                         Keycast Server                          │
│                                                                 │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │  OAuth/API  │    │  Pseudo-Relay    │    │ SigningHandler│  │
│  │   (Axum)    │    │  WS /nip46       │───►│    Cache      │  │
│  └─────────────┘    └──────────────────┘    └───────────────┘  │
│                              ▲                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │ WebSocket
                    ┌──────────┴──────────┐
                    │      Client         │
                    └─────────────────────┘
```

**Components:**
- Single WebSocket endpoint (~100 lines)
- No relay dependencies
- Direct request/response
- Reuses existing SigningHandler infrastructure
- No hashring or instance coordination

## Code Changes

### Files to Delete (~3,500 lines)

| File | Lines | Purpose |
|------|-------|---------|
| `signer/src/signer_daemon.rs` | 1,630 | Relay subscription, NIP-46 handling |
| `signer/src/signer_manager.rs` | 313 | Process management (legacy) |
| `signer/tests/client_pubkey_tests.rs` | 464 | Daemon-specific tests |
| `signer/tests/permission_validation_tests.rs` | 561 | Can be adapted for pseudo-relay |
| `core/src/hashring.rs` | 330 | No longer needed (direct routing) |
| `core/src/instance_registry.rs` | 283 | No longer needed (no coordination) |
| `database/migrations/0002_signer_instances.sql` | — | Hashring coordination table |

**Keep:** `signer/tests/secret_key_format_test.rs` (key parsing tests, still useful)

### Files to Modify

| File | Change |
|------|--------|
| `api/src/api/http/mod.rs` | Add WebSocket route for `/nip46` |
| `api/src/api/http/oauth.rs` | Change bunker URL to `wss://login.divine.video/nip46` |
| `keycast/src/main.rs` | Remove signer daemon, hashring, instance registry |
| `core/src/lib.rs` | Remove hashring and instance_registry modules |

### Code to Add (~100 lines)

New file: `api/src/api/http/nip46_ws.rs`

```rust
use axum::{
    extract::{State, WebSocketUpgrade},
    response::IntoResponse,
};
use std::time::Duration;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60); // 1 minute
const PING_INTERVAL: Duration = Duration::from_secs(30);

struct Nip46Connection {
    sub_id: Option<String>,
}

/// WebSocket upgrade handler - also serves NIP-11 for HTTP GET
pub async fn nip46_handler(
    ws: Option<WebSocketUpgrade>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match ws {
        Some(ws) => ws.on_upgrade(|socket| handle_connection(socket, state)),
        None => nip11_response(),  // HTTP GET returns relay info
    }
}

async fn handle_connection(mut socket: WebSocket, state: AppState) {
    let mut conn = Nip46Connection { sub_id: None };
    let mut last_activity = Instant::now();
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);

    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(msg)) => {
                        last_activity = Instant::now();
                        handle_message(&mut socket, &mut conn, &state, msg).await;
                    }
                    _ => break,
                }
            }
            _ = ping_interval.tick() => {
                // Check idle timeout
                if last_activity.elapsed() > IDLE_TIMEOUT {
                    if let Some(sub_id) = &conn.sub_id {
                        send(&mut socket, json!(["CLOSED", sub_id, "idle timeout"])).await;
                    }
                    break;
                }
                // Send ping to detect dead connections
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn handle_message(socket: &mut WebSocket, conn: &mut Nip46Connection, state: &AppState, msg: Message) {
    let text = match msg { Message::Text(t) => t, _ => return };
    let parsed: Vec<Value> = match serde_json::from_str(&text) { Ok(v) => v, _ => return };

    match parsed.get(0).and_then(|v| v.as_str()) {
        Some("REQ") => {
            let sub_id = parsed.get(1).and_then(|v| v.as_str()).unwrap_or("");
            if sub_id.is_empty() || sub_id.len() > 64 {
                send(socket, json!(["CLOSED", sub_id, "error: invalid subscription id"])).await;
                return;
            }
            conn.sub_id = Some(sub_id.to_string());
            send(socket, json!(["EOSE", sub_id])).await;
        }
        Some("EVENT") => {
            let Some(sub_id) = &conn.sub_id else {
                send(socket, json!(["OK", "", false, "error: send REQ first"])).await;
                return;
            };
            // Validate and process NIP-46 event...
            // Reuse existing nostr_rpc.rs signing logic
        }
        Some("CLOSE") => {
            if let Some(sub_id) = parsed.get(1).and_then(|v| v.as_str()) {
                if conn.sub_id.as_deref() == Some(sub_id) {
                    conn.sub_id = None;
                }
            }
        }
        _ => send(socket, json!(["NOTICE", "error: unrecognized message"])).await,
    }
}
```

### Code to Reuse

| Component | Location | Purpose |
|-----------|----------|---------|
| `SigningHandler` trait | `core/src/signing_handler.rs` | Abstract signing interface |
| `AuthorizationHandler` | `signer/src/signer_daemon.rs` | Permission validation, key access |
| `get_user_keys()` | `api/src/api/http/nostr_rpc.rs` | Fast-path key lookup |
| Permission validation | `api/src/api/http/auth.rs` | Event signing permissions |

The `AuthorizationHandler` struct and its `SigningHandler` implementation move from the signer crate to core or api, stripped of relay-specific code.

## Cloud Run & Scaling

The NIP-46 request-response pattern is well-suited to Cloud Run. Each signing request arrives, gets processed, and returns a response — no stateful pub/sub relationships or Redis synchronization needed.

### Why Hashring Is No Longer Needed

**Current architecture (relay-based):**
- External relays broadcast events to ALL Keycast instances
- All instances receive every NIP-46 request
- Hashring determines which instance processes each bunker pubkey
- Purpose: **deduplication** (prevent multiple instances handling same request)

**Pseudo-relay architecture:**
- Client connects directly to ONE instance via load balancer
- Only that instance receives the request
- No broadcast, no deduplication needed
- Any instance can handle any bunker pubkey via on-demand key loading

```
┌────────────────────────────────────────────────────────────────────┐
│                  Cloud Run Load Balancer                           │
│                         │                                          │
│         ┌───────────────┼───────────────┐                         │
│         ▼               ▼               ▼                         │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐                   │
│   │Instance A│    │Instance B│    │Instance C│                   │
│   │          │    │          │    │          │                   │
│   │ On-demand│    │ On-demand│    │ On-demand│                   │
│   │ key load │    │ key load │    │ key load │                   │
│   └──────────┘    └──────────┘    └──────────┘                   │
│         │               │               │                         │
│         └───────────────┴───────────────┘                         │
│                         │                                          │
│                    Database + KMS                                  │
└────────────────────────────────────────────────────────────────────┘
```

### Cloud Run Configuration

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"       # Eliminate cold starts
        autoscaling.knative.dev/maxScale: "10"      # Cost control
        run.googleapis.com/cpu-throttling: "false"  # Keep CPU for responsive WebSocket
    spec:
      containerConcurrency: 500   # NIP-46 requests are lightweight
      timeoutSeconds: 300         # 5 minutes (default is fine)
```

| Setting | Value | Rationale |
|---------|-------|-----------|
| `timeout` | 300s (5 min) | Default is sufficient; we close idle at 1 min |
| `concurrency` | 500 | NIP-46 RPC is lightweight; many concurrent OK |
| `min-instances` | 1 | Eliminates cold starts |
| `max-instances` | 10 | Cost control; adjust based on traffic |
| `cpu` | 1 vCPU | Sufficient for WebSocket + signing |
| `memory` | 256-512 MB | Rust is memory-efficient |
| `cpu-throttling` | false | Responsive WebSocket handling |
| HTTP/2 e2e | **Disabled** | Required for WebSocket (Google recommendation) |

### Connection Lifecycle: 1-Minute Idle Timeout

**Problem:** WebSocket connections count toward Cloud Run concurrency even when idle. An instance with open WebSockets is billed continuously.

**Solution:** Aggressive 1-minute idle timeout encourages "connect, sign, disconnect" pattern.

| Timeout | Value | Purpose |
|---------|-------|---------|
| Cloud Run request timeout | 5 minutes | Hard limit (plenty of headroom) |
| Server idle timeout | **1 minute** | Graceful close before waste |
| Ping interval | 30 seconds | Detect dead connections |

**Flow:**
```
t=0s    Client connects, sends REQ
t=0.1s  Client sends EVENT (sign request)
t=0.2s  Server responds with signed event
t=30s   Server sends ping, client responds pong
t=60s   No activity → server sends CLOSED, disconnects
t=70s   Client needs to sign → reconnects (transparent via nostr-tools)
```

**Why 1 minute, not longer?**
- NIP-46 signing is bursty: sign a few events, then idle
- Idle connections waste money (billed continuously)
- Reconnection is cheap (~100ms) and automatic
- Encourages stateless "one connection per session" pattern

### Graceful Shutdown (SIGTERM Handling)

Cloud Run sends **SIGTERM** before terminating instances, with a 10-second grace period before SIGKILL. Critical requirements:

1. **Application must run as PID 1** — or signals won't be forwarded
2. **Drain connections within 5 seconds** — leave buffer before SIGKILL

**Dockerfile (exec form required):**
```dockerfile
# Correct - receives SIGTERM directly
CMD ["./keycast"]

# Wrong - shell doesn't forward signals
CMD ./keycast
```

**Rust shutdown handler:**
```rust
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, draining connections (5s max)");
}
```

### Ping/Pong Keepalive

Application-level ping/pong detects dead connections and keeps NAT tables alive:

```rust
let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

loop {
    tokio::select! {
        msg = socket.recv() => { /* handle */ }
        _ = ping_interval.tick() => {
            if socket.send(Message::Ping(vec![])).await.is_err() {
                break; // Connection dead
            }
        }
    }
}
```

30-second interval: aggressive enough to detect failures, not so frequent as to waste bandwidth.

### Client Reconnection

nostr-tools `AbstractRelay` supports automatic reconnection when `enableReconnect: true`:

```typescript
// Exponential backoff (milliseconds)
resubscribeBackoff: [10000, 10000, 10000, 20000, 20000, 30000, 60000]

// On reconnect: automatically re-subscribes
for (const sub of this.openSubs.values()) {
  sub.eosed = false
  sub.fire()  // Re-sends REQ
}
```

This means idle timeout is **transparent to applications** — the library handles reconnection.

### Autoscaling Behavior

Cloud Run scales based on **concurrent connections** (targeting 60% of max):

| containerConcurrency | Scale-up trigger | At limit |
|---------------------|------------------|----------|
| 80 (default) | ~48 connections | Too low for WebSocket |
| 500 | ~300 connections | Good balance |
| 1000 (max) | ~600 connections | High throughput |

**With 1-minute idle timeout:**
- Connections don't accumulate (closed quickly)
- Concurrency reflects actual signing load
- Autoscaling responds to real demand
- Cost stays proportional to usage

### Session Affinity Caveat

Session affinity is **"best effort" only**. Even with affinity enabled, Cloud Run may route reconnecting clients to different instances during scale events. This is fine for pseudo-relay because:

- Each request is self-contained (RPC pattern)
- Any instance can handle any bunker pubkey
- No session state needed between requests

### Cost Considerations

Cloud Run bills continuously for instances with open WebSocket connections:

| Scenario | Instances | Monthly Cost (approx) |
|----------|-----------|----------------------|
| Low traffic, min=1 | 1 | ~$63 |
| Moderate (1000 concurrent) | 2-3 | ~$150-200 |
| High (10,000 concurrent) | 10-20 | ~$600-1,200 |
| Very high (100,000+) | Consider dedicated infra | — |

The break-even point for dedicated Kubernetes is roughly **10,000+ sustained concurrent connections**. For typical NIP-46 relay traffic, Cloud Run is cost-effective.

**Cost optimization via 1-minute idle timeout:**
- Connections close quickly when idle
- Only actively-signing clients hold resources
- Scales down faster when traffic drops

### HTTP RPC Alternative

For high-scale deployments, the existing HTTP RPC endpoint (`POST /api/nostr`) offers better scaling characteristics:

| Aspect | WebSocket Pseudo-Relay | HTTP RPC |
|--------|------------------------|----------|
| Connection overhead | Per-session | Per-request |
| Idle resource usage | Connections count | None |
| Load balancing | Connection-sticky | Natural distribution |
| Autoscaling | Requires idle timeout | Optimal |
| Client compatibility | Standard NIP-46 | Custom integration |

**Recommendation:**
- **Pseudo-relay**: For standard NIP-46 client compatibility
- **HTTP RPC**: For first-party apps and high-scale scenarios

Both share the same signing infrastructure and can coexist.

## Benefits

### Performance
- **3-4x lower latency** — No relay round-trip
- **Predictable timing** — No relay queue delays
- **Connection reuse** — WebSocket stays open for multiple requests

### Reliability
- **Fewer failure modes** — No external relay outages
- **Simpler debugging** — Direct request/response correlation
- **No message loss** — No relay queuing/expiration issues

### Simplicity
- **~3,500 lines deleted** — Signer daemon, hashring, instance registry removed
- **One process** — No daemon management
- **No nostr-sdk relay dependency** — Still used for crypto
- **No instance coordination** — Each instance is independent

### Compatibility
- **Standard protocol** — NIP-01 relay messages
- **Existing tooling** — nostr-tools, nak, etc. work unchanged
- **Graceful migration** — Old bunker URLs could fallback to relay

## Migration Path

### Phase 1: Add Pseudo-Relay (Non-Breaking)
1. Implement `/nip46` WebSocket endpoint
2. Test with nostr-tools `Nip46RemoteSigner`
3. Keep signer daemon running for existing bunker URLs

### Phase 2: Switch Default
1. New OAuth authorizations get `wss://login.divine.video/nip46` bunker URLs
2. Existing authorizations continue using relay-based URLs
3. Monitor both paths

### Phase 3: Deprecate Signer Daemon
1. Migrate remaining clients to new bunker URLs
2. Remove signer daemon code
3. Remove external relay configuration

## FAQ

### What if login.divine.video is down?

Same as now — if Keycast is down, signing doesn't work. The external relay doesn't help because the signer daemon (which runs on Keycast) would also be down.

### What about clients that already have bunker URLs pointing to external relays?

They continue working until migrated. The signer daemon can run in parallel during migration. Alternatively, revoke and reissue authorizations.

### Is this compliant with NIP-46?

Yes. NIP-46 says the signer provides the bunker URL and chooses which relay(s) to include. The spec doesn't require external relays.

### Why not just HTTP RPC?

HTTP RPC already exists (`POST /api/nostr`) but requires a custom client. The pseudo-relay speaks standard relay protocol, so existing NIP-46 libraries work without modification. Both can coexist.

### What about the "indirection is important for self-hosting" argument?

That argument (from nostr-protocol/nips#1207) applies to general-purpose NIP-46 signers that users might run on home hardware. Keycast is a managed OAuth service — the client already trusts and connects to it directly. The indirection solves nothing for this use case.

## References

### Nostr Protocol
- [NIP-01: Basic Protocol Flow](https://github.com/nostr-protocol/nips/blob/master/01.md) — Relay message format
- [NIP-11: Relay Information](https://github.com/nostr-protocol/nips/blob/master/11.md) — Relay metadata endpoint
- [NIP-46: Nostr Remote Signing](https://github.com/nostr-protocol/nips/blob/master/46.md) — Remote signer protocol
- [nostr-protocol/nips#1207: HTTP alternative discussion](https://github.com/nostr-protocol/nips/issues/1207)

### Client Libraries
- [nostr-tools nip46.ts](https://github.com/nbd-wtf/nostr-tools/blob/master/nip46.ts) — BunkerSigner implementation
- [nostr-tools abstract-relay.ts](https://github.com/nbd-wtf/nostr-tools/blob/master/abstract-relay.ts) — Reconnection logic

### Cloud Run
- [Cloud Run WebSockets](https://cloud.google.com/run/docs/triggering/websockets) — WebSocket support and limitations
- [Cloud Run Request Timeout](https://cloud.google.com/run/docs/configuring/request-timeout) — Default 5 min, max 60 min
- [Cloud Run Concurrency](https://cloud.google.com/run/docs/about-concurrency) — Max 1000 per instance
- [Cloud Run Autoscaling](https://cloud.google.com/run/docs/about-instance-autoscaling) — 60% concurrency target

### Community Resources
- [nostr-rs-relay](https://github.com/scsibug/nostr-rs-relay) — Rust Nostr relay implementation
- [gabihodoroaga/http-grpc-websocket](https://github.com/gabihodoroaga/http-grpc-websocket) — Cloud Run WebSocket patterns
