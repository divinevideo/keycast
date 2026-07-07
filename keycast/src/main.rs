// ABOUTME: Unified binary that runs both API server and Signer daemon in one process
// ABOUTME: API uses HttpRpcHandler cache, NIP-46 signer uses Nip46Handler cache

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use cluster_hashring::ClusterCoordinator;
use dotenv::dotenv;
use keycast_api::api::tenant::Tenant;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::TenantCache;
use keycast_core::authorization_channel;
use keycast_core::database::Database;
#[cfg(feature = "aws")]
use keycast_core::encryption::aws_key_manager::AwsKeyManager;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_signer::{RelayQueue, UnifiedSigner};
use moka::future::Cache;
use nostr_sdk::Keys;
use serde_json::json;
use std::env;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::signal;
use tokio::sync::Notify;
use tokio_util::task::TaskTracker;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zeroize::Zeroizing;

/// Maximum time the readiness probe will wait on the database before failing.
/// Kept well under typical kubelet `timeoutSeconds` so a stalled connection
/// fails the probe fast instead of hanging it.
const READYZ_DB_TIMEOUT: Duration = Duration::from_millis(800);

/// Duration the process pauses between flipping the readiness probe to 503
/// and starting to drain accepted connections. On GKE this is the window during
/// which the pod's deletion triggers endpoint/NEG detach (the Pod is removed
/// from the Service EndpointSlice and the GCLB NEG) so the load balancer stops
/// routing new traffic to us; the readiness probe flipping to 503 only
/// *reinforces* this — it is the Pod's `deletionTimestamp`, not a failing
/// readiness probe, that drives endpoint removal on a normal scale-down. NEG
/// detach propagation can take >10s, so the default covers a conservative upper
/// bound. Keeping this out of the drain budget is critical — otherwise new
/// NIP-46 sign requests arriving during these seconds would be rejected
/// mid-request and trigger client-side reconnect storms on scale-down.
///
/// Cloud Run has **no** readiness-probe-driven endpoint removal: a terminating
/// instance is removed from routing by the platform, and peer rebalancing comes
/// from the cluster coordinator's `leave` event (published at the start of
/// phase 3 — see `deregister_within_signer_budget`), not from this pause. Set
/// `SHUTDOWN_PRE_DRAIN_SECS=0` there. Override with `SHUTDOWN_PRE_DRAIN_SECS`
/// (e.g. `0` in local dev / tests).
const DEFAULT_SHUTDOWN_PRE_DRAIN_SECS: u64 = 15;

/// Maximum time we wait for axum to drain in-flight HTTP requests after we
/// stop accepting new connections. The sum of `pre_drain + http_drain +
/// signer_drain` plus the teardown margin must fit inside the Deployment's
/// `terminationGracePeriodSeconds` — otherwise the kubelet SIGKILLs us
/// mid-drain. Defaults are sized so `pre_drain(15) + http_drain(40) +
/// signer_drain(10) + margin(10) = 75` fits `terminationGracePeriodSeconds: 75`
/// exactly. When the configured budget does not fit the ceiling it is clamped
/// down proportionally at runtime (see `clamp_shutdown_timings`). Override with
/// `SHUTDOWN_HTTP_DRAIN_SECS`.
const DEFAULT_SHUTDOWN_HTTP_DRAIN_SECS: u64 = 40;

/// Budget for the whole of phase 3: the bounded cluster deregister
/// (`CLUSTER_DEREGISTER_TIMEOUT`, carved out of this budget — see
/// `deregister_within_signer_budget`) followed by the relay queue, NIP-46
/// signer, and tracked background task drain before/while tearing down the
/// relay client. Must comfortably exceed `CLUSTER_DEREGISTER_TIMEOUT` or the
/// drain is starved. Override with `SHUTDOWN_SIGNER_DRAIN_SECS`.
const DEFAULT_SHUTDOWN_SIGNER_DRAIN_SECS: u64 = 10;

/// Upper bound on the platform's post-SIGTERM grace (the kubelet's
/// `terminationGracePeriodSeconds` on GKE, or the ~10s SIGTERM→SIGKILL window
/// on Cloud Run) used to size and clamp the shutdown phase budgets.
///
/// **This default must be set per deployment** — it does NOT change platform
/// behavior, it only tells keycast how much grace it actually has so the phased
/// drain provably fits. The default of 75 matches the intended GKE grace
/// (`terminationGracePeriodSeconds: 75`) ONLY; Cloud Run, which enforces ~10s,
/// MUST set `SHUTDOWN_GRACE_PERIOD_CEILING_SECS=10` (see `cloudbuild.yaml`).
/// Leaving the default on a platform with a smaller real grace would let the
/// full budget run and be SIGKILLed mid-drain. When the configured budget
/// exceeds the ceiling it is clamped down proportionally at runtime rather than
/// run as-is (see `clamp_shutdown_timings`). Override with
/// `SHUTDOWN_GRACE_PERIOD_CEILING_SECS`.
const DEFAULT_SHUTDOWN_GRACE_CEILING_SECS: u64 = 75;

/// Headroom reserved between the end of the phased drain and the platform
/// SIGKILL for DB pool close, tracing flush, and other post-drain cleanup.
/// Subtracted from the ceiling when sizing/clamping the phase budgets and used
/// as the phase-4 pool-close bound. Configurable because on a tight grace
/// (Cloud Run's ~10s) the GKE-sized 10s margin alone would consume the whole
/// ceiling; there it must be set small (1–2s) via `SHUTDOWN_TEARDOWN_MARGIN_SECS`.
const DEFAULT_SHUTDOWN_TEARDOWN_MARGIN_SECS: u64 = 10;

/// Headroom carved out of the teardown margin for the final "Graceful shutdown
/// complete" log line (and tracing flush) to be emitted *after* the DB pool
/// close future resolves but *before* the platform SIGKILL. The phase-4 pool
/// close is bounded by `teardown_margin - this` so the success/timeout log
/// always has time to flush.
const POOL_CLOSE_LOG_HEADROOM: Duration = Duration::from_secs(2);

/// Upper bound on the shutdown-time cluster deregister (publish `leave` +
/// remove from the registry). It opens phase 3 — immediately before the relay
/// queue closes — and is carved OUT of the `signer_drain` budget (further
/// capped at `signer_drain` itself; see `deregister_within_signer_budget`), so
/// it never adds wall-clock on top of the phase budgets that
/// `validate_shutdown_timings`/`clamp_shutdown_timings` prove fit the grace
/// ceiling. Kept small so a dead Redis cannot eat the drain budget.
/// `signer_drain` must comfortably exceed this or the queue drain is starved —
/// the Cloud Run sizing in `cloudbuild.yaml` accounts for it explicitly.
const CLUSTER_DEREGISTER_TIMEOUT: Duration = Duration::from_secs(2);

/// Slice of the phase-3 `signer_drain` budget reserved for a best-effort relay
/// client close (`Client::shutdown`) — graceful WebSocket close plus a flush of
/// any already-published NIP-46 responses. It is reserved so the relay close is
/// never starved by a slow worker/tracker drain, and it bounds the *additional*
/// close attempt made on the drain-timeout path. Capped at half the budget so
/// the worker/tracker drain always keeps the larger share.
const RELAY_CLOSE_BUDGET: Duration = Duration::from_secs(2);

/// Per-field sanity ceiling on each `SHUTDOWN_*_SECS` env var. Values above
/// this fall back to the per-field default with a warning. 1 day is far
/// above any plausible operational value (real drains are seconds, not
/// hours) but prevents a typo like `SHUTDOWN_PRE_DRAIN_SECS=18446744073709551600`
/// from making `ShutdownTimings::total_budget()` overflow — which would
/// panic before the validate-and-warn path could surface an operator-actionable
/// message. Three fields at the ceiling sum to 3 days, comfortably inside u64.
const SHUTDOWN_PER_FIELD_CEILING_SECS: u64 = 24 * 3600;

/// Parsed shutdown phase timings. See the `DEFAULT_SHUTDOWN_*` constants and
/// the graceful-shutdown sequence in `async_main` for the phase breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShutdownTimings {
    /// Sleep between setting readiness=503 and closing the accept loop.
    pre_drain: Duration,
    /// Maximum wait for axum HTTP drain.
    http_drain: Duration,
    /// Maximum wait for signer + tracked background tasks.
    signer_drain: Duration,
}

impl ShutdownTimings {
    /// Sum of all three phase durations. Does NOT include the teardown
    /// margin — add that separately when comparing against a grace-period
    /// ceiling. The phase-3 cluster deregister needs no separate term:
    /// it is carved out of `signer_drain` (see
    /// `deregister_within_signer_budget`), so this sum already covers it.
    fn total_budget(&self) -> Duration {
        self.pre_drain + self.http_drain + self.signer_drain
    }
}

/// Read a non-negative integer duration (in seconds) from the given env var,
/// falling back to `default_secs` if unset, unparseable, or above
/// `SHUTDOWN_PER_FIELD_CEILING_SECS`. Zero is a valid value and is respected
/// (not treated as "use default").
///
/// The per-field ceiling prevents an operator typo near `u64::MAX` from
/// propagating into `ShutdownTimings::total_budget()` where the `+` sum
/// would panic on overflow — which would abort the process before the
/// validate-and-warn path could surface an operator-actionable message.
fn parse_duration_secs_env(var: &str, default_secs: u64) -> Duration {
    match env::var(var) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > SHUTDOWN_PER_FIELD_CEILING_SECS => {
                tracing::warn!(
                    env_var = var,
                    value = secs,
                    ceiling_secs = SHUTDOWN_PER_FIELD_CEILING_SECS,
                    default_secs,
                    "Shutdown timing env var exceeds per-field sanity ceiling; using default"
                );
                Duration::from_secs(default_secs)
            }
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => {
                tracing::warn!(
                    env_var = var,
                    value = %raw,
                    default_secs,
                    "Invalid value for shutdown timing env var; using default"
                );
                Duration::from_secs(default_secs)
            }
        },
        Err(_) => Duration::from_secs(default_secs),
    }
}

/// Parse all three shutdown phase durations from the environment.
fn parse_shutdown_timings() -> ShutdownTimings {
    ShutdownTimings {
        pre_drain: parse_duration_secs_env(
            "SHUTDOWN_PRE_DRAIN_SECS",
            DEFAULT_SHUTDOWN_PRE_DRAIN_SECS,
        ),
        http_drain: parse_duration_secs_env(
            "SHUTDOWN_HTTP_DRAIN_SECS",
            DEFAULT_SHUTDOWN_HTTP_DRAIN_SECS,
        ),
        signer_drain: parse_duration_secs_env(
            "SHUTDOWN_SIGNER_DRAIN_SECS",
            DEFAULT_SHUTDOWN_SIGNER_DRAIN_SECS,
        ),
    }
}

/// Parse the configured `terminationGracePeriodSeconds` ceiling against
/// which the phased shutdown budget is validated at startup. Override with
/// `SHUTDOWN_GRACE_PERIOD_CEILING_SECS` when the Deployment's grace period
/// changes without a keycast release.
fn parse_shutdown_grace_ceiling() -> Duration {
    parse_duration_secs_env(
        "SHUTDOWN_GRACE_PERIOD_CEILING_SECS",
        DEFAULT_SHUTDOWN_GRACE_CEILING_SECS,
    )
}

/// Parse the teardown margin (post-drain headroom for DB pool close, tracing
/// flush, and process teardown). Override with `SHUTDOWN_TEARDOWN_MARGIN_SECS`.
fn parse_shutdown_teardown_margin() -> Duration {
    parse_duration_secs_env(
        "SHUTDOWN_TEARDOWN_MARGIN_SECS",
        DEFAULT_SHUTDOWN_TEARDOWN_MARGIN_SECS,
    )
}

/// Whether `SHUTDOWN_PRE_DRAIN_SECS` was explicitly set to a valid value.
///
/// Used by `clamp_shutdown_timings` to decide whether the pre-drain pause is
/// load-bearing (operator chose it deliberately — e.g. to cover GKE NEG-detach
/// propagation, or `0` on Cloud Run) and must be preserved when clamping, or
/// is merely the built-in default and may be scaled down with the drains to
/// fit a tight ceiling.
fn pre_drain_was_explicitly_set() -> bool {
    matches!(
        env::var("SHUTDOWN_PRE_DRAIN_SECS"),
        Ok(raw) if raw
            .trim()
            .parse::<u64>()
            .map(|secs| secs <= SHUTDOWN_PER_FIELD_CEILING_SECS)
            .unwrap_or(false)
    )
}

/// Check that `timings.total_budget() + margin <= ceiling`.
/// The margin is the reserved headroom for DB pool close, tracing flush, and
/// process teardown between the end of the phased drain and the platform
/// SIGKILL. Exact equality is accepted (the margin fully fits); anything
/// larger is rejected.
///
/// Returned `Err(String)` is operator-actionable and includes the current
/// budget, margin, and ceiling so it can be dropped straight into a log line.
/// This is the predicate `clamp_shutdown_timings` uses to decide whether the
/// configured budget must be scaled down to fit the platform grace.
fn validate_shutdown_timings(
    timings: &ShutdownTimings,
    ceiling: Duration,
    margin: Duration,
) -> Result<(), String> {
    let total = timings.total_budget();
    let required = total + margin;
    if required > ceiling {
        Err(format!(
            "shutdown phase budget ({total_secs}s) + teardown margin ({margin_secs}s) \
             = {required_secs}s does not fit inside SHUTDOWN_GRACE_PERIOD_CEILING_SECS \
             = {ceiling_secs}s (pre_drain={pre}s, http_drain={http}s, signer_drain={sig}s); \
             the platform will SIGKILL mid-drain at its grace period",
            total_secs = total.as_secs(),
            margin_secs = margin.as_secs(),
            required_secs = required.as_secs(),
            ceiling_secs = ceiling.as_secs(),
            pre = timings.pre_drain.as_secs(),
            http = timings.http_drain.as_secs(),
            sig = timings.signer_drain.as_secs(),
        ))
    } else {
        Ok(())
    }
}

/// Outcome of clamping the configured phase budget against the platform grace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClampedTimings {
    timings: ShutdownTimings,
    /// True when the configured budget did not fit and was scaled down.
    clamped: bool,
}

/// Scale the phase budget down so it provably fits the platform grace:
/// `pre_drain + http_drain + signer_drain + margin <= ceiling`.
///
/// If the configured budget already fits, the timings are returned unchanged
/// with `clamped == false`. Otherwise the phases are reduced into the
/// `available = ceiling - margin` window:
///
/// - When `pre_drain_explicit` is true the pre-drain pause is load-bearing
///   (the operator chose it — e.g. to cover GKE NEG-detach propagation, or `0`
///   on Cloud Run), so it is preserved (capped at `available`) and only
///   `http_drain`/`signer_drain` are scaled proportionally into the remainder.
/// - Otherwise pre_drain is just the built-in default and is scaled
///   proportionally alongside the drains, so a tight ceiling does not get its
///   whole budget eaten by an unconfigured pre-drain.
///
/// Proportional scaling uses millisecond integer math and floors each result,
/// so the clamped sum is always `<= available` (never overshoots the ceiling).
fn clamp_shutdown_timings(
    timings: ShutdownTimings,
    ceiling: Duration,
    margin: Duration,
    pre_drain_explicit: bool,
) -> ClampedTimings {
    let available = ceiling.saturating_sub(margin);
    if timings.total_budget() <= available {
        return ClampedTimings {
            timings,
            clamped: false,
        };
    }

    // pre_drain kept fixed (capped) when explicit; otherwise it joins the
    // proportional pool with the two drains.
    let (kept_pre, scalable_pre) = if pre_drain_explicit {
        (timings.pre_drain.min(available), Duration::ZERO)
    } else {
        (Duration::ZERO, timings.pre_drain)
    };

    let remaining = available.saturating_sub(kept_pre);
    let scalable_total = scalable_pre + timings.http_drain + timings.signer_drain;

    // Scale `d` into `remaining` by the share it holds of `scalable_total`.
    let scale = |d: Duration| -> Duration {
        if scalable_total.is_zero() {
            Duration::ZERO
        } else {
            let scaled_ms = d.as_millis() * remaining.as_millis() / scalable_total.as_millis();
            Duration::from_millis(scaled_ms as u64)
        }
    };

    ClampedTimings {
        timings: ShutdownTimings {
            pre_drain: kept_pre + scale(scalable_pre),
            http_drain: scale(timings.http_drain),
            signer_drain: scale(timings.signer_drain),
        },
        clamped: true,
    }
}

/// The effective shutdown plan resolved from the environment: the
/// operator-configured timings, the clamped (effective) timings, the grace
/// ceiling, and the teardown margin. Resolved once at startup (for the
/// fits/clamped log) and once at shutdown (for the real phase budgets) so both
/// paths apply identical clamping.
struct ShutdownPlan {
    configured: ShutdownTimings,
    clamped: ClampedTimings,
    ceiling: Duration,
    margin: Duration,
}

/// Parse phase timings, ceiling, and teardown margin from the environment and
/// clamp the phases so they provably fit the grace ceiling.
fn resolve_shutdown_plan() -> ShutdownPlan {
    let configured = parse_shutdown_timings();
    let ceiling = parse_shutdown_grace_ceiling();
    let margin = parse_shutdown_teardown_margin();
    let clamped =
        clamp_shutdown_timings(configured, ceiling, margin, pre_drain_was_explicitly_set());
    ShutdownPlan {
        configured,
        clamped,
        ceiling,
        margin,
    }
}

/// Flip the unready flag (so `/healthz/ready` returns 503) and then sleep for
/// `duration` to give Kubernetes time to remove us from the Service
/// EndpointSlice before we close the accept loop. Must set the flag **before**
/// awaiting anything so the next readiness probe sees the new value.
async fn pre_drain_pause(unready: &Arc<AtomicBool>, duration: Duration) {
    unready.store(true, Ordering::Relaxed);
    if duration > Duration::ZERO {
        tokio::time::sleep(duration).await;
    }
}

/// Result of awaiting the DB pool's close future with the documented
/// teardown margin as an upper bound.
#[derive(Debug)]
enum PoolCloseOutcome {
    /// The pool finished closing before the margin elapsed. The caller can
    /// emit the clean "Graceful shutdown complete" log.
    Completed,
    /// The margin elapsed before the pool finished. The caller logs a
    /// warning and proceeds — the platform SIGKILL at the grace period is the
    /// final backstop.
    TimedOut,
}

/// Await `close_fut` for up to `margin`. If it finishes in time, return
/// `Completed`; otherwise return `TimedOut`. The close future is dropped on
/// timeout — sqlx's `Pool::close()` is cancellation-safe, and we would not
/// gain anything by continuing to await past the margin when the platform is
/// about to SIGKILL us anyway.
///
/// This enforces the teardown margin (less `POOL_CLOSE_LOG_HEADROOM`) as a real
/// bound on phase 4 so a stuck DB connection (e.g. a preload task mid-query when
/// `task_tracker.wait()` timed out and `signer_handle.abort()` was called
/// but not awaited) cannot block past the platform SIGKILL and swallow the
/// final "Graceful shutdown complete" log.
///
/// Generic over `F: Future<Output = ()>` so we can exercise the timeout
/// behaviour deterministically with `tokio::time::pause` in tests without
/// standing up a real Postgres pool.
async fn close_within_margin<F>(close_fut: F, margin: Duration) -> PoolCloseOutcome
where
    F: std::future::Future<Output = ()>,
{
    match tokio::time::timeout(margin, close_fut).await {
        Ok(()) => PoolCloseOutcome::Completed,
        Err(_) => PoolCloseOutcome::TimedOut,
    }
}

/// Result of awaiting the axum HTTP server's graceful-shutdown future with a
/// bounded budget.
#[derive(Debug)]
enum HttpDrainOutcome {
    /// The server finished its graceful-shutdown future before the budget ran
    /// out. Join errors are logged by the caller but do not change the phase.
    Completed,
    /// The budget expired before the server finished. The server task was
    /// aborted and awaited to cancellation, which stops the **accept loop** so
    /// the caller can proceed to phase 3 (relay teardown) and phase 4 (DB pool
    /// close) without racing a still-live accept loop. Note this does NOT
    /// guarantee every in-flight per-connection task is finished — hyper's
    /// per-connection tasks are not children of the aborted handle and may
    /// still be running; phase 4's bounded pool close covers any that linger
    /// holding a DB connection.
    AbortedAfterTimeout,
}

/// Result of awaiting phase 3 (relay client teardown + relay worker drain +
/// tracked task drain) under the `signer_drain` budget.
#[derive(Debug)]
enum SignerDrainOutcome {
    /// Relay worker joins, `client.shutdown()`, and `task_tracker.wait()`
    /// finished before the drain sub-budget elapsed.
    Completed,
    /// The drain sub-budget elapsed before the drain finished. The abort
    /// callback was invoked to stop the signer task and the relay workers were
    /// aborted; a best-effort bounded relay close was then attempted so the
    /// relay client still closes gracefully. The caller can safely proceed to
    /// phase 4 (DB pool close).
    AbortedAfterTimeout,
}

/// Await relay worker handles until they finish after the queue is closed.
async fn wait_for_join_handles(handles: Vec<tokio::task::JoinHandle<()>>) {
    for handle in handles {
        match handle.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {
                tracing::debug!("Relay worker task cancelled during shutdown");
            }
            Err(error) => {
                tracing::warn!(error = %error, "Relay worker task failed during shutdown");
            }
        }
    }
}

fn abort_join_handles(handles: &[tokio::task::AbortHandle]) {
    for handle in handles {
        handle.abort();
    }
}

/// Outcome of the bounded SIGTERM-time cluster deregister that opens phase 3.
/// All variants continue shutdown; `Failed`/`TimedOut` mean peers converge via
/// heartbeat staleness instead of the explicit `leave` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClusterDeregisterOutcome {
    /// `leave` published and instance removed from the registry.
    Deregistered,
    /// The deregister returned an error (e.g. Redis unreachable).
    Failed,
    /// The deregister exceeded its slice of the `signer_drain` budget.
    TimedOut,
}

/// Run the bounded cluster deregister that opens phase 3 and return the
/// signer-drain budget left for the relay/tracker drain.
///
/// Publishing the cluster `leave` here — immediately before the relay queue
/// closes — makes peers rebuild the hashring and take over this shard while
/// we drain, shrinking the dual-ownership window (peer and this instance both
/// handling the same bunker pubkeys) to Pub/Sub propagation time. Handover is
/// deliberately at-least-once: duplicates over drops.
///
/// Budget accounting: the deregister is bounded by
/// `CLUSTER_DEREGISTER_TIMEOUT.min(signer_drain)` and its elapsed wall-clock
/// is subtracted from the returned drain budget, so phase 3's total
/// (deregister + drain) never exceeds `signer_drain`. That keeps the
/// deregister inside the budget already proven to fit the grace ceiling by
/// `validate_shutdown_timings`/`clamp_shutdown_timings` — no unmodeled
/// overhang, no reliance on slack in other constants.
async fn deregister_within_signer_budget<F, E>(
    deregister: F,
    signer_drain: Duration,
) -> (ClusterDeregisterOutcome, Duration)
where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let budget = CLUSTER_DEREGISTER_TIMEOUT.min(signer_drain);
    // tokio::time::Instant (not std) so paused-clock tests measure the same
    // virtual time the timeout runs on.
    let started = tokio::time::Instant::now();
    let outcome = match tokio::time::timeout(budget, deregister).await {
        Ok(Ok(())) => {
            tracing::info!("Graceful shutdown: cluster leave published, instance deregistered");
            ClusterDeregisterOutcome::Deregistered
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Graceful shutdown: cluster deregister failed; peers will converge via heartbeat staleness");
            ClusterDeregisterOutcome::Failed
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = budget.as_secs(),
                "Graceful shutdown: cluster deregister timed out (Redis slow/down); continuing"
            );
            ClusterDeregisterOutcome::TimedOut
        }
    };
    (outcome, signer_drain.saturating_sub(started.elapsed()))
}

/// Run phase 3 under the shared `budget`, split into a drain sub-budget and a
/// reserved relay-close slice (`RELAY_CLOSE_BUDGET`, capped at half the budget):
///
/// 1. **Drain** (`budget - slice`): close the relay queue so workers drain and
///    exit while the relay client is still connected, await
///    `relay_worker_handles`, call `client_shutdown` (which stops `signer.run()`
///    so `tracker_wait` can complete), then await `tracker_wait`. `client_shutdown`
///    must run before `tracker_wait` because `signer.run()` is tracked by the
///    task tracker and only ends once the relay client disconnects.
/// 2. **Relay close** (`slice`): on the drain-timeout path, after aborting the
///    signer and relay workers, attempt a fresh bounded `client_shutdown` so
///    the relay client still closes its WebSockets gracefully and flushes any
///    already-published responses even though the drain timed out. (On the
///    happy path the relay client was already shut down in step 1, so this slice
///    goes unused.) `Client::shutdown` is idempotent, so the second call is
///    safe.
///
/// Returns `Completed` only when the drain finished within its sub-budget;
/// otherwise `abort_signer` (in production `signer_handle.abort()`) and the
/// relay worker handles are aborted and it returns `AbortedAfterTimeout`.
///
/// Budget contract: drain sub-budget + relay-close slice == `budget`, and only
/// one of them runs the relay close, so total wall-clock never exceeds `budget`.
/// In production `budget` is the `signer_drain` remainder returned by
/// `deregister_within_signer_budget`, so the whole of phase 3 (deregister +
/// drain) stays within `signer_drain`. This preserves the design contract
/// enforced by `validate_shutdown_timings`/`clamp_shutdown_timings`:
/// `pre_drain + http_drain + signer_drain + teardown_margin <= grace ceiling`.
///
/// `client_shutdown` is a factory (`Fn() -> Future`) rather than a single
/// future so it can be invoked again on the timeout path. It is generic, along
/// with the inner futures and the abort callback, so the timeout behaviour can
/// be exercised deterministically with `tokio::time::pause` in tests without
/// standing up a real `nostr_sdk::Client` or a real signer `JoinHandle`.
async fn drain_signer_or_abort<CF, CFut, Q, W, A>(
    client_shutdown: CF,
    close_relay_queue: Q,
    relay_worker_handles: Vec<tokio::task::JoinHandle<()>>,
    tracker_wait: W,
    abort_signer: A,
    budget: Duration,
) -> SignerDrainOutcome
where
    CF: Fn() -> CFut,
    CFut: std::future::Future<Output = ()>,
    Q: FnOnce(),
    W: std::future::Future<Output = ()>,
    A: FnOnce(),
{
    let relay_worker_abort_handles: Vec<_> = relay_worker_handles
        .iter()
        .map(tokio::task::JoinHandle::abort_handle)
        .collect();

    // Reserve a slice for the relay close so it cannot be starved by a slow
    // drain; cap at half the budget so the drain keeps the larger share.
    let relay_close_slice = RELAY_CLOSE_BUDGET.min(budget / 2);
    let drain_budget = budget.saturating_sub(relay_close_slice);

    // Borrow (not move) the factory into the drain future so it can be called
    // again on the timeout path after the drain future is dropped.
    let client_shutdown_ref = &client_shutdown;
    let drain = async move {
        close_relay_queue();
        wait_for_join_handles(relay_worker_handles).await;
        client_shutdown_ref().await;
        tracker_wait.await;
    };

    match tokio::time::timeout(drain_budget, drain).await {
        Ok(()) => SignerDrainOutcome::Completed,
        Err(_) => {
            abort_signer();
            abort_join_handles(&relay_worker_abort_handles);
            // Best-effort graceful relay close even though the drain timed out:
            // workers may have been stuck before reaching the in-drain
            // client_shutdown, leaving the relay client connected with
            // unflushed responses. Bounded by the reserved slice.
            let _ = tokio::time::timeout(relay_close_slice, client_shutdown()).await;
            SignerDrainOutcome::AbortedAfterTimeout
        }
    }
}

/// Await the axum server's `JoinHandle` for up to `budget`. If it finishes
/// in time, return `Completed`. Otherwise call `abort()` on the task,
/// await its cancellation, and return `AbortedAfterTimeout`.
///
/// This exists because dropping a `tokio::task::JoinHandle` does NOT cancel
/// the underlying task — the axum server would keep running concurrently
/// with the relay-teardown and DB-pool-close phases, causing decode errors
/// on late-arriving requests and forcing the kubelet SIGKILL to be the
/// ultimate stop. The abort makes the HTTP drain budget a real bound on
/// axum's lifetime.
async fn drain_http_or_abort(
    mut handle: tokio::task::JoinHandle<()>,
    budget: Duration,
) -> HttpDrainOutcome {
    // `JoinHandle<T>` is `Unpin` and implements `Future<Output = Result<T,
    // JoinError>>`, so `&mut handle` can be awaited by `timeout` without
    // consuming it. This lets us still call `abort()` on the same handle on
    // the timeout path.
    match tokio::time::timeout(budget, &mut handle).await {
        Ok(join_result) => {
            if let Err(e) = join_result {
                tracing::warn!("API server task error: {:?}", e);
            }
            HttpDrainOutcome::Completed
        }
        Err(_) => {
            handle.abort();
            // Await cancellation so we don't return while the accept loop is
            // still being torn down. A cancelled task completes quickly; if
            // it somehow doesn't, the outer kubelet grace period is still
            // the final backstop, so no second timeout here.
            let _ = (&mut handle).await;
            HttpDrainOutcome::AbortedAfterTimeout
        }
    }
}

#[derive(Clone)]
struct LivenessState {
    shutting_down: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ReadinessState {
    pool: sqlx::PgPool,
    shutting_down: Arc<AtomicBool>,
}

fn readiness_response(is_shutting_down: bool, database_ready: bool) -> (StatusCode, &'static str) {
    if is_shutting_down {
        (StatusCode::SERVICE_UNAVAILABLE, "Shutting down")
    } else if database_ready {
        (StatusCode::OK, "OK")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
    }
}

async fn health_check() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({
            "status": "ok",
            "service": "keycast",
        })),
    )
}

async fn livez(state: Arc<LivenessState>) -> impl IntoResponse {
    if state.shutting_down.load(Ordering::Relaxed) {
        (StatusCode::OK, "OK (shutting down)")
    } else {
        (StatusCode::OK, "OK")
    }
}

async fn startupz() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn readyz(state: Arc<ReadinessState>) -> impl IntoResponse {
    let is_shutting_down = state.shutting_down.load(Ordering::Relaxed);
    let database_ready = if is_shutting_down {
        false
    } else {
        // Bound the DB check so a stalled connection or exhausted pool fails
        // the probe fast rather than blocking the kubelet probe past its
        // `timeoutSeconds`. Both timeout and query error => not ready.
        let query = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool);
        matches!(
            tokio::time::timeout(READYZ_DB_TIMEOUT, query).await,
            Ok(Ok(_))
        )
    };

    readiness_response(is_shutting_down, database_ready)
}

/// Run database migrations and exit
/// Used by Kubernetes Jobs to run migrations before app startup
fn run_migrations() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Running database migrations...");

    let database_url =
        env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set for migrations")?;

    // Build minimal runtime just for migrations
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;

        // Run migrations using SQLx's built-in migrator
        // Uses advisory locks to prevent concurrent migrations
        sqlx::migrate!("../database/migrations").run(&pool).await?;

        pool.close().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    println!("✅ Migrations complete!");
    Ok(())
}

/// Inject runtime environment variables into HTML via window.__ENV__
/// Injects a <script> tag before </head> with runtime config
fn inject_runtime_env(html: &str) -> String {
    // Build runtime environment object
    let mut env_obj = json!({});

    // VITE_DOMAIN - API domain for frontend (from APP_URL)
    if let Ok(domain) = env::var("APP_URL") {
        env_obj["VITE_DOMAIN"] = json!(domain);
    }

    // ALLOWED_PUBKEYS - comma-separated admin pubkeys
    if let Ok(pubkeys) = env::var("ALLOWED_PUBKEYS") {
        env_obj["ALLOWED_PUBKEYS"] = json!(pubkeys);
    }

    // SHOW_TEAMS_FUNCTIONALITY - enable teams UI (optional, default: hidden)
    if let Ok(val) = env::var("SHOW_TEAMS_FUNCTIONALITY") {
        env_obj["SHOW_TEAMS_FUNCTIONALITY"] = json!(val);
    }

    // If no env vars to inject, return original HTML
    if env_obj.as_object().is_none_or(|o| o.is_empty()) {
        return html.to_string();
    }

    // Serialize to JSON (serde_json properly escapes)
    let env_json = serde_json::to_string(&env_obj).unwrap_or_else(|_| "{}".to_string());

    // Create injection script
    let injection_script = format!(r#"<script>window.__ENV__={};</script>"#, env_json);

    // Inject before </head> tag, or at the beginning if no </head> found
    if let Some(head_end_pos) = html.rfind("</head>") {
        let mut injected = html[..head_end_pos].to_string();
        injected.push_str(&injection_script);
        injected.push('\n');
        injected.push_str(&html[head_end_pos..]);
        injected
    } else if let Some(body_start_pos) = html.find("<body>") {
        // Fallback: inject before <body> if no </head>
        let mut injected = html[..body_start_pos].to_string();
        injected.push_str(&injection_script);
        injected.push('\n');
        injected.push_str(&html[body_start_pos..]);
        injected
    } else {
        // Last resort: prepend to HTML
        format!("{}\n{}", injection_script, html)
    }
}

fn origin_is_allowed(origin: &str, allowed_origins: &str) -> bool {
    if origin.starts_with("http://localhost:") || origin == "http://localhost" {
        return true;
    }

    allowed_origins
        .split(',')
        .map(|value| value.trim())
        .any(|allowed| origin_matches_allowed_pattern(origin, allowed))
}

fn origin_matches_allowed_pattern(origin: &str, allowed: &str) -> bool {
    if !allowed.contains('*') {
        return origin == allowed;
    }

    let Some((origin_scheme, origin_host)) = parse_origin(origin) else {
        return false;
    };
    let Some((allowed_scheme, allowed_host)) = parse_origin(allowed) else {
        return false;
    };

    if origin_scheme != allowed_scheme {
        return false;
    }

    let Some(host_suffix) = allowed_host.strip_prefix("*.") else {
        return false;
    };

    origin_host.len() > host_suffix.len()
        && origin_host.ends_with(host_suffix)
        && origin_host
            .strip_suffix(host_suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn parse_origin(origin: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = origin.split_once("://")?;
    let host = rest.split('/').next()?;
    Some((scheme, host))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KmsProvider {
    File,
    Gcp,
    Aws,
}

fn resolve_kms_provider() -> Result<KmsProvider, String> {
    let use_gcp_kms = env::var("USE_GCP_KMS").ok().map(|v| v == "true");

    if let Ok(provider) = env::var("KMS_PROVIDER") {
        let resolved_provider = match provider.trim().to_ascii_lowercase().as_str() {
            "file" => Ok(KmsProvider::File),
            "gcp" => Ok(KmsProvider::Gcp),
            "aws" => Ok(KmsProvider::Aws),
            invalid => Err(format!(
                "KMS_PROVIDER must be one of: file, gcp, aws (got '{}')",
                invalid
            )),
        }?;

        if let Some(use_gcp) = use_gcp_kms {
            let legacy_provider = if use_gcp {
                KmsProvider::Gcp
            } else {
                KmsProvider::File
            };

            if legacy_provider != resolved_provider {
                tracing::warn!(
                    kms_provider = kms_provider_label(resolved_provider),
                    use_gcp_kms = use_gcp,
                    legacy_provider = kms_provider_label(legacy_provider),
                    "KMS_PROVIDER and USE_GCP_KMS disagree; using KMS_PROVIDER as source of truth"
                );
            }
        }

        return Ok(resolved_provider);
    }

    if use_gcp_kms.unwrap_or(false) {
        Ok(KmsProvider::Gcp)
    } else {
        Ok(KmsProvider::File)
    }
}

fn kms_provider_label(provider: KmsProvider) -> &'static str {
    match provider {
        KmsProvider::File => "file",
        KmsProvider::Gcp => "gcp",
        KmsProvider::Aws => "aws",
    }
}

async fn build_key_manager(
    kms_provider: KmsProvider,
) -> Result<Box<dyn KeyManager>, Box<dyn std::error::Error>> {
    match kms_provider {
        KmsProvider::File => Ok(Box::new(FileKeyManager::new()?)),
        KmsProvider::Gcp => Ok(Box::new(GcpKeyManager::new().await?)),
        KmsProvider::Aws => {
            #[cfg(feature = "aws")]
            {
                Ok(Box::new(AwsKeyManager::new().await?))
            }
            #[cfg(not(feature = "aws"))]
            {
                Err("KMS_PROVIDER=aws but keycast was built without --features aws".into())
            }
        }
    }
}

/// Serve Apple App Site Association file with correct content type
async fn apple_app_site_association(
    axum::extract::State(web_build_dir): axum::extract::State<String>,
) -> impl IntoResponse {
    let path = PathBuf::from(&web_build_dir).join(".well-known/apple-app-site-association");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

/// Serve Android Asset Links file with correct content type
async fn assetlinks_json(
    axum::extract::State(web_build_dir): axum::extract::State<String>,
) -> impl IntoResponse {
    let path = PathBuf::from(&web_build_dir).join(".well-known/assetlinks.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

/// Middleware to set Cache-Control headers for static assets
/// Browser caching reduces load and improves performance
async fn cache_control_middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;

    // Don't overwrite if route already set Cache-Control
    if response.headers().contains_key(header::CACHE_CONTROL) {
        return response;
    }

    let cache_value = if path.starts_with("/_app/") {
        // SvelteKit hash-versioned assets - cache forever (1 year)
        "public, max-age=31536000, immutable"
    } else if path.starts_with("/api/") || path.starts_with("/health") || path == "/livez" {
        // Dynamic content - no caching
        // (`/health`, `/healthz/startup`, `/healthz/ready` all match `/health`;
        //  `/livez` is the only probe route not under that prefix.)
        "no-store"
    } else if path == "/index.html" || path == "/" {
        // SPA entry - must revalidate to get latest app
        "public, max-age=0, must-revalidate"
    } else if path.starts_with("/.well-known/") || path == "/site.webmanifest" {
        // Config files - cache 24 hours
        "public, max-age=86400"
    } else if path.starts_with("/dist/") || path.starts_with("/examples/") {
        // Dev bundles - cache 1 hour
        "public, max-age=3600"
    } else if path.ends_with(".png") || path.ends_with(".ico") || path.ends_with(".svg") {
        // Static images - cache 30 days
        "public, max-age=2592000"
    } else {
        // Default for other static files (HTML fallback via SPA)
        "public, max-age=0, must-revalidate"
    };

    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, cache_value.parse().unwrap());

    response
}

/// Validate required environment variables at startup
fn validate_environment() -> Result<(), String> {
    let mut errors = Vec::new();

    // Required variables
    if env::var("DATABASE_URL").is_err() {
        errors.push("DATABASE_URL must be set (PostgreSQL connection string)");
    }

    if env::var("ALLOWED_ORIGINS").is_err() {
        errors.push("ALLOWED_ORIGINS must be set (comma-separated CORS origins)");
    }

    if env::var("SERVER_NSEC").is_err() {
        errors.push("SERVER_NSEC must be set (server's Nostr secret key for signing UCANs)");
    }

    if env::var("REDIS_URL").is_err() {
        errors.push("REDIS_URL must be set (Redis/Memorystore URL for cluster coordination)");
    }

    let kms_provider = resolve_kms_provider()?;
    match kms_provider {
        KmsProvider::File => {
            if env::var("MASTER_KEY_PATH").is_err() {
                errors.push("MASTER_KEY_PATH must be set when KMS_PROVIDER=file");
            }
        }
        KmsProvider::Gcp => {
            if env::var("GCP_PROJECT_ID").is_err() {
                errors.push("GCP_PROJECT_ID must be set when KMS_PROVIDER=gcp");
            }
        }
        KmsProvider::Aws => {
            if env::var("AWS_KMS_KEY_ID").is_err() {
                errors.push("AWS_KMS_KEY_ID must be set when KMS_PROVIDER=aws");
            }
            #[cfg(not(feature = "aws"))]
            {
                errors.push("KMS_PROVIDER=aws requires building keycast with --features aws");
            }
        }
    }

    // Tenant isolation configuration
    let has_allowed_domains = env::var("ALLOWED_TENANT_DOMAINS").is_ok();
    let has_auto_provisioning = env::var("ENABLE_TENANT_AUTO_PROVISIONING")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !has_allowed_domains && !has_auto_provisioning {
        tracing::warn!(
            "Neither ALLOWED_TENANT_DOMAINS nor ENABLE_TENANT_AUTO_PROVISIONING is configured. \
             All requests from unknown domains will be rejected. \
             Set ALLOWED_TENANT_DOMAINS for production or ENABLE_TENANT_AUTO_PROVISIONING=true for development."
        );
    }

    if has_auto_provisioning && !has_allowed_domains {
        tracing::warn!(
            "ENABLE_TENANT_AUTO_PROVISIONING=true without ALLOWED_TENANT_DOMAINS. \
             Any valid domain can auto-create a tenant. This should only be used in development."
        );
    }

    // Docker deployment requires additional vars
    if env::var("POSTGRES_PASSWORD").is_err() {
        // Only required for docker-compose, so just warn
        tracing::warn!("POSTGRES_PASSWORD not set (required for docker-compose deployments)");
    }

    // Validate email configuration (fail-closed in production)
    if let Err(e) = keycast_api::email_service::create_email_sender() {
        errors.push(Box::leak(e.into_boxed_str()));
    }

    warn_atproto_control_plane_config();

    if !errors.is_empty() {
        return Err(format!(
            "Missing required environment variables:\n  - {}\n\nSee .env.example for configuration guide.",
            errors.join("\n  - ")
        ));
    }

    Ok(())
}

fn warn_atproto_control_plane_config() {
    let configured = env::var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(url) = configured else {
        warn_atproto_control_plane_config_issue(
            "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL is not set; ATProto provisioning endpoints will return a scoped unavailable response",
        );
        return;
    };

    if let Err(error) = keycast_api::atproto_provisioning::validate_control_plane_base_url(&url) {
        warn_atproto_control_plane_config_issue(&format!(
            "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL {error}; ATProto provisioning endpoints will return a scoped unavailable response"
        ));
    }
}

fn warn_atproto_control_plane_config_issue(message: &str) {
    tracing::warn!("{}", message);
    eprintln!("Configuration warning: {message}");
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, initiating graceful shutdown"),
        _ = terminate => tracing::info!("Received SIGTERM, initiating graceful shutdown"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure panics in any thread (including spawned tasks) kill the process
    // This prevents the server from running in a broken state
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(1);
    }));

    dotenv().ok();

    // Check for --migrate flag (run migrations and exit)
    if std::env::args().any(|arg| arg == "--migrate") {
        return run_migrations();
    }

    // Use tokio default: 1 worker thread per CPU core
    // Override with TOKIO_WORKER_THREADS env var if needed
    let worker_threads = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(num_cpus::get);

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?
        .block_on(async_main(worker_threads))
}

async fn async_main(worker_threads: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n================================================");
    println!("🔑 Keycast Unified Service Starting...");
    println!("   Running API + Signer in single process");
    println!("   Tokio worker threads: {}", worker_threads);
    println!("================================================\n");

    // Validate environment variables before proceeding
    if let Err(e) = validate_environment() {
        eprintln!("\n❌ Configuration Error:\n{}\n", e);
        std::process::exit(1);
    }

    // Initialize tracing with JSON format in production for GCP Cloud Logging
    let is_production = std::env::var("NODE_ENV").unwrap_or_default() == "production";
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if is_production {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // Log instance capacity info for distributed tracing
    // Initialize global instance ID (combines revision + unique UUID)
    let instance_id = keycast_core::instance::instance_id();
    let cpu_count = num_cpus::get();
    let pool_size = env::var("SQLX_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);

    tracing::info!(
        event = "instance_startup",
        instance_id = %instance_id,
        cpu_count = cpu_count,
        worker_threads = worker_threads,
        pool_size = pool_size,
        "Instance starting: id={} cpus={} workers={} pool={}",
        instance_id, cpu_count, worker_threads, pool_size
    );

    // Resolve and log the effective shutdown phase budget at startup. The
    // configured budget is clamped to provably fit the configured grace
    // ceiling (`SHUTDOWN_GRACE_PERIOD_CEILING_SECS`, which must be set to the
    // platform's real post-SIGTERM grace — ~10s on Cloud Run, 75s on GKE). If
    // the operator-configured budget does not fit (e.g. `SHUTDOWN_HTTP_DRAIN_SECS=120`
    // against a 75s ceiling, or the GKE-sized defaults against a 10s Cloud Run
    // ceiling), the phases are scaled down proportionally at runtime rather
    // than run as-is and SIGKILLed mid-drain. We log the clamp loudly so the
    // operator can retune; we do not refuse to boot.
    {
        let plan = resolve_shutdown_plan();
        if plan.clamped.clamped {
            let eff = plan.clamped.timings;
            tracing::warn!(
                event = "shutdown_budget_clamped_to_grace_ceiling",
                configured_pre_drain_secs = plan.configured.pre_drain.as_secs(),
                configured_http_drain_secs = plan.configured.http_drain.as_secs(),
                configured_signer_drain_secs = plan.configured.signer_drain.as_secs(),
                effective_pre_drain_secs = eff.pre_drain.as_secs(),
                effective_http_drain_secs = eff.http_drain.as_secs(),
                effective_signer_drain_secs = eff.signer_drain.as_secs(),
                teardown_margin_secs = plan.margin.as_secs(),
                grace_ceiling_secs = plan.ceiling.as_secs(),
                "Configured shutdown phase budget exceeds the grace ceiling; phases clamped down proportionally to fit"
            );
            if let Err(err) = validate_shutdown_timings(&eff, plan.ceiling, plan.margin) {
                // Should be unreachable: clamp guarantees a fit. Surface loudly
                // if the invariant is ever broken.
                tracing::error!(
                    event = "shutdown_budget_clamp_invariant_violated",
                    "{}",
                    err
                );
            }
        } else {
            tracing::info!(
                pre_drain_secs = plan.clamped.timings.pre_drain.as_secs(),
                http_drain_secs = plan.clamped.timings.http_drain.as_secs(),
                signer_drain_secs = plan.clamped.timings.signer_drain.as_secs(),
                teardown_margin_secs = plan.margin.as_secs(),
                grace_ceiling_secs = plan.ceiling.as_secs(),
                "Shutdown phase budget fits inside configured grace ceiling"
            );
        }
    }

    // Setup database
    let database = Database::new().await?;
    tracing::info!("✔︎ Database initialized");

    // Initialize cluster coordination with Redis/Valkey (Pub/Sub mode)
    // This handles instance registration, membership detection, and heartbeats
    // Uses Redis Pub/Sub for instant membership updates
    // Supports GCP Memorystore Valkey with IAM authentication
    let redis_url = env::var("REDIS_URL")?; // Validated above
    let redis_prefix = env::var("REDIS_KEY_PREFIX").ok();
    let use_valkey_iam =
        env::var("USE_VALKEY_IAM").unwrap_or_else(|_| "false".to_string()) == "true";

    let coordinator = Arc::new(
        ClusterCoordinator::start_with_config(&redis_url, redis_prefix.as_deref(), use_valkey_iam)
            .await?,
    );
    let instance_id = coordinator.instance_id();
    tracing::info!(
        "✔︎ Cluster coordinator started: {} ({}{})",
        instance_id,
        if use_valkey_iam {
            "Valkey IAM"
        } else {
            "Redis Pub/Sub"
        },
        redis_prefix
            .as_ref()
            .map(|p| format!(", prefix: {}", p))
            .unwrap_or_default()
    );

    // Create Redis connection for API using coordinator's factory (shares IAM auth)
    let factory = coordinator.factory();
    let redis_conn = factory.get_connection_manager().await?;
    let prefixed_redis =
        keycast_api::PrefixedRedis::new_with_factory(redis_conn, factory, redis_prefix);
    tracing::info!(
        "✔︎ Redis connection for API initialized{}",
        if use_valkey_iam {
            " (IAM auth enabled)"
        } else {
            ""
        }
    );

    // Setup key managers (one for signer, one for API - they're cheap to create)
    let kms_provider =
        resolve_kms_provider().map_err(|e| format!("Invalid KMS provider configuration: {}", e))?;
    tracing::info!(
        "Using {} KMS provider for encryption",
        kms_provider_label(kms_provider)
    );

    let signer_key_manager: Box<dyn KeyManager> = build_key_manager(kms_provider).await?;
    let api_key_manager: Box<dyn KeyManager> = build_key_manager(kms_provider).await?;

    // Load server keys for signing UCANs (wrap in Zeroizing for auto-zeroization)
    let server_nsec = Zeroizing::new(env::var("SERVER_NSEC")?); // Validated above
    let server_keys = Keys::parse(&server_nsec).map_err(|e| {
        format!(
            "Invalid SERVER_NSEC: {}. Must be valid hex (64 chars) or nsec bech32.",
            e
        )
    })?;
    // server_nsec is zeroized here when dropped
    tracing::info!(
        "✔︎ Server keys loaded (pubkey: {})",
        server_keys.public_key().to_hex()
    );

    // Create authorization channel for instant communication between API and Signer
    let (auth_tx, auth_rx) = authorization_channel::create_channel();
    tracing::info!(
        "✔︎ Authorization channel created (buffer size: {})",
        authorization_channel::CHANNEL_BUFFER_SIZE
    );

    // Create signer (relay connections deferred to background task for faster startup)
    let mut signer = UnifiedSigner::new(
        database.pool.clone(),
        signer_key_manager,
        auth_rx,
        coordinator.clone(),
    )
    .await?;
    signer.load_authorizations().await?;
    // Note: connect_to_relays() moved to signer daemon task to allow HTTP server to bind faster

    // Create relay queue for bounded concurrency on NIP-46 relay requests
    // Queue (4096) buffers relay events; workers control processing rate
    let relay_queue = RelayQueue::new();
    let relay_sender = relay_queue.sender();
    signer.set_relay_sender(relay_sender);

    // Spawn relay workers for NIP-46 request processing
    // Worker count balances throughput vs CPU contention with HTTP RPC
    // Can override with RELAY_WORKER_COUNT env var
    let num_workers = std::env::var("RELAY_WORKER_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| num_cpus::get().max(4) * 2);
    let relay_worker_handles = relay_queue.spawn_workers(
        num_workers,
        signer.handlers(),
        signer.client(),
        signer.pool(),
        signer.key_manager(),
        signer.coordinator(),
    );
    tracing::info!(
        "✔︎ Signer daemon initialized (Tokio workers: {}, relay workers: {}, queue: 4096)",
        worker_threads,
        num_workers
    );

    // Create tenant cache (preload deferred to background task for faster startup)
    let tenant_cache: TenantCache = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(3600))
        .build();
    tracing::info!("✔︎ Tenant cache initialized (preload deferred)");

    // Create bcrypt queue for async password hashing during registration
    // Uses email verification latency as natural buffer for CPU-intensive work
    let bcrypt_queue = keycast_api::bcrypt_queue::BcryptQueue::new();
    let bcrypt_sender = bcrypt_queue.sender();
    let _bcrypt_worker_handles = bcrypt_queue.spawn_workers(database.pool.clone());
    let _bcrypt_cleanup_handle =
        keycast_api::bcrypt_queue::spawn_cleanup_task(database.pool.clone());
    tracing::info!(
        "✔︎ Bcrypt queue initialized ({} workers, cleanup every 5min)",
        num_cpus::get()
    );

    // Create secret pool for instant authorization creation
    // Background producer pre-computes (secret, bcrypt_hash) pairs
    let secret_pool = keycast_core::secret_pool::SecretPool::default();
    let secret_pool_receiver = secret_pool.receiver();
    let _secret_pool_producer = secret_pool.spawn_producer();
    tracing::info!("✔︎ Secret pool initialized (capacity: 100, bcrypt cost: 10)");

    // Create API state with http_handler_cache for on-demand loading
    // Note: api no longer depends on signer's handler cache (decoupled)
    let api_state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(api_key_manager),
        signer_handlers: None, // Deprecated: api uses http_handler_cache with on-demand loading
        http_handler_cache: new_http_handler_cache(),
        server_keys,
        tenant_cache,
        bcrypt_sender,
        redis: Some(prefixed_redis),
        secret_pool: secret_pool_receiver,
    });

    // Set global state for routes that use it
    keycast_api::state::KEYCAST_STATE
        .set(api_state.clone())
        .ok();

    // Get API port (default 3000)
    let api_port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    // Set up static file directories
    let root_dir = env!("CARGO_MANIFEST_DIR");

    // Use WEB_BUILD_DIR if set, otherwise use web/build for dev
    let web_build_dir = env::var("WEB_BUILD_DIR").unwrap_or_else(|_| {
        PathBuf::from(root_dir)
            .parent()
            .unwrap()
            .join("web/build")
            .to_string_lossy()
            .to_string()
    });

    tracing::info!("✔︎ Serving web frontend from: {}", web_build_dir);

    // CORS configuration
    use tower_http::cors::AllowOrigin;

    let allowed_origins_str = env::var("ALLOWED_ORIGINS")?; // Validated above
    let allowed_origins_for_closure = allowed_origins_str.clone();

    let auth_cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let origin_str = origin.to_str().unwrap_or("");
            origin_is_allowed(origin_str, &allowed_origins_for_closure)
        }))
        .allow_methods([
            axum::http::Method::POST,
            axum::http::Method::GET,
            axum::http::Method::OPTIONS,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(86400));

    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(false)
        .max_age(std::time::Duration::from_secs(86400));

    let shutting_down = Arc::new(AtomicBool::new(false));
    let livez_state = Arc::new(LivenessState {
        shutting_down: shutting_down.clone(),
    });
    let readyz_state = Arc::new(ReadinessState {
        pool: database.pool.clone(),
        shutting_down: shutting_down.clone(),
    });

    // Get pure API routes (JSON endpoints only) - pass authorization sender
    let api_routes = keycast_api::api::http::routes::api_routes(
        database.pool.clone(),
        api_state.clone(),
        auth_cors,
        public_cors,
        Some(auth_tx),
    );

    // Serve examples directory (only in development)
    let enable_examples = env::var("ENABLE_EXAMPLES")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Routes for Apple/Android app association files (with correct content type)
    let well_known_routes = Router::new()
        .route(
            "/apple-app-site-association",
            get(apple_app_site_association),
        )
        .route("/assetlinks.json", get(assetlinks_json))
        .route(
            "/oauth-authorization-server",
            get(keycast_api::api::http::atproto_oauth_metadata::authorization_server_metadata),
        )
        .with_state(web_build_dir.clone());

    let mut app = Router::new()
        // Health checks at root level (for k8s/Cloud Run)
        .route("/health", get(health_check))
        .route("/livez", get(move || livez(livez_state.clone())))
        .route("/healthz/startup", get(startupz))
        .route("/healthz/ready", get(move || readyz(readyz_state.clone())))
        // NIP-05 discovery at root level
        .route(
            "/.well-known/nostr.json",
            get(keycast_api::api::http::nostr_discovery_public),
        )
        .with_state(database.pool.clone())
        // Apple/Android app association files
        .nest("/.well-known", well_known_routes)
        // All API endpoints under /api prefix
        .nest("/api", api_routes);

    // Only serve examples when enabled
    if enable_examples {
        // In Docker, examples are at /app/examples; in dev, relative to workspace root
        let examples_path = if PathBuf::from("/app/examples").exists() {
            PathBuf::from("/app/examples")
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("examples")
        };
        tracing::info!(
            "✔︎ Examples directory enabled at /examples (serving from {:?})",
            examples_path
        );
        app = app.nest_service("/examples", ServeDir::new(&examples_path));

        // Serve keycast-client dist for examples (IIFE bundle)
        let client_dist_path = if PathBuf::from("/app/packages/keycast-client/dist").exists() {
            PathBuf::from("/app/packages/keycast-client/dist")
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("packages/keycast-client/dist")
        };
        if client_dist_path.exists() {
            tracing::info!(
                "✔︎ Keycast client served at /dist (from {:?})",
                client_dist_path
            );
            app = app.nest_service("/dist", ServeDir::new(&client_dist_path));
        }
    }

    // SvelteKit frontend - explicitly handle root and index.html with injection
    // This ensures index.html always goes through injection, not served as static file
    let index_path = PathBuf::from(&web_build_dir).join("index.html");
    let index_path_for_root = index_path.clone();
    let index_path_for_index = index_path.clone();

    // Handler that injects runtime env vars into index.html
    let inject_handler = move || {
        let index_path = index_path_for_root.clone();
        async move {
            match tokio::fs::read_to_string(&index_path).await {
                Ok(content) => {
                    // Inject runtime environment variables into HTML
                    let injected_content = inject_runtime_env(&content);
                    Html(injected_content).into_response()
                }
                Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
            }
        }
    };

    let inject_handler_index = move || {
        let index_path = index_path_for_index.clone();
        async move {
            match tokio::fs::read_to_string(&index_path).await {
                Ok(content) => {
                    // Inject runtime environment variables into HTML
                    let injected_content = inject_runtime_env(&content);
                    Html(injected_content).into_response()
                }
                Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
            }
        }
    };

    // Explicitly route root and index.html to injection handler
    let app = app
        .route("/", axum::routing::get(inject_handler))
        .route("/index.html", axum::routing::get(inject_handler_index));

    // Serve other static files, with fallback for SPA routes (non-file routes)
    let web_build_dir_for_fallback = web_build_dir.clone();
    let index_path_for_fallback = PathBuf::from(&web_build_dir).join("index.html");
    let app = app.fallback_service(ServeDir::new(&web_build_dir).fallback(axum::routing::get(
        move || {
            let index_path = index_path_for_fallback.clone();
            let _web_build_dir = web_build_dir_for_fallback.clone();
            async move {
                match tokio::fs::read_to_string(&index_path).await {
                    Ok(content) => {
                        // Inject runtime environment variables into HTML
                        let injected_content = inject_runtime_env(&content);
                        Html(injected_content).into_response()
                    }
                    Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
                }
            }
        },
    )));

    // Add request tracing with trace_id for debugging
    // TraceLayer creates a span for each request with method, uri, and trace_id
    // All logs within the request will automatically include these fields
    let app = app.layer(
        TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
            let trace_id = keycast_api::api::http::auth_observability::request_context(request)
                .map(|context| context.request_id.clone())
                .or_else(|| {
                    keycast_api::api::http::auth_observability::request_id_from_headers(
                        request.headers(),
                    )
                })
                .unwrap_or_else(|| "missing-request-id".to_string());

            tracing::span!(
                Level::INFO,
                "request",
                method = %request.method(),
                uri = %request.uri(),
                trace_id = %trace_id,
            )
        }),
    );

    let app = app.layer(middleware::from_fn(
        keycast_api::api::http::auth_observability::request_id_middleware,
    ));

    // Add Cache-Control headers for browser caching
    let app = app.layer(middleware::from_fn(cache_control_middleware));

    // Try dual-stack [::] first (accepts both IPv4 and IPv6), fall back to 0.0.0.0
    let dual_stack_addr = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, api_port));
    let ipv4_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, api_port));
    tracing::info!("✔︎ API server ready on port {}", api_port);

    // Setup graceful shutdown with TaskTracker for background tasks
    let shutdown_signal = Arc::new(Notify::new());
    let shutdown_for_api = shutdown_signal.clone();
    let client_for_shutdown = signer.client();
    let pool_for_shutdown = database.pool.clone();
    let task_tracker = TaskTracker::new();

    // Spawn API server with graceful shutdown
    let api_handle = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(dual_stack_addr).await {
            Ok(l) => {
                tracing::info!(
                    "🌐 API server listening on {} (dual-stack)",
                    dual_stack_addr
                );
                l
            }
            Err(_) => {
                tracing::info!(
                    "🌐 API server listening on {} (IPv4-only, IPv6 unavailable)",
                    ipv4_addr
                );
                tokio::net::TcpListener::bind(ipv4_addr)
                    .await
                    .expect("Failed to bind API server")
            }
        };
        axum::serve(listener, app)
            .tcp_nodelay(true)
            .with_graceful_shutdown(async move {
                shutdown_for_api.notified().await;
            })
            .await
            .unwrap();
    });

    // Spawn Signer daemon task (connects to relays in background for faster startup)
    let signer_handle = task_tracker.spawn(async move {
        let mut signer = signer;
        // Connect to relays in background (deferred from startup for faster health checks)
        if let Err(e) = signer.connect_to_relays().await {
            tracing::error!("Failed to connect to relays: {}", e);
        }
        tracing::info!("🤙 Signer daemon ready, listening for NIP-46 requests");
        signer.run().await.unwrap();
    });

    // Spawn tenant cache preload task (deferred from startup for faster health checks)
    let tenant_pool = database.pool.clone();
    let tenant_cache_for_preload = api_state.tenant_cache.clone();
    task_tracker.spawn(async move {
        let tenants: Vec<Tenant> = sqlx::query_as(
            "SELECT id, domain, name, settings, created_at, updated_at FROM tenants",
        )
        .fetch_all(&tenant_pool)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to preload tenants: {}", e);
            vec![]
        });

        for tenant in tenants {
            let domain = tenant.domain.clone();
            tenant_cache_for_preload
                .insert(domain.clone(), Arc::new(tenant))
                .await;
        }
        tracing::info!(
            "✔︎ Tenant cache preloaded ({} tenants)",
            tenant_cache_for_preload.entry_count()
        );
    });

    // Note: Heartbeat and hashring coordination is now handled internally by ClusterCoordinator
    // via Redis Pub/Sub for instant updates and 30s heartbeat for crash detection

    println!("✨ Unified service running!");
    println!("   API: http://0.0.0.0:{}", api_port);
    println!("   Signer: NIP-46 relay listener active");
    println!(
        "   Tokio workers: {}, relay workers: {} (queue: 4096)",
        worker_threads, num_workers
    );
    println!(
        "   Instance: {} (cluster-hashring Redis Pub/Sub enabled)",
        instance_id
    );
    println!("   HTTP handler cache: on-demand loading enabled\n");

    // Wait for shutdown signal
    wait_for_shutdown_signal().await;

    // --- Graceful shutdown ---
    //
    // Phase ordering matters. On scale-down the platform sends SIGTERM and
    // *also* starts removing the instance from load-balancer routing, but that
    // removal is asynchronous. On GKE the Pod's `deletionTimestamp` (not a
    // failing readiness probe) drives endpoint/NEG detach from the Service
    // EndpointSlice and the GCLB NEG; the readiness probe flipping to 503 only
    // reinforces it. On Cloud Run the platform stops routing to a terminating
    // instance directly. Either way propagation lags SIGTERM by seconds. If we
    // stop accepting connections the instant we see SIGTERM, the LB may still
    // be routing new NIP-46 / HTTP requests to us and those fail mid-flight —
    // the exact client-reconnect storm that issue #692 targets.
    //
    // So the sequence is:
    //   1. Flip `/healthz/ready` to 503 and sleep `pre_drain` so endpoint/NEG
    //      detach (GKE) propagates before we stop accepting. On Cloud Run there
    //      is no readiness-driven endpoint removal, so `pre_drain` is set to 0
    //      and peer rebalancing comes from the cluster coordinator `leave`.
    //   2. Stop accepting new HTTP connections (axum `.with_graceful_shutdown`
    //      future resolves) and wait up to `http_drain` for in-flight requests.
    //   3. Tear down the NIP-46 relay client (which stops `signer.run()` and
    //      drains the relay worker queue) and wait up to `signer_drain` for
    //      tracked background tasks.
    //   4. Close the DB pool.
    //
    // The effective budget `pre_drain + http_drain + signer_drain +
    // teardown_margin` is clamped at resolve time to fit the configured grace
    // ceiling (`SHUTDOWN_GRACE_PERIOD_CEILING_SECS`) so the platform does not
    // SIGKILL us mid-drain.
    let plan = resolve_shutdown_plan();
    let timings = plan.clamped.timings;
    let teardown_margin = plan.margin;
    let shutdown_started_at = std::time::Instant::now();
    if plan.clamped.clamped {
        tracing::warn!(
            event = "shutdown_budget_clamped_to_grace_ceiling",
            effective_pre_drain_secs = timings.pre_drain.as_secs(),
            effective_http_drain_secs = timings.http_drain.as_secs(),
            effective_signer_drain_secs = timings.signer_drain.as_secs(),
            teardown_margin_secs = teardown_margin.as_secs(),
            grace_ceiling_secs = plan.ceiling.as_secs(),
            "Graceful shutdown: configured budget exceeds grace ceiling; using clamped phase budget"
        );
    }
    tracing::info!(
        pre_drain_secs = timings.pre_drain.as_secs(),
        http_drain_secs = timings.http_drain.as_secs(),
        signer_drain_secs = timings.signer_drain.as_secs(),
        "Graceful shutdown: starting pre-drain phase (readiness now 503)"
    );

    // Phase 1: flip readiness and sleep so endpoint/NEG detach (GKE)
    // propagates. The cluster `leave` is deliberately NOT published yet: this
    // instance keeps sole ownership of its shard while it is still processing
    // NIP-46 work (phases 1-2), and deregisters at the start of phase 3
    // instead — right before the relay queue closes — so the dual-ownership
    // window where a peer and this instance both handle the same bunker
    // pubkeys shrinks from pre_drain+http_drain to Pub/Sub propagation time.
    pre_drain_pause(&shutting_down, timings.pre_drain).await;

    // Phase 2: tell axum to stop accepting new HTTP connections and wait for
    // in-flight requests to finish.
    shutdown_signal.notify_waiters();
    // Close task tracker to prevent new tracked tasks from being spawned.
    task_tracker.close();

    tracing::info!(
        elapsed_secs = shutdown_started_at.elapsed().as_secs(),
        "Graceful shutdown: draining HTTP (axum with_graceful_shutdown)"
    );
    match drain_http_or_abort(api_handle, timings.http_drain).await {
        HttpDrainOutcome::Completed => {}
        HttpDrainOutcome::AbortedAfterTimeout => {
            // Axum did not finish its graceful-shutdown future in time, so we
            // aborted the server task. Log at warn — this means either (a) a
            // handler hung for longer than the drain budget, or (b) there are
            // stuck upstream connections. Aborting the server task stops the
            // accept loop, but per-connection tasks spawned by hyper are NOT
            // children of this handle and may still be running; phase 4's
            // bounded pool close is what ultimately covers any of those still
            // holding a DB connection. The point of the abort is to stop
            // accepting *new* connections so phase 3 (relay teardown) and
            // phase 4 (DB pool close) don't race a still-live accept loop.
            tracing::warn!(
                http_drain_secs = timings.http_drain.as_secs(),
                "API server shutdown timed out; axum accept loop aborted (in-flight connection tasks may still run; bounded DB pool close covers any lingering ones)"
            );
        }
    }

    // Phase 3: publish the cluster `leave` and deregister FIRST (bounded,
    // carved out of the signer_drain budget — see
    // `deregister_within_signer_budget`), so peers rebuild the hashring and
    // take over this shard while we close and drain the relay queue right
    // after. The deregister is the *only* rebalance trigger on Cloud Run (no
    // readiness-driven endpoint removal); on GKE it follows endpoint detach.
    // The coordinator is an `Arc` shared with the signer/workers and has no
    // Drop hook, so it is NOT deregistered implicitly on return — this
    // explicit call is required. The heartbeat task is stopped as part of the
    // deregister (it cancels the shared token), so it cannot re-register us
    // after this point.
    //
    // Then close the relay queue so relay workers stop accepting new events,
    // drain queued relay work while the relay client remains connected, then
    // tear down the relay client (stopping signer.run()'s subscription) and
    // wait for signer + other tracked tasks. This runs **after** HTTP drain so
    // NIP-46 requests that arrived before the queue closed have a chance to
    // complete and publish responses back to the requesting client before we
    // disconnect from the relays.
    //
    // `drain_signer_or_abort` bounds the drain by the signer budget REMAINING
    // after the deregister (split into a drain sub-budget plus a reserved
    // relay-close slice) so `signer_drain` is a real bound on the whole of
    // phase 3, deregister included — previously only the trailing
    // `task_tracker.wait()` was bounded, leaving
    // `client_for_shutdown.shutdown()` (a nostr_sdk WebSocket close handshake)
    // unbounded in practice. A hung close could therefore blow past the grace
    // period and swallow phase 4. The reserved slice also guarantees a graceful
    // relay close is attempted even when the drain itself times out.
    tracing::info!(
        elapsed_secs = shutdown_started_at.elapsed().as_secs(),
        "Graceful shutdown: deregistering from cluster, then draining relay workers and tearing down NIP-46 relay client and signer tasks"
    );
    let (_deregister_outcome, signer_drain_budget) = deregister_within_signer_budget(
        coordinator.deregister_and_stop_heartbeat(),
        timings.signer_drain,
    )
    .await;
    let signer_handle_for_abort = signer_handle;
    let close_relay_queue = move || relay_queue.close();
    // Factory (not a single future) so the relay close can be re-attempted on
    // the drain-timeout path. Each call clones the cheap Arc-backed Client and
    // returns an owning ('static) future. `Client::shutdown` is idempotent.
    let client_shutdown = move || {
        let client = client_for_shutdown.clone();
        async move { client.shutdown().await }
    };
    match drain_signer_or_abort(
        client_shutdown,
        close_relay_queue,
        relay_worker_handles,
        task_tracker.wait(),
        || signer_handle_for_abort.abort(),
        signer_drain_budget,
    )
    .await
    {
        SignerDrainOutcome::Completed => {
            tracing::info!("All tracked tasks completed");
        }
        SignerDrainOutcome::AbortedAfterTimeout => {
            tracing::warn!(
                signer_drain_secs = timings.signer_drain.as_secs(),
                drain_budget_secs = signer_drain_budget.as_secs(),
                "Signer drain timed out (client.shutdown(), relay workers, and/or task_tracker.wait() exceeded the signer_drain budget remaining after the cluster deregister); aborted signer and relay workers"
            );
        }
    }

    // Phase 4: close database pool. Bounded by the teardown margin less
    // POOL_CLOSE_LOG_HEADROOM so a connection stuck in a long-running query
    // (e.g. a tenant-cache preload task mid-query when task_tracker.wait()
    // timed out and signer_handle.abort() was called but not awaited) cannot
    // block past the platform SIGKILL. The reserved headroom guarantees the
    // final "Graceful shutdown complete" log (and tracing flush) lands before
    // the SIGKILL even on the timeout path. sqlx's Pool::close is
    // cancellation-safe, so dropping the future on timeout is safe.
    let pool_close_budget = teardown_margin.saturating_sub(POOL_CLOSE_LOG_HEADROOM);
    match close_within_margin(pool_for_shutdown.close(), pool_close_budget).await {
        PoolCloseOutcome::Completed => {
            tracing::info!(
                total_shutdown_secs = shutdown_started_at.elapsed().as_secs(),
                "Graceful shutdown complete"
            );
        }
        PoolCloseOutcome::TimedOut => {
            tracing::warn!(
                total_shutdown_secs = shutdown_started_at.elapsed().as_secs(),
                pool_close_budget_secs = pool_close_budget.as_secs(),
                teardown_margin_secs = teardown_margin.as_secs(),
                "Graceful shutdown complete with warning: DB pool close exceeded its budget; stuck checked-out connections were dropped"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request, StatusCode},
        routing::get,
        Router,
    };
    use keycast_api::api::http::auth_observability::request_id_middleware;
    use serial_test::serial;
    use tower::ServiceExt;

    fn set_minimal_valid_environment() {
        std::env::set_var(
            "DATABASE_URL",
            "postgres://postgres:password@localhost/keycast_test",
        );
        std::env::set_var("ALLOWED_ORIGINS", "http://localhost:5173");
        std::env::set_var("SERVER_NSEC", "a".repeat(64));
        std::env::set_var("REDIS_URL", "redis://localhost:16379");
        std::env::set_var("KMS_PROVIDER", "file");
        std::env::set_var("MASTER_KEY_PATH", "./master.key");
        std::env::set_var("DISABLE_EMAILS", "true");
    }

    fn clear_minimal_valid_environment() {
        for key in [
            "DATABASE_URL",
            "ALLOWED_ORIGINS",
            "SERVER_NSEC",
            "REDIS_URL",
            "KMS_PROVIDER",
            "MASTER_KEY_PATH",
            "DISABLE_EMAILS",
            "NODE_ENV",
            "RUST_ENV",
            "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_legacy_file_default() {
        std::env::remove_var("KMS_PROVIDER");
        std::env::set_var("USE_GCP_KMS", "false");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::File);

        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_legacy_gcp_fallback() {
        std::env::remove_var("KMS_PROVIDER");
        std::env::set_var("USE_GCP_KMS", "true");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::Gcp);

        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_explicit_aws() {
        std::env::set_var("KMS_PROVIDER", "aws");
        std::env::set_var("USE_GCP_KMS", "false");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::Aws);

        std::env::remove_var("KMS_PROVIDER");
        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_prefers_explicit_over_legacy() {
        std::env::set_var("KMS_PROVIDER", "file");
        std::env::set_var("USE_GCP_KMS", "true");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::File);

        std::env::remove_var("KMS_PROVIDER");
        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_rejects_invalid_value() {
        std::env::set_var("KMS_PROVIDER", "invalid");
        let result = resolve_kms_provider();
        assert!(result.is_err());
        std::env::remove_var("KMS_PROVIDER");
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_missing_atproto_control_plane_in_production() {
        set_minimal_valid_environment();
        std::env::set_var("NODE_ENV", "production");
        std::env::remove_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL");

        let result = validate_environment();

        assert!(result.is_ok());

        clear_minimal_valid_environment();
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_invalid_atproto_control_plane_url() {
        set_minimal_valid_environment();
        std::env::set_var("NODE_ENV", "production");
        std::env::set_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", "not a url");

        let result = validate_environment();

        assert!(result.is_ok());

        clear_minimal_valid_environment();
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_atproto_control_plane_url_with_query_or_fragment() {
        for url in [
            "https://control-plane.example?tenant=prod",
            "https://control-plane.example#provisioning",
        ] {
            set_minimal_valid_environment();
            std::env::set_var("NODE_ENV", "production");
            std::env::set_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", url);

            let result = validate_environment();

            assert!(result.is_ok(), "{url} should not block startup");

            clear_minimal_valid_environment();
        }
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_atproto_control_plane_url_with_path() {
        for url in [
            "https://control-plane.example/api",
            "https://control-plane.example/api/",
            "https://control-plane.example/nested/path",
        ] {
            set_minimal_valid_environment();
            std::env::set_var("NODE_ENV", "production");
            std::env::set_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", url);

            let result = validate_environment();

            assert!(result.is_ok(), "{url} should not block startup");

            clear_minimal_valid_environment();
        }
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_with_head_tag() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        // Set environment variables
        std::env::set_var("APP_URL", "https://example.com");
        std::env::set_var("ALLOWED_PUBKEYS", "pubkey1,pubkey2");

        let result = inject_runtime_env(html);

        // Should inject script before </head>
        assert!(result.contains("window.__ENV__"));
        assert!(result.contains("VITE_DOMAIN"));
        assert!(result.contains("https://example.com"));
        assert!(result.contains("ALLOWED_PUBKEYS"));
        assert!(result.contains("pubkey1,pubkey2"));
        assert!(result.contains("</head>"));

        // Clean up
        std::env::remove_var("APP_URL");
        std::env::remove_var("ALLOWED_PUBKEYS");
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_without_head_tag() {
        let html = r#"<!DOCTYPE html>
<html>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        std::env::set_var("APP_URL", "https://example.com");

        let result = inject_runtime_env(html);

        // Should inject before <body>
        assert!(result.contains("window.__ENV__"));
        assert!(result.contains("<body>"));

        std::env::remove_var("APP_URL");
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_no_env_vars() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        // Clear all env vars that might be set from other tests
        std::env::remove_var("APP_URL");
        std::env::remove_var("ALLOWED_PUBKEYS");
        std::env::remove_var("SHOW_TEAMS_FUNCTIONALITY");

        let result = inject_runtime_env(html);

        // Should return original HTML unchanged
        assert_eq!(result, html);
        assert!(!result.contains("window.__ENV__"));
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_all_vars() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        std::env::set_var("APP_URL", "https://example.com");
        std::env::set_var("ALLOWED_PUBKEYS", "key1,key2");
        std::env::set_var("SHOW_TEAMS_FUNCTIONALITY", "true");

        let result = inject_runtime_env(html);

        assert!(result.contains("VITE_DOMAIN"));
        assert!(result.contains("ALLOWED_PUBKEYS"));
        assert!(result.contains("SHOW_TEAMS_FUNCTIONALITY"));

        std::env::remove_var("APP_URL");
        std::env::remove_var("ALLOWED_PUBKEYS");
        std::env::remove_var("SHOW_TEAMS_FUNCTIONALITY");
    }

    #[test]
    fn test_origin_is_allowed_for_exact_match() {
        assert!(origin_is_allowed(
            "https://login.divine.video",
            "https://login.divine.video,https://divine.video"
        ));
    }

    #[test]
    fn test_origin_is_allowed_for_pages_preview_wildcard() {
        assert!(origin_is_allowed(
            "https://f582401d.openvine-app.pages.dev",
            "https://login.divine.video,https://*.openvine-app.pages.dev"
        ));
    }

    #[test]
    fn test_origin_is_not_allowed_for_non_matching_wildcard_host() {
        assert!(!origin_is_allowed(
            "https://openvine-app.pages.dev",
            "https://login.divine.video,https://*.openvine-app.pages.dev"
        ));
        assert!(!origin_is_allowed(
            "https://evil.pages.dev",
            "https://login.divine.video,https://*.openvine-app.pages.dev"
        ));
    }

    #[tokio::test]
    async fn test_request_id_middleware_echoes_trace_header() {
        let app = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .header("x-trace-id", "trace-1234")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "trace-1234"
        );
    }

    #[tokio::test]
    async fn test_request_id_middleware_generates_request_id() {
        let app = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id_middleware));

        let response = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let request_id = response.headers().get("x-request-id").unwrap();
        assert!(!request_id.is_empty());
    }

    #[tokio::test]
    async fn test_health_check_returns_json_body() {
        let response = health_check().await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["service"], "keycast");
    }

    #[test]
    fn test_readiness_response_reports_shutdown_as_unavailable() {
        let (status, body) = readiness_response(true, true);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Shutting down");
    }

    #[test]
    fn test_readiness_response_reports_database_failures_as_unavailable() {
        let (status, body) = readiness_response(false, false);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Database unavailable");
    }

    /// Router-level smoke test: verifies the probe routes are mounted at the
    /// exact paths the kubelet hits. Catches typos like `/healthz/startup`
    /// vs `/healthz/start`. Skips `/healthz/ready` because that handler
    /// requires a live DB pool.
    #[tokio::test]
    async fn test_health_probe_routes_respond_ok() {
        let livez_state = Arc::new(LivenessState {
            shutting_down: Arc::new(AtomicBool::new(false)),
        });

        let app = Router::new()
            .route("/livez", get(move || livez(livez_state.clone())))
            .route("/healthz/startup", get(startupz));

        for path in ["/livez", "/healthz/startup"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {path} not OK");
        }
    }

    // --- Shutdown timings ---
    //
    // These tests exercise the env-var-driven shutdown phase durations used by
    // the graceful-shutdown sequence in `async_main`. Values must be stable
    // because the iac repo's `terminationGracePeriodSeconds` is tuned against
    // them: PRE_DRAIN + HTTP_DRAIN + SIGNER_DRAIN must fit inside the grace
    // period with margin for process teardown.

    fn clear_shutdown_env() {
        std::env::remove_var("SHUTDOWN_PRE_DRAIN_SECS");
        std::env::remove_var("SHUTDOWN_HTTP_DRAIN_SECS");
        std::env::remove_var("SHUTDOWN_SIGNER_DRAIN_SECS");
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_defaults() {
        clear_shutdown_env();

        let timings = parse_shutdown_timings();

        // Documented defaults — see main.rs docs on graceful shutdown.
        // Sized so pre(15) + http(40) + signer(10) + margin(10) = 75 fits the
        // intended GKE terminationGracePeriodSeconds exactly.
        assert_eq!(timings.pre_drain, Duration::from_secs(15));
        assert_eq!(timings.http_drain, Duration::from_secs(40));
        assert_eq!(timings.signer_drain, Duration::from_secs(10));
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_overrides_each_field() {
        clear_shutdown_env();
        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "3");
        std::env::set_var("SHUTDOWN_HTTP_DRAIN_SECS", "20");
        std::env::set_var("SHUTDOWN_SIGNER_DRAIN_SECS", "5");

        let timings = parse_shutdown_timings();

        assert_eq!(timings.pre_drain, Duration::from_secs(3));
        assert_eq!(timings.http_drain, Duration::from_secs(20));
        assert_eq!(timings.signer_drain, Duration::from_secs(5));

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_accepts_zero() {
        // Zero is a legitimate value for tests and local dev: skip the
        // endpoint-propagation wait, drain as fast as possible. It must NOT
        // collapse back to the default.
        clear_shutdown_env();
        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "0");
        std::env::set_var("SHUTDOWN_HTTP_DRAIN_SECS", "0");
        std::env::set_var("SHUTDOWN_SIGNER_DRAIN_SECS", "0");

        let timings = parse_shutdown_timings();

        assert_eq!(timings.pre_drain, Duration::ZERO);
        assert_eq!(timings.http_drain, Duration::ZERO);
        assert_eq!(timings.signer_drain, Duration::ZERO);

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_invalid_value_falls_back_to_default() {
        // An unparseable value should fall through to the default rather than
        // panic at startup — we'd rather ship with a sane default than crash.
        clear_shutdown_env();
        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "not-a-number");

        let timings = parse_shutdown_timings();

        assert_eq!(
            timings.pre_drain,
            Duration::from_secs(DEFAULT_SHUTDOWN_PRE_DRAIN_SECS)
        );

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_rejects_u64_max_and_falls_back_to_default() {
        // Regression: if a misconfig sets SHUTDOWN_PRE_DRAIN_SECS near
        // u64::MAX, `Duration::from_secs` itself is fine but the later
        // `total_budget()` sum with `+` panics on overflow. That aborts
        // the process before the validate-and-warn path can run, turning
        // an operator misconfig into a raw crashloop. Parsing must clamp
        // or reject any value above SHUTDOWN_PER_FIELD_CEILING_SECS so
        // the sum can never overflow.
        clear_shutdown_env();
        std::env::set_var(
            "SHUTDOWN_PRE_DRAIN_SECS",
            "18446744073709551600", // u64::MAX - 15, well above the ceiling
        );

        let timings = parse_shutdown_timings();

        // Fell back to the default, NOT the u64::MAX-ish value.
        assert_eq!(
            timings.pre_drain,
            Duration::from_secs(DEFAULT_SHUTDOWN_PRE_DRAIN_SECS)
        );

        // And the downstream total_budget() MUST NOT panic. This is the
        // actual safety property — the validate-and-warn path must be
        // reachable even under this misconfig.
        let _ = timings.total_budget(); // must not panic

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_rejects_value_above_per_field_ceiling() {
        // Exactly one second above the ceiling. Reject and fall back to
        // default so total_budget cannot overflow and the warn-with-context
        // path in validate_shutdown_timings still runs.
        clear_shutdown_env();
        let too_big = SHUTDOWN_PER_FIELD_CEILING_SECS + 1;
        std::env::set_var("SHUTDOWN_HTTP_DRAIN_SECS", too_big.to_string());

        let timings = parse_shutdown_timings();

        assert_eq!(
            timings.http_drain,
            Duration::from_secs(DEFAULT_SHUTDOWN_HTTP_DRAIN_SECS),
            "value above per-field ceiling must fall back to default"
        );

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_accepts_value_at_per_field_ceiling() {
        // The ceiling itself is a legitimate value (though far above any
        // real operational setting). Reject only values strictly greater
        // than the ceiling, so operators can explicitly opt into the max
        // if they know what they are doing.
        clear_shutdown_env();
        std::env::set_var(
            "SHUTDOWN_PRE_DRAIN_SECS",
            SHUTDOWN_PER_FIELD_CEILING_SECS.to_string(),
        );

        let timings = parse_shutdown_timings();

        assert_eq!(
            timings.pre_drain,
            Duration::from_secs(SHUTDOWN_PER_FIELD_CEILING_SECS)
        );

        clear_shutdown_env();
    }

    #[test]
    fn test_total_budget_no_overflow_at_per_field_ceiling() {
        // Safety property: with every field at the per-field ceiling,
        // total_budget() must not panic and must stay comfortably inside
        // u64 range. 3 * 86400 = 259200s = 3 days, far below u64::MAX.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(SHUTDOWN_PER_FIELD_CEILING_SECS),
            http_drain: Duration::from_secs(SHUTDOWN_PER_FIELD_CEILING_SECS),
            signer_drain: Duration::from_secs(SHUTDOWN_PER_FIELD_CEILING_SECS),
        };

        // Must not panic.
        let total = t.total_budget();
        assert_eq!(
            total,
            Duration::from_secs(3 * SHUTDOWN_PER_FIELD_CEILING_SECS)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_pre_drain_pause_flips_unready_before_sleeping() {
        // The pre-drain pause exists so K8s can remove the pod from the
        // Service EndpointSlice (readiness probe failing) BEFORE we stop
        // accepting new connections. The AtomicBool MUST be set to true
        // before the sleep — otherwise the probe never fails and the grace
        // window is wasted.

        let unready = Arc::new(AtomicBool::new(false));
        let unready_for_task = unready.clone();

        let pause_handle = tokio::spawn(async move {
            pre_drain_pause(&unready_for_task, Duration::from_secs(5)).await
        });

        // Yield once so the spawned task gets a chance to set the flag before
        // the `tokio::time` pause machinery advances. With start_paused=true
        // real time is frozen; only `tokio::time::advance` or awaiting a
        // sleep moves it. The flag is set synchronously before the first
        // `.await` inside `pre_drain_pause`, so a yield is enough.
        tokio::task::yield_now().await;

        assert!(
            unready.load(Ordering::Relaxed),
            "pre_drain_pause must flip unready before sleeping so /healthz/ready starts returning 503 immediately"
        );

        // Now advance virtual time past the sleep and confirm the function
        // returns (no hang, no early return before the sleep).
        tokio::time::advance(Duration::from_secs(5)).await;
        pause_handle.await.expect("pre_drain_pause panicked");
    }

    #[tokio::test(start_paused = true)]
    async fn test_pre_drain_pause_with_zero_duration_returns_immediately() {
        // Local dev / tests set SHUTDOWN_PRE_DRAIN_SECS=0 to skip the wait.
        // The function must still set the flag and then return without
        // requiring any time to pass.
        let unready = Arc::new(AtomicBool::new(false));

        pre_drain_pause(&unready, Duration::ZERO).await;

        assert!(unready.load(Ordering::Relaxed));
    }

    // --- Shutdown grace-period ceiling validation ---
    //
    // The iac repo pins `terminationGracePeriodSeconds` in the Deployment; the
    // kubelet SIGKILLs any pod whose graceful shutdown exceeds that. The three
    // shutdown env vars (`SHUTDOWN_PRE_DRAIN_SECS` / `HTTP_DRAIN` /
    // `SIGNER_DRAIN`) are independent u64s with no upper bound, so a misconfig
    // (e.g. `SHUTDOWN_HTTP_DRAIN_SECS=120` against a 75s grace) would silently
    // lose in-flight requests on scale-down — exactly the failure this
    // feature is supposed to prevent. We validate the total + teardown margin
    // against a configurable ceiling on startup and log a loud warning if it
    // exceeds. We deliberately warn rather than refuse to boot: the ceiling is
    // cross-repo-coupled and an operator may legitimately need to boot with a
    // larger grace period before the iac repo catches up.

    fn clear_shutdown_ceiling_env() {
        std::env::remove_var("SHUTDOWN_GRACE_PERIOD_CEILING_SECS");
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_grace_ceiling_default() {
        clear_shutdown_ceiling_env();

        // Default must match the intended Deployment grace period. A default
        // higher than the real pod grace would let unsafe phase budgets pass
        // validation locally and only fail later under kubelet SIGKILL.
        assert_eq!(parse_shutdown_grace_ceiling(), Duration::from_secs(75));
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_grace_ceiling_override() {
        clear_shutdown_ceiling_env();
        std::env::set_var("SHUTDOWN_GRACE_PERIOD_CEILING_SECS", "60");

        assert_eq!(parse_shutdown_grace_ceiling(), Duration::from_secs(60));

        clear_shutdown_ceiling_env();
    }

    #[test]
    fn test_shutdown_timings_total_budget() {
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };
        assert_eq!(t.total_budget(), Duration::from_secs(65));
    }

    #[test]
    fn test_validate_shutdown_timings_ok_when_under_ceiling() {
        // Default timings (65s) + teardown margin (10s) = 75s. A 75s or
        // larger ceiling must validate cleanly; this is the iac PR's target.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };

        let margin = Duration::from_secs(10);
        assert!(validate_shutdown_timings(&t, Duration::from_secs(75), margin).is_ok());
        assert!(validate_shutdown_timings(&t, Duration::from_secs(90), margin).is_ok());
    }

    #[test]
    fn test_validate_shutdown_timings_error_when_over_ceiling() {
        // The 65s default budget + 10s margin does NOT fit a 60s grace
        // period. This is the concrete failure mode flagged in review:
        // if the sibling iac PR lands with terminationGracePeriodSeconds=60,
        // the kubelet will SIGKILL mid-signer-drain. Validation must catch
        // this and return a descriptive error string.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };

        let err = validate_shutdown_timings(&t, Duration::from_secs(60), Duration::from_secs(10))
            .expect_err("65s budget + 10s margin must not fit in 60s ceiling");
        // Error message should be operator-actionable: include the total,
        // the margin, and the ceiling so they can tune either side.
        assert!(err.contains("65"), "error should name total budget: {err}");
        assert!(err.contains("60"), "error should name ceiling: {err}");
    }

    #[test]
    fn test_validate_shutdown_timings_error_when_single_field_exceeds_ceiling() {
        // Operator misconfig: SHUTDOWN_HTTP_DRAIN_SECS=120 against default
        // 75s ceiling. Single-field overshoot must still be caught.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(120),
            signer_drain: Duration::from_secs(10),
        };

        assert!(
            validate_shutdown_timings(&t, Duration::from_secs(75), Duration::from_secs(10))
                .is_err()
        );
    }

    // --- HTTP drain abort-on-timeout ---
    //
    // On shutdown, the HTTP drain phase waits up to `SHUTDOWN_HTTP_DRAIN_SECS`
    // for axum's `.with_graceful_shutdown()` future to complete. The axum
    // task is a raw `tokio::spawn`, NOT on TaskTracker. Previously the
    // timeout arm just logged "API server shutdown timed out" and fell
    // through — but dropping a JoinHandle does NOT cancel the underlying
    // task (std+tokio semantics). axum would keep running (potentially
    // still accepting / serving new connections) during phase 3 (relay
    // client teardown) and phase 4 (DB pool close), with pool-close
    // generating decode errors on late-arriving requests until the kubelet
    // SIGKILL finally stopped the process at terminationGracePeriodSeconds.
    // The abort-on-timeout helper below makes the budget a real bound.

    #[tokio::test(start_paused = true)]
    async fn test_drain_http_or_abort_returns_completed_when_task_finishes_before_budget() {
        // Fast path: if the spawned task completes inside the drain budget,
        // we should report Completed and not touch abort().
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let outcome = drain_http_or_abort(handle, Duration::from_secs(5)).await;

        assert!(
            matches!(outcome, HttpDrainOutcome::Completed),
            "expected Completed, got {:?}",
            outcome
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_http_or_abort_aborts_task_when_budget_exceeded() {
        // The behavioral promise: if the axum task is still running at the
        // end of the HTTP drain budget, drain_http_or_abort must stop it
        // before returning so phase 3 (relay teardown) and phase 4 (DB pool
        // close) aren't racing a still-live accept loop.
        //
        // We spawn a task that would sleep for an hour; with a 5s drain
        // budget the helper must abort it. After the helper returns, the
        // spawned task must be finished (cancelled), NOT still pending.

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_flag_task = cancel_flag.clone();

        let handle = tokio::spawn(async move {
            // Use an async block with a drop guard so we can observe that
            // the task was actually cancelled, not just left pending.
            struct CancelSignal(Arc<AtomicBool>);
            impl Drop for CancelSignal {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let _guard = CancelSignal(cancel_flag_task);

            // Would sleep for an hour if not aborted.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        let outcome = drain_http_or_abort(handle, Duration::from_secs(5)).await;

        assert!(
            matches!(outcome, HttpDrainOutcome::AbortedAfterTimeout),
            "expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            cancel_flag.load(Ordering::Relaxed),
            "drain_http_or_abort must abort the spawned task — task drop guard did not fire, meaning the task is still running past the HTTP drain budget"
        );
    }

    #[test]
    fn test_validate_shutdown_timings_boundary_exactly_at_ceiling() {
        // total_budget + teardown margin = 65 + 10 = 75.
        // A ceiling of 75 means the teardown margin exactly fits — that is
        // precisely what the margin is reserved for, so accept. The iac
        // PR's terminationGracePeriodSeconds=75s should validate cleanly
        // against these timings with no operator action.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };

        let margin = Duration::from_secs(10);
        // Exactly the ceiling: OK (margin fits).
        assert!(validate_shutdown_timings(&t, Duration::from_secs(75), margin).is_ok());
        // One second below: reject — margin no longer fits.
        assert!(validate_shutdown_timings(&t, Duration::from_secs(74), margin).is_err());
        // One second above: OK — extra headroom.
        assert!(validate_shutdown_timings(&t, Duration::from_secs(76), margin).is_ok());
    }

    #[test]
    fn test_default_timings_fit_default_ceiling_without_clamping() {
        // The shipped defaults (pre=15, http=40, signer=10) plus the default
        // margin (10) must fit the default GKE ceiling (75) exactly so the
        // normal GKE path never clamps.
        let defaults = ShutdownTimings {
            pre_drain: Duration::from_secs(DEFAULT_SHUTDOWN_PRE_DRAIN_SECS),
            http_drain: Duration::from_secs(DEFAULT_SHUTDOWN_HTTP_DRAIN_SECS),
            signer_drain: Duration::from_secs(DEFAULT_SHUTDOWN_SIGNER_DRAIN_SECS),
        };
        let ceiling = Duration::from_secs(DEFAULT_SHUTDOWN_GRACE_CEILING_SECS);
        let margin = Duration::from_secs(DEFAULT_SHUTDOWN_TEARDOWN_MARGIN_SECS);

        assert!(validate_shutdown_timings(&defaults, ceiling, margin).is_ok());
        // pre_drain explicitly set or not, an already-fitting budget is never
        // clamped.
        for explicit in [true, false] {
            let result = clamp_shutdown_timings(defaults, ceiling, margin, explicit);
            assert!(
                !result.clamped,
                "defaults must not be clamped (explicit={explicit})"
            );
            assert_eq!(result.timings, defaults);
        }
    }

    // --- Teardown margin parsing ---

    fn clear_shutdown_margin_env() {
        std::env::remove_var("SHUTDOWN_TEARDOWN_MARGIN_SECS");
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_teardown_margin_default() {
        clear_shutdown_margin_env();
        assert_eq!(parse_shutdown_teardown_margin(), Duration::from_secs(10));
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_teardown_margin_override() {
        clear_shutdown_margin_env();
        std::env::set_var("SHUTDOWN_TEARDOWN_MARGIN_SECS", "2");
        assert_eq!(parse_shutdown_teardown_margin(), Duration::from_secs(2));
        clear_shutdown_margin_env();
    }

    #[test]
    #[serial]
    fn test_pre_drain_explicit_detection() {
        clear_shutdown_env();
        assert!(
            !pre_drain_was_explicitly_set(),
            "unset must not count as explicit"
        );

        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "0");
        assert!(
            pre_drain_was_explicitly_set(),
            "an explicit 0 must count as set"
        );

        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "not-a-number");
        assert!(
            !pre_drain_was_explicitly_set(),
            "an unparseable value falls back to default and must not count as explicit"
        );
        clear_shutdown_env();
    }

    // --- Clamp shutdown timings ---
    //
    // The clamp makes the phased drain provably fit whatever post-SIGTERM grace
    // the platform actually enforces. The GKE-sized defaults validate cleanly
    // against a 75s ceiling but bust a Cloud Run ~10s ceiling; rather than run
    // the full budget and get SIGKILLed mid-drain, the phases are scaled down.

    #[test]
    fn test_clamp_scales_drains_into_cloud_run_ceiling_keeping_explicit_pre_drain() {
        // Cloud Run: pre_drain explicitly 0, tiny ceiling, small margin. The
        // two drains must be scaled to fit `ceiling - margin = 8`.
        let configured = ShutdownTimings {
            pre_drain: Duration::ZERO,
            http_drain: Duration::from_secs(40),
            signer_drain: Duration::from_secs(10),
        };
        let ceiling = Duration::from_secs(10);
        let margin = Duration::from_secs(2);

        let result = clamp_shutdown_timings(configured, ceiling, margin, /* explicit */ true);

        assert!(
            result.clamped,
            "GKE-sized drains must be clamped to a 10s ceiling"
        );
        assert_eq!(
            result.timings.pre_drain,
            Duration::ZERO,
            "explicit pre_drain preserved"
        );
        // Must provably fit, with the margin reserved.
        assert!(
            result.timings.total_budget() + margin <= ceiling,
            "clamped budget {:?} + margin {:?} must fit ceiling {:?}",
            result.timings.total_budget(),
            margin,
            ceiling
        );
        // Proportions roughly preserved (http was 4x signer): http stays larger.
        assert!(result.timings.http_drain > result.timings.signer_drain);
    }

    #[test]
    fn test_clamp_scales_pre_drain_too_when_not_explicit() {
        // Default (non-explicit) pre_drain against a tight ceiling: pre_drain
        // is eligible for scaling so it does not eat the whole budget.
        let configured = ShutdownTimings {
            pre_drain: Duration::from_secs(15),
            http_drain: Duration::from_secs(40),
            signer_drain: Duration::from_secs(10),
        };
        let ceiling = Duration::from_secs(10);
        let margin = Duration::from_secs(2);

        let result = clamp_shutdown_timings(configured, ceiling, margin, /* explicit */ false);

        assert!(result.clamped);
        assert!(
            result.timings.pre_drain > Duration::ZERO
                && result.timings.pre_drain < Duration::from_secs(15),
            "non-explicit pre_drain should be scaled down, not preserved or zeroed: {:?}",
            result.timings.pre_drain
        );
        assert!(result.timings.total_budget() + margin <= ceiling);
    }

    #[test]
    fn test_clamp_preserves_explicit_pre_drain_even_when_it_consumes_budget() {
        // Operator explicitly demanded a large pre_drain on a tight ceiling:
        // honor it (capped at available) and starve the drains rather than
        // silently shrinking the endpoint-propagation wait they asked for.
        let configured = ShutdownTimings {
            pre_drain: Duration::from_secs(30),
            http_drain: Duration::from_secs(40),
            signer_drain: Duration::from_secs(10),
        };
        let ceiling = Duration::from_secs(10);
        let margin = Duration::from_secs(2);

        let result = clamp_shutdown_timings(configured, ceiling, margin, /* explicit */ true);

        assert!(result.clamped);
        // pre_drain capped at available (ceiling - margin = 8); drains squeezed to 0.
        assert_eq!(result.timings.pre_drain, Duration::from_secs(8));
        assert_eq!(result.timings.http_drain, Duration::ZERO);
        assert_eq!(result.timings.signer_drain, Duration::ZERO);
        assert!(result.timings.total_budget() + margin <= ceiling);
    }

    #[test]
    fn test_clamp_noop_when_budget_fits() {
        let configured = ShutdownTimings {
            pre_drain: Duration::from_secs(1),
            http_drain: Duration::from_secs(2),
            signer_drain: Duration::from_secs(1),
        };
        let result = clamp_shutdown_timings(
            configured,
            Duration::from_secs(60),
            Duration::from_secs(10),
            true,
        );
        assert!(!result.clamped);
        assert_eq!(result.timings, configured);
    }

    // --- Phase 4 bounded DB pool close ---
    //
    // sqlx's `Pool::close()` waits for every checked-out connection to be
    // returned to the pool. If a long-running query is still outstanding
    // when we enter phase 4 (e.g. a tenant-cache preload task was mid-query
    // when task_tracker.wait() timed out and signer_handle.abort() was
    // called but did not await), close can block indefinitely into the
    // kubelet SIGKILL. That swallows the final "Graceful shutdown complete"
    // log, so operators have no positive signal of clean shutdown.
    // close_within_margin enforces the documented SHUTDOWN_TEARDOWN_MARGIN
    // as a real bound.

    #[tokio::test(start_paused = true)]
    async fn test_close_within_margin_returns_completed_when_future_finishes_before_margin() {
        // Fast path: close completes immediately. Should report Completed
        // so the caller can emit the clean "Graceful shutdown complete"
        // log with no warning.
        let close_fut = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        let outcome = close_within_margin(close_fut, Duration::from_secs(10)).await;

        assert!(
            matches!(outcome, PoolCloseOutcome::Completed),
            "expected Completed, got {:?}",
            outcome
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_close_within_margin_reports_timed_out_when_margin_exceeded() {
        // Slow path: close blocks past the margin. Should report TimedOut
        // so the caller logs a warning and proceeds — we cannot hang the
        // process on pool teardown when the kubelet SIGKILL is about to
        // hit us anyway.
        let close_fut = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };

        let outcome = close_within_margin(close_fut, Duration::from_secs(10)).await;

        assert!(
            matches!(outcome, PoolCloseOutcome::TimedOut),
            "expected TimedOut, got {:?}",
            outcome
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_close_within_margin_enforces_real_bound_past_margin() {
        // A close future that blocks well past the margin must NOT extend
        // the helper's runtime past `margin`. We measure virtual time
        // elapsed under start_paused: it must be exactly the margin (not
        // the 1h sleep). This is the safety property the reviewer asked
        // for — phase 4 cannot eat into the kubelet's SIGKILL window.
        let start = tokio::time::Instant::now();
        let margin = Duration::from_secs(10);
        let close_fut = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };

        let _outcome = close_within_margin(close_fut, margin).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed <= margin + Duration::from_millis(100),
            "close_within_margin must return within the margin, not block on the inner future; elapsed={:?}, margin={:?}",
            elapsed,
            margin
        );
    }

    // --- Phase 3 bounded signer drain ---
    //
    // Phase 3 drains relay workers, runs `client_for_shutdown.shutdown().await`,
    // then `task_tracker.wait().await`. Previously `client.shutdown()` was
    // unbounded: a stuck WebSocket close handshake, a bug in
    // `nostr_sdk::Client::shutdown`, or a dead relay socket could hang
    // the phase past the grace period and swallow phase 4 entirely. The
    // `signer_drain` timeout only wrapped the trailing `task_tracker.wait()`,
    // silently busting the design contract (enforced by
    // `validate_shutdown_timings`) that `pre_drain + http_drain + signer_drain
    // + teardown_margin <= ceiling`.
    //
    // `drain_signer_or_abort` bounds the whole phase by `signer_drain`, split
    // into a drain sub-budget plus a reserved relay-close slice, so
    // `signer_drain` is a real bound on phase 3 regardless of how many awaits
    // are inside. On timeout it invokes the caller-supplied abort callback
    // (which aborts the
    // signer JoinHandle in production).

    #[tokio::test(start_paused = true)]
    async fn test_deregister_within_signer_budget_fast_path_keeps_full_drain_budget() {
        // An instant deregister must not eat into the drain budget.
        let signer_drain = Duration::from_secs(10);
        let (outcome, remaining) =
            deregister_within_signer_budget(async { Ok::<(), String>(()) }, signer_drain).await;
        assert_eq!(outcome, ClusterDeregisterOutcome::Deregistered);
        assert_eq!(remaining, signer_drain);
    }

    #[tokio::test(start_paused = true)]
    async fn test_deregister_within_signer_budget_hung_deregister_capped_at_cluster_timeout() {
        // A hung Redis costs at most CLUSTER_DEREGISTER_TIMEOUT of the
        // signer_drain budget; the rest stays available for the queue drain.
        let signer_drain = Duration::from_secs(10);
        let started = tokio::time::Instant::now();
        let (outcome, remaining) = deregister_within_signer_budget(
            std::future::pending::<Result<(), String>>(),
            signer_drain,
        )
        .await;
        assert_eq!(outcome, ClusterDeregisterOutcome::TimedOut);
        assert_eq!(started.elapsed(), CLUSTER_DEREGISTER_TIMEOUT);
        assert_eq!(remaining, signer_drain - CLUSTER_DEREGISTER_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn test_deregister_within_signer_budget_hung_deregister_capped_at_signer_drain() {
        // When signer_drain is smaller than CLUSTER_DEREGISTER_TIMEOUT the
        // phase-3 wall clock must still never exceed signer_drain — the
        // deregister is carved out of the phase budget, not added on top.
        let signer_drain = Duration::from_secs(1);
        assert!(signer_drain < CLUSTER_DEREGISTER_TIMEOUT);
        let started = tokio::time::Instant::now();
        let (outcome, remaining) = deregister_within_signer_budget(
            std::future::pending::<Result<(), String>>(),
            signer_drain,
        )
        .await;
        assert_eq!(outcome, ClusterDeregisterOutcome::TimedOut);
        assert_eq!(started.elapsed(), signer_drain);
        assert_eq!(remaining, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn test_deregister_within_signer_budget_error_path_keeps_drain_budget() {
        // A fast Redis error (connection refused) must not eat the drain
        // budget either; shutdown continues and peers converge via heartbeat
        // staleness.
        let signer_drain = Duration::from_secs(10);
        let (outcome, remaining) = deregister_within_signer_budget(
            async { Err::<(), String>("redis connection refused".to_string()) },
            signer_drain,
        )
        .await;
        assert_eq!(outcome, ClusterDeregisterOutcome::Failed);
        assert_eq!(remaining, signer_drain);
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_returns_completed_when_both_finish_before_budget() {
        // Fast path: both client.shutdown() and task_tracker.wait()
        // complete inside the signer_drain budget. Should report
        // Completed and NOT invoke the abort callback.
        let abort_called = Arc::new(AtomicBool::new(false));
        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };

        let client_shutdown = || async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let tracker_wait = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let relay_worker_handles = Vec::new();

        let outcome = drain_signer_or_abort(
            client_shutdown,
            || {},
            relay_worker_handles,
            tracker_wait,
            abort_signer,
            Duration::from_secs(10),
        )
        .await;

        assert!(
            matches!(outcome, SignerDrainOutcome::Completed),
            "expected Completed, got {:?}",
            outcome
        );
        assert!(
            !abort_called.load(Ordering::Relaxed),
            "abort_signer must NOT be called on the happy path"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_drains_relay_workers_before_client_shutdown() {
        // Regression target: relay workers spawned by RelayQueue are not in
        // TaskTracker. Phase 3 must explicitly close the relay queue and await
        // those worker handles before reporting Completed, otherwise phase 4
        // can close the DB pool while relay workers are still processing queued
        // NIP-46 requests.
        let queue_closed = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::new(AtomicBool::new(false));
        let abort_called = Arc::new(AtomicBool::new(false));

        let queue_closed_for_worker = queue_closed.clone();
        let worker_finished_for_worker = worker_finished.clone();
        let relay_worker_handles = vec![tokio::spawn(async move {
            while !queue_closed_for_worker.load(Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            worker_finished_for_worker.store(true, Ordering::Relaxed);
        })];

        let queue_closed_for_cb = queue_closed.clone();
        let close_relay_queue = move || {
            queue_closed_for_cb.store(true, Ordering::Relaxed);
        };
        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };
        let queue_closed_for_client = queue_closed.clone();
        let worker_finished_for_client = worker_finished.clone();
        // Factory: clone the Arcs per call so the closure stays `Fn`.
        let client_shutdown = move || {
            let queue_closed_for_client = queue_closed_for_client.clone();
            let worker_finished_for_client = worker_finished_for_client.clone();
            async move {
                assert!(
                    queue_closed_for_client.load(Ordering::Relaxed),
                    "phase 3 must close relay intake before shutting down the relay client"
                );
                assert!(
                    worker_finished_for_client.load(Ordering::Relaxed),
                    "phase 3 must drain relay workers before shutting down the relay client"
                );
            }
        };

        let outcome = drain_signer_or_abort(
            client_shutdown,
            close_relay_queue,
            relay_worker_handles,
            async {},
            abort_signer,
            Duration::from_secs(10),
        )
        .await;

        assert!(
            matches!(outcome, SignerDrainOutcome::Completed),
            "expected Completed, got {:?}",
            outcome
        );
        assert!(
            queue_closed.load(Ordering::Relaxed),
            "phase 3 must close the relay queue before waiting for relay workers"
        );
        assert!(
            worker_finished.load(Ordering::Relaxed),
            "phase 3 must wait for relay worker handles before reporting Completed"
        );
        assert!(
            !abort_called.load(Ordering::Relaxed),
            "abort_signer must NOT be called on the happy path"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_completes_with_retained_relay_sender_clone() {
        let relay_queue = RelayQueue::new();
        let retained_sender = relay_queue.sender();
        let worker_sender_view = retained_sender.clone();
        let abort_called = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::new(AtomicBool::new(false));

        let worker_finished_for_task = worker_finished.clone();
        let relay_worker_handles = vec![tokio::spawn(async move {
            while !worker_sender_view.is_closed() {
                tokio::task::yield_now().await;
            }
            worker_finished_for_task.store(true, Ordering::Relaxed);
        })];

        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };

        let outcome = drain_signer_or_abort(
            || async {},
            move || relay_queue.close(),
            relay_worker_handles,
            async {},
            abort_signer,
            Duration::from_secs(10),
        )
        .await;

        assert!(
            matches!(outcome, SignerDrainOutcome::Completed),
            "expected Completed with retained RelaySender clone, got {:?}",
            outcome
        );
        assert!(
            retained_sender.is_closed(),
            "explicit close must be visible through retained RelaySender clones"
        );
        assert!(
            worker_finished.load(Ordering::Relaxed),
            "phase 3 must drain relay workers after explicit close"
        );
        assert!(
            !abort_called.load(Ordering::Relaxed),
            "retained RelaySender clones must not force the timeout path"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_aborts_relay_workers_on_timeout() {
        // If a relay worker is stuck past signer_drain, dropping its JoinHandle
        // is insufficient: tokio keeps the task running. Phase 3 must abort
        // the relay worker handles on the timeout path before phase 4 closes
        // the DB pool.
        let queue_closed = Arc::new(AtomicBool::new(false));
        let abort_called = Arc::new(AtomicBool::new(false));
        let relay_worker_aborted = Arc::new(AtomicBool::new(false));

        struct MarkOnDrop {
            dropped: Arc<AtomicBool>,
        }

        impl Drop for MarkOnDrop {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Relaxed);
            }
        }

        let relay_worker_aborted_for_task = relay_worker_aborted.clone();
        let relay_worker_handles = vec![tokio::spawn(async move {
            let mark_on_drop = MarkOnDrop {
                dropped: relay_worker_aborted_for_task,
            };
            tokio::time::sleep(Duration::from_secs(3600)).await;
            std::mem::forget(mark_on_drop);
        })];

        let queue_closed_for_cb = queue_closed.clone();
        let close_relay_queue = move || {
            queue_closed_for_cb.store(true, Ordering::Relaxed);
        };
        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };

        let outcome = drain_signer_or_abort(
            || async {},
            close_relay_queue,
            relay_worker_handles,
            async {},
            abort_signer,
            Duration::from_secs(10),
        )
        .await;
        tokio::task::yield_now().await;

        assert!(
            matches!(outcome, SignerDrainOutcome::AbortedAfterTimeout),
            "expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            queue_closed.load(Ordering::Relaxed),
            "phase 3 must close the relay queue even when a worker exceeds signer_drain"
        );
        assert!(
            abort_called.load(Ordering::Relaxed),
            "abort_signer must be called when the shared phase budget is exceeded"
        );
        assert!(
            relay_worker_aborted.load(Ordering::Relaxed),
            "relay worker handle must be aborted on timeout, not just dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_attempts_relay_close_on_timeout() {
        // flow-f2: when the drain times out because relay workers are stuck
        // BEFORE the in-drain client.shutdown() is reached, the relay client
        // must still receive a bounded close so it disconnects gracefully and
        // flushes any already-published responses.
        let shutdown_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let shutdown_calls_factory = shutdown_calls.clone();
        let client_shutdown = move || {
            let shutdown_calls_factory = shutdown_calls_factory.clone();
            async move {
                shutdown_calls_factory.fetch_add(1, Ordering::Relaxed);
            }
        };

        // Worker never finishes inside the budget, so the drain times out in
        // wait_for_join_handles before the in-drain client.shutdown() is reached.
        let relay_worker_handles = vec![tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        })];

        let abort_called = Arc::new(AtomicBool::new(false));
        let abort_called_cb = abort_called.clone();

        let outcome = drain_signer_or_abort(
            client_shutdown,
            || {},
            relay_worker_handles,
            async {},
            move || {
                abort_called_cb.store(true, Ordering::Relaxed);
            },
            Duration::from_secs(10),
        )
        .await;

        assert!(
            matches!(outcome, SignerDrainOutcome::AbortedAfterTimeout),
            "expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            abort_called.load(Ordering::Relaxed),
            "abort_signer must be called on the drain-timeout path"
        );
        assert!(
            shutdown_calls.load(Ordering::Relaxed) >= 1,
            "relay client.shutdown() must be attempted on the drain-timeout path (flow-f2), calls={}",
            shutdown_calls.load(Ordering::Relaxed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_aborts_when_client_shutdown_hangs() {
        // Regression target: the reviewer-flagged failure mode. The
        // client.shutdown() future hangs (stuck WebSocket close
        // handshake). The helper must bound the whole phase at
        // `signer_drain` and invoke the abort callback — previously
        // the unbounded client.shutdown().await would have blocked
        // phase 3 indefinitely.
        let abort_called = Arc::new(AtomicBool::new(false));
        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };

        let client_shutdown = || async {
            // Would hang for an hour if not bounded.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };
        let tracker_wait = async {
            // Never reached because client_shutdown is awaited first
            // and never completes inside the budget.
            tokio::time::sleep(Duration::from_secs(0)).await;
        };
        let relay_worker_handles = Vec::new();

        let outcome = drain_signer_or_abort(
            client_shutdown,
            || {},
            relay_worker_handles,
            tracker_wait,
            abort_signer,
            Duration::from_secs(10),
        )
        .await;

        assert!(
            matches!(outcome, SignerDrainOutcome::AbortedAfterTimeout),
            "expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            abort_called.load(Ordering::Relaxed),
            "abort_signer must be called when the signer_drain budget is exceeded by a hung client.shutdown()"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_aborts_when_tracker_wait_hangs() {
        // The other half of the failure space: client.shutdown()
        // completes cleanly but task_tracker.wait() hangs (a tracked
        // task stuck in a long-running operation). The whole phase
        // must still be bounded by `signer_drain` and the signer
        // handle aborted. This matches the pre-patch behavior for
        // this specific case but must be preserved under the new
        // outer-timeout structure.
        let abort_called = Arc::new(AtomicBool::new(false));
        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };

        let client_shutdown = || async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let tracker_wait = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };
        let relay_worker_handles = Vec::new();

        let outcome = drain_signer_or_abort(
            client_shutdown,
            || {},
            relay_worker_handles,
            tracker_wait,
            abort_signer,
            Duration::from_secs(10),
        )
        .await;

        assert!(
            matches!(outcome, SignerDrainOutcome::AbortedAfterTimeout),
            "expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            abort_called.load(Ordering::Relaxed),
            "abort_signer must be called when the signer_drain budget is exceeded by a hung tracker_wait"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_enforces_real_bound_past_budget() {
        // The safety property: the helper returns within `budget`
        // regardless of how long the inner futures would take.
        // This is what makes `validate_shutdown_timings`'s contract
        // honest — phase 3 cannot eat into phase 4 or the kubelet
        // SIGKILL window.
        let start = tokio::time::Instant::now();
        let budget = Duration::from_secs(10);

        let client_shutdown = || async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };
        let tracker_wait = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };
        let abort_signer = || {};
        let relay_worker_handles = Vec::new();

        let _outcome = drain_signer_or_abort(
            client_shutdown,
            || {},
            relay_worker_handles,
            tracker_wait,
            abort_signer,
            budget,
        )
        .await;
        let elapsed = start.elapsed();

        assert!(
            elapsed <= budget + Duration::from_millis(100),
            "drain_signer_or_abort must return within the signer_drain budget, not block on the inner futures; elapsed={:?}, budget={:?}",
            elapsed,
            budget
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_signer_or_abort_shares_budget_across_client_and_tracker() {
        // Subtle but critical: the phase budget is shared across the
        // two awaits, NOT applied independently to each. If each got
        // its own `budget`-sized timeout, phase 3 worst-case would be
        // `2 * signer_drain`, quietly busting the design contract in
        // validate_shutdown_timings. This test pins the shared-budget
        // semantic: client.shutdown() takes 80% of the budget, and
        // task_tracker.wait() would take another 80% — total 160% of
        // budget. The helper must time out at exactly `budget`.
        let start = tokio::time::Instant::now();
        let budget = Duration::from_secs(10);
        let abort_called = Arc::new(AtomicBool::new(false));
        let abort_called_cb = abort_called.clone();
        let abort_signer = move || {
            abort_called_cb.store(true, Ordering::Relaxed);
        };

        let client_shutdown = || async {
            tokio::time::sleep(Duration::from_secs(8)).await;
        };
        let tracker_wait = async {
            tokio::time::sleep(Duration::from_secs(8)).await;
        };
        let relay_worker_handles = Vec::new();

        let outcome = drain_signer_or_abort(
            client_shutdown,
            || {},
            relay_worker_handles,
            tracker_wait,
            abort_signer,
            budget,
        )
        .await;
        let elapsed = start.elapsed();

        assert!(
            matches!(outcome, SignerDrainOutcome::AbortedAfterTimeout),
            "8s + 8s > 10s budget; expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            elapsed <= budget + Duration::from_millis(100),
            "helper must return at the shared budget, not extend to 2x it; elapsed={:?}, budget={:?}",
            elapsed,
            budget
        );
        assert!(
            abort_called.load(Ordering::Relaxed),
            "abort_signer must be called when the shared phase budget is exceeded by the sum of the two awaits"
        );
    }
}
