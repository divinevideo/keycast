// ABOUTME: Wall-clock bounds shared between the HTTP RPC handler and the work it waits on
// ABOUTME: Lives in core so a retune has to face every budget nested inside it

use std::time::Duration;

/// Wall-clock bound for a single HTTP RPC request on `/api/nostr`.
///
/// This is the ceiling every other budget on that path has to fit inside: the
/// SQLx acquire timeout, the KMS retry loop on a cold handler load, and any
/// future per-dependency bound. It lives here rather than next to the handler
/// so `core` can assert those budgets against it — a bound the code below it
/// cannot see is a bound nothing can hold it to.
pub const HTTP_RPC_HANDLER_TIMEOUT: Duration = Duration::from_secs(8);

/// Maximum wait for an SQLx pool connection.
///
/// This must stay below [`HTTP_RPC_HANDLER_TIMEOUT`] so pool saturation can
/// surface as a retryable 503 before the HTTP RPC handler's 504 backstop fires.
///
/// 1.5s is sized for the warm mutating RPC, which is the path #291's evidence
/// is actually about: one acquire for the account-status check, no KMS, and the
/// rest of the 8s left for the work. It governs saturation and first-connection
/// establishment; a settled pool acquires in well under a millisecond.
///
/// Read this as a per-step bound and nothing more. Per-step timeouts do not
/// compose into a path bound, and the cold handler load is the case that shows
/// it: `load_handler_on_demand` runs up to three separate pool queries before it
/// reaches `decrypt` (`api/src/api/http/nostr_rpc.rs`, via
/// `OAuthAuthorizationRepository`, the conditional `PolicyRepository` and
/// `PersonalKeysRepository`, each executing against its own `PgPool` clone),
/// then the KMS retry loop reserves 6.3s (`KMS_TOTAL_BUDGET` in
/// `core/src/encryption/gcp_key_manager.rs`), then the account-status check
/// acquires once more. Stacked worst case is 4 x 1.5s + 6.3s, well past this
/// ceiling. Shrinking this constant until that arithmetic closes would put it
/// near 400ms, trading real warm-path headroom to bound a case the deadline
/// already covers, so the stack is left unclosed deliberately.
///
/// What the value is doing between those two extremes is keeping the cold path
/// *reachable*: at 3s the pre-KMS acquires alone can spend 9s and burn the whole
/// deadline before the request ever reaches KMS, while at 1.5s that worst case
/// is 4.5s and a request under contention can still get into the loop and
/// complete a normal KMS call. That is a claim about which value is less bad on
/// a path already known to be unbounded, not a claim that the stack fits.
///
/// So [`HTTP_RPC_HANDLER_TIMEOUT`] is the only real bound on the cold path, and
/// it does its job: the request is cancelled and answered as a 504 rather than
/// running unbounded. Closing the gap honestly means either fewer acquires
/// ahead of KMS or a deadline threaded through the path so each step waits only
/// the remaining budget. Issue #356 tracks the pool, acquire and operation
/// metrics that should size that work from production rather than from
/// worst-case arithmetic.
///
/// This is the process-wide pool bound, not an HTTP-RPC-only one: the signer,
/// OAuth, login and background work all draw from the same pool and all fail
/// fast at this value. It also bounds connection *establishment*, not just
/// queue wait -- sqlx uses it as the deadline covering TCP, TLS and auth
/// (`pool/inner.rs` and `pool/options.rs` in sqlx 0.8.6), so the startup
/// connect in `crate::database` gets it per attempt, behind that module's
/// five-attempt backoff loop. `min_connections` is left at zero there, so a
/// fresh instance also pays a handshake inside this budget as it grows the pool
/// for the first time.
pub const SQLX_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(1_500);

// `as_nanos` rather than `as_secs`: these budgets are tuned in milliseconds, and
// a whole-second comparison silently rounds a violation away. `Duration`'s
// `PartialOrd` is not const, so the comparison goes through the integer form.
const _: () = assert!(
    SQLX_ACQUIRE_TIMEOUT.as_nanos() < HTTP_RPC_HANDLER_TIMEOUT.as_nanos(),
    "SQLx acquire timeout must fit inside the HTTP RPC handler bound"
);
