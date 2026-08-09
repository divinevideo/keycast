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
pub const SQLX_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

const _: () = assert!(
    SQLX_ACQUIRE_TIMEOUT.as_secs() < HTTP_RPC_HANDLER_TIMEOUT.as_secs(),
    "SQLx acquire timeout must fit inside the HTTP RPC handler bound"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlx_acquire_timeout_fits_inside_http_rpc_request_bound() {
        assert!(
            SQLX_ACQUIRE_TIMEOUT < HTTP_RPC_HANDLER_TIMEOUT,
            "{SQLX_ACQUIRE_TIMEOUT:?} SQLx acquire timeout must fit inside \
             {HTTP_RPC_HANDLER_TIMEOUT:?} HTTP RPC handler bound"
        );
    }
}
