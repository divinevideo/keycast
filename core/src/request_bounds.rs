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
