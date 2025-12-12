// ABOUTME: Library interface for the Keycast signer daemon
// ABOUTME: Exports signer_daemon module for use by binaries and tests

pub mod error;
pub mod signer_daemon;
pub mod work_queue;

// Re-export main types for convenience
pub use error::{SignerError, SignerResult};
pub use signer_daemon::{Nip46Handler, UnifiedSigner};
pub use work_queue::{Nip46RpcItem, RelayQueue, RelaySender};
