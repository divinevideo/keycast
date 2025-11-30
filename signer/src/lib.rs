// ABOUTME: Library interface for the Keycast signer daemon
// ABOUTME: Exports signer_daemon module for use by binaries and tests

pub mod error;
pub mod signer_daemon;

// Re-export main types for convenience
pub use error::{SignerError, SignerResult};
pub use signer_daemon::{AuthorizationHandler, UnifiedSigner};
