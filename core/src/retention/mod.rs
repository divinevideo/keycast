//! Retention primitives shared by repositories and service handlers.

mod digest;

pub use digest::{DigestPurpose, RetentionDigestKeyring, RetentionDigestKeyringError};
