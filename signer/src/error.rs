// ABOUTME: Typed error handling for the signer daemon
// ABOUTME: Replaces Box<dyn Error> with structured error types for better debugging and handling

use keycast_core::types::authorization::AuthorizationError;
use nostr_sdk::prelude::*;
use thiserror::Error;

/// Errors that can occur during signer operations
#[derive(Debug, Error)]
pub enum SignerError {
    /// Database operation failed
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Authorization lookup or validation failed
    #[error("Authorization error: {0}")]
    Authorization(#[from] AuthorizationError),

    /// Key decryption or encryption failed
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Invalid cryptographic key format
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Permission check failed - request not allowed by policy
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Failed to convert permission configuration
    #[error("Invalid permission config: {0}")]
    InvalidPermission(String),

    /// NIP-04 encryption/decryption failed
    #[error("NIP-04 error: {0}")]
    Nip04(#[from] nip04::Error),

    /// NIP-44 encryption/decryption failed
    #[error("NIP-44 error: {0}")]
    Nip44(#[from] nip44::Error),

    /// Event signing failed
    #[error("Signing error: {0}")]
    Signing(#[from] nostr_sdk::signer::SignerError),

    /// Event building failed
    #[error("Event builder error: {0}")]
    EventBuilder(#[from] nostr_sdk::event::builder::Error),

    /// Client operation failed
    #[error("Client error: {0}")]
    Client(#[from] nostr_sdk::client::Error),

    /// JSON parsing failed
    #[error("JSON error: {0}")]
    Json(#[from] nostr_sdk::serde_json::Error),

    /// Tag parsing failed
    #[error("Tag parse error: {0}")]
    TagParse(#[from] nostr_sdk::event::tag::Error),

    /// Missing required request parameter
    #[error("Missing parameter: {0}")]
    MissingParameter(&'static str),

    /// Invalid request format or data
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Data integrity issue (e.g., derived key mismatch)
    #[error("Data corruption: {0}")]
    DataCorruption(String),

    /// Relay connection or communication failed
    #[error("Relay error: {0}")]
    Relay(String),

    /// Internal logic error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl SignerError {
    /// Create an encryption error
    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }

    /// Create an invalid key error
    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    /// Create a permission denied error
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    /// Create an invalid permission error
    pub fn invalid_permission(msg: impl Into<String>) -> Self {
        Self::InvalidPermission(msg.into())
    }

    /// Create an invalid request error
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::InvalidRequest(msg.into())
    }

    /// Create a data corruption error
    pub fn data_corruption(msg: impl Into<String>) -> Self {
        Self::DataCorruption(msg.into())
    }

    /// Create a relay error
    pub fn relay(msg: impl Into<String>) -> Self {
        Self::Relay(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Result type for signer operations
pub type SignerResult<T> = Result<T, SignerError>;
