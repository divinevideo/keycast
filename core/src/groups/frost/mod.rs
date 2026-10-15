//! Optional FROST coordination. No server-held share or implicit service vote.
pub mod client;
mod protocol;
mod service;
pub use protocol::*;
pub use service::{FrostCoordinator, Session};

#[derive(Debug, thiserror::Error)]
pub enum FrostError {
    #[error("FROST protocol rejected: {0}")]
    Invalid(&'static str),
    #[error("FROST state conflict: {0}")]
    Conflict(&'static str),
    #[error("FROST coordinator busy; retry")]
    Busy,
    #[error("FROST operation forbidden")]
    Forbidden,
    #[error("FROST session not found")]
    NotFound,
    #[error("FROST session aborted; start again with fresh randomness")]
    Aborted,
    #[error("FROST database error")]
    Database(#[from] sqlx::Error),
    #[error("FROST serialization error")]
    Json(#[from] serde_json::Error),
}

pub(crate) fn crypto<T>(r: Result<T, frost_secp256k1_tr::Error>) -> Result<T, FrostError> {
    r.map_err(|_| FrostError::Invalid("invalid cryptographic package"))
}
