// ABOUTME: Repository error types that don't leak sqlx implementation details
// ABOUTME: Provides domain-level errors for data access operations

use thiserror::Error;

/// Repository-level errors for data access operations.
/// These errors abstract away the underlying database implementation.
#[derive(Error, Debug)]
pub enum RepositoryError {
    /// The requested record was not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// A record with the same unique constraint already exists
    #[error("Already exists")]
    Duplicate,

    /// A foreign key or other integrity constraint was violated
    #[error("Integrity violation: {0}")]
    Integrity(String),

    /// A database error occurred
    #[error("Database error: {0}")]
    Database(String),

    /// The database could not be reached in time -- typically a pool acquire
    /// timeout under connection saturation. Separated from [`Self::Database`]
    /// because it is transient: callers should surface it as retryable rather
    /// than as an internal failure.
    #[error("Database unavailable: {0}")]
    Unavailable(String),
}

impl From<sqlx::Error> for RepositoryError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => Self::NotFound("record not found".into()),
            sqlx::Error::Database(db_err) => {
                // PostgreSQL error codes
                match db_err.code().as_deref() {
                    // 55P03 = lock_not_available (including lock_timeout)
                    Some("55P03") => Self::Unavailable(db_err.message().to_string()),
                    // 23505 = unique_violation
                    Some("23505") => Self::Duplicate,
                    // 23503 = foreign_key_violation
                    Some("23503") => Self::Integrity(db_err.message().to_string()),
                    // 23514 = check_violation
                    Some("23514") => Self::Integrity(db_err.message().to_string()),
                    _ => Self::Database(db_err.message().to_string()),
                }
            }
            sqlx::Error::PoolTimedOut => Self::Unavailable("pool timed out".into()),
            sqlx::Error::PoolClosed => Self::Unavailable("pool closed".into()),
            other => Self::Database(other.to_string()),
        }
    }
}
