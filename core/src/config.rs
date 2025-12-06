use std::env;
use std::fmt;

/// Connection pool mode for the application.
///
/// Controls how database connections are routed:
/// - `Direct`: All connections go directly to PostgreSQL (port 5432)
/// - `Hybrid`: Coordination uses direct connections, queries use PgBouncer/MCP
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PoolMode {
    /// Full cluster coordination via pg-hashring.
    /// Direct PostgreSQL connections for both coordination AND queries.
    /// PgBouncer/MCP is completely unused in this mode.
    #[default]
    Direct,

    /// Hybrid mode: ClusterCoordinator on direct connection,
    /// queries through MCP/PgBouncer.
    ///
    /// Requires both DATABASE_URL (direct) and DATABASE_URL_POOLED (MCP).
    /// Use this mode with Cloud SQL Managed Connection Pooling.
    Hybrid,
}

impl PoolMode {
    /// Parse pool mode from POOL_MODE environment variable.
    ///
    /// Returns `Direct` by default (current behavior).
    pub fn from_env() -> Self {
        match env::var("POOL_MODE").as_deref() {
            Ok("hybrid") => Self::Hybrid,
            _ => Self::Direct,
        }
    }

    /// Returns true if this mode requires DATABASE_URL_POOLED.
    pub fn requires_pooled_url(&self) -> bool {
        matches!(self, Self::Hybrid)
    }

    /// Returns the name used for metrics labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Hybrid => "hybrid",
        }
    }
}

impl fmt::Display for PoolMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_mode_default() {
        assert_eq!(PoolMode::default(), PoolMode::Direct);
    }

    #[test]
    fn test_pool_mode_display() {
        assert_eq!(PoolMode::Direct.to_string(), "direct");
        assert_eq!(PoolMode::Hybrid.to_string(), "hybrid");
    }

    #[test]
    fn test_requires_pooled_url() {
        assert!(!PoolMode::Direct.requires_pooled_url());
        assert!(PoolMode::Hybrid.requires_pooled_url());
    }
}
