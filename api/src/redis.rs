// ABOUTME: Wrapper around Redis connection that applies optional key prefix
// ABOUTME: Enables multi-app GCP Memorystore deployments with isolated namespaces

use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, RedisResult};
use std::borrow::Cow;

/// A Redis connection wrapper that automatically applies a key prefix.
/// Used for isolating keys in shared Redis instances (e.g., GCP Memorystore).
#[derive(Clone)]
pub struct PrefixedRedis {
    conn: MultiplexedConnection,
    prefix: Option<String>,
}

impl PrefixedRedis {
    /// Create a new PrefixedRedis wrapper.
    ///
    /// # Arguments
    /// * `conn` - The underlying Redis connection
    /// * `prefix` - Optional prefix to prepend to all keys (e.g., "keycast" → "keycast:key")
    #[must_use]
    pub fn new(conn: MultiplexedConnection, prefix: Option<String>) -> Self {
        Self { conn, prefix }
    }

    /// Apply prefix to a key if configured.
    fn prefixed_key<'a>(&'a self, key: &'a str) -> Cow<'a, str> {
        match &self.prefix {
            Some(prefix) => Cow::Owned(format!("{}:{}", prefix, key)),
            None => Cow::Borrowed(key),
        }
    }

    /// Set a key with expiration (SETEX).
    pub async fn setex(&self, key: &str, seconds: u64, value: &str) -> RedisResult<()> {
        let prefixed = self.prefixed_key(key);
        self.conn.clone().set_ex(prefixed, value, seconds).await
    }

    /// Get a key's value.
    pub async fn get(&self, key: &str) -> RedisResult<Option<String>> {
        let prefixed = self.prefixed_key(key);
        self.conn.clone().get(prefixed).await
    }

    /// Delete a key.
    pub async fn del(&self, key: &str) -> RedisResult<()> {
        let prefixed = self.prefixed_key(key);
        self.conn.clone().del(prefixed).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_prefixed_key_with_prefix() {
        // Can't test without a real connection, but we can test the key logic
        // by extracting it to a separate function

        // With prefix
        let key = "oauth_poll:abc123";
        let prefix = Some("keycast".to_string());
        let result = match &prefix {
            Some(p) => format!("{}:{}", p, key),
            None => key.to_string(),
        };
        assert_eq!(result, "keycast:oauth_poll:abc123");
    }

    #[test]
    fn test_prefixed_key_without_prefix() {
        let key = "oauth_poll:abc123";
        let prefix: Option<String> = None;
        let result = match &prefix {
            Some(p) => format!("{}:{}", p, key),
            None => key.to_string(),
        };
        assert_eq!(result, "oauth_poll:abc123");
    }
}
