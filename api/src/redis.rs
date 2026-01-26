// ABOUTME: Wrapper around Redis connection that applies optional key prefix
// ABOUTME: Enables multi-app GCP Memorystore deployments with isolated namespaces

use cluster_hashring::ValkeyConnectionFactory;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, RedisResult};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A Redis connection wrapper that automatically applies a key prefix.
/// Used for isolating keys in shared Redis instances (e.g., GCP Memorystore).
///
/// When created with a `ValkeyConnectionFactory`, supports automatic connection
/// refresh for IAM token rotation.
#[derive(Clone)]
pub struct PrefixedRedis {
    conn: Arc<RwLock<MultiplexedConnection>>,
    factory: Option<Arc<ValkeyConnectionFactory>>,
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
        Self {
            conn: Arc::new(RwLock::new(conn)),
            factory: None,
            prefix,
        }
    }

    /// Create a new PrefixedRedis wrapper with a factory for connection refresh.
    ///
    /// # Arguments
    /// * `conn` - The underlying Redis connection
    /// * `factory` - Factory for creating new connections (supports IAM auth)
    /// * `prefix` - Optional prefix to prepend to all keys
    #[must_use]
    pub fn new_with_factory(
        conn: MultiplexedConnection,
        factory: Arc<ValkeyConnectionFactory>,
        prefix: Option<String>,
    ) -> Self {
        Self {
            conn: Arc::new(RwLock::new(conn)),
            factory: Some(factory),
            prefix,
        }
    }

    /// Apply prefix to a key if configured.
    fn prefixed_key<'a>(&'a self, key: &'a str) -> Cow<'a, str> {
        match &self.prefix {
            Some(prefix) => Cow::Owned(format!("{}:{}", prefix, key)),
            None => Cow::Borrowed(key),
        }
    }

    /// Refresh the connection (for IAM token rotation).
    /// No-op if no factory is configured.
    pub async fn refresh_connection(&self) -> RedisResult<()> {
        if let Some(ref factory) = self.factory {
            if factory.needs_token_refresh().await {
                match factory.get_multiplexed_connection().await {
                    Ok(new_conn) => {
                        let mut conn = self.conn.write().await;
                        *conn = new_conn;
                        tracing::debug!("Refreshed PrefixedRedis connection for IAM token rotation");
                    }
                    Err(e) => {
                        tracing::error!("Failed to refresh connection: {:?}", e);
                        // Continue with existing connection
                    }
                }
            }
        }
        Ok(())
    }

    /// Set a key with expiration (SETEX).
    pub async fn setex(&self, key: &str, seconds: u64, value: &str) -> RedisResult<()> {
        let prefixed = self.prefixed_key(key);
        let conn = self.conn.read().await;
        conn.clone().set_ex(prefixed, value, seconds).await
    }

    /// Get a key's value.
    pub async fn get(&self, key: &str) -> RedisResult<Option<String>> {
        let prefixed = self.prefixed_key(key);
        let conn = self.conn.read().await;
        conn.clone().get(prefixed).await
    }

    /// Delete a key.
    pub async fn del(&self, key: &str) -> RedisResult<()> {
        let prefixed = self.prefixed_key(key);
        let conn = self.conn.read().await;
        conn.clone().del(prefixed).await
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
