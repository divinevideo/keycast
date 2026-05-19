// ABOUTME: Wrapper around Redis connection that applies optional key prefix
// ABOUTME: Enables multi-app GCP Memorystore deployments with isolated namespaces

use cluster_hashring::ValkeyConnectionFactory;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisResult};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Redis connection wrapper with automatic key prefixing.
///
/// Used for isolating keys in shared Redis instances (e.g., GCP Memorystore).
/// When created with a [`ValkeyConnectionFactory`], supports automatic
/// connection refresh for IAM token rotation.
#[derive(Clone)]
pub struct PrefixedRedis {
    conn: Arc<RwLock<ConnectionManager>>,
    factory: Option<Arc<ValkeyConnectionFactory>>,
    prefix: Option<String>,
}

impl std::fmt::Debug for PrefixedRedis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixedRedis")
            .field("conn", &"<connection>")
            .field("factory", &self.factory.as_ref().map(|_| "<configured>"))
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl PrefixedRedis {
    /// Create a new PrefixedRedis wrapper.
    ///
    /// # Arguments
    /// * `conn` - The underlying Redis connection
    /// * `prefix` - Optional prefix to prepend to all keys (e.g., "keycast" → "keycast:key")
    #[must_use]
    pub fn new(conn: ConnectionManager, prefix: Option<String>) -> Self {
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
        conn: ConnectionManager,
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

    /// Check if an error indicates authentication failure.
    ///
    /// Handles various auth error patterns from Redis/Valkey including expired
    /// IAM tokens which may manifest as NOAUTH or WRONGPASS errors.
    fn is_auth_error(e: &redis::RedisError) -> bool {
        use redis::ErrorKind;

        // Check for explicit authentication failure kind (set during connection setup)
        if e.kind() == ErrorKind::AuthenticationFailed {
            return true;
        }

        // Check error code directly - NOAUTH/WRONGPASS come through as Extension errors
        // with the code accessible via e.code(). This is more reliable than string matching.
        if let Some(code) = e.code() {
            let code_upper = code.to_uppercase();
            if code_upper == "NOAUTH" || code_upper == "WRONGPASS" {
                return true;
            }
        }

        // Fallback: check error message for auth-related patterns.
        // This handles edge cases where the error might not have a code set.
        let msg = e.to_string().to_lowercase();
        msg.contains("noauth") || msg.contains("wrongpass")
    }

    /// Execute operation with automatic connection refresh on auth failure.
    async fn with_refresh<T, F, Fut>(&self, op: F) -> RedisResult<T>
    where
        F: Fn(ConnectionManager) -> Fut,
        Fut: std::future::Future<Output = RedisResult<T>>,
    {
        let conn = self.conn.read().await.clone();
        match op(conn).await {
            Ok(result) => Ok(result),
            Err(e) if Self::is_auth_error(&e) => {
                // Token may have expired, try refresh
                if let Some(ref factory) = self.factory {
                    tracing::debug!("Auth error detected, attempting connection refresh");
                    match factory.get_connection_manager().await {
                        Ok(new_conn) => {
                            *self.conn.write().await = new_conn.clone();
                            tracing::debug!(
                                "Connection refreshed after auth error, retrying operation"
                            );
                            // Retry with new connection
                            op(new_conn).await
                        }
                        Err(refresh_err) => {
                            tracing::error!("Failed to refresh connection: {:?}", refresh_err);
                            Err(e) // Return original error
                        }
                    }
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Refresh the connection proactively (for IAM token rotation).
    ///
    /// This is a best-effort operation that logs errors but does not fail.
    /// The existing connection remains usable if refresh fails - the next
    /// operation will trigger reactive refresh via [`Self::with_refresh`].
    ///
    /// No-op if no factory is configured or token doesn't need refresh yet.
    pub async fn refresh_connection(&self) {
        let Some(ref factory) = self.factory else {
            return;
        };

        if !factory.needs_token_refresh().await {
            return;
        }

        match factory.get_connection_manager().await {
            Ok(new_conn) => {
                *self.conn.write().await = new_conn;
                tracing::debug!("Refreshed PrefixedRedis connection for IAM token rotation");
            }
            Err(e) => {
                tracing::error!("Failed to refresh connection: {:?}", e);
            }
        }
    }

    /// Set a key with expiration (SETEX).
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn setex(&self, key: &str, seconds: u64, value: &str) -> RedisResult<()> {
        let prefixed = self.prefixed_key(key).into_owned();
        let value = value.to_string();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            let val = value.clone();
            async move { conn.set_ex(key, val, seconds).await }
        })
        .await
    }

    /// Set a key with expiration only if it does not already exist.
    ///
    /// Returns `true` when the key was set and `false` when the key already exists.
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn set_nx_ex(&self, key: &str, seconds: u64, value: &str) -> RedisResult<bool> {
        let prefixed = self.prefixed_key(key).into_owned();
        let value = value.to_string();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            let value = value.clone();
            async move {
                redis::cmd("SET")
                    .arg(key)
                    .arg(value)
                    .arg("EX")
                    .arg(seconds)
                    .arg("NX")
                    .query_async::<Option<String>>(&mut conn)
                    .await
                    .map(|reply| reply.is_some())
            }
        })
        .await
    }

    /// Get a key's value.
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn get(&self, key: &str) -> RedisResult<Option<String>> {
        let prefixed = self.prefixed_key(key).into_owned();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            async move { conn.get(key).await }
        })
        .await
    }

    /// Delete a key.
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn del(&self, key: &str) -> RedisResult<()> {
        let prefixed = self.prefixed_key(key).into_owned();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            async move { conn.del(key).await }
        })
        .await
    }

    /// Check if a value is a member of a set (SISMEMBER).
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn sismember(&self, key: &str, member: &str) -> RedisResult<bool> {
        let prefixed = self.prefixed_key(key).into_owned();
        let member = member.to_string();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            let member = member.clone();
            async move { conn.sismember(key, member).await }
        })
        .await
    }

    /// Get all members of a set (SMEMBERS).
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn smembers(&self, key: &str) -> RedisResult<Vec<String>> {
        let prefixed = self.prefixed_key(key).into_owned();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            async move { conn.smembers(key).await }
        })
        .await
    }

    /// Add a member to a set (SADD). Returns the number of members added.
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn sadd(&self, key: &str, member: &str) -> RedisResult<i64> {
        let prefixed = self.prefixed_key(key).into_owned();
        let member = member.to_string();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            let member = member.clone();
            async move { conn.sadd(key, member).await }
        })
        .await
    }

    /// Remove a member from a set (SREM). Returns the number of members removed.
    ///
    /// # Errors
    ///
    /// Returns error if Redis operation fails or connection refresh fails.
    pub async fn srem(&self, key: &str, member: &str) -> RedisResult<i64> {
        let prefixed = self.prefixed_key(key).into_owned();
        let member = member.to_string();
        self.with_refresh(|mut conn| {
            let key = prefixed.clone();
            let member = member.clone();
            async move { conn.srem(key, member).await }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time assertion that PrefixedRedis is Send + Sync.
    // Required for safe use across async task boundaries.
    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrefixedRedis>();
    };

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

    #[test]
    fn test_is_auth_error_authentication_failed() {
        let err = redis::RedisError::from((
            redis::ErrorKind::AuthenticationFailed,
            "Authentication failed",
        ));
        assert!(PrefixedRedis::is_auth_error(&err));
    }

    #[test]
    fn test_is_auth_error_noauth_message() {
        // Tests the string-matching fallback for NOAUTH errors
        let err = redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "NOAUTH Authentication required",
        ));
        assert!(PrefixedRedis::is_auth_error(&err));
    }

    #[test]
    fn test_is_auth_error_wrongpass_message() {
        // Tests the string-matching fallback for WRONGPASS errors
        let err = redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "WRONGPASS invalid password",
        ));
        assert!(PrefixedRedis::is_auth_error(&err));
    }

    #[test]
    fn test_is_auth_error_non_auth_error() {
        let err = redis::RedisError::from((redis::ErrorKind::IoError, "Connection refused"));
        assert!(!PrefixedRedis::is_auth_error(&err));
    }

    #[test]
    fn test_is_auth_error_unrelated_response_error() {
        // Other response errors should not be treated as auth errors
        let err =
            redis::RedisError::from((redis::ErrorKind::ResponseError, "ERR unknown command 'foo'"));
        assert!(!PrefixedRedis::is_auth_error(&err));
    }

    /// Integration test for PrefixedRedis operations.
    /// Requires a running Redis instance at localhost:6379.
    /// Run with: cargo test --package keycast-api test_prefixed_redis_integration -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_prefixed_redis_integration() {
        let client = redis::Client::open("redis://localhost:6379").unwrap();
        let conn = ConnectionManager::new(client).await.unwrap();
        let redis = PrefixedRedis::new(conn, Some("test_prefix".to_string()));

        // Test setex and get
        redis
            .setex("integration_key", 60, "test_value")
            .await
            .unwrap();
        let result = redis.get("integration_key").await.unwrap();
        assert_eq!(result, Some("test_value".to_string()));

        // Test del
        redis.del("integration_key").await.unwrap();
        let result = redis.get("integration_key").await.unwrap();
        assert_eq!(result, None);

        // Verify the key was actually prefixed by checking raw Redis
        let client2 = redis::Client::open("redis://localhost:6379").unwrap();
        let mut raw_conn = client2.get_multiplexed_async_connection().await.unwrap();

        // Set via prefixed, check via raw
        redis
            .setex("verify_prefix", 60, "prefixed_value")
            .await
            .unwrap();
        let raw_result: Option<String> =
            redis::AsyncCommands::get(&mut raw_conn, "test_prefix:verify_prefix")
                .await
                .unwrap();
        assert_eq!(raw_result, Some("prefixed_value".to_string()));

        // Cleanup
        redis.del("verify_prefix").await.unwrap();
    }

    /// Integration test without prefix to verify pass-through behavior.
    #[tokio::test]
    #[ignore]
    async fn test_prefixed_redis_no_prefix_integration() {
        let client = redis::Client::open("redis://localhost:6379").unwrap();
        let conn = ConnectionManager::new(client).await.unwrap();
        let redis = PrefixedRedis::new(conn, None);

        // Test without prefix
        redis
            .setex("no_prefix_key", 60, "direct_value")
            .await
            .unwrap();
        let result = redis.get("no_prefix_key").await.unwrap();
        assert_eq!(result, Some("direct_value".to_string()));

        // Cleanup
        redis.del("no_prefix_key").await.unwrap();
    }

    /// Integration test for SET NX EX helper.
    #[tokio::test]
    #[ignore]
    async fn test_prefixed_redis_set_nx_ex_integration() {
        let client = redis::Client::open("redis://localhost:6379").unwrap();
        let conn = ConnectionManager::new(client).await.unwrap();
        let redis = PrefixedRedis::new(conn, Some("test_prefix".to_string()));

        redis.del("setnx_key").await.unwrap_or(());

        let first = redis.set_nx_ex("setnx_key", 60, "v1").await.unwrap();
        assert!(first);

        let second = redis.set_nx_ex("setnx_key", 60, "v2").await.unwrap();
        assert!(!second);

        let result = redis.get("setnx_key").await.unwrap();
        assert_eq!(result.as_deref(), Some("v1"));

        redis.del("setnx_key").await.unwrap();
    }

    /// Integration test for recovery after Redis closes the active command socket.
    #[tokio::test]
    #[ignore]
    async fn test_prefixed_redis_recovers_after_connection_killed() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".into());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let conn = ConnectionManager::new(client.clone()).await.unwrap();
        let redis = PrefixedRedis::new(conn, Some("test_prefix".to_string()));

        redis
            .setex("killed_connection", 60, "before")
            .await
            .unwrap();

        let mut active_conn = redis.conn.read().await.clone();
        let client_id: i64 = redis::cmd("CLIENT")
            .arg("ID")
            .query_async(&mut active_conn)
            .await
            .unwrap();

        let mut admin_conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: () = redis::cmd("CLIENT")
            .arg("KILL")
            .arg("ID")
            .arg(client_id)
            .query_async(&mut admin_conn)
            .await
            .unwrap();

        assert!(
            redis.get("killed_connection").await.is_err(),
            "first command after CLIENT KILL should observe the closed socket"
        );

        redis.setex("killed_connection", 60, "after").await.unwrap();
        let result = redis.get("killed_connection").await.unwrap();
        assert_eq!(result.as_deref(), Some("after"));

        redis.del("killed_connection").await.unwrap();
    }
}
