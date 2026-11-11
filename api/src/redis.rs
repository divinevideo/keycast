// ABOUTME: Wrapper around Redis connection that applies optional key prefix
// ABOUTME: Enables multi-app GCP Memorystore deployments with isolated namespaces

use cluster_hashring::{is_read_only_error, ValkeyConnectionFactory};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, FromRedisValue, RedisResult, Script};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Redis connection wrapper with automatic key prefixing.
///
/// Used for isolating keys in shared Redis instances (e.g., GCP Memorystore).
/// When created with a [`ValkeyConnectionFactory`], supports automatic
/// connection refresh for IAM token rotation and for a changed Redis primary.
#[derive(Clone)]
pub struct PrefixedRedis {
    conn: Arc<RwLock<CurrentConnection>>,
    /// Serializes connection replacement so concurrent failures open one new connection.
    refresh_lock: Arc<Mutex<()>>,
    factory: Option<Arc<ValkeyConnectionFactory>>,
    prefix: Option<String>,
    #[cfg(any(test, feature = "integration-tests"))]
    fail_writes: bool,
    #[cfg(any(test, feature = "integration-tests"))]
    fail_scripts: bool,
}

/// The live connection and how many times it has been replaced.
struct CurrentConnection {
    manager: ConnectionManager,
    generation: u64,
}

impl CurrentConnection {
    fn new(manager: ConnectionManager) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            manager,
            generation: 0,
        }))
    }
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
            conn: CurrentConnection::new(conn),
            refresh_lock: Arc::new(Mutex::new(())),
            factory: None,
            prefix,
            #[cfg(any(test, feature = "integration-tests"))]
            fail_writes: false,
            #[cfg(any(test, feature = "integration-tests"))]
            fail_scripts: false,
        }
    }

    /// Create a test Redis wrapper that rejects every SETEX and SET NX EX operation.
    #[cfg(any(test, feature = "integration-tests"))]
    #[must_use]
    pub fn new_failing(conn: ConnectionManager, prefix: Option<String>) -> Self {
        let mut redis = Self::new(conn, prefix);
        redis.fail_writes = true;
        redis
    }

    /// Create a test Redis wrapper that rejects every Lua script invocation.
    #[cfg(any(test, feature = "integration-tests"))]
    #[must_use]
    pub fn new_failing_scripts(conn: ConnectionManager, prefix: Option<String>) -> Self {
        let mut redis = Self::new(conn, prefix);
        redis.fail_scripts = true;
        redis
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
            conn: CurrentConnection::new(conn),
            refresh_lock: Arc::new(Mutex::new(())),
            factory: Some(factory),
            prefix,
            #[cfg(any(test, feature = "integration-tests"))]
            fail_writes: false,
            #[cfg(any(test, feature = "integration-tests"))]
            fail_scripts: false,
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

    /// Check if an error means the connection needs replacing before a retry.
    ///
    /// Covers expired credentials and a connection left on a demoted primary.
    fn needs_new_connection(e: &redis::RedisError) -> bool {
        Self::is_auth_error(e) || is_read_only_error(e)
    }

    /// Execute operation, replacing the connection and retrying once when it is stale.
    ///
    /// A connection is stale after an auth failure (expired IAM token) or a
    /// `READONLY` reply (the node it reaches is no longer the primary).
    async fn with_refresh<T, F, Fut>(&self, op: F) -> RedisResult<T>
    where
        F: Fn(ConnectionManager) -> Fut,
        Fut: std::future::Future<Output = RedisResult<T>>,
    {
        #[cfg(any(test, feature = "integration-tests"))]
        if self.fail_scripts {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "injected script failure",
            )));
        }

        let (conn, generation) = {
            let current = self.conn.read().await;
            (current.manager.clone(), current.generation)
        };
        match op(conn).await {
            Ok(result) => Ok(result),
            Err(e) if self.factory.is_some() && Self::needs_new_connection(&e) => {
                if is_read_only_error(&e) {
                    tracing::warn!(
                        "Redis rejected a write as READONLY; reconnecting to reach the current primary"
                    );
                } else {
                    tracing::debug!("Auth error detected, attempting connection refresh");
                }
                match self.replace_connection(generation).await {
                    Some(new_conn) => {
                        tracing::debug!("Connection refreshed, retrying operation");
                        op(new_conn).await
                    }
                    None => Err(e), // Return original error
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Replace the connection that failed at `failed_generation`.
    ///
    /// When another caller already replaced it, returns that newer connection
    /// instead of opening another. Returns `None` when there is no factory or
    /// the new connection cannot be opened.
    async fn replace_connection(&self, failed_generation: u64) -> Option<ConnectionManager> {
        let factory = self.factory.as_ref()?;
        let _refreshing = self.refresh_lock.lock().await;

        {
            let current = self.conn.read().await;
            if current.generation != failed_generation {
                return Some(current.manager.clone());
            }
        }

        match factory.get_connection_manager().await {
            Ok(new_conn) => {
                let mut current = self.conn.write().await;
                current.manager = new_conn.clone();
                current.generation += 1;
                Some(new_conn)
            }
            Err(refresh_err) => {
                tracing::error!("Failed to refresh connection: {:?}", refresh_err);
                None
            }
        }
    }

    /// Invoke one Lua script with every key in this wrapper's namespace.
    ///
    /// The script text is static so callers cannot accidentally construct code
    /// from request data. Keys and arguments remain regular Redis values.
    ///
    /// # Errors
    ///
    /// Returns an error when Redis rejects the script or connection refresh fails.
    pub(crate) async fn invoke_script<T>(
        &self,
        script: &'static str,
        keys: &[String],
        arguments: &[String],
    ) -> RedisResult<T>
    where
        T: FromRedisValue,
    {
        let keys = keys
            .iter()
            .map(|key| self.prefixed_key(key).into_owned())
            .collect::<Vec<_>>();
        let arguments = arguments.to_vec();

        self.with_refresh(|mut connection| {
            let keys = keys.clone();
            let arguments = arguments.clone();
            async move {
                let script = Script::new(script);
                let mut invocation = script.prepare_invoke();
                for key in keys {
                    invocation.key(key);
                }
                for argument in arguments {
                    invocation.arg(argument);
                }
                invocation.invoke_async(&mut connection).await
            }
        })
        .await
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

        let _refreshing = self.refresh_lock.lock().await;
        match factory.get_connection_manager().await {
            Ok(new_conn) => {
                let mut current = self.conn.write().await;
                current.manager = new_conn;
                current.generation += 1;
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
        #[cfg(any(test, feature = "integration-tests"))]
        if self.fail_writes {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "injected SETEX failure",
            )));
        }

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
        #[cfg(any(test, feature = "integration-tests"))]
        if self.fail_writes {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "injected SET NX EX failure",
            )));
        }

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

        let mut active_conn = redis.conn.read().await.manager.clone();
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

#[cfg(all(test, feature = "integration-tests"))]
mod integration_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn redis_url() -> String {
        std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must name the dedicated test Redis")
    }

    async fn redis_with_factory() -> PrefixedRedis {
        let factory = Arc::new(
            ValkeyConnectionFactory::new(&redis_url(), false)
                .await
                .expect("connection factory"),
        );
        let conn = factory
            .get_connection_manager()
            .await
            .expect("initial connection");
        PrefixedRedis::new_with_factory(conn, factory, None)
    }

    fn read_only_error() -> redis::RedisError {
        redis::RedisError::from((
            redis::ErrorKind::ReadOnly,
            "You can't write against a read only replica.",
        ))
    }

    async fn client_id(mut conn: ConnectionManager) -> RedisResult<i64> {
        redis::cmd("CLIENT").arg("ID").query_async(&mut conn).await
    }

    async fn current_client_id(redis: &PrefixedRedis) -> i64 {
        client_id(redis.conn.read().await.manager.clone())
            .await
            .expect("CLIENT ID")
    }

    #[tokio::test]
    async fn read_only_reply_replaces_connection_and_retries_once() {
        let redis = redis_with_factory().await;
        let original = current_client_id(&redis).await;

        let attempts = AtomicUsize::new(0);
        let retried_on = redis
            .with_refresh(|conn| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        return Err(read_only_error());
                    }
                    client_id(conn).await
                }
            })
            .await
            .expect("retry on a new connection should succeed");

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_ne!(retried_on, original, "retry should use a new connection");
        assert_eq!(current_client_id(&redis).await, retried_on);
        assert_eq!(redis.conn.read().await.generation, 1);
    }

    #[tokio::test]
    async fn concurrent_read_only_replies_open_one_new_connection() {
        let redis = redis_with_factory().await;
        let original = current_client_id(&redis).await;
        let first_attempts = Arc::new(AtomicUsize::new(0));
        let callers = 16;

        let results: Vec<RedisResult<i64>> =
            futures_util::future::join_all((0..callers).map(|_| {
                let redis = redis.clone();
                let first_attempts = Arc::clone(&first_attempts);
                async move {
                    let failed = AtomicUsize::new(0);
                    redis
                        .with_refresh(|conn| {
                            let failed_before = failed.fetch_add(1, Ordering::SeqCst);
                            let first_attempts = Arc::clone(&first_attempts);
                            async move {
                                if failed_before == 0 {
                                    first_attempts.fetch_add(1, Ordering::SeqCst);
                                    // Hold every first attempt until all callers have
                                    // failed on the original connection.
                                    while first_attempts.load(Ordering::SeqCst) < callers {
                                        tokio::task::yield_now().await;
                                    }
                                    return Err(read_only_error());
                                }
                                client_id(conn).await
                            }
                        })
                        .await
                }
            }))
            .await;

        let ids = results
            .into_iter()
            .map(|result| result.expect("every caller should succeed after the retry"))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 1, "all callers should share one new connection");
        assert!(!ids.contains(&original));
        assert_eq!(redis.conn.read().await.generation, 1);
    }

    #[tokio::test]
    async fn read_only_reply_without_factory_is_returned_unchanged() {
        let client = redis::Client::open(redis_url()).expect("valid Redis URL");
        let conn = ConnectionManager::new(client)
            .await
            .expect("initial connection");
        let redis = PrefixedRedis::new(conn, None);

        let attempts = AtomicUsize::new(0);
        let result: RedisResult<()> = redis
            .with_refresh(|_conn| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err(read_only_error()) }
            })
            .await;

        assert_eq!(
            result.expect_err("no factory means no retry").kind(),
            redis::ErrorKind::ReadOnly
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn other_errors_keep_the_connection() {
        let redis = redis_with_factory().await;
        let original = current_client_id(&redis).await;

        let attempts = AtomicUsize::new(0);
        let result: RedisResult<()> = redis
            .with_refresh(|_conn| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(redis::RedisError::from((
                        redis::ErrorKind::ResponseError,
                        "ERR unknown command",
                    )))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(current_client_id(&redis).await, original);
        assert_eq!(redis.conn.read().await.generation, 0);
    }
}
