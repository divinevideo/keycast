//! Valkey/Redis connection factory with optional GCP IAM authentication.
//!
//! This module provides authenticated connections to GCP Memorystore Valkey
//! when `AUTH_MODE_IAM` is enabled, while also supporting standard Redis
//! connections for local development.
//!
//! # Usage
//!
//! ```rust,ignore
//! use cluster_hashring::ValkeyConnectionFactory;
//!
//! // For local Redis (no IAM)
//! let factory = ValkeyConnectionFactory::new("redis://localhost:6379", false).await?;
//!
//! // For GCP Memorystore Valkey with IAM
//! let factory = ValkeyConnectionFactory::new("redis://10.0.0.5:6379", true).await?;
//!
//! // Get connections
//! let conn = factory.get_multiplexed_connection().await?;
//! let pubsub = factory.get_pubsub_connection().await?;
//! ```

use crate::Error;
use gcp_auth::TokenProvider;
use redis::aio::{MultiplexedConnection, PubSub};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Buffer time before token expiry to trigger refresh (5 minutes).
const TOKEN_REFRESH_BUFFER_SECS: u64 = 300;

/// Token with cached expiry time.
struct CachedToken {
    token: String,
    expires_at: Instant,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at - Duration::from_secs(TOKEN_REFRESH_BUFFER_SECS)
    }

    fn ttl_secs(&self) -> u64 {
        self.expires_at
            .saturating_duration_since(Instant::now())
            .as_secs()
    }
}

/// Provides GCP access tokens for Valkey IAM authentication.
/// Uses Application Default Credentials (ADC) via Workload Identity.
struct GcpTokenProvider {
    provider: Arc<dyn TokenProvider>,
    cached_token: RwLock<Option<CachedToken>>,
}

impl GcpTokenProvider {
    /// Create a new token provider using ADC.
    async fn new() -> Result<Self, Error> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| Error::Auth(format!("Failed to initialize GCP auth: {}", e)))?;

        Ok(Self {
            provider,
            cached_token: RwLock::new(None),
        })
    }

    /// Get a valid access token, refreshing if necessary.
    async fn get_token(&self) -> Result<String, Error> {
        // Check cache first (read lock)
        {
            let cache = self.cached_token.read().await;
            if let Some(ref token) = *cache {
                if !token.is_expired() {
                    return Ok(token.token.clone());
                }
            }
        }

        // Need to refresh (write lock)
        let mut cache = self.cached_token.write().await;

        // Double-check after acquiring write lock
        if let Some(ref token) = *cache {
            if !token.is_expired() {
                return Ok(token.token.clone());
            }
        }

        // Fetch new token
        let token = self
            .provider
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|e| Error::Auth(format!("Failed to get GCP token: {}", e)))?;

        // Convert chrono DateTime to Instant
        let expires_at_chrono = token.expires_at();
        let now_chrono = chrono::Utc::now();
        let duration_until_expiry = (expires_at_chrono - now_chrono)
            .to_std()
            .unwrap_or(Duration::from_secs(3600));
        let expires_at = Instant::now() + duration_until_expiry;

        let access_token = token.as_str().to_string();
        let ttl = expires_at.saturating_duration_since(Instant::now()).as_secs();
        tracing::debug!(ttl_secs = ttl, "Refreshed GCP access token");

        *cache = Some(CachedToken {
            token: access_token.clone(),
            expires_at,
        });

        Ok(access_token)
    }

    /// Get the TTL of the current cached token in seconds.
    /// Returns 0 if no token is cached or it's expired.
    async fn token_ttl_secs(&self) -> u64 {
        let cache = self.cached_token.read().await;
        cache.as_ref().map(|t| t.ttl_secs()).unwrap_or(0)
    }
}

/// Factory for creating authenticated Redis/Valkey connections.
///
/// When IAM authentication is enabled, this factory:
/// - Fetches GCP access tokens via Application Default Credentials
/// - Caches tokens and refreshes them 5 minutes before expiry
/// - Injects tokens as passwords in Redis connection URLs
///
/// When IAM is disabled, it creates standard Redis connections.
#[derive(Clone)]
pub struct ValkeyConnectionFactory {
    redis_url: String,
    use_iam_auth: bool,
    token_provider: Option<Arc<GcpTokenProvider>>,
}

impl ValkeyConnectionFactory {
    /// Create a new connection factory.
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection URL (e.g., "redis://host:port")
    /// * `use_iam_auth` - Enable GCP IAM authentication for Memorystore Valkey
    ///
    /// # Errors
    ///
    /// Returns an error if IAM auth is enabled but GCP credentials are unavailable.
    pub async fn new(redis_url: &str, use_iam_auth: bool) -> Result<Self, Error> {
        let token_provider = if use_iam_auth {
            let provider = GcpTokenProvider::new().await?;
            tracing::info!("ValkeyConnectionFactory: IAM authentication enabled");
            Some(Arc::new(provider))
        } else {
            tracing::debug!("ValkeyConnectionFactory: Using standard Redis authentication");
            None
        };

        Ok(Self {
            redis_url: redis_url.to_string(),
            use_iam_auth,
            token_provider,
        })
    }

    /// Check if IAM authentication is enabled.
    #[must_use]
    pub fn uses_iam_auth(&self) -> bool {
        self.use_iam_auth
    }

    /// Get the TTL of the current cached token in seconds.
    /// Returns 0 if IAM is disabled or no token is cached.
    pub async fn token_ttl_secs(&self) -> u64 {
        if let Some(ref provider) = self.token_provider {
            provider.token_ttl_secs().await
        } else {
            0
        }
    }

    /// Check if token refresh is needed (TTL < 5 minutes).
    pub async fn needs_token_refresh(&self) -> bool {
        if !self.use_iam_auth {
            return false;
        }
        self.token_ttl_secs().await < TOKEN_REFRESH_BUFFER_SECS
    }

    /// Create a Redis client with authentication if needed.
    async fn create_client(&self) -> Result<redis::Client, Error> {
        let url = if self.use_iam_auth {
            let token = self
                .token_provider
                .as_ref()
                .expect("token_provider should be set when use_iam_auth is true")
                .get_token()
                .await?;

            // Parse and reconstruct URL with token as password
            // Format: redis://default:TOKEN@host:port
            let parsed = url::Url::parse(&self.redis_url)
                .map_err(|e| Error::Config(format!("Invalid Redis URL: {}", e)))?;

            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(6379);

            format!("redis://default:{}@{}:{}", token, host, port)
        } else {
            self.redis_url.clone()
        };

        redis::Client::open(url).map_err(Error::Redis)
    }

    /// Get a multiplexed connection for general Redis operations.
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails or token refresh fails.
    pub async fn get_multiplexed_connection(&self) -> Result<MultiplexedConnection, Error> {
        let client = self.create_client().await?;
        client
            .get_multiplexed_async_connection()
            .await
            .map_err(Error::Redis)
    }

    /// Get a Pub/Sub connection.
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails or token refresh fails.
    pub async fn get_pubsub_connection(&self) -> Result<PubSub, Error> {
        let client = self.create_client().await?;
        client.get_async_pubsub().await.map_err(Error::Redis)
    }

    /// Force a token refresh (useful before long-running operations).
    /// No-op if IAM is disabled.
    pub async fn refresh_token(&self) -> Result<(), Error> {
        if let Some(ref provider) = self.token_provider {
            provider.get_token().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_factory_without_iam() {
        let factory = ValkeyConnectionFactory::new("redis://localhost:6379", false)
            .await
            .unwrap();

        assert!(!factory.uses_iam_auth());
        assert_eq!(factory.token_ttl_secs().await, 0);
        assert!(!factory.needs_token_refresh().await);
    }

    // Note: IAM tests require GCP credentials and are skipped in CI
    // Manual testing:
    // 1. Deploy to GCP with Workload Identity
    // 2. Set USE_VALKEY_IAM=true
    // 3. Verify connections work and tokens refresh automatically
}
