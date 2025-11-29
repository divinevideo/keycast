use std::env;
use std::time::Duration;

/// Test server configuration and utilities
#[derive(Clone)]
pub struct TestServer {
    pub base_url: String,
    pub database_url: String,
}

impl TestServer {
    pub fn from_env() -> Self {
        Self {
            base_url: env::var("TEST_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string()),
        }
    }

    pub fn api_url(&self, path: &str) -> String {
        format!("{}/api{}", self.base_url, path)
    }

    pub fn oauth_url(&self, path: &str) -> String {
        format!("{}/api/oauth{}", self.base_url, path)
    }

    /// Wait for the server to be healthy
    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<(), String> {
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            match client
                .get(&format!("{}/health", self.base_url))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }

        Err(format!(
            "Server at {} not ready after {:?}",
            self.base_url, timeout
        ))
    }

    /// Get a database connection pool for direct assertions
    pub async fn db_pool(&self) -> Result<sqlx::PgPool, sqlx::Error> {
        sqlx::PgPool::connect(&self.database_url).await
    }
}

impl Default for TestServer {
    fn default() -> Self {
        Self::from_env()
    }
}
