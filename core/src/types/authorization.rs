use crate::encryption::KeyManagerError;
use crate::types::permission::Permission;
use crate::types::policy::Policy;
use crate::types::stored_key::StoredKey;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use urlencoding;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),
    #[error("Invalid bunker secret key")]
    InvalidBunkerSecretKey,
    #[error("Authorization is expired")]
    Expired,
    #[error("Authorization is fully redeemed")]
    FullyRedeemed,
    #[error("Invalid secret")]
    InvalidSecret,
    #[error("Unauthorized by permission")]
    Unauthorized,
    #[error("Unsupported request")]
    UnsupportedRequest,
}

/// A list of relays, this is used to store the relays that signers will listen on for an authorization
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Relays(Vec<String>);

impl IntoIterator for Relays {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Relays {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl TryFrom<String> for Relays {
    type Error = serde_json::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Relays(serde_json::from_str(&s)?))
    }
}

/// An authorization is a set of permissions that belong to a team and can be used to control access to a team's stored keys
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Authorization {
    /// The id of the authorization
    pub id: i32,
    /// The id of the stored key the authorization belongs to
    pub stored_key_id: i32,
    /// The generated secret connection uuid
    pub secret: String,
    /// The public key of the bunker nostr secret key
    pub bunker_public_key: String,
    /// The encrypted bunker nostr secret key
    pub bunker_secret: Vec<u8>,
    #[sqlx(try_from = "String")]
    /// The list of relays the authorization will listen on
    pub relays: Relays,
    /// The id of the policy the authorization belongs to
    pub policy_id: i32,
    /// The maximum number of uses for this authorization, None means unlimited
    pub max_uses: Option<i16>,
    /// The date and time at which this authorization expires, None means it never expires
    pub expires_at: Option<DateTime<chrono::Utc>>,
    /// The date and time the authorization was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the authorization was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct AuthorizationWithRelations {
    #[sqlx(flatten)]
    pub authorization: Authorization,
    #[sqlx(flatten)]
    pub policy: Policy,
    pub users: Vec<UserAuthorization>,
    pub bunker_connection_string: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct UserAuthorization {
    pub user_public_key: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl Authorization {
    pub async fn find(pool: &PgPool, tenant_id: i64, id: i32) -> Result<Self, AuthorizationError> {
        let authorization = sqlx::query_as::<_, Authorization>(
            r#"
            SELECT * FROM authorizations WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(authorization)
    }

    pub async fn all_ids(pool: &PgPool, tenant_id: i64) -> Result<Vec<i32>, AuthorizationError> {
        let authorizations = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT id FROM authorizations WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }

    pub async fn all_ids_for_all_tenants(pool: &PgPool) -> Result<Vec<(i64, i32)>, AuthorizationError> {
        let authorizations = sqlx::query_as::<_, (i64, i32)>(
            r#"
            SELECT tenant_id, id FROM authorizations
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }

    /// Get the stored key for this authorization
    pub async fn stored_key(&self, pool: &PgPool, tenant_id: i64) -> Result<StoredKey, AuthorizationError> {
        let stored_key = sqlx::query_as::<_, StoredKey>(
            r#"
            SELECT * FROM stored_keys WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(self.stored_key_id)
        .fetch_one(pool)
        .await?;
        Ok(stored_key)
    }

    /// Get the permissions for this authorization (async version)
    pub async fn permissions(
        &self,
        pool: &PgPool,
        tenant_id: i64,
    ) -> Result<Vec<Permission>, AuthorizationError> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT p.*
            FROM permissions p
            JOIN policy_permissions pp ON pp.permission_id = p.id
            JOIN policies pol ON pol.id = pp.policy_id
            WHERE p.tenant_id = $1 AND pol.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(self.policy_id)
        .fetch_all(pool)
        .await?;

        Ok(permissions)
    }

    /// Generate a connection string for the authorization
    ///
    /// Format: `bunker://<remote-signer-pubkey>?relay=<encoded-relay-1,encoded-relay-2>&secret=<encoded-secret>`
    ///
    /// Uses the deployment-wide BUNKER_RELAYS configuration (not per-authorization relays).
    /// All bunker URLs reference the same relay infrastructure for security and scalability.
    pub async fn bunker_connection_string(&self) -> Result<String, AuthorizationError> {
        // Get deployment-wide relay list from environment
        let relays = Self::get_bunker_relays();

        let relay_params = relays
            .iter()
            .map(|r| format!("relay={}", urlencoding::encode(r)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!(
            "bunker://{}?{}&secret={}",
            self.bunker_public_key,
            relay_params,
            urlencoding::encode(&self.secret),
        ))
    }

    /// Get the configured bunker relay list from environment
    pub fn get_bunker_relays() -> Vec<String> {
        let relays_str = std::env::var("BUNKER_RELAYS")
            .unwrap_or_else(|_| "wss://relay.divine.video,wss://relay.primal.net,wss://relay.nsec.app,wss://nos.lol".to_string());

        relays_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

// TODO: Migrate tests from SQLite to PostgreSQL - tests temporarily disabled
#[cfg(all(test, feature = "sqlite-tests"))]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use nostr::nips::nip46::NostrConnectRequest;
    use nostr_sdk::{Keys, PublicKey};
    // Helper function to create a test database connection
    async fn setup_test_db() -> PgPool {
        PgPool::connect("sqlite::memory:").await.unwrap()
    }

    // Helper function to create a test authorization
    async fn create_test_authorization(
        pool: &PgPool,
        max_uses: Option<i16>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Authorization {
        // Create policies table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        // Insert test policy
        sqlx::query(
            r#"
            INSERT INTO policies (name, description, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind("test_policy")
        .bind("A test policy")
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(pool)
        .await
        .unwrap();

        // First create necessary tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS authorizations (
                id INTEGER PRIMARY KEY,
                stored_key_id INTEGER,
                secret TEXT,
                bunker_public_key TEXT,
                bunker_secret BLOB,
                relays TEXT,
                policy_id INTEGER,
                max_uses INTEGER,
                expires_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_authorizations (
                authorization_id INTEGER,
                user_public_key TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        // Insert test authorization
        let keys = Keys::generate();
        let auth = Authorization {
            id: 0,
            stored_key_id: 1,
            secret: "test_secret".to_string(),
            bunker_public_key: keys.public_key().to_hex(),
            bunker_secret: keys.secret_key().to_secret_bytes().to_vec(), // normally this would be encrypted
            relays: Relays(vec!["wss://test.relay".to_string()]),
            policy_id: 1,
            max_uses,
            expires_at,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        sqlx::query(
            r#"
            INSERT INTO authorizations 
            (stored_key_id, secret, bunker_public_key, bunker_secret, relays, policy_id, max_uses, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(auth.stored_key_id)
        .bind(&auth.secret)
        .bind(&auth.bunker_public_key)
        .bind(&auth.bunker_secret)
        .bind(serde_json::to_string(&auth.relays.0).unwrap())
        .bind(auth.policy_id)
        .bind(auth.max_uses)
        .bind(auth.expires_at)
        .bind(auth.created_at)
        .bind(auth.updated_at)
        .execute(pool)
        .await
        .unwrap();

        auth
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_expired() {
        let pool = setup_test_db().await;

        // Test non-expired authorization
        let future_date = Utc::now() + Duration::hours(24);
        let auth = create_test_authorization(&pool, None, Some(future_date)).await;
        assert!(!auth.expired().unwrap());

        // Test expired authorization
        let past_date = Utc::now() - Duration::hours(24);
        let auth = create_test_authorization(&pool, None, Some(past_date)).await;
        assert!(auth.expired().unwrap());

        // Test never-expiring authorization
        let auth = create_test_authorization(&pool, None, None).await;
        assert!(!auth.expired().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fully_redeemed() {
        let pool = setup_test_db().await;

        // Test authorization with no redemptions
        let auth = create_test_authorization(&pool, Some(2), None).await;
        assert!(!auth.fully_redeemed(&pool, 1).unwrap());

        // Add some redemptions
        sqlx::query(
            "INSERT INTO user_authorizations (authorization_id, user_public_key, created_at, updated_at) 
             VALUES (?, ?, ?, ?)"
        )
        .bind(auth.id)
        .bind("test_user")
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();

        // Test partially redeemed
        assert!(!auth.fully_redeemed(&pool, 1).unwrap());

        // Add another redemption to reach max
        sqlx::query(
            "INSERT INTO user_authorizations (authorization_id, user_public_key, created_at, updated_at) 
             VALUES (?, ?, ?, ?)"
        )
        .bind(auth.id)
        .bind("test_user2")
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();

        // Test fully redeemed
        assert!(auth.fully_redeemed(&pool, 1).unwrap());

        // Test unlimited uses
        let auth = create_test_authorization(&pool, None, None).await;
        assert!(!auth.fully_redeemed(&pool, 1).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_validate_policy() {
        let pool = setup_test_db().await;

        // Create test tables for permissions
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY,
                identifier TEXT,
                name TEXT,
                description TEXT
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policy_permissions (
                policy_id INTEGER,
                permission_id INTEGER
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create users table (required by validate_policy)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                public_key CHAR(64) PRIMARY KEY,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let auth = create_test_authorization(&pool, None, None).await;
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        // Test with a simple request
        let request = NostrConnectRequest::Connect {
            remote_signer_public_key: PublicKey::from_hex(&auth.bunker_public_key).unwrap(),
            secret: Some(auth.secret.clone()),
        };

        // This should return true as per current implementation
        assert!(auth.validate_policy(&pool, 1, &pubkey, &request).unwrap());
    }
}
