// ABOUTME: OAuth authorization type for handling OAuth-based remote signing
// ABOUTME: Unlike regular authorizations, OAuth uses the user's personal key for both NIP-46 encryption and event signing

use crate::types::authorization::{AuthorizationError, Relays};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

/// An OAuth authorization where the user's personal key serves as both bunker key and signing key
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct OAuthAuthorization {
    /// The id of the authorization
    pub id: i32,
    /// The user's public key (also used as bunker public key)
    pub user_public_key: String,
    /// The redirect_uri origin (scheme + host + port) - primary identifier for the app
    pub redirect_origin: String,
    /// The OAuth application id (optional metadata, origin is primary)
    pub application_id: Option<i32>,
    /// The bunker public key (same as user_public_key)
    pub bunker_public_key: String,
    /// The encrypted user private key (used for both NIP-46 decryption and event signing)
    pub bunker_secret: Vec<u8>,
    /// The connection secret for NIP-46 authentication
    pub secret: String,
    #[sqlx(try_from = "String")]
    /// The list of relays the authorization will listen on
    pub relays: Relays,
    /// Optional policy for permission restrictions
    pub policy_id: Option<i32>,
    /// Tenant ID for multi-tenancy isolation
    pub tenant_id: i64,
    /// The client's public key from nostr-login (nostrconnect:// URI)
    /// This is set at authorization creation time for nostr-login flow
    pub client_public_key: Option<String>,
    /// The connected NIP-46 client's public key (set after successful connect)
    /// Per NIP-46: after connect, this becomes the client identifier for security
    pub connected_client_pubkey: Option<String>,
    /// When the client connected (for audit purposes)
    pub connected_at: Option<DateTime<chrono::Utc>>,
    /// The date and time the authorization was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the authorization was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

impl OAuthAuthorization {
    /// Get the permissions for this OAuth authorization (if policy exists)
    pub async fn permissions(
        &self,
        pool: &PgPool,
        _tenant_id: i64,
    ) -> Result<Vec<crate::types::permission::Permission>, AuthorizationError> {
        // If no policy, return empty vec (allow all)
        let policy_id = match self.policy_id {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        // Load permissions from database
        // Tenant isolation is enforced at authorization lookup level
        let permissions = sqlx::query_as::<_, crate::types::permission::Permission>(
            r#"
            SELECT p.*
            FROM permissions p
            JOIN policy_permissions pp ON pp.permission_id = p.id
            WHERE pp.policy_id = $1
            "#,
        )
        .bind(policy_id)
        .fetch_all(pool)
        .await
        .map_err(AuthorizationError::Database)?;

        Ok(permissions)
    }

    pub async fn find(pool: &PgPool, tenant_id: i64, id: i32) -> Result<Self, AuthorizationError> {
        let authorization = sqlx::query_as::<_, OAuthAuthorization>(
            r#"
            SELECT * FROM oauth_authorizations
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(authorization)
    }

    pub async fn all_ids(pool: &PgPool) -> Result<Vec<i32>, AuthorizationError> {
        let authorizations = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT id FROM oauth_authorizations
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }

    pub async fn all_ids_for_all_tenants(pool: &PgPool) -> Result<Vec<(i64, i32)>, AuthorizationError> {
        let authorizations = sqlx::query_as::<_, (i64, i32)>(
            r#"
            SELECT tenant_id, id FROM oauth_authorizations
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }
}
