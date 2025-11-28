// ABOUTME: OAuth authorization type for handling OAuth-based remote signing
// ABOUTME: Unlike regular authorizations, OAuth uses the user's personal key for both NIP-46 encryption and event signing

use crate::traits::AuthorizationValidations;
use crate::types::authorization::{AuthorizationError, Relays};
use chrono::DateTime;
use nostr::nips::nip46::NostrConnectRequest;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

/// An OAuth authorization where the user's personal key serves as both bunker key and signing key
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct OAuthAuthorization {
    /// The id of the authorization
    pub id: i32,
    /// The user's public key (also used as bunker public key)
    pub user_public_key: String,
    /// The OAuth application id
    pub application_id: i32,
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
        tenant_id: i64,
    ) -> Result<Vec<crate::types::permission::Permission>, AuthorizationError> {
        // If no policy, return empty vec (allow all)
        let policy_id = match self.policy_id {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        // Load permissions from database with tenant isolation
        let permissions = sqlx::query_as::<_, crate::types::permission::Permission>(
            r#"
            SELECT p.*
            FROM permissions p
            JOIN policy_permissions pp ON pp.permission_id = p.id
            WHERE p.tenant_id = $1 AND pp.policy_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_all(pool)
        .await
        .map_err(AuthorizationError::Database)?;

        Ok(permissions)
    }

    /// Synchronous version for non-async contexts (deprecated, use permissions() instead)
    #[deprecated(note = "Use async permissions() method instead")]
    pub fn permissions_sync(
        &self,
        pool: &PgPool,
        tenant_id: i64,
    ) -> Result<Vec<crate::types::permission::Permission>, AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.permissions(pool, tenant_id).await
            })
        })
    }

    pub async fn find(pool: &PgPool, tenant_id: i64, id: i32) -> Result<Self, AuthorizationError> {
        let authorization = sqlx::query_as::<_, OAuthAuthorization>(
            r#"
            SELECT * FROM oauth_authorizations WHERE tenant_id = $1 AND id = $2
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

impl AuthorizationValidations for OAuthAuthorization {
    fn validate_policy(
        &self,
        pool: &PgPool,
        tenant_id: i64,
        pubkey: &PublicKey,
        request: &NostrConnectRequest,
    ) -> Result<bool, AuthorizationError> {
        // Load permissions if policy exists
        let permissions = self.permissions_sync(pool, tenant_id)?;

        // Convert to CustomPermission trait objects
        let custom_permissions: Result<Vec<Box<dyn crate::traits::CustomPermission>>, _> = permissions
            .iter()
            .map(|p| p.to_custom_permission())
            .collect();
        let custom_permissions = custom_permissions
            .map_err(|_| AuthorizationError::Unauthorized)?;

        match request {
            NostrConnectRequest::Connect { remote_signer_public_key, secret } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Connect request received");
                // Check the public key matches
                if remote_signer_public_key.to_hex() != self.bunker_public_key {
                    return Err(AuthorizationError::Unauthorized);
                }
                // Check that secret is correct
                match secret {
                    Some(ref s) if s != &self.secret => {
                        return Err(AuthorizationError::InvalidSecret)
                    }
                    _ => {}
                }
                Ok(true)
            }
            NostrConnectRequest::GetPublicKey => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Get public key request");
                Ok(true)
            }
            NostrConnectRequest::SignEvent(event) => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Sign event request");
                // Validate against all permissions (AND logic)
                for permission in &custom_permissions {
                    if !permission.can_sign(event) {
                        tracing::warn!(
                            "OAuth authorization {} denied by {} permission for kind {}",
                            self.id,
                            permission.identifier(),
                            event.kind.as_u16()
                        );
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            NostrConnectRequest::Nip04Encrypt { public_key, text }
            | NostrConnectRequest::Nip44Encrypt { public_key, text } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth NIP04/44 encrypt request");
                // Validate against all permissions
                for permission in &custom_permissions {
                    if !permission.can_encrypt(text, pubkey, public_key) {
                        tracing::warn!(
                            "OAuth authorization {} denied encryption by {} permission",
                            self.id,
                            permission.identifier()
                        );
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            NostrConnectRequest::Nip04Decrypt { public_key, ciphertext }
            | NostrConnectRequest::Nip44Decrypt { public_key, ciphertext } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth NIP04/44 decrypt request");
                // Validate against all permissions
                for permission in &custom_permissions {
                    if !permission.can_decrypt(ciphertext, public_key, pubkey) {
                        tracing::warn!(
                            "OAuth authorization {} denied decryption by {} permission",
                            self.id,
                            permission.identifier()
                        );
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            NostrConnectRequest::Ping => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Ping request");
                Ok(true)
            }
        }
    }
}
