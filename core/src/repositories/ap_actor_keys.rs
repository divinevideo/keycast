// ABOUTME: Repository for ap_actor_keys — per-user ActivityPub RSA keys
// ABOUTME: Stores encrypted PKCS#8 DER private key + plaintext SPKI public PEM, 1:1 per tenant

use crate::repositories::RepositoryError;
use sqlx::PgPool;

/// A stored AP key row (encrypted private key + public PEM).
#[derive(Debug, Clone)]
pub struct ApActorKeyRow {
    pub encrypted_private_key: Vec<u8>,
    pub public_key_pem: String,
    pub key_type: String,
}

#[derive(Debug, Clone)]
pub struct ApActorKeysRepository {
    pool: PgPool,
}

impl ApActorKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch the full row (encrypted private key + public PEM) for signing.
    pub async fn find_for_tenant(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Option<ApActorKeyRow>, RepositoryError> {
        let row = sqlx::query_as::<_, (Vec<u8>, String, String)>(
            "SELECT encrypted_private_key, public_key_pem, key_type
             FROM ap_actor_keys
             WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(encrypted_private_key, public_key_pem, key_type)| ApActorKeyRow {
                encrypted_private_key,
                public_key_pem,
                key_type,
            },
        ))
    }

    /// Fetch only the public PEM (GET path — never decrypts).
    pub async fn find_public_pem(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Option<(String, String)>, RepositoryError> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT public_key_pem, key_type
             FROM ap_actor_keys
             WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Insert a new key. Idempotency is enforced by the caller checking existence first
    /// AND by the UNIQUE(tenant_id, user_pubkey) constraint as a backstop.
    pub async fn create(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
        encrypted_private_key: &[u8],
        public_key_pem: &str,
        key_type: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO ap_actor_keys
                (tenant_id, user_pubkey, encrypted_private_key, public_key_pem, key_type)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .bind(encrypted_private_key)
        .bind(public_key_pem)
        .bind(key_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns true if an AP actor key already exists for this tenant/user pair.
    pub async fn exists(&self, tenant_id: i64, user_pubkey: &str) -> Result<bool, RepositoryError> {
        let found: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM ap_actor_keys WHERE tenant_id = $1 AND user_pubkey = $2",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    async fn setup_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        assert!(
            url.contains("localhost") || url.contains("127.0.0.1") || url.is_empty(),
            "tests must run against localhost"
        );
        PgPool::connect(&url).await.expect("connect")
    }

    #[tokio::test]
    async fn create_find_exists_roundtrip() {
        let pool = setup_pool().await;
        let repo = ApActorKeysRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        assert!(!repo.exists(1, &pubkey).await.unwrap());
        assert!(repo.find_for_tenant(1, &pubkey).await.unwrap().is_none());

        repo.create(
            1,
            &pubkey,
            &[1, 2, 3, 4],
            "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n",
            "rsa-2048",
        )
        .await
        .unwrap();

        assert!(repo.exists(1, &pubkey).await.unwrap());
        let row = repo.find_for_tenant(1, &pubkey).await.unwrap().unwrap();
        assert_eq!(row.encrypted_private_key, vec![1, 2, 3, 4]);
        assert!(row.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let (pem, kt) = repo.find_public_pem(1, &pubkey).await.unwrap().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(kt, "rsa-2048");

        // Tenant isolation: tenant 2 sees nothing.
        assert!(!repo.exists(2, &pubkey).await.unwrap());

        // Cleanup
        sqlx::query("DELETE FROM ap_actor_keys WHERE user_pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }
}
