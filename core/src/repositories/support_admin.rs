// ABOUTME: Repository for the per-tenant support admin grant list
// ABOUTME: Postgres is the source of truth for who may use read-only support tooling

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::repositories::RepositoryError;

/// A support admin grant, with the grantee's email when they have an account
/// in the same tenant.
#[derive(Debug, Clone, FromRow)]
pub struct SupportAdminRow {
    pub pubkey: String,
    pub email: Option<String>,
    pub added_by_pubkey: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Repository for support admin grants.
///
/// Every method is a single statement on the pool, so none of them holds a
/// connection while acquiring another.
#[derive(Debug)]
pub struct SupportAdminRepository {
    pool: PgPool,
}

impl SupportAdminRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Whether `pubkey` holds a support admin grant in `tenant_id`.
    pub async fn is_support_admin(
        &self,
        tenant_id: i64,
        pubkey: &str,
    ) -> Result<bool, RepositoryError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM support_admins WHERE tenant_id = $1 AND pubkey = $2
             )",
        )
        .bind(tenant_id)
        .bind(pubkey)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    /// List the tenant's support admins, oldest grant first.
    pub async fn list(&self, tenant_id: i64) -> Result<Vec<SupportAdminRow>, RepositoryError> {
        let rows = sqlx::query_as::<_, SupportAdminRow>(
            "SELECT s.pubkey, u.email, s.added_by_pubkey, s.created_at
             FROM support_admins s
             LEFT JOIN users u ON u.pubkey = s.pubkey AND u.tenant_id = s.tenant_id
             WHERE s.tenant_id = $1
             ORDER BY s.created_at, s.pubkey",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Grant support admin to `pubkey` in `tenant_id`.
    ///
    /// Returns `false` when the grant already existed; the original grant's
    /// `added_by_pubkey` and `created_at` are kept.
    pub async fn add(
        &self,
        tenant_id: i64,
        pubkey: &str,
        added_by_pubkey: &str,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "INSERT INTO support_admins (tenant_id, pubkey, added_by_pubkey)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, pubkey) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(pubkey)
        .bind(added_by_pubkey)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke the support admin grant for `pubkey` in `tenant_id`.
    ///
    /// Returns `false` when there was no grant to revoke.
    pub async fn remove(&self, tenant_id: i64, pubkey: &str) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM support_admins WHERE tenant_id = $1 AND pubkey = $2")
            .bind(tenant_id)
            .bind(pubkey)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}
