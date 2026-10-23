// ABOUTME: Repository for accounts linked to an upstream OpenID Provider subject
// ABOUTME: Backs the OIDC login (api/src/api/http/oidc.rs); one subject per issuer per account

use sqlx::PgPool;

use crate::repositories::RepositoryError;

/// Outcome of [`OidcIdentityRepository::link`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcLinkOutcome {
    /// A new link was written.
    Linked,
    /// The subject was already linked to this account.
    AlreadyLinked,
    /// The account is already linked to another subject at this issuer, or the subject to
    /// another account. Nothing was written.
    Conflict,
}

#[derive(Debug)]
pub struct OidcIdentityRepository {
    pool: PgPool,
}

impl OidcIdentityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The account linked to `subject` at `issuer`, if any.
    pub async fn find_pubkey(
        &self,
        tenant_id: i64,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<String>, RepositoryError> {
        let pubkey = sqlx::query_scalar::<_, String>(
            "SELECT user_pubkey FROM oidc_identities
             WHERE tenant_id = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;
        Ok(pubkey)
    }

    /// Link `subject` at `issuer` to `pubkey`. Idempotent for the same pair; refuses to
    /// re-point an existing link in either direction.
    pub async fn link(
        &self,
        tenant_id: i64,
        issuer: &str,
        subject: &str,
        pubkey: &str,
    ) -> Result<OidcLinkOutcome, RepositoryError> {
        let inserted = sqlx::query(
            "INSERT INTO oidc_identities (tenant_id, issuer, subject, user_pubkey)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .bind(pubkey)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(OidcLinkOutcome::Linked);
        }
        match self.find_pubkey(tenant_id, issuer, subject).await? {
            Some(existing) if existing == pubkey => Ok(OidcLinkOutcome::AlreadyLinked),
            _ => Ok(OidcLinkOutcome::Conflict),
        }
    }

    /// Record a successful login for the link.
    pub async fn touch(
        &self,
        tenant_id: i64,
        issuer: &str,
        subject: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE oidc_identities SET last_login_at = NOW()
             WHERE tenant_id = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
