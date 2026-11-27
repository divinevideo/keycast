// ABOUTME: Data access for sign-in providers (Google, Apple) linked to Keycast accounts
// ABOUTME: Finds, links and creates accounts by provider subject inside short transactions

use super::RepositoryError;
use crate::social_login::SocialProvider;
use chrono::Utc;
use sqlx::{PgPool, Postgres, Transaction};

/// An account a provider subject already signs in to.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LinkedIdentity {
    pub user_pubkey: String,
}

/// An account whose stored email matches a provider email case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct EmailMatch {
    pub pubkey: String,
    pub email: String,
    pub email_verified: bool,
}

/// Everything needed to create an account that signs in through a provider.
pub struct NewSocialAccount<'a> {
    pub tenant_id: i64,
    pub pubkey: &'a str,
    /// Normalized (lowercase) address the provider verified.
    pub email: &'a str,
    pub encrypted_secret: &'a [u8],
    pub provider: SocialProvider,
    pub subject: &'a str,
}

/// Result of [`UserIdentityRepository::create_account`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateSocialAccountOutcome {
    /// The account was created. `released` names the unconfirmed accounts the email was removed
    /// from, in pubkey order; usually none.
    Created { released: Vec<String> },
    /// A confirmed account holds this email now, for example because its owner confirmed it
    /// meanwhile. Resolve again.
    EmailTaken,
    /// Another request linked this provider subject first. Resolve again.
    SubjectTaken,
}

/// Result of [`UserIdentityRepository::link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSocialIdentityOutcome {
    Linked,
    /// The email no longer belongs to exactly this confirmed account. Resolve again.
    AccountChanged,
    /// Another request linked this provider subject first. Resolve again.
    SubjectTaken,
}

/// Repository for `user_identities`.
#[derive(Debug, Clone)]
pub struct UserIdentityRepository {
    pool: PgPool,
}

impl UserIdentityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find the account a provider subject signs in to.
    pub async fn find_by_subject(
        &self,
        tenant_id: i64,
        provider: SocialProvider,
        subject: &str,
    ) -> Result<Option<LinkedIdentity>, RepositoryError> {
        sqlx::query_as(
            "SELECT user_pubkey FROM user_identities
             WHERE tenant_id = $1 AND provider = $2 AND subject = $3",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Record a sign-in through an already linked subject.
    ///
    /// Keeps the last email the provider reported when it sent one.
    pub async fn record_login(
        &self,
        tenant_id: i64,
        provider: SocialProvider,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE user_identities
             SET last_login_at = $1, email = COALESCE($2, email)
             WHERE tenant_id = $3 AND provider = $4 AND subject = $5",
        )
        .bind(Utc::now())
        .bind(email)
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Accounts whose email equals `normalized_email` ignoring case.
    ///
    /// The unique email index is case-sensitive, so older rows may differ only in case. All of
    /// them are returned, confirmed or not, because the decision depends on the confirmed ones.
    pub async fn find_users_by_email(
        &self,
        tenant_id: i64,
        normalized_email: &str,
    ) -> Result<Vec<EmailMatch>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, email, COALESCE(email_verified, false) AS email_verified
             FROM users
             WHERE tenant_id = $1 AND LOWER(email) = $2
             ORDER BY pubkey",
        )
        .bind(tenant_id)
        .bind(normalized_email)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Link a provider subject to an existing account found by email.
    ///
    /// Re-checks inside the transaction that exactly this account is still the only confirmed
    /// one with the email, so a concurrent email change or duplicate cannot be linked by
    /// accident. Unconfirmed accounts with the same email are left as they are.
    pub async fn link(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
        normalized_email: &str,
        provider: SocialProvider,
        subject: &str,
    ) -> Result<LinkSocialIdentityOutcome, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        lock_email(&mut tx, tenant_id, normalized_email).await?;

        let matches = lock_email_matches(&mut tx, tenant_id, normalized_email).await?;
        let confirmed: Vec<&EmailMatch> = matches.iter().filter(|m| m.email_verified).collect();
        let still_linkable = matches!(confirmed.as_slice(), [only] if only.pubkey == user_pubkey);
        if !still_linkable {
            return Ok(LinkSocialIdentityOutcome::AccountChanged);
        }

        if !insert_identity(
            &mut tx,
            tenant_id,
            user_pubkey,
            provider,
            subject,
            normalized_email,
        )
        .await?
        {
            return Ok(LinkSocialIdentityOutcome::SubjectTaken);
        }

        tx.commit().await?;
        Ok(LinkSocialIdentityOutcome::Linked)
    }

    /// Create an account, its personal key and its provider link in one transaction.
    ///
    /// The account has a verified email and no password. Encryption of the new key happens
    /// before this call so no transaction is held across the key manager.
    ///
    /// Accounts that never confirmed this email cannot sign in, so the email is released to the
    /// provider sign-in: in the same transaction, it is removed from them along with their
    /// verification, password reset and email change tokens. They are released only while still
    /// unconfirmed; once one is confirmed this answers [`CreateSocialAccountOutcome::EmailTaken`].
    pub async fn create_account(
        &self,
        account: NewSocialAccount<'_>,
    ) -> Result<CreateSocialAccountOutcome, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        lock_email(&mut tx, account.tenant_id, account.email).await?;

        let matches = lock_email_matches(&mut tx, account.tenant_id, account.email).await?;
        if matches.iter().any(|m| m.email_verified) {
            return Ok(CreateSocialAccountOutcome::EmailTaken);
        }
        let released = if matches.is_empty() {
            Vec::new()
        } else {
            release_unconfirmed_email(&mut tx, account.tenant_id, account.email).await?
        };
        if released.len() != matches.len() {
            // Not expected while the rows are locked; resolve again rather than guess.
            return Ok(CreateSocialAccountOutcome::EmailTaken);
        }

        let now = Utc::now();
        let inserted = sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified,
                                created_at, updated_at)
             VALUES ($1, $2, $3, NULL, true, $4, $4)",
        )
        .bind(account.pubkey)
        .bind(account.tenant_id)
        .bind(account.email)
        .bind(now)
        .execute(&mut *tx)
        .await;
        match inserted.map_err(RepositoryError::from) {
            Ok(_) => {}
            // A password registration finalized the same address without taking our lock.
            Err(RepositoryError::Duplicate) => return Ok(CreateSocialAccountOutcome::EmailTaken),
            Err(error) => return Err(error),
        }

        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id,
                                        created_at, updated_at)
             VALUES ($1, $2, $3, $4, $4)",
        )
        .bind(account.pubkey)
        .bind(account.encrypted_secret)
        .bind(account.tenant_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        if !insert_identity(
            &mut tx,
            account.tenant_id,
            account.pubkey,
            account.provider,
            account.subject,
            account.email,
        )
        .await?
        {
            return Ok(CreateSocialAccountOutcome::SubjectTaken);
        }

        tx.commit().await?;
        Ok(CreateSocialAccountOutcome::Created { released })
    }

    /// Store the encrypted Apple refresh token for a linked Apple subject, with the client (bundle
    /// ID or Services ID) it was issued to.
    pub async fn store_apple_refresh_token(
        &self,
        tenant_id: i64,
        subject: &str,
        user_pubkey: &str,
        encrypted_refresh_token: &[u8],
        client_id: &str,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "INSERT INTO apple_identity_grants (identity_id, client_id, encrypted_token)
             SELECT id, $2, $1 FROM user_identities
             WHERE tenant_id = $3 AND provider = 'apple' AND subject = $4 AND user_pubkey = $5
             FOR UPDATE
             ON CONFLICT (identity_id, client_id) DO UPDATE
             SET encrypted_token = EXCLUDED.encrypted_token",
        )
        .bind(encrypted_refresh_token)
        .bind(client_id)
        .bind(tenant_id)
        .bind(subject)
        .bind(user_pubkey)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() != 0)
    }

    /// Providers linked to an account, in a stable order.
    pub async fn providers_for_user(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Vec<String>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT provider FROM user_identities
             WHERE tenant_id = $1 AND user_pubkey = $2
             ORDER BY provider, id",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}

/// Serialize account creation and linking for one address.
///
/// Transaction-scoped, so it is released with the transaction and works with transaction-mode
/// pooling.
async fn lock_email(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    normalized_email: &str,
) -> Result<(), RepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("social_login_email:{tenant_id}:{normalized_email}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Every account with this email ignoring case, locked until the transaction ends.
async fn lock_email_matches(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    normalized_email: &str,
) -> Result<Vec<EmailMatch>, RepositoryError> {
    sqlx::query_as(
        "SELECT pubkey, email, COALESCE(email_verified, false) AS email_verified
         FROM users
         WHERE tenant_id = $1 AND LOWER(email) = $2
         ORDER BY pubkey
         FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(normalized_email)
    .fetch_all(&mut **tx)
    .await
    .map_err(Into::into)
}

/// Remove the email from every account that never confirmed it, together with the links that
/// could still act on it: email verification, password reset and pending email change. Returns
/// the pubkeys of those accounts.
///
/// The rows stay, without an email: nothing can sign in to them or reset them any more, and
/// their pubkeys remain for support and audit. Only rows still unconfirmed are changed, so a
/// confirmation that commits first keeps its email.
async fn release_unconfirmed_email(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    normalized_email: &str,
) -> Result<Vec<String>, RepositoryError> {
    // As when an account is deleted: an opted-in address may already be a contact on the email
    // platform, and once no account holds it nothing else would tell the sync to remove it.
    sqlx::query(
        "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at)
         SELECT tenant_id, email, NOW() FROM users
         WHERE tenant_id = $1 AND LOWER(email) = $2
           AND email_verified IS NOT TRUE
           AND email_marketing_consent = 'opted_in'",
    )
    .bind(tenant_id)
    .bind(normalized_email)
    .execute(&mut **tx)
    .await?;

    sqlx::query_scalar(
        "UPDATE users
         SET email = NULL,
             email_verification_token = NULL,
             email_verification_expires_at = NULL,
             email_verification_sent_at = NULL,
             password_reset_token = NULL,
             password_reset_expires_at = NULL,
             pending_email = NULL,
             pending_email_old_token = NULL,
             pending_email_new_token = NULL,
             pending_email_expires_at = NULL,
             pending_email_sent_at = NULL,
             pending_email_old_confirmed_at = NULL,
             pending_email_new_confirmed_at = NULL,
             updated_at = $3
         WHERE tenant_id = $1 AND LOWER(email) = $2
           AND email_verified IS NOT TRUE
         RETURNING pubkey",
    )
    .bind(tenant_id)
    .bind(normalized_email)
    .bind(Utc::now())
    .fetch_all(&mut **tx)
    .await
    .map(|mut released: Vec<String>| {
        released.sort();
        released
    })
    .map_err(Into::into)
}

/// Insert a provider link. Returns `false` when the subject is already linked.
async fn insert_identity(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    user_pubkey: &str,
    provider: SocialProvider,
    subject: &str,
    email: &str,
) -> Result<bool, RepositoryError> {
    let now = Utc::now();
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO user_identities (tenant_id, user_pubkey, provider, subject, email,
                                      created_at, last_login_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)
         ON CONFLICT (tenant_id, provider, subject) DO NOTHING
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(user_pubkey)
    .bind(provider.as_str())
    .bind(subject)
    .bind(email)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(inserted.is_some())
}
