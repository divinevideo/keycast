// ABOUTME: Repository for OAuth authorization codes
// ABOUTME: Handles temporary code storage for OAuth 2.0 authorization flow

use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Data returned when finding an OAuth code
///
/// Field names match `oauth_codes` columns so `sqlx::FromRow` maps by name; queries may
/// list the columns in any order as long as every field has a matching selected column.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OAuthCodeData {
    pub user_pubkey: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub pending_email: Option<String>,
    pub pending_password_hash: Option<String>,
    pub pending_email_verification_token: Option<String>,
    pub pending_encrypted_secret: Option<Vec<u8>>,
    pub previous_auth_id: Option<i32>,
    pub state: Option<String>,
    /// RFC 8628 device_code for secure polling (returned in response body, never in URLs)
    pub device_code: Option<String>,
    /// Whether this code was issued via headless flow (for first_party UCAN fact)
    pub is_headless: bool,
    /// bcrypt hash of the 6-digit in-app PIN fallback (keycast#262), if one was issued
    pub pin_hash: Option<String>,
    /// Failed verify-pin attempts; brute-force cap is enforced against this counter
    pub pin_attempts: i32,
    /// Timestamp of the last PIN issuance; backs the PIN-resend cooldown
    pub pin_sent_at: Option<DateTime<Utc>>,
}

/// Parameters for storing a basic OAuth code
#[derive(Debug, Clone)]
pub struct StoreOAuthCodeParams<'a> {
    pub tenant_id: i64,
    pub code: &'a str,
    pub user_pubkey: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub expires_at: DateTime<Utc>,
    pub previous_auth_id: Option<i32>,
    pub state: Option<&'a str>,
    /// Whether this code is from headless flow (for first_party UCAN fact)
    pub is_headless: bool,
}

/// Parameters for storing OAuth code with pending registration data
#[derive(Debug, Clone)]
pub struct StoreOAuthCodeWithRegistrationParams<'a> {
    pub tenant_id: i64,
    pub code: &'a str,
    pub user_pubkey: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub expires_at: DateTime<Utc>,
    pub pending_email: &'a str,
    pub pending_password_hash: &'a str,
    pub pending_email_verification_token: &'a str,
    pub pending_encrypted_secret: Option<&'a [u8]>,
    pub state: Option<&'a str>,
    /// RFC 8628 device_code for secure polling (returned in response body, never in URLs)
    pub device_code: Option<&'a str>,
    /// Whether this code is from headless flow (for first_party UCAN fact)
    pub is_headless: bool,
    /// bcrypt hash of the 6-digit in-app PIN fallback (keycast#262); None for browser OAuth
    pub pin_hash: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct OAuthCodeRepository {
    pool: PgPool,
}

impl OAuthCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store an OAuth authorization code with PKCE support.
    pub async fn store(&self, params: StoreOAuthCodeParams<'_>) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO oauth_codes (tenant_id, code, user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, previous_auth_id, state, is_headless, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(params.tenant_id)
        .bind(params.code)
        .bind(params.user_pubkey)
        .bind(params.client_id)
        .bind(params.redirect_uri)
        .bind(params.scope)
        .bind(params.code_challenge)
        .bind(params.code_challenge_method)
        .bind(params.expires_at)
        .bind(params.previous_auth_id)
        .bind(params.state)
        .bind(params.is_headless)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Store OAuth code with pending registration data (deferred user creation).
    /// Used by oauth_register to defer user creation until token exchange.
    pub async fn store_with_pending_registration(
        &self,
        params: StoreOAuthCodeWithRegistrationParams<'_>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO oauth_codes (tenant_id, code, user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at,
             pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret, state, device_code, is_headless, pin_hash, pin_sent_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
        )
        .bind(params.tenant_id)
        .bind(params.code)
        .bind(params.user_pubkey)
        .bind(params.client_id)
        .bind(params.redirect_uri)
        .bind(params.scope)
        .bind(params.code_challenge)
        .bind(params.code_challenge_method)
        .bind(params.expires_at)
        .bind(Utc::now())
        .bind(params.pending_email)
        .bind(params.pending_password_hash)
        .bind(params.pending_email_verification_token)
        .bind(params.pending_encrypted_secret)
        .bind(params.state)
        .bind(params.device_code)
        .bind(params.is_headless)
        .bind(params.pin_hash)
        // pin_sent_at tracks the last PIN issuance for the resend cooldown; set when a PIN is issued.
        .bind(params.pin_hash.map(|_| Utc::now()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Columns selected for every `OAuthCodeData` lookup (matches the struct's `FromRow` fields).
    const SELECT_COLUMNS: &'static str =
        "user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, \
         pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret, \
         previous_auth_id, state, device_code, is_headless, pin_hash, pin_attempts, pin_sent_at";

    /// Find a valid (non-expired) OAuth code.
    pub async fn find_valid(
        &self,
        tenant_id: i64,
        code: &str,
    ) -> Result<Option<OAuthCodeData>, RepositoryError> {
        let query = format!(
            "SELECT {} FROM oauth_codes WHERE tenant_id = $1 AND code = $2 AND expires_at > $3",
            Self::SELECT_COLUMNS
        );
        let result = sqlx::query_as::<_, OAuthCodeData>(&query)
            .bind(tenant_id)
            .bind(code)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?;

        Ok(result)
    }

    /// Find a pending OAuth registration by email verification token.
    /// Used when user clicks the email verification link to complete OAuth flow.
    pub async fn find_by_verification_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<OAuthCodeData>, RepositoryError> {
        let query = format!(
            "SELECT {} FROM oauth_codes WHERE pending_email_verification_token = $1 AND tenant_id = $2 AND expires_at > $3",
            Self::SELECT_COLUMNS
        );
        let result = sqlx::query_as::<_, OAuthCodeData>(&query)
            .bind(token)
            .bind(tenant_id)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?;

        Ok(result)
    }

    /// Find a pending registration by its RFC 8628 `device_code` (the 64-char app-held secret).
    ///
    /// This is the lookup gate for in-app PIN verification (keycast#262): the `device_code` is the
    /// real authenticator and the 6-digit PIN is defense-in-depth, so PIN verification MUST resolve
    /// the pending row by `device_code` rather than by a global PIN scan (which would be brute-forceable
    /// across all pending registrations). Only pending rows carry a non-null `device_code`, and the PIN
    /// stays valid for the full 24h verify window, so this filters on `expires_at > now`.
    pub async fn find_by_device_code(
        &self,
        device_code: &str,
        tenant_id: i64,
    ) -> Result<Option<OAuthCodeData>, RepositoryError> {
        let query = format!(
            "SELECT {} FROM oauth_codes WHERE device_code = $1 AND tenant_id = $2 AND expires_at > $3",
            Self::SELECT_COLUMNS
        );
        let result = sqlx::query_as::<_, OAuthCodeData>(&query)
            .bind(device_code)
            .bind(tenant_id)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?;

        Ok(result)
    }

    /// Atomically reserve one PIN-verification attempt slot for a pending registration, returning
    /// the new attempt count. Returns `None` when no slot could be reserved — either the row is
    /// already at `max_attempts` (locked) or no pending row matches the `device_code`.
    ///
    /// The increment happens in a single conditional `UPDATE ... WHERE pin_attempts < $max
    /// RETURNING`, so the cap is enforced by the database rather than by a snapshot read. This is
    /// what bounds brute force: callers reserve a slot BEFORE running the (expensive) bcrypt
    /// comparison, so at most `max_attempts` comparisons can ever run for a given `device_code`,
    /// even across concurrent verify-pin requests on different Cloud Run instances.
    pub async fn reserve_pin_attempt(
        &self,
        device_code: &str,
        tenant_id: i64,
        max_attempts: i32,
    ) -> Result<Option<i32>, RepositoryError> {
        let row: Option<(i32,)> = sqlx::query_as(
            "UPDATE oauth_codes SET pin_attempts = pin_attempts + 1 \
             WHERE device_code = $1 AND tenant_id = $2 AND pin_attempts < $3 \
             RETURNING pin_attempts",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(max_attempts)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0))
    }

    /// Re-arm a pending registration for PIN resend: install a fresh verification token + PIN hash,
    /// reset the attempt counter to zero, refresh `pin_sent_at`, and extend the verify window.
    ///
    /// Used by the lockout-recovery path: after the attempt cap is hit, the user must request a resend
    /// (subject to the cooldown) which mints a new PIN and clears the lockout.
    pub async fn reset_pin_for_resend(
        &self,
        device_code: &str,
        tenant_id: i64,
        new_verification_token: &str,
        new_pin_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE oauth_codes \
             SET pending_email_verification_token = $1, pin_hash = $2, pin_attempts = 0, \
                 pin_sent_at = $3, expires_at = $4 \
             WHERE device_code = $5 AND tenant_id = $6",
        )
        .bind(new_verification_token)
        .bind(new_pin_hash)
        .bind(Utc::now())
        .bind(new_expires_at)
        .bind(device_code)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete pending OAuth registration by verification token.
    pub async fn delete_by_verification_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "DELETE FROM oauth_codes WHERE pending_email_verification_token = $1 AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete an OAuth code (one-time use).
    pub async fn delete(&self, tenant_id: i64, code: &str) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM oauth_codes WHERE tenant_id = $1 AND code = $2")
            .bind(tenant_id)
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;

    fn assert_localhost_db() {
        let url = std::env::var("DATABASE_URL").unwrap_or_default();
        assert!(
            url.contains("localhost") || url.contains("127.0.0.1") || url.is_empty(),
            "Tests must run against localhost database"
        );
    }

    async fn setup_pool() -> PgPool {
        assert_localhost_db();
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database")
    }

    #[tokio::test]
    async fn test_oauth_code_lifecycle() {
        use chrono::Duration;
        use nostr_sdk::Keys;

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let code = format!("test_code_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + Duration::minutes(10);

        // Create user first
        sqlx::query("INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at) VALUES ($1, 1, $2, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .bind(format!("oauth-test-{}@example.com", uuid::Uuid::new_v4()))
            .execute(&pool)
            .await
            .unwrap();

        // Store code
        repo.store(StoreOAuthCodeParams {
            tenant_id: 1,
            code: &code,
            user_pubkey: &user_pubkey,
            client_id: "test_client",
            redirect_uri: "http://localhost:3000/callback",
            scope: "sign_event",
            code_challenge: Some("challenge123"),
            code_challenge_method: Some("S256"),
            expires_at,
            previous_auth_id: None,
            state: None,
            is_headless: false,
        })
        .await
        .unwrap();

        // Find valid code
        let found = repo.find_valid(1, &code).await.unwrap();
        assert!(found.is_some());
        let data = found.unwrap();
        assert_eq!(data.user_pubkey, user_pubkey);
        assert_eq!(data.client_id, "test_client");
        assert_eq!(data.code_challenge, Some("challenge123".to_string()));

        // Delete code
        repo.delete(1, &code).await.unwrap();

        // Should no longer be found
        let found = repo.find_valid(1, &code).await.unwrap();
        assert!(found.is_none());
    }

    /// Helper: insert a pending headless registration with a device_code and optional PIN hash.
    async fn insert_pending_registration(
        repo: &OAuthCodeRepository,
        device_code: &str,
        pin_hash: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> (String, String) {
        use nostr_sdk::Keys;
        let user_pubkey = Keys::generate().public_key().to_hex();
        let code = format!("pending_{}", uuid::Uuid::new_v4());
        let token = format!("verif_{}", uuid::Uuid::new_v4());
        let email = format!("pin-test-{}@example.com", uuid::Uuid::new_v4());

        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: &code,
            user_pubkey: &user_pubkey,
            client_id: "test_client",
            redirect_uri: "http://localhost:3000/callback",
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at,
            pending_email: &email,
            pending_password_hash: "hashed",
            pending_email_verification_token: &token,
            pending_encrypted_secret: Some(b"secret"),
            state: None,
            device_code: Some(device_code),
            is_headless: true,
            pin_hash,
        })
        .await
        .unwrap();

        (token, email)
    }

    #[tokio::test]
    async fn test_find_by_device_code_returns_pending_with_pin() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        let (_token, email) =
            insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;

        let found = repo.find_by_device_code(&device_code, 1).await.unwrap();
        assert!(
            found.is_some(),
            "pending row should be found by device_code"
        );
        let data = found.unwrap();
        assert_eq!(data.pin_hash.as_deref(), Some("pinhash123"));
        assert_eq!(data.pin_attempts, 0);
        assert_eq!(data.pending_email.as_deref(), Some(email.as_str()));
        assert!(data.is_headless);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_find_by_device_code_excludes_expired() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() - chrono::Duration::hours(1); // already expired
        insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;

        let found = repo.find_by_device_code(&device_code, 1).await.unwrap();
        assert!(found.is_none(), "expired pending row must not be returned");

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_reserve_pin_attempt_accumulates_and_enforces_cap() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;

        // Reserve up to the cap; each call returns the post-increment count.
        let max = 3;
        let first = repo
            .reserve_pin_attempt(&device_code, 1, max)
            .await
            .unwrap();
        assert_eq!(first, Some(1));
        let second = repo
            .reserve_pin_attempt(&device_code, 1, max)
            .await
            .unwrap();
        assert_eq!(second, Some(2));
        let third = repo
            .reserve_pin_attempt(&device_code, 1, max)
            .await
            .unwrap();
        assert_eq!(third, Some(3));

        // At the cap: no slot can be reserved (atomic lockout), and the counter does not grow.
        let locked = repo
            .reserve_pin_attempt(&device_code, 1, max)
            .await
            .unwrap();
        assert_eq!(locked, None, "reserve must return None once at the cap");
        let after = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.pin_attempts, max, "counter must not exceed the cap");

        // Unknown device_code returns None (no row updated).
        let none = repo
            .reserve_pin_attempt("nonexistent", 1, max)
            .await
            .unwrap();
        assert_eq!(none, None);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_reset_pin_for_resend_rearms_token_pin_and_attempts() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("oldpin"), expires_at).await;

        // Burn two attempts.
        repo.reserve_pin_attempt(&device_code, 1, 5).await.unwrap();
        repo.reserve_pin_attempt(&device_code, 1, 5).await.unwrap();

        let new_token = format!("verif_{}", uuid::Uuid::new_v4());
        let new_expires = Utc::now() + chrono::Duration::hours(24);
        repo.reset_pin_for_resend(&device_code, 1, &new_token, "newpin", new_expires)
            .await
            .unwrap();

        let data = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .expect("row should still exist after resend");
        assert_eq!(data.pin_hash.as_deref(), Some("newpin"));
        assert_eq!(data.pin_attempts, 0, "attempts reset on resend");

        // New token is now the live verification token.
        let by_token = repo
            .find_by_verification_token(&new_token, 1)
            .await
            .unwrap();
        assert!(by_token.is_some(), "new token should resolve to the row");

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }
}
