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
    /// Failed attempts against the *current* PIN; a resend clears this, which is what makes a
    /// resend the recovery path out of a lockout
    pub pin_attempts: i32,
    /// Failed attempts across every PIN this email's live registration lineage has issued; never
    /// reset by resend or same-email supersession, so it is the adversarial guessing bound
    pub pin_failed_total: i32,
    /// When the current PIN was handed to the delivery provider; backs the PIN validity window
    pub pin_sent_at: Option<DateTime<Utc>>,
    /// When a PIN resend was last performed; backs the resend cooldown. Stays NULL through
    /// registration so a user's first resend request is never swallowed by a cooldown they
    /// never started.
    pub pin_resend_at: Option<DateTime<Utc>>,
    /// Terminal marker (keycast#262): set after the registration's exchange code successfully
    /// issues tokens. Once non-NULL, finalize refuses to re-mint and the row is eligible for cleanup.
    pub consumed_at: Option<DateTime<Utc>>,
    /// End of the registration's verification window. Lookups that need to tell an expired
    /// registration apart from an absent one select this and decide for themselves.
    pub expires_at: DateTime<Utc>,
}

/// Outcome of trying to reserve one PIN-verification attempt slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAttemptReservation {
    /// A slot was reserved; carries the resulting count against the current PIN.
    Reserved { attempt: i32 },
    /// The current PIN has spent its per-PIN cap. A resend clears this.
    CurrentPinLocked,
    /// The registration has spent its lifetime cap across every PIN it has issued. A resend does
    /// not clear this; the emailed link remains the way in.
    LifetimeExhausted,
    /// The registration's verification window has closed.
    Expired,
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

/// Outcome of storing a pending registration.
#[derive(Debug, Clone)]
pub struct StoredPendingRegistration {
    /// The `device_code` now on the row — the caller's own on a fresh registration, or the
    /// superseded row's existing one. This is what the client must poll.
    pub device_code: Option<String>,
    /// Whether this call re-armed an existing live pending registration instead of creating one.
    pub superseded: bool,
}

/// Exchange code selected for one pending registration generation.
#[derive(Debug, Clone)]
pub struct StoredExchangeCode {
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub freshly_minted: bool,
}

/// Pending registration and exchange code committed by one finalization transaction.
#[derive(Debug)]
pub struct FinalizedPendingRegistration {
    pub pending: OAuthCodeData,
    pub exchange_code: StoredExchangeCode,
}

/// Result of materializing one exact pending registration generation.
#[derive(Debug)]
pub enum MaterializePendingRegistrationOutcome {
    /// User/key materialization and exchange-code selection committed together.
    Ready(Box<FinalizedPendingRegistration>),
    /// A live exchange code is currently claimed by token issuance.
    Processing,
    /// The generation was superseded, consumed, expired, or removed before it could be locked.
    NotFound,
    /// The pending pubkey is already bound to another email.
    DuplicateKey,
    /// Another pubkey already owns the pending email.
    EmailAlreadyExists,
}

enum UserMaterializationOutcome {
    Materialized(Box<OAuthCodeData>),
    DuplicateKey,
    EmailAlreadyExists,
}

enum ExchangeSelection {
    Ready(StoredExchangeCode),
    Processing,
}

/// Result of releasing a PIN-attempt reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAttemptRelease {
    /// The reservation still belonged to the current generation.
    CurrentGeneration,
    /// A newer generation replaced it; only the lineage lifetime counter was compensated.
    GenerationChanged,
    /// No live pending lineage remained to compensate.
    Missing,
}

/// The PIN-resend fields of a pending registration as they stood before a resend attempt.
///
/// Captured so [`OAuthCodeRepository::restore_pin_after_failed_resend`] can put the row back
/// exactly as it was when the replacement email could not be delivered — leaving the previous PIN
/// usable and neither the validity window nor the resend cooldown restamped by a send that never
/// reached the user.
#[derive(Debug, Clone, Copy)]
pub struct PinResendSnapshot<'a> {
    pub verification_token: Option<&'a str>,
    pub pin_hash: Option<&'a str>,
    pub pin_attempts: i32,
    pub pin_sent_at: Option<DateTime<Utc>>,
    pub pin_resend_at: Option<DateTime<Utc>>,
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

    /// Store an exchange code only while the matching pending registration is still active.
    pub async fn store_for_pending_registration(
        &self,
        params: StoreOAuthCodeParams<'_>,
        pending: &OAuthCodeData,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "INSERT INTO oauth_codes (tenant_id, code, user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, previous_auth_id, state, is_headless, created_at, pending_email_verification_token, device_code)
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
              WHERE EXISTS (
                  SELECT 1 FROM oauth_codes pending
                  WHERE pending.tenant_id = $1
                   AND pending.user_pubkey = $3
                   AND pending.client_id = $4
                   AND pending.redirect_uri = $5
                   AND pending.scope = $6
                   AND pending.code_challenge IS NOT DISTINCT FROM $7
                   AND pending.code_challenge_method IS NOT DISTINCT FROM $8
                   AND pending.state IS NOT DISTINCT FROM $11
                   AND pending.is_headless = $12
                   AND pending.pending_email IS NOT NULL
                   AND pending.pending_email_verification_token IS NOT DISTINCT FROM $14
                   AND pending.device_code IS NOT DISTINCT FROM $15
                   AND pending.consumed_at IS NULL
                   AND pending.expires_at > $13
             )",
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
        .bind(pending.pending_email_verification_token.as_deref())
        .bind(pending.device_code.as_deref())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    /// Store OAuth code with pending registration data (deferred user creation).
    /// Used by oauth_register and headless_register to defer user creation until token exchange.
    ///
    /// Registering an email that already has a live pending registration **supersedes** that row
    /// in place rather than creating a second one. The mobile client can fire
    /// `POST /api/headless/register` twice for one signup; two rows meant two verification emails
    /// and two device_codes, and opening the older link produced a 409 that deleted the stale row
    /// and then a 401 "Invalid or expired token" (keycast#268).
    ///
    /// **The newest attempt wins every registration field**: password hash, keypair, PKCE
    /// challenge, client_id/redirect_uri/scope/state, verification token, PIN, and the expiry
    /// window. Re-arming must not silently keep the first attempt's password (the user may have
    /// corrected it), and it must not keep the first attempt's `code_challenge` — the client mints
    /// a fresh PKCE verifier per register call, so the stored challenge has to be the one matching
    /// the verifier the app is now holding or token exchange would fail PKCE.
    ///
    /// **`device_code` is deliberately preserved**, and the effective one is returned. It is the
    /// only field where the *first* attempt wins: keeping it makes the outcome independent of the
    /// order the two responses arrive in, so an app that stored the first response's device_code
    /// is still polling the right registration.
    ///
    /// `expires_at` is refreshed, unlike [`Self::reset_pin_for_resend`], which deliberately never
    /// extends the window. A resend is free; a re-register is a whole new registration (new
    /// bcrypt, new keypair), so it earns a fresh window — and without this an expired-but-unconsumed
    /// row would block its own email from ever registering again, since the unique index has no
    /// expiry predicate.
    ///
    /// Supersession resets the current-PIN lockout and resend cooldown for usability, so neither is
    /// a security boundary: a caller can always register again. `pin_failed_total` is deliberately
    /// omitted from `DO UPDATE` below so the guessing budget survives that route. This also means
    /// repeated registration can extend time, but cannot grant additional PIN guesses.
    ///
    /// Race-proofed by `idx_oauth_codes_live_pending_email`; the insert-or-supersede decision is a
    /// single statement, so concurrent duplicate registers cannot both create a row.
    pub async fn store_with_pending_registration(
        &self,
        params: StoreOAuthCodeWithRegistrationParams<'_>,
    ) -> Result<StoredPendingRegistration, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "INSERT INTO oauth_codes (tenant_id, code, user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at,
             pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret, state, device_code, is_headless, pin_hash, pin_sent_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
             ON CONFLICT (tenant_id, lower(pending_email))
                 WHERE pending_email IS NOT NULL AND consumed_at IS NULL
             DO UPDATE SET
                 user_pubkey = EXCLUDED.user_pubkey,
                 client_id = EXCLUDED.client_id,
                 redirect_uri = EXCLUDED.redirect_uri,
                 scope = EXCLUDED.scope,
                 code_challenge = EXCLUDED.code_challenge,
                 code_challenge_method = EXCLUDED.code_challenge_method,
                 expires_at = EXCLUDED.expires_at,
                 pending_email = EXCLUDED.pending_email,
                 pending_password_hash = EXCLUDED.pending_password_hash,
                 pending_email_verification_token = EXCLUDED.pending_email_verification_token,
                 pending_encrypted_secret = EXCLUDED.pending_encrypted_secret,
                 state = EXCLUDED.state,
                 is_headless = EXCLUDED.is_headless,
                 pin_hash = EXCLUDED.pin_hash,
                 pin_attempts = 0,
                 pin_sent_at = NULL,
                 pin_resend_at = NULL
               WHERE NOT EXISTS (
                     SELECT 1 FROM users
                     WHERE users.tenant_id = EXCLUDED.tenant_id
                       AND lower(users.email) = lower(EXCLUDED.pending_email)
                )
              RETURNING device_code",
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
        // pin_sent_at tracks confirmed delivery; callers set it after the email send succeeds.
        .bind(None::<DateTime<Utc>>)
        .fetch_optional(&mut *tx)
        .await?;

        // An upsert that was already waiting on the pending-row lock uses the snapshot from before
        // materialization committed. Recheck in a new statement and roll back any stale-snapshot
        // rewrite before exposing success.
        let materialized: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM users
                WHERE tenant_id = $1 AND lower(email) = lower($2)
            )",
        )
        .bind(params.tenant_id)
        .bind(params.pending_email)
        .fetch_one(&mut *tx)
        .await?;
        if materialized {
            tx.rollback().await?;
            return Err(RepositoryError::Duplicate);
        }

        let Some((device_code,)) = row else {
            tx.rollback().await?;
            return Err(RepositoryError::Unavailable(
                "pending registration could not be superseded".to_string(),
            ));
        };
        // The UPDATE branch leaves device_code untouched, so a returned value different from the
        // one we offered means we superseded an existing pending registration.
        let superseded = device_code.as_deref() != params.device_code;
        tx.commit().await?;

        Ok(StoredPendingRegistration {
            device_code,
            superseded,
        })
    }

    /// Lock and materialize one exact pending registration generation atomically.
    ///
    /// The pending row lock serializes exact-generation finalizers and blocks the in-place
    /// supersession upsert until the users row is visible. No pool acquisition occurs while this
    /// transaction is held.
    pub async fn materialize_pending_registration(
        &self,
        tenant_id: i64,
        verification_token: &str,
        candidate_code: &str,
    ) -> Result<MaterializePendingRegistrationOutcome, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let query = format!(
            "SELECT {} FROM oauth_codes
             WHERE tenant_id = $1 AND pending_email_verification_token = $2
               AND pending_email IS NOT NULL AND consumed_at IS NULL AND expires_at > $3
             FOR UPDATE",
            Self::SELECT_COLUMNS
        );
        let Some(pending) = sqlx::query_as::<_, OAuthCodeData>(&query)
            .bind(tenant_id)
            .bind(verification_token)
            .bind(Utc::now())
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.rollback().await?;
            return Ok(MaterializePendingRegistrationOutcome::NotFound);
        };

        let email = pending.pending_email.as_deref().ok_or_else(|| {
            RepositoryError::Integrity("pending registration has no email".to_string())
        })?;
        let password_hash = pending.pending_password_hash.as_deref().ok_or_else(|| {
            RepositoryError::Integrity("pending registration has no password hash".to_string())
        })?;
        let now = Utc::now();

        let existing: Option<(Option<String>, bool, bool)> = sqlx::query_as(
            "SELECT u.email, u.email_verified,
                    u.password_hash IS NOT NULL AS has_password_hash
             FROM users u
             WHERE u.pubkey = $1 AND u.tenant_id = $2
             FOR UPDATE",
        )
        .bind(&pending.user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;

        let outcome = if let Some((existing_email, email_verified, has_password_hash)) = existing {
            match existing_email.as_deref() {
                Some(bound_email) if bound_email != email => {
                    Self::delete_pending_generation(&mut tx, tenant_id, verification_token).await?;
                    UserMaterializationOutcome::DuplicateKey
                }
                _ => {
                    let email_owner: Option<(String,)> = sqlx::query_as(
                        "SELECT pubkey FROM users
                         WHERE tenant_id = $1 AND email = $2 AND pubkey <> $3
                         FOR UPDATE",
                    )
                    .bind(tenant_id)
                    .bind(email)
                    .bind(&pending.user_pubkey)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if email_owner.is_some() {
                        Self::delete_pending_generation(&mut tx, tenant_id, verification_token)
                            .await?;
                        UserMaterializationOutcome::EmailAlreadyExists
                    } else {
                        if existing_email.is_none() || !email_verified || !has_password_hash {
                            sqlx::query(
                                "UPDATE users
                                 SET email = $1, password_hash = COALESCE(password_hash, $2),
                                     email_verified = true, email_verification_token = $3,
                                     updated_at = $4
                                 WHERE pubkey = $5 AND tenant_id = $6",
                            )
                            .bind(email)
                            .bind(password_hash)
                            .bind(verification_token)
                            .bind(now)
                            .bind(&pending.user_pubkey)
                            .bind(tenant_id)
                            .execute(&mut *tx)
                            .await?;
                        }
                        Self::insert_pending_personal_key(&mut tx, tenant_id, &pending, now)
                            .await?;
                        UserMaterializationOutcome::Materialized(Box::new(pending))
                    }
                }
            }
        } else {
            let inserted: Option<(String,)> = sqlx::query_as(
                "INSERT INTO users
                     (pubkey, tenant_id, email, password_hash, email_verified,
                      email_verification_token, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, true, $5, $6, $6)
                 ON CONFLICT DO NOTHING
                 RETURNING pubkey",
            )
            .bind(&pending.user_pubkey)
            .bind(tenant_id)
            .bind(email)
            .bind(password_hash)
            .bind(verification_token)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;

            if inserted.is_some() {
                Self::insert_pending_personal_key(&mut tx, tenant_id, &pending, now).await?;
                UserMaterializationOutcome::Materialized(Box::new(pending))
            } else {
                let pubkey_state: Option<(Option<String>, bool, bool)> = sqlx::query_as(
                    "SELECT email, email_verified,
                            password_hash IS NOT NULL AS has_password_hash
                     FROM users WHERE pubkey = $1 AND tenant_id = $2 FOR UPDATE",
                )
                .bind(&pending.user_pubkey)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
                match pubkey_state {
                    Some((Some(bound_email), _, _)) if bound_email != email => {
                        Self::delete_pending_generation(&mut tx, tenant_id, verification_token)
                            .await?;
                        UserMaterializationOutcome::DuplicateKey
                    }
                    Some((existing_email, email_verified, has_password_hash)) => {
                        let email_owner: Option<(String,)> = sqlx::query_as(
                            "SELECT pubkey FROM users
                             WHERE tenant_id = $1 AND email = $2 AND pubkey <> $3
                             FOR UPDATE",
                        )
                        .bind(tenant_id)
                        .bind(email)
                        .bind(&pending.user_pubkey)
                        .fetch_optional(&mut *tx)
                        .await?;
                        if email_owner.is_some() {
                            Self::delete_pending_generation(&mut tx, tenant_id, verification_token)
                                .await?;
                            UserMaterializationOutcome::EmailAlreadyExists
                        } else {
                            if existing_email.is_none() || !email_verified || !has_password_hash {
                                sqlx::query(
                                    "UPDATE users
                                     SET email = $1, password_hash = COALESCE(password_hash, $2),
                                         email_verified = true, email_verification_token = $3,
                                         updated_at = $4
                                     WHERE pubkey = $5 AND tenant_id = $6",
                                )
                                .bind(email)
                                .bind(password_hash)
                                .bind(verification_token)
                                .bind(now)
                                .bind(&pending.user_pubkey)
                                .bind(tenant_id)
                                .execute(&mut *tx)
                                .await?;
                            }
                            Self::insert_pending_personal_key(&mut tx, tenant_id, &pending, now)
                                .await?;
                            UserMaterializationOutcome::Materialized(Box::new(pending))
                        }
                    }
                    None => {
                        Self::delete_pending_generation(&mut tx, tenant_id, verification_token)
                            .await?;
                        UserMaterializationOutcome::EmailAlreadyExists
                    }
                }
            }
        };

        let pending = match outcome {
            UserMaterializationOutcome::DuplicateKey => {
                tx.commit().await?;
                return Ok(MaterializePendingRegistrationOutcome::DuplicateKey);
            }
            UserMaterializationOutcome::EmailAlreadyExists => {
                tx.commit().await?;
                return Ok(MaterializePendingRegistrationOutcome::EmailAlreadyExists);
            }
            UserMaterializationOutcome::Materialized(pending) => pending,
        };

        let existing: Option<(String, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT exchange.code, exchange.expires_at, exchange.consumed_at
             FROM oauth_codes exchange
             WHERE exchange.tenant_id = $1
               AND exchange.user_pubkey = $2
               AND exchange.client_id = $3
               AND exchange.redirect_uri = $4
               AND exchange.scope = $5
               AND exchange.code_challenge IS NOT DISTINCT FROM $6
               AND exchange.code_challenge_method IS NOT DISTINCT FROM $7
               AND exchange.state IS NOT DISTINCT FROM $8
               AND exchange.is_headless = $9
               AND exchange.pending_email_verification_token IS NOT DISTINCT FROM $10
               AND exchange.device_code IS NOT DISTINCT FROM $11
               AND exchange.pending_email IS NULL
               AND exchange.expires_at > clock_timestamp()
             ORDER BY (exchange.consumed_at IS NOT NULL) DESC, exchange.created_at DESC
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(&pending.user_pubkey)
        .bind(&pending.client_id)
        .bind(&pending.redirect_uri)
        .bind(&pending.scope)
        .bind(pending.code_challenge.as_deref())
        .bind(pending.code_challenge_method.as_deref())
        .bind(pending.state.as_deref())
        .bind(pending.is_headless)
        .bind(pending.pending_email_verification_token.as_deref())
        .bind(pending.device_code.as_deref())
        .fetch_optional(&mut *tx)
        .await?;

        let selection = match existing {
            Some((_, _, Some(_))) => ExchangeSelection::Processing,
            Some((code, expires_at, None)) => ExchangeSelection::Ready(StoredExchangeCode {
                code,
                expires_at,
                freshly_minted: false,
            }),
            None => {
                let expires_at: DateTime<Utc> = sqlx::query_scalar(
                    "INSERT INTO oauth_codes
                         (tenant_id, code, user_pubkey, client_id, redirect_uri, scope,
                          code_challenge, code_challenge_method, expires_at, previous_auth_id, state,
                          is_headless, created_at, pending_email_verification_token, device_code)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                             clock_timestamp() + INTERVAL '10 minutes', $9, $10, $11,
                             clock_timestamp(), $12, $13)
                     RETURNING expires_at",
                )
                .bind(tenant_id)
                .bind(candidate_code)
                .bind(&pending.user_pubkey)
                .bind(&pending.client_id)
                .bind(&pending.redirect_uri)
                .bind(&pending.scope)
                .bind(pending.code_challenge.as_deref())
                .bind(pending.code_challenge_method.as_deref())
                .bind(pending.previous_auth_id)
                .bind(pending.state.as_deref())
                .bind(pending.is_headless)
                .bind(pending.pending_email_verification_token.as_deref())
                .bind(pending.device_code.as_deref())
                .fetch_one(&mut *tx)
                .await?;
                ExchangeSelection::Ready(StoredExchangeCode {
                    code: candidate_code.to_string(),
                    expires_at,
                    freshly_minted: true,
                })
            }
        };

        let still_live: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM oauth_codes
                WHERE tenant_id = $1 AND pending_email_verification_token = $2
                  AND pending_email IS NOT NULL AND consumed_at IS NULL
                  AND expires_at > clock_timestamp()
            )",
        )
        .bind(tenant_id)
        .bind(verification_token)
        .fetch_one(&mut *tx)
        .await?;
        if !still_live {
            tx.rollback().await?;
            return Ok(MaterializePendingRegistrationOutcome::NotFound);
        }

        let result = match selection {
            ExchangeSelection::Ready(exchange_code) => {
                MaterializePendingRegistrationOutcome::Ready(Box::new(
                    FinalizedPendingRegistration {
                        pending: *pending,
                        exchange_code,
                    },
                ))
            }
            ExchangeSelection::Processing => MaterializePendingRegistrationOutcome::Processing,
        };
        tx.commit().await?;
        Ok(result)
    }

    async fn insert_pending_personal_key(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: i64,
        pending: &OAuthCodeData,
        now: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        if let Some(secret) = pending.pending_encrypted_secret.as_deref() {
            sqlx::query(
                "INSERT INTO personal_keys
                     (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $4)
                 ON CONFLICT (user_pubkey) DO NOTHING",
            )
            .bind(&pending.user_pubkey)
            .bind(secret)
            .bind(tenant_id)
            .bind(now)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn delete_pending_generation(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: i64,
        verification_token: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "DELETE FROM oauth_codes
             WHERE tenant_id = $1 AND pending_email_verification_token = $2",
        )
        .bind(tenant_id)
        .bind(verification_token)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Columns selected for every `OAuthCodeData` lookup (matches the struct's `FromRow` fields).
    const SELECT_COLUMNS: &'static str =
        "user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, \
         pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret, \
         previous_auth_id, state, device_code, is_headless, pin_hash, pin_attempts, \
         pin_failed_total, pin_sent_at, pin_resend_at, consumed_at, expires_at";

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
            "SELECT {} FROM oauth_codes WHERE pending_email_verification_token = $1 AND tenant_id = $2 AND pending_email IS NOT NULL AND expires_at > $3",
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

    /// Find a pending registration token even after its verification window closes.
    pub async fn find_by_verification_token_including_expired(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<OAuthCodeData>, RepositoryError> {
        let query = format!(
            "SELECT {} FROM oauth_codes
             WHERE pending_email_verification_token = $1 AND tenant_id = $2
               AND pending_email IS NOT NULL",
            Self::SELECT_COLUMNS
        );
        let result = sqlx::query_as::<_, OAuthCodeData>(&query)
            .bind(token)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result)
    }

    /// Find a pending registration by its RFC 8628 `device_code` (the 64-char app-held secret).
    ///
    /// This is the lookup gate for in-app PIN verification (keycast#262): the `device_code` is the
    /// real authenticator and the 6-digit PIN is defense-in-depth, so PIN verification MUST resolve
    /// the pending row by `device_code` rather than by a global PIN scan (which would be
    /// brute-forceable across all pending registrations). Only pending rows carry a non-null
    /// `device_code`.
    ///
    /// Deliberately does **not** filter on `expires_at`: an expired registration and an unknown
    /// `device_code` are different situations for the user, and filtering here would collapse them
    /// into one. Callers get `expires_at` on the returned row and decide. Every caller must
    /// therefore check it — reaching a registration past its window must not let the flow proceed.
    pub async fn find_by_device_code(
        &self,
        device_code: &str,
        tenant_id: i64,
    ) -> Result<Option<OAuthCodeData>, RepositoryError> {
        let query = format!(
            "SELECT {} FROM oauth_codes WHERE device_code = $1 AND tenant_id = $2 AND pending_email IS NOT NULL",
            Self::SELECT_COLUMNS
        );
        let result = sqlx::query_as::<_, OAuthCodeData>(&query)
            .bind(device_code)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(result)
    }

    /// Atomically reserve one PIN-verification attempt slot for a pending registration.
    ///
    /// Scoped to the pending registration row itself (`pending_email IS NOT NULL AND consumed_at
    /// IS NULL`): minted exchange-code rows copy `device_code` from the pending row, and a
    /// device_code-only UPDATE would mutate those siblings too.
    ///
    /// The increment happens in a single conditional `UPDATE ... RETURNING`, so both caps are
    /// enforced by the database rather than by a snapshot read. This is what bounds brute force:
    /// callers reserve a slot BEFORE running the (expensive) bcrypt comparison, so no more
    /// comparisons can ever run for a given `device_code` than the caps allow, even across
    /// concurrent verify-pin requests on different instances.
    ///
    /// # Why two caps
    ///
    /// `max_attempts` bounds guesses against the current PIN, and a resend clears it — that reset
    /// is what makes a resend the way out of a lockout. On its own, though, it is escapable: an
    /// attacker who resends whenever the per-PIN cap is spent gets a fresh PIN and a fresh cap
    /// forever, so the only real limit becomes the resend cooldown. `max_lifetime_attempts` closes
    /// that by counting failures across every PIN the registration has issued, and nothing resets
    /// it. Exhausting it disables PIN entry for this registration; the emailed link still works.
    ///
    /// # Expiry
    ///
    /// The reservation also refuses an expired registration, so this statement is authoritative
    /// rather than relying on the caller's earlier snapshot. Callers still check expiry up front to
    /// classify it before paying for bcrypt, but a window that closes between that check and this
    /// call is caught here instead of letting a comparison run against a dead registration.
    ///
    /// # Concurrency
    ///
    /// The increment and both caps are one conditional UPDATE, so row locking serializes concurrent
    /// reservations and neither cap can be exceeded. The follow-up classification is a separate
    /// read and is deliberately *not* serialized with it: it only chooses which recovery message
    /// the user sees, and under concurrency it can transiently name a cap that a simultaneous
    /// refund or resend has just reopened. That is accepted. Making the message choice
    /// transactional would add contention to the hot path to fix wording, and the caps themselves
    /// are already exact.
    pub async fn reserve_pin_attempt(
        &self,
        device_code: &str,
        tenant_id: i64,
        expected_generation_token: &str,
        max_attempts: i32,
        max_lifetime_attempts: i32,
    ) -> Result<PinAttemptReservation, RepositoryError> {
        let now = Utc::now();
        let row: Option<(i32,)> = sqlx::query_as(
            "UPDATE oauth_codes \
              SET pin_attempts = pin_attempts + 1, pin_failed_total = pin_failed_total + 1 \
              WHERE device_code = $1 AND tenant_id = $2 \
                AND pending_email_verification_token = $3 \
                AND pin_attempts < $4 AND pin_failed_total < $5 \
                AND pending_email IS NOT NULL AND consumed_at IS NULL AND expires_at > $6 \
              RETURNING pin_attempts",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .bind(max_attempts)
        .bind(max_lifetime_attempts)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((attempt,)) = row {
            return Ok(PinAttemptReservation::Reserved { attempt });
        }

        // The reservation failed. Re-read to say why, so the caller can tell the user whether a
        // resend helps. Only on the failure path, which already writes an audit record.
        let state: Option<(i32, DateTime<Utc>)> = sqlx::query_as(
            "SELECT pin_failed_total, expires_at FROM oauth_codes \
              WHERE device_code = $1 AND tenant_id = $2 \
                AND pending_email_verification_token = $3 \
                AND pending_email IS NOT NULL AND consumed_at IS NULL",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .fetch_optional(&self.pool)
        .await?;

        match state {
            Some((_, expires_at)) if expires_at <= now => Ok(PinAttemptReservation::Expired),
            Some((failed_total, _)) if failed_total >= max_lifetime_attempts => {
                Ok(PinAttemptReservation::LifetimeExhausted)
            }
            // Includes the row vanishing between the two statements: treating that as a per-PIN
            // lockout is the conservative reading, and the caller has already established the row
            // existed.
            _ => Ok(PinAttemptReservation::CurrentPinLocked),
        }
    }

    /// Refund a reserved PIN attempt when no bcrypt comparison ran.
    ///
    /// Decrements both counters, since [`Self::reserve_pin_attempt`] incremented both. The
    /// decrement is atomic so a concurrent failed comparison remains counted. The lower bounds
    /// protect the counters if a successful verification reset them before this refund completed.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when the database update fails.
    pub async fn refund_pin_attempt(
        &self,
        device_code: &str,
        tenant_id: i64,
        expected_generation_token: &str,
    ) -> Result<PinAttemptRelease, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "UPDATE oauth_codes \
             SET pin_attempts = GREATEST(pin_attempts - 1, 0), \
                 pin_failed_total = GREATEST(pin_failed_total - 1, 0) \
              WHERE device_code = $1 AND tenant_id = $2 \
                AND pending_email_verification_token = $3 \
                AND pending_email IS NOT NULL AND consumed_at IS NULL",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if current {
            tx.commit().await?;
            return Ok(PinAttemptRelease::CurrentGeneration);
        }

        let changed = Self::compensate_changed_pin_generation(
            &mut tx,
            device_code,
            tenant_id,
            expected_generation_token,
        )
        .await?;
        tx.commit().await?;
        Ok(if changed {
            PinAttemptRelease::GenerationChanged
        } else {
            PinAttemptRelease::Missing
        })
    }

    /// Re-arm a pending registration for PIN resend: install a fresh verification token + PIN hash,
    /// reset the attempt counter to zero, and stamp both `pin_sent_at` (the new PIN's validity
    /// anchor) and `pin_resend_at` (the resend-cooldown anchor).
    ///
    /// Used by the lockout-recovery path: after the attempt cap is hit, the user must request a resend
    /// which mints a new PIN and clears the lockout. Because `pin_resend_at` starts NULL at
    /// registration and is only stamped here, that first recovery resend is always available;
    /// the cooldown then bounds the ones after it.
    ///
    /// Deliberately does NOT touch `expires_at`: the pending row keeps its original 24h registration
    /// window. Otherwise repeated resends could extend a pending row indefinitely, defeating the
    /// row's finite lifecycle (keycast#262).
    ///
    /// The rewrite is applied to the pending row and to every sibling row sharing the
    /// `device_code` (unlike [`Self::reserve_pin_attempt`] / [`Self::reset_pin_attempts`], which
    /// are scoped to the pending row). That is deliberate: this rewrites
    /// `pending_email_verification_token`, which minted sibling exchange-code rows copy and which
    /// redemption correlates on (see [`Self::mark_pending_consumed`]). Restricting the rewrite to
    /// the pending row would desynchronize the token between a pre-resend minted code and the
    /// pending row, so redeeming that code would no longer mark the registration consumed. If you
    /// need to narrow this, change the redemption correlation key first.
    ///
    /// # Cooldown claim
    ///
    /// The cooldown is enforced *here* by the conditional pending-row lock, and the whole rewrite
    /// runs in one transaction. Returns `true` only if this call won the claim.
    ///
    /// Checking the cooldown with a separate read first would be a time-of-check/time-of-use gap:
    /// two concurrent resends could both observe an expired cooldown, both mint a PIN, both send an
    /// email, and leave whichever UPDATE landed last as the only valid PIN — so a user could be
    /// looking at a freshly delivered code that does not work. Callers may still do a cheap
    /// pre-check to avoid paying for bcrypt, but this claim is what actually decides.
    pub async fn reset_pin_for_resend(
        &self,
        device_code: &str,
        tenant_id: i64,
        expected_generation_token: &str,
        new_verification_token: &str,
        new_pin_hash: &str,
        cooldown_cutoff: DateTime<Utc>,
    ) -> Result<bool, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        // Lock the exact pending generation before inspecting exchange claims. Under READ
        // COMMITTED, the separate claim query below then gets a new snapshot after any redemption
        // that held this lock has committed.
        let locked: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM oauth_codes \
             WHERE device_code = $1 AND tenant_id = $2 \
               AND pending_email_verification_token = $3 \
               AND pending_email IS NOT NULL AND consumed_at IS NULL \
               AND expires_at > clock_timestamp() \
               AND (pin_resend_at IS NULL OR pin_resend_at <= $4) \
             FOR UPDATE",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .bind(cooldown_cutoff)
        .fetch_optional(&mut *tx)
        .await?;

        if locked.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }

        let consumed_claim: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM oauth_codes exchange \
                 WHERE exchange.tenant_id = $1 AND exchange.device_code = $2 \
                   AND exchange.pending_email_verification_token = $3 \
                   AND exchange.pending_email IS NULL \
                   AND exchange.consumed_at IS NOT NULL \
                   AND exchange.expires_at > clock_timestamp() \
             )",
        )
        .bind(tenant_id)
        .bind(device_code)
        .bind(expected_generation_token)
        .fetch_one(&mut *tx)
        .await?;
        if consumed_claim {
            tx.rollback().await?;
            return Ok(false);
        }

        let claimed = sqlx::query(
            "UPDATE oauth_codes \
             SET pending_email_verification_token = $1, pin_hash = $2, pin_attempts = 0, \
                 pin_sent_at = NULL, pin_resend_at = clock_timestamp() \
             WHERE device_code = $3 AND tenant_id = $4 \
               AND pending_email_verification_token = $5 \
               AND pending_email IS NOT NULL AND consumed_at IS NULL \
               AND expires_at > clock_timestamp() \
               AND (pin_resend_at IS NULL OR pin_resend_at <= $6)",
        )
        .bind(new_verification_token)
        .bind(new_pin_hash)
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .bind(cooldown_cutoff)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !claimed {
            tx.rollback().await?;
            return Ok(false);
        }

        // Keep sibling exchange-code rows correlated with the pending row's new token.
        sqlx::query(
            "UPDATE oauth_codes SET pending_email_verification_token = $1 \
              WHERE device_code = $2 AND tenant_id = $3 \
                AND pending_email_verification_token = $4 \
                AND pending_email IS NULL AND consumed_at IS NULL",
        )
        .bind(new_verification_token)
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Restore PIN resend fields after replacement email delivery fails.
    ///
    /// Like [`Self::reset_pin_for_resend`], the restore covers the pending row and its sibling
    /// exchange-code rows, so it undoes that call's token rewrite everywhere (see the coupling note
    /// there).
    ///
    /// `expected_verification_token` and `expected_pin_hash` identify the generation the failing
    /// call itself wrote. The restore applies only while both values are still current, so a resend
    /// whose delivery failed can never roll back over a later resend that already succeeded and put
    /// a different PIN in the user's inbox. Returns `true` if the restore applied.
    pub async fn restore_pin_after_failed_resend(
        &self,
        device_code: &str,
        tenant_id: i64,
        previous: PinResendSnapshot<'_>,
        expected_verification_token: &str,
        expected_pin_hash: &str,
    ) -> Result<bool, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let locked: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM oauth_codes \
             WHERE device_code = $1 AND tenant_id = $2 \
               AND pending_email IS NOT NULL AND consumed_at IS NULL \
               AND pin_hash = $3 AND pending_email_verification_token = $4 \
             FOR UPDATE",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_pin_hash)
        .bind(expected_verification_token)
        .fetch_optional(&mut *tx)
        .await?;
        if locked.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }

        let consumed_claim: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM oauth_codes exchange \
                 WHERE exchange.tenant_id = $1 AND exchange.device_code = $2 \
                   AND exchange.pending_email_verification_token = $3 \
                   AND exchange.pending_email IS NULL \
                   AND exchange.consumed_at IS NOT NULL \
                   AND exchange.expires_at > clock_timestamp() \
             )",
        )
        .bind(tenant_id)
        .bind(device_code)
        .bind(expected_verification_token)
        .fetch_one(&mut *tx)
        .await?;
        if consumed_claim {
            tx.rollback().await?;
            return Ok(false);
        }

        let restored = sqlx::query(
            "UPDATE oauth_codes \
             SET pending_email_verification_token = $1, pin_hash = $2, pin_attempts = $3, \
                  pin_sent_at = $4, pin_resend_at = $5 \
              WHERE device_code = $6 AND tenant_id = $7 \
                AND pending_email IS NOT NULL AND consumed_at IS NULL \
                AND pin_hash = $8 AND pending_email_verification_token = $9",
        )
        .bind(previous.verification_token)
        .bind(previous.pin_hash)
        .bind(previous.pin_attempts)
        .bind(previous.pin_sent_at)
        .bind(previous.pin_resend_at)
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_pin_hash)
        .bind(expected_verification_token)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;

        if !restored {
            tx.rollback().await?;
            return Ok(false);
        }

        sqlx::query(
            "UPDATE oauth_codes SET pending_email_verification_token = $1 \
             WHERE device_code = $2 AND tenant_id = $3 \
               AND pending_email_verification_token = $4 \
               AND pending_email IS NULL AND consumed_at IS NULL",
        )
        .bind(previous.verification_token)
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_verification_token)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Mark that a PIN email was successfully handed to the delivery provider.
    pub async fn mark_pin_sent(
        &self,
        device_code: &str,
        tenant_id: i64,
        expected_verification_token: &str,
    ) -> Result<bool, RepositoryError> {
        let marked = sqlx::query(
            "UPDATE oauth_codes SET pin_sent_at = $1 \
             WHERE device_code = $2 AND tenant_id = $3 \
               AND pending_email_verification_token = $4 \
               AND pending_email IS NOT NULL AND consumed_at IS NULL",
        )
        .bind(Utc::now())
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_verification_token)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;
        Ok(marked)
    }

    /// Clear the failed-attempt counter for a pending registration after a correct PIN (keycast#262).
    ///
    /// `reserve_pin_attempt` increments `pin_attempts` before every bcrypt compare, including the
    /// successful one, so a verified registration would otherwise carry that success toward the
    /// lockout cap and a duplicate/retried verify of the same correct PIN could spuriously lock out.
    /// Resetting to zero on success keeps the invariant that only *failed* attempts lock, without
    /// weakening the brute-force cap: this is reachable only with a correct PIN.
    ///
    /// Both counters are decremented by one rather than zeroed, undoing exactly the increment this
    /// successful attempt made. Zeroing `pin_failed_total` would let a correct PIN wipe the
    /// registration's lifetime guessing record, and that record is meant to survive everything.
    ///
    /// Scoped to the live pending registration row like [`Self::reserve_pin_attempt`]; minted
    /// sibling exchange-code rows share the `device_code` and must not be touched.
    pub async fn reset_pin_attempts(
        &self,
        device_code: &str,
        tenant_id: i64,
        expected_generation_token: &str,
    ) -> Result<PinAttemptRelease, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "UPDATE oauth_codes \
              SET pin_attempts = 0, pin_failed_total = GREATEST(pin_failed_total - 1, 0) \
              WHERE device_code = $1 AND tenant_id = $2 \
                AND pending_email_verification_token = $3 \
                AND pending_email IS NOT NULL AND consumed_at IS NULL",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if current {
            tx.commit().await?;
            return Ok(PinAttemptRelease::CurrentGeneration);
        }

        let changed = Self::compensate_changed_pin_generation(
            &mut tx,
            device_code,
            tenant_id,
            expected_generation_token,
        )
        .await?;
        tx.commit().await?;
        Ok(if changed {
            PinAttemptRelease::GenerationChanged
        } else {
            PinAttemptRelease::Missing
        })
    }

    async fn compensate_changed_pin_generation(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        device_code: &str,
        tenant_id: i64,
        expected_generation_token: &str,
    ) -> Result<bool, RepositoryError> {
        let compensated = sqlx::query(
            "UPDATE oauth_codes
             SET pin_failed_total = GREATEST(pin_failed_total - 1, 0)
             WHERE device_code = $1 AND tenant_id = $2
               AND pending_email_verification_token IS DISTINCT FROM $3
               AND pending_email IS NOT NULL AND consumed_at IS NULL",
        )
        .bind(device_code)
        .bind(tenant_id)
        .bind(expected_generation_token)
        .execute(&mut **tx)
        .await?
        .rows_affected()
            == 1;
        Ok(compensated)
    }

    /// Find a still-live exchange code matching the same pending registration semantics.
    pub async fn find_live_exchange_code_with_expiry_for_pending(
        &self,
        tenant_id: i64,
        pending: &OAuthCodeData,
    ) -> Result<Option<(String, DateTime<Utc>)>, RepositoryError> {
        let now = Utc::now();
        let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT exchange.code, exchange.expires_at FROM oauth_codes exchange
             WHERE exchange.tenant_id = $1
               AND exchange.user_pubkey = $2
               AND exchange.client_id = $3
               AND exchange.redirect_uri = $4
               AND exchange.scope = $5
               AND exchange.code_challenge IS NOT DISTINCT FROM $6
               AND exchange.code_challenge_method IS NOT DISTINCT FROM $7
               AND exchange.state IS NOT DISTINCT FROM $8
               AND exchange.is_headless = $9
               AND exchange.pending_email_verification_token IS NOT DISTINCT FROM $11
               AND exchange.device_code IS NOT DISTINCT FROM $12
               AND exchange.pending_email IS NULL
               AND exchange.consumed_at IS NULL
               AND exchange.expires_at > $10
               AND EXISTS (
                   SELECT 1 FROM oauth_codes pending_row
                   WHERE pending_row.tenant_id = $1
                     AND pending_row.user_pubkey = $2
                     AND pending_row.client_id = $3
                     AND pending_row.redirect_uri = $4
                     AND pending_row.scope = $5
                     AND pending_row.code_challenge IS NOT DISTINCT FROM $6
                     AND pending_row.code_challenge_method IS NOT DISTINCT FROM $7
                     AND pending_row.state IS NOT DISTINCT FROM $8
                     AND pending_row.is_headless = $9
                     AND pending_row.pending_email IS NOT NULL
                     AND pending_row.pending_email_verification_token IS NOT DISTINCT FROM $11
                     AND pending_row.device_code IS NOT DISTINCT FROM $12
                     AND pending_row.consumed_at IS NULL
                     AND pending_row.expires_at > $10
               )
             ORDER BY exchange.created_at DESC
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(&pending.user_pubkey)
        .bind(&pending.client_id)
        .bind(&pending.redirect_uri)
        .bind(&pending.scope)
        .bind(pending.code_challenge.as_deref())
        .bind(pending.code_challenge_method.as_deref())
        .bind(pending.state.as_deref())
        .bind(pending.is_headless)
        .bind(now)
        .bind(pending.pending_email_verification_token.as_deref())
        .bind(pending.device_code.as_deref())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Claim an exchange code while locking its exact pending generation.
    pub async fn redeem_code(
        &self,
        tenant_id: i64,
        code: &str,
        auth_code: &OAuthCodeData,
    ) -> Result<bool, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        if auth_code.pending_email_verification_token.is_some() {
            let pending_exists: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM oauth_codes
                 WHERE tenant_id = $1
                   AND user_pubkey = $2
                   AND client_id = $3
                   AND redirect_uri = $4
                   AND scope = $5
                   AND code_challenge IS NOT DISTINCT FROM $6
                   AND code_challenge_method IS NOT DISTINCT FROM $7
                   AND state IS NOT DISTINCT FROM $8
                   AND is_headless = $9
                   AND pending_email IS NOT NULL
                    AND pending_email_verification_token IS NOT DISTINCT FROM $10
                    AND device_code IS NOT DISTINCT FROM $11
                    AND consumed_at IS NULL
                    AND expires_at > clock_timestamp()
                  FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(&auth_code.user_pubkey)
            .bind(&auth_code.client_id)
            .bind(&auth_code.redirect_uri)
            .bind(&auth_code.scope)
            .bind(auth_code.code_challenge.as_deref())
            .bind(auth_code.code_challenge_method.as_deref())
            .bind(auth_code.state.as_deref())
            .bind(auth_code.is_headless)
            .bind(auth_code.pending_email_verification_token.as_deref())
            .bind(auth_code.device_code.as_deref())
            .fetch_optional(&mut *tx)
            .await?;

            if pending_exists.is_none() {
                tx.rollback().await?;
                return Ok(false);
            }
        }

        let claimed = sqlx::query(
            "UPDATE oauth_codes
             SET consumed_at = clock_timestamp()
             WHERE tenant_id = $1 AND code = $2
               AND user_pubkey = $3 AND client_id = $4 AND redirect_uri = $5 AND scope = $6
               AND code_challenge IS NOT DISTINCT FROM $7
               AND code_challenge_method IS NOT DISTINCT FROM $8
               AND state IS NOT DISTINCT FROM $9 AND is_headless = $10
               AND pending_email_verification_token IS NOT DISTINCT FROM $11
               AND device_code IS NOT DISTINCT FROM $12
               AND pending_email IS NULL AND consumed_at IS NULL
               AND expires_at > clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(code)
        .bind(&auth_code.user_pubkey)
        .bind(&auth_code.client_id)
        .bind(&auth_code.redirect_uri)
        .bind(&auth_code.scope)
        .bind(auth_code.code_challenge.as_deref())
        .bind(auth_code.code_challenge_method.as_deref())
        .bind(auth_code.state.as_deref())
        .bind(auth_code.is_headless)
        .bind(auth_code.pending_email_verification_token.as_deref())
        .bind(auth_code.device_code.as_deref())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;

        if !claimed {
            tx.rollback().await?;
            return Ok(false);
        }

        tx.commit().await?;
        Ok(true)
    }

    /// Release a failed token-issuance claim so the same code can retry.
    pub async fn release_redeemed_code(
        &self,
        tenant_id: i64,
        code: &str,
        auth_code: &OAuthCodeData,
    ) -> Result<bool, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        if auth_code.pending_email_verification_token.is_some() {
            let locked: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM oauth_codes
                 WHERE tenant_id = $1 AND user_pubkey = $2 AND client_id = $3
                   AND redirect_uri = $4 AND scope = $5
                   AND code_challenge IS NOT DISTINCT FROM $6
                   AND code_challenge_method IS NOT DISTINCT FROM $7
                   AND state IS NOT DISTINCT FROM $8 AND is_headless = $9
                   AND pending_email IS NOT NULL
                   AND pending_email_verification_token IS NOT DISTINCT FROM $10
                   AND device_code IS NOT DISTINCT FROM $11
                   AND consumed_at IS NULL AND expires_at > clock_timestamp()
                 FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(&auth_code.user_pubkey)
            .bind(&auth_code.client_id)
            .bind(&auth_code.redirect_uri)
            .bind(&auth_code.scope)
            .bind(auth_code.code_challenge.as_deref())
            .bind(auth_code.code_challenge_method.as_deref())
            .bind(auth_code.state.as_deref())
            .bind(auth_code.is_headless)
            .bind(auth_code.pending_email_verification_token.as_deref())
            .bind(auth_code.device_code.as_deref())
            .fetch_optional(&mut *tx)
            .await?;
            if locked.is_none() {
                tx.rollback().await?;
                return Ok(false);
            }
        }

        let released = sqlx::query(
            "UPDATE oauth_codes SET consumed_at = NULL
             WHERE tenant_id = $1 AND code = $2
               AND user_pubkey = $3 AND client_id = $4 AND redirect_uri = $5 AND scope = $6
               AND pending_email_verification_token IS NOT DISTINCT FROM $7
               AND device_code IS NOT DISTINCT FROM $8
               AND pending_email IS NULL AND consumed_at IS NOT NULL
               AND expires_at > clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(code)
        .bind(&auth_code.user_pubkey)
        .bind(&auth_code.client_id)
        .bind(&auth_code.redirect_uri)
        .bind(&auth_code.scope)
        .bind(auth_code.pending_email_verification_token.as_deref())
        .bind(auth_code.device_code.as_deref())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        tx.commit().await?;
        Ok(released)
    }

    /// Mark the pending registration associated with a successfully issued exchange code as
    /// terminal. Returns `false` if the pending row is missing or already consumed.
    pub async fn mark_pending_consumed(
        &self,
        tenant_id: i64,
        code: &str,
        auth_code: &OAuthCodeData,
    ) -> Result<bool, RepositoryError> {
        if auth_code.pending_email_verification_token.is_none() {
            return Ok(true);
        }

        let updated = sqlx::query(
            "UPDATE oauth_codes SET consumed_at = $1
             WHERE tenant_id = $2
               AND user_pubkey = $3
               AND client_id = $4
               AND redirect_uri = $5
               AND scope = $6
               AND code_challenge IS NOT DISTINCT FROM $7
               AND code_challenge_method IS NOT DISTINCT FROM $8
               AND state IS NOT DISTINCT FROM $9
               AND is_headless = $10
               AND pending_email IS NOT NULL
                AND pending_email_verification_token IS NOT DISTINCT FROM $11
                AND device_code IS NOT DISTINCT FROM $12
                AND consumed_at IS NULL
                AND EXISTS (
                    SELECT 1 FROM oauth_codes exchange
                    WHERE exchange.tenant_id = $2 AND exchange.code = $13
                      AND exchange.pending_email IS NULL
                      AND exchange.pending_email_verification_token IS NOT DISTINCT FROM $11
                      AND exchange.device_code IS NOT DISTINCT FROM $12
                      AND exchange.consumed_at IS NOT NULL
                      AND exchange.expires_at > clock_timestamp()
                )",
        )
        .bind(Utc::now())
        .bind(tenant_id)
        .bind(&auth_code.user_pubkey)
        .bind(&auth_code.client_id)
        .bind(&auth_code.redirect_uri)
        .bind(&auth_code.scope)
        .bind(auth_code.code_challenge.as_deref())
        .bind(auth_code.code_challenge_method.as_deref())
        .bind(auth_code.state.as_deref())
        .bind(auth_code.is_headless)
        .bind(auth_code.pending_email_verification_token.as_deref())
        .bind(auth_code.device_code.as_deref())
        .bind(code)
        .execute(&self.pool)
        .await?;

        Ok(updated.rows_affected() == 1)
    }

    /// Delete dead rows: anything past its expiry, plus consumed pending registrations (terminal
    /// once their exchange code successfully issued tokens). Bounds table growth and enforces the pending row's
    /// finite lifecycle (keycast#262). Returns the number of rows removed.
    pub async fn delete_expired_and_consumed(&self) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM oauth_codes
             WHERE expires_at < $1
                OR (pending_email IS NOT NULL AND consumed_at IS NOT NULL)",
        )
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
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
    use serial_test::serial;

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

    async fn insert_and_finalize_registration(
        repo: &OAuthCodeRepository,
        device_code: &str,
    ) -> FinalizedPendingRegistration {
        let (token, _) = insert_pending_registration(
            repo,
            device_code,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        let candidate = format!("exchange_{}", uuid::Uuid::new_v4());
        let outcome = repo
            .materialize_pending_registration(1, &token, &candidate)
            .await
            .unwrap();
        let MaterializePendingRegistrationOutcome::Ready(finalized) = outcome else {
            panic!("test registration must finalize");
        };
        *finalized
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

    // Serialized against `test_delete_expired_and_consumed_removes_dead_rows`: that cleanup is
    // global by design, so an expired fixture is fair game for it while both run concurrently.
    #[serial]
    #[tokio::test]
    async fn test_find_by_device_code_returns_expired_rows_for_the_caller_to_judge() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() - chrono::Duration::hours(1); // already expired
        insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;

        // The lookup returns the expired row and reports its window, rather than hiding it. An
        // expired registration and an unknown device_code are different situations for the user,
        // and filtering here would collapse them into one — so callers decide instead.
        let found = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .expect("an expired pending row is still returned, so callers can tell it apart");
        assert!(
            found.expires_at <= Utc::now(),
            "the caller must be able to see that the window has closed"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_materialization_lock_blocks_then_rejects_supersession() {
        use nostr_sdk::Keys;
        use tokio::time::{sleep, timeout, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let (token, email) =
            insert_pending_registration(&repo, &device_code, Some("old-pin"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&pending.user_pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // Hold the users row so materialization pauses after acquiring the pending-row lock.
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pubkey FROM users WHERE pubkey = $1 FOR UPDATE")
            .bind(&pending.user_pubkey)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();

        let materialize_repo = repo.clone();
        let materialize_token = token.clone();
        let candidate = format!("exchange_{}", uuid::Uuid::new_v4());
        let materializer = tokio::spawn(async move {
            materialize_repo
                .materialize_pending_registration(1, &materialize_token, &candidate)
                .await
        });

        // Wait until PostgreSQL confirms materialization is blocked on the users row. At this
        // point its transaction already owns the pending-row FOR UPDATE lock.
        let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity activity
                    WHERE cardinality(pg_blocking_pids(activity.pid)) > 0
                      AND activity.query LIKE '%SELECT u.email, u.email_verified%'
                )",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < wait_deadline,
                "materialization did not reach the users-row lock"
            );
            sleep(Duration::from_millis(10)).await;
        }

        let replacement_pubkey = Keys::generate().public_key().to_hex();
        let replacement_device = format!("replacement_{}", uuid::Uuid::new_v4());
        let supersede_repo = repo.clone();
        let supersede_email = email.clone();
        let mut supersession = tokio::spawn(async move {
            supersede_repo
                .store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
                    tenant_id: 1,
                    code: "replacement-code",
                    user_pubkey: &replacement_pubkey,
                    client_id: "replacement-client",
                    redirect_uri: "http://localhost:3000/replacement",
                    scope: "policy:social",
                    code_challenge: None,
                    code_challenge_method: None,
                    expires_at: Utc::now() + chrono::Duration::hours(24),
                    pending_email: &supersede_email,
                    pending_password_hash: "replacement-hash",
                    pending_email_verification_token: "replacement-token",
                    pending_encrypted_secret: Some(b"replacement-secret"),
                    state: None,
                    device_code: Some(&replacement_device),
                    is_headless: true,
                    pin_hash: Some("replacement-pin"),
                })
                .await
        });

        assert!(
            timeout(Duration::from_millis(100), &mut supersession)
                .await
                .is_err(),
            "supersession must wait on the pending row while materialization is in progress"
        );

        blocker.commit().await.unwrap();
        assert!(matches!(
            materializer.await.unwrap().unwrap(),
            MaterializePendingRegistrationOutcome::Ready(_)
        ));

        let supersession_result = supersession.await.unwrap();
        assert!(
            matches!(supersession_result, Err(RepositoryError::Duplicate)),
            "supersession must be rejected after materialization, got {supersession_result:?}"
        );
        let surviving = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(surviving.user_pubkey, pending.user_pubkey);
        assert_eq!(
            surviving.pending_email_verification_token.as_deref(),
            Some(token.as_str())
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_materialization_rolls_back_if_registration_expires_while_waiting() {
        use tokio::time::{sleep, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::milliseconds(300);
        let (token, _) =
            insert_pending_registration(&repo, &device_code, Some("pin"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&pending.user_pubkey)
        .execute(&pool)
        .await
        .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pubkey FROM users WHERE pubkey = $1 FOR UPDATE")
            .bind(&pending.user_pubkey)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();

        let materialize_repo = repo.clone();
        let candidate = format!("exchange_{}", uuid::Uuid::new_v4());
        let materializer = tokio::spawn(async move {
            materialize_repo
                .materialize_pending_registration(1, &token, &candidate)
                .await
        });
        let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity activity
                    WHERE cardinality(pg_blocking_pids(activity.pid)) > 0
                      AND activity.query LIKE '%SELECT u.email, u.email_verified%'
                )",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            assert!(tokio::time::Instant::now() < wait_deadline);
            sleep(Duration::from_millis(10)).await;
        }
        loop {
            let expired: bool = sqlx::query_scalar("SELECT clock_timestamp() >= $1")
                .bind(expires_at)
                .fetch_one(&pool)
                .await
                .unwrap();
            if expired {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        blocker.commit().await.unwrap();
        assert!(matches!(
            materializer.await.unwrap().unwrap(),
            MaterializePendingRegistrationOutcome::NotFound
        ));
        let user: (Option<String>, Option<String>, bool) = sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users
             WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pending.user_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        let key_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pending.user_pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        let exchange_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE device_code = $1 AND pending_email IS NULL",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(user, (None, None, false));
        assert_eq!(key_count, 0);
        assert_eq!(exchange_count, 0);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_materialization_completes_with_one_pool_connection() {
        use sqlx::postgres::PgPoolOptions;

        let pool = setup_pool().await;
        let setup_repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (token, _) = insert_pending_registration(
            &setup_repo,
            &device_code,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        let pending = setup_repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        let one_connection_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .unwrap();
        let outcome = OAuthCodeRepository::new(one_connection_pool)
            .materialize_pending_registration(1, &token, "one-connection-exchange")
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            MaterializePendingRegistrationOutcome::Ready(_)
        ));

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_exact_generation_materializers_are_idempotent() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (token, _) = insert_pending_registration(
            &repo,
            &device_code,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();

        let candidate_a = format!("exchange_a_{}", uuid::Uuid::new_v4());
        let candidate_b = format!("exchange_b_{}", uuid::Uuid::new_v4());
        let (first, second) = tokio::join!(
            repo.materialize_pending_registration(1, &token, &candidate_a),
            repo.materialize_pending_registration(1, &token, &candidate_b),
        );
        let MaterializePendingRegistrationOutcome::Ready(first) = first.unwrap() else {
            panic!("first finalizer must be ready");
        };
        let MaterializePendingRegistrationOutcome::Ready(second) = second.unwrap() else {
            panic!("second finalizer must be ready");
        };
        assert_eq!(first.exchange_code.code, second.exchange_code.code);

        let user_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pending.user_pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        let key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pending.user_pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(user_count, 1);
        assert_eq!(key_count, 1);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pending.user_pubkey)
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
        let (token, _) =
            insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;

        // Reserve up to the cap; each call returns the post-increment count. The lifetime cap is
        // set far out of the way so this test isolates the per-PIN cap.
        let max = 3;
        const LIFETIME: i32 = 1000;
        let first = repo
            .reserve_pin_attempt(&device_code, 1, &token, max, LIFETIME)
            .await
            .unwrap();
        assert_eq!(first, PinAttemptReservation::Reserved { attempt: 1 });
        let second = repo
            .reserve_pin_attempt(&device_code, 1, &token, max, LIFETIME)
            .await
            .unwrap();
        assert_eq!(second, PinAttemptReservation::Reserved { attempt: 2 });
        let third = repo
            .reserve_pin_attempt(&device_code, 1, &token, max, LIFETIME)
            .await
            .unwrap();
        assert_eq!(third, PinAttemptReservation::Reserved { attempt: 3 });

        // At the cap: no slot can be reserved (atomic lockout), and the counter does not grow.
        let locked = repo
            .reserve_pin_attempt(&device_code, 1, &token, max, LIFETIME)
            .await
            .unwrap();
        assert_eq!(
            locked,
            PinAttemptReservation::CurrentPinLocked,
            "reserve must refuse once at the per-PIN cap"
        );
        let after = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.pin_attempts, max, "counter must not exceed the cap");

        // Unknown device_code reserves nothing.
        let none = repo
            .reserve_pin_attempt("nonexistent", 1, "missing-token", max, LIFETIME)
            .await
            .unwrap();
        assert_eq!(none, PinAttemptReservation::CurrentPinLocked);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_reset_pin_attempts_clears_counter() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        let (token, _) =
            insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;

        // Burn a couple of attempt slots (as a near-success run would), then reset on success.
        repo.reserve_pin_attempt(&device_code, 1, &token, 5, 1000)
            .await
            .unwrap();
        repo.reserve_pin_attempt(&device_code, 1, &token, 5, 1000)
            .await
            .unwrap();
        let before = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.pin_attempts, 2, "attempts accumulated before reset");
        assert_eq!(
            before.pin_failed_total, 2,
            "lifetime counter tracked them too"
        );

        repo.reset_pin_attempts(&device_code, 1, &token)
            .await
            .unwrap();

        let after = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.pin_attempts, 0,
            "successful verify must clear the failed-attempt counter"
        );
        // The lifetime counter gives back exactly the one slot the successful attempt reserved. It
        // must not be zeroed: a correct PIN cannot be allowed to wipe the registration's record of
        // how much guessing it has already absorbed.
        assert_eq!(
            after.pin_failed_total, 1,
            "successful verify releases only its own reservation from the lifetime counter"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_queue_rejection_after_supersession_compensates_lifetime_only() {
        use nostr_sdk::Keys;

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (stale_token, email) = insert_pending_registration(
            &repo,
            &device_code,
            Some("stale-pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        assert_eq!(
            repo.reserve_pin_attempt(&device_code, 1, &stale_token, 5, 50)
                .await
                .unwrap(),
            PinAttemptReservation::Reserved { attempt: 1 }
        );

        let replacement_pubkey = Keys::generate().public_key().to_hex();
        let replacement_device = format!("replacement_{}", uuid::Uuid::new_v4());
        let replacement_token = format!("replacement_{}", uuid::Uuid::new_v4());
        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: "replacement-code",
            user_pubkey: &replacement_pubkey,
            client_id: "replacement-client",
            redirect_uri: "http://localhost:3000/replacement",
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            pending_email: &email,
            pending_password_hash: "replacement-hash",
            pending_email_verification_token: &replacement_token,
            pending_encrypted_secret: Some(b"replacement-secret"),
            state: None,
            device_code: Some(&replacement_device),
            is_headless: true,
            pin_hash: Some("replacement-pin"),
        })
        .await
        .unwrap();

        assert_eq!(
            repo.refund_pin_attempt(&device_code, 1, &stale_token)
                .await
                .unwrap(),
            PinAttemptRelease::GenerationChanged
        );

        let current = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.pending_email_verification_token.as_deref(),
            Some(replacement_token.as_str())
        );
        assert_eq!((current.pin_attempts, current.pin_failed_total), (0, 0));

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_correct_old_pin_after_supersession_compensates_lifetime_only() {
        use nostr_sdk::Keys;

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (stale_token, email) = insert_pending_registration(
            &repo,
            &device_code,
            Some("stale-pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        assert_eq!(
            repo.reserve_pin_attempt(&device_code, 1, &stale_token, 5, 50)
                .await
                .unwrap(),
            PinAttemptReservation::Reserved { attempt: 1 }
        );

        let replacement_pubkey = Keys::generate().public_key().to_hex();
        let replacement_device = format!("replacement_{}", uuid::Uuid::new_v4());
        let replacement_token = format!("replacement_{}", uuid::Uuid::new_v4());
        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: "replacement-code-correct-pin",
            user_pubkey: &replacement_pubkey,
            client_id: "replacement-client",
            redirect_uri: "http://localhost:3000/replacement",
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            pending_email: &email,
            pending_password_hash: "replacement-hash",
            pending_email_verification_token: &replacement_token,
            pending_encrypted_secret: Some(b"replacement-secret"),
            state: None,
            device_code: Some(&replacement_device),
            is_headless: true,
            pin_hash: Some("replacement-pin"),
        })
        .await
        .unwrap();

        assert_eq!(
            repo.reset_pin_attempts(&device_code, 1, &stale_token)
                .await
                .unwrap(),
            PinAttemptRelease::GenerationChanged
        );
        let current = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.pin_hash.as_deref(), Some("replacement-pin"));
        assert_eq!((current.pin_attempts, current.pin_failed_total), (0, 0));

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_pin_attempt_ops_target_only_live_pending_row() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash123"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();

        // Mint a sibling exchange-code row: it copies device_code (and the verification token)
        // from the pending row but is not itself a pending registration (pending_email is NULL).
        let minted_code = format!("minted_{}", uuid::Uuid::new_v4());
        let stored = repo
            .store_for_pending_registration(
                StoreOAuthCodeParams {
                    tenant_id: 1,
                    code: &minted_code,
                    user_pubkey: &pending.user_pubkey,
                    client_id: &pending.client_id,
                    redirect_uri: &pending.redirect_uri,
                    scope: &pending.scope,
                    code_challenge: None,
                    code_challenge_method: None,
                    expires_at: Utc::now() + chrono::Duration::minutes(10),
                    previous_auth_id: None,
                    state: None,
                    is_headless: true,
                },
                &pending,
            )
            .await
            .unwrap();
        assert!(stored, "sibling exchange code should be minted");

        let sibling_attempts = |pool: PgPool, code: String| async move {
            let row: (i32,) =
                sqlx::query_as("SELECT pin_attempts FROM oauth_codes WHERE code = $1")
                    .bind(&code)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            row.0
        };

        // Reserving an attempt must touch only the pending row, never the minted sibling.
        let reserved = repo
            .reserve_pin_attempt(
                &device_code,
                1,
                pending.pending_email_verification_token.as_deref().unwrap(),
                5,
                1000,
            )
            .await
            .unwrap();
        assert_eq!(reserved, PinAttemptReservation::Reserved { attempt: 1 });
        assert_eq!(
            sibling_attempts(pool.clone(), minted_code.clone()).await,
            0,
            "reserve_pin_attempt must not increment the minted sibling row"
        );

        // Resetting on success must also leave the sibling row alone.
        sqlx::query("UPDATE oauth_codes SET pin_attempts = 2 WHERE code = $1")
            .bind(&minted_code)
            .execute(&pool)
            .await
            .unwrap();
        repo.reset_pin_attempts(
            &device_code,
            1,
            pending.pending_email_verification_token.as_deref().unwrap(),
        )
        .await
        .unwrap();
        let pending_after = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending_after.pin_attempts, 0);
        assert_eq!(
            sibling_attempts(pool.clone(), minted_code.clone()).await,
            2,
            "reset_pin_attempts must not touch the minted sibling row"
        );

        // Once the registration is consumed (token issuance succeeded), no attempt slot may be
        // reserved: the terminal marker must end the PIN lifecycle too.
        sqlx::query("UPDATE oauth_codes SET consumed_at = NOW() WHERE device_code = $1 AND pending_email IS NOT NULL")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        let after_consumed = repo
            .reserve_pin_attempt(
                &device_code,
                1,
                pending.pending_email_verification_token.as_deref().unwrap(),
                5,
                1000,
            )
            .await
            .unwrap();
        assert_eq!(
            after_consumed,
            PinAttemptReservation::CurrentPinLocked,
            "reserve_pin_attempt must not reserve a slot on a consumed registration"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The reservation itself refuses an expired registration, so the expiry decision does not rest
    /// on the caller's earlier snapshot. Without this, a window closing between the caller's check
    /// and the reservation would let a bcrypt comparison run against a dead registration and be
    /// reported as a wrong PIN.
    // Serialized against `test_delete_expired_and_consumed_removes_dead_rows`: that cleanup is
    // global by design, so an expired fixture is fair game for it while both run concurrently.
    #[serial]
    #[tokio::test]
    async fn test_reserve_pin_attempt_refuses_an_expired_registration() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (token, _) = insert_pending_registration(
            &repo,
            &device_code,
            Some("pinhash123"),
            Utc::now() - chrono::Duration::minutes(1),
        )
        .await;

        let outcome = repo
            .reserve_pin_attempt(&device_code, 1, &token, 5, 50)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            PinAttemptReservation::Expired,
            "an expired registration must be refused, and named as expired rather than as locked"
        );

        let after = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (after.pin_attempts, after.pin_failed_total),
            (0, 0),
            "a refused reservation must not charge either counter"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The cooldown must be claimed by the same statement that rotates the credentials. Checking it
    /// with a separate read first would let two concurrent resends both mint a PIN and both send an
    /// email, leaving whichever UPDATE landed last as the only valid one — so a user could be
    /// holding a code that was just mailed to them and does not work.
    #[tokio::test]
    async fn test_concurrent_resends_only_one_wins_the_cooldown_claim() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (expected_generation, _) = insert_pending_registration(
            &repo,
            &device_code,
            Some("oldpin"),
            Utc::now() + chrono::Duration::hours(12),
        )
        .await;

        // Both callers pass the same cutoff, exactly as two requests arriving together would.
        let cutoff = Utc::now();
        let token_a = format!("verif_a_{}", uuid::Uuid::new_v4());
        let token_b = format!("verif_b_{}", uuid::Uuid::new_v4());

        let (a, b) = tokio::join!(
            repo.reset_pin_for_resend(
                &device_code,
                1,
                &expected_generation,
                &token_a,
                "pin_a",
                cutoff
            ),
            repo.reset_pin_for_resend(
                &device_code,
                1,
                &expected_generation,
                &token_b,
                "pin_b",
                cutoff
            ),
        );
        let (a, b) = (a.unwrap(), b.unwrap());

        assert!(
            a ^ b,
            "exactly one concurrent resend may claim the cooldown, got a={a} b={b}"
        );

        // The row must agree with whichever caller was told it won.
        let winner_pin = if a { "pin_a" } else { "pin_b" };
        let winner_token = if a { &token_a } else { &token_b };
        let data = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .expect("pending row still exists");
        assert_eq!(
            data.pin_hash.as_deref(),
            Some(winner_pin),
            "the stored PIN must be the one the winning caller was told it installed"
        );
        assert_eq!(
            data.pending_email_verification_token.as_deref(),
            Some(winner_token.as_str())
        );

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
        // Original registration window: an exact, known expiry we can assert stays put.
        let expires_at = Utc::now() + chrono::Duration::hours(12);
        let (old_token, _) =
            insert_pending_registration(&repo, &device_code, Some("oldpin"), expires_at).await;
        let original_expiry: DateTime<Utc> =
            sqlx::query_scalar("SELECT expires_at FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();

        // Burn two attempts.
        repo.reserve_pin_attempt(&device_code, 1, &old_token, 5, 1000)
            .await
            .unwrap();
        repo.reserve_pin_attempt(&device_code, 1, &old_token, 5, 1000)
            .await
            .unwrap();

        let new_token = format!("verif_{}", uuid::Uuid::new_v4());
        assert!(repo
            .reset_pin_for_resend(
                &device_code,
                1,
                &old_token,
                &new_token,
                "newpin",
                Utc::now(),
            )
            .await
            .unwrap());

        let data = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .expect("row should still exist after resend");
        assert_eq!(data.pin_hash.as_deref(), Some("newpin"));
        assert_eq!(data.pin_attempts, 0, "attempts reset on resend");

        // Resend must NOT extend the original 24h window (keycast#262 bounded lifecycle).
        let after_expiry: DateTime<Utc> =
            sqlx::query_scalar("SELECT expires_at FROM oauth_codes WHERE device_code = $1")
                .bind(&device_code)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            after_expiry, original_expiry,
            "resend must not extend expires_at past the original registration window"
        );

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

    #[tokio::test]
    async fn test_reset_pin_for_resend_refuses_superseded_generation() {
        use nostr_sdk::Keys;

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (stale_token, email) = insert_pending_registration(
            &repo,
            &device_code,
            Some("stale-pin"),
            Utc::now() + chrono::Duration::hours(12),
        )
        .await;

        // This is the resend snapshot. A fresh registration supersedes it while bcrypt would run.
        let replacement_pubkey = Keys::generate().public_key().to_hex();
        let replacement_device = format!("replacement_{}", uuid::Uuid::new_v4());
        let replacement_token = format!("replacement_{}", uuid::Uuid::new_v4());
        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: "replacement-code",
            user_pubkey: &replacement_pubkey,
            client_id: "replacement-client",
            redirect_uri: "http://localhost:3000/replacement",
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            pending_email: &email,
            pending_password_hash: "replacement-hash",
            pending_email_verification_token: &replacement_token,
            pending_encrypted_secret: Some(b"replacement-secret"),
            state: None,
            device_code: Some(&replacement_device),
            is_headless: true,
            pin_hash: Some("replacement-pin"),
        })
        .await
        .unwrap();

        assert!(!repo
            .reset_pin_for_resend(
                &device_code,
                1,
                &stale_token,
                "stale-resend-token",
                "stale-resend-pin",
                Utc::now(),
            )
            .await
            .unwrap());

        let current = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.pending_email_verification_token.as_deref(),
            Some(replacement_token.as_str())
        );
        assert_eq!(current.pin_hash.as_deref(), Some("replacement-pin"));

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_reset_pin_for_resend_refuses_registration_expired_during_hashing() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let (old_token, _) =
            insert_pending_registration(&repo, &device_code, Some("oldpin"), expires_at).await;

        sqlx::query("UPDATE oauth_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();

        assert!(!repo
            .reset_pin_for_resend(
                &device_code,
                1,
                &old_token,
                "new-token",
                "new-pin",
                Utc::now() - chrono::Duration::minutes(5),
            )
            .await
            .unwrap());
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.pending_email_verification_token.as_deref(),
            Some(old_token.as_str()),
            "an expired registration must keep its last usable generation"
        );
        assert_eq!(pending.pin_hash.as_deref(), Some("oldpin"));

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mark_pin_sent_only_stamps_the_delivered_generation() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let (token, _) =
            insert_pending_registration(&repo, &device_code, Some("pinhash"), expires_at).await;

        assert!(!repo
            .mark_pin_sent(&device_code, 1, "superseded-token")
            .await
            .unwrap());
        assert!(repo.mark_pin_sent(&device_code, 1, &token).await.unwrap());
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.pin_sent_at.is_some());

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_exchange_code_selection_returns_one_code() {
        use tokio::time::{sleep, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (token, _) = insert_pending_registration(
            &repo,
            &device_code,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        let candidate_a = format!("exchange_a_{}", uuid::Uuid::new_v4());
        let candidate_b = format!("exchange_b_{}", uuid::Uuid::new_v4());

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM oauth_codes
             WHERE device_code = $1 AND pending_email IS NOT NULL FOR UPDATE",
        )
        .bind(&device_code)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();

        let first_repo = repo.clone();
        let first_token = token.clone();
        let first = tokio::spawn(async move {
            first_repo
                .materialize_pending_registration(1, &first_token, &candidate_a)
                .await
        });
        let second_repo = repo.clone();
        let second_token = token.clone();
        let second = tokio::spawn(async move {
            second_repo
                .materialize_pending_registration(1, &second_token, &candidate_b)
                .await
        });

        let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity activity
                 WHERE cardinality(pg_blocking_pids(activity.pid)) > 0
                   AND activity.query LIKE '%pending_email_verification_token = $2%FOR UPDATE%'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting >= 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < wait_deadline,
                "both exchange-code selectors must wait on the pending row"
            );
            sleep(Duration::from_millis(10)).await;
        }
        blocker.commit().await.unwrap();

        let MaterializePendingRegistrationOutcome::Ready(first) = first.await.unwrap().unwrap()
        else {
            panic!("first finalizer must be ready");
        };
        let MaterializePendingRegistrationOutcome::Ready(second) = second.await.unwrap().unwrap()
        else {
            panic!("second finalizer must be ready");
        };
        assert_eq!(first.exchange_code.code, second.exchange_code.code);
        assert!(first.exchange_code.freshly_minted ^ second.exchange_code.freshly_minted);
        let code_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE device_code = $1 AND pending_email IS NULL",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(code_count, 1);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_exchange_code_selection_completes_with_one_pool_connection() {
        use sqlx::postgres::PgPoolOptions;

        let pool = setup_pool().await;
        let setup_repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let (token, _) = insert_pending_registration(
            &setup_repo,
            &device_code,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await;
        let pending = setup_repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        let one_connection_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .unwrap();
        let candidate = format!("exchange_{}", uuid::Uuid::new_v4());
        let outcome = OAuthCodeRepository::new(one_connection_pool)
            .materialize_pending_registration(1, &token, &candidate)
            .await
            .unwrap();
        let MaterializePendingRegistrationOutcome::Ready(finalized) = outcome else {
            panic!("single-connection finalizer must be ready");
        };
        assert_eq!(finalized.exchange_code.code, candidate);
        assert!(finalized.exchange_code.freshly_minted);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_find_live_exchange_code_reuses_not_pending_row() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        // A pending registration row (device_code + pending_email set).
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        let user_pubkey = pending.user_pubkey.clone();
        let client_id = pending.client_id.clone();

        // No exchange code minted yet: the pending row must not be mistaken for one.
        assert!(
            repo.find_live_exchange_code_with_expiry_for_pending(1, &pending)
                .await
                .unwrap()
                .is_none(),
            "pending registration row must NOT be returned as an exchange code"
        );

        // A previously minted exchange code for the same pending registration.
        let exchange_code = format!("exch_{}", uuid::Uuid::new_v4());
        assert!(repo
            .store_for_pending_registration(
                StoreOAuthCodeParams {
                    tenant_id: 1,
                    code: &exchange_code,
                    user_pubkey: &user_pubkey,
                    client_id: &client_id,
                    redirect_uri: "http://localhost:3000/callback",
                    scope: "policy:social",
                    code_challenge: None,
                    code_challenge_method: None,
                    expires_at: Utc::now() + chrono::Duration::minutes(10),
                    previous_auth_id: None,
                    state: None,
                    is_headless: true,
                },
                &pending,
            )
            .await
            .unwrap());

        // The live exchange code is now found and reused; the pending row is still untouched.
        assert_eq!(
            repo.find_live_exchange_code_with_expiry_for_pending(1, &pending)
                .await
                .unwrap()
                .as_ref()
                .map(|row| row.0.as_str()),
            Some(exchange_code.as_str()),
            "live exchange code must be returned for reuse"
        );
        assert!(
            repo.find_by_device_code(&device_code, 1)
                .await
                .unwrap()
                .is_some(),
            "pending registration row must NOT be consumed by the lookup"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_find_live_exchange_code_skips_expired() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();

        // An already-expired exchange code must not be reused.
        let expired_code = format!("exch_{}", uuid::Uuid::new_v4());
        repo.store(StoreOAuthCodeParams {
            tenant_id: 1,
            code: &expired_code,
            user_pubkey: &pending.user_pubkey,
            client_id: &pending.client_id,
            redirect_uri: "http://localhost:3000/callback",
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at: Utc::now() - chrono::Duration::minutes(1),
            previous_auth_id: None,
            state: None,
            is_headless: true,
        })
        .await
        .unwrap();

        assert!(
            repo.find_live_exchange_code_with_expiry_for_pending(1, &pending)
                .await
                .unwrap()
                .is_none(),
            "expired exchange code must NOT be reused"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_find_live_exchange_code_with_expiry_returns_remaining_db_lifetime() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let pending_expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash"), pending_expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        let exchange_code = format!("exch_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::seconds(90);

        assert!(repo
            .store_for_pending_registration(
                StoreOAuthCodeParams {
                    tenant_id: 1,
                    code: &exchange_code,
                    user_pubkey: &pending.user_pubkey,
                    client_id: &pending.client_id,
                    redirect_uri: "http://localhost:3000/callback",
                    scope: "policy:social",
                    code_challenge: None,
                    code_challenge_method: None,
                    expires_at,
                    previous_auth_id: None,
                    state: None,
                    is_headless: true,
                },
                &pending,
            )
            .await
            .unwrap());

        let found = repo
            .find_live_exchange_code_with_expiry_for_pending(1, &pending)
            .await
            .unwrap()
            .expect("live exchange code should be returned with expiry");

        assert_eq!(found.0, exchange_code);
        assert!(
            found.1 <= expires_at && found.1 > Utc::now(),
            "expiry must come from the DB row so Redis TTL can be bounded"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
            .bind(&pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_find_live_exchange_code_does_not_cross_pending_oauth_semantics() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let user_pubkey = nostr_sdk::Keys::generate().public_key().to_hex();
        let client_id = format!("client_{}", uuid::Uuid::new_v4());
        let device_a = format!("dc_a_{}", uuid::Uuid::new_v4());
        let device_b = format!("dc_b_{}", uuid::Uuid::new_v4());
        let pending_a_code = format!("pending_a_{}", uuid::Uuid::new_v4());
        let pending_b_code = format!("pending_b_{}", uuid::Uuid::new_v4());
        let token_a = format!("token_a_{}", uuid::Uuid::new_v4());
        let token_b = format!("token_b_{}", uuid::Uuid::new_v4());
        let email_a = format!("same-user-a-{}@example.com", uuid::Uuid::new_v4());
        let email_b = format!("same-user-b-{}@example.com", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: &pending_a_code,
            user_pubkey: &user_pubkey,
            client_id: &client_id,
            redirect_uri: "http://localhost:3000/callback",
            scope: "policy:social",
            code_challenge: Some("challenge-a"),
            code_challenge_method: Some("S256"),
            expires_at,
            pending_email: &email_a,
            pending_password_hash: "hashed",
            pending_email_verification_token: &token_a,
            pending_encrypted_secret: Some(b"secret-a"),
            state: Some("state-a"),
            device_code: Some(&device_a),
            is_headless: true,
            pin_hash: Some("pin-a"),
        })
        .await
        .unwrap();
        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: &pending_b_code,
            user_pubkey: &user_pubkey,
            client_id: &client_id,
            redirect_uri: "http://localhost:3000/callback",
            scope: "policy:social",
            code_challenge: Some("challenge-b"),
            code_challenge_method: Some("S256"),
            expires_at,
            pending_email: &email_b,
            pending_password_hash: "hashed",
            pending_email_verification_token: &token_b,
            pending_encrypted_secret: Some(b"secret-b"),
            state: Some("state-b"),
            device_code: Some(&device_b),
            is_headless: true,
            pin_hash: Some("pin-b"),
        })
        .await
        .unwrap();

        let exchange_a = format!("exch_a_{}", uuid::Uuid::new_v4());
        let pending_a = repo
            .find_by_device_code(&device_a, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(repo
            .store_for_pending_registration(
                StoreOAuthCodeParams {
                    tenant_id: 1,
                    code: &exchange_a,
                    user_pubkey: &user_pubkey,
                    client_id: &client_id,
                    redirect_uri: "http://localhost:3000/callback",
                    scope: "policy:social",
                    code_challenge: Some("challenge-a"),
                    code_challenge_method: Some("S256"),
                    expires_at: Utc::now() + chrono::Duration::minutes(10),
                    previous_auth_id: None,
                    state: Some("state-a"),
                    is_headless: true,
                },
                &pending_a,
            )
            .await
            .unwrap());

        let pending_b = repo
            .find_by_device_code(&device_b, 1)
            .await
            .unwrap()
            .unwrap();
        let found = repo
            .find_live_exchange_code_with_expiry_for_pending(1, &pending_b)
            .await
            .unwrap();
        assert!(
            found.is_none(),
            "second same-user/client pending registration must not receive first registration's exchange code"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_redemptions_only_one_claims_code() {
        use tokio::time::{sleep, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code;
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM oauth_codes
             WHERE device_code = $1 AND pending_email IS NOT NULL FOR UPDATE",
        )
        .bind(&device_code)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();

        let first_repo = repo.clone();
        let first_code = code.clone();
        let first_auth = auth_code.clone();
        let first =
            tokio::spawn(async move { first_repo.redeem_code(1, &first_code, &first_auth).await });
        let second_repo = repo.clone();
        let second_code = code.clone();
        let second_auth = auth_code.clone();
        let second =
            tokio::spawn(
                async move { second_repo.redeem_code(1, &second_code, &second_auth).await },
            );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity activity
                 WHERE cardinality(pg_blocking_pids(activity.pid)) > 0
                   AND activity.query LIKE '%pending_email IS NOT NULL%FOR UPDATE%'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting >= 2 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            sleep(Duration::from_millis(10)).await;
        }
        blocker.commit().await.unwrap();

        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        assert!(first ^ second);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&finalized.pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_failed_issuance_release_makes_same_code_redeemable() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code;
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();

        assert!(repo.redeem_code(1, &code, &auth_code).await.unwrap());
        assert!(repo
            .release_redeemed_code(1, &code, &auth_code)
            .await
            .unwrap());
        assert!(repo.redeem_code(1, &code, &auth_code).await.unwrap());

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&finalized.pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_resend_does_not_rotate_an_in_progress_exchange_claim() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code.clone();
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();
        let token = finalized
            .pending
            .pending_email_verification_token
            .as_deref()
            .unwrap();

        assert!(repo.redeem_code(1, &code, &auth_code).await.unwrap());
        assert!(!repo
            .reset_pin_for_resend(
                &device_code,
                1,
                token,
                "replacement-token",
                "replacement-pin",
                Utc::now() - chrono::Duration::minutes(5),
            )
            .await
            .unwrap());

        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.pending_email_verification_token.as_deref(),
            Some(token)
        );
        let exchange_token: Option<String> = sqlx::query_scalar(
            "SELECT pending_email_verification_token FROM oauth_codes WHERE code = $1",
        )
        .bind(&code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(exchange_token.as_deref(), Some(token));

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&finalized.pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_queued_resend_observes_redemption_claim_after_pending_lock_wait() {
        use tokio::time::{sleep, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code.clone();
        let token = finalized
            .pending
            .pending_email_verification_token
            .clone()
            .unwrap();
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();

        let mut redemption = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM oauth_codes
             WHERE tenant_id = 1 AND device_code = $1
               AND pending_email_verification_token = $2
               AND pending_email IS NOT NULL
             FOR UPDATE",
        )
        .bind(&device_code)
        .bind(&token)
        .fetch_one(&mut *redemption)
        .await
        .unwrap();

        let resend_repo = repo.clone();
        let resend_device = device_code.clone();
        let resend_token = token.clone();
        let resend = tokio::spawn(async move {
            resend_repo
                .reset_pin_for_resend(
                    &resend_device,
                    1,
                    &resend_token,
                    "replacement-token",
                    "replacement-pin",
                    Utc::now() - chrono::Duration::minutes(5),
                )
                .await
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity activity
                     WHERE cardinality(pg_blocking_pids(activity.pid)) > 0
                       AND activity.query LIKE '%pin_resend_at IS NULL OR pin_resend_at <=%FOR UPDATE%'
                 )",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "resend did not queue on the pending-generation lock"
            );
            sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            sqlx::query(
                "UPDATE oauth_codes SET consumed_at = clock_timestamp()
                 WHERE tenant_id = 1 AND code = $1
                   AND pending_email_verification_token = $2
                   AND pending_email IS NULL AND consumed_at IS NULL",
            )
            .bind(&code)
            .bind(&token)
            .execute(&mut *redemption)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        redemption.commit().await.unwrap();

        assert!(!resend.await.unwrap().unwrap());
        let pending_token: Option<String> = sqlx::query_scalar(
            "SELECT pending_email_verification_token FROM oauth_codes
             WHERE tenant_id = 1 AND device_code = $1 AND pending_email IS NOT NULL",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        let (exchange_token, exchange_consumed): (Option<String>, bool) = sqlx::query_as(
            "SELECT pending_email_verification_token, consumed_at IS NOT NULL
             FROM oauth_codes WHERE tenant_id = 1 AND code = $1",
        )
        .bind(&code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pending_token.as_deref(), Some(token.as_str()));
        assert_eq!(exchange_token, pending_token);
        assert!(exchange_consumed);
        assert!(repo
            .mark_pending_consumed(1, &code, &auth_code)
            .await
            .unwrap());

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&finalized.pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_queued_failed_resend_restore_observes_redemption_claim() {
        use tokio::time::{sleep, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code.clone();
        let old_token = finalized
            .pending
            .pending_email_verification_token
            .clone()
            .unwrap();
        let old_pin_hash = finalized.pending.pin_hash.clone().unwrap();
        let replacement_token = format!("replacement_{}", uuid::Uuid::new_v4());
        let replacement_pin_hash = format!("replacement_pin_{}", uuid::Uuid::new_v4());

        assert!(repo
            .reset_pin_for_resend(
                &device_code,
                1,
                &old_token,
                &replacement_token,
                &replacement_pin_hash,
                Utc::now() - chrono::Duration::minutes(5),
            )
            .await
            .unwrap());
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();

        let mut redemption = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM oauth_codes
             WHERE tenant_id = 1 AND device_code = $1
               AND pending_email_verification_token = $2
               AND pending_email IS NOT NULL
             FOR UPDATE",
        )
        .bind(&device_code)
        .bind(&replacement_token)
        .fetch_one(&mut *redemption)
        .await
        .unwrap();

        let restore_repo = repo.clone();
        let restore_device = device_code.clone();
        let restore_old_token = old_token.clone();
        let restore_old_pin_hash = old_pin_hash.clone();
        let restore_token = replacement_token.clone();
        let restore_pin_hash = replacement_pin_hash.clone();
        let restore = tokio::spawn(async move {
            restore_repo
                .restore_pin_after_failed_resend(
                    &restore_device,
                    1,
                    PinResendSnapshot {
                        verification_token: Some(&restore_old_token),
                        pin_hash: Some(&restore_old_pin_hash),
                        pin_attempts: finalized.pending.pin_attempts,
                        pin_sent_at: finalized.pending.pin_sent_at,
                        pin_resend_at: finalized.pending.pin_resend_at,
                    },
                    &restore_token,
                    &restore_pin_hash,
                )
                .await
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity activity
                     WHERE cardinality(pg_blocking_pids(activity.pid)) > 0
                       AND activity.query LIKE '%pin_hash = $3 AND pending_email_verification_token = $4%FOR UPDATE%'
                 )",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "failed-resend restore did not queue on the pending-generation lock"
            );
            sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            sqlx::query(
                "UPDATE oauth_codes SET consumed_at = clock_timestamp()
                 WHERE tenant_id = 1 AND code = $1
                   AND pending_email_verification_token = $2
                   AND pending_email IS NULL AND consumed_at IS NULL",
            )
            .bind(&code)
            .bind(&replacement_token)
            .execute(&mut *redemption)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        redemption.commit().await.unwrap();

        assert!(!restore.await.unwrap().unwrap());
        let (pending_token, pending_pin): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pending_email_verification_token, pin_hash FROM oauth_codes
             WHERE tenant_id = 1 AND device_code = $1 AND pending_email IS NOT NULL",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        let (exchange_token, exchange_consumed): (Option<String>, bool) = sqlx::query_as(
            "SELECT pending_email_verification_token, consumed_at IS NOT NULL
             FROM oauth_codes WHERE tenant_id = 1 AND code = $1",
        )
        .bind(&code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pending_token.as_deref(), Some(replacement_token.as_str()));
        assert_eq!(pending_pin.as_deref(), Some(replacement_pin_hash.as_str()));
        assert_eq!(exchange_token, pending_token);
        assert!(exchange_consumed);
        assert!(repo
            .mark_pending_consumed(1, &code, &auth_code)
            .await
            .unwrap());

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&auth_code.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_finalizer_and_redemption_never_create_second_live_code() {
        use tokio::time::{sleep, Duration};

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code.clone();
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();
        let token = finalized
            .pending
            .pending_email_verification_token
            .clone()
            .unwrap();

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM oauth_codes
             WHERE device_code = $1 AND pending_email IS NOT NULL FOR UPDATE",
        )
        .bind(&device_code)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
        let redeem_repo = repo.clone();
        let redeem_code = code.clone();
        let redeem_auth = auth_code.clone();
        let redemption =
            tokio::spawn(
                async move { redeem_repo.redeem_code(1, &redeem_code, &redeem_auth).await },
            );
        let finalize_repo = repo.clone();
        let replacement = format!("replacement_{}", uuid::Uuid::new_v4());
        let finalizer = tokio::spawn(async move {
            finalize_repo
                .materialize_pending_registration(1, &token, &replacement)
                .await
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity activity
                 WHERE cardinality(pg_blocking_pids(activity.pid)) > 0",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting >= 2 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            sleep(Duration::from_millis(10)).await;
        }
        blocker.commit().await.unwrap();

        assert!(redemption.await.unwrap().unwrap());
        match finalizer.await.unwrap().unwrap() {
            MaterializePendingRegistrationOutcome::Ready(result) => {
                assert_eq!(result.exchange_code.code, code)
            }
            MaterializePendingRegistrationOutcome::Processing => {}
            other => panic!("unexpected finalizer outcome: {other:?}"),
        }
        let live_codes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_codes
             WHERE device_code = $1 AND pending_email IS NULL
               AND expires_at > clock_timestamp()",
        )
        .bind(&device_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(live_codes, 1);

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&finalized.pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_finalizer_reports_processing_then_recovers_after_claim_expiry() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());
        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let finalized = insert_and_finalize_registration(&repo, &device_code).await;
        let code = finalized.exchange_code.code.clone();
        let token = finalized
            .pending
            .pending_email_verification_token
            .clone()
            .unwrap();
        let auth_code = repo.find_valid(1, &code).await.unwrap().unwrap();
        assert!(repo.redeem_code(1, &code, &auth_code).await.unwrap());

        assert!(matches!(
            repo.materialize_pending_registration(1, &token, "must-not-mint")
                .await
                .unwrap(),
            MaterializePendingRegistrationOutcome::Processing
        ));
        sqlx::query("UPDATE oauth_codes SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE code = $1")
            .bind(&code)
            .execute(&pool)
            .await
            .unwrap();
        let recovered = repo
            .materialize_pending_registration(1, &token, "recovered-code")
            .await
            .unwrap();
        let MaterializePendingRegistrationOutcome::Ready(recovered) = recovered else {
            panic!("expired claim must allow a replacement code");
        };
        assert_eq!(recovered.exchange_code.code, "recovered-code");

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&finalized.pending.user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mark_pending_consumed_sets_marker_on_pending_row_only() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.consumed_at.is_none(), "starts un-consumed");

        let exchange_code = format!("exch_{}", uuid::Uuid::new_v4());
        assert!(repo
            .store_for_pending_registration(
                StoreOAuthCodeParams {
                    tenant_id: 1,
                    code: &exchange_code,
                    user_pubkey: &pending.user_pubkey,
                    client_id: &pending.client_id,
                    redirect_uri: &pending.redirect_uri,
                    scope: &pending.scope,
                    code_challenge: pending.code_challenge.as_deref(),
                    code_challenge_method: pending.code_challenge_method.as_deref(),
                    expires_at: Utc::now() + chrono::Duration::minutes(10),
                    previous_auth_id: pending.previous_auth_id,
                    state: pending.state.as_deref(),
                    is_headless: pending.is_headless,
                },
                &pending,
            )
            .await
            .unwrap());
        let auth_code = repo.find_valid(1, &exchange_code).await.unwrap().unwrap();

        repo.redeem_code(1, &exchange_code, &auth_code)
            .await
            .unwrap();

        let after_redeem = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(
            after_redeem.consumed_at.is_none(),
            "redeeming the exchange code must leave recovery possible until issuance succeeds"
        );

        assert!(repo
            .mark_pending_consumed(1, &exchange_code, &auth_code)
            .await
            .unwrap());
        let after_issuance = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(
            after_issuance.consumed_at.is_some(),
            "pending row should be marked consumed"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&device_code)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_duplicate_exchange_code_redeem_is_one_shot_for_pending_registration() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let device_code = format!("dc_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        insert_pending_registration(&repo, &device_code, Some("pinhash"), expires_at).await;
        let pending = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        let exchange_a = format!("exch_a_{}", uuid::Uuid::new_v4());
        let exchange_b = format!("exch_b_{}", uuid::Uuid::new_v4());

        for exchange_code in [&exchange_a, &exchange_b] {
            assert!(repo
                .store_for_pending_registration(
                    StoreOAuthCodeParams {
                        tenant_id: 1,
                        code: exchange_code,
                        user_pubkey: &pending.user_pubkey,
                        client_id: &pending.client_id,
                        redirect_uri: &pending.redirect_uri,
                        scope: &pending.scope,
                        code_challenge: pending.code_challenge.as_deref(),
                        code_challenge_method: pending.code_challenge_method.as_deref(),
                        expires_at: Utc::now() + chrono::Duration::minutes(10),
                        previous_auth_id: pending.previous_auth_id,
                        state: pending.state.as_deref(),
                        is_headless: pending.is_headless,
                    },
                    &pending,
                )
                .await
                .unwrap());
        }

        let auth_code_a = repo.find_valid(1, &exchange_a).await.unwrap().unwrap();
        assert!(
            repo.redeem_code(1, &exchange_a, &auth_code_a)
                .await
                .unwrap(),
            "first exchange code should redeem the pending registration"
        );
        assert!(repo
            .mark_pending_consumed(1, &exchange_a, &auth_code_a)
            .await
            .unwrap());

        let after_first = repo
            .find_by_device_code(&device_code, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(
            after_first.consumed_at.is_some(),
            "first redemption should consume the pending row"
        );

        let auth_code_b = repo.find_valid(1, &exchange_b).await.unwrap().unwrap();
        assert!(
            !repo
                .redeem_code(1, &exchange_b, &auth_code_b)
                .await
                .unwrap(),
            "second sibling exchange code must not redeem after pending row is consumed"
        );
        assert!(
            repo.find_valid(1, &exchange_b).await.unwrap().is_some(),
            "failed redemption should leave the exchange-code tombstone"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1 OR code IN ($2, $3)")
            .bind(&device_code)
            .bind(&exchange_a)
            .bind(&exchange_b)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mark_pending_consumed_does_not_cross_pending_oauth_semantics() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let user_pubkey = nostr_sdk::Keys::generate().public_key().to_hex();
        let client_id = format!("client_{}", uuid::Uuid::new_v4());
        let device_a = format!("dc_a_{}", uuid::Uuid::new_v4());
        let device_b = format!("dc_b_{}", uuid::Uuid::new_v4());
        let pending_a_code = format!("pending_a_{}", uuid::Uuid::new_v4());
        let pending_b_code = format!("pending_b_{}", uuid::Uuid::new_v4());
        let token_a = format!("token_a_{}", uuid::Uuid::new_v4());
        let token_b = format!("token_b_{}", uuid::Uuid::new_v4());
        let email_a = format!("consume-a-{}@example.com", uuid::Uuid::new_v4());
        let email_b = format!("consume-b-{}@example.com", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: &pending_a_code,
            user_pubkey: &user_pubkey,
            client_id: &client_id,
            redirect_uri: "http://localhost:3000/callback",
            scope: "policy:social",
            code_challenge: Some("challenge-a"),
            code_challenge_method: Some("S256"),
            expires_at,
            pending_email: &email_a,
            pending_password_hash: "hashed",
            pending_email_verification_token: &token_a,
            pending_encrypted_secret: Some(b"secret-a"),
            state: Some("state-a"),
            device_code: Some(&device_a),
            is_headless: true,
            pin_hash: Some("pin-a"),
        })
        .await
        .unwrap();
        repo.store_with_pending_registration(StoreOAuthCodeWithRegistrationParams {
            tenant_id: 1,
            code: &pending_b_code,
            user_pubkey: &user_pubkey,
            client_id: &client_id,
            redirect_uri: "http://localhost:3000/callback",
            scope: "policy:social",
            code_challenge: Some("challenge-b"),
            code_challenge_method: Some("S256"),
            expires_at,
            pending_email: &email_b,
            pending_password_hash: "hashed",
            pending_email_verification_token: &token_b,
            pending_encrypted_secret: Some(b"secret-b"),
            state: Some("state-b"),
            device_code: Some(&device_b),
            is_headless: true,
            pin_hash: Some("pin-b"),
        })
        .await
        .unwrap();

        let exchange_a = format!("exch_a_{}", uuid::Uuid::new_v4());
        let pending_a_for_exchange = repo
            .find_by_device_code(&device_a, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(repo
            .store_for_pending_registration(
                StoreOAuthCodeParams {
                    tenant_id: 1,
                    code: &exchange_a,
                    user_pubkey: &user_pubkey,
                    client_id: &client_id,
                    redirect_uri: "http://localhost:3000/callback",
                    scope: "policy:social",
                    code_challenge: Some("challenge-a"),
                    code_challenge_method: Some("S256"),
                    expires_at: Utc::now() + chrono::Duration::minutes(10),
                    previous_auth_id: None,
                    state: Some("state-a"),
                    is_headless: true,
                },
                &pending_a_for_exchange,
            )
            .await
            .unwrap());
        let auth_code = repo.find_valid(1, &exchange_a).await.unwrap().unwrap();

        repo.redeem_code(1, &exchange_a, &auth_code).await.unwrap();
        assert!(repo
            .mark_pending_consumed(1, &exchange_a, &auth_code)
            .await
            .unwrap());

        let pending_a = repo
            .find_by_device_code(&device_a, 1)
            .await
            .unwrap()
            .unwrap();
        let pending_b = repo
            .find_by_device_code(&device_b, 1)
            .await
            .unwrap()
            .unwrap();

        assert!(
            pending_a.consumed_at.is_some(),
            "the intended pending registration should be consumed"
        );
        assert!(
            pending_b.consumed_at.is_none(),
            "a different same-user/client pending registration must remain active"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .execute(&pool)
            .await
            .unwrap();
    }

    // Serialized against `test_delete_expired_and_consumed_removes_dead_rows`: that cleanup is
    // global by design, so an expired fixture is fair game for it while both run concurrently.
    #[serial]
    #[tokio::test]
    async fn test_delete_expired_and_consumed_removes_dead_rows() {
        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        // Live row (kept).
        let live_dc = format!("dc_live_{}", uuid::Uuid::new_v4());
        insert_pending_registration(
            &repo,
            &live_dc,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(24),
        )
        .await;

        // Expired row (removed).
        let expired_dc = format!("dc_exp_{}", uuid::Uuid::new_v4());
        insert_pending_registration(
            &repo,
            &expired_dc,
            Some("pin"),
            Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        // Live-but-consumed row (removed).
        let consumed_dc = format!("dc_con_{}", uuid::Uuid::new_v4());
        insert_pending_registration(
            &repo,
            &consumed_dc,
            Some("pin"),
            Utc::now() + chrono::Duration::hours(24),
        )
        .await;
        let _consumed = repo
            .find_by_device_code(&consumed_dc, 1)
            .await
            .unwrap()
            .unwrap();
        sqlx::query("UPDATE oauth_codes SET consumed_at = $1 WHERE device_code = $2")
            .bind(Utc::now())
            .bind(&consumed_dc)
            .execute(&pool)
            .await
            .unwrap();

        // A consumed exchange row is an in-progress issuance tombstone and must survive until its
        // own expiry so verification cannot mint a concurrent replacement.
        let exchange_code = format!("exchange_claim_{}", uuid::Uuid::new_v4());
        repo.store(StoreOAuthCodeParams {
            tenant_id: 1,
            code: &exchange_code,
            user_pubkey: "exchange-claim-user",
            client_id: "exchange-claim-client",
            redirect_uri: "https://example.com/callback",
            scope: "policy:social",
            code_challenge: None,
            code_challenge_method: None,
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            previous_auth_id: None,
            state: None,
            is_headless: true,
        })
        .await
        .unwrap();
        sqlx::query("UPDATE oauth_codes SET consumed_at = NOW() WHERE code = $1")
            .bind(&exchange_code)
            .execute(&pool)
            .await
            .unwrap();

        let removed = repo.delete_expired_and_consumed().await.unwrap();
        assert!(removed >= 2, "expired and consumed rows should be deleted");

        // find_by_device_code filters expired, so query the raw row for the expired case.
        let expired_still_present: Option<(String,)> =
            sqlx::query_as("SELECT device_code FROM oauth_codes WHERE device_code = $1")
                .bind(&expired_dc)
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(expired_still_present.is_none(), "expired row removed");
        let consumed_still_present: Option<(String,)> =
            sqlx::query_as("SELECT device_code FROM oauth_codes WHERE device_code = $1")
                .bind(&consumed_dc)
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(consumed_still_present.is_none(), "consumed row removed");
        let exchange_claim_present: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_codes WHERE code = $1)")
                .bind(&exchange_code)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            exchange_claim_present,
            "live exchange claim must be retained"
        );
        assert!(
            repo.find_by_device_code(&live_dc, 1)
                .await
                .unwrap()
                .is_some(),
            "live un-consumed row retained"
        );

        sqlx::query("DELETE FROM oauth_codes WHERE device_code = $1")
            .bind(&live_dc)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
            .bind(&exchange_code)
            .execute(&pool)
            .await
            .unwrap();
    }
}
