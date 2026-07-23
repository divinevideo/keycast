// ABOUTME: User repository for data access operations
// ABOUTME: Provides methods for finding, creating, and querying user data

use crate::repositories::RepositoryError;
use crate::types::user::{User, UserAtprotoState, UserStatus};
use chrono::{DateTime, Utc};
use nostr_sdk::PublicKey;
use sqlx::{FromRow, PgPool};

pub type StatusTransition = (
    UserStatus,
    UserStatus,
    Option<String>,
    Option<DateTime<Utc>>,
);

/// Data returned when looking up a user by verification token.
/// Includes fields needed to check async bcrypt completion state.
#[derive(Debug, FromRow)]
pub struct VerificationTokenData {
    pub pubkey: String,
    pub email_verification_expires_at: Option<DateTime<Utc>>,
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub email_verified: bool,
}

/// Snapshot of an existing users row used to gate OAuth registration finalization.
///
/// Distinguishes a genuine registration retry (row already carries the pending
/// email) from a bare row created by another path (team membership, authorization
/// pre-creation) that still needs the pending credentials applied.
#[derive(Debug, FromRow)]
pub struct OAuthRegistrationState {
    /// Email currently on the row, if any.
    pub email: Option<String>,
    /// Whether the row has completed email verification.
    pub email_verified: bool,
    /// Whether the row has a password hash ready for password login.
    pub has_password_hash: bool,
    /// Whether a personal_keys row exists for this pubkey.
    pub has_personal_key: bool,
}

/// Which side of a pending email change a token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingEmailSide {
    /// Token sent to the user's current (old) address.
    Old,
    /// Token sent to the proposed new address.
    New,
}

/// Result of attempting to finalize a pending email change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeEmailOutcome {
    /// Both sides confirmed; the email was swapped and pending state cleared.
    Finalized,
    /// Not both sides have confirmed yet (or there is no pending change).
    NotReady,
    /// The target email was registered by someone else; pending state was cleared.
    EmailTaken,
}

/// Snapshot of a pending email change, looked up by either confirmation token.
#[derive(Debug, Clone)]
pub struct PendingEmailChange {
    pub pubkey: String,
    pub pending_email: Option<String>,
    pub pending_email_expires_at: Option<DateTime<Utc>>,
    pub pending_email_old_confirmed_at: Option<DateTime<Utc>>,
    pub pending_email_new_confirmed_at: Option<DateTime<Utc>>,
}

/// Provenance of an admin lookup row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserMatchKind {
    /// Exact email, username, Vine ID, npub, or hex-pubkey match.
    Authoritative,
    /// Literal email substring or username-prefix match.
    #[default]
    Partial,
    /// Typo-near email match retained by the bounded fuzzy filter.
    Fuzzy,
}

/// User details returned by admin lookup.
#[derive(Debug, FromRow)]
pub struct AdminUserDetails {
    pub pubkey: String,
    #[sqlx(default)]
    pub authoritative: bool,
    /// How this row matched the admin's query.
    #[sqlx(skip)]
    pub match_kind: AdminUserMatchKind,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub vine_id: Option<String>,
    pub has_personal_key: bool,
    pub status: UserStatus,
    pub suspended_reason: Option<String>,
    // Selected by every admin-lookup query (deliberately no `#[sqlx(default)]`, unlike
    // `authoritative` which is computed post-fetch): a query that forgets these columns
    // must fail loudly rather than silently report a minor as non-minor.
    pub verified_minor: bool,
    pub verified_minor_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Ordered users and authority metadata returned by an admin lookup.
#[derive(Debug)]
pub struct AdminUserLookup {
    pub users: Vec<AdminUserDetails>,
    pub authoritative_match: bool,
    pub authoritative_count: usize,
}

/// Maximum number of primary users returned by one admin lookup.
pub const ADMIN_USER_LOOKUP_LIMIT: usize = 20;

/// Minimum word similarity used to select plausible email suggestions.
const ADMIN_EMAIL_SUGGESTION_MIN_WORD_SIMILARITY: f32 = 0.2;

/// Maximum edit distance allowed between an admin query and a suggested email.
const ADMIN_EMAIL_SUGGESTION_MAX_EDIT_DISTANCE: usize = 2;

/// Maximum number of close email suggestions returned to an admin.
const ADMIN_EMAIL_SUGGESTION_LIMIT: usize = 5;

/// Maximum number of trigram-ranked rows checked for close email suggestions.
const ADMIN_EMAIL_SUGGESTION_CANDIDATE_LIMIT: i64 = 100;

const ADMIN_EMAIL_SUGGESTION_QUERY: &str = "SELECT
        u.pubkey,
        u.email,
        u.email_verified,
        u.username,
        u.display_name,
        u.vine_id,
        (pk.user_pubkey IS NOT NULL) as \"has_personal_key\",
        u.status,
        u.suspended_reason,
        u.verified_minor,
        u.verified_minor_at,
        u.created_at,
        u.updated_at
     FROM users u
     LEFT JOIN personal_keys pk ON pk.user_pubkey = u.pubkey AND pk.tenant_id = u.tenant_id
     WHERE u.email IS NOT NULL
       AND u.email %> $1
       AND word_similarity($1, u.email) >= $3
       AND u.tenant_id = $2
     ORDER BY word_similarity($1, u.email) DESC, LOWER(u.email), u.pubkey
     LIMIT $4";

fn escape_like_pattern(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn edit_distance(left: &[char], right: &[char]) -> usize {
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];

    for (left_index, left_character) in left.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_character) in right.iter().enumerate() {
            let substitution_cost = usize::from(left_character != right_character);
            current[right_index + 1] = (current[right_index] + 1)
                .min(previous[right_index + 1] + 1)
                .min(previous[right_index] + substitution_cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right.len()]
}

fn closest_email_edit_distance(query: &str, email: &str, maximum: usize) -> Option<usize> {
    let query = query.chars().collect::<Vec<_>>();
    let email = email.chars().collect::<Vec<_>>();

    if query.contains(&'@') {
        if query.len().abs_diff(email.len()) > maximum {
            return None;
        }
        let distance = edit_distance(&query, &email);
        return (distance <= maximum).then_some(distance);
    }

    let mut previous = vec![0; email.len() + 1];
    let mut current = vec![0; email.len() + 1];

    for (query_index, query_character) in query.iter().enumerate() {
        current[0] = query_index + 1;
        for (email_index, email_character) in email.iter().enumerate() {
            let substitution_cost = usize::from(query_character != email_character);
            current[email_index + 1] = (current[email_index] + 1)
                .min(previous[email_index + 1] + 1)
                .min(previous[email_index] + substitution_cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    let distance = previous.iter().copied().min().unwrap_or(query.len());
    (distance <= maximum).then_some(distance)
}

#[cfg(test)]
mod admin_email_match_unit_tests {
    use super::{
        closest_email_edit_distance, merge_admin_lookup_candidates, ADMIN_USER_LOOKUP_LIMIT,
    };

    #[test]
    fn partial_query_uses_the_closest_email_substring() {
        assert_eq!(
            closest_email_edit_distance("publish", "socialpulishllc@gmail.com", 2),
            Some(1)
        );
        assert_eq!(
            closest_email_edit_distance("publish", "unrelated@gmail.com", 2),
            None
        );
        assert_eq!(
            closest_email_edit_distance("mañana", "hola-mañna@example.com", 2),
            Some(1)
        );
    }

    #[test]
    fn lookup_merge_ranks_tiers_and_deduplicates_pubkeys() {
        let merged = merge_admin_lookup_candidates(
            vec!["authoritative"],
            vec!["partial-primary", "duplicate"],
            vec!["partial-email", "duplicate"],
            vec!["fuzzy", "authoritative"],
            |pubkey| *pubkey,
        );

        assert_eq!(
            merged,
            vec![
                "authoritative",
                "partial-primary",
                "partial-email",
                "duplicate",
                "fuzzy"
            ]
        );
    }

    #[test]
    fn lookup_merge_does_not_let_fuzzy_rows_exceed_the_overall_cap() {
        let partial = (0..ADMIN_USER_LOOKUP_LIMIT).collect::<Vec<_>>();
        let merged =
            merge_admin_lookup_candidates(vec![], partial, vec![], vec![usize::MAX], |key| *key);

        assert_eq!(merged.len(), ADMIN_USER_LOOKUP_LIMIT);
        assert!(!merged.contains(&usize::MAX));
    }
}

fn merge_admin_lookup_candidates<T, K>(
    authoritative: Vec<T>,
    primary_loose: Vec<T>,
    email_loose: Vec<T>,
    fuzzy: Vec<T>,
    key: impl Fn(&T) -> K,
) -> Vec<T>
where
    K: Eq + std::hash::Hash,
{
    let mut candidates = Vec::with_capacity(ADMIN_USER_LOOKUP_LIMIT);
    let mut seen = std::collections::HashSet::new();

    for candidate in authoritative {
        if seen.insert(key(&candidate)) {
            candidates.push(candidate);
        }
        if candidates.len() == ADMIN_USER_LOOKUP_LIMIT {
            return candidates;
        }
    }

    let mut primary_loose = primary_loose.into_iter();
    let mut email_loose = email_loose.into_iter();
    while candidates.len() < ADMIN_USER_LOOKUP_LIMIT {
        let mut had_candidate = false;

        if let Some(candidate) = primary_loose.next() {
            had_candidate = true;
            if seen.insert(key(&candidate)) {
                candidates.push(candidate);
            }
        }
        if candidates.len() == ADMIN_USER_LOOKUP_LIMIT {
            break;
        }

        if let Some(candidate) = email_loose.next() {
            had_candidate = true;
            if seen.insert(key(&candidate)) {
                candidates.push(candidate);
            }
        }

        if !had_candidate {
            break;
        }
    }

    for candidate in fuzzy {
        if candidates.len() == ADMIN_USER_LOOKUP_LIMIT {
            break;
        }
        if seen.insert(key(&candidate)) {
            candidates.push(candidate);
        }
    }

    candidates
}

impl AdminUserLookup {
    /// Append de-duplicated loose results while preserving authoritative metadata.
    pub fn append_loose_results(mut self, loose: Self) -> Self {
        let mut authoritative = Vec::new();
        let mut partial = Vec::new();
        let mut fuzzy = Vec::new();
        for user in self.users.into_iter().chain(loose.users) {
            match user.match_kind {
                AdminUserMatchKind::Authoritative => authoritative.push(user),
                AdminUserMatchKind::Partial => partial.push(user),
                AdminUserMatchKind::Fuzzy => fuzzy.push(user),
            }
        }
        self.users = merge_admin_lookup_candidates(authoritative, partial, vec![], fuzzy, |user| {
            user.pubkey.clone()
        });
        self.authoritative_count = self.users.iter().filter(|user| user.authoritative).count();
        self.authoritative_match = self.authoritative_count > 0;
        self
    }
}

fn is_undefined_postgres_function(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("42883")
    )
}

// Row structs backing the account-status / verified_minor safeguard queries below.
// `FromRow` maps by column name, so callers read named fields and the six-column
// shape can no longer be mis-ordered the way a positional tuple can. These are
// per-method rather than one over-selecting struct so every query's `SELECT` list
// stays byte-for-byte identical, including the oauth hot-path `get_account_status`.

/// Email + status for `get_account_status` (oauth login/session path).
#[derive(Debug, FromRow)]
pub struct AccountStatusRow {
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub status: UserStatus,
    pub suspended_reason: Option<String>,
}

/// `AccountStatusRow` plus the approved-minor flag/timestamp for
/// `get_account_status_with_minor` (backs `GET /user/account`).
#[derive(Debug, FromRow)]
pub struct AccountStatusWithMinorRow {
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub status: UserStatus,
    pub suspended_reason: Option<String>,
    pub verified_minor: bool,
    pub verified_minor_at: Option<DateTime<Utc>>,
}

/// Verified-minor flag + timestamp for `get_verified_minor`.
#[derive(Debug, FromRow)]
pub struct VerifiedMinorRow {
    pub verified_minor: bool,
    pub verified_minor_at: Option<DateTime<Utc>>,
}

/// Status + suspension + verified-minor fields for `get_full_admin_status`
/// (admin status endpoints).
#[derive(Debug, FromRow)]
pub struct FullAdminStatusRow {
    pub status: UserStatus,
    pub suspended_reason: Option<String>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub verified_minor: bool,
    pub verified_minor_at: Option<DateTime<Utc>>,
}

/// Outcome of atomically consuming a claim token and claiming the account.
/// Only `Claimed` mutates anything; the other outcomes guarantee both the
/// token and the user row are untouched (see
/// `UserRepository::claim_account_consuming_token`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimConsumeOutcome {
    /// Token consumed and account claimed in one transaction.
    Claimed { user_pubkey: String },
    /// Token was used, admin-invalidated, expired, or unknown — nothing mutated.
    TokenNotConsumable,
    /// Token was valid but the user row was not claimable (already has an
    /// email) — the token consume was rolled back, nothing mutated.
    UserNotClaimable,
}

/// Repository for user-related database operations.
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    /// Create a new UserRepository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find a user by their public key.
    pub async fn find_by_pubkey(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
    ) -> Result<User, RepositoryError> {
        sqlx::query_as::<_, User>(
            "SELECT pubkey, created_at, updated_at, status, suspended_reason, suspended_at FROM users WHERE tenant_id = $1 AND pubkey = $2",
        )
        .bind(tenant_id)
        .bind(pubkey.to_hex())
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a user by pubkey, or create them if they don't exist.
    /// Returns the user (existing or newly created).
    pub async fn find_or_create(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
    ) -> Result<User, RepositoryError> {
        let pubkey_hex = pubkey.to_hex();

        // Use upsert pattern: INSERT ... ON CONFLICT ... RETURNING
        // This is atomic and handles the race condition properly
        sqlx::query_as::<_, User>(
            "INSERT INTO users (tenant_id, pubkey, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             ON CONFLICT (pubkey) DO UPDATE SET updated_at = users.updated_at
             RETURNING pubkey, created_at, updated_at, status, suspended_reason, suspended_at",
        )
        .bind(tenant_id)
        .bind(&pubkey_hex)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if a user is an admin of a specific team.
    ///
    /// The `tenant_id` parameter is reserved for future multi-tenant isolation
    /// at the team_users level. Currently, tenant isolation is enforced at the
    /// team level by handlers validating team ownership before calling this.
    #[allow(unused_variables)]
    pub async fn is_team_admin(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2 AND role = 'admin'",
        )
        .bind(pubkey.to_hex())
        .bind(team_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Check if a user is a member (non-admin) of a specific team.
    ///
    /// The `tenant_id` parameter is reserved for future multi-tenant isolation.
    #[allow(unused_variables)]
    pub async fn is_team_member(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2 AND role = 'member'",
        )
        .bind(pubkey.to_hex())
        .bind(team_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Check if a user is part of a team (admin or member).
    ///
    /// The `tenant_id` parameter is reserved for future multi-tenant isolation.
    #[allow(unused_variables)]
    pub async fn is_team_teammate(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2",
        )
        .bind(pubkey.to_hex())
        .bind(team_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    // =========================================================================
    // Authentication methods
    // =========================================================================

    /// Check if a user exists by pubkey.
    pub async fn exists(&self, pubkey: &str, tenant_id: i64) -> Result<bool, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE pubkey = $1 AND tenant_id = $2")
                .bind(pubkey)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.is_some())
    }

    /// Find user pubkey by email for login.
    pub async fn find_pubkey_by_email(
        &self,
        email: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = $2")
                .bind(email)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.map(|r| r.0))
    }

    /// Find user pubkey by username (for NIP-05).
    pub async fn find_pubkey_by_username(
        &self,
        username: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT pubkey FROM users WHERE LOWER(username) = LOWER($1) AND tenant_id = $2",
        )
        .bind(username)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.map(|r| r.0))
    }

    /// Find user with password hash, email verification status, and account status for login verification.
    /// Returns (pubkey, password_hash, email_verified, status).
    pub async fn find_with_password(
        &self,
        email: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String, bool, UserStatus)>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, password_hash, email_verified, status FROM users WHERE email = $1 AND tenant_id = $2 AND password_hash IS NOT NULL",
        )
        .bind(email)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create a new user with email/password credentials.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_credentials(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        email_verified: bool,
        verification_token: &str,
        verification_expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(email_verified)
        .bind(verification_token)
        .bind(verification_expires_at)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Create a new user with email/password and pre-verified status.
    pub async fn create_with_password_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        email_verified: bool,
        email_verification_token: Option<&str>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(email_verified)
        .bind(email_verification_token)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ensure a user exists (create if not exists, for API compatibility).
    pub async fn ensure_exists(&self, pubkey: &str, tenant_id: i64) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Register a new user with email/password and personal key atomically.
    ///
    /// Creates both the user record and personal key in a single transaction,
    /// ensuring consistency if either operation fails.
    ///
    /// # Arguments
    ///
    /// * `password_hash` - Optional password hash. Pass `None` for async bcrypt flow where
    ///   the hash is computed in background and updated later via `UPDATE users SET password_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Duplicate`] if email already exists.
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_with_personal_key(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: Option<&str>,
        verification_token: &str,
        verification_expires_at: DateTime<Utc>,
        encrypted_secret: &[u8],
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Insert user with email verification token
        // password_hash may be NULL for async bcrypt flow (computed in background)
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(false)
        .bind(verification_token)
        .bind(verification_expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Insert personal key
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Email verification methods
    // =========================================================================

    /// Find user by email verification token.
    pub async fn find_by_verification_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<VerificationTokenData>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, email_verification_expires_at, password_hash, created_at, email_verified FROM users
             WHERE email_verification_token = $1 AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark user's email as verified.
    pub async fn verify_email(&self, pubkey: &str, tenant_id: i64) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET email_verified = true, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get email verification status.
    pub async fn get_verification_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, bool, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, email_verified, email_verification_sent_at FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Set new email verification token (for resending verification).
    pub async fn set_verification_token(
        &self,
        pubkey: &str,
        tenant_id: i64,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET email_verification_token = $1, email_verification_expires_at = $2, email_verification_sent_at = $3, updated_at = $4
             WHERE pubkey = $5 AND tenant_id = $6",
        )
        .bind(token)
        .bind(expires_at)
        .bind(Utc::now())
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get email_verified status only.
    pub async fn get_email_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<bool>, RepositoryError> {
        sqlx::query_scalar("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Get email verification status by email address.
    ///
    /// Returns (pubkey, email_verified, last_sent_at) if user exists.
    pub async fn get_verification_status_by_email(
        &self,
        email: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, bool, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, email_verified, email_verification_sent_at FROM users WHERE email = $1 AND tenant_id = $2",
        )
        .bind(email)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Set new email verification token by email address.
    pub async fn set_verification_token_by_email(
        &self,
        email: &str,
        tenant_id: i64,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET email_verification_token = $1, email_verification_expires_at = $2, email_verification_sent_at = $3, updated_at = $4
             WHERE email = $5 AND tenant_id = $6",
        )
        .bind(token)
        .bind(expires_at)
        .bind(Utc::now())
        .bind(Utc::now())
        .bind(email)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // =========================================================================
    // Password reset methods
    // =========================================================================

    /// Set password reset token.
    pub async fn set_password_reset_token(
        &self,
        pubkey: &str,
        tenant_id: i64,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = $3
             WHERE pubkey = $4 AND tenant_id = $5",
        )
        .bind(token)
        .bind(expires_at)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find user by password reset token.
    pub async fn find_by_reset_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, password_reset_expires_at FROM users
             WHERE password_reset_token = $1 AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Reset user's password.
    /// Also clears the reset token and marks email as verified (password reset proves email ownership).
    pub async fn reset_password(
        &self,
        pubkey: &str,
        tenant_id: i64,
        password_hash: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET password_hash = $1,
                 password_reset_token = NULL,
                 password_reset_expires_at = NULL,
                 email_verified = true,
                 email_verification_token = NULL,
                 email_verification_expires_at = NULL,
                 updated_at = $2
             WHERE pubkey = $3 AND tenant_id = $4",
        )
        .bind(password_hash)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // =========================================================================
    // Pending email change (self-serve, dual confirmation)
    // =========================================================================

    /// Store a pending email change (dual-token). Overwrites any existing pending change,
    /// which naturally cancels a prior in-flight change.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_pending_email_change(
        &self,
        pubkey: &str,
        tenant_id: i64,
        new_email: &str,
        old_token: &str,
        new_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE users
             SET pending_email = $1,
                 pending_email_old_token = $2,
                 pending_email_new_token = $3,
                 pending_email_expires_at = $4,
                 pending_email_sent_at = $5,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $5
             WHERE pubkey = $6 AND tenant_id = $7",
        )
        .bind(new_email)
        .bind(old_token)
        .bind(new_token)
        .bind(expires_at)
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Current pending-change target and the timestamp of its last send.
    /// Used to scope the resend cooldown to re-initiations of the *same* target; a change to a
    /// different address is a new request and should not be rate-limited by a prior one.
    /// Returns `(pending_email, pending_email_sent_at)` for the user, or `None` if no user row.
    pub async fn pending_email_send_state(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(Option<String>, Option<DateTime<Utc>>)>, RepositoryError> {
        let row: Option<(Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT pending_email, pending_email_sent_at FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Find a pending change by either the old- or new-address token, and report which side
    /// the token belongs to.
    pub async fn find_by_pending_email_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<(PendingEmailChange, PendingEmailSide)>, RepositoryError> {
        // Select both token columns so we can decide the side without trusting the caller.
        type Row = (
            String,                // pubkey
            Option<String>,        // pending_email
            Option<DateTime<Utc>>, // pending_email_expires_at
            Option<DateTime<Utc>>, // pending_email_old_confirmed_at
            Option<DateTime<Utc>>, // pending_email_new_confirmed_at
            Option<String>,        // pending_email_old_token
            Option<String>,        // pending_email_new_token
        );
        let row: Option<Row> = sqlx::query_as(
            "SELECT pubkey, pending_email, pending_email_expires_at,
                    pending_email_old_confirmed_at, pending_email_new_confirmed_at,
                    pending_email_old_token, pending_email_new_token
             FROM users
             WHERE (pending_email_old_token = $1 OR pending_email_new_token = $1)
               AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(pubkey, email, expires, old_conf, new_conf, old_tok, _new_tok)| {
                let side = if old_tok.as_deref() == Some(token) {
                    PendingEmailSide::Old
                } else {
                    PendingEmailSide::New
                };
                (
                    PendingEmailChange {
                        pubkey,
                        pending_email: email,
                        pending_email_expires_at: expires,
                        pending_email_old_confirmed_at: old_conf,
                        pending_email_new_confirmed_at: new_conf,
                    },
                    side,
                )
            },
        ))
    }

    /// Record confirmation from one side of a pending email change.
    ///
    /// Token-gated: the UPDATE only applies when the per-side token still matches the row, so a
    /// token whose side was resolved before a concurrent re-initiation rotated the tokens cannot
    /// mark a *different* pending change confirmed. Returns `true` iff a row was updated; `false`
    /// means the change was superseded and the caller should treat the token as no longer valid.
    pub async fn mark_pending_email_confirmed(
        &self,
        pubkey: &str,
        tenant_id: i64,
        side: PendingEmailSide,
        token: &str,
    ) -> Result<bool, RepositoryError> {
        // Column names are a fixed internal mapping, never user input.
        let (confirmed_col, token_col) = match side {
            PendingEmailSide::Old => ("pending_email_old_confirmed_at", "pending_email_old_token"),
            PendingEmailSide::New => ("pending_email_new_confirmed_at", "pending_email_new_token"),
        };
        let sql = format!(
            "UPDATE users SET {confirmed_col} = $1, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3 AND {token_col} = $4"
        );
        let result = sqlx::query(&sql)
            .bind(Utc::now())
            .bind(pubkey)
            .bind(tenant_id)
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically finalize the pending email change **only if both addresses have confirmed**,
    /// then clear pending state. Evaluating both confirmations and applying the swap in a single
    /// UPDATE avoids a TOCTOU race when the two confirmation links are clicked concurrently.
    ///
    /// Safe to key on pubkey+tenant without a token because [`Self::set_pending_email_change`]
    /// resets **both** `confirmed_at` columns atomically on every (re-)initiation. "Both sides
    /// confirmed" can therefore only ever be true for the *current* change, so this guard cannot
    /// finalize a superseded or partially-approved one. That invariant is load-bearing: if
    /// re-initiation ever stopped clearing confirmations, this path would need token-gating too.
    ///
    /// Returns:
    /// - `Finalized` if the swap was applied.
    /// - `NotReady` if both sides have not yet confirmed (or there is no pending change).
    /// - `EmailTaken` if the target email was registered by someone else in the meantime
    ///   (unique violation); pending state is cleared so the user can restart.
    pub async fn finalize_email_change_if_ready(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<FinalizeEmailOutcome, RepositoryError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE users
             SET email = pending_email,
                 email_verified = true,
                 pending_email = NULL,
                 pending_email_old_token = NULL,
                 pending_email_new_token = NULL,
                 pending_email_expires_at = NULL,
                 pending_email_sent_at = NULL,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3
               AND pending_email IS NOT NULL
               AND pending_email_old_confirmed_at IS NOT NULL
               AND pending_email_new_confirmed_at IS NOT NULL",
        )
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => Ok(FinalizeEmailOutcome::Finalized),
            Ok(_) => Ok(FinalizeEmailOutcome::NotReady),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                self.clear_pending_email_change(pubkey, tenant_id).await?;
                Ok(FinalizeEmailOutcome::EmailTaken)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Clear a pending email change only if `token` still matches one of its two token columns.
    ///
    /// Used by the cancel path: gating on the token prevents a cancel link whose change was
    /// superseded by a concurrent re-initiation from wiping the fresh, legitimate change. Returns
    /// `true` iff a row was cleared. The unconditional [`Self::clear_pending_email_change`] remains
    /// for the finalize cleanup path, which must clear regardless of token.
    pub async fn clear_pending_email_change_by_token(
        &self,
        pubkey: &str,
        tenant_id: i64,
        token: &str,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "UPDATE users
             SET pending_email = NULL,
                 pending_email_old_token = NULL,
                 pending_email_new_token = NULL,
                 pending_email_expires_at = NULL,
                 pending_email_sent_at = NULL,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3
               AND (pending_email_old_token = $4 OR pending_email_new_token = $4)",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .bind(token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Clear any pending email change (cleanup path: finalize's EmailTaken branch).
    ///
    /// Unconditional by design — the cancel path uses the token-gated
    /// [`Self::clear_pending_email_change_by_token`] instead.
    pub async fn clear_pending_email_change(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET pending_email = NULL,
                 pending_email_old_token = NULL,
                 pending_email_new_token = NULL,
                 pending_email_expires_at = NULL,
                 pending_email_sent_at = NULL,
                 pending_email_old_confirmed_at = NULL,
                 pending_email_new_confirmed_at = NULL,
                 updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update user's password hash (for authenticated password change).
    pub async fn update_password(
        &self,
        pubkey: &str,
        tenant_id: i64,
        password_hash: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET password_hash = $1, updated_at = $2 WHERE pubkey = $3 AND tenant_id = $4",
        )
        .bind(password_hash)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find user with email, password hash, and email verified status (for key export verification).
    pub async fn find_with_password_and_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String, bool)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    // =========================================================================
    // Profile methods
    // =========================================================================

    /// Get user's username.
    pub async fn get_username(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<Option<String>>, RepositoryError> {
        sqlx::query_as("SELECT username FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map(|opt: Option<(Option<String>,)>| opt.map(|r| r.0))
            .map_err(Into::into)
    }

    /// Get username for a globally unique pubkey.
    pub async fn get_username_by_pubkey(
        &self,
        pubkey: &str,
    ) -> Result<Option<Option<String>>, RepositoryError> {
        sqlx::query_as("SELECT username FROM users WHERE pubkey = $1")
            .bind(pubkey)
            .fetch_optional(&self.pool)
            .await
            .map(|opt: Option<(Option<String>,)>| opt.map(|r| r.0))
            .map_err(Into::into)
    }

    /// Get user's email, verified status, and account status.
    /// Returns None if user doesn't exist.
    pub async fn get_account_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<AccountStatusRow>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, email_verified, status, suspended_reason FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Like `get_account_status`, but also returns the approved-minor flag and timestamp
    /// (see [`AccountStatusWithMinorRow`]).
    /// Backs `GET /user/account` so clients can detect the protected-minor (13-15) state
    /// directly from Keycast. Kept separate from `get_account_status` so the oauth
    /// login/session paths that share that method are untouched.
    pub async fn get_account_status_with_minor(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<AccountStatusWithMinorRow>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, email_verified, status, suspended_reason, verified_minor, verified_minor_at \
             FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get user's account status fields for admin queries.
    /// Returns (status, suspended_reason, suspended_at) or None if user not found.
    pub async fn get_user_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(UserStatus, Option<String>, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT status, suspended_reason, suspended_at FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Set user's account status. Clears suspended_reason/suspended_at when setting to active.
    /// Preserves suspended_at when escalating between non-active states (e.g. suspended → banned).
    /// Returns (old_status, new_status, suspended_reason, suspended_at) atomically via CTE.
    pub async fn set_user_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
        status: &UserStatus,
        reason: Option<&str>,
    ) -> Result<StatusTransition, RepositoryError> {
        let now = Utc::now();
        let suspended_reason: Option<&str> = if status.is_active() { None } else { reason };
        // When setting to active, clear suspended_at. When restricting, preserve existing
        // suspended_at if already set (escalation), otherwise set it now.
        let row: Option<StatusTransition> = sqlx::query_as(
            "WITH old AS (SELECT status, suspended_at FROM users WHERE pubkey = $5 AND tenant_id = $6) \
             UPDATE users SET status = $1, suspended_reason = $2, \
               suspended_at = CASE WHEN $1 = 'active' THEN NULL \
                                   WHEN (SELECT suspended_at FROM old) IS NOT NULL THEN (SELECT suspended_at FROM old) \
                                   ELSE $3 END, \
               updated_at = $4 \
             WHERE pubkey = $5 AND tenant_id = $6 \
             RETURNING (SELECT status FROM old), users.status, users.suspended_reason, users.suspended_at",
        )
        .bind(status.as_str())
        .bind(suspended_reason)
        .bind(now)
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or_else(|| RepositoryError::NotFound("user not found".to_string()))
    }

    /// Check if username is available (excluding a specific pubkey).
    pub async fn check_username_available(
        &self,
        username: &str,
        exclude_pubkey: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT pubkey FROM users WHERE LOWER(username) = LOWER($1) AND pubkey != $2 AND tenant_id = $3",
        )
        .bind(username)
        .bind(exclude_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.is_none())
    }

    /// Update user's username.
    pub async fn update_username(
        &self,
        pubkey: &str,
        username: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET username = $1, updated_at = $2 WHERE pubkey = $3 AND tenant_id = $4",
        )
        .bind(username)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update a user's ATProto lifecycle state.
    pub async fn set_atproto_state(
        &self,
        pubkey: &str,
        tenant_id: i64,
        enabled: bool,
        state: Option<&str>,
        did: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE users
             SET atproto_enabled = $1,
                 atproto_state = $2,
                 atproto_did = $3,
                 atproto_error = $4,
                 atproto_updated_at = $5,
                 updated_at = $5
             WHERE pubkey = $6 AND tenant_id = $7",
        )
        .bind(enabled)
        .bind(state)
        .bind(did)
        .bind(error)
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound("user not found".to_string()));
        }

        Ok(())
    }

    /// Update a user's ATProto lifecycle state using globally unique pubkey lookup.
    pub async fn set_atproto_state_by_pubkey(
        &self,
        pubkey: &str,
        enabled: bool,
        state: Option<&str>,
        did: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE users
             SET atproto_enabled = $1,
                 atproto_state = $2,
                 atproto_did = $3,
                 atproto_error = $4,
                 atproto_updated_at = $5,
                 updated_at = $5
             WHERE pubkey = $6",
        )
        .bind(enabled)
        .bind(state)
        .bind(did)
        .bind(error)
        .bind(now)
        .bind(pubkey)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound("user not found".to_string()));
        }

        Ok(())
    }

    /// Get a user's ATProto lifecycle state.
    pub async fn get_atproto_state(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<UserAtprotoState>, RepositoryError> {
        sqlx::query_as::<_, UserAtprotoState>(
            "SELECT
                atproto_enabled AS enabled,
                atproto_state AS state,
                atproto_did AS did,
                atproto_error AS error,
                atproto_updated_at AS updated_at
             FROM users
             WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get a user's ATProto lifecycle state using globally unique pubkey lookup.
    pub async fn get_atproto_state_by_pubkey(
        &self,
        pubkey: &str,
    ) -> Result<Option<UserAtprotoState>, RepositoryError> {
        sqlx::query_as::<_, UserAtprotoState>(
            "SELECT
                atproto_enabled AS enabled,
                atproto_state AS state,
                atproto_did AS did,
                atproto_error AS error,
                atproto_updated_at AS updated_at
             FROM users
             WHERE pubkey = $1",
        )
        .bind(pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get user's email and password hash for credential verification.
    pub async fn get_credentials(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, password_hash FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get user's email, password hash, and verified status.
    pub async fn get_credentials_with_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String, bool)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get user's email (for token exchange).
    pub async fn get_email(&self, pubkey: &str, tenant_id: i64) -> Result<String, RepositoryError> {
        sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Key change methods
    // =========================================================================

    /// Orphan user's identity (clear email/password for key change).
    pub async fn orphan_identity(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET email = NULL, password_hash = NULL, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Finalize OAuth registration atomically.
    ///
    /// Creates user and personal key records, then deletes the one-time oauth code.
    /// Used in the token exchange flow to finalize pending registrations.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_oauth_registration(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        verification_token: &str,
        verification_expires_at: DateTime<Utc>,
        encrypted_secret: &[u8],
        oauth_code: &str,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Create users row
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(false)
        .bind(verification_token)
        .bind(verification_expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Create personal_keys row
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Delete the oauth code (one-time use)
        sqlx::query("DELETE FROM oauth_codes WHERE tenant_id = $1 AND code = $2")
            .bind(tenant_id)
            .bind(oauth_code)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Fetch the registration-relevant state of an existing users row.
    ///
    /// Returns `None` when no row exists for this pubkey in the tenant.
    pub async fn oauth_registration_state(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<OAuthRegistrationState>, RepositoryError> {
        sqlx::query_as(
            "SELECT u.email,
                    u.email_verified,
                    u.password_hash IS NOT NULL AS has_password_hash,
                    EXISTS(SELECT 1 FROM personal_keys pk WHERE pk.user_pubkey = u.pubkey) AS has_personal_key
             FROM users u WHERE u.pubkey = $1 AND u.tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Insert a missing personal key for an existing OAuth user.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the insert query fails.
    pub async fn backfill_personal_key(
        &self,
        pubkey: &str,
        tenant_id: i64,
        encrypted_secret: &[u8],
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $4)
             ON CONFLICT (user_pubkey) DO NOTHING",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Apply a pending OAuth registration to an existing users row.
    ///
    /// Sets email/password/verified state on the row and inserts the personal
    /// key if one is pending and none exists yet, all in one transaction.
    /// If the row already carries the pending email (a concurrent request won
    /// the completion race), this is success: existing credentials are never
    /// rewritten and only a missing personal key is backfilled.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::NotFound`] if no row exists for this pubkey.
    /// Returns [`RepositoryError::Duplicate`] if the email is owned by another
    /// user or the row is already bound to a different email.
    pub async fn complete_pending_oauth_registration(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        verification_token: &str,
        encrypted_secret: Option<&[u8]>,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        let updated = sqlx::query(
            "UPDATE users
             SET email = $1, password_hash = COALESCE(password_hash, $2), email_verified = true,
                 email_verification_token = $3, updated_at = $4
             WHERE pubkey = $5
               AND tenant_id = $6
               AND (
                   email IS NULL
                   OR (email = $1 AND (email_verified = false OR password_hash IS NULL))
               )",
        )
        .bind(email)
        .bind(password_hash)
        .bind(verification_token)
        .bind(now)
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if updated == 0 {
            let existing_state = sqlx::query_as::<_, (Option<String>, bool, bool)>(
                "SELECT email, email_verified, password_hash IS NOT NULL AS has_password_hash
                 FROM users WHERE pubkey = $1 AND tenant_id = $2",
            )
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;

            match existing_state {
                // A concurrent request already applied this exact registration;
                // fall through so a missing personal key can still be backfilled.
                Some((Some(existing), true, true)) if existing == email => {}
                Some(_) => return Err(RepositoryError::Duplicate),
                None => {
                    return Err(RepositoryError::NotFound(format!(
                        "no users row for pubkey {} in tenant {}",
                        pubkey, tenant_id
                    )));
                }
            }
        }

        if let Some(secret) = encrypted_secret {
            sqlx::query(
                "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $4)
                 ON CONFLICT (user_pubkey) DO NOTHING",
            )
            .bind(pubkey)
            .bind(secret)
            .bind(tenant_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Change user's key in a single transaction.
    ///
    /// Performs a complete key rotation:
    /// 1. Counts and deletes OAuth authorizations for the old pubkey
    /// 2. Deletes personal_keys for the old pubkey
    /// 3. Orphans the old user identity (clears email/password)
    /// 4. Creates new user identity with email/password
    /// 5. Creates personal_keys for the new identity
    ///
    /// Returns the count of OAuth authorizations that were deleted.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_key_transaction(
        &self,
        old_pubkey: &str,
        new_pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        encrypted_secret: &[u8],
    ) -> Result<i64, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Count OAuth authorizations that will be deleted (for logging)
        let oauth_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1")
                .bind(old_pubkey)
                .fetch_one(&mut *tx)
                .await?;

        // Delete OAuth authorizations (we can't sign with old nsec anymore)
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
            .bind(old_pubkey)
            .execute(&mut *tx)
            .await?;

        // Delete old personal_keys (we no longer hold old nsec)
        sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(old_pubkey)
            .execute(&mut *tx)
            .await?;

        // Orphan old identity (transfer email/password to NULL)
        sqlx::query(
            "UPDATE users SET email = NULL, password_hash = NULL, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(now)
        .bind(old_pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

        // Create new user identity with email/password
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(new_pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(true) // Keep email verified status
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Create personal_keys for new identity
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(new_pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(oauth_count)
    }

    /// Get verified_minor flag and timestamp for a user.
    pub async fn get_verified_minor(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<VerifiedMinorRow>, RepositoryError> {
        sqlx::query_as(
            "SELECT verified_minor, verified_minor_at FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Clear the verified_minor designation (age-up or revocation).
    /// Idempotent: clearing an already-cleared or never-minor account succeeds.
    /// Returns NotFound only when the user does not exist. Touches only the two
    /// minor columns plus updated_at; never alters status/suspended_reason/suspended_at.
    ///
    /// Returns `true` only when a real transition happened (the flag was set and
    /// is now cleared). A no-op clear (already-cleared or never-minor) returns
    /// `false` and leaves `updated_at` untouched, so callers can audit exactly
    /// the transitions that actually occurred rather than every retry.
    ///
    /// The three cases are distinguished in a single statement so that a missing
    /// user (NotFound) never collapses into an already-cleared no-op: `existing`
    /// probes for the row, `changed` conditionally updates only a set flag, and
    /// the outer SELECT reports both.
    pub async fn clear_verified_minor(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let (user_exists, transitioned): (bool, bool) = sqlx::query_as(
            "WITH existing AS ( \
                 SELECT 1 FROM users WHERE pubkey = $1 AND tenant_id = $2 \
             ), changed AS ( \
                 UPDATE users \
                 SET verified_minor = FALSE, verified_minor_at = NULL, updated_at = $3 \
                 WHERE pubkey = $1 AND tenant_id = $2 AND verified_minor = TRUE \
                 RETURNING 1 \
             ) \
             SELECT EXISTS (SELECT 1 FROM existing), EXISTS (SELECT 1 FROM changed)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await?;

        if !user_exists {
            return Err(RepositoryError::NotFound("user not found".to_string()));
        }
        Ok(transitioned)
    }

    /// Combined status + verified_minor query for admin status endpoints.
    pub async fn get_full_admin_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<FullAdminStatusRow>, RepositoryError> {
        sqlx::query_as(
            "SELECT status, suspended_reason, suspended_at, verified_minor, verified_minor_at \
             FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Look up a user by username, returning enough state to distinguish
    /// unclaimed approved-minors (retryable) from other accounts (conflict).
    /// Returns (pubkey, verified_minor, is_unclaimed) in a single query.
    /// NOTE: `is_unclaimed` relies on email+password_hash being NULL — must stay
    /// in sync with the claim flow that sets both columns on completion.
    pub async fn find_user_minor_status_by_username(
        &self,
        username: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, bool, bool)>, RepositoryError> {
        let result: Option<(String, bool, bool)> = sqlx::query_as(
            "SELECT pubkey, verified_minor,
                    (verified_minor = TRUE AND email IS NULL AND password_hash IS NULL) AS is_unclaimed
             FROM users
             WHERE LOWER(username) = LOWER($1) AND tenant_id = $2",
        )
        .bind(username)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    /// Create an approved minor account with personal key atomically.
    /// Like create_preloaded_user but without vine_id and with verified_minor=true.
    pub async fn create_minor_account(
        &self,
        pubkey: &str,
        tenant_id: i64,
        username: &str,
        display_name: Option<&str>,
        encrypted_secret: &[u8],
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, username, display_name, verified_minor, verified_minor_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, TRUE, $5, $5, $5)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(username)
        .bind(display_name)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Preloaded account methods (for Vine import)
    // =========================================================================

    /// Create a preloaded user with personal key atomically.
    ///
    /// Creates a user without email/password for later claiming.
    /// Used for importing users from external systems (e.g., Vine).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_preloaded_user(
        &self,
        pubkey: &str,
        tenant_id: i64,
        vine_id: &str,
        username: &str,
        display_name: Option<&str>,
        encrypted_secret: &[u8],
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Insert user with vine_id, username, display_name, but no email/password
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, vine_id, username, display_name, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(vine_id)
        .bind(username)
        .bind(display_name)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Insert personal key
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Find user pubkey by vine_id.
    pub async fn find_pubkey_by_vine_id(
        &self,
        vine_id: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
                .bind(vine_id)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.map(|r| r.0))
    }

    /// Check if a user is unclaimed (has no email set).
    /// Returns None if user doesn't exist, Some(true) if unclaimed, Some(false) if claimed.
    pub async fn is_unclaimed(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<bool>, RepositoryError> {
        let result: Option<(Option<String>,)> =
            sqlx::query_as("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
                .bind(pubkey)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.map(|r| r.0.is_none()))
    }

    /// Get user info for claim page (username, display_name).
    pub async fn get_claim_info(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(Option<String>, Option<String>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT username, display_name FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Atomically consume a still-valid claim token and claim the account in
    /// one transaction (#280 review). The consume re-checks full validity
    /// (`used_at IS NULL AND invalidated_at IS NULL AND expires_at > NOW()`)
    /// under the row lock, mirroring the predicates of
    /// `ClaimTokenRepository::invalidate_valid_for_user`. A concurrent admin
    /// invalidation (e.g. clear-verified-minor revoking an unclaimed minor's
    /// outstanding link) therefore either commits first — we consume nothing
    /// and the user is untouched — or blocks on the row lock and matches
    /// nothing after we commit. The user mutation only happens if the token
    /// consume succeeded, and rolls back if the user row itself is not
    /// claimable, so a failed claim never burns the token.
    pub async fn claim_account_consuming_token(
        &self,
        token: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
    ) -> Result<ClaimConsumeOutcome, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let consumed: Option<(String,)> = sqlx::query_as(
            "UPDATE account_claim_tokens
             SET used_at = NOW()
             WHERE token = $1
               AND tenant_id = $2
               AND used_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > NOW()
             RETURNING user_pubkey",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((user_pubkey,)) = consumed else {
            tx.rollback().await?;
            return Ok(ClaimConsumeOutcome::TokenNotConsumable);
        };

        let result = sqlx::query(
            "UPDATE users
             SET email = $1, password_hash = $2, email_verified = true, updated_at = $3
             WHERE pubkey = $4 AND tenant_id = $5 AND email IS NULL",
        )
        .bind(email)
        .bind(password_hash)
        .bind(Utc::now())
        .bind(&user_pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(ClaimConsumeOutcome::UserNotClaimable);
        }

        tx.commit().await?;
        Ok(ClaimConsumeOutcome::Claimed { user_pubkey })
    }

    /// Check if email is already in use.
    pub async fn email_exists(&self, email: &str, tenant_id: i64) -> Result<bool, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = $2")
                .bind(email)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.is_some())
    }

    /// Search for users matching an admin-support query.
    ///
    /// Email queries use case-insensitive substring matching. Non-`npub` queries without an
    /// `@` merge email substring matches with the username, vine ID, and hex-pubkey paths.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when a database query fails.
    pub async fn find_users_for_admin(
        &self,
        query: &str,
        tenant_id: i64,
    ) -> Result<AdminUserLookup, RepositoryError> {
        let normalized_query = query.to_lowercase();
        let (authoritative_pubkeys, primary_loose_pubkeys, email_loose_pubkeys) = if query
            .contains('@')
        {
            if query.len() < 3 {
                (vec![], vec![], vec![])
            } else {
                let exact_email: Vec<(String,)> = sqlx::query_as(
                    "SELECT pubkey FROM users
                     WHERE LOWER(email) = $1
                       AND tenant_id = $2
                       AND email IS NOT NULL
                     ORDER BY pubkey",
                )
                .bind(&normalized_query)
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?;
                let email_pattern = format!("%{}%", escape_like_pattern(&normalized_query));
                let substring_email: Vec<(String,)> = sqlx::query_as(
                    "SELECT pubkey FROM users
                     WHERE email ILIKE $1 ESCAPE '\\'
                       AND LOWER(email) <> $2
                       AND tenant_id = $3
                     ORDER BY LOWER(email), pubkey
                     LIMIT 20",
                )
                .bind(email_pattern)
                .bind(&normalized_query)
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?;
                (
                    exact_email.into_iter().map(|row| row.0).collect(),
                    vec![],
                    substring_email.into_iter().map(|row| row.0).collect(),
                )
            }
        } else if query.starts_with("npub") {
            // Decode npub to hex — at most one result
            match PublicKey::parse(query) {
                Ok(pk) => (vec![pk.to_hex()], vec![], vec![]),
                Err(_) => {
                    return Ok(AdminUserLookup {
                        users: vec![],
                        authoritative_match: false,
                        authoritative_count: 0,
                    });
                }
            }
        } else {
            let email_pattern =
                (query.len() >= 3).then(|| format!("%{}%", escape_like_pattern(&normalized_query)));
            let by_email: Vec<(String,)> = if let Some(email_pattern) = email_pattern {
                sqlx::query_as(
                    "SELECT pubkey FROM users
                     WHERE email ILIKE $1 ESCAPE '\\' AND tenant_id = $2
                     ORDER BY LOWER(email), pubkey
                     LIMIT 20",
                )
                .bind(email_pattern)
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?
            } else {
                vec![]
            };

            // Username: case-insensitive, strip dots, hyphens, and underscores.
            let by_username: Vec<(String,)> = sqlx::query_as(
                "SELECT pubkey FROM users
                 WHERE LOWER(REGEXP_REPLACE(username, '[._\\-]', '', 'g')) = LOWER(REGEXP_REPLACE($1, '[._\\-]', '', 'g'))
                   AND tenant_id = $2
                 ORDER BY pubkey
                 LIMIT 20",
            )
            .bind(query)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;

            let by_vine_id: Vec<(String,)> = sqlx::query_as(
                "SELECT pubkey FROM users
                 WHERE LOWER(vine_id) = LOWER($1) AND tenant_id = $2
                 ORDER BY pubkey
                 LIMIT 20",
            )
            .bind(query)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;

            let by_hex_pubkey = if query.len() == 64
                && query.chars().all(|character| character.is_ascii_hexdigit())
            {
                vec![query.to_lowercase()]
            } else {
                vec![]
            };

            let by_prefix = if by_username.is_empty() && query.len() >= 3 {
                // Prefix search fallback (uses B-tree index on LOWER(username))
                let normalized: String = query
                    .chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect::<String>()
                    .to_lowercase();
                let pattern = format!("{}%", normalized);
                let by_prefix: Vec<(String,)> = sqlx::query_as(
                    "SELECT pubkey FROM users
                     WHERE LOWER(REGEXP_REPLACE(username, '[._\\-]', '', 'g')) LIKE $1
                       AND tenant_id = $2
                     ORDER BY pubkey
                     LIMIT 20",
                )
                .bind(&pattern)
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?;

                by_prefix.into_iter().map(|row| row.0).collect()
            } else {
                vec![]
            };

            let authoritative = by_username
                .into_iter()
                .chain(by_vine_id)
                .map(|row| row.0)
                .chain(by_hex_pubkey)
                .collect();
            (
                authoritative,
                by_prefix,
                by_email.into_iter().map(|row| row.0).collect(),
            )
        };

        let authoritative_pubkey_set: std::collections::HashSet<String> =
            authoritative_pubkeys.iter().cloned().collect();
        let pubkeys = merge_admin_lookup_candidates(
            authoritative_pubkeys,
            primary_loose_pubkeys,
            email_loose_pubkeys,
            vec![],
            Clone::clone,
        );

        if pubkeys.is_empty() {
            return Ok(AdminUserLookup {
                users: vec![],
                authoritative_match: false,
                authoritative_count: 0,
            });
        }

        let mut rows: Vec<AdminUserDetails> = sqlx::query_as(
            "SELECT
                u.pubkey,
                u.email,
                u.email_verified,
                u.username,
                u.display_name,
                u.vine_id,
                (pk.user_pubkey IS NOT NULL) as \"has_personal_key\",
                u.status,
                u.suspended_reason,
                u.verified_minor,
                u.verified_minor_at,
                u.created_at,
                u.updated_at
             FROM users u
             LEFT JOIN personal_keys pk ON pk.user_pubkey = u.pubkey AND pk.tenant_id = u.tenant_id
             WHERE u.pubkey = ANY($1::text[]) AND u.tenant_id = $2
             ORDER BY array_position($1::text[], u.pubkey)",
        )
        .bind(&pubkeys)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        for row in &mut rows {
            row.authoritative = authoritative_pubkey_set.contains(row.pubkey.as_str());
            row.match_kind = if row.authoritative {
                AdminUserMatchKind::Authoritative
            } else {
                AdminUserMatchKind::Partial
            };
        }
        let authoritative_count = rows.iter().filter(|row| row.authoritative).count();

        Ok(AdminUserLookup {
            users: rows,
            authoritative_match: authoritative_count > 0,
            authoritative_count,
        })
    }

    /// Suggest users whose emails contain a typo-near match for an admin query.
    ///
    /// PostgreSQL word similarity supplies a bounded candidate set, then an edit-distance filter
    /// retains only full-address or closest-substring matches within two edits.
    ///
    /// Short queries, npubs, and 64-character hex pubkeys return no suggestions.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when the database query fails for reasons other than a missing
    /// `pg_trgm` operator or function. Databases without `pg_trgm` return no suggestions.
    pub async fn suggest_users_for_admin(
        &self,
        query: &str,
        tenant_id: i64,
    ) -> Result<Vec<AdminUserDetails>, RepositoryError> {
        let is_hex_pubkey = query.len() == 64 && query.chars().all(|char| char.is_ascii_hexdigit());
        if query.len() < 3 || query.starts_with("npub") || is_hex_pubkey {
            return Ok(vec![]);
        }

        let normalized_query = query.to_lowercase();
        let mut transaction = self.pool.begin().await?;
        sqlx::query_scalar::<_, String>(
            "SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)",
        )
        .bind(ADMIN_EMAIL_SUGGESTION_MIN_WORD_SIMILARITY.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        let rows: Result<Vec<AdminUserDetails>, sqlx::Error> =
            sqlx::query_as(ADMIN_EMAIL_SUGGESTION_QUERY)
                .bind(&normalized_query)
                .bind(tenant_id)
                .bind(ADMIN_EMAIL_SUGGESTION_MIN_WORD_SIMILARITY)
                .bind(ADMIN_EMAIL_SUGGESTION_CANDIDATE_LIMIT)
                .fetch_all(&mut *transaction)
                .await;

        match rows {
            Ok(rows) => {
                let mut close_rows = rows
                    .into_iter()
                    .filter_map(|mut user| {
                        let distance = closest_email_edit_distance(
                            &normalized_query,
                            &user.email.as_ref()?.to_lowercase(),
                            ADMIN_EMAIL_SUGGESTION_MAX_EDIT_DISTANCE,
                        )?;
                        (distance > 0).then(|| {
                            user.authoritative = false;
                            user.match_kind = AdminUserMatchKind::Fuzzy;
                            (distance, user)
                        })
                    })
                    .collect::<Vec<_>>();
                close_rows.sort_by_key(|(distance, _)| *distance);
                transaction.commit().await?;
                Ok(close_rows
                    .into_iter()
                    .map(|(_, user)| user)
                    .take(ADMIN_EMAIL_SUGGESTION_LIMIT)
                    .collect())
            }
            Err(error) if is_undefined_postgres_function(&error) => Ok(vec![]),
            Err(error) => Err(error.into()),
        }
    }

    /// Look up multiple users by email for enrichment (batch).
    /// Returns AdminUserDetails for each email that matches a user in the tenant.
    pub async fn find_users_by_emails(
        &self,
        emails: &[String],
        tenant_id: i64,
    ) -> Result<Vec<AdminUserDetails>, RepositoryError> {
        if emails.is_empty() {
            return Ok(vec![]);
        }

        let lowered: Vec<String> = emails.iter().map(|e| e.to_lowercase()).collect();

        let rows: Vec<AdminUserDetails> = sqlx::query_as(
            "SELECT
                u.pubkey,
                u.email,
                u.email_verified,
                u.username,
                u.display_name,
                u.vine_id,
                (pk.user_pubkey IS NOT NULL) as \"has_personal_key\",
                u.status,
                u.suspended_reason,
                u.verified_minor,
                u.verified_minor_at,
                u.created_at,
                u.updated_at
             FROM users u
             LEFT JOIN personal_keys pk ON pk.user_pubkey = u.pubkey AND pk.tenant_id = u.tenant_id
             WHERE LOWER(u.email) = ANY($1::text[])
               AND u.tenant_id = $2
               AND u.email IS NOT NULL",
        )
        .bind(&lowered)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
    /// Delete a user account and all associated data.
    ///
    /// This performs a complete account deletion:
    /// 1. Removes user from all teams (team_users)
    /// 2. Clears pending OAuth codes
    /// 3. Deletes the user (cascades to personal_keys, oauth_authorizations, etc.)
    ///
    /// Returns information about what was deleted for logging.
    pub async fn delete_account(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<DeleteAccountResult, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        // Count teams for logging
        let teams_removed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1")
                .bind(pubkey)
                .fetch_one(&mut *tx)
                .await?;

        // Count OAuth authorizations for logging
        let oauth_authorizations_deleted: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1")
                .bind(pubkey)
                .fetch_one(&mut *tx)
                .await?;

        // Get bunker pubkeys for signer daemon notification (before deletion)
        let bunker_pubkeys: Vec<String> = sqlx::query_scalar(
            "SELECT bunker_public_key FROM oauth_authorizations WHERE user_pubkey = $1",
        )
        .bind(pubkey)
        .fetch_all(&mut *tx)
        .await?;

        // 1. Remove from all teams (no CASCADE, would block user delete)
        sqlx::query("DELETE FROM team_users WHERE user_pubkey = $1")
            .bind(pubkey)
            .execute(&mut *tx)
            .await?;

        // 2. Clear pending OAuth codes
        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;

        // 3. Delete user (cascades to personal_keys, oauth_authorizations -> refresh_tokens,
        //    email_verification_tokens, password_reset_tokens, user_profiles,
        //    account_claim_tokens)
        let result = sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound("User not found".to_string()));
        }

        tx.commit().await?;

        Ok(DeleteAccountResult {
            teams_removed,
            oauth_authorizations_deleted,
            bunker_pubkeys,
        })
    }
}

/// Result of account deletion for logging and signer notification.
#[derive(Debug, Clone)]
pub struct DeleteAccountResult {
    /// Number of teams the user was removed from
    pub teams_removed: i64,
    /// Number of OAuth authorizations that were deleted
    pub oauth_authorizations_deleted: i64,
    /// Bunker public keys for signer daemon notification
    pub bunker_pubkeys: Vec<String>,
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use nostr_sdk::Keys;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;

    async fn setup_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

        // Safety check: don't run on production
        assert!(
            database_url.contains("localhost") || database_url.contains("127.0.0.1"),
            "Tests must run against localhost database"
        );

        PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database")
    }

    fn test_suffix() -> String {
        uuid::Uuid::new_v4().to_string()[..8].to_string()
    }

    fn plan_mentions_index(plan: &serde_json::Value, index_name: &str) -> bool {
        match plan {
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| plan_mentions_index(value, index_name)),
            serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
                (key == "Index Name" && value.as_str() == Some(index_name))
                    || plan_mentions_index(value, index_name)
            }),
            _ => false,
        }
    }

    async fn create_test_team(pool: &PgPool, name: &str) -> i32 {
        let result: (i32,) = sqlx::query_as(
            "INSERT INTO teams (name, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())
             RETURNING id",
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
        result.0
    }

    async fn add_user_to_team(pool: &PgPool, pubkey: &str, team_id: i32, role: &str) {
        sqlx::query(
            "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             ON CONFLICT (team_id, user_pubkey) DO NOTHING",
        )
        .bind(team_id)
        .bind(pubkey)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_find_by_pubkey_returns_user() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        // Create user directly
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(pubkey.to_hex())
        .execute(&pool)
        .await
        .unwrap();

        // Find via repository
        let result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(result.is_ok(), "Should find user");
        assert_eq!(result.unwrap().pubkey, pubkey.to_hex());
    }

    #[tokio::test]
    async fn test_find_by_pubkey_not_found() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool);
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        let result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_find_or_create_creates_new() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        // User doesn't exist yet
        let find_result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));

        // Find or create should create
        let result = repo.find_or_create(1, &pubkey).await;
        assert!(result.is_ok(), "Should create user");
        assert_eq!(result.unwrap().pubkey, pubkey.to_hex());

        // Now user exists
        let find_result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(find_result.is_ok(), "User should exist now");
    }

    #[tokio::test]
    async fn test_find_or_create_returns_existing() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        // Create user first
        let first = repo.find_or_create(1, &pubkey).await.unwrap();

        // Call again - should return same user
        let second = repo.find_or_create(1, &pubkey).await.unwrap();
        assert_eq!(first.pubkey, second.pubkey);
    }

    #[tokio::test]
    async fn test_is_team_admin_true_for_admin() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Admin Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "admin").await;

        let result = repo.is_team_admin(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "User should be admin");
    }

    #[tokio::test]
    async fn test_is_team_admin_false_for_member() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Member Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "member").await;

        let result = repo.is_team_admin(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Member should not be admin");
    }

    #[tokio::test]
    async fn test_is_team_member_true() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Member Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "member").await;

        let result = repo.is_team_member(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "User should be member");
    }

    #[tokio::test]
    async fn test_is_team_member_false() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team but don't add to team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("No Member Test {}", suffix)).await;

        let result = repo.is_team_member(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "User should not be member");
    }

    #[tokio::test]
    async fn test_is_team_teammate_true() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Teammate Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "admin").await;

        let result = repo.is_team_teammate(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "User should be teammate");
    }

    #[tokio::test]
    async fn test_is_team_teammate_false() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team but don't add to team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("No Teammate Test {}", suffix)).await;

        let result = repo.is_team_teammate(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "User should not be teammate");
    }

    async fn create_user_with_email(pool: &PgPool, pubkey: &str, email: &str) {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, true, NOW(), NOW())",
        )
        .bind(pubkey)
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_user_with_username(pool: &PgPool, pubkey: &str, username: &str) {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
             VALUES ($1, 1, $2, NOW(), NOW())",
        )
        .bind(pubkey)
        .bind(username)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn cleanup_user(pool: &PgPool, pubkey: &str) {
        sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_find_users_for_admin_normalized_username() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let k1 = Keys::generate();
        let h1 = k1.public_key().to_hex();
        let k2 = Keys::generate();
        let h2 = k2.public_key().to_hex();
        let k3 = Keys::generate();
        let h3 = k3.public_key().to_hex();

        // Three users with equivalent admin-search usernames. They must remain distinct under
        // LOWER(username), because NIP-05 usernames are now case-insensitively unique per tenant.
        create_user_with_username(&pool, &h1, &format!("Lele.Pons-{}", suffix)).await;
        create_user_with_username(&pool, &h2, &format!("lele_pons-{}", suffix)).await;
        create_user_with_username(&pool, &h3, &format!("LELE-PONS-{}", suffix)).await;

        let lookup = repo
            .find_users_for_admin(&format!("lelepons-{}", suffix), 1)
            .await
            .unwrap();
        let results = lookup.users;
        assert_eq!(results.len(), 3, "Should find all 3 normalized matches");

        let found_pubkeys: Vec<&str> = results.iter().map(|u| u.pubkey.as_str()).collect();
        assert!(found_pubkeys.contains(&h1.as_str()));
        assert!(found_pubkeys.contains(&h2.as_str()));
        assert!(found_pubkeys.contains(&h3.as_str()));

        cleanup_user(&pool, &h1).await;
        cleanup_user(&pool, &h2).await;
        cleanup_user(&pool, &h3).await;
    }

    #[tokio::test]
    async fn test_find_users_for_admin_surfaces_verified_minor() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let pubkey = Keys::generate().public_key().to_hex();
        let username = format!("minoruser-{}", suffix);
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, username, verified_minor, verified_minor_at, created_at, updated_at) \
             VALUES ($1, 1, $2, TRUE, NOW(), NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

        let results = repo.find_users_for_admin(&username, 1).await.unwrap().users;
        assert_eq!(results.len(), 1, "should find the verified-minor user");
        assert!(
            results[0].verified_minor,
            "admin lookup must surface verified_minor so support sees the terminal age-review state"
        );
        assert!(
            results[0].verified_minor_at.is_some(),
            "verified_minor_at should accompany a set flag"
        );

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_find_users_for_admin_merges_email_contains_with_username_matches() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("socialp{suffix}");
        let username_pubkey = Keys::generate().public_key().to_hex();
        let email_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_username(&pool, &username_pubkey, &query).await;
        create_user_with_email(
            &pool,
            &email_pubkey,
            &format!("creator+{query}@example.com"),
        )
        .await;

        let results = repo.find_users_for_admin(&query, 1).await.unwrap().users;
        let found_pubkeys: Vec<&str> = results.iter().map(|user| user.pubkey.as_str()).collect();
        assert!(found_pubkeys.contains(&username_pubkey.as_str()));
        assert!(found_pubkeys.contains(&email_pubkey.as_str()));

        cleanup_user(&pool, &username_pubkey).await;
        cleanup_user(&pool, &email_pubkey).await;
    }

    #[tokio::test]
    async fn test_find_users_for_admin_by_email_domain_suffix() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let domain = format!("@lookup-{suffix}.test");
        let first_pubkey = Keys::generate().public_key().to_hex();
        let second_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(&pool, &first_pubkey, &format!("first{domain}")).await;
        create_user_with_email(&pool, &second_pubkey, &format!("second{domain}")).await;

        let results = repo.find_users_for_admin(&domain, 1).await.unwrap().users;
        let found_pubkeys: Vec<&str> = results.iter().map(|user| user.pubkey.as_str()).collect();
        assert_eq!(found_pubkeys.len(), 2);
        assert!(found_pubkeys.contains(&first_pubkey.as_str()));
        assert!(found_pubkeys.contains(&second_pubkey.as_str()));

        cleanup_user(&pool, &first_pubkey).await;
        cleanup_user(&pool, &second_pubkey).await;
    }

    #[tokio::test]
    async fn test_find_users_for_admin_places_exact_email_before_substrings() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("exact-{suffix}@lookup.test");
        let substring_pubkey = Keys::generate().public_key().to_hex();
        let exact_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(&pool, &substring_pubkey, &format!("prefix-{query}")).await;
        create_user_with_email(&pool, &exact_pubkey, &query).await;

        let lookup = repo.find_users_for_admin(&query, 1).await.unwrap();
        assert!(lookup.authoritative_match);
        assert_eq!(lookup.authoritative_count, 1);
        assert_eq!(lookup.users[0].pubkey, exact_pubkey);
        assert!(lookup.users[0].authoritative);
        assert_eq!(lookup.users[1].pubkey, substring_pubkey);
        assert!(!lookup.users[1].authoritative);

        cleanup_user(&pool, &substring_pubkey).await;
        cleanup_user(&pool, &exact_pubkey).await;
    }

    #[tokio::test]
    async fn test_find_users_for_admin_reports_authoritative_and_partial_match_kinds() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("kind-{suffix}@lookup.test");
        let exact_pubkey = Keys::generate().public_key().to_hex();
        let partial_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(&pool, &exact_pubkey, &query).await;
        create_user_with_email(&pool, &partial_pubkey, &format!("prefix-{query}")).await;

        let lookup = repo.find_users_for_admin(&query, 1).await.unwrap();
        assert_eq!(
            lookup.users[0].match_kind,
            AdminUserMatchKind::Authoritative
        );
        assert_eq!(lookup.users[1].match_kind, AdminUserMatchKind::Partial);

        cleanup_user(&pool, &exact_pubkey).await;
        cleanup_user(&pool, &partial_pubkey).await;
    }

    #[tokio::test]
    async fn test_find_users_for_admin_keeps_case_variant_exact_emails() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("duplicate-{suffix}@lookup.test");
        let lowercase_pubkey = Keys::generate().public_key().to_hex();
        let uppercase_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(&pool, &lowercase_pubkey, &query).await;
        create_user_with_email(&pool, &uppercase_pubkey, &query.to_uppercase()).await;

        let lookup = repo.find_users_for_admin(&query, 1).await.unwrap();
        let found_pubkeys: Vec<&str> = lookup
            .users
            .iter()
            .map(|user| user.pubkey.as_str())
            .collect();
        assert!(lookup.authoritative_match);
        assert_eq!(lookup.authoritative_count, 2);
        assert_eq!(found_pubkeys.len(), 2);
        assert!(found_pubkeys.contains(&lowercase_pubkey.as_str()));
        assert!(found_pubkeys.contains(&uppercase_pubkey.as_str()));

        cleanup_user(&pool, &lowercase_pubkey).await;
        cleanup_user(&pool, &uppercase_pubkey).await;
    }

    #[tokio::test]
    async fn test_exact_email_lookup_has_matching_functional_index() {
        let pool = setup_pool().await;
        let index_definition: Option<String> = sqlx::query_scalar(
            "SELECT indexdef
             FROM pg_indexes
             WHERE schemaname = 'public'
               AND tablename = 'users'
               AND indexname = 'idx_users_tenant_lower_email'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let index_definition =
            index_definition.expect("exact email lookup should have a matching functional index");
        assert!(index_definition.contains("(tenant_id, lower(email))"));
        assert!(index_definition.contains("WHERE (email IS NOT NULL)"));
    }

    #[tokio::test]
    async fn test_find_users_for_admin_keeps_username_and_email_candidates_at_limit() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("mixed{suffix}");
        let mut username_pubkeys = Vec::new();
        let mut email_pubkeys = Vec::new();

        for index in 0..20 {
            let username_pubkey = Keys::generate().public_key().to_hex();
            create_user_with_username(
                &pool,
                &username_pubkey,
                &format!("{query}-username-{index:02}"),
            )
            .await;
            username_pubkeys.push(username_pubkey);

            let email_pubkey = Keys::generate().public_key().to_hex();
            create_user_with_email(
                &pool,
                &email_pubkey,
                &format!("owner-{index:02}+{query}@lookup.test"),
            )
            .await;
            email_pubkeys.push(email_pubkey);
        }

        let lookup = repo.find_users_for_admin(&query, 1).await.unwrap();
        assert!(!lookup.authoritative_match);
        assert_eq!(lookup.authoritative_count, 0);
        assert_eq!(lookup.users.len(), 20);
        assert!(lookup
            .users
            .iter()
            .any(|user| username_pubkeys.contains(&user.pubkey)));
        assert!(lookup
            .users
            .iter()
            .any(|user| email_pubkeys.contains(&user.pubkey)));

        for pubkey in username_pubkeys.iter().chain(&email_pubkeys) {
            cleanup_user(&pool, pubkey).await;
        }
    }

    #[tokio::test]
    async fn test_find_users_for_admin_escapes_email_contains_wildcards() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("literal%_{suffix}");
        let literal_pubkey = Keys::generate().public_key().to_hex();
        let wildcard_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(
            &pool,
            &literal_pubkey,
            &format!("owner+{query}@example.com"),
        )
        .await;
        create_user_with_email(
            &pool,
            &wildcard_pubkey,
            &format!("owner+literalXX{suffix}@example.com"),
        )
        .await;

        let results = repo.find_users_for_admin(&query, 1).await.unwrap().users;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pubkey, literal_pubkey);

        cleanup_user(&pool, &literal_pubkey).await;
        cleanup_user(&pool, &wildcard_pubkey).await;
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_bounds_database_candidates() {
        let pool = setup_pool().await;
        let explain_sql = format!("EXPLAIN (FORMAT JSON) {ADMIN_EMAIL_SUGGESTION_QUERY}");
        let plan: serde_json::Value = sqlx::query_scalar(&explain_sql)
            .bind("missing@example.com")
            .bind(1_i64)
            .bind(ADMIN_EMAIL_SUGGESTION_MIN_WORD_SIMILARITY)
            .bind(ADMIN_EMAIL_SUGGESTION_CANDIDATE_LIMIT)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(plan[0]["Plan"]["Node Type"], "Limit");
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_uses_the_email_trigram_index() {
        let pool = setup_pool().await;
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
             SELECT
                md5('admin-email-trgm-noise-' || value)::text || md5('admin-email-trgm-suffix-' || value)::text,
                1,
                'noise-' || value || '@example.com',
                NOW(),
                NOW()
             FROM generate_series(1, 20000) value",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
             VALUES (
                md5('admin-email-trgm-match')::text || md5('admin-email-trgm-match-suffix')::text,
                1,
                'socialpublishcommunity@example.com',
                NOW(),
                NOW()
             )",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("ANALYZE users")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query_scalar::<_, String>(
            "SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)",
        )
        .bind(ADMIN_EMAIL_SUGGESTION_MIN_WORD_SIMILARITY.to_string())
        .fetch_one(&mut *transaction)
        .await
        .unwrap();

        let explain_sql = format!("EXPLAIN (FORMAT JSON) {ADMIN_EMAIL_SUGGESTION_QUERY}");
        let plan: serde_json::Value = sqlx::query_scalar(&explain_sql)
            .bind("publish")
            .bind(1_i64)
            .bind(ADMIN_EMAIL_SUGGESTION_MIN_WORD_SIMILARITY)
            .bind(ADMIN_EMAIL_SUGGESTION_CANDIDATE_LIMIT)
            .fetch_one(&mut *transaction)
            .await
            .unwrap();

        assert!(
            plan_mentions_index(&plan, "idx_users_email_trgm"),
            "the production suggestion query should use idx_users_email_trgm: {plan}"
        );
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_ranks_close_emails_and_excludes_distant_ones() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("socialpublishllc-{suffix}@lookup.test");
        let closest_pubkey = Keys::generate().public_key().to_hex();
        let two_edits_pubkey = Keys::generate().public_key().to_hex();
        let farther_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(
            &pool,
            &closest_pubkey,
            &format!("socialpulishllc-{suffix}@lookup.test"),
        )
        .await;
        create_user_with_email(
            &pool,
            &two_edits_pubkey,
            &format!("socialpulishllx-{suffix}@lookup.test"),
        )
        .await;
        create_user_with_email(
            &pool,
            &farther_pubkey,
            &format!("socialllc-{suffix}@lookup.test"),
        )
        .await;

        assert!(repo
            .find_users_for_admin(&query, 1)
            .await
            .unwrap()
            .users
            .is_empty());
        let suggestions = repo.suggest_users_for_admin(&query, 1).await.unwrap();
        let closest_position = suggestions
            .iter()
            .position(|user| user.pubkey == closest_pubkey)
            .expect("one-edit email should be suggested");
        let two_edits_position = suggestions
            .iter()
            .position(|user| user.pubkey == two_edits_pubkey)
            .expect("two-edit email should be suggested");
        assert!(closest_position < two_edits_position);
        assert!(!suggestions.iter().any(|user| user.pubkey == farther_pubkey));

        cleanup_user(&pool, &closest_pubkey).await;
        cleanup_user(&pool, &two_edits_pubkey).await;
        cleanup_user(&pool, &farther_pubkey).await;
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_finds_a_typo_near_partial_email_fragment() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("publish{suffix}");
        let partial_pubkey = Keys::generate().public_key().to_hex();
        let fuzzy_pubkey = Keys::generate().public_key().to_hex();

        create_user_with_email(
            &pool,
            &partial_pubkey,
            &format!("social{query}llc@gmail.com"),
        )
        .await;
        create_user_with_email(
            &pool,
            &fuzzy_pubkey,
            &format!("socialpulish{suffix}llc@gmail.com"),
        )
        .await;

        let primary = repo.find_users_for_admin(&query, 1).await.unwrap().users;
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].pubkey, partial_pubkey);
        assert_eq!(primary[0].match_kind, AdminUserMatchKind::Partial);

        let suggestions = repo.suggest_users_for_admin(&query, 1).await.unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].pubkey, fuzzy_pubkey);
        assert_eq!(suggestions[0].match_kind, AdminUserMatchKind::Fuzzy);

        cleanup_user(&pool, &partial_pubkey).await;
        cleanup_user(&pool, &fuzzy_pubkey).await;
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_keeps_fuzzy_fragments_tenant_scoped() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("publish{suffix}");
        let local_pubkey = Keys::generate().public_key().to_hex();
        let foreign_pubkey = Keys::generate().public_key().to_hex();
        let foreign_tenant_id: i64 = sqlx::query_scalar(
            "INSERT INTO tenants (domain, name, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id",
        )
        .bind(format!("fuzzy-{suffix}.lookup.test"))
        .bind(format!("Fuzzy tenant {suffix}"))
        .fetch_one(&pool)
        .await
        .unwrap();

        create_user_with_email(
            &pool,
            &local_pubkey,
            &format!("socialpulish{suffix}local@gmail.com"),
        )
        .await;
        sqlx::query(
            "INSERT INTO users
                (pubkey, tenant_id, email, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&foreign_pubkey)
        .bind(foreign_tenant_id)
        .bind(format!("socialpulish{suffix}foreign@gmail.com"))
        .execute(&pool)
        .await
        .unwrap();

        let suggestions = repo.suggest_users_for_admin(&query, 1).await.unwrap();
        assert!(suggestions.iter().any(|user| user.pubkey == local_pubkey));
        assert!(!suggestions.iter().any(|user| user.pubkey == foreign_pubkey));

        cleanup_user(&pool, &local_pubkey).await;
        cleanup_user(&pool, &foreign_pubkey).await;
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(foreign_tenant_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_filters_edit_distance_before_result_limit() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("socialpublishllc-{suffix}@lookup.test");
        let close_pubkey = Keys::generate().public_key().to_hex();
        let distant_infixes = ["123", "xyz", "uvw", "456", "789"];
        let mut distant_pubkeys = Vec::with_capacity(distant_infixes.len());

        create_user_with_email(
            &pool,
            &close_pubkey,
            &format!("socialpulishllx-{suffix}@lookup.test"),
        )
        .await;

        for infix in distant_infixes {
            let pubkey = Keys::generate().public_key().to_hex();
            create_user_with_email(
                &pool,
                &pubkey,
                &format!("socialpublishllc{infix}-{suffix}@lookup.test"),
            )
            .await;
            distant_pubkeys.push(pubkey);
        }

        let suggestions = repo.suggest_users_for_admin(&query, 1).await.unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].pubkey, close_pubkey);

        cleanup_user(&pool, &close_pubkey).await;
        for pubkey in distant_pubkeys {
            cleanup_user(&pool, &pubkey).await;
        }
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_caps_filtered_fuzzy_results() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let query = format!("fuzzycap{suffix}");
        let mut pubkeys = Vec::new();

        for index in 0..6 {
            let mut variant = query.chars().collect::<Vec<_>>();
            variant[index] = 'q';
            let variant = variant.into_iter().collect::<String>();
            let pubkey = Keys::generate().public_key().to_hex();
            create_user_with_email(&pool, &pubkey, &format!("social{variant}llc@gmail.com")).await;
            pubkeys.push(pubkey);
        }

        let suggestions = repo.suggest_users_for_admin(&query, 1).await.unwrap();
        assert_eq!(suggestions.len(), ADMIN_EMAIL_SUGGESTION_LIMIT);
        assert!(suggestions
            .iter()
            .all(|user| user.match_kind == AdminUserMatchKind::Fuzzy));

        for pubkey in pubkeys {
            cleanup_user(&pool, &pubkey).await;
        }
    }

    #[tokio::test]
    async fn test_suggest_users_for_admin_skips_when_pg_trgm_is_unavailable() {
        let administrative_pool = setup_pool().await;
        let schema = format!("no_trgm_{}", test_suffix());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&administrative_pool)
            .await
            .unwrap();

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());
        let isolated_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .unwrap();
        let mut connection = isolated_pool.acquire().await.unwrap();
        sqlx::query(&format!("SET search_path TO {schema}, pg_catalog"))
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users (
                pubkey TEXT PRIMARY KEY,
                email TEXT,
                email_verified BOOLEAN,
                username TEXT,
                display_name TEXT,
                vine_id TEXT,
                tenant_id BIGINT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                suspended_reason TEXT,
                verified_minor BOOLEAN NOT NULL DEFAULT FALSE,
                verified_minor_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE personal_keys (
                user_pubkey TEXT NOT NULL,
                tenant_id BIGINT NOT NULL
            )",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        // A matching row makes this test fail if the isolated connection ever regains access to
        // pg_trgm. The intended path still fails at query planning and returns no suggestions.
        let matching_pubkey = Keys::generate().public_key().to_hex();
        sqlx::query(
            "INSERT INTO users (pubkey, email, tenant_id, status)
             VALUES ($1, 'missing@example.com', 1, 'active')",
        )
        .bind(&matching_pubkey)
        .execute(&mut *connection)
        .await
        .unwrap();
        drop(connection);

        let repo = UserRepository::new(isolated_pool.clone());
        let suggestions = repo
            .suggest_users_for_admin("missing@example.com", 1)
            .await
            .expect("missing pg_trgm should disable suggestions");
        assert!(suggestions.is_empty());

        isolated_pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&administrative_pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_clear_verified_minor_clears_flag_and_timestamp() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
             VALUES ($1, 1, TRUE, NOW(), NOW(), NOW())",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        let transitioned = repo.clear_verified_minor(&pubkey, 1).await.unwrap();
        assert!(transitioned, "clearing a set flag is a real transition");

        let VerifiedMinorRow {
            verified_minor,
            verified_minor_at,
        } = repo.get_verified_minor(&pubkey, 1).await.unwrap().unwrap();
        assert!(!verified_minor);
        assert!(verified_minor_at.is_none());

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_clear_verified_minor_idempotent_on_already_cleared() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // A never-minor / already-cleared account clears successfully but is not
        // a real transition, so both calls report `false`.
        assert!(!repo.clear_verified_minor(&pubkey, 1).await.unwrap());
        assert!(!repo.clear_verified_minor(&pubkey, 1).await.unwrap());

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_clear_verified_minor_noop_does_not_bump_updated_at() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        // Never-minor account with a fixed, in-the-past updated_at.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) \
             VALUES ($1, 1, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day')",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        let before: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM users WHERE pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();

        // No-op clear: must not report a transition and must not touch updated_at.
        assert!(!repo.clear_verified_minor(&pubkey, 1).await.unwrap());

        let after: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM users WHERE pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(before, after, "a no-op clear must not bump updated_at");

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_clear_verified_minor_is_tenant_scoped() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        // verified-minor under tenant 1
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
             VALUES ($1, 1, TRUE, NOW(), NOW(), NOW())",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        // Clearing under a different tenant must not match the row.
        let result = repo.clear_verified_minor(&pubkey, 2).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));

        // Tenant-1 flag is untouched.
        let VerifiedMinorRow {
            verified_minor,
            verified_minor_at,
        } = repo.get_verified_minor(&pubkey, 1).await.unwrap().unwrap();
        assert!(
            verified_minor,
            "tenant-1 flag must survive a tenant-2 clear attempt"
        );
        assert!(verified_minor_at.is_some());

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_clear_verified_minor_unknown_pubkey_not_found() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool);
        let pubkey = Keys::generate().public_key().to_hex();

        let result = repo.clear_verified_minor(&pubkey, 1).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_clear_verified_minor_leaves_status_untouched() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, status, suspended_reason, suspended_at, created_at, updated_at) \
             VALUES ($1, 1, TRUE, NOW(), 'suspended', 'age_review', NOW(), NOW(), NOW())",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

        assert!(repo.clear_verified_minor(&pubkey, 1).await.unwrap());

        let FullAdminStatusRow {
            status,
            suspended_reason,
            suspended_at,
            verified_minor,
            ..
        } = repo
            .get_full_admin_status(&pubkey, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.as_str(), "suspended");
        assert_eq!(suspended_reason.as_deref(), Some("age_review"));
        assert!(suspended_at.is_some());
        assert!(!verified_minor);

        cleanup_user(&pool, &pubkey).await;
    }

    async fn create_bare_user(pool: &PgPool, pubkey: &str) {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(pubkey)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_oauth_registration_state_none_for_unknown_user() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool);
        let pubkey = Keys::generate().public_key().to_hex();

        let state = repo.oauth_registration_state(&pubkey, 1).await.unwrap();
        assert!(state.is_none(), "Unknown pubkey should have no state");
    }

    #[tokio::test]
    async fn test_oauth_registration_state_reports_email_and_key_presence() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let bare_pubkey = Keys::generate().public_key().to_hex();
        create_bare_user(&pool, &bare_pubkey).await;

        let full_pubkey = Keys::generate().public_key().to_hex();
        let email = format!("oauth-state-{}@example.com", suffix);
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, 'hash', true, NOW(), NOW())",
        )
        .bind(&full_pubkey)
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, 1, NOW(), NOW())",
        )
        .bind(&full_pubkey)
        .bind(vec![1_u8, 2, 3])
        .execute(&pool)
        .await
        .unwrap();

        let bare_state = repo
            .oauth_registration_state(&bare_pubkey, 1)
            .await
            .unwrap()
            .expect("bare row should have state");
        assert_eq!(bare_state.email, None);
        assert!(!bare_state.email_verified);
        assert!(!bare_state.has_password_hash);
        assert!(!bare_state.has_personal_key);

        let full_state = repo
            .oauth_registration_state(&full_pubkey, 1)
            .await
            .unwrap()
            .expect("full row should have state");
        assert_eq!(full_state.email.as_deref(), Some(email.as_str()));
        assert!(full_state.email_verified);
        assert!(full_state.has_password_hash);
        assert!(full_state.has_personal_key);

        cleanup_user(&pool, &bare_pubkey).await;
        cleanup_user(&pool, &full_pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_applies_pending_to_bare_row() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let pubkey = Keys::generate().public_key().to_hex();
        let email = format!("oauth-complete-{}@example.com", suffix);
        let token = format!("token-{}", suffix);
        let secret = vec![7_u8; 32];

        create_bare_user(&pool, &pubkey).await;

        repo.complete_pending_oauth_registration(&pubkey, 1, &email, "hash", &token, Some(&secret))
            .await
            .unwrap();

        let row: (Option<String>, Option<String>, bool, Option<String>) = sqlx::query_as(
            "SELECT email, password_hash, email_verified, email_verification_token
             FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some(email.as_str()));
        assert_eq!(row.1.as_deref(), Some("hash"));
        assert!(row.2, "email_verified should be set");
        assert_eq!(row.3.as_deref(), Some(token.as_str()));

        let stored_secret: (Vec<u8>,) =
            sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_secret.0, secret);

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_keeps_existing_personal_key() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let pubkey = Keys::generate().public_key().to_hex();
        let email = format!("oauth-keep-key-{}@example.com", suffix);
        let existing_secret = vec![9_u8; 32];

        create_bare_user(&pool, &pubkey).await;
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, 1, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&existing_secret)
        .execute(&pool)
        .await
        .unwrap();

        repo.complete_pending_oauth_registration(
            &pubkey,
            1,
            &email,
            "hash",
            "token",
            Some(&[1_u8; 32]),
        )
        .await
        .unwrap();

        let keys: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(keys.len(), 1, "existing key must not be duplicated");
        assert_eq!(keys[0].0, existing_secret, "existing key must be preserved");

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_backfill_personal_key_is_idempotent() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let pubkey = Keys::generate().public_key().to_hex();

        create_bare_user(&pool, &pubkey).await;

        repo.backfill_personal_key(&pubkey, 1, &[1_u8; 32])
            .await
            .unwrap();
        repo.backfill_personal_key(&pubkey, 1, &[2_u8; 32])
            .await
            .unwrap();

        let keys: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(keys.len(), 1, "backfill must not duplicate personal keys");
        assert_eq!(keys[0].0, vec![1_u8; 32], "first key must be preserved");

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_duplicate_email_rolls_back() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let email = format!("oauth-dup-{}@example.com", suffix);

        let owner_pubkey = Keys::generate().public_key().to_hex();
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
             VALUES ($1, 1, $2, NOW(), NOW())",
        )
        .bind(&owner_pubkey)
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();

        let pubkey = Keys::generate().public_key().to_hex();
        create_bare_user(&pool, &pubkey).await;

        let result = repo
            .complete_pending_oauth_registration(&pubkey, 1, &email, "hash", "token", None)
            .await;
        assert!(
            matches!(result, Err(RepositoryError::Duplicate)),
            "claiming an owned email must fail with Duplicate, got: {result:?}"
        );

        let row: (Option<String>, bool) = sqlx::query_as(
            "SELECT email, email_verified FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, None, "failed completion must roll back the email");
        assert!(!row.1, "failed completion must roll back email_verified");

        cleanup_user(&pool, &owner_pubkey).await;
        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_bound_row_returns_duplicate() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let pubkey = Keys::generate().public_key().to_hex();
        let existing_email = format!("oauth-bound-existing-{}@example.com", suffix);
        let pending_email = format!("oauth-bound-pending-{}@example.com", suffix);

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, 'existing-hash', true, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&existing_email)
        .execute(&pool)
        .await
        .unwrap();

        let result = repo
            .complete_pending_oauth_registration(
                &pubkey,
                1,
                &pending_email,
                "pending-hash",
                "token",
                Some(&[1_u8; 32]),
            )
            .await;
        assert!(
            matches!(result, Err(RepositoryError::Duplicate)),
            "completing a row already bound to an email must fail with Duplicate, got: {result:?}"
        );

        let row: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT email, password_hash FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some(existing_email.as_str()));
        assert_eq!(row.1.as_deref(), Some("existing-hash"));

        let key_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(key_count.0, 0, "failed completion must not insert a key");

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_already_applied_email_is_idempotent() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let pubkey = Keys::generate().public_key().to_hex();
        let email = format!("oauth-applied-{}@example.com", suffix);
        let secret = vec![5_u8; 32];

        // Simulate losing the completion race: a concurrent request already
        // bound the row to the pending email, but the personal key is missing.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, 'existing-hash', true, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();

        repo.complete_pending_oauth_registration(
            &pubkey,
            1,
            &email,
            "pending-hash",
            "token",
            Some(&secret),
        )
        .await
        .expect("row already bound to the pending email must be treated as success");

        let row: (Option<String>,) =
            sqlx::query_as("SELECT password_hash FROM users WHERE pubkey = $1 AND tenant_id = 1")
                .bind(&pubkey)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            row.0.as_deref(),
            Some("existing-hash"),
            "idempotent completion must not rewrite existing credentials"
        );

        let keys: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(keys.len(), 1, "missing personal key must be backfilled");
        assert_eq!(
            keys[0].0, secret,
            "backfilled key must hold the pending secret"
        );

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_completes_same_email_incomplete_row() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();
        let pubkey = Keys::generate().public_key().to_hex();
        let email = format!("oauth-incomplete-{}@example.com", suffix);
        let secret = vec![6_u8; 32];

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, 1, $2, NULL, false, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();

        repo.complete_pending_oauth_registration(
            &pubkey,
            1,
            &email,
            "pending-hash",
            "token",
            Some(&secret),
        )
        .await
        .expect("same-email incomplete row should be completed");

        let row: (Option<String>, Option<String>, bool, Option<String>) = sqlx::query_as(
            "SELECT email, password_hash, email_verified, email_verification_token
             FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some(email.as_str()));
        assert_eq!(row.1.as_deref(), Some("pending-hash"));
        assert!(row.2, "same-email row must be marked verified");
        assert_eq!(row.3.as_deref(), Some("token"));

        let keys: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
                .bind(&pubkey)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(keys.len(), 1, "missing personal key must be backfilled");
        assert_eq!(keys[0].0, secret);

        cleanup_user(&pool, &pubkey).await;
    }

    #[tokio::test]
    async fn test_complete_pending_oauth_registration_unknown_user_not_found() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool);
        let pubkey = Keys::generate().public_key().to_hex();

        let result = repo
            .complete_pending_oauth_registration(
                &pubkey,
                1,
                "oauth-missing@example.com",
                "hash",
                "token",
                None,
            )
            .await;
        assert!(
            matches!(result, Err(RepositoryError::NotFound(_))),
            "completing a missing row must fail with NotFound, got: {result:?}"
        );
    }
}
