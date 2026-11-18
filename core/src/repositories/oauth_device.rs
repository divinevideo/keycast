//! Persistence and transitions for RFC 8628 television sign-in.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::PgPool;

pub const DEVICE_CLIENT_ID: &str = "divine-tv";
pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const DEVICE_TOKEN_ORIGIN: &str = "urn:keycast:device:divine-tv";
pub const DEVICE_SCOPE: &str = "tv:read";
pub const DEVICE_LIFETIME_SECONDS: i64 = 600;
pub const DEVICE_POLL_INTERVAL_SECONDS: i32 = 5;
const USER_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

pub fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| char::from(USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())]))
        .collect()
}

pub fn normalize_user_code(input: &str) -> Option<String> {
    if input.len() > 32 {
        return None;
    }
    let code = input
        .bytes()
        .filter(|byte| !matches!(byte, b'-' | b' '))
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if code.len() != 8 || !code.iter().all(|byte| USER_CODE_ALPHABET.contains(byte)) {
        return None;
    }
    String::from_utf8(code).ok()
}

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceSession {
    pub id: String,
    pub user_pubkey: String,
    pub expires_at: DateTime<Utc>,
}

/// An active TV connection that its owner can end from their account.
#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct DeviceSessionInfo {
    pub id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum DevicePoll {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Invalid,
    Approved(DeviceSession),
}

#[derive(sqlx::FromRow)]
struct DeviceGrant {
    user_pubkey: Option<String>,
    expires_at: DateTime<Utc>,
    next_poll_at: DateTime<Utc>,
    poll_interval_seconds: i32,
    status: String,
}

pub struct DeviceAuthorizationRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> DeviceAuthorizationRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// An existing human-readable code is a harmless collision. The caller
    /// generates another code before returning it to the device.
    pub async fn create_grant(
        &self,
        tenant_id: i64,
        device_code_hash: &str,
        user_code_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO oauth_device_grants
                (tenant_id, device_code_hash, user_code_hash, expires_at,
                 next_poll_at, poll_interval_seconds)
             VALUES ($1, $2, $3, clock_timestamp() + make_interval(secs => $4),
                     clock_timestamp() + make_interval(secs => $5::integer), $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(device_code_hash)
        .bind(user_code_hash)
        .bind(DEVICE_LIFETIME_SECONDS as f64)
        .bind(DEVICE_POLL_INTERVAL_SECONDS)
        .execute(self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn is_pending(
        &self,
        tenant_id: i64,
        user_code_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_device_grants
             WHERE tenant_id = $1 AND user_code_hash = $2
               AND status = 'pending' AND expires_at > clock_timestamp())",
        )
        .bind(tenant_id)
        .bind(user_code_hash)
        .fetch_one(self.pool)
        .await
    }

    pub async fn decide(
        &self,
        tenant_id: i64,
        user_code_hash: &str,
        user_pubkey: &str,
        approved: bool,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE oauth_device_grants AS pending_grant
             SET status = $4, user_pubkey = CASE WHEN $4 = 'approved' THEN account.pubkey END
             FROM users AS account
             WHERE pending_grant.tenant_id = $1 AND pending_grant.user_code_hash = $2
               AND pending_grant.status = 'pending' AND pending_grant.expires_at > clock_timestamp()
               AND account.tenant_id = $1 AND account.pubkey = $3 AND account.status = 'active'
               AND account.email IS NOT NULL AND account.email_verified",
        )
        .bind(tenant_id)
        .bind(user_code_hash)
        .bind(user_pubkey)
        .bind(if approved { "approved" } else { "denied" })
        .execute(self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Poll throttling, single-use redemption, and session creation share the
    /// grant row lock. The transaction performs database work only.
    pub async fn poll(
        &self,
        tenant_id: i64,
        device_code_hash: &str,
        session_id: &str,
        refresh_token_hash: &str,
        session_lifetime_days: i64,
    ) -> Result<DevicePoll, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let grant = sqlx::query_as::<_, DeviceGrant>(
            "SELECT user_pubkey, expires_at, next_poll_at, poll_interval_seconds, status
             FROM oauth_device_grants WHERE tenant_id = $1 AND device_code_hash = $2
             FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(device_code_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(grant) = grant else {
            return Ok(DevicePoll::Invalid);
        };

        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let outcome = if grant.expires_at <= now {
            DevicePoll::Expired
        } else if grant.status == "denied" {
            DevicePoll::Denied
        } else if grant.status == "consumed" {
            DevicePoll::Invalid
        } else if grant.next_poll_at > now || grant.status == "pending" {
            let early = grant.next_poll_at > now;
            let interval = if early {
                (grant.poll_interval_seconds + 5).min(DEVICE_LIFETIME_SECONDS as i32)
            } else {
                grant.poll_interval_seconds
            };
            sqlx::query(
                "UPDATE oauth_device_grants
                 SET next_poll_at = $3, poll_interval_seconds = $4
                 WHERE tenant_id = $1 AND device_code_hash = $2",
            )
            .bind(tenant_id)
            .bind(device_code_hash)
            .bind(now + Duration::seconds(i64::from(interval)))
            .bind(interval)
            .execute(&mut *tx)
            .await?;
            if early {
                DevicePoll::SlowDown
            } else {
                DevicePoll::Pending
            }
        } else {
            let session = sqlx::query_as::<_, DeviceSession>(
                "INSERT INTO oauth_device_sessions
                    (id, tenant_id, user_pubkey, refresh_token_hash, expires_at)
                 SELECT $1, tenant_id, pubkey, $4, $5 FROM users
                 WHERE tenant_id = $2 AND pubkey = $3 AND status = 'active'
                   AND email IS NOT NULL AND email_verified
                 RETURNING id, user_pubkey, expires_at",
            )
            .bind(session_id)
            .bind(tenant_id)
            .bind(grant.user_pubkey)
            .bind(refresh_token_hash)
            .bind(now + Duration::days(session_lifetime_days))
            .fetch_optional(&mut *tx)
            .await?;

            sqlx::query(
                "UPDATE oauth_device_grants SET status = $3, user_pubkey = NULL
                 WHERE tenant_id = $1 AND device_code_hash = $2",
            )
            .bind(tenant_id)
            .bind(device_code_hash)
            .bind(if session.is_some() {
                "consumed"
            } else {
                "denied"
            })
            .execute(&mut *tx)
            .await?;

            session.map_or(DevicePoll::Denied, DevicePoll::Approved)
        };
        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn rotate_refresh_token(
        &self,
        tenant_id: i64,
        old_hash: &str,
        new_hash: &str,
    ) -> Result<Option<DeviceSession>, sqlx::Error> {
        sqlx::query_as(
            "UPDATE oauth_device_sessions AS session
             SET refresh_token_hash = $3
             FROM users AS account
             WHERE session.tenant_id = $1 AND session.refresh_token_hash = $2
               AND session.revoked_at IS NULL AND session.expires_at > clock_timestamp()
               AND account.pubkey = session.user_pubkey AND account.tenant_id = $1
               AND account.status = 'active' AND account.email IS NOT NULL AND account.email_verified
             RETURNING session.id, session.user_pubkey, session.expires_at",
        )
        .bind(tenant_id)
        .bind(old_hash)
        .bind(new_hash)
        .fetch_optional(self.pool)
        .await
    }

    pub async fn active_session_protected_minor(
        &self,
        tenant_id: i64,
        session_id: &str,
        user_pubkey: &str,
    ) -> Result<Option<bool>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT account.verified_minor FROM oauth_device_sessions AS session
             JOIN users AS account ON account.pubkey = session.user_pubkey
                                   AND account.tenant_id = session.tenant_id
             WHERE session.tenant_id = $1 AND session.id = $2 AND session.user_pubkey = $3
               AND session.revoked_at IS NULL AND session.expires_at > clock_timestamp()
               AND account.status = 'active' AND account.email IS NOT NULL AND account.email_verified",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(user_pubkey)
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_active_sessions(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<Vec<DeviceSessionInfo>, sqlx::Error> {
        sqlx::query_as(
            "SELECT session.id, session.expires_at FROM oauth_device_sessions AS session
             JOIN users AS account ON account.pubkey = session.user_pubkey
                                   AND account.tenant_id = session.tenant_id
             WHERE session.tenant_id = $1 AND session.user_pubkey = $2
               AND session.revoked_at IS NULL AND session.expires_at > clock_timestamp()
               AND account.status = 'active' AND account.email IS NOT NULL AND account.email_verified
             ORDER BY session.expires_at DESC, session.id",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .fetch_all(self.pool)
        .await
    }

    pub async fn revoke(
        &self,
        tenant_id: i64,
        session_id: &str,
        user_pubkey: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE oauth_device_sessions SET revoked_at = clock_timestamp()
             WHERE tenant_id = $1 AND id = $2 AND user_pubkey = $3 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(user_pubkey)
        .execute(self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn cleanup(&self) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM oauth_device_grants WHERE expires_at <= NOW() - INTERVAL '1 day'")
            .execute(self.pool)
            .await?;
        sqlx::query("DELETE FROM oauth_device_sessions WHERE expires_at <= NOW()")
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_codes_can_be_entered_with_spaces_or_dashes() {
        assert_eq!(
            normalize_user_code("abcd-2345").as_deref(),
            Some("ABCD2345")
        );
        assert_eq!(
            normalize_user_code(" ABcD 2345 ").as_deref(),
            Some("ABCD2345")
        );
        assert_eq!(normalize_user_code("ABCD1234"), None);
        assert_eq!(normalize_user_code("ABCD234!"), None);
        assert_eq!(normalize_user_code("ABC"), None);
        for _ in 0..32 {
            let code = generate_user_code();
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
        }
    }
}
