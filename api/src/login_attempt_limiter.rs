//! Redis-backed coordination for password-login attempt limits.

use crate::PrefixedRedis;
use keycast_core::login_attempts::{
    LoginAttemptSubject, LOGIN_FAILURE_STATE_TTL, LOGIN_FREE_FAILURES, LOGIN_MAX_DELAY,
    LOGIN_MAX_IN_FLIGHT, LOGIN_RESERVATION_TTL,
};
use redis::RedisResult;
use std::fmt;
use uuid::Uuid;

/// Enumeration-safe response code for a delayed password attempt.
pub const LOGIN_RATE_LIMIT_CODE: &str = "TOO_MANY_ATTEMPTS";
/// Enumeration-safe response text for a delayed password attempt.
pub const LOGIN_RATE_LIMIT_MESSAGE: &str =
    "Too many login attempts. Please wait before trying again or reset your password.";

const RESERVE_SCRIPT: &str = r#"
local state_key = KEYS[1]
local reservations_key = KEYS[2]
local reservation_id = ARGV[1]
local reservation_ttl_ms = tonumber(ARGV[2])
local max_in_flight = tonumber(ARGV[3])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', reservations_key, '-inf', now_ms)

local blocked_until_ms = tonumber(redis.call('HGET', state_key, 'blocked_until_ms') or '0')
if blocked_until_ms > now_ms then
    local retry_ms = blocked_until_ms - now_ms
    return {0, math.max(1, math.floor((retry_ms + 999) / 1000))}
end

if redis.call('ZCARD', reservations_key) >= max_in_flight then
    return {0, 1}
end

redis.call('ZADD', reservations_key, now_ms + reservation_ttl_ms, reservation_id)
redis.call('PEXPIRE', reservations_key, reservation_ttl_ms)
return {1, 0}
"#;

const RECORD_FAILURE_SCRIPT: &str = r#"
local reservations_key = KEYS[1]
local state_key = KEYS[2]
local reservation_id = ARGV[1]
local free_failures = tonumber(ARGV[2])
local max_delay_seconds = tonumber(ARGV[3])
local state_ttl_ms = tonumber(ARGV[4])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
local expires_at = redis.call('ZSCORE', reservations_key, reservation_id)
if not expires_at or tonumber(expires_at) <= now_ms then
    return redis.error_reply('login-attempt reservation is no longer active')
end

local failures = redis.call('HINCRBY', state_key, 'failures', 1)
local delay_seconds = 0
if failures >= free_failures then
    delay_seconds = math.min(max_delay_seconds, math.pow(2, failures - free_failures))
    redis.call('HSET', state_key, 'blocked_until_ms', now_ms + (delay_seconds * 1000))
end
redis.call('PEXPIRE', state_key, state_ttl_ms)
local removed = redis.call('ZREM', reservations_key, reservation_id)
if removed ~= 1 then
    return redis.error_reply('login-attempt reservation is no longer active')
end
return delay_seconds
"#;

const CLEAR_SCRIPT: &str = r#"
local expires_at = redis.call('ZSCORE', KEYS[2], ARGV[1])
local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
if not expires_at or tonumber(expires_at) <= now_ms then
    return redis.error_reply('login-attempt reservation is no longer active')
end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"#;

const RELEASE_SCRIPT: &str = r#"
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
if removed ~= 1 then
    return redis.error_reply('login-attempt reservation is no longer active')
end
return 1
"#;

const RESET_SCRIPT: &str = r#"
return redis.call('DEL', KEYS[1], KEYS[2])
"#;

/// Result of reserving one password-login attempt.
#[derive(Debug)]
pub enum LoginAttemptAdmission {
    /// The caller owns an in-flight password attempt.
    Reserved(LoginAttemptReservation),
    /// The subject must wait before another attempt.
    Limited { retry_after: u32 },
}

/// One in-flight password-login attempt.
pub struct LoginAttemptReservation {
    redis: PrefixedRedis,
    state_key: String,
    reservations_key: String,
    id: String,
}

impl fmt::Debug for LoginAttemptReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginAttemptReservation")
            .field("subject", &"<redacted>")
            .field("id", &"<redacted>")
            .finish()
    }
}

impl LoginAttemptReservation {
    /// Record a failed credential check and release this reservation.
    pub async fn record_failure(self) -> RedisResult<()> {
        let arguments = vec![
            self.id,
            LOGIN_FREE_FAILURES.to_string(),
            LOGIN_MAX_DELAY.as_secs().to_string(),
            LOGIN_FAILURE_STATE_TTL.as_millis().to_string(),
        ];
        let _: i64 = self
            .redis
            .invoke_script(
                RECORD_FAILURE_SCRIPT,
                &[self.reservations_key, self.state_key],
                &arguments,
            )
            .await?;
        Ok(())
    }

    /// Clear failure history after a successful credential check.
    pub async fn clear(self) -> RedisResult<()> {
        let _: i64 = self
            .redis
            .invoke_script(
                CLEAR_SCRIPT,
                &[self.state_key, self.reservations_key],
                &[self.id],
            )
            .await?;
        Ok(())
    }

    /// Release this reservation without changing failure history.
    pub async fn release(self) -> RedisResult<()> {
        let _: i64 = self
            .redis
            .invoke_script(RELEASE_SCRIPT, &[self.reservations_key], &[self.id])
            .await?;
        Ok(())
    }
}

/// Distributed password-login attempt limiter.
#[derive(Clone, Debug)]
pub struct LoginAttemptLimiter {
    redis: PrefixedRedis,
}

impl LoginAttemptLimiter {
    /// Create a limiter over the application's shared Redis connection.
    #[must_use]
    pub fn new(redis: PrefixedRedis) -> Self {
        Self { redis }
    }

    /// Reserve one attempt for a tenant and normalized email.
    pub async fn reserve(
        &self,
        tenant_id: i64,
        normalized_email: &str,
    ) -> RedisResult<LoginAttemptAdmission> {
        let subject = LoginAttemptSubject::new(tenant_id, normalized_email);
        let state_key = format!("{}:state", subject.storage_key());
        let reservations_key = format!("{}:reservations", subject.storage_key());
        let id = Uuid::new_v4().to_string();
        let arguments = vec![
            id.clone(),
            LOGIN_RESERVATION_TTL.as_millis().to_string(),
            LOGIN_MAX_IN_FLIGHT.to_string(),
        ];
        let (admitted, retry_after): (i64, i64) = self
            .redis
            .invoke_script(
                RESERVE_SCRIPT,
                &[state_key.clone(), reservations_key.clone()],
                &arguments,
            )
            .await?;

        if admitted == 1 {
            Ok(LoginAttemptAdmission::Reserved(LoginAttemptReservation {
                redis: self.redis.clone(),
                state_key,
                reservations_key,
                id,
            }))
        } else {
            Ok(LoginAttemptAdmission::Limited {
                retry_after: retry_after.clamp(1, i64::from(u32::MAX)) as u32,
            })
        }
    }

    /// Clear failure history after password-reset recovery.
    pub async fn reset(&self, tenant_id: i64, normalized_email: &str) -> RedisResult<()> {
        let subject = LoginAttemptSubject::new(tenant_id, normalized_email);
        let state_key = format!("{}:state", subject.storage_key());
        let reservations_key = format!("{}:reservations", subject.storage_key());
        let _: i64 = self
            .redis
            .invoke_script(RESET_SCRIPT, &[state_key, reservations_key], &[])
            .await?;
        Ok(())
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use redis::aio::ConnectionManager;

    async fn test_limiter() -> LoginAttemptLimiter {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("TEST_REDIS_URL must name the dedicated test Redis");
        let client = redis::Client::open(redis_url).expect("valid Redis URL");
        let connection = ConnectionManager::new(client)
            .await
            .expect("connect to Redis");
        let prefix = format!("keycast-login-attempts:{}", Uuid::new_v4());
        LoginAttemptLimiter::new(PrefixedRedis::new(connection, Some(prefix)))
    }

    async fn record_failure(limiter: &LoginAttemptLimiter, email: &str) {
        let LoginAttemptAdmission::Reserved(reservation) = limiter
            .reserve(1, email)
            .await
            .expect("reserve login attempt")
        else {
            panic!("attempt should be admitted");
        };
        reservation
            .record_failure()
            .await
            .expect("record login failure");
    }

    #[tokio::test]
    async fn failure_boundary_returns_retry_after() {
        let limiter = test_limiter().await;
        let email = "boundary@example.com";

        for _ in 0..LOGIN_FREE_FAILURES {
            record_failure(&limiter, email).await;
        }

        assert!(matches!(
            limiter.reserve(1, email).await.expect("limited admission"),
            LoginAttemptAdmission::Limited { retry_after: 1 }
        ));
        limiter.reset(1, email).await.expect("cleanup subject");
    }

    #[tokio::test]
    async fn successful_attempt_resets_failure_count() {
        let limiter = test_limiter().await;
        let email = "success@example.com";
        for _ in 0..2 {
            record_failure(&limiter, email).await;
        }

        let LoginAttemptAdmission::Reserved(success) =
            limiter.reserve(1, email).await.expect("reserve success")
        else {
            panic!("successful attempt should be admitted");
        };
        success.clear().await.expect("clear on success");

        for _ in 0..LOGIN_FREE_FAILURES {
            record_failure(&limiter, email).await;
        }
        assert!(matches!(
            limiter.reserve(1, email).await.expect("limited admission"),
            LoginAttemptAdmission::Limited { retry_after: 1 }
        ));
        limiter.reset(1, email).await.expect("cleanup subject");
    }

    #[tokio::test]
    async fn password_reset_reopens_locked_subject() {
        let limiter = test_limiter().await;
        let email = "recovery@example.com";
        for _ in 0..LOGIN_FREE_FAILURES {
            record_failure(&limiter, email).await;
        }
        assert!(matches!(
            limiter.reserve(1, email).await.expect("limited admission"),
            LoginAttemptAdmission::Limited { .. }
        ));

        limiter.reset(1, email).await.expect("password reset");
        let LoginAttemptAdmission::Reserved(reservation) =
            limiter.reserve(1, email).await.expect("reopened admission")
        else {
            panic!("password reset should reopen the subject");
        };
        reservation.release().await.expect("release reservation");
        limiter.reset(1, email).await.expect("cleanup subject");
    }
}
