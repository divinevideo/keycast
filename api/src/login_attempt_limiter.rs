//! Redis-backed coordination for password-login attempt limits.

use crate::PrefixedRedis;
use keycast_core::login_attempts::{
    LoginAttemptSubject, LOGIN_DELAYS_SECONDS, LOGIN_FAILURE_WINDOW, LOGIN_FREE_FAILURES,
    LOGIN_MAX_IN_FLIGHT, LOGIN_RESERVATION_TTL,
};
use redis::RedisResult;
use std::fmt;
use uuid::Uuid;

const RESERVE_SCRIPT: &str = r#"
local failures_key = KEYS[1]
local reservations_key = KEYS[2]
local blocked_key = KEYS[3]
local reservation_id = ARGV[1]
local reservation_ttl_ms = tonumber(ARGV[2])
local max_in_flight = tonumber(ARGV[3])
local failure_window_ms = tonumber(ARGV[4])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', reservations_key, '-inf', now_ms)
redis.call('ZREMRANGEBYSCORE', failures_key, '-inf', now_ms - failure_window_ms)

local retry_ms = redis.call('PTTL', blocked_key)
if retry_ms > 0 then
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
local failures_key = KEYS[2]
local blocked_key = KEYS[3]
local reservation_id = ARGV[1]
local free_failures = tonumber(ARGV[2])
local failure_window_ms = tonumber(ARGV[3])
local schedule_length = tonumber(ARGV[4])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
local expires_at = redis.call('ZSCORE', reservations_key, reservation_id)
if not expires_at or tonumber(expires_at) <= now_ms then
    return redis.error_reply('login-attempt reservation is no longer active')
end

redis.call('ZREMRANGEBYSCORE', failures_key, '-inf', now_ms - failure_window_ms)
redis.call('ZADD', failures_key, now_ms, reservation_id)
redis.call('PEXPIRE', failures_key, failure_window_ms)
local failures = redis.call('ZCARD', failures_key)
local delay_seconds = 0
if failures >= free_failures then
    local schedule_start = #ARGV - schedule_length + 1
    local delay_index = math.min(schedule_start + failures - free_failures, #ARGV)
    delay_seconds = tonumber(ARGV[delay_index])
    redis.call('SET', blocked_key, '1', 'PX', delay_seconds * 1000)
end
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
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
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
return redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
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
    failures_key: String,
    reservations_key: String,
    blocked_key: String,
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
            LOGIN_FAILURE_WINDOW.as_millis().to_string(),
            LOGIN_DELAYS_SECONDS.len().to_string(),
        ];
        let arguments = arguments
            .into_iter()
            .chain(LOGIN_DELAYS_SECONDS.iter().map(ToString::to_string))
            .collect::<Vec<_>>();
        let _: i64 = self
            .redis
            .invoke_script(
                RECORD_FAILURE_SCRIPT,
                &[self.reservations_key, self.failures_key, self.blocked_key],
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
                &[self.failures_key, self.reservations_key, self.blocked_key],
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
        let failures_key = format!("{}:failures", subject.storage_key());
        let reservations_key = format!("{}:reservations", subject.storage_key());
        let blocked_key = format!("{}:blocked", subject.storage_key());
        let id = Uuid::new_v4().to_string();
        let arguments = vec![
            id.clone(),
            LOGIN_RESERVATION_TTL.as_millis().to_string(),
            LOGIN_MAX_IN_FLIGHT.to_string(),
            LOGIN_FAILURE_WINDOW.as_millis().to_string(),
        ];
        let (admitted, retry_after): (i64, i64) = self
            .redis
            .invoke_script(
                RESERVE_SCRIPT,
                &[
                    failures_key.clone(),
                    reservations_key.clone(),
                    blocked_key.clone(),
                ],
                &arguments,
            )
            .await?;

        if admitted == 1 {
            Ok(LoginAttemptAdmission::Reserved(LoginAttemptReservation {
                redis: self.redis.clone(),
                failures_key,
                reservations_key,
                blocked_key,
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
        let failures_key = format!("{}:failures", subject.storage_key());
        let reservations_key = format!("{}:reservations", subject.storage_key());
        let blocked_key = format!("{}:blocked", subject.storage_key());
        let _: i64 = self
            .redis
            .invoke_script(
                RESET_SCRIPT,
                &[failures_key, reservations_key, blocked_key],
                &[],
            )
            .await?;
        Ok(())
    }

    /// Install a deterministic block for HTTP integration tests.
    #[cfg(any(test, feature = "integration-tests"))]
    pub async fn block_for_test(
        &self,
        tenant_id: i64,
        normalized_email: &str,
        seconds: u64,
    ) -> RedisResult<()> {
        let subject = LoginAttemptSubject::new(tenant_id, normalized_email);
        self.redis
            .setex(&format!("{}:blocked", subject.storage_key()), seconds, "1")
            .await
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use redis::aio::ConnectionManager;

    const SEED_EXPIRED_FAILURES_SCRIPT: &str = r#"
local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
local score = now_ms - tonumber(ARGV[1]) - 1000
for index = 1, tonumber(ARGV[2]) do
    redis.call('ZADD', KEYS[1], score, 'expired-' .. index)
end
return 1
"#;
    const PTTL_SCRIPT: &str = "return redis.call('PTTL', KEYS[1])";

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

    async fn clear_block(limiter: &LoginAttemptLimiter, email: &str) {
        let subject = LoginAttemptSubject::new(1, email);
        limiter
            .redis
            .del(&format!("{}:blocked", subject.storage_key()))
            .await
            .expect("clear test block");
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
            LoginAttemptAdmission::Limited { retry_after: 5 }
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
            LoginAttemptAdmission::Limited { retry_after: 5 }
        ));
        limiter.reset(1, email).await.expect("cleanup subject");
    }

    #[tokio::test]
    async fn enforced_delay_curve_escalates_to_cap() {
        let limiter = test_limiter().await;
        let email = "escalation@example.com";
        for _ in 0..LOGIN_FREE_FAILURES - 1 {
            record_failure(&limiter, email).await;
        }

        for expected in LOGIN_DELAYS_SECONDS {
            record_failure(&limiter, email).await;
            assert!(matches!(
                limiter.reserve(1, email).await.expect("limited admission"),
                LoginAttemptAdmission::Limited { retry_after } if retry_after == *expected
            ));
            clear_block(&limiter, email).await;
        }

        limiter.reset(1, email).await.expect("cleanup subject");
    }

    #[tokio::test]
    async fn released_attempt_does_not_consume_failure_budget() {
        let limiter = test_limiter().await;
        let email = "released@example.com";
        for _ in 0..LOGIN_FREE_FAILURES {
            let LoginAttemptAdmission::Reserved(reservation) = limiter
                .reserve(1, email)
                .await
                .expect("reserve login attempt")
            else {
                panic!("released attempt should not consume the budget");
            };
            reservation.release().await.expect("release attempt");
        }

        let LoginAttemptAdmission::Reserved(reservation) = limiter
            .reserve(1, email)
            .await
            .expect("reserve after releases")
        else {
            panic!("released attempts must leave the budget open");
        };
        reservation.release().await.expect("release final attempt");
        limiter.reset(1, email).await.expect("cleanup subject");
    }

    #[tokio::test]
    async fn failures_outside_the_window_do_not_escalate() {
        let limiter = test_limiter().await;
        let email = "decayed@example.com";
        let subject = LoginAttemptSubject::new(1, email);
        let failures_key = format!("{}:failures", subject.storage_key());
        let _: i64 = limiter
            .redis
            .invoke_script(
                SEED_EXPIRED_FAILURES_SCRIPT,
                &[failures_key],
                &[
                    LOGIN_FAILURE_WINDOW.as_millis().to_string(),
                    LOGIN_FREE_FAILURES.to_string(),
                ],
            )
            .await
            .expect("seed expired failures");

        record_failure(&limiter, email).await;
        let LoginAttemptAdmission::Reserved(reservation) = limiter
            .reserve(1, email)
            .await
            .expect("admission after decay")
        else {
            panic!("expired failures must not impose a delay");
        };
        reservation.release().await.expect("release attempt");
        limiter.reset(1, email).await.expect("cleanup subject");
    }

    #[tokio::test]
    async fn abandoned_attempt_has_short_bounded_ttl() {
        let limiter = test_limiter().await;
        let email = "abandoned@example.com";
        let LoginAttemptAdmission::Reserved(reservation) =
            limiter.reserve(1, email).await.expect("reserve attempt")
        else {
            panic!("first attempt should be admitted");
        };
        drop(reservation);

        let subject = LoginAttemptSubject::new(1, email);
        let reservations_key = format!("{}:reservations", subject.storage_key());
        let remaining_ms: i64 = limiter
            .redis
            .invoke_script(PTTL_SCRIPT, &[reservations_key], &[])
            .await
            .expect("read reservation TTL");
        assert!(
            remaining_ms > 0 && remaining_ms <= LOGIN_RESERVATION_TTL.as_millis() as i64,
            "abandoned reservation must expire inside the five-second bound: {remaining_ms}ms"
        );
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
