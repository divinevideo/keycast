//! Coordinates the raw-key egress password-attempt budget.

use crate::PrefixedRedis;
use redis::RedisResult;
use std::{fmt, time::Duration};
use uuid::Uuid;

const RESERVE_SCRIPT: &str = r#"
local failures_key = KEYS[1]
local reservations_key = KEYS[2]
local reservation_id = ARGV[1]
local attempt_limit = tonumber(ARGV[2])
local window_ms = tonumber(ARGV[3])
local reservation_ttl_ms = tonumber(ARGV[4])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', failures_key, '-inf', now_ms - window_ms)
redis.call('ZREMRANGEBYSCORE', reservations_key, '-inf', now_ms)

local failure_count = redis.call('ZCARD', failures_key)
local reservation_count = redis.call('ZCARD', reservations_key)
if failure_count + reservation_count >= attempt_limit then
    local next_available_ms = now_ms + window_ms
    local oldest_failure = redis.call('ZRANGE', failures_key, 0, 0, 'WITHSCORES')
    if #oldest_failure > 0 then
        next_available_ms = math.min(
            next_available_ms,
            tonumber(oldest_failure[2]) + window_ms
        )
    end
    local oldest_reservation = redis.call(
        'ZRANGE',
        reservations_key,
        0,
        0,
        'WITHSCORES'
    )
    if #oldest_reservation > 0 then
        next_available_ms = math.min(
            next_available_ms,
            tonumber(oldest_reservation[2])
        )
    end

    local retry_ms = math.max(1, next_available_ms - now_ms)
    local retry_seconds = math.max(1, math.floor((retry_ms + 999) / 1000))
    return {0, retry_seconds}
end

redis.call('ZADD', reservations_key, now_ms + reservation_ttl_ms, reservation_id)
redis.call('PEXPIRE', reservations_key, reservation_ttl_ms)
return {1, 0}
"#;

const RELEASE_SCRIPT: &str = r#"
local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
local expires_at = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not expires_at or tonumber(expires_at) <= now_ms then
    return redis.error_reply('key-egress reservation is no longer active')
end

local removed = redis.call('ZREM', KEYS[1], ARGV[1])
if removed ~= 1 then
    return redis.error_reply('key-egress reservation is no longer active')
end
return 1
"#;

const RECORD_FAILURE_SCRIPT: &str = r#"
local reservations_key = KEYS[1]
local failures_key = KEYS[2]
local reservation_id = ARGV[1]
local window_ms = tonumber(ARGV[2])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
local expires_at = redis.call('ZSCORE', reservations_key, reservation_id)
if not expires_at or tonumber(expires_at) <= now_ms then
    return redis.error_reply('key-egress reservation is no longer active')
end

redis.call('ZREMRANGEBYSCORE', failures_key, '-inf', now_ms - window_ms)
redis.call('ZADD', failures_key, now_ms, reservation_id)
redis.call('PEXPIRE', failures_key, window_ms)
-- Spend the failure before releasing its lease. Redis scripts do not roll
-- back earlier writes after a later runtime error, so the opposite ordering
-- could reopen budget if failure persistence failed after ZREM.
local removed = redis.call('ZREM', reservations_key, reservation_id)
if removed ~= 1 then
    return redis.error_reply('key-egress reservation is no longer active')
end
return 1
"#;

/// Wrong passwords permitted during one sliding window.
pub const KEY_EGRESS_MAX_ATTEMPTS: usize = 5;
/// Sliding window for wrong-password history.
pub const KEY_EGRESS_ATTEMPT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Maximum lifetime of an abandoned in-flight reservation.
pub const KEY_EGRESS_RESERVATION_TTL: Duration = Duration::from_secs(60);
/// Maximum work accepted from before the reservation request is sent.
pub const KEY_EGRESS_RESERVED_WORK_DEADLINE: Duration = Duration::from_secs(40);
/// Maximum time allowed to finalize a reservation.
pub const KEY_EGRESS_FINALIZATION_DEADLINE: Duration = Duration::from_secs(5);
/// Spare time between logical completion and reservation expiry.
pub const KEY_EGRESS_RESERVATION_SAFETY_MARGIN: Duration = Duration::from_secs(5);

/// Result of trying to reserve one password attempt.
#[derive(Debug)]
pub enum KeyEgressAdmission {
    /// The caller owns one in-flight attempt.
    Reserved(KeyEgressReservation),
    /// The current identity has spent its budget.
    Locked {
        /// Whole seconds until the next slot should become available.
        retry_after: u32,
    },
}

/// One in-flight raw-key egress password attempt.
pub struct KeyEgressReservation {
    redis: PrefixedRedis,
    failures_key: String,
    reservations_key: String,
    id: String,
}

impl fmt::Debug for KeyEgressReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyEgressReservation")
            .field("subject", &"<redacted>")
            .field("id", &"<redacted>")
            .finish()
    }
}

impl KeyEgressReservation {
    /// Release this reservation without spending the failure budget.
    ///
    /// # Errors
    ///
    /// Returns a Redis error when the reservation cannot be released.
    pub async fn release(self) -> RedisResult<()> {
        let _: i64 = self
            .redis
            .invoke_script(RELEASE_SCRIPT, &[self.reservations_key], &[self.id])
            .await?;
        Ok(())
    }

    /// Convert this reservation into one wrong-password failure.
    ///
    /// # Errors
    ///
    /// Returns a Redis error when the failure cannot be recorded.
    pub async fn record_failure(self) -> RedisResult<()> {
        let window_ms = KEY_EGRESS_ATTEMPT_WINDOW.as_millis().to_string();
        let _: i64 = self
            .redis
            .invoke_script(
                RECORD_FAILURE_SCRIPT,
                &[self.reservations_key, self.failures_key],
                &[self.id, window_ms],
            )
            .await?;
        Ok(())
    }
}

/// Redis-backed raw-key egress attempt limiter.
#[derive(Clone, Debug)]
pub struct KeyEgressLimiter {
    redis: PrefixedRedis,
}

impl KeyEgressLimiter {
    /// Create a limiter over the application's shared Redis connection.
    #[must_use]
    pub fn new(redis: PrefixedRedis) -> Self {
        Self { redis }
    }

    /// Reserve an attempt for the current tenant and pubkey.
    ///
    /// The current pubkey is the limiter subject. A successful key rotation
    /// intentionally starts a fresh budget for the new identity.
    ///
    /// # Errors
    ///
    /// Returns a Redis error when admission cannot be decided.
    pub async fn reserve(
        &self,
        tenant_id: i64,
        current_pubkey: &str,
    ) -> RedisResult<KeyEgressAdmission> {
        // The literal hash tag keeps both sorted sets on one Redis Cluster slot.
        let subject = format!("key_egress:{{{tenant_id}:{current_pubkey}}}");
        let failures_key = format!("{subject}:failures");
        let reservations_key = format!("{subject}:reservations");
        let id = Uuid::new_v4().to_string();
        let arguments = vec![
            id.clone(),
            KEY_EGRESS_MAX_ATTEMPTS.to_string(),
            KEY_EGRESS_ATTEMPT_WINDOW.as_millis().to_string(),
            KEY_EGRESS_RESERVATION_TTL.as_millis().to_string(),
        ];
        let (admitted, retry_after): (i64, i64) = self
            .redis
            .invoke_script(
                RESERVE_SCRIPT,
                &[failures_key.clone(), reservations_key.clone()],
                &arguments,
            )
            .await?;

        if admitted == 1 {
            Ok(KeyEgressAdmission::Reserved(KeyEgressReservation {
                redis: self.redis.clone(),
                failures_key,
                reservations_key,
                id,
            }))
        } else {
            Ok(KeyEgressAdmission::Locked {
                retry_after: retry_after.clamp(1, i64::from(u32::MAX)) as u32,
            })
        }
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use redis::{aio::ConnectionManager, AsyncCommands};

    async fn test_limiter() -> (KeyEgressLimiter, String, redis::Client) {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("TEST_REDIS_URL must name the dedicated test Redis");
        let client = redis::Client::open(redis_url).expect("valid Redis URL");
        let connection = ConnectionManager::new(client.clone())
            .await
            .expect("connect to Redis");
        let prefix = format!("keycast-pr326-independent-review:{}", Uuid::new_v4());
        let redis = PrefixedRedis::new(connection, Some(prefix.clone()));
        (KeyEgressLimiter::new(redis), prefix, client)
    }

    async fn cleanup_subject(limiter: &KeyEgressLimiter, tenant_id: i64, pubkey: &str) {
        let subject = format!("key_egress:{{{tenant_id}:{pubkey}}}");
        limiter
            .redis
            .del(&format!("{subject}:failures"))
            .await
            .expect("delete failure history");
        limiter
            .redis
            .del(&format!("{subject}:reservations"))
            .await
            .expect("delete reservations");
    }

    #[tokio::test]
    async fn concurrent_reservations_never_exceed_the_budget() {
        let (limiter, _prefix, _client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..10 {
            let limiter = limiter.clone();
            tasks.spawn(async move { limiter.reserve(1, pubkey).await });
        }

        let mut reserved = Vec::new();
        let mut locked = 0;
        while let Some(result) = tasks.join_next().await {
            match result.expect("reservation task").expect("Redis admission") {
                KeyEgressAdmission::Reserved(reservation) => reserved.push(reservation),
                KeyEgressAdmission::Locked { .. } => locked += 1,
            }
        }

        assert_eq!(reserved.len(), KEY_EGRESS_MAX_ATTEMPTS);
        assert_eq!(locked, 10 - KEY_EGRESS_MAX_ATTEMPTS);
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn wrong_password_conversion_spends_the_reserved_attempt() {
        let (limiter, _prefix, _client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();

        for _ in 0..KEY_EGRESS_MAX_ATTEMPTS {
            let KeyEgressAdmission::Reserved(reservation) =
                limiter.reserve(1, pubkey).await.expect("reserve")
            else {
                panic!("budget should still have room");
            };
            reservation.record_failure().await.expect("record failure");
        }

        assert!(matches!(
            limiter.reserve(1, pubkey).await.expect("locked admission"),
            KeyEgressAdmission::Locked {
                retry_after: 1..=900
            }
        ));
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn releasing_an_attempt_makes_its_slot_available() {
        let (limiter, _prefix, _client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let mut reservations = Vec::new();
        for _ in 0..KEY_EGRESS_MAX_ATTEMPTS {
            let KeyEgressAdmission::Reserved(reservation) =
                limiter.reserve(1, pubkey).await.expect("reserve")
            else {
                panic!("budget should still have room");
            };
            reservations.push(reservation);
        }

        reservations
            .pop()
            .expect("one reservation")
            .release()
            .await
            .expect("release");
        assert!(matches!(
            limiter
                .reserve(1, pubkey)
                .await
                .expect("admission after release"),
            KeyEgressAdmission::Reserved(_)
        ));
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn failures_outside_the_sliding_window_do_not_consume_budget() {
        let (limiter, prefix, client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let failures_key = format!("{prefix}:key_egress:{{1:{pubkey}}}:failures");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let server_time: (i64, i64) = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .expect("Redis server time");
        let now_ms = server_time.0 * 1_000 + server_time.1 / 1_000;
        let window_ms = KEY_EGRESS_ATTEMPT_WINDOW.as_millis() as i64;

        for index in 0..KEY_EGRESS_MAX_ATTEMPTS {
            let score = if index == 0 {
                now_ms - window_ms - 2_000
            } else {
                now_ms - window_ms + 2_000
            };
            let _: usize = connection
                .zadd(&failures_key, format!("failure-{index}"), score)
                .await
                .expect("seed failure");
        }

        assert!(matches!(
            limiter
                .reserve(1, pubkey)
                .await
                .expect("boundary admission"),
            KeyEgressAdmission::Reserved(_)
        ));
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn finalization_after_expiry_fails_closed() {
        let (limiter, prefix, client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let KeyEgressAdmission::Reserved(reservation) =
            limiter.reserve(1, pubkey).await.expect("reserve")
        else {
            panic!("first attempt should be admitted");
        };
        let reservations_key = format!("{prefix}:key_egress:{{1:{pubkey}}}:reservations");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let _: usize = connection
            .zadd(&reservations_key, &reservation.id, 0)
            .await
            .expect("expire reservation score");

        assert!(
            reservation.release().await.is_err(),
            "an expired owner token must not finalize successfully"
        );
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn duplicate_finalization_cannot_release_another_slot() {
        let (limiter, _prefix, _client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let KeyEgressAdmission::Reserved(reservation) =
            limiter.reserve(1, pubkey).await.expect("reserve")
        else {
            panic!("first attempt should be admitted");
        };
        let duplicate = KeyEgressReservation {
            redis: reservation.redis.clone(),
            failures_key: reservation.failures_key.clone(),
            reservations_key: reservation.reservations_key.clone(),
            id: reservation.id.clone(),
        };

        reservation.release().await.expect("owner finalizes once");
        assert!(
            duplicate.release().await.is_err(),
            "replaying an owner token must fail"
        );
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn failed_failure_persistence_does_not_release_the_owner_lease() {
        let (limiter, prefix, client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let KeyEgressAdmission::Reserved(reservation) =
            limiter.reserve(1, pubkey).await.expect("reserve")
        else {
            panic!("first attempt should be admitted");
        };
        let reservation_id = reservation.id.clone();
        let failures_key = format!("{prefix}:key_egress:{{1:{pubkey}}}:failures");
        let reservations_key = format!("{prefix}:key_egress:{{1:{pubkey}}}:reservations");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let _: () = connection
            .set(&failures_key, "wrong-type")
            .await
            .expect("inject failure-write error");

        assert!(
            reservation.record_failure().await.is_err(),
            "failure conversion must surface Redis ambiguity"
        );
        let still_reserved: Option<f64> = connection
            .zscore(&reservations_key, reservation_id)
            .await
            .expect("inspect owner lease");
        assert!(
            still_reserved.is_some(),
            "a failed failure write must leave the exact owner lease fail-closed"
        );
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn cancelled_requests_leave_only_bounded_reservations() {
        let (limiter, prefix, client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let mut cancelled_reservations = Vec::new();
        for _ in 0..KEY_EGRESS_MAX_ATTEMPTS {
            let KeyEgressAdmission::Reserved(reservation) =
                limiter.reserve(1, pubkey).await.expect("reserve")
            else {
                panic!("budget should still have room");
            };
            cancelled_reservations.push(reservation);
        }
        // Dropping the handler future abandons its owner token without
        // finalization. The Redis lease must remain fail-closed until its
        // explicitly bounded expiry rather than being released by Drop.
        drop(cancelled_reservations);
        assert!(matches!(
            limiter.reserve(1, pubkey).await.expect("locked admission"),
            KeyEgressAdmission::Locked { .. }
        ));

        let reservations_key = format!("{prefix}:key_egress:{{1:{pubkey}}}:reservations");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let remaining_ms: i64 = connection
            .pttl(&reservations_key)
            .await
            .expect("reservation TTL");
        assert!(
            remaining_ms > 0 && remaining_ms <= KEY_EGRESS_RESERVATION_TTL.as_millis() as i64,
            "abandoned slots must expire within the documented 60 seconds: {remaining_ms}ms"
        );

        let _: bool = connection
            .pexpire(&reservations_key, 10)
            .await
            .expect("shorten TTL for test");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(
            limiter
                .reserve(1, pubkey)
                .await
                .expect("admission after expiry"),
            KeyEgressAdmission::Reserved(_)
        ));
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn retry_after_rounds_up_from_redis_server_time() {
        let (limiter, prefix, client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let failures_key = format!("{prefix}:key_egress:{{1:{pubkey}}}:failures");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let before: (i64, i64) = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .expect("Redis server time");
        let before_ms = before.0 * 1_000 + before.1 / 1_000;
        let window_ms = KEY_EGRESS_ATTEMPT_WINDOW.as_millis() as i64;
        let oldest_failure_ms = before_ms - window_ms + 10_500;
        for index in 0..KEY_EGRESS_MAX_ATTEMPTS {
            let _: usize = connection
                .zadd(
                    &failures_key,
                    format!("failure-{index}"),
                    oldest_failure_ms + index as i64,
                )
                .await
                .expect("seed failure");
        }

        let KeyEgressAdmission::Locked { retry_after } =
            limiter.reserve(1, pubkey).await.expect("locked admission")
        else {
            panic!("five live failures must lock the subject");
        };
        let after: (i64, i64) = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .expect("Redis server time");
        let after_ms = after.0 * 1_000 + after.1 / 1_000;
        let remaining_ms = oldest_failure_ms + window_ms - after_ms;
        let reported_ms = i64::from(retry_after) * 1_000;
        assert!(
            reported_ms >= remaining_ms,
            "Retry-After must not reopen before Redis says the slot expires"
        );
        assert!(
            reported_ms - 1_000 < remaining_ms,
            "Retry-After should round up by less than one second"
        );
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn redis_state_loss_resets_the_attempt_budget() {
        let (limiter, _prefix, _client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        for _ in 0..KEY_EGRESS_MAX_ATTEMPTS {
            let KeyEgressAdmission::Reserved(reservation) =
                limiter.reserve(1, pubkey).await.expect("reserve")
            else {
                panic!("budget should still have room");
            };
            reservation.record_failure().await.expect("record failure");
        }
        assert!(matches!(
            limiter.reserve(1, pubkey).await.expect("locked admission"),
            KeyEgressAdmission::Locked { .. }
        ));

        cleanup_subject(&limiter, 1, pubkey).await;
        assert!(matches!(
            limiter
                .reserve(1, pubkey)
                .await
                .expect("admission after state loss"),
            KeyEgressAdmission::Reserved(_)
        ));
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[tokio::test]
    async fn subject_keys_share_a_redis_cluster_hash_tag() {
        let (limiter, prefix, client) = test_limiter().await;
        let pubkey = KeysFixture::pubkey();
        let KeyEgressAdmission::Reserved(first) =
            limiter.reserve(1, pubkey).await.expect("first reservation")
        else {
            panic!("first attempt should be admitted");
        };
        first.record_failure().await.expect("record failure");
        assert!(matches!(
            limiter
                .reserve(1, pubkey)
                .await
                .expect("second reservation"),
            KeyEgressAdmission::Reserved(_)
        ));

        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("raw Redis connection");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{prefix}:key_egress:*"))
            .query_async(&mut connection)
            .await
            .expect("list test keys");
        assert_eq!(keys.len(), 2);
        let expected_hash_tag = format!("{{1:{pubkey}}}");
        assert!(
            keys.iter().all(|key| key.contains(&expected_hash_tag)),
            "both subject keys must share one Redis Cluster hash tag: {keys:?}"
        );
        cleanup_subject(&limiter, 1, pubkey).await;
    }

    #[test]
    fn reservation_lifetime_exceeds_all_accepted_work() {
        assert!(
            KEY_EGRESS_RESERVED_WORK_DEADLINE
                + KEY_EGRESS_FINALIZATION_DEADLINE
                + KEY_EGRESS_RESERVATION_SAFETY_MARGIN
                <= KEY_EGRESS_RESERVATION_TTL
        );
    }

    struct KeysFixture;

    impl KeysFixture {
        const fn pubkey() -> &'static str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    }
}
