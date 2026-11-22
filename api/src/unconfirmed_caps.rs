//! Hourly caps on posts, comments and reports for accounts whose email is not
//! confirmed yet, backed by Redis sliding windows.
//!
//! The rules live in [`keycast_core::unconfirmed_email`]; this is the Redis
//! implementation every signing path shares once [`install`] has run. A
//! working email inbox used to be the per-account cost of a throwaway account.
//! Instant access removes it, so until someone confirms, the actions abuse
//! scales with are capped well above what a real new account does in an hour.
//!
//! Admission fails open when Redis cannot answer: an outage lifts the caps
//! rather than stopping new accounts from posting at all.

use crate::PrefixedRedis;
use async_trait::async_trait;
use keycast_core::metrics::METRICS;
use keycast_core::unconfirmed_email::{CapAdmission, CapCategory, UnconfirmedCaps};
use std::{env, sync::Arc, time::Duration};
use uuid::Uuid;

/// Bound Redis itself so a live but unresponsive socket cannot hold up signing.
const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_millis(250);

const ADMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local id = ARGV[1]
local limit = tonumber(ARGV[2])
local window_ms = tonumber(ARGV[3])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
if redis.call('ZCARD', key) >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_ms = window_ms
    if #oldest > 0 then
        retry_ms = math.max(1, tonumber(oldest[2]) + window_ms - now_ms)
    end
    return {0, math.max(1, math.floor((retry_ms + 999) / 1000))}
end

redis.call('ZADD', key, now_ms, id)
redis.call('PEXPIRE', key, window_ms)
return {1, 0}
"#;

/// Per-window limits for unconfirmed accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnconfirmedCapsConfig {
    /// Video posts per window.
    pub post_limit: usize,
    /// Comments and text notes per window.
    pub comment_limit: usize,
    /// Reports per window.
    pub report_limit: usize,
    /// Length of the sliding window.
    pub window: Duration,
}

impl Default for UnconfirmedCapsConfig {
    fn default() -> Self {
        Self {
            post_limit: 5,
            comment_limit: 30,
            report_limit: 5,
            window: Duration::from_secs(60 * 60),
        }
    }
}

impl UnconfirmedCapsConfig {
    /// Read `UNCONFIRMED_POST_LIMIT`, `UNCONFIRMED_COMMENT_LIMIT`,
    /// `UNCONFIRMED_REPORT_LIMIT` and `UNCONFIRMED_WINDOW_SECONDS`.
    ///
    /// # Errors
    ///
    /// Returns an error when a value is not a positive integer.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        Ok(Self {
            post_limit: env_positive("UNCONFIRMED_POST_LIMIT", defaults.post_limit)?,
            comment_limit: env_positive("UNCONFIRMED_COMMENT_LIMIT", defaults.comment_limit)?,
            report_limit: env_positive("UNCONFIRMED_REPORT_LIMIT", defaults.report_limit)?,
            window: Duration::from_secs(env_positive(
                "UNCONFIRMED_WINDOW_SECONDS",
                defaults.window.as_secs() as usize,
            )? as u64),
        })
    }

    fn limit(&self, category: CapCategory) -> usize {
        match category {
            CapCategory::Post => self.post_limit,
            CapCategory::Comment => self.comment_limit,
            CapCategory::Report => self.report_limit,
        }
    }
}

fn env_positive(name: &str, default: usize) -> Result<usize, String> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| format!("{name} must be a positive integer"))
}

/// Redis-backed [`UnconfirmedCaps`].
#[derive(Clone, Debug)]
pub struct RedisUnconfirmedCaps {
    redis: PrefixedRedis,
    config: UnconfirmedCapsConfig,
}

impl RedisUnconfirmedCaps {
    /// Create the limiter over the shared Redis connection.
    #[must_use]
    pub fn new(redis: PrefixedRedis, config: UnconfirmedCapsConfig) -> Self {
        Self { redis, config }
    }
}

#[async_trait]
impl UnconfirmedCaps for RedisUnconfirmedCaps {
    async fn admit(&self, tenant_id: i64, pubkey_hex: &str, category: CapCategory) -> CapAdmission {
        let keys = [format!(
            "unconfirmed_caps:{{shared}}:{tenant_id}:{}:{pubkey_hex}",
            category.as_str()
        )];
        let arguments = [
            Uuid::new_v4().to_string(),
            self.config.limit(category).to_string(),
            self.config.window.as_millis().to_string(),
        ];
        let decision = tokio::time::timeout(
            REDIS_OPERATION_TIMEOUT,
            self.redis
                .invoke_script::<(i64, i64)>(ADMIT_SCRIPT, &keys, &arguments),
        )
        .await;
        match decision {
            Ok(Ok((1, _))) => {
                METRICS.observe_unconfirmed_cap(category, "admitted");
                CapAdmission::Admitted
            }
            Ok(Ok((_, retry_after))) => {
                METRICS.observe_unconfirmed_cap(category, "limited");
                CapAdmission::Limited {
                    retry_after: u32::try_from(retry_after.max(1)).unwrap_or(u32::MAX),
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, category = category.as_str(), "Unconfirmed cap unavailable; admitting");
                METRICS.observe_unconfirmed_cap(category, "unavailable");
                CapAdmission::Admitted
            }
            Err(_) => {
                tracing::warn!(
                    category = category.as_str(),
                    "Unconfirmed cap timed out; admitting"
                );
                METRICS.observe_unconfirmed_cap(category, "unavailable");
                CapAdmission::Admitted
            }
        }
    }
}

/// Validate the caps from the environment and install them for every signing
/// path. Without Redis nothing is installed and nothing is capped.
///
/// # Errors
///
/// Returns the [`UnconfirmedCapsConfig::from_env`] error for an invalid value.
pub fn install(redis: Option<PrefixedRedis>) -> Result<UnconfirmedCapsConfig, String> {
    let config = UnconfirmedCapsConfig::from_env()?;
    if let Some(redis) = redis {
        keycast_core::unconfirmed_email::install_caps(Arc::new(RedisUnconfirmedCaps::new(
            redis, config,
        )));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_leave_room_for_a_real_new_account() {
        let config = UnconfirmedCapsConfig::default();
        assert_eq!(config.limit(CapCategory::Post), 5);
        assert_eq!(config.limit(CapCategory::Comment), 30);
        assert_eq!(config.limit(CapCategory::Report), 5);
        assert_eq!(config.window, Duration::from_secs(3600));
    }

    #[test]
    fn env_positive_rejects_zero_and_junk() {
        std::env::set_var("UNCONFIRMED_TEST_ZERO", "0");
        assert!(env_positive("UNCONFIRMED_TEST_ZERO", 5).is_err());
        std::env::remove_var("UNCONFIRMED_TEST_ZERO");
        std::env::set_var("UNCONFIRMED_TEST_JUNK", "lots");
        assert!(env_positive("UNCONFIRMED_TEST_JUNK", 5).is_err());
        std::env::remove_var("UNCONFIRMED_TEST_JUNK");
        assert_eq!(env_positive("UNCONFIRMED_TEST_UNSET", 9), Ok(9));
    }
}
