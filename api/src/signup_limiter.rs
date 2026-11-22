//! Rolling limits on account creation, per source network and overall.
//!
//! An instant-access registration creates a permanent account: a users row,
//! an encrypted key and a confirmation email. Nothing reaps it the way an
//! unconfirmed pending registration expires, so registration is admitted
//! against two sliding windows before any password hashing or key work:
//!
//! * one per coarse source network (an IPv4 /24 or IPv6 /56, the same subject
//!   the email-delivery controls use), and
//! * one across every source, which bounds the total even when no source can
//!   be derived.
//!
//! Admission fails open when Redis cannot answer: a Redis outage must not stop
//! people from signing up.

use crate::email_delivery::coarse_source;
use crate::PrefixedRedis;
use axum::http::HeaderMap;
use keycast_core::metrics::METRICS;
use sha2::{Digest, Sha256};
use std::{env, sync::OnceLock, time::Duration};
use uuid::Uuid;

/// Body of a 429 from the sign-up admission limits, shared by every
/// registration endpoint.
pub const SIGNUP_RATE_LIMIT_MESSAGE: &str =
    "Too many accounts have been created from this network recently. Please try again later.";

/// Bound Redis itself so a live but unresponsive socket cannot hold up sign-up.
const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_millis(250);

const ADMIT_SCRIPT: &str = r#"
local source_key = KEYS[1]
local global_key = KEYS[2]
local id = ARGV[1]
local source_enabled = tonumber(ARGV[2])
local source_limit = tonumber(ARGV[3])
local global_limit = tonumber(ARGV[4])
local window_ms = tonumber(ARGV[5])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)

local function retry_seconds(key)
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_ms = window_ms
    if #oldest > 0 then
        retry_ms = math.max(1, tonumber(oldest[2]) + window_ms - now_ms)
    end
    return math.max(1, math.floor((retry_ms + 999) / 1000))
end

if source_enabled == 1 then
    redis.call('ZREMRANGEBYSCORE', source_key, '-inf', now_ms - window_ms)
    if redis.call('ZCARD', source_key) >= source_limit then
        return {0, retry_seconds(source_key), 1}
    end
end

redis.call('ZREMRANGEBYSCORE', global_key, '-inf', now_ms - window_ms)
if redis.call('ZCARD', global_key) >= global_limit then
    return {0, retry_seconds(global_key), 2}
end

if source_enabled == 1 then
    redis.call('ZADD', source_key, now_ms, id)
    redis.call('PEXPIRE', source_key, window_ms)
end
redis.call('ZADD', global_key, now_ms, id)
redis.call('PEXPIRE', global_key, window_ms)
return {1, 0, 0}
"#;

/// Limits applied to account registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignupLimitConfig {
    /// Registrations admitted from one source network per window. Zero
    /// disables the per-source limit.
    pub source_limit: usize,
    /// Registrations admitted from all sources per window.
    pub global_limit: usize,
    /// Length of the sliding window.
    pub window: Duration,
    /// Trusted proxies in front of Keycast, counted from the right of
    /// `X-Forwarded-For`.
    pub source_trusted_proxy_hops: usize,
}

impl Default for SignupLimitConfig {
    fn default() -> Self {
        // Production peaked at 21 confirmed sign-ups in an hour over the 30
        // days before this limit landed, so both bounds sit far above real
        // traffic while stopping a script that mints accounts in bulk.
        Self {
            source_limit: 20,
            global_limit: 600,
            window: Duration::from_secs(60 * 60),
            // Cloud Run domain mapping supplies the client as the rightmost
            // address, matching the email-delivery default.
            source_trusted_proxy_hops: 0,
        }
    }
}

impl SignupLimitConfig {
    /// Read the limits from `SIGNUP_SOURCE_LIMIT`, `SIGNUP_GLOBAL_LIMIT`,
    /// `SIGNUP_WINDOW_SECONDS` and `SIGNUP_SOURCE_TRUSTED_PROXY_HOPS`.
    ///
    /// # Errors
    ///
    /// Returns an error when a value is not an integer, or when the global
    /// limit or the window is zero.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        Ok(Self {
            source_limit: env_integer("SIGNUP_SOURCE_LIMIT", defaults.source_limit, true)?,
            global_limit: env_integer("SIGNUP_GLOBAL_LIMIT", defaults.global_limit, false)?,
            window: Duration::from_secs(env_integer(
                "SIGNUP_WINDOW_SECONDS",
                defaults.window.as_secs() as usize,
                false,
            )? as u64),
            source_trusted_proxy_hops: env_integer(
                "SIGNUP_SOURCE_TRUSTED_PROXY_HOPS",
                defaults.source_trusted_proxy_hops,
                true,
            )?,
        })
    }
}

fn env_integer(name: &str, default: usize, allow_zero: bool) -> Result<usize, String> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|parsed| allow_zero || *parsed > 0)
        .ok_or_else(|| {
            if allow_zero {
                format!("{name} must be a non-negative integer")
            } else {
                format!("{name} must be a positive integer")
            }
        })
}

static CONFIG: OnceLock<SignupLimitConfig> = OnceLock::new();

/// Validate the sign-up limits from the environment once, at startup.
///
/// # Errors
///
/// Returns the [`SignupLimitConfig::from_env`] error for an invalid value.
pub fn init_from_env() -> Result<SignupLimitConfig, String> {
    let config = SignupLimitConfig::from_env()?;
    Ok(*CONFIG.get_or_init(|| config))
}

/// The configured limits, or the defaults when startup did not set them.
#[must_use]
pub fn configured() -> SignupLimitConfig {
    *CONFIG.get_or_init(SignupLimitConfig::default)
}

/// Outcome of asking to create one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignupAdmission {
    /// The registration may proceed.
    Admitted,
    /// A window is full.
    Limited {
        /// Whole seconds until the oldest counted registration leaves the
        /// window.
        retry_after: u32,
    },
}

/// Redis-backed admission for account registration.
#[derive(Clone, Debug)]
pub struct SignupLimiter {
    redis: Option<PrefixedRedis>,
    config: SignupLimitConfig,
}

impl SignupLimiter {
    /// Create a limiter. Without Redis every registration is admitted.
    #[must_use]
    pub fn new(redis: Option<PrefixedRedis>, config: SignupLimitConfig) -> Self {
        Self { redis, config }
    }

    /// Count one registration attempt for the request's source network.
    ///
    /// Counts the attempt, not the outcome: a registration refused later for a
    /// duplicate email still spent the window, which is what bounds a script
    /// probing addresses as well as one creating accounts.
    pub async fn admit(&self, tenant_id: i64, headers: &HeaderMap) -> SignupAdmission {
        let Some(redis) = &self.redis else {
            return SignupAdmission::Admitted;
        };
        let source = coarse_source(headers, self.config.source_trusted_proxy_hops);
        let source_enabled = source.is_some() && self.config.source_limit > 0;
        let tag = "signup:{shared}";
        let source_hash = source
            .map(|source| hex::encode(Sha256::digest(format!("{tenant_id}:{source}").as_bytes())))
            .unwrap_or_else(|| "none".to_string());
        let keys = [
            format!("{tag}:source:{source_hash}"),
            format!("{tag}:global:{tenant_id}"),
        ];
        let arguments = [
            Uuid::new_v4().to_string(),
            usize::from(source_enabled).to_string(),
            self.config.source_limit.to_string(),
            self.config.global_limit.to_string(),
            self.config.window.as_millis().to_string(),
        ];

        let decision = tokio::time::timeout(
            REDIS_OPERATION_TIMEOUT,
            redis.invoke_script::<(i64, i64, i64)>(ADMIT_SCRIPT, &keys, &arguments),
        )
        .await;
        match decision {
            Ok(Ok((1, _, _))) => {
                METRICS.observe_signup_admission("admitted");
                SignupAdmission::Admitted
            }
            Ok(Ok((_, retry_after, scope))) => {
                METRICS.observe_signup_admission(if scope == 1 {
                    "source_limited"
                } else {
                    "global_limited"
                });
                SignupAdmission::Limited {
                    retry_after: u32::try_from(retry_after.max(1)).unwrap_or(u32::MAX),
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "Sign-up admission unavailable; admitting");
                METRICS.observe_signup_admission("unavailable");
                SignupAdmission::Admitted
            }
            Err(_) => {
                tracing::warn!("Sign-up admission timed out; admitting");
                METRICS.observe_signup_admission("unavailable");
                SignupAdmission::Admitted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_sit_well_above_observed_traffic() {
        let config = SignupLimitConfig::default();
        assert_eq!(config.source_limit, 20);
        assert_eq!(config.global_limit, 600);
        assert_eq!(config.window, Duration::from_secs(3600));
    }

    #[test]
    fn env_integer_rejects_zero_where_zero_is_meaningless() {
        std::env::set_var("SIGNUP_TEST_ZERO", "0");
        assert!(env_integer("SIGNUP_TEST_ZERO", 5, false).is_err());
        assert_eq!(env_integer("SIGNUP_TEST_ZERO", 5, true), Ok(0));
        std::env::remove_var("SIGNUP_TEST_ZERO");
    }

    #[test]
    fn env_integer_rejects_non_integers() {
        std::env::set_var("SIGNUP_TEST_JUNK", "ten");
        assert!(env_integer("SIGNUP_TEST_JUNK", 5, true).is_err());
        std::env::remove_var("SIGNUP_TEST_JUNK");
    }

    #[test]
    fn env_integer_falls_back_to_the_default_when_unset() {
        std::env::remove_var("SIGNUP_TEST_UNSET");
        assert_eq!(env_integer("SIGNUP_TEST_UNSET", 7, false), Ok(7));
    }

    #[tokio::test]
    async fn admits_everything_without_redis() {
        let limiter = SignupLimiter::new(None, SignupLimitConfig::default());
        assert_eq!(
            limiter.admit(1, &HeaderMap::new()).await,
            SignupAdmission::Admitted
        );
    }
}
