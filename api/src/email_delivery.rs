//! Shared admission and bounded provider execution for security-sensitive email.

use crate::{
    email_service::{create_email_sender, EmailProviderOutcome, EmailSendError, EmailSender},
    PrefixedRedis,
};
use axum::http::HeaderMap;
use keycast_core::metrics::METRICS;
use redis::RedisResult;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    env,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

const ADMIT_SCRIPT: &str = r#"
local id = ARGV[1]
local destination_count = tonumber(ARGV[2])
local slots = tonumber(ARGV[3])
local provider_slots = tonumber(ARGV[4])
local destination_cooldown_ms = tonumber(ARGV[5])
local destination_limit = tonumber(ARGV[6])
local destination_window_ms = tonumber(ARGV[7])
local account_enabled = tonumber(ARGV[8])
local account_limit = tonumber(ARGV[9])
local account_window_ms = tonumber(ARGV[10])
local source_enabled = tonumber(ARGV[11])
local source_limit = tonumber(ARGV[12])
local source_window_ms = tonumber(ARGV[13])
local global_limit = tonumber(ARGV[14])
local global_window_ms = tonumber(ARGV[15])
local in_flight_limit = tonumber(ARGV[16])
local reservation_ttl_ms = tonumber(ARGV[17])

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000)
    + math.floor(tonumber(server_time[2]) / 1000)
local account_key = KEYS[destination_count + 1]
local source_key = KEYS[destination_count + 2]
local global_key = KEYS[destination_count + 3]
local in_flight_key = KEYS[destination_count + 4]

local function trim_window(key, window_ms)
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
end

for index = 1, destination_count do
    local key = KEYS[index]
    trim_window(key, destination_window_ms)
    local latest = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
    if #latest > 0 and now_ms - tonumber(latest[2]) < destination_cooldown_ms then
        return {0, 1}
    end
    if redis.call('ZCARD', key) >= destination_limit then
        return {0, 2}
    end
end

if account_enabled == 1 then
    trim_window(account_key, account_window_ms)
    if redis.call('ZCARD', account_key) + slots > account_limit then
        return {0, 3}
    end
end

local source_exceeded = 0
if source_enabled == 1 then
    trim_window(source_key, source_window_ms)
    if redis.call('ZCARD', source_key) + slots > source_limit then
        source_exceeded = 1
    end
end

trim_window(global_key, global_window_ms)
if redis.call('ZCARD', global_key) + slots > global_limit then
    return {0, 5}
end

redis.call('ZREMRANGEBYSCORE', in_flight_key, '-inf', now_ms)
if redis.call('ZCARD', in_flight_key) + provider_slots > in_flight_limit then
    return {0, 6}
end

for index = 1, destination_count do
    redis.call('ZADD', KEYS[index], now_ms, id .. ':destination:' .. index)
    redis.call('PEXPIRE', KEYS[index], destination_window_ms)
end
for index = 1, slots do
    local member = id .. ':' .. index
    if account_enabled == 1 then redis.call('ZADD', account_key, now_ms, member) end
    if source_enabled == 1 then redis.call('ZADD', source_key, now_ms, member) end
    redis.call('ZADD', global_key, now_ms, member)
end
for index = 1, provider_slots do
    redis.call('ZADD', in_flight_key, now_ms + reservation_ttl_ms, id .. ':' .. index)
end
if account_enabled == 1 then redis.call('PEXPIRE', account_key, account_window_ms) end
if source_enabled == 1 then redis.call('PEXPIRE', source_key, source_window_ms) end
redis.call('PEXPIRE', global_key, global_window_ms)
redis.call('PEXPIRE', in_flight_key, reservation_ttl_ms)
return {1, source_exceeded == 1 and 4 or 0}
"#;

const AUDIT_ONCE_SCRIPT: &str = r#"
if redis.call('SET', KEYS[1], '1', 'PX', ARGV[1], 'NX') then
    return 1
end
return 0
"#;

const RELEASE_SCRIPT: &str = r#"
local removed = 0
for index = 1, tonumber(ARGV[2]) do
    removed = removed + redis.call('ZREM', KEYS[1], ARGV[1] .. ':' .. index)
end
return removed
"#;

/// Independently configurable email-delivery limits.
#[derive(Clone, Debug)]
pub struct EmailDeliveryConfig {
    pub destination_cooldown: Duration,
    pub destination_limit: usize,
    pub destination_window: Duration,
    pub account_limit: usize,
    pub account_window: Duration,
    pub source_limit: usize,
    pub source_window: Duration,
    pub source_trusted_proxy_hops: usize,
    pub global_limit: usize,
    pub global_window: Duration,
    pub provider_in_flight_limit: usize,
    pub provider_request_timeout: Duration,
    pub fallback_instance_divisor: usize,
}

impl Default for EmailDeliveryConfig {
    fn default() -> Self {
        Self {
            destination_cooldown: Duration::from_secs(5 * 60),
            destination_limit: 5,
            destination_window: Duration::from_secs(60 * 60),
            account_limit: 6,
            account_window: Duration::from_secs(60 * 60),
            source_limit: 50,
            source_window: Duration::from_secs(60 * 60),
            // Cloud Run domain mapping supplies the client as the rightmost address.
            source_trusted_proxy_hops: 0,
            global_limit: 1_000,
            global_window: Duration::from_secs(60),
            provider_in_flight_limit: 20,
            provider_request_timeout: Duration::from_secs(10),
            fallback_instance_divisor: 3,
        }
    }
}

impl EmailDeliveryConfig {
    /// Read delivery controls from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit or timeout is zero, or any value is not an integer.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        Ok(Self {
            destination_cooldown: env_duration(
                "EMAIL_DELIVERY_DESTINATION_COOLDOWN_SECONDS",
                defaults.destination_cooldown,
            )?,
            destination_limit: env_usize(
                "EMAIL_DELIVERY_DESTINATION_LIMIT",
                defaults.destination_limit,
            )?,
            destination_window: env_duration(
                "EMAIL_DELIVERY_DESTINATION_WINDOW_SECONDS",
                defaults.destination_window,
            )?,
            account_limit: env_usize("EMAIL_DELIVERY_ACCOUNT_LIMIT", defaults.account_limit)?,
            account_window: env_duration(
                "EMAIL_DELIVERY_ACCOUNT_WINDOW_SECONDS",
                defaults.account_window,
            )?,
            source_limit: env_nonnegative_usize(
                "EMAIL_DELIVERY_SOURCE_LIMIT",
                defaults.source_limit,
            )?,
            source_window: env_duration(
                "EMAIL_DELIVERY_SOURCE_WINDOW_SECONDS",
                defaults.source_window,
            )?,
            source_trusted_proxy_hops: env_nonnegative_usize(
                "EMAIL_DELIVERY_SOURCE_TRUSTED_PROXY_HOPS",
                defaults.source_trusted_proxy_hops,
            )?,
            global_limit: env_usize("EMAIL_DELIVERY_GLOBAL_LIMIT", defaults.global_limit)?,
            global_window: env_duration(
                "EMAIL_DELIVERY_GLOBAL_WINDOW_SECONDS",
                defaults.global_window,
            )?,
            provider_in_flight_limit: env_usize(
                "EMAIL_PROVIDER_MAX_IN_FLIGHT",
                defaults.provider_in_flight_limit,
            )?,
            provider_request_timeout: env_duration_millis(
                "EMAIL_PROVIDER_REQUEST_TIMEOUT_MS",
                defaults.provider_request_timeout,
            )?,
            fallback_instance_divisor: env_usize(
                "EMAIL_DELIVERY_FALLBACK_INSTANCE_DIVISOR",
                defaults.fallback_instance_divisor,
            )?,
        })
    }

    fn reservation_ttl(&self, slots: usize) -> Duration {
        let provider_work =
            self.provider_request_timeout.saturating_mul(slots as u32) + Duration::from_secs(5);
        provider_work.max(Duration::from_secs(60))
    }
}

fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    let Some(value) = env::var(name).ok() else {
        return Ok(default);
    };
    value
        .parse::<usize>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| format!("{name} must be a positive integer"))
}

fn env_nonnegative_usize(name: &str, default: usize) -> Result<usize, String> {
    let Some(value) = env::var(name).ok() else {
        return Ok(default);
    };
    value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a non-negative integer"))
}

fn env_duration(name: &str, default: Duration) -> Result<Duration, String> {
    env_usize(name, default.as_secs() as usize).map(|value| Duration::from_secs(value as u64))
}

fn env_duration_millis(name: &str, default: Duration) -> Result<Duration, String> {
    env_usize(name, default.as_millis() as usize).map(|value| Duration::from_millis(value as u64))
}

/// Low-cardinality purpose labels shared by audit and metrics.
#[derive(Clone, Copy, Debug)]
pub enum EmailDeliveryPurpose {
    PasswordReset,
    Verification,
    EmailChange,
    EmailChangeNew,
    EmailChangeOld,
}

impl EmailDeliveryPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::Verification => "verification",
            Self::EmailChange => "email_change",
            Self::EmailChangeNew => "email_change_new",
            Self::EmailChangeOld => "email_change_old",
        }
    }
}

/// Subjects considered by one atomic admission decision.
pub struct EmailAdmissionRequest<'a> {
    pub tenant_id: i64,
    pub purpose: EmailDeliveryPurpose,
    pub destinations: &'a [&'a str],
    pub account: Option<&'a str>,
    pub source: Option<&'a str>,
    /// Number of provider deliveries charged to account/global capacity.
    pub delivery_slots: usize,
}

/// Stable refusal reason safe for audit and metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailAdmissionRefusal {
    DestinationCooldown,
    DestinationVolume,
    AccountVolume,
    SourceVolume,
    GlobalVolume,
    ProviderCapacity,
    Unavailable,
}

impl EmailAdmissionRefusal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DestinationCooldown => "destination_cooldown",
            Self::DestinationVolume => "destination_volume",
            Self::AccountVolume => "account_volume",
            Self::SourceVolume => "source_volume",
            Self::GlobalVolume => "global_volume",
            Self::ProviderCapacity => "provider_capacity",
            Self::Unavailable => "admission_unavailable",
        }
    }
}

#[derive(Debug)]
pub struct EmailAdmissionDenied {
    pub reason: EmailAdmissionRefusal,
}

enum ReservationBackend {
    Redis {
        redis: PrefixedRedis,
        in_flight_key: String,
        id: String,
        slots: usize,
    },
    Local {
        state: Arc<Mutex<LocalAdmissionState>>,
        slots: usize,
    },
    Unrestricted,
}

/// Owner token for global provider slots reserved during admission.
pub struct EmailDeliveryReservation {
    backend: ReservationBackend,
}

impl EmailDeliveryReservation {
    /// Release global provider capacity while retaining spent rolling budgets.
    pub async fn release(self) {
        if let ReservationBackend::Local { state, slots } = &self.backend {
            let mut state = state.lock().expect("local email admission lock poisoned");
            state.in_flight = state.in_flight.saturating_sub(*slots);
            return;
        }
        let ReservationBackend::Redis {
            redis,
            in_flight_key,
            id,
            slots,
        } = self.backend
        else {
            return;
        };
        let arguments = vec![id, slots.to_string()];
        if let Err(error) = redis
            .invoke_script::<i64>(RELEASE_SCRIPT, &[in_flight_key], &arguments)
            .await
        {
            tracing::warn!(error = %error, "Failed to release email provider reservation");
        }
    }
}

#[derive(Default)]
struct LocalAdmissionState {
    destinations: HashMap<String, VecDeque<Instant>>,
    accounts: HashMap<String, VecDeque<Instant>>,
    suppression_audits: HashMap<String, Instant>,
    global: VecDeque<Instant>,
    in_flight: usize,
}

#[derive(Clone)]
enum AdmissionBackend {
    Redis(PrefixedRedis),
    Unrestricted,
    Deny(EmailAdmissionRefusal),
}

/// Shared email delivery dependency injected into HTTP routes.
#[derive(Clone)]
pub struct EmailDeliveryService {
    backend: AdmissionBackend,
    sender: Arc<dyn EmailSender>,
    provider_semaphore: Arc<Semaphore>,
    config: EmailDeliveryConfig,
    local_fallback: Arc<Mutex<LocalAdmissionState>>,
}

impl EmailDeliveryService {
    /// Construct the production Redis-backed service and shared sender.
    pub fn from_env(redis: PrefixedRedis) -> Result<Self, String> {
        let config = EmailDeliveryConfig::from_env()?;
        let sender = create_email_sender()?;
        Ok(Self::new(redis, sender, config))
    }

    #[must_use]
    pub fn new(
        redis: PrefixedRedis,
        sender: Arc<dyn EmailSender>,
        config: EmailDeliveryConfig,
    ) -> Self {
        Self {
            backend: AdmissionBackend::Redis(redis),
            sender,
            provider_semaphore: Arc::new(Semaphore::new(config.provider_in_flight_limit)),
            config,
            local_fallback: Arc::new(Mutex::new(LocalAdmissionState::default())),
        }
    }

    /// Construct an unrestricted dependency for legacy handler tests.
    #[must_use]
    pub fn unrestricted_for_tests(sender: Arc<dyn EmailSender>) -> Self {
        let config = EmailDeliveryConfig::default();
        Self {
            backend: AdmissionBackend::Unrestricted,
            sender,
            provider_semaphore: Arc::new(Semaphore::new(config.provider_in_flight_limit)),
            config,
            local_fallback: Arc::new(Mutex::new(LocalAdmissionState::default())),
        }
    }

    /// Construct a dependency that deterministically suppresses handler tests.
    #[must_use]
    pub fn denying_for_tests(sender: Arc<dyn EmailSender>, reason: EmailAdmissionRefusal) -> Self {
        let config = EmailDeliveryConfig::default();
        Self {
            backend: AdmissionBackend::Deny(reason),
            sender,
            provider_semaphore: Arc::new(Semaphore::new(config.provider_in_flight_limit)),
            config,
            local_fallback: Arc::new(Mutex::new(LocalAdmissionState::default())),
        }
    }

    /// Derive a coarse source from the trusted suffix of `X-Forwarded-For`.
    #[must_use]
    pub fn coarse_source(&self, headers: &HeaderMap) -> Option<String> {
        let source = coarse_source(headers, self.config.source_trusted_proxy_hops);
        METRICS.observe_email_delivery_source_subject(source.is_some());
        source
    }

    /// Atomically reserve all rolling budgets and provider slots for one flow.
    pub async fn admit(
        &self,
        request: EmailAdmissionRequest<'_>,
    ) -> Result<EmailDeliveryReservation, EmailAdmissionDenied> {
        let purpose = request.purpose.as_str();
        let redis = match &self.backend {
            AdmissionBackend::Redis(redis) => redis,
            AdmissionBackend::Unrestricted => {
                METRICS.observe_email_delivery_admission(purpose, "admitted", "none");
                return Ok(EmailDeliveryReservation {
                    backend: ReservationBackend::Unrestricted,
                });
            }
            AdmissionBackend::Deny(reason) => {
                METRICS.observe_email_delivery_admission(purpose, "suppressed", reason.as_str());
                return Err(EmailAdmissionDenied { reason: *reason });
            }
        };

        let destinations = request
            .destinations
            .iter()
            .map(|destination| subject_hash(request.tenant_id, destination))
            .collect::<BTreeSet<_>>();
        let slots = request.delivery_slots;
        let provider_slots = slots;
        if slots == 0 {
            let denied = EmailAdmissionDenied {
                reason: EmailAdmissionRefusal::Unavailable,
            };
            METRICS.observe_email_delivery_admission(purpose, "suppressed", denied.reason.as_str());
            return Err(denied);
        }

        let tag = "email_delivery:{shared}";
        let mut keys = destinations
            .iter()
            .map(|hash| format!("{tag}:destination:{purpose}:{hash}"))
            .collect::<Vec<_>>();
        let account_hash = request
            .account
            .map(|account| subject_hash(request.tenant_id, account))
            .unwrap_or_else(|| "none".to_string());
        let source_hash = request
            .source
            .map(|source| subject_hash(request.tenant_id, source))
            .unwrap_or_else(|| "none".to_string());
        keys.push(format!("{tag}:account:{account_hash}"));
        keys.push(format!("{tag}:source:{source_hash}"));
        keys.push(format!("{tag}:global"));
        let in_flight_key = format!("{tag}:in_flight");
        keys.push(in_flight_key.clone());

        let id = Uuid::new_v4().to_string();
        let arguments = vec![
            id.clone(),
            destinations.len().to_string(),
            slots.to_string(),
            provider_slots.to_string(),
            self.config.destination_cooldown.as_millis().to_string(),
            self.config.destination_limit.to_string(),
            self.config.destination_window.as_millis().to_string(),
            usize::from(request.account.is_some()).to_string(),
            self.config.account_limit.to_string(),
            self.config.account_window.as_millis().to_string(),
            usize::from(request.source.is_some() && self.config.source_limit > 0).to_string(),
            self.config.source_limit.to_string(),
            self.config.source_window.as_millis().to_string(),
            self.config.global_limit.to_string(),
            self.config.global_window.as_millis().to_string(),
            self.config.provider_in_flight_limit.to_string(),
            self.config.reservation_ttl(slots).as_millis().to_string(),
        ];
        let decision: RedisResult<(i64, i64)> =
            redis.invoke_script(ADMIT_SCRIPT, &keys, &arguments).await;
        let (admitted, reason) = match decision {
            Ok(decision) => decision,
            Err(error) => {
                tracing::warn!(error = %error, "Email delivery admission unavailable");
                METRICS.observe_email_delivery_admission(
                    purpose,
                    "fallback",
                    EmailAdmissionRefusal::Unavailable.as_str(),
                );
                return self.admit_local(request, destinations, purpose);
            }
        };
        if admitted == 1 {
            METRICS.observe_email_delivery_admission(
                purpose,
                "admitted",
                if reason == 4 { "source_volume" } else { "none" },
            );
            return Ok(EmailDeliveryReservation {
                backend: ReservationBackend::Redis {
                    redis: redis.clone(),
                    in_flight_key,
                    id,
                    slots: provider_slots,
                },
            });
        }

        let reason = match reason {
            1 => EmailAdmissionRefusal::DestinationCooldown,
            2 => EmailAdmissionRefusal::DestinationVolume,
            3 => EmailAdmissionRefusal::AccountVolume,
            4 => EmailAdmissionRefusal::SourceVolume,
            5 => EmailAdmissionRefusal::GlobalVolume,
            6 => EmailAdmissionRefusal::ProviderCapacity,
            _ => EmailAdmissionRefusal::Unavailable,
        };
        METRICS.observe_email_delivery_admission(purpose, "suppressed", reason.as_str());
        Err(EmailAdmissionDenied { reason })
    }

    fn admit_local(
        &self,
        request: EmailAdmissionRequest<'_>,
        destinations: BTreeSet<String>,
        purpose: &str,
    ) -> Result<EmailDeliveryReservation, EmailAdmissionDenied> {
        let now = Instant::now();
        let divisor = self.config.fallback_instance_divisor;
        let divided = |limit: usize| limit.div_ceil(divisor).max(1);
        let mut state = self
            .local_fallback
            .lock()
            .expect("local email admission lock poisoned");

        state.destinations.retain(|_, events| {
            trim_local(events, now, self.config.destination_window);
            !events.is_empty()
        });
        state.accounts.retain(|_, events| {
            trim_local(events, now, self.config.account_window);
            !events.is_empty()
        });

        for destination in &destinations {
            let key = format!("{purpose}:{destination}");
            let events = state.destinations.entry(key).or_default();
            trim_local(events, now, self.config.destination_window);
            if events
                .back()
                .is_some_and(|last| now.duration_since(*last) < self.config.destination_cooldown)
            {
                return local_denial(purpose, EmailAdmissionRefusal::DestinationCooldown);
            }
            if events.len() >= divided(self.config.destination_limit) {
                return local_denial(purpose, EmailAdmissionRefusal::DestinationVolume);
            }
        }
        if let Some(account) = request.account {
            let account = subject_hash(request.tenant_id, account);
            let events = state.accounts.entry(account).or_default();
            trim_local(events, now, self.config.account_window);
            if events.len() + request.delivery_slots > divided(self.config.account_limit) {
                return local_denial(purpose, EmailAdmissionRefusal::AccountVolume);
            }
        }
        trim_local(&mut state.global, now, self.config.global_window);
        if state.global.len() + request.delivery_slots > divided(self.config.global_limit) {
            return local_denial(purpose, EmailAdmissionRefusal::GlobalVolume);
        }
        if state.in_flight + request.delivery_slots > divided(self.config.provider_in_flight_limit)
        {
            return local_denial(purpose, EmailAdmissionRefusal::ProviderCapacity);
        }

        for destination in destinations {
            state
                .destinations
                .entry(format!("{purpose}:{destination}"))
                .or_default()
                .push_back(now);
        }
        if let Some(account) = request.account {
            let events = state
                .accounts
                .entry(subject_hash(request.tenant_id, account))
                .or_default();
            events.extend(std::iter::repeat_n(now, request.delivery_slots));
        }
        state
            .global
            .extend(std::iter::repeat_n(now, request.delivery_slots));
        state.in_flight += request.delivery_slots;
        METRICS.observe_email_delivery_admission(purpose, "admitted", "local_fallback");
        drop(state);
        Ok(EmailDeliveryReservation {
            backend: ReservationBackend::Local {
                state: self.local_fallback.clone(),
                slots: request.delivery_slots,
            },
        })
    }

    /// Return true only for the first suppressed anonymous request in one destination window.
    pub async fn should_record_anonymous_suppression(
        &self,
        tenant_id: i64,
        purpose: EmailDeliveryPurpose,
        destination: &str,
        reason: EmailAdmissionRefusal,
    ) -> bool {
        let key = format!(
            "email_delivery:{{shared}}:audit:{}:{}:{}",
            purpose.as_str(),
            reason.as_str(),
            subject_hash(tenant_id, destination)
        );
        let redis = match &self.backend {
            AdmissionBackend::Redis(redis) => redis,
            AdmissionBackend::Deny(EmailAdmissionRefusal::Unavailable) => {
                return self.reserve_local_suppression_audit(key);
            }
            AdmissionBackend::Deny(_) => return true,
            AdmissionBackend::Unrestricted => return false,
        };
        let args = vec![self.config.destination_window.as_millis().to_string()];
        match redis
            .invoke_script::<i64>(AUDIT_ONCE_SCRIPT, std::slice::from_ref(&key), &args)
            .await
        {
            Ok(created) => created == 1,
            Err(_) => self.reserve_local_suppression_audit(key),
        }
    }

    fn reserve_local_suppression_audit(&self, key: String) -> bool {
        let now = Instant::now();
        let mut state = self
            .local_fallback
            .lock()
            .expect("local email admission lock poisoned");
        state
            .suppression_audits
            .retain(|_, recorded| now.duration_since(*recorded) < self.config.destination_window);
        if let std::collections::hash_map::Entry::Vacant(entry) =
            state.suppression_audits.entry(key)
        {
            entry.insert(now);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn captured_emails(&self) -> Vec<crate::email_service::CapturedEmail> {
        self.sender.get_captured_emails()
    }

    pub async fn send_verification(
        &self,
        email: &str,
        token: &str,
    ) -> Result<EmailProviderOutcome, EmailSendError> {
        self.run_provider_call(EmailDeliveryPurpose::Verification, async {
            self.sender
                .send_verification_email(email, token, None)
                .await
        })
        .await
    }

    pub async fn send_password_reset(
        &self,
        email: &str,
        token: &str,
    ) -> Result<EmailProviderOutcome, EmailSendError> {
        self.run_provider_call(EmailDeliveryPurpose::PasswordReset, async {
            self.sender.send_password_reset_email(email, token).await
        })
        .await
    }

    pub async fn send_email_change_new(
        &self,
        email: &str,
        token: &str,
    ) -> Result<EmailProviderOutcome, EmailSendError> {
        self.run_provider_call(EmailDeliveryPurpose::EmailChangeNew, async {
            self.sender
                .send_email_change_confirmation(email, token)
                .await
        })
        .await
    }

    pub async fn send_email_change_old(
        &self,
        old_email: &str,
        new_email: &str,
        token: &str,
    ) -> Result<EmailProviderOutcome, EmailSendError> {
        self.run_provider_call(EmailDeliveryPurpose::EmailChangeOld, async {
            self.sender
                .send_email_change_notification(old_email, new_email, token, token)
                .await
        })
        .await
    }

    async fn run_provider_call<F>(
        &self,
        purpose: EmailDeliveryPurpose,
        call: F,
    ) -> Result<EmailProviderOutcome, EmailSendError>
    where
        F: Future<Output = Result<(), EmailSendError>>,
    {
        let Ok(permit) = self.provider_semaphore.clone().try_acquire_owned() else {
            METRICS.observe_email_provider_outcome(
                purpose.as_str(),
                EmailProviderOutcome::Unavailable.as_str(),
                Duration::ZERO,
            );
            return Err(EmailSendError::Unavailable);
        };
        let _in_flight = ProviderInFlightMetric::new();
        let started = Instant::now();
        let result = match tokio::time::timeout(self.config.provider_request_timeout, call).await {
            Ok(result) => result,
            Err(_) => Err(EmailSendError::TimedOut),
        };
        drop(permit);

        let outcome = result
            .as_ref()
            .map(|()| EmailProviderOutcome::Accepted)
            .unwrap_or_else(|error| error.outcome());
        METRICS.observe_email_provider_outcome(
            purpose.as_str(),
            outcome.as_str(),
            started.elapsed(),
        );
        result.map(|()| EmailProviderOutcome::Accepted)
    }
}

fn trim_local(events: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while events
        .front()
        .is_some_and(|event| now.duration_since(*event) >= window)
    {
        events.pop_front();
    }
}

fn local_denial(
    purpose: &str,
    reason: EmailAdmissionRefusal,
) -> Result<EmailDeliveryReservation, EmailAdmissionDenied> {
    METRICS.observe_email_delivery_admission(purpose, "suppressed", reason.as_str());
    Err(EmailAdmissionDenied { reason })
}

struct ProviderInFlightMetric;

impl ProviderInFlightMetric {
    fn new() -> Self {
        METRICS.inc_email_provider_in_flight();
        Self
    }
}

impl Drop for ProviderInFlightMetric {
    fn drop(&mut self) {
        METRICS.dec_email_provider_in_flight();
    }
}

fn subject_hash(tenant_id: i64, subject: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{tenant_id}:{}", subject.trim().to_lowercase()).as_bytes(),
    ))
}

/// Return a coarse source subnet without retaining the request address.
#[must_use]
fn coarse_source(headers: &HeaderMap, trusted_proxy_hops: usize) -> Option<String> {
    let forwarded = headers.get("x-forwarded-for")?.to_str().ok()?;
    // Trusted ingress addresses form a suffix. Values before the selected hop may have been
    // supplied by the caller, so selection must never depend on caller-controlled chain length.
    let candidate = forwarded.split(',').rev().nth(trusted_proxy_hops)?;
    // An unusable trusted suffix disables this secondary control rather than falling back to a
    // potentially caller-controlled header.
    let value = candidate.trim().parse::<IpAddr>().ok()?;
    Some(match value {
        IpAddr::V4(address) => {
            let octets = address.octets();
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0)).to_string()
        }
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            octets[7..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn source_addresses_are_grouped_into_subnets() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.0.2.91".parse().unwrap());
        assert_eq!(coarse_source(&headers, 0).as_deref(), Some("192.0.2.0"));

        headers.insert("x-forwarded-for", "2001:db8:1234:5678::1".parse().unwrap());
        assert_eq!(
            coarse_source(&headers, 0).as_deref(),
            Some("2001:db8:1234:5600::")
        );
    }

    #[test]
    fn source_ignores_caller_supplied_forwarded_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.9, 203.0.113.77".parse().unwrap(),
        );
        headers.insert("x-real-ip", "192.0.2.44".parse().unwrap());

        assert_eq!(coarse_source(&headers, 0).as_deref(), Some("203.0.113.0"));
    }

    #[test]
    fn unusable_trusted_forwarded_hop_does_not_fall_back() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.9, unknown".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.44".parse().unwrap());

        assert_eq!(coarse_source(&headers, 0), None);
    }

    #[test]
    fn source_requires_forwarded_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "192.0.2.44".parse().unwrap());

        assert_eq!(coarse_source(&headers, 0), None);
    }

    struct SlowSender {
        delay: Duration,
        active: AtomicUsize,
        maximum: AtomicUsize,
    }

    impl SlowSender {
        fn new(delay: Duration) -> Self {
            Self {
                delay,
                active: AtomicUsize::new(0),
                maximum: AtomicUsize::new(0),
            }
        }

        async fn send(&self) -> Result<(), EmailSendError> {
            struct ActiveGuard<'a>(&'a AtomicUsize);
            impl Drop for ActiveGuard<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }

            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            let _guard = ActiveGuard(&self.active);
            tokio::time::sleep(self.delay).await;
            Ok(())
        }
    }

    #[async_trait]
    impl EmailSender for SlowSender {
        async fn send_verification_email(
            &self,
            _to_email: &str,
            _verification_token: &str,
            _pin: Option<&str>,
        ) -> Result<(), EmailSendError> {
            self.send().await
        }

        async fn send_password_reset_email(
            &self,
            _to_email: &str,
            _reset_token: &str,
        ) -> Result<(), EmailSendError> {
            self.send().await
        }

        async fn send_claim_email(
            &self,
            _to_email: &str,
            _claim_url: &str,
        ) -> Result<(), EmailSendError> {
            self.send().await
        }

        async fn send_email_change_confirmation(
            &self,
            _to_new_email: &str,
            _confirm_token: &str,
        ) -> Result<(), EmailSendError> {
            self.send().await
        }

        async fn send_email_change_notification(
            &self,
            _to_old_email: &str,
            _new_email: &str,
            _confirm_token: &str,
            _cancel_token: &str,
        ) -> Result<(), EmailSendError> {
            self.send().await
        }
    }

    #[tokio::test]
    async fn provider_deadline_releases_bounded_local_capacity() {
        let sender = Arc::new(SlowSender::new(Duration::from_millis(100)));
        let config = EmailDeliveryConfig {
            provider_in_flight_limit: 1,
            provider_request_timeout: Duration::from_millis(20),
            ..EmailDeliveryConfig::default()
        };
        let service = EmailDeliveryService {
            backend: AdmissionBackend::Unrestricted,
            sender: sender.clone(),
            provider_semaphore: Arc::new(Semaphore::new(1)),
            config,
            local_fallback: Arc::new(Mutex::new(LocalAdmissionState::default())),
        };

        let first_service = service.clone();
        let first = tokio::spawn(async move {
            first_service
                .send_password_reset("first@example.com", "token")
                .await
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            service
                .send_password_reset("second@example.com", "token")
                .await,
            Err(EmailSendError::Unavailable)
        ));
        assert!(matches!(
            first.await.unwrap(),
            Err(EmailSendError::TimedOut)
        ));
        assert!(matches!(
            service
                .send_password_reset("third@example.com", "token")
                .await,
            Err(EmailSendError::TimedOut)
        ));
        assert_eq!(sender.maximum.load(Ordering::SeqCst), 1);
        assert_eq!(sender.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn local_fallback_is_bounded_and_releases_capacity() {
        let sender: Arc<dyn EmailSender> = Arc::new(SlowSender::new(Duration::ZERO));
        let config = EmailDeliveryConfig {
            destination_cooldown: Duration::ZERO,
            destination_limit: 30,
            account_limit: 6,
            global_limit: 30,
            provider_in_flight_limit: 6,
            fallback_instance_divisor: 3,
            ..EmailDeliveryConfig::default()
        };
        let service = EmailDeliveryService {
            backend: AdmissionBackend::Unrestricted,
            sender,
            provider_semaphore: Arc::new(Semaphore::new(6)),
            config,
            local_fallback: Arc::new(Mutex::new(LocalAdmissionState::default())),
        };
        let request = || EmailAdmissionRequest {
            tenant_id: 1,
            purpose: EmailDeliveryPurpose::EmailChange,
            destinations: &["corrected@example.com"],
            account: Some("account"),
            source: Some("192.0.2.0"),
            delivery_slots: 2,
        };

        let reservation = service
            .admit_local(
                request(),
                BTreeSet::from([subject_hash(1, "corrected@example.com")]),
                "email_change",
            )
            .expect("two fallback slots fit the divided per-instance budget");
        let denied = match service.admit_local(
            request(),
            BTreeSet::from([subject_hash(1, "another@example.com")]),
            "email_change",
        ) {
            Ok(_) => panic!("a second two-message change must exceed the local account budget"),
            Err(denied) => denied,
        };
        assert_eq!(denied.reason, EmailAdmissionRefusal::AccountVolume);
        reservation.release().await;
        assert_eq!(service.local_fallback.lock().unwrap().in_flight, 0);
    }

    #[tokio::test]
    async fn unavailable_redis_aggregates_anonymous_suppression_audits_locally() {
        let sender: Arc<dyn EmailSender> = Arc::new(SlowSender::new(Duration::ZERO));
        let service = EmailDeliveryService {
            backend: AdmissionBackend::Deny(EmailAdmissionRefusal::Unavailable),
            sender,
            provider_semaphore: Arc::new(Semaphore::new(1)),
            config: EmailDeliveryConfig::default(),
            local_fallback: Arc::new(Mutex::new(LocalAdmissionState::default())),
        };

        assert!(
            service
                .should_record_anonymous_suppression(
                    1,
                    EmailDeliveryPurpose::PasswordReset,
                    "fallback-audit@example.com",
                    EmailAdmissionRefusal::DestinationCooldown,
                )
                .await
        );
        assert!(
            !service
                .should_record_anonymous_suppression(
                    1,
                    EmailDeliveryPurpose::PasswordReset,
                    "fallback-audit@example.com",
                    EmailAdmissionRefusal::DestinationCooldown,
                )
                .await
        );
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod integration_tests {
    use super::*;
    use crate::email_service::DevEmailSender;
    use redis::aio::ConnectionManager;

    fn refusal(
        result: Result<EmailDeliveryReservation, EmailAdmissionDenied>,
    ) -> EmailAdmissionRefusal {
        match result {
            Ok(_) => panic!("delivery should have been suppressed"),
            Err(denied) => denied.reason,
        }
    }

    async fn services(config: EmailDeliveryConfig) -> (EmailDeliveryService, EmailDeliveryService) {
        let redis_url =
            env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must name the dedicated test Redis");
        let client = redis::Client::open(redis_url).expect("valid Redis URL");
        let first = ConnectionManager::new(client.clone())
            .await
            .expect("first Redis connection");
        let second = ConnectionManager::new(client)
            .await
            .expect("second Redis connection");
        let prefix = format!("keycast-email-delivery-test:{}", Uuid::new_v4());
        let sender: Arc<dyn EmailSender> = Arc::new(DevEmailSender::new());
        (
            EmailDeliveryService::new(
                PrefixedRedis::new(first, Some(prefix.clone())),
                sender.clone(),
                config.clone(),
            ),
            EmailDeliveryService::new(PrefixedRedis::new(second, Some(prefix)), sender, config),
        )
    }

    async fn failing_redis_service(config: EmailDeliveryConfig) -> EmailDeliveryService {
        let redis_url =
            env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must name the dedicated test Redis");
        let client = redis::Client::open(redis_url).expect("valid Redis URL");
        let connection = ConnectionManager::new(client)
            .await
            .expect("fallback test Redis connection");
        EmailDeliveryService::new(
            PrefixedRedis::new_failing_scripts(
                connection,
                Some(format!("keycast-email-fallback-test:{}", Uuid::new_v4())),
            ),
            Arc::new(DevEmailSender::new()),
            config,
        )
    }

    #[tokio::test]
    async fn redis_failure_uses_bounded_local_admission() {
        let service = failing_redis_service(EmailDeliveryConfig {
            destination_cooldown: Duration::ZERO,
            destination_limit: 3,
            fallback_instance_divisor: 3,
            ..EmailDeliveryConfig::default()
        })
        .await;
        let request = |destination| EmailAdmissionRequest {
            tenant_id: 1,
            purpose: EmailDeliveryPurpose::PasswordReset,
            destinations: destination,
            account: None,
            source: Some("192.0.2.0"),
            delivery_slots: 1,
        };
        let first_destination = ["fallback@example.com"];
        let first = service
            .admit(request(&first_destination))
            .await
            .expect("Redis failure degrades to one bounded local delivery");
        first.release().await;
        let denied = service.admit(request(&first_destination)).await;
        assert_eq!(refusal(denied), EmailAdmissionRefusal::DestinationVolume);
    }

    #[tokio::test]
    async fn anonymous_suppression_audit_is_reserved_once_per_window() {
        let (service, _) = services(EmailDeliveryConfig::default()).await;
        assert!(
            service
                .should_record_anonymous_suppression(
                    1,
                    EmailDeliveryPurpose::PasswordReset,
                    "audit@example.com",
                    EmailAdmissionRefusal::DestinationCooldown,
                )
                .await
        );
        assert!(
            !service
                .should_record_anonymous_suppression(
                    1,
                    EmailDeliveryPurpose::PasswordReset,
                    "audit@example.com",
                    EmailAdmissionRefusal::DestinationCooldown,
                )
                .await
        );
    }

    #[tokio::test]
    async fn independent_instances_admit_one_destination_cooldown_winner() {
        let (first, second) = services(EmailDeliveryConfig::default()).await;
        let first_task = tokio::spawn(async move {
            first
                .admit(EmailAdmissionRequest {
                    tenant_id: 1,
                    purpose: EmailDeliveryPurpose::PasswordReset,
                    destinations: &["same@example.com"],
                    account: None,
                    source: Some("192.0.2.0"),
                    delivery_slots: 1,
                })
                .await
        });
        let second_task = tokio::spawn(async move {
            second
                .admit(EmailAdmissionRequest {
                    tenant_id: 1,
                    purpose: EmailDeliveryPurpose::PasswordReset,
                    destinations: &["same@example.com"],
                    account: None,
                    source: Some("192.0.2.0"),
                    delivery_slots: 1,
                })
                .await
        });
        let decisions = [first_task.await.unwrap(), second_task.await.unwrap()];
        assert_eq!(
            decisions.iter().filter(|decision| decision.is_ok()).count(),
            1
        );
        let denied = decisions
            .iter()
            .find_map(|decision| decision.as_ref().err())
            .expect("one request must be suppressed");
        assert_eq!(denied.reason, EmailAdmissionRefusal::DestinationCooldown);
        for reservation in decisions.into_iter().flatten() {
            reservation.release().await;
        }
    }

    #[tokio::test]
    async fn destination_budgets_are_isolated_by_delivery_purpose() {
        let (service, _) = services(EmailDeliveryConfig::default()).await;
        let reset = service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::PasswordReset,
                destinations: &["same@example.com"],
                account: None,
                source: Some("192.0.2.0"),
                delivery_slots: 1,
            })
            .await
            .expect("password reset reservation");
        let verification = service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::Verification,
                destinations: &["same@example.com"],
                account: None,
                source: Some("192.0.2.0"),
                delivery_slots: 1,
            })
            .await
            .expect("verification has an independent destination budget");

        reset.release().await;
        verification.release().await;
    }

    #[tokio::test]
    async fn account_source_signal_and_global_budgets_are_independent() {
        let base = EmailDeliveryConfig {
            destination_cooldown: Duration::ZERO,
            destination_limit: 100,
            account_limit: 1,
            source_limit: 100,
            global_limit: 100,
            ..EmailDeliveryConfig::default()
        };
        let destination_config = EmailDeliveryConfig {
            destination_limit: 1,
            account_limit: 100,
            ..base.clone()
        };
        let (destination_service, _) = services(destination_config).await;
        let first = destination_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::PasswordReset,
                destinations: &["destination-volume@example.com"],
                account: None,
                source: Some("192.0.2.0"),
                delivery_slots: 1,
            })
            .await
            .expect("first destination delivery");
        assert_eq!(
            refusal(
                destination_service
                    .admit(EmailAdmissionRequest {
                        tenant_id: 1,
                        purpose: EmailDeliveryPurpose::PasswordReset,
                        destinations: &["destination-volume@example.com"],
                        account: None,
                        source: Some("192.0.3.0"),
                        delivery_slots: 1,
                    })
                    .await
            ),
            EmailAdmissionRefusal::DestinationVolume
        );
        first.release().await;

        let (account_service, _) = services(base.clone()).await;
        let first = account_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::EmailChange,
                destinations: &["one@example.com"],
                account: Some("account-a"),
                source: Some("192.0.2.0"),
                delivery_slots: 1,
            })
            .await
            .expect("first account delivery");
        assert_eq!(
            refusal(
                account_service
                    .admit(EmailAdmissionRequest {
                        tenant_id: 1,
                        purpose: EmailDeliveryPurpose::EmailChange,
                        destinations: &["two@example.com"],
                        account: Some("account-a"),
                        source: Some("192.0.2.0"),
                        delivery_slots: 1,
                    })
                    .await
            ),
            EmailAdmissionRefusal::AccountVolume
        );
        first.release().await;

        let source_config = EmailDeliveryConfig {
            account_limit: 100,
            source_limit: 2,
            ..base.clone()
        };
        let (source_service, _) = services(source_config).await;
        let first = source_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::Verification,
                destinations: &["three@example.com"],
                account: Some("account-b"),
                source: Some("198.51.100.0"),
                delivery_slots: 1,
            })
            .await
            .expect("first source delivery");
        let second = source_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::Verification,
                destinations: &["four@example.com"],
                account: Some("account-c"),
                source: Some("198.51.100.0"),
                delivery_slots: 1,
            })
            .await
            .expect("second user behind shared source");
        let third = source_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::Verification,
                destinations: &["shared-source-cap@example.com"],
                account: Some("account-d"),
                source: Some("198.51.100.0"),
                delivery_slots: 1,
            })
            .await
            .expect("a shared source is an observation signal, not a recovery denial");
        first.release().await;
        second.release().await;
        third.release().await;

        let global_config = EmailDeliveryConfig {
            source_limit: 100,
            global_limit: 1,
            ..base.clone()
        };
        let (global_service, _) = services(global_config).await;
        let first = global_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::PasswordReset,
                destinations: &["five@example.com"],
                account: None,
                source: Some("203.0.113.0"),
                delivery_slots: 1,
            })
            .await
            .expect("first global delivery");
        assert_eq!(
            refusal(
                global_service
                    .admit(EmailAdmissionRequest {
                        tenant_id: 1,
                        purpose: EmailDeliveryPurpose::PasswordReset,
                        destinations: &["six@example.com"],
                        account: None,
                        source: Some("203.0.114.0"),
                        delivery_slots: 1,
                    })
                    .await
            ),
            EmailAdmissionRefusal::GlobalVolume
        );
        first.release().await;

        let provider_config = EmailDeliveryConfig {
            provider_in_flight_limit: 1,
            source_limit: 100,
            global_limit: 100,
            ..base
        };
        let (provider_service, _) = services(provider_config).await;
        let first = provider_service
            .admit(EmailAdmissionRequest {
                tenant_id: 1,
                purpose: EmailDeliveryPurpose::Verification,
                destinations: &["provider-one@example.com"],
                account: None,
                source: Some("203.0.115.0"),
                delivery_slots: 1,
            })
            .await
            .expect("first provider reservation");
        assert_eq!(
            refusal(
                provider_service
                    .admit(EmailAdmissionRequest {
                        tenant_id: 1,
                        purpose: EmailDeliveryPurpose::Verification,
                        destinations: &["provider-two@example.com"],
                        account: None,
                        source: Some("203.0.116.0"),
                        delivery_slots: 1,
                    })
                    .await
            ),
            EmailAdmissionRefusal::ProviderCapacity
        );
        first.release().await;
    }
}
