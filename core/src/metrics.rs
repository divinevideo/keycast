// ABOUTME: Global metrics counters for Prometheus endpoint
// ABOUTME: Uses atomic counters that can be incremented from signer and read from API

use crate::bcrypt_admission::{BcryptOperation, BcryptWorkload};
use once_cell::sync::Lazy;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

const AUTH_DURATION_BUCKETS: [f64; 8] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
const HTTP_RPC_DURATION_BUCKETS: [f64; 12] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];
const HTTP_RPC_ACQUIRE_BUCKETS: [f64; 9] = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0, 5.0];
const BCRYPT_WORKLOADS: usize = BcryptWorkload::ALL.len();
const BCRYPT_OPERATIONS: usize = BcryptOperation::ALL.len();

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AuthRequestKey {
    endpoint: String,
    outcome: String,
    reason_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AuthDurationKey {
    endpoint: String,
    outcome: String,
}

#[derive(Clone, Debug, Default)]
struct AuthDurationMetric {
    buckets: [u64; AUTH_DURATION_BUCKETS.len()],
    count: u64,
    sum: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct EmailDeliveryKey {
    purpose: String,
    decision: String,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct EmailProviderKey {
    purpose: String,
    outcome: String,
}

#[derive(Clone, Debug, Default)]
struct EmailProviderDurationMetric {
    count: u64,
    sum: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct HttpRpcDurationKey {
    method: String,
    outcome: String,
}

#[derive(Clone, Debug)]
struct HttpRpcDurationMetric {
    buckets: [u64; HTTP_RPC_DURATION_BUCKETS.len()],
    count: u64,
    sum: f64,
}

impl Default for HttpRpcDurationMetric {
    fn default() -> Self {
        Self {
            buckets: [0; HTTP_RPC_DURATION_BUCKETS.len()],
            count: 0,
            sum: 0.0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct HttpRpcAcquireKey {
    operation: String,
    outcome: String,
}

#[derive(Clone, Debug)]
struct HttpRpcAcquireMetric {
    buckets: [u64; HTTP_RPC_ACQUIRE_BUCKETS.len()],
    count: u64,
    sum: f64,
}

impl Default for HttpRpcAcquireMetric {
    fn default() -> Self {
        Self {
            buckets: [0; HTTP_RPC_ACQUIRE_BUCKETS.len()],
            count: 0,
            sum: 0.0,
        }
    }
}

/// Global metrics counters accessible from any crate
pub struct Metrics {
    // === NIP-46 Signer Daemon Metrics ===
    /// Total cache hits - handler was found in LRU cache
    pub cache_hits: AtomicU64,
    /// Total cache misses - handler had to be loaded from DB
    pub cache_misses: AtomicU64,
    /// Current number of handlers in the cache
    pub cache_size: AtomicU64,
    /// Total NIP-46 requests received via relay
    pub nip46_requests_total: AtomicU64,
    /// NIP-46 requests rejected by hashring (not our responsibility)
    pub nip46_requests_rejected_hashring: AtomicU64,
    /// NIP-46 requests rejected by hashring before relay queue admission
    pub nip46_requests_rejected_hashring_prequeue: AtomicU64,
    /// NIP-46 requests rejected by hashring after leaving the relay queue
    pub nip46_requests_rejected_hashring_worker: AtomicU64,
    /// NIP-46 requests where handler was not found
    pub nip46_requests_handler_not_found: AtomicU64,
    /// NIP-46 requests successfully processed
    pub nip46_requests_processed: AtomicU64,
    /// NIP-46 requests dropped due to queue full (overload backpressure)
    pub nip46_requests_queue_dropped: AtomicU64,
    /// NIP-46 requests rejected because the queue was closed (graceful
    /// shutdown). Tracked separately from `queue_dropped` so shutdown-time
    /// rejections are not misread as overload.
    pub nip46_requests_queue_closed: AtomicU64,
    /// NIP-46 tombstone responses sent (revoked/expired authorizations)
    pub nip46_tombstone_responses: AtomicU64,
    /// Approximate relay queue depth after admission and worker receives
    pub nip46_queue_depth: AtomicU64,
    /// Configured relay queue capacity
    pub nip46_queue_capacity: AtomicU64,
    /// Number of observed relay queue wait durations
    pub nip46_queue_wait_count: AtomicU64,
    /// Sum of observed relay queue wait durations in microseconds
    pub nip46_queue_wait_micros: AtomicU64,
    /// Current number of relay workers processing a request
    pub nip46_workers_active: AtomicU64,
    /// Number of observed relay worker processing durations
    pub nip46_worker_duration_count: AtomicU64,
    /// Sum of observed relay worker processing durations in microseconds
    pub nip46_worker_duration_micros: AtomicU64,
    /// Relay requests shed because one target pubkey occupied too much queue capacity
    pub nip46_noisy_target_shed: AtomicU64,
    /// Relay requests shed because one client pubkey occupied too much queue capacity
    pub nip46_noisy_client_shed: AtomicU64,
    /// Current number of cache-miss authorization lookups in flight
    pub nip46_lookup_in_flight: AtomicU64,
    /// Configured cache-miss authorization lookup concurrency limit
    pub nip46_lookup_limit: AtomicU64,
    /// Cache-miss authorization lookups that reached the database/KMS path
    pub nip46_lookup_database_total: AtomicU64,
    /// Cache-miss authorization lookups that failed on a dependency error
    pub nip46_lookup_errors: AtomicU64,
    /// Cache-miss authorization lookups shed because lookup admission was full
    pub nip46_lookup_shed: AtomicU64,
    /// Cache-miss authorization lookup results discarded after invalidation races
    pub nip46_lookup_invalidated: AtomicU64,
    /// Unknown-bunker requests served from the negative lookup cache
    pub nip46_negative_cache_hits: AtomicU64,
    /// Current approximate negative lookup cache entry count
    pub nip46_negative_cache_size: AtomicU64,
    /// Relay activity updates accepted by the coalescing writer
    pub nip46_activity_queued: AtomicU64,
    /// Relay activity updates dropped because the coalescing writer queue was full
    pub nip46_activity_dropped_queue_full: AtomicU64,
    /// Relay activity updates dropped because the coalescing writer had stopped
    pub nip46_activity_dropped_writer_stopped: AtomicU64,
    /// Relay activity updates lost during final shutdown flush
    pub nip46_activity_dropped_shutdown: AtomicU64,
    /// Relay activity updates dropped to keep retained pending IDs bounded
    pub nip46_activity_dropped_retention: AtomicU64,
    /// Failed coalesced relay activity database writes
    pub nip46_activity_write_failures: AtomicU64,
    /// Current retained authorization IDs in the relay activity writer
    pub nip46_activity_pending: AtomicU64,

    // === HTTP RPC Metrics ===
    /// Total HTTP RPC requests
    pub http_rpc_requests_total: AtomicU64,
    /// HTTP RPC cache hits
    pub http_rpc_cache_hits: AtomicU64,
    /// HTTP RPC cache misses
    pub http_rpc_cache_misses: AtomicU64,
    /// HTTP RPC cache size
    pub http_rpc_cache_size: AtomicU64,
    /// HTTP RPC requests successfully processed
    pub http_rpc_success: AtomicU64,
    /// HTTP RPC authorization errors
    pub http_rpc_auth_errors: AtomicU64,
    /// Current SQLx pool size observed by HTTP RPC.
    pub http_rpc_db_pool_size: AtomicU64,
    /// Current SQLx idle connection count observed by HTTP RPC.
    pub http_rpc_db_pool_idle: AtomicU64,
    /// OAuth activity updates that never reached the database: queue full,
    /// writer already stopped, or given up after repeated flush failures.
    pub http_rpc_activity_dropped: AtomicU64,

    // === Auth Metrics ===
    /// Total successful user registrations
    pub registrations_total: AtomicU64,
    /// Total successful logins
    pub logins_total: AtomicU64,
    /// Total failed login attempts (wrong password)
    pub login_failures_total: AtomicU64,
    /// Total account deletions
    pub account_deletions_total: AtomicU64,

    // === OAuth Metrics ===
    /// Total OAuth authorizations created
    pub oauth_authorizations_created: AtomicU64,
    /// Total OAuth authorizations revoked
    pub oauth_authorizations_revoked: AtomicU64,

    // === Bcrypt admission metrics ===
    bcrypt_active: [[AtomicU64; BCRYPT_OPERATIONS]; BCRYPT_WORKLOADS],
    bcrypt_waiting: [[AtomicU64; BCRYPT_OPERATIONS]; BCRYPT_WORKLOADS],
    bcrypt_rejected_capacity: [[AtomicU64; BCRYPT_OPERATIONS]; BCRYPT_WORKLOADS],
    bcrypt_rejected_shutdown: [[AtomicU64; BCRYPT_OPERATIONS]; BCRYPT_WORKLOADS],

    // === Labeled Auth Metrics ===
    auth_requests_total: Mutex<BTreeMap<AuthRequestKey, u64>>,
    auth_request_durations: Mutex<BTreeMap<AuthDurationKey, AuthDurationMetric>>,
    auth_audit_write_failures_total: Mutex<BTreeMap<String, u64>>,
    auth_email_send_failures_total: Mutex<BTreeMap<String, u64>>,
    email_delivery_admissions_total: Mutex<BTreeMap<EmailDeliveryKey, u64>>,
    email_provider_outcomes_total: Mutex<BTreeMap<EmailProviderKey, u64>>,
    email_provider_durations: Mutex<BTreeMap<EmailProviderKey, EmailProviderDurationMetric>>,
    email_provider_in_flight: AtomicU64,
    http_rpc_request_durations: Mutex<BTreeMap<HttpRpcDurationKey, HttpRpcDurationMetric>>,
    http_rpc_status_check_durations: Mutex<BTreeMap<String, HttpRpcDurationMetric>>,
    http_rpc_db_acquire_durations: Mutex<BTreeMap<HttpRpcAcquireKey, HttpRpcAcquireMetric>>,
}

impl Metrics {
    fn new() -> Self {
        Self {
            // NIP-46 metrics
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_size: AtomicU64::new(0),
            nip46_requests_total: AtomicU64::new(0),
            nip46_requests_rejected_hashring: AtomicU64::new(0),
            nip46_requests_rejected_hashring_prequeue: AtomicU64::new(0),
            nip46_requests_rejected_hashring_worker: AtomicU64::new(0),
            nip46_requests_handler_not_found: AtomicU64::new(0),
            nip46_requests_processed: AtomicU64::new(0),
            nip46_requests_queue_dropped: AtomicU64::new(0),
            nip46_requests_queue_closed: AtomicU64::new(0),
            nip46_tombstone_responses: AtomicU64::new(0),
            nip46_queue_depth: AtomicU64::new(0),
            nip46_queue_capacity: AtomicU64::new(0),
            nip46_queue_wait_count: AtomicU64::new(0),
            nip46_queue_wait_micros: AtomicU64::new(0),
            nip46_workers_active: AtomicU64::new(0),
            nip46_worker_duration_count: AtomicU64::new(0),
            nip46_worker_duration_micros: AtomicU64::new(0),
            nip46_noisy_target_shed: AtomicU64::new(0),
            nip46_noisy_client_shed: AtomicU64::new(0),
            nip46_lookup_in_flight: AtomicU64::new(0),
            nip46_lookup_limit: AtomicU64::new(0),
            nip46_lookup_database_total: AtomicU64::new(0),
            nip46_lookup_errors: AtomicU64::new(0),
            nip46_lookup_shed: AtomicU64::new(0),
            nip46_lookup_invalidated: AtomicU64::new(0),
            nip46_negative_cache_hits: AtomicU64::new(0),
            nip46_negative_cache_size: AtomicU64::new(0),
            nip46_activity_queued: AtomicU64::new(0),
            nip46_activity_dropped_queue_full: AtomicU64::new(0),
            nip46_activity_dropped_writer_stopped: AtomicU64::new(0),
            nip46_activity_dropped_shutdown: AtomicU64::new(0),
            nip46_activity_dropped_retention: AtomicU64::new(0),
            nip46_activity_write_failures: AtomicU64::new(0),
            nip46_activity_pending: AtomicU64::new(0),
            // HTTP RPC metrics
            http_rpc_requests_total: AtomicU64::new(0),
            http_rpc_cache_hits: AtomicU64::new(0),
            http_rpc_cache_misses: AtomicU64::new(0),
            http_rpc_cache_size: AtomicU64::new(0),
            http_rpc_success: AtomicU64::new(0),
            http_rpc_auth_errors: AtomicU64::new(0),
            http_rpc_db_pool_size: AtomicU64::new(0),
            http_rpc_db_pool_idle: AtomicU64::new(0),
            http_rpc_activity_dropped: AtomicU64::new(0),
            // Auth metrics
            registrations_total: AtomicU64::new(0),
            logins_total: AtomicU64::new(0),
            login_failures_total: AtomicU64::new(0),
            account_deletions_total: AtomicU64::new(0),
            // OAuth metrics
            oauth_authorizations_created: AtomicU64::new(0),
            oauth_authorizations_revoked: AtomicU64::new(0),
            bcrypt_active: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            bcrypt_waiting: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            bcrypt_rejected_capacity: std::array::from_fn(|_| {
                std::array::from_fn(|_| AtomicU64::new(0))
            }),
            bcrypt_rejected_shutdown: std::array::from_fn(|_| {
                std::array::from_fn(|_| AtomicU64::new(0))
            }),
            // Labeled auth metrics
            auth_requests_total: Mutex::new(BTreeMap::new()),
            auth_request_durations: Mutex::new(BTreeMap::new()),
            auth_audit_write_failures_total: Mutex::new(BTreeMap::new()),
            auth_email_send_failures_total: Mutex::new(BTreeMap::new()),
            email_delivery_admissions_total: Mutex::new(BTreeMap::new()),
            email_provider_outcomes_total: Mutex::new(BTreeMap::new()),
            email_provider_durations: Mutex::new(BTreeMap::new()),
            email_provider_in_flight: AtomicU64::new(0),
            http_rpc_request_durations: Mutex::new(BTreeMap::new()),
            http_rpc_status_check_durations: Mutex::new(BTreeMap::new()),
            http_rpc_db_acquire_durations: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn inc_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_cache_size(&self, size: u64) {
        self.cache_size.store(size, Ordering::Relaxed);
    }

    pub fn inc_nip46_request(&self) {
        self.nip46_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_rejected_hashring(&self) {
        self.nip46_requests_rejected_hashring
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_rejected_hashring_prequeue(&self) {
        self.inc_nip46_rejected_hashring();
        self.nip46_requests_rejected_hashring_prequeue
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_rejected_hashring_worker(&self) {
        self.inc_nip46_rejected_hashring();
        self.nip46_requests_rejected_hashring_worker
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_handler_not_found(&self) {
        self.nip46_requests_handler_not_found
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_processed(&self) {
        self.nip46_requests_processed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_queue_dropped(&self) {
        self.nip46_requests_queue_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_queue_closed(&self) {
        self.nip46_requests_queue_closed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_tombstone_response(&self) {
        self.nip46_tombstone_responses
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_nip46_queue_depth(&self, depth: u64) {
        self.nip46_queue_depth.store(depth, Ordering::Relaxed);
    }

    pub fn set_nip46_queue_capacity(&self, capacity: u64) {
        self.nip46_queue_capacity.store(capacity, Ordering::Relaxed);
    }

    pub fn observe_nip46_queue_wait(&self, duration: Duration) {
        self.nip46_queue_wait_count.fetch_add(1, Ordering::Relaxed);
        self.nip46_queue_wait_micros
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn inc_nip46_workers_active(&self) {
        self.nip46_workers_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_nip46_workers_active(&self) {
        self.nip46_workers_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn observe_nip46_worker_duration(&self, duration: Duration) {
        self.nip46_worker_duration_count
            .fetch_add(1, Ordering::Relaxed);
        self.nip46_worker_duration_micros
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn inc_nip46_noisy_flow_shed(&self, flow: &str) {
        match flow {
            "target" => &self.nip46_noisy_target_shed,
            "client" => &self.nip46_noisy_client_shed,
            _ => return,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_nip46_lookup_limit(&self, limit: u64) {
        self.nip46_lookup_limit.store(limit, Ordering::Relaxed);
    }

    pub fn inc_nip46_lookup_in_flight(&self) {
        self.nip46_lookup_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_nip46_lookup_in_flight(&self) {
        self.nip46_lookup_in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_lookup_database(&self) {
        self.nip46_lookup_database_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_lookup_error(&self) {
        self.nip46_lookup_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_lookup_shed(&self) {
        self.nip46_lookup_shed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_lookup_invalidated(&self) {
        self.nip46_lookup_invalidated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_negative_cache_hit(&self) {
        self.nip46_negative_cache_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_nip46_negative_cache_size(&self, size: u64) {
        self.nip46_negative_cache_size
            .store(size, Ordering::Relaxed);
    }

    pub fn inc_nip46_activity_queued(&self) {
        self.nip46_activity_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nip46_activity_dropped(&self, reason: &str) {
        self.add_nip46_activity_dropped(reason, 1);
    }

    pub fn add_nip46_activity_dropped(&self, reason: &str, count: u64) {
        match reason {
            "queue_full" => &self.nip46_activity_dropped_queue_full,
            "writer_stopped" => &self.nip46_activity_dropped_writer_stopped,
            "shutdown_flush_failed" => &self.nip46_activity_dropped_shutdown,
            "retention_limit" => &self.nip46_activity_dropped_retention,
            _ => return,
        }
        .fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_nip46_activity_write_failure(&self) {
        self.nip46_activity_write_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_nip46_activity_pending(&self, pending: u64) {
        self.nip46_activity_pending
            .store(pending, Ordering::Relaxed);
    }

    // === HTTP RPC metric methods ===

    pub fn inc_http_rpc_request(&self) {
        self.http_rpc_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_http_rpc_cache_hit(&self) {
        self.http_rpc_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_http_rpc_cache_miss(&self) {
        self.http_rpc_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_http_rpc_cache_size(&self, size: u64) {
        self.http_rpc_cache_size.store(size, Ordering::Relaxed);
    }

    pub fn inc_http_rpc_success(&self) {
        self.http_rpc_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_http_rpc_auth_error(&self) {
        self.http_rpc_auth_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_http_rpc_request(&self, method: &str, outcome: &str, duration: Duration) {
        let method = normalize_http_rpc_method(method).to_string();
        let outcome = normalize_http_rpc_outcome(outcome).to_string();
        let mut duration_metrics = self
            .http_rpc_request_durations
            .lock()
            .expect("http rpc duration metrics lock poisoned");
        let metric = duration_metrics
            .entry(HttpRpcDurationKey { method, outcome })
            .or_default();
        observe_http_rpc_duration(metric, duration);
    }

    pub fn observe_http_rpc_status_check(&self, outcome: &str, duration: Duration) {
        let outcome = normalize_http_rpc_outcome(outcome).to_string();
        let mut duration_metrics = self
            .http_rpc_status_check_durations
            .lock()
            .expect("http rpc status check metrics lock poisoned");
        let metric = duration_metrics.entry(outcome).or_default();
        observe_http_rpc_duration(metric, duration);
    }

    pub fn observe_http_rpc_db_acquire(&self, operation: &str, outcome: &str, duration: Duration) {
        let operation = normalize_http_rpc_db_operation(operation).to_string();
        let outcome = normalize_http_rpc_outcome(outcome).to_string();
        let mut duration_metrics = self
            .http_rpc_db_acquire_durations
            .lock()
            .expect("http rpc db acquire metrics lock poisoned");
        let metric = duration_metrics
            .entry(HttpRpcAcquireKey { operation, outcome })
            .or_default();
        observe_http_rpc_acquire_duration(metric, duration);
    }

    pub fn set_http_rpc_db_pool_state(&self, size: u32, idle: u32) {
        self.http_rpc_db_pool_size
            .store(size as u64, Ordering::Relaxed);
        self.http_rpc_db_pool_idle
            .store(idle as u64, Ordering::Relaxed);
    }

    pub fn inc_http_rpc_activity_dropped(&self) {
        self.add_http_rpc_activity_dropped(1);
    }

    pub fn add_http_rpc_activity_dropped(&self, count: u64) {
        self.http_rpc_activity_dropped
            .fetch_add(count, Ordering::Relaxed);
    }

    // === Auth metric methods ===

    pub fn inc_registration(&self) {
        self.registrations_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_login(&self) {
        self.logins_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_login_failure(&self) {
        self.login_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_account_deleted(&self) {
        self.account_deletions_total.fetch_add(1, Ordering::Relaxed);
    }

    // === OAuth metric methods ===

    pub fn inc_oauth_created(&self) {
        self.oauth_authorizations_created
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_oauth_revoked(&self) {
        self.oauth_authorizations_revoked
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_auth_request(
        &self,
        endpoint: &str,
        outcome: &str,
        reason_code: Option<&str>,
        duration: Duration,
    ) {
        let endpoint = normalize_auth_endpoint(endpoint).to_string();
        let outcome = normalize_auth_outcome(outcome).to_string();
        let reason_code = normalize_auth_reason(reason_code).to_string();

        let mut request_totals = self
            .auth_requests_total
            .lock()
            .expect("auth request totals lock poisoned");
        *request_totals
            .entry(AuthRequestKey {
                endpoint: endpoint.clone(),
                outcome: outcome.clone(),
                reason_code,
            })
            .or_insert(0) += 1;
        drop(request_totals);

        let seconds = duration.as_secs_f64();
        let mut duration_metrics = self
            .auth_request_durations
            .lock()
            .expect("auth duration metrics lock poisoned");
        let metric = duration_metrics
            .entry(AuthDurationKey { endpoint, outcome })
            .or_default();
        metric.count += 1;
        metric.sum += seconds;
        for (index, bucket) in AUTH_DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *bucket {
                metric.buckets[index] += 1;
            }
        }
    }

    pub fn inc_auth_audit_write_failure(&self, endpoint: &str) {
        let endpoint = normalize_auth_endpoint(endpoint).to_string();
        let mut failures = self
            .auth_audit_write_failures_total
            .lock()
            .expect("auth audit failures lock poisoned");
        *failures.entry(endpoint).or_insert(0) += 1;
    }

    pub fn inc_auth_email_send_failure(&self, template: &str) {
        let template = normalize_email_template(template).to_string();
        let mut failures = self
            .auth_email_send_failures_total
            .lock()
            .expect("auth email failures lock poisoned");
        *failures.entry(template).or_insert(0) += 1;
    }

    pub fn observe_email_delivery_admission(&self, purpose: &str, decision: &str, reason: &str) {
        let key = EmailDeliveryKey {
            purpose: normalize_email_delivery_purpose(purpose).to_string(),
            decision: normalize_email_admission_decision(decision).to_string(),
            reason: normalize_email_admission_reason(reason).to_string(),
        };
        let mut totals = self
            .email_delivery_admissions_total
            .lock()
            .expect("email delivery admission metrics lock poisoned");
        *totals.entry(key).or_insert(0) += 1;
    }

    pub fn inc_email_provider_in_flight(&self) {
        self.email_provider_in_flight
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_email_provider_in_flight(&self) {
        self.email_provider_in_flight
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn observe_email_provider_outcome(&self, purpose: &str, outcome: &str, duration: Duration) {
        let key = EmailProviderKey {
            purpose: normalize_email_delivery_purpose(purpose).to_string(),
            outcome: normalize_email_provider_outcome(outcome).to_string(),
        };
        let mut outcomes = self
            .email_provider_outcomes_total
            .lock()
            .expect("email provider outcome metrics lock poisoned");
        *outcomes.entry(key.clone()).or_insert(0) += 1;
        drop(outcomes);

        let mut durations = self
            .email_provider_durations
            .lock()
            .expect("email provider duration metrics lock poisoned");
        let metric = durations.entry(key).or_default();
        metric.count += 1;
        metric.sum += duration.as_secs_f64();
    }

    pub fn inc_bcrypt_active(&self, workload: BcryptWorkload, operation: BcryptOperation) {
        self.bcrypt_active[workload.index()][operation.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_bcrypt_active(&self, workload: BcryptWorkload, operation: BcryptOperation) {
        self.bcrypt_active[workload.index()][operation.index()].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_bcrypt_waiting(&self, workload: BcryptWorkload, operation: BcryptOperation) {
        self.bcrypt_waiting[workload.index()][operation.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_bcrypt_waiting(&self, workload: BcryptWorkload, operation: BcryptOperation) {
        self.bcrypt_waiting[workload.index()][operation.index()].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_bcrypt_rejection(
        &self,
        workload: BcryptWorkload,
        operation: BcryptOperation,
        shutting_down: bool,
    ) {
        let metrics = if shutting_down {
            &self.bcrypt_rejected_shutdown
        } else {
            &self.bcrypt_rejected_capacity
        };
        metrics[workload.index()][operation.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Format all metrics as Prometheus text
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Cache metrics
        output.push_str("# HELP keycast_cache_hits_total Authorization handler cache hits (handler found in memory)\n");
        output.push_str("# TYPE keycast_cache_hits_total counter\n");
        output.push_str(&format!(
            "keycast_cache_hits_total {}\n",
            self.cache_hits.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_cache_misses_total Authorization handler cache misses (loaded from DB)\n");
        output.push_str("# TYPE keycast_cache_misses_total counter\n");
        output.push_str(&format!(
            "keycast_cache_misses_total {}\n",
            self.cache_misses.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_cache_size Current number of handlers in LRU cache\n");
        output.push_str("# TYPE keycast_cache_size gauge\n");
        output.push_str(&format!(
            "keycast_cache_size {}\n",
            self.cache_size.load(Ordering::Relaxed)
        ));

        // NIP-46 request metrics
        output.push_str("\n# HELP keycast_nip46_requests_total Total NIP-46 signing requests received via relay\n");
        output.push_str("# TYPE keycast_nip46_requests_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_requests_total {}\n",
            self.nip46_requests_total.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_rejected_hashring_total NIP-46 requests rejected (assigned to different instance)\n");
        output.push_str("# TYPE keycast_nip46_rejected_hashring_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_rejected_hashring_total {}\n",
            self.nip46_requests_rejected_hashring
                .load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_rejected_hashring_prequeue_total Peer-owned NIP-46 requests rejected before local queue admission\n");
        output.push_str("# TYPE keycast_nip46_rejected_hashring_prequeue_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_rejected_hashring_prequeue_total {}\n",
            self.nip46_requests_rejected_hashring_prequeue
                .load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_rejected_hashring_worker_total Queued NIP-46 requests rejected after ownership changed\n");
        output.push_str("# TYPE keycast_nip46_rejected_hashring_worker_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_rejected_hashring_worker_total {}\n",
            self.nip46_requests_rejected_hashring_worker
                .load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_handler_not_found_total NIP-46 requests where authorization was not found\n");
        output.push_str("# TYPE keycast_nip46_handler_not_found_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_handler_not_found_total {}\n",
            self.nip46_requests_handler_not_found
                .load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_nip46_processed_total NIP-46 requests successfully processed\n",
        );
        output.push_str("# TYPE keycast_nip46_processed_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_processed_total {}\n",
            self.nip46_requests_processed.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_queue_dropped_total NIP-46 requests dropped due to queue full (overload backpressure)\n");
        output.push_str("# TYPE keycast_nip46_queue_dropped_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_queue_dropped_total {}\n",
            self.nip46_requests_queue_dropped.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_queue_closed_total NIP-46 requests rejected because the queue was closed (graceful shutdown)\n");
        output.push_str("# TYPE keycast_nip46_queue_closed_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_queue_closed_total {}\n",
            self.nip46_requests_queue_closed.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_tombstone_responses_total NIP-46 error responses sent for revoked/expired authorizations\n");
        output.push_str("# TYPE keycast_nip46_tombstone_responses_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_tombstone_responses_total {}\n",
            self.nip46_tombstone_responses.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_queue_depth Current queued NIP-46 requests\n# TYPE keycast_nip46_queue_depth gauge\n");
        output.push_str(&format!(
            "keycast_nip46_queue_depth {}\n",
            self.nip46_queue_depth.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_queue_capacity Configured NIP-46 queue capacity\n# TYPE keycast_nip46_queue_capacity gauge\n");
        output.push_str(&format!(
            "keycast_nip46_queue_capacity {}\n",
            self.nip46_queue_capacity.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_queue_wait_seconds Time NIP-46 requests spent waiting in the relay queue\n# TYPE keycast_nip46_queue_wait_seconds summary\n");
        output.push_str(&format!(
            "keycast_nip46_queue_wait_seconds_count {}\nkeycast_nip46_queue_wait_seconds_sum {}\n",
            self.nip46_queue_wait_count.load(Ordering::Relaxed),
            self.nip46_queue_wait_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
        ));
        output.push_str("# HELP keycast_nip46_workers_active NIP-46 workers currently processing requests\n# TYPE keycast_nip46_workers_active gauge\n");
        output.push_str(&format!(
            "keycast_nip46_workers_active {}\n",
            self.nip46_workers_active.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_worker_duration_seconds NIP-46 worker processing time\n# TYPE keycast_nip46_worker_duration_seconds summary\n");
        output.push_str(&format!("keycast_nip46_worker_duration_seconds_count {}\nkeycast_nip46_worker_duration_seconds_sum {}\n", self.nip46_worker_duration_count.load(Ordering::Relaxed), self.nip46_worker_duration_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0));
        output.push_str("# HELP keycast_nip46_noisy_flow_shed_total NIP-46 requests shed by bounded flow admission\n# TYPE keycast_nip46_noisy_flow_shed_total counter\n");
        output.push_str(&format!("keycast_nip46_noisy_flow_shed_total{{flow=\"target\"}} {}\nkeycast_nip46_noisy_flow_shed_total{{flow=\"client\"}} {}\n", self.nip46_noisy_target_shed.load(Ordering::Relaxed), self.nip46_noisy_client_shed.load(Ordering::Relaxed)));
        output.push_str("# HELP keycast_nip46_lookup_in_flight Authorization lookups currently using a database admission permit\n# TYPE keycast_nip46_lookup_in_flight gauge\n");
        output.push_str(&format!(
            "keycast_nip46_lookup_in_flight {}\n",
            self.nip46_lookup_in_flight.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_lookup_limit Configured concurrent NIP-46 authorization lookup limit\n# TYPE keycast_nip46_lookup_limit gauge\n");
        output.push_str(&format!(
            "keycast_nip46_lookup_limit {}\n",
            self.nip46_lookup_limit.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_lookup_database_total Coalesced NIP-46 authorization database lookups\n# TYPE keycast_nip46_lookup_database_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_lookup_database_total {}\n",
            self.nip46_lookup_database_total.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_lookup_errors_total NIP-46 authorization lookup dependency failures\n# TYPE keycast_nip46_lookup_errors_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_lookup_errors_total {}\n",
            self.nip46_lookup_errors.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_lookup_shed_total NIP-46 cache misses shed because lookup admission was full\n# TYPE keycast_nip46_lookup_shed_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_lookup_shed_total {}\n",
            self.nip46_lookup_shed.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_lookup_invalidated_total NIP-46 lookup results discarded after concurrent authorization changes\n# TYPE keycast_nip46_lookup_invalidated_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_lookup_invalidated_total {}\n",
            self.nip46_lookup_invalidated.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_negative_cache_hits_total NIP-46 unknown-target requests answered by the negative cache\n# TYPE keycast_nip46_negative_cache_hits_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_negative_cache_hits_total {}\n",
            self.nip46_negative_cache_hits.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_negative_cache_size Current cached unknown NIP-46 targets\n# TYPE keycast_nip46_negative_cache_size gauge\n");
        output.push_str(&format!(
            "keycast_nip46_negative_cache_size {}\n",
            self.nip46_negative_cache_size.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_activity_queued_total NIP-46 activity events accepted by the coalescing writer\n# TYPE keycast_nip46_activity_queued_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_activity_queued_total {}\n",
            self.nip46_activity_queued.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_activity_dropped_total NIP-46 activity events lost at a bounded writer boundary\n# TYPE keycast_nip46_activity_dropped_total counter\n");
        output.push_str(&format!("keycast_nip46_activity_dropped_total{{reason=\"queue_full\"}} {}\nkeycast_nip46_activity_dropped_total{{reason=\"writer_stopped\"}} {}\nkeycast_nip46_activity_dropped_total{{reason=\"shutdown_flush_failed\"}} {}\nkeycast_nip46_activity_dropped_total{{reason=\"retention_limit\"}} {}\n", self.nip46_activity_dropped_queue_full.load(Ordering::Relaxed), self.nip46_activity_dropped_writer_stopped.load(Ordering::Relaxed), self.nip46_activity_dropped_shutdown.load(Ordering::Relaxed), self.nip46_activity_dropped_retention.load(Ordering::Relaxed)));
        output.push_str("# HELP keycast_nip46_activity_write_failures_total Failed coalesced NIP-46 activity database writes\n# TYPE keycast_nip46_activity_write_failures_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_activity_write_failures_total {}\n",
            self.nip46_activity_write_failures.load(Ordering::Relaxed)
        ));
        output.push_str("# HELP keycast_nip46_activity_pending Authorization IDs retained by the NIP-46 activity writer\n# TYPE keycast_nip46_activity_pending gauge\n");
        output.push_str(&format!(
            "keycast_nip46_activity_pending {}\n",
            self.nip46_activity_pending.load(Ordering::Relaxed)
        ));

        // HTTP RPC metrics
        output.push_str(
            "\n# HELP keycast_http_rpc_requests_total Total HTTP RPC requests to /api/nostr\n",
        );
        output.push_str("# TYPE keycast_http_rpc_requests_total counter\n");
        output.push_str(&format!(
            "keycast_http_rpc_requests_total {}\n",
            self.http_rpc_requests_total.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_http_rpc_cache_hits_total HTTP RPC handler cache hits\n");
        output.push_str("# TYPE keycast_http_rpc_cache_hits_total counter\n");
        output.push_str(&format!(
            "keycast_http_rpc_cache_hits_total {}\n",
            self.http_rpc_cache_hits.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_http_rpc_cache_misses_total HTTP RPC handler cache misses\n",
        );
        output.push_str("# TYPE keycast_http_rpc_cache_misses_total counter\n");
        output.push_str(&format!(
            "keycast_http_rpc_cache_misses_total {}\n",
            self.http_rpc_cache_misses.load(Ordering::Relaxed)
        ));

        output
            .push_str("\n# HELP keycast_http_rpc_cache_size Current HTTP RPC handler cache size\n");
        output.push_str("# TYPE keycast_http_rpc_cache_size gauge\n");
        output.push_str(&format!(
            "keycast_http_rpc_cache_size {}\n",
            self.http_rpc_cache_size.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_http_rpc_success_total HTTP RPC requests successfully processed\n",
        );
        output.push_str("# TYPE keycast_http_rpc_success_total counter\n");
        output.push_str(&format!(
            "keycast_http_rpc_success_total {}\n",
            self.http_rpc_success.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_http_rpc_auth_errors_total HTTP RPC authorization errors\n",
        );
        output.push_str("# TYPE keycast_http_rpc_auth_errors_total counter\n");
        output.push_str(&format!(
            "keycast_http_rpc_auth_errors_total {}\n",
            self.http_rpc_auth_errors.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_http_rpc_request_duration_seconds HTTP RPC request latency by method and outcome\n",
        );
        output.push_str("# TYPE keycast_http_rpc_request_duration_seconds histogram\n");
        for (key, metric) in self
            .http_rpc_request_durations
            .lock()
            .expect("http rpc duration metrics lock poisoned")
            .iter()
        {
            for (index, bucket) in HTTP_RPC_DURATION_BUCKETS.iter().enumerate() {
                output.push_str(&format!(
                    "keycast_http_rpc_request_duration_seconds_bucket{{method=\"{}\",outcome=\"{}\",le=\"{}\"}} {}\n",
                    key.method, key.outcome, bucket, metric.buckets[index]
                ));
            }
            output.push_str(&format!(
                "keycast_http_rpc_request_duration_seconds_bucket{{method=\"{}\",outcome=\"{}\",le=\"+Inf\"}} {}\n",
                key.method, key.outcome, metric.count
            ));
            output.push_str(&format!(
                "keycast_http_rpc_request_duration_seconds_sum{{method=\"{}\",outcome=\"{}\"}} {}\n",
                key.method, key.outcome, metric.sum
            ));
            output.push_str(&format!(
                "keycast_http_rpc_request_duration_seconds_count{{method=\"{}\",outcome=\"{}\"}} {}\n",
                key.method, key.outcome, metric.count
            ));
        }

        output.push_str(
            "\n# HELP keycast_http_rpc_status_check_duration_seconds HTTP RPC live user status check latency by outcome\n",
        );
        output.push_str("# TYPE keycast_http_rpc_status_check_duration_seconds histogram\n");
        for (outcome, metric) in self
            .http_rpc_status_check_durations
            .lock()
            .expect("http rpc status check metrics lock poisoned")
            .iter()
        {
            for (index, bucket) in HTTP_RPC_DURATION_BUCKETS.iter().enumerate() {
                output.push_str(&format!(
                    "keycast_http_rpc_status_check_duration_seconds_bucket{{outcome=\"{}\",le=\"{}\"}} {}\n",
                    outcome, bucket, metric.buckets[index]
                ));
            }
            output.push_str(&format!(
                "keycast_http_rpc_status_check_duration_seconds_bucket{{outcome=\"{}\",le=\"+Inf\"}} {}\n",
                outcome, metric.count
            ));
            output.push_str(&format!(
                "keycast_http_rpc_status_check_duration_seconds_sum{{outcome=\"{}\"}} {}\n",
                outcome, metric.sum
            ));
            output.push_str(&format!(
                "keycast_http_rpc_status_check_duration_seconds_count{{outcome=\"{}\"}} {}\n",
                outcome, metric.count
            ));
        }

        output.push_str(
            "\n# HELP keycast_http_rpc_db_acquire_duration_seconds HTTP RPC DB acquire wait by operation and outcome\n",
        );
        output.push_str("# TYPE keycast_http_rpc_db_acquire_duration_seconds histogram\n");
        for (key, metric) in self
            .http_rpc_db_acquire_durations
            .lock()
            .expect("http rpc db acquire metrics lock poisoned")
            .iter()
        {
            for (index, bucket) in HTTP_RPC_ACQUIRE_BUCKETS.iter().enumerate() {
                output.push_str(&format!(
                    "keycast_http_rpc_db_acquire_duration_seconds_bucket{{operation=\"{}\",outcome=\"{}\",le=\"{}\"}} {}\n",
                    key.operation, key.outcome, bucket, metric.buckets[index]
                ));
            }
            output.push_str(&format!(
                "keycast_http_rpc_db_acquire_duration_seconds_bucket{{operation=\"{}\",outcome=\"{}\",le=\"+Inf\"}} {}\n",
                key.operation, key.outcome, metric.count
            ));
            output.push_str(&format!(
                "keycast_http_rpc_db_acquire_duration_seconds_sum{{operation=\"{}\",outcome=\"{}\"}} {}\n",
                key.operation, key.outcome, metric.sum
            ));
            output.push_str(&format!(
                "keycast_http_rpc_db_acquire_duration_seconds_count{{operation=\"{}\",outcome=\"{}\"}} {}\n",
                key.operation, key.outcome, metric.count
            ));
        }

        output.push_str(
            "\n# HELP keycast_http_rpc_db_pool_size Current SQLx pool size observed by HTTP RPC\n",
        );
        output.push_str("# TYPE keycast_http_rpc_db_pool_size gauge\n");
        output.push_str(&format!(
            "keycast_http_rpc_db_pool_size {}\n",
            self.http_rpc_db_pool_size.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_http_rpc_db_pool_idle Current SQLx idle connection count observed by HTTP RPC\n",
        );
        output.push_str("# TYPE keycast_http_rpc_db_pool_idle gauge\n");
        output.push_str(&format!(
            "keycast_http_rpc_db_pool_idle {}\n",
            self.http_rpc_db_pool_idle.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_http_rpc_activity_dropped_total OAuth activity updates that never reached the database (queue full, writer stopped, or given up after repeated flush failures)\n",
        );
        output.push_str("# TYPE keycast_http_rpc_activity_dropped_total counter\n");
        output.push_str(&format!(
            "keycast_http_rpc_activity_dropped_total {}\n",
            self.http_rpc_activity_dropped.load(Ordering::Relaxed)
        ));

        // Auth metrics
        output
            .push_str("\n# HELP keycast_registrations_total Total successful user registrations\n");
        output.push_str("# TYPE keycast_registrations_total counter\n");
        output.push_str(&format!(
            "keycast_registrations_total {}\n",
            self.registrations_total.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_logins_total Total successful logins\n");
        output.push_str("# TYPE keycast_logins_total counter\n");
        output.push_str(&format!(
            "keycast_logins_total {}\n",
            self.logins_total.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_login_failures_total Total failed login attempts\n");
        output.push_str("# TYPE keycast_login_failures_total counter\n");
        output.push_str(&format!(
            "keycast_login_failures_total {}\n",
            self.login_failures_total.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_account_deletions_total Total account deletions\n");
        output.push_str("# TYPE keycast_account_deletions_total counter\n");
        output.push_str(&format!(
            "keycast_account_deletions_total {}\n",
            self.account_deletions_total.load(Ordering::Relaxed)
        ));

        // OAuth metrics
        output.push_str(
            "\n# HELP keycast_oauth_authorizations_created_total Total OAuth authorizations created\n",
        );
        output.push_str("# TYPE keycast_oauth_authorizations_created_total counter\n");
        output.push_str(&format!(
            "keycast_oauth_authorizations_created_total {}\n",
            self.oauth_authorizations_created.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_oauth_authorizations_revoked_total Total OAuth authorizations revoked\n",
        );
        output.push_str("# TYPE keycast_oauth_authorizations_revoked_total counter\n");
        output.push_str(&format!(
            "keycast_oauth_authorizations_revoked_total {}\n",
            self.oauth_authorizations_revoked.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_bcrypt_active_work Current bcrypt operations running on blocking workers\n",
        );
        output.push_str("# TYPE keycast_bcrypt_active_work gauge\n");
        output.push_str(
            "# HELP keycast_bcrypt_waiting_work Current bcrypt operations waiting for CPU admission\n",
        );
        output.push_str("# TYPE keycast_bcrypt_waiting_work gauge\n");
        output.push_str(
            "# HELP keycast_bcrypt_admission_rejections_total Bcrypt operations rejected before blocking execution\n",
        );
        output.push_str("# TYPE keycast_bcrypt_admission_rejections_total counter\n");
        for workload in BcryptWorkload::ALL {
            for operation in BcryptOperation::ALL {
                let workload_index = workload.index();
                let operation_index = operation.index();
                output.push_str(&format!(
                    "keycast_bcrypt_active_work{{workload=\"{}\",operation=\"{}\"}} {}\n",
                    workload.as_str(),
                    operation.as_str(),
                    self.bcrypt_active[workload_index][operation_index].load(Ordering::Relaxed)
                ));
                output.push_str(&format!(
                    "keycast_bcrypt_waiting_work{{workload=\"{}\",operation=\"{}\"}} {}\n",
                    workload.as_str(),
                    operation.as_str(),
                    self.bcrypt_waiting[workload_index][operation_index].load(Ordering::Relaxed)
                ));
                for (reason, metrics) in [
                    ("capacity", &self.bcrypt_rejected_capacity),
                    ("shutdown", &self.bcrypt_rejected_shutdown),
                ] {
                    output.push_str(&format!(
                        "keycast_bcrypt_admission_rejections_total{{workload=\"{}\",operation=\"{}\",reason=\"{}\"}} {}\n",
                        workload.as_str(),
                        operation.as_str(),
                        reason,
                        metrics[workload_index][operation_index].load(Ordering::Relaxed)
                    ));
                }
            }
        }

        output.push_str(
            "\n# HELP keycast_auth_requests_total Auth request outcomes by endpoint and reason\n",
        );
        output.push_str("# TYPE keycast_auth_requests_total counter\n");
        for (key, count) in self
            .auth_requests_total
            .lock()
            .expect("auth request totals lock poisoned")
            .iter()
        {
            output.push_str(&format!(
                "keycast_auth_requests_total{{endpoint=\"{}\",outcome=\"{}\",reason_code=\"{}\"}} {}\n",
                key.endpoint, key.outcome, key.reason_code, count
            ));
        }

        output.push_str(
            "\n# HELP keycast_auth_request_duration_seconds Auth request latency by endpoint and outcome\n",
        );
        output.push_str("# TYPE keycast_auth_request_duration_seconds histogram\n");
        for (key, metric) in self
            .auth_request_durations
            .lock()
            .expect("auth duration metrics lock poisoned")
            .iter()
        {
            for (index, bucket) in AUTH_DURATION_BUCKETS.iter().enumerate() {
                output.push_str(&format!(
                    "keycast_auth_request_duration_seconds_bucket{{endpoint=\"{}\",outcome=\"{}\",le=\"{}\"}} {}\n",
                    key.endpoint, key.outcome, bucket, metric.buckets[index]
                ));
            }
            output.push_str(&format!(
                "keycast_auth_request_duration_seconds_bucket{{endpoint=\"{}\",outcome=\"{}\",le=\"+Inf\"}} {}\n",
                key.endpoint, key.outcome, metric.count
            ));
            output.push_str(&format!(
                "keycast_auth_request_duration_seconds_sum{{endpoint=\"{}\",outcome=\"{}\"}} {}\n",
                key.endpoint, key.outcome, metric.sum
            ));
            output.push_str(&format!(
                "keycast_auth_request_duration_seconds_count{{endpoint=\"{}\",outcome=\"{}\"}} {}\n",
                key.endpoint, key.outcome, metric.count
            ));
        }

        output.push_str(
            "\n# HELP keycast_auth_audit_write_failures_total Auth audit writes that failed but did not fail the user request\n",
        );
        output.push_str("# TYPE keycast_auth_audit_write_failures_total counter\n");
        for (endpoint, count) in self
            .auth_audit_write_failures_total
            .lock()
            .expect("auth audit failures lock poisoned")
            .iter()
        {
            output.push_str(&format!(
                "keycast_auth_audit_write_failures_total{{endpoint=\"{}\"}} {}\n",
                endpoint, count
            ));
        }

        output.push_str(
            "\n# HELP keycast_auth_email_send_failures_total Auth email send failures by template\n",
        );
        output.push_str("# TYPE keycast_auth_email_send_failures_total counter\n");
        for (template, count) in self
            .auth_email_send_failures_total
            .lock()
            .expect("auth email failures lock poisoned")
            .iter()
        {
            output.push_str(&format!(
                "keycast_auth_email_send_failures_total{{template=\"{}\"}} {}\n",
                template, count
            ));
        }

        output.push_str(
            "\n# HELP keycast_email_delivery_admissions_total Email delivery admission decisions\n",
        );
        output.push_str("# TYPE keycast_email_delivery_admissions_total counter\n");
        for (key, count) in self
            .email_delivery_admissions_total
            .lock()
            .expect("email delivery admission metrics lock poisoned")
            .iter()
        {
            output.push_str(&format!(
                "keycast_email_delivery_admissions_total{{purpose=\"{}\",decision=\"{}\",reason=\"{}\"}} {}\n",
                key.purpose, key.decision, key.reason, count
            ));
        }

        output.push_str(
            "\n# HELP keycast_email_provider_in_flight Email provider calls currently in flight\n",
        );
        output.push_str("# TYPE keycast_email_provider_in_flight gauge\n");
        output.push_str(&format!(
            "keycast_email_provider_in_flight {}\n",
            self.email_provider_in_flight.load(Ordering::Relaxed)
        ));

        output.push_str(
            "\n# HELP keycast_email_provider_outcomes_total Terminal email provider outcomes\n",
        );
        output.push_str("# TYPE keycast_email_provider_outcomes_total counter\n");
        for (key, count) in self
            .email_provider_outcomes_total
            .lock()
            .expect("email provider outcome metrics lock poisoned")
            .iter()
        {
            output.push_str(&format!(
                "keycast_email_provider_outcomes_total{{purpose=\"{}\",outcome=\"{}\"}} {}\n",
                key.purpose, key.outcome, count
            ));
        }

        output.push_str(
            "\n# HELP keycast_email_provider_duration_seconds Email provider call latency\n",
        );
        output.push_str("# TYPE keycast_email_provider_duration_seconds summary\n");
        for (key, metric) in self
            .email_provider_durations
            .lock()
            .expect("email provider duration metrics lock poisoned")
            .iter()
        {
            output.push_str(&format!(
                "keycast_email_provider_duration_seconds_sum{{purpose=\"{}\",outcome=\"{}\"}} {}\n",
                key.purpose, key.outcome, metric.sum
            ));
            output.push_str(&format!(
                "keycast_email_provider_duration_seconds_count{{purpose=\"{}\",outcome=\"{}\"}} {}\n",
                key.purpose, key.outcome, metric.count
            ));
        }

        output
    }
}

fn observe_http_rpc_duration(metric: &mut HttpRpcDurationMetric, duration: Duration) {
    let seconds = duration.as_secs_f64();
    metric.count += 1;
    metric.sum += seconds;
    for (index, bucket) in HTTP_RPC_DURATION_BUCKETS.iter().enumerate() {
        if seconds <= *bucket {
            metric.buckets[index] += 1;
        }
    }
}

fn observe_http_rpc_acquire_duration(metric: &mut HttpRpcAcquireMetric, duration: Duration) {
    let seconds = duration.as_secs_f64();
    metric.count += 1;
    metric.sum += seconds;
    for (index, bucket) in HTTP_RPC_ACQUIRE_BUCKETS.iter().enumerate() {
        if seconds <= *bucket {
            metric.buckets[index] += 1;
        }
    }
}

fn normalize_http_rpc_method(method: &str) -> &'static str {
    match method {
        "get_public_key" => "get_public_key",
        "sign_event" => "sign_event",
        "nip04_encrypt" => "nip04_encrypt",
        "nip04_decrypt" => "nip04_decrypt",
        "nip44_encrypt" => "nip44_encrypt",
        "nip44_decrypt" => "nip44_decrypt",
        "nip17_unwrap_batch" => "nip17_unwrap_batch",
        "nip17_wrap_batch" => "nip17_wrap_batch",
        _ => "unsupported",
    }
}

fn normalize_http_rpc_outcome(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "auth_error" => "auth_error",
        "client_error" => "client_error",
        "account_restricted" => "account_restricted",
        "unavailable" => "unavailable",
        "timeout" => "timeout",
        "error" => "error",
        _ => "other",
    }
}

fn normalize_http_rpc_db_operation(operation: &str) -> &'static str {
    match operation {
        "check_user_status_active" => "check_user_status_active",
        _ => "other",
    }
}

fn normalize_auth_endpoint(endpoint: &str) -> &'static str {
    match endpoint {
        "/api/auth/register" => "/api/auth/register",
        "/api/auth/login" => "/api/auth/login",
        "/api/auth/verify-email" => "/api/auth/verify-email",
        "/api/auth/forgot-password" => "/api/auth/forgot-password",
        "/api/auth/reset-password" => "/api/auth/reset-password",
        "/api/auth/resend-verification" => "/api/auth/resend-verification",
        "/api/user/change-email" => "/api/user/change-email",
        "/api/auth/confirm-email-change" => "/api/auth/confirm-email-change",
        "/api/auth/cancel-email-change" => "/api/auth/cancel-email-change",
        "/api/oauth/login" => "/api/oauth/login",
        "/api/oauth/register" => "/api/oauth/register",
        "/api/oauth/authorize" => "/api/oauth/authorize",
        "/api/oauth/token" => "/api/oauth/token",
        "/api/oauth/poll" => "/api/oauth/poll",
        "/api/oauth/connect" => "/api/oauth/connect",
        "/api/headless/register" => "/api/headless/register",
        "/api/headless/login" => "/api/headless/login",
        "/api/headless/authorize" => "/api/headless/authorize",
        "/api/claim" => "/api/claim",
        "/api/admin/auth-debug" => "/api/admin/auth-debug",
        "/api/user/export-key" => "/api/user/export-key",
        "/api/user/change-key" => "/api/user/change-key",
        _ => "other",
    }
}

fn normalize_auth_outcome(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "failure" => "failure",
        "accepted" => "accepted",
        "admitted" => "admitted",
        "suppressed" => "suppressed",
        "error" => "error",
        _ => "other",
    }
}

fn normalize_auth_reason(reason_code: Option<&str>) -> &'static str {
    match reason_code.unwrap_or("none") {
        "none" => "none",
        "user_not_found" => "user_not_found",
        "invalid_password" => "invalid_password",
        "invalid_credentials" => "invalid_credentials",
        "email_not_verified" => "email_not_verified",
        "invalid_request" => "invalid_request",
        "invalid_token" => "invalid_token",
        "token_expired" => "token_expired",
        "conflict" => "conflict",
        "email_send_failed" => "email_send_failed",
        "service_unavailable" => "service_unavailable",
        "account_setup_incomplete" => "account_setup_incomplete",
        "missing_personal_key" => "missing_personal_key",
        "password_hash_updated" => "password_hash_updated",
        "unsupported_client" => "unsupported_client",
        "authorization_not_found" => "authorization_not_found",
        "policy_denied" => "policy_denied",
        "rate_limited" => "rate_limited",
        "missing_password" => "missing_password",
        "invalid_format" => "invalid_format",
        "invalid_nsec" => "invalid_nsec",
        "duplicate_key" => "duplicate_key",
        "encryption_failed" => "encryption_failed",
        "change_key_failed" => "change_key_failed",
        "destination_cooldown" => "destination_cooldown",
        "destination_volume" => "destination_volume",
        "account_volume" => "account_volume",
        "source_volume" => "source_volume",
        "global_volume" => "global_volume",
        "provider_capacity" => "provider_capacity",
        "admission_unavailable" => "admission_unavailable",
        "accepted" => "accepted",
        "rejected" => "rejected",
        "timed_out" => "timed_out",
        "unavailable" => "unavailable",
        "wrong_password" => "wrong_password",
        "invalid_email" => "invalid_email",
        "email_already_registered" => "email_already_registered",
        "finalized" => "finalized",
        "cancelled" => "cancelled",
        _ => "other",
    }
}

fn normalize_email_template(template: &str) -> &'static str {
    match template {
        "verification" => "verification",
        "password_reset" => "password_reset",
        "resend_verification" => "resend_verification",
        "email_change_new" => "email_change_new",
        "email_change_old" => "email_change_old",
        _ => "other",
    }
}

fn normalize_email_delivery_purpose(purpose: &str) -> &'static str {
    match purpose {
        "password_reset" => "password_reset",
        "verification" => "verification",
        "email_change" => "email_change",
        "email_change_new" => "email_change_new",
        "email_change_old" => "email_change_old",
        _ => "other",
    }
}

fn normalize_email_admission_decision(decision: &str) -> &'static str {
    match decision {
        "admitted" => "admitted",
        "suppressed" => "suppressed",
        _ => "other",
    }
}

fn normalize_email_admission_reason(reason: &str) -> &'static str {
    match reason {
        "none" => "none",
        "destination_cooldown" => "destination_cooldown",
        "destination_volume" => "destination_volume",
        "account_volume" => "account_volume",
        "source_volume" => "source_volume",
        "global_volume" => "global_volume",
        "provider_capacity" => "provider_capacity",
        "admission_unavailable" => "admission_unavailable",
        _ => "other",
    }
}

fn normalize_email_provider_outcome(outcome: &str) -> &'static str {
    match outcome {
        "accepted" => "accepted",
        "rejected" => "rejected",
        "rate_limited" => "rate_limited",
        "timed_out" => "timed_out",
        "unavailable" => "unavailable",
        _ => "other",
    }
}

/// Global metrics instance
pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

#[cfg(test)]
mod tests {
    use super::Metrics;
    use crate::bcrypt_admission::{BcryptOperation, BcryptWorkload};
    use std::time::Duration;

    #[test]
    fn test_auth_labeled_metrics_render_prometheus_series() {
        let metrics = Metrics::new();

        metrics.observe_auth_request(
            "/api/headless/login",
            "failure",
            Some("user_not_found"),
            Duration::from_millis(120),
        );
        metrics.inc_auth_audit_write_failure("/api/headless/login");
        metrics.inc_auth_email_send_failure("password_reset");
        metrics.observe_email_delivery_admission("email_change", "suppressed", "account_volume");
        metrics.inc_email_provider_in_flight();
        metrics.observe_email_provider_outcome(
            "email_change_new",
            "timed_out",
            Duration::from_millis(250),
        );
        metrics.dec_email_provider_in_flight();

        let output = metrics.to_prometheus();

        assert!(output.contains(
            "keycast_auth_requests_total{endpoint=\"/api/headless/login\",outcome=\"failure\",reason_code=\"user_not_found\"} 1"
        ));
        assert!(output.contains(
            "keycast_auth_request_duration_seconds_bucket{endpoint=\"/api/headless/login\",outcome=\"failure\",le=\"0.25\"} 1"
        ));
        assert!(output.contains(
            "keycast_auth_request_duration_seconds_count{endpoint=\"/api/headless/login\",outcome=\"failure\"} 1"
        ));
        assert!(output.contains(
            "keycast_auth_audit_write_failures_total{endpoint=\"/api/headless/login\"} 1"
        ));
        assert!(output
            .contains("keycast_auth_email_send_failures_total{template=\"password_reset\"} 1"));
        assert!(output.contains(
            "keycast_email_delivery_admissions_total{purpose=\"email_change\",decision=\"suppressed\",reason=\"account_volume\"} 1"
        ));
        assert!(output.contains("keycast_email_provider_in_flight 0"));
        assert!(output.contains(
            "keycast_email_provider_outcomes_total{purpose=\"email_change_new\",outcome=\"timed_out\"} 1"
        ));
        assert!(output.contains(
            "keycast_email_provider_duration_seconds_count{purpose=\"email_change_new\",outcome=\"timed_out\"} 1"
        ));
    }

    #[test]
    fn test_http_rpc_labeled_metrics_render_long_tail_buckets() {
        let metrics = Metrics::new();

        metrics.observe_http_rpc_request("nip44_encrypt", "success", Duration::from_secs(23));
        metrics.observe_http_rpc_status_check("success", Duration::from_millis(25));
        metrics.observe_http_rpc_db_acquire(
            "check_user_status_active",
            "success",
            Duration::from_millis(20),
        );
        metrics.set_http_rpc_db_pool_state(50, 2);
        metrics.inc_http_rpc_activity_dropped();

        let output = metrics.to_prometheus();

        assert!(output.contains(
            "keycast_http_rpc_request_duration_seconds_bucket{method=\"nip44_encrypt\",outcome=\"success\",le=\"30\"} 1"
        ));
        assert!(output.contains(
            "keycast_http_rpc_request_duration_seconds_bucket{method=\"nip44_encrypt\",outcome=\"success\",le=\"10\"} 0"
        ));
        assert!(output.contains(
            "keycast_http_rpc_status_check_duration_seconds_count{outcome=\"success\"} 1"
        ));
        assert!(output.contains(
            "keycast_http_rpc_db_acquire_duration_seconds_count{operation=\"check_user_status_active\",outcome=\"success\"} 1"
        ));
        assert!(output.contains("keycast_http_rpc_db_pool_size 50"));
        assert!(output.contains("keycast_http_rpc_db_pool_idle 2"));
        assert!(output.contains("keycast_http_rpc_activity_dropped_total 1"));
    }

    #[test]
    fn nip46_overload_metrics_render_each_shedding_reason() {
        let metrics = Metrics::new();
        metrics.inc_nip46_noisy_flow_shed("target");
        metrics.inc_nip46_noisy_flow_shed("client");
        metrics.inc_nip46_rejected_hashring_prequeue();
        metrics.inc_nip46_rejected_hashring_worker();
        metrics.inc_queue_dropped();
        metrics.inc_queue_closed();
        metrics.inc_nip46_lookup_database();
        metrics.inc_nip46_lookup_error();
        metrics.inc_nip46_lookup_shed();
        metrics.inc_nip46_lookup_invalidated();
        metrics.inc_nip46_negative_cache_hit();
        metrics.inc_nip46_activity_dropped("queue_full");
        metrics.inc_nip46_activity_dropped("writer_stopped");
        metrics.add_nip46_activity_dropped("shutdown_flush_failed", 2);
        metrics.add_nip46_activity_dropped("retention_limit", 3);
        metrics.observe_nip46_queue_wait(Duration::from_millis(5));
        metrics.observe_nip46_worker_duration(Duration::from_millis(7));

        let output = metrics.to_prometheus();
        assert!(output.contains("keycast_nip46_noisy_flow_shed_total{flow=\"target\"} 1"));
        assert!(output.contains("keycast_nip46_noisy_flow_shed_total{flow=\"client\"} 1"));
        assert!(output.contains("keycast_nip46_rejected_hashring_prequeue_total 1"));
        assert!(output.contains("keycast_nip46_rejected_hashring_worker_total 1"));
        assert!(output.contains("keycast_nip46_queue_dropped_total 1"));
        assert!(output.contains("keycast_nip46_queue_closed_total 1"));
        assert!(output.contains("keycast_nip46_lookup_database_total 1"));
        assert!(output.contains("keycast_nip46_lookup_errors_total 1"));
        assert!(output.contains("keycast_nip46_lookup_shed_total 1"));
        assert!(output.contains("keycast_nip46_lookup_invalidated_total 1"));
        assert!(output.contains("keycast_nip46_negative_cache_hits_total 1"));
        assert!(output.contains("keycast_nip46_activity_dropped_total{reason=\"queue_full\"} 1"));
        assert!(
            output.contains("keycast_nip46_activity_dropped_total{reason=\"writer_stopped\"} 1")
        );
        assert!(output
            .contains("keycast_nip46_activity_dropped_total{reason=\"shutdown_flush_failed\"} 2"));
        assert!(
            output.contains("keycast_nip46_activity_dropped_total{reason=\"retention_limit\"} 3")
        );
        assert!(output.contains("keycast_nip46_queue_wait_seconds_count 1"));
        assert!(output.contains("keycast_nip46_worker_duration_seconds_count 1"));
    }

    #[test]
    fn bcrypt_admission_metrics_use_bounded_labels() {
        let metrics = Metrics::new();
        metrics.inc_bcrypt_active(BcryptWorkload::Login, BcryptOperation::Verify);
        metrics.inc_bcrypt_waiting(BcryptWorkload::Pin, BcryptOperation::Verify);
        metrics.inc_bcrypt_rejection(BcryptWorkload::Background, BcryptOperation::Hash, false);

        let output = metrics.to_prometheus();
        assert!(output
            .contains("keycast_bcrypt_active_work{workload=\"login\",operation=\"verify\"} 1"));
        assert!(
            output.contains("keycast_bcrypt_waiting_work{workload=\"pin\",operation=\"verify\"} 1")
        );
        assert!(output.contains(
            "keycast_bcrypt_admission_rejections_total{workload=\"background\",operation=\"hash\",reason=\"capacity\"} 1"
        ));
    }
}
