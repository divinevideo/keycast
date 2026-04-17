// ABOUTME: Global metrics counters for Prometheus endpoint
// ABOUTME: Uses atomic counters that can be incremented from signer and read from API

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
    /// NIP-46 requests where handler was not found
    pub nip46_requests_handler_not_found: AtomicU64,
    /// NIP-46 requests successfully processed
    pub nip46_requests_processed: AtomicU64,
    /// NIP-46 requests dropped due to queue full (backpressure)
    pub nip46_requests_queue_dropped: AtomicU64,
    /// NIP-46 tombstone responses sent (revoked/expired authorizations)
    pub nip46_tombstone_responses: AtomicU64,

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

    // === Labeled Auth Metrics ===
    auth_requests_total: Mutex<BTreeMap<AuthRequestKey, u64>>,
    auth_request_durations: Mutex<BTreeMap<AuthDurationKey, AuthDurationMetric>>,
    auth_audit_write_failures_total: Mutex<BTreeMap<String, u64>>,
    auth_email_send_failures_total: Mutex<BTreeMap<String, u64>>,
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
            nip46_requests_handler_not_found: AtomicU64::new(0),
            nip46_requests_processed: AtomicU64::new(0),
            nip46_requests_queue_dropped: AtomicU64::new(0),
            nip46_tombstone_responses: AtomicU64::new(0),
            // HTTP RPC metrics
            http_rpc_requests_total: AtomicU64::new(0),
            http_rpc_cache_hits: AtomicU64::new(0),
            http_rpc_cache_misses: AtomicU64::new(0),
            http_rpc_cache_size: AtomicU64::new(0),
            http_rpc_success: AtomicU64::new(0),
            http_rpc_auth_errors: AtomicU64::new(0),
            // Auth metrics
            registrations_total: AtomicU64::new(0),
            logins_total: AtomicU64::new(0),
            login_failures_total: AtomicU64::new(0),
            account_deletions_total: AtomicU64::new(0),
            // OAuth metrics
            oauth_authorizations_created: AtomicU64::new(0),
            oauth_authorizations_revoked: AtomicU64::new(0),
            // Labeled auth metrics
            auth_requests_total: Mutex::new(BTreeMap::new()),
            auth_request_durations: Mutex::new(BTreeMap::new()),
            auth_audit_write_failures_total: Mutex::new(BTreeMap::new()),
            auth_email_send_failures_total: Mutex::new(BTreeMap::new()),
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

    pub fn inc_nip46_tombstone_response(&self) {
        self.nip46_tombstone_responses
            .fetch_add(1, Ordering::Relaxed);
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

        output.push_str("\n# HELP keycast_nip46_queue_dropped_total NIP-46 requests dropped due to queue full (backpressure)\n");
        output.push_str("# TYPE keycast_nip46_queue_dropped_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_queue_dropped_total {}\n",
            self.nip46_requests_queue_dropped.load(Ordering::Relaxed)
        ));

        output.push_str("\n# HELP keycast_nip46_tombstone_responses_total NIP-46 error responses sent for revoked/expired authorizations\n");
        output.push_str("# TYPE keycast_nip46_tombstone_responses_total counter\n");
        output.push_str(&format!(
            "keycast_nip46_tombstone_responses_total {}\n",
            self.nip46_tombstone_responses.load(Ordering::Relaxed)
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

        output
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
        _ => "other",
    }
}

fn normalize_auth_outcome(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "failure" => "failure",
        "accepted" => "accepted",
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
        _ => "other",
    }
}

fn normalize_email_template(template: &str) -> &'static str {
    match template {
        "verification" => "verification",
        "password_reset" => "password_reset",
        "resend_verification" => "resend_verification",
        _ => "other",
    }
}

/// Global metrics instance
pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

#[cfg(test)]
mod tests {
    use super::Metrics;
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
    }
}
