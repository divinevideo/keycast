// ABOUTME: Global metrics counters for Prometheus endpoint
// ABOUTME: Uses atomic counters that can be incremented from signer and read from API

use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

impl Metrics {
    const fn new() -> Self {
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
            // HTTP RPC metrics
            http_rpc_requests_total: AtomicU64::new(0),
            http_rpc_cache_hits: AtomicU64::new(0),
            http_rpc_cache_misses: AtomicU64::new(0),
            http_rpc_cache_size: AtomicU64::new(0),
            http_rpc_success: AtomicU64::new(0),
            http_rpc_auth_errors: AtomicU64::new(0),
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

        output
    }
}

/// Global metrics instance
pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);
