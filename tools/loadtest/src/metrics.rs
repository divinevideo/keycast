use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Metrics collector for load test results
pub struct Metrics {
    /// Latency histogram (microseconds)
    latency: parking_lot::Mutex<Histogram<u64>>,

    /// Request counters
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_error: AtomicU64,

    /// Error breakdown
    errors_auth: AtomicU64,
    errors_server: AtomicU64,
    errors_client: AtomicU64,
    errors_network: AtomicU64,

    /// Cache estimation (based on latency thresholds)
    cache_hits_estimated: AtomicU64,
    cache_misses_estimated: AtomicU64,

    /// Timing
    start_time: Instant,
    end_time: parking_lot::Mutex<Option<Instant>>,

    /// Timeline snapshots
    timeline: parking_lot::Mutex<Vec<TimelinePoint>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            latency: parking_lot::Mutex::new(
                Histogram::new_with_bounds(1, 600_000_000, 3).unwrap(), // 1μs to 10min
            ),
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_error: AtomicU64::new(0),
            errors_auth: AtomicU64::new(0),
            errors_server: AtomicU64::new(0),
            errors_client: AtomicU64::new(0),
            errors_network: AtomicU64::new(0),
            cache_hits_estimated: AtomicU64::new(0),
            cache_misses_estimated: AtomicU64::new(0),
            start_time: Instant::now(),
            end_time: parking_lot::Mutex::new(None),
            timeline: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn record_request(&self, duration: Duration, success: bool, status: Option<u16>) {
        let micros = duration.as_micros() as u64;

        // Record latency
        if let Some(mut hist) = self.latency.try_lock() {
            let _ = hist.record(micros);
        }

        self.requests_total.fetch_add(1, Ordering::Relaxed);

        if success {
            self.requests_success.fetch_add(1, Ordering::Relaxed);
            // Estimate cache hit/miss based on latency (15ms threshold)
            if micros < 15_000 {
                self.cache_hits_estimated.fetch_add(1, Ordering::Relaxed);
            } else {
                self.cache_misses_estimated.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.requests_error.fetch_add(1, Ordering::Relaxed);
            match status {
                Some(401) | Some(403) => {
                    self.errors_auth.fetch_add(1, Ordering::Relaxed);
                }
                Some(s) if s >= 500 => {
                    self.errors_server.fetch_add(1, Ordering::Relaxed);
                }
                Some(s) if s >= 400 => {
                    self.errors_client.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    self.errors_network.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    pub fn snapshot(&self) -> TimelinePoint {
        let hist = self.latency.lock();
        TimelinePoint {
            elapsed_secs: self.start_time.elapsed().as_secs_f64(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_error: self.requests_error.load(Ordering::Relaxed),
            latency_p50_ms: hist.value_at_quantile(0.50) as f64 / 1000.0,
            latency_p99_ms: hist.value_at_quantile(0.99) as f64 / 1000.0,
        }
    }

    pub fn add_timeline_point(&self) {
        let point = self.snapshot();
        self.timeline.lock().push(point);
    }

    pub fn finish(&self) {
        *self.end_time.lock() = Some(Instant::now());
    }

    pub fn summary(&self) -> MetricsSummary {
        let duration = self.end_time.lock().unwrap_or(Instant::now()) - self.start_time;
        let total = self.requests_total.load(Ordering::Relaxed);
        let success = self.requests_success.load(Ordering::Relaxed);
        let hist = self.latency.lock();

        MetricsSummary {
            duration_secs: duration.as_secs_f64(),
            requests_per_second: if duration.as_secs_f64() > 0.0 {
                total as f64 / duration.as_secs_f64()
            } else {
                0.0
            },
            total_requests: total,
            successful_requests: success,
            failed_requests: self.requests_error.load(Ordering::Relaxed),
            latency_min_ms: hist.min() as f64 / 1000.0,
            latency_p50_ms: hist.value_at_quantile(0.50) as f64 / 1000.0,
            latency_p95_ms: hist.value_at_quantile(0.95) as f64 / 1000.0,
            latency_p99_ms: hist.value_at_quantile(0.99) as f64 / 1000.0,
            latency_max_ms: hist.max() as f64 / 1000.0,
            cache_hit_ratio: if success > 0 {
                self.cache_hits_estimated.load(Ordering::Relaxed) as f64 / success as f64
            } else {
                0.0
            },
            error_rate: if total > 0 {
                self.requests_error.load(Ordering::Relaxed) as f64 / total as f64
            } else {
                0.0
            },
            errors_auth: self.errors_auth.load(Ordering::Relaxed),
            errors_server: self.errors_server.load(Ordering::Relaxed),
            errors_client: self.errors_client.load(Ordering::Relaxed),
            errors_network: self.errors_network.load(Ordering::Relaxed),
        }
    }

    pub fn to_results(&self, metadata: TestMetadata) -> TestResults {
        TestResults {
            metadata,
            summary: self.summary(),
            timeline: self.timeline.lock().clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMetadata {
    pub url: String,
    pub scenario: String,
    pub method: String,
    pub concurrency: usize,
    pub duration_secs: u64,
    pub user_count: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub duration_secs: f64,
    pub requests_per_second: f64,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub latency_min_ms: f64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub latency_max_ms: f64,
    pub cache_hit_ratio: f64,
    pub error_rate: f64,
    pub errors_auth: u64,
    pub errors_server: u64,
    pub errors_client: u64,
    pub errors_network: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub elapsed_secs: f64,
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_error: u64,
    pub latency_p50_ms: f64,
    pub latency_p99_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResults {
    pub metadata: TestMetadata,
    pub summary: MetricsSummary,
    pub timeline: Vec<TimelinePoint>,
}

impl TestResults {
    pub fn format_text(&self) -> String {
        let s = &self.summary;
        format!(
            r#"Keycast Load Test Results
=========================
Target:        {}/api/nostr
Scenario:      {}
Method:        {}
Concurrency:   {}
Duration:      {:.1}s
Users:         {}

Summary:
  Requests:      {}
  Throughput:    {:.1} req/s
  Success Rate:  {:.1}%

Latency (ms):
  Min:   {:.1}
  p50:   {:.1}
  p95:   {:.1}
  p99:   {:.1}
  Max:   {:.1}

Cache (estimated):
  Hits:   {:.1}%
  Misses: {:.1}%

Errors:
  Auth:    {}
  Server:  {}
  Client:  {}
  Network: {}"#,
            self.metadata.url,
            self.metadata.scenario,
            self.metadata.method,
            self.metadata.concurrency,
            s.duration_secs,
            self.metadata.user_count,
            s.total_requests,
            s.requests_per_second,
            (1.0 - s.error_rate) * 100.0,
            s.latency_min_ms,
            s.latency_p50_ms,
            s.latency_p95_ms,
            s.latency_p99_ms,
            s.latency_max_ms,
            s.cache_hit_ratio * 100.0,
            (1.0 - s.cache_hit_ratio) * 100.0,
            s.errors_auth,
            s.errors_server,
            s.errors_client,
            s.errors_network,
        )
    }

    pub fn format_csv(&self) -> String {
        let s = &self.summary;
        format!(
            "url,scenario,method,concurrency,duration_secs,users,total_requests,rps,success_rate,p50_ms,p95_ms,p99_ms\n{},{},{},{},{:.1},{},{},{:.1},{:.1},{:.1},{:.1},{:.1}",
            self.metadata.url,
            self.metadata.scenario,
            self.metadata.method,
            self.metadata.concurrency,
            s.duration_secs,
            self.metadata.user_count,
            s.total_requests,
            s.requests_per_second,
            (1.0 - s.error_rate) * 100.0,
            s.latency_p50_ms,
            s.latency_p95_ms,
            s.latency_p99_ms,
        )
    }

    pub fn compare(&self, other: &TestResults) -> String {
        let s1 = &self.summary;
        let s2 = &other.summary;

        let rps_diff =
            ((s1.requests_per_second - s2.requests_per_second) / s2.requests_per_second) * 100.0;
        let p50_diff = ((s1.latency_p50_ms - s2.latency_p50_ms) / s2.latency_p50_ms) * 100.0;
        let p99_diff = ((s1.latency_p99_ms - s2.latency_p99_ms) / s2.latency_p99_ms) * 100.0;

        format!(
            r#"Comparison
==========
                    Current     Baseline    Change
Throughput (rps):   {:.1}       {:.1}       {:+.1}%
Latency p50 (ms):   {:.1}       {:.1}       {:+.1}%
Latency p99 (ms):   {:.1}       {:.1}       {:+.1}%"#,
            s1.requests_per_second,
            s2.requests_per_second,
            rps_diff,
            s1.latency_p50_ms,
            s2.latency_p50_ms,
            p50_diff,
            s1.latency_p99_ms,
            s2.latency_p99_ms,
            p99_diff,
        )
    }
}
