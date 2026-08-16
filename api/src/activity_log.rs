// ABOUTME: Bounded OAuth activity logger for HTTP RPC requests
// ABOUTME: Coalesces authorization activity updates so request handlers never spawn DB work

use async_trait::async_trait;
use keycast_core::{
    coalescing_activity::{
        accumulate_unbounded, total_events, CoalescingActivityHooks, CoalescingActivityLogger,
        CoalescingActivityWorker, CoalescingRecordResult,
    },
    metrics::METRICS,
};
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Notify;

const DEFAULT_QUEUE_CAPACITY: usize = 4096;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_BATCH_IDS: usize = 256;

/// Ceiling on retained-but-unwritten authorization ids after failed flushes.
/// A failed flush is retried on the next tick rather than discarded, but a
/// database that stays unhappy must not grow this map without bound.
const MAX_RETAINED_IDS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityLogResult {
    Queued,
    Dropped,
    SkippedNonOauth,
    Disabled,
    /// The writer has already stopped. Distinct from `Disabled` because the
    /// record would have been accepted before shutdown drain completed.
    WriterStopped,
}

#[derive(Debug, Clone)]
pub struct ActivityLogger {
    logger: Option<CoalescingActivityLogger<i64, HttpRpcActivityHooks>>,
}

impl ActivityLogger {
    pub fn new(pool: PgPool) -> (Self, ActivityLogWorker) {
        Self::with_config(
            pool,
            DEFAULT_QUEUE_CAPACITY,
            DEFAULT_FLUSH_INTERVAL,
            DEFAULT_MAX_BATCH_IDS,
        )
    }

    pub fn with_config(
        pool: PgPool,
        queue_capacity: usize,
        flush_interval: Duration,
        max_batch_ids: usize,
    ) -> (Self, ActivityLogWorker) {
        let (logger, worker) = CoalescingActivityLogger::new(
            pool,
            queue_capacity,
            flush_interval,
            max_batch_ids,
            HttpRpcActivityHooks,
        );

        (
            Self {
                logger: Some(logger),
            },
            ActivityLogWorker { worker },
        )
    }

    pub fn disabled() -> Self {
        Self { logger: None }
    }

    pub fn record(&self, is_oauth: bool, authorization_id: i64) -> ActivityLogResult {
        if !is_oauth {
            return ActivityLogResult::SkippedNonOauth;
        }

        let Some(logger) = &self.logger else {
            return ActivityLogResult::Disabled;
        };

        match logger.record(authorization_id) {
            CoalescingRecordResult::Queued => ActivityLogResult::Queued,
            CoalescingRecordResult::Dropped => ActivityLogResult::Dropped,
            CoalescingRecordResult::WriterStopped => ActivityLogResult::WriterStopped,
        }
    }
}

pub struct ActivityLogWorker {
    worker: CoalescingActivityWorker<i64, HttpRpcActivityHooks>,
}

impl ActivityLogWorker {
    pub async fn run_until_shutdown(self, shutdown: Arc<Notify>) {
        self.worker.run_until_shutdown(shutdown).await;
    }
}

#[derive(Debug, Clone)]
struct HttpRpcActivityHooks;

#[async_trait]
impl CoalescingActivityHooks<i64> for HttpRpcActivityHooks {
    fn accumulate(&self, pending: &mut BTreeMap<i64, i64>, authorization_id: i64, count: i64) {
        accumulate_by(pending, authorization_id, count);
    }

    fn queued(&self) {}

    fn dropped_full(&self) {}

    fn writer_stopped(&self) {}

    fn set_pending(&self, _pending: usize) {}

    fn final_flush_lost(&self, lost: u64) {
        METRICS.add_http_rpc_activity_dropped(lost);
        tracing::error!(
            lost_events = lost,
            "Lost OAuth authorization activity: the final flush before shutdown failed"
        );
    }

    fn flush_lost(&self, lost: u64) {
        METRICS.add_http_rpc_activity_dropped(lost);
    }

    async fn flush_pending(&self, pool: &PgPool, pending: &mut BTreeMap<i64, i64>) -> u64 {
        flush_pending(pool, pending).await
    }
}

#[cfg(test)]
fn accumulate(pending: &mut BTreeMap<i64, i64>, authorization_id: i64) {
    accumulate_by(pending, authorization_id, 1);
}

fn accumulate_by(pending: &mut BTreeMap<i64, i64>, authorization_id: i64, count: i64) {
    accumulate_unbounded(pending, authorization_id, count);
}

/// Writes the coalesced counts and returns the number of events that were lost
/// outright. A failed write is normally retained for the next flush; it is only
/// given up when retaining it would grow `pending` past [`MAX_RETAINED_IDS`].
async fn flush_pending(pool: &PgPool, pending: &mut BTreeMap<i64, i64>) -> u64 {
    if pending.is_empty() {
        return 0;
    }

    let ids: Vec<i64> = pending.keys().copied().collect();
    let counts: Vec<i64> = pending.values().copied().collect();
    let batch = std::mem::take(pending);

    if let Err(error) = sqlx::query(
        "UPDATE oauth_authorizations AS oa
         SET last_activity = NOW(),
             activity_count = oa.activity_count + batch.count_delta::integer
         FROM (
             SELECT * FROM UNNEST($1::bigint[], $2::bigint[])
         ) AS batch(id, count_delta)
         WHERE oa.id = batch.id",
    )
    .bind(&ids)
    .bind(&counts)
    .execute(pool)
    .await
    {
        for (id, count) in batch {
            accumulate_by(pending, id, count);
        }

        if pending.len() > MAX_RETAINED_IDS {
            let lost = total_events(pending);
            pending.clear();
            tracing::error!(
                error = %error,
                batch_size = ids.len(),
                lost_events = lost,
                "Gave up on OAuth authorization activity after repeated flush failures"
            );
            return lost;
        }

        tracing::error!(
            error = %error,
            batch_size = ids.len(),
            "Failed to flush OAuth authorization activity, retaining for the next flush"
        );
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn disabled_logger_does_not_queue() {
        let logger = ActivityLogger::disabled();

        assert_eq!(logger.record(false, 1), ActivityLogResult::SkippedNonOauth);
        assert_eq!(logger.record(true, 1), ActivityLogResult::Disabled);
    }

    #[tokio::test]
    async fn logger_drops_when_queue_is_full() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost/keycast_test")
            .expect("lazy pool");
        let (logger, _worker) =
            ActivityLogger::with_config(pool, 1, Duration::from_secs(60), DEFAULT_MAX_BATCH_IDS);

        assert_eq!(logger.record(true, 10), ActivityLogResult::Queued);
        assert_eq!(logger.record(true, 11), ActivityLogResult::Dropped);
    }

    #[tokio::test]
    async fn queue_full_drop_does_not_increment_metric_inside_logger() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost/keycast_test")
            .expect("lazy pool");
        let (logger, _worker) =
            ActivityLogger::with_config(pool, 1, Duration::from_secs(60), DEFAULT_MAX_BATCH_IDS);

        assert_eq!(logger.record(true, 10), ActivityLogResult::Queued);
        let before = METRICS.http_rpc_activity_dropped.load(Ordering::Relaxed);
        assert_eq!(logger.record(true, 11), ActivityLogResult::Dropped);
        assert_eq!(
            METRICS.http_rpc_activity_dropped.load(Ordering::Relaxed),
            before
        );
    }

    #[tokio::test]
    async fn worker_exits_on_shutdown_even_when_sender_is_alive() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost/keycast_test")
            .expect("lazy pool");
        let (_logger, worker) =
            ActivityLogger::with_config(pool, 1, Duration::from_secs(60), DEFAULT_MAX_BATCH_IDS);
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = shutdown.clone();

        let worker_task = tokio::spawn(async move {
            worker.run_until_shutdown(shutdown_for_task).await;
        });
        tokio::task::yield_now().await;
        shutdown.notify_waiters();

        tokio::time::timeout(Duration::from_secs(1), worker_task)
            .await
            .expect("worker should observe shutdown")
            .expect("worker task should not panic");
    }

    /// Graceful shutdown calls `Notify::notify_waiters`, which wakes only the
    /// waiters registered at that instant. This drives the worker into the
    /// middle of a flush (a Postgres handshake against a listener that accepts
    /// but never replies) and signals shutdown there, so the worker is *not*
    /// parked in its `select!` when the signal lands.
    #[tokio::test]
    #[serial(activity_log_dropped_metric)]
    async fn worker_observes_shutdown_signalled_during_a_flush() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole listener");
        let port = listener.local_addr().expect("listener addr").port();
        let _blackhole = tokio::spawn(async move {
            let mut accepted = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                accepted.push(socket);
            }
        });

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy(&format!("postgres://postgres:postgres@127.0.0.1:{port}/x"))
            .expect("lazy pool");
        // `max_batch_ids = 1` makes the worker flush as soon as it takes the
        // event, so the shutdown below lands while it is inside that flush.
        let (logger, worker) = ActivityLogger::with_config(pool, 8, Duration::from_secs(60), 1);
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = shutdown.clone();

        let worker_task = tokio::spawn(async move {
            worker.run_until_shutdown(shutdown_for_task).await;
        });

        assert_eq!(logger.record(true, 1), ActivityLogResult::Queued);
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.notify_waiters();

        tokio::time::timeout(Duration::from_secs(15), worker_task)
            .await
            .expect("worker should observe a shutdown signalled outside its select")
            .expect("worker task should not panic");
    }

    #[tokio::test]
    async fn failed_flush_retains_counts_for_the_next_attempt() {
        // Port 1 refuses instantly, so the write fails without a long wait.
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/x")
            .expect("lazy pool");
        let mut pending = BTreeMap::new();
        accumulate(&mut pending, 42);
        accumulate(&mut pending, 42);
        accumulate(&mut pending, 7);

        let lost = flush_pending(&pool, &mut pending).await;

        assert_eq!(lost, 0, "a single failure gives up nothing");
        assert_eq!(
            pending.get(&42),
            Some(&2),
            "coalesced counts survive a failed write"
        );
        assert_eq!(pending.get(&7), Some(&1));
    }

    #[tokio::test]
    async fn flush_gives_up_and_reports_loss_once_retention_is_exceeded() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/x")
            .expect("lazy pool");
        let mut pending: BTreeMap<i64, i64> =
            (0..=MAX_RETAINED_IDS as i64).map(|id| (id, 1)).collect();

        let lost = flush_pending(&pool, &mut pending).await;

        assert_eq!(lost, MAX_RETAINED_IDS as u64 + 1);
        assert!(pending.is_empty(), "the retained map is bounded");
    }

    /// Every flush attempt opens one connection to this listener, which never
    /// answers, so the accept count is a direct measurement of how many times
    /// the worker retried a failing write.
    #[tokio::test]
    #[serial(activity_log_dropped_metric)]
    async fn a_failing_flush_stops_the_batch_size_trigger_from_retrying_per_event() {
        const EVENTS: i64 = 10;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole listener");
        let port = listener.local_addr().expect("listener addr").port();
        let attempts = Arc::new(AtomicU64::new(0));
        let attempts_for_listener = attempts.clone();
        let _blackhole = tokio::spawn(async move {
            let mut accepted = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                attempts_for_listener.fetch_add(1, Ordering::Relaxed);
                accepted.push(socket);
            }
        });

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy(&format!("postgres://postgres:postgres@127.0.0.1:{port}/x"))
            .expect("lazy pool");
        // A 60s interval never fires inside this test, so only the batch-size
        // trigger can drive a flush. `max_batch_ids = 1` means every event is
        // eligible to trigger one.
        let (logger, worker) = ActivityLogger::with_config(pool, 64, Duration::from_secs(60), 1);
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = shutdown.clone();
        let worker_task = tokio::spawn(async move {
            worker.run_until_shutdown(shutdown_for_task).await;
        });

        for id in 1..=EVENTS {
            assert_eq!(logger.record(true, id), ActivityLogResult::Queued);
        }
        // Long enough for the worker to take every event and, without the
        // latch, to have attempted a flush for each one.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let attempted = attempts.load(Ordering::Relaxed);
        assert!(
            attempted <= 2,
            "worker made {attempted} write attempts for {EVENTS} events while the database \
             was failing; the batch-size trigger is retrying per event instead of leaving \
             retries to the interval"
        );

        shutdown.notify_waiters();
        tokio::time::timeout(Duration::from_secs(10), worker_task)
            .await
            .expect("worker should exit")
            .expect("worker task should not panic");
    }

    // Serialised with the other tests whose shutdown drain feeds the same
    // process-global counter: a concurrent add landing inside the before/after
    // window would satisfy this assertion without the code under test doing
    // anything, and that contamination only ever pushes the test toward passing.
    #[tokio::test]
    #[serial(activity_log_dropped_metric)]
    async fn a_failed_final_flush_reports_the_counts_it_could_not_write() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/x")
            .expect("lazy pool");
        let (logger, worker) = ActivityLogger::with_config(pool, 8, Duration::from_secs(60), 64);
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = shutdown.clone();
        let worker_task = tokio::spawn(async move {
            worker.run_until_shutdown(shutdown_for_task).await;
        });

        assert_eq!(logger.record(true, 900), ActivityLogResult::Queued);
        assert_eq!(logger.record(true, 900), ActivityLogResult::Queued);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let before = METRICS.http_rpc_activity_dropped.load(Ordering::Relaxed);
        shutdown.notify_waiters();
        tokio::time::timeout(Duration::from_secs(10), worker_task)
            .await
            .expect("worker should exit")
            .expect("worker task should not panic");
        let after = METRICS.http_rpc_activity_dropped.load(Ordering::Relaxed);

        assert!(
            after >= before + 2,
            "the two events the final flush could not write must be reported as lost \
             (counter went {before} -> {after})"
        );
    }

    #[test]
    fn accumulate_coalesces_authorization_counts() {
        let mut pending = BTreeMap::new();

        accumulate(&mut pending, 42);
        accumulate(&mut pending, 42);
        accumulate(&mut pending, 7);

        assert_eq!(pending.get(&42), Some(&2));
        assert_eq!(pending.get(&7), Some(&1));
    }
}
