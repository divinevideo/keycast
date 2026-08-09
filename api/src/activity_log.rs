// ABOUTME: Bounded OAuth activity logger for HTTP RPC requests
// ABOUTME: Coalesces authorization activity updates so request handlers never spawn DB work

use keycast_core::metrics::METRICS;
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, Notify},
    time::MissedTickBehavior,
};

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
    sender: Option<mpsc::Sender<ActivityLogEvent>>,
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
        let (sender, receiver) = mpsc::channel(queue_capacity);

        (
            Self {
                sender: Some(sender),
            },
            ActivityLogWorker {
                pool,
                receiver,
                flush_interval,
                max_batch_ids,
            },
        )
    }

    pub fn disabled() -> Self {
        Self { sender: None }
    }

    pub fn record(&self, is_oauth: bool, authorization_id: i64) -> ActivityLogResult {
        if !is_oauth {
            return ActivityLogResult::SkippedNonOauth;
        }

        let Some(sender) = &self.sender else {
            return ActivityLogResult::Disabled;
        };

        match sender.try_send(ActivityLogEvent { authorization_id }) {
            Ok(()) => ActivityLogResult::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => ActivityLogResult::Dropped,
            Err(mpsc::error::TrySendError::Closed(_)) => ActivityLogResult::WriterStopped,
        }
    }
}

#[derive(Debug)]
struct ActivityLogEvent {
    authorization_id: i64,
}

pub struct ActivityLogWorker {
    pool: PgPool,
    receiver: mpsc::Receiver<ActivityLogEvent>,
    flush_interval: Duration,
    max_batch_ids: usize,
}

impl ActivityLogWorker {
    pub async fn run_until_shutdown(mut self, shutdown: Arc<Notify>) {
        let mut pending: BTreeMap<i64, i64> = BTreeMap::new();
        let mut flush_interval = tokio::time::interval(self.flush_interval);
        flush_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // `Notify::notify_waiters` (what graceful shutdown calls) only wakes
        // waiters already registered when it fires; it stores no permit. A
        // `notified()` future created fresh on each `select!` iteration is not
        // registered while the loop is inside `flush_pending`, so a shutdown
        // landing in that window would be lost forever and this task would
        // never exit — the sender lives in the process-lifetime `KeycastState`,
        // so `recv()` never returns `None` either. Register once, up front, and
        // keep that registration across iterations.
        let shutdown_notified = shutdown.notified();
        tokio::pin!(shutdown_notified);
        shutdown_notified.as_mut().enable();

        // Because a failed flush retains its batch, `pending.len()` stays above
        // `max_batch_ids` while the database is unhappy. Without this latch the
        // size trigger below would then fire on every single received event —
        // one acquire attempt per RPC request, competing for the very pool this
        // change exists to relieve. While it is set, only the interval tick
        // retries, which is the pacing the size trigger was never meant to
        // override.
        let mut last_flush_failed = false;

        loop {
            tokio::select! {
                event = self.receiver.recv() => {
                    match event {
                        Some(event) => accumulate(&mut pending, event.authorization_id),
                        None => break,
                    }
                }
                _ = flush_interval.tick() => {
                    last_flush_failed = !self.flush(&mut pending).await;
                }
                _ = &mut shutdown_notified => {
                    break;
                }
            }

            if !last_flush_failed && pending.len() >= self.max_batch_ids {
                last_flush_failed = !self.flush(&mut pending).await;
            }
        }

        while let Ok(event) = self.receiver.try_recv() {
            accumulate(&mut pending, event.authorization_id);
        }
        self.flush(&mut pending).await;

        // Last chance is gone: the task is about to return and `pending` dies
        // with it, so anything still retained is lost and has to say so.
        if !pending.is_empty() {
            let lost: u64 = pending.values().map(|count| *count as u64).sum();
            METRICS.add_http_rpc_activity_dropped(lost);
            tracing::error!(
                lost_events = lost,
                "Lost OAuth authorization activity: the final flush before shutdown failed"
            );
        }
    }

    /// Returns whether the write succeeded, so the caller can stop using the
    /// batch-size trigger while the database is failing.
    async fn flush(&self, pending: &mut BTreeMap<i64, i64>) -> bool {
        let before = pending.len();
        let lost = flush_pending(&self.pool, pending).await;
        if lost > 0 {
            METRICS.add_http_rpc_activity_dropped(lost);
        }
        // A successful write always empties the map; a failure either retains
        // the batch or gives it up and reports the loss.
        before == 0 || (pending.is_empty() && lost == 0)
    }
}

fn accumulate(pending: &mut BTreeMap<i64, i64>, authorization_id: i64) {
    accumulate_by(pending, authorization_id, 1);
}

fn accumulate_by(pending: &mut BTreeMap<i64, i64>, authorization_id: i64, count: i64) {
    *pending.entry(authorization_id).or_insert(0) += count;
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
            let lost: u64 = pending.values().map(|count| *count as u64).sum();
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
