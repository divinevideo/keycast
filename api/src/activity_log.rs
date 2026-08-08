// ABOUTME: Bounded OAuth activity logger for HTTP RPC requests
// ABOUTME: Coalesces authorization activity updates so request handlers never spawn DB work

use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, Notify},
    time::MissedTickBehavior,
};

const DEFAULT_QUEUE_CAPACITY: usize = 4096;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_BATCH_IDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityLogResult {
    Queued,
    Dropped,
    SkippedNonOauth,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct ActivityLogger {
    sender: Option<mpsc::Sender<ActivityLogEvent>>,
    dropped_total: Arc<AtomicU64>,
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
        let dropped_total = Arc::new(AtomicU64::new(0));

        (
            Self {
                sender: Some(sender),
                dropped_total: dropped_total.clone(),
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
        Self {
            sender: None,
            dropped_total: Arc::new(AtomicU64::new(0)),
        }
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
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped_total.fetch_add(1, Ordering::Relaxed);
                ActivityLogResult::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(_)) => ActivityLogResult::Disabled,
        }
    }

    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
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
    pub async fn run(mut self) {
        let mut pending: BTreeMap<i64, i64> = BTreeMap::new();
        let mut flush_interval = tokio::time::interval(self.flush_interval);
        flush_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = self.receiver.recv() => {
                    match event {
                        Some(event) => accumulate(&mut pending, event.authorization_id),
                        None => break,
                    }
                }
                _ = flush_interval.tick() => {
                    flush_pending(&self.pool, &mut pending).await;
                }
            }

            if pending.len() >= self.max_batch_ids {
                flush_pending(&self.pool, &mut pending).await;
            }
        }

        while let Ok(event) = self.receiver.try_recv() {
            accumulate(&mut pending, event.authorization_id);
        }
        flush_pending(&self.pool, &mut pending).await;
    }

    pub async fn run_until_shutdown(mut self, shutdown: Arc<Notify>) {
        let mut pending: BTreeMap<i64, i64> = BTreeMap::new();
        let mut flush_interval = tokio::time::interval(self.flush_interval);
        flush_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = self.receiver.recv() => {
                    match event {
                        Some(event) => accumulate(&mut pending, event.authorization_id),
                        None => break,
                    }
                }
                _ = flush_interval.tick() => {
                    flush_pending(&self.pool, &mut pending).await;
                }
                _ = shutdown.notified() => {
                    break;
                }
            }

            if pending.len() >= self.max_batch_ids {
                flush_pending(&self.pool, &mut pending).await;
            }
        }

        while let Ok(event) = self.receiver.try_recv() {
            accumulate(&mut pending, event.authorization_id);
        }
        flush_pending(&self.pool, &mut pending).await;
    }
}

fn accumulate(pending: &mut BTreeMap<i64, i64>, authorization_id: i64) {
    *pending.entry(authorization_id).or_insert(0) += 1;
}

async fn flush_pending(pool: &PgPool, pending: &mut BTreeMap<i64, i64>) {
    if pending.is_empty() {
        return;
    }

    let ids: Vec<i64> = pending.keys().copied().collect();
    let counts: Vec<i64> = pending.values().copied().collect();
    pending.clear();

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
        tracing::error!(
            error = %error,
            batch_size = ids.len(),
            "Failed to flush OAuth authorization activity"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn disabled_logger_does_not_queue() {
        let logger = ActivityLogger::disabled();

        assert_eq!(logger.record(false, 1), ActivityLogResult::SkippedNonOauth);
        assert_eq!(logger.record(true, 1), ActivityLogResult::Disabled);
        assert_eq!(logger.dropped_total(), 0);
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
        assert_eq!(logger.dropped_total(), 1);
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
