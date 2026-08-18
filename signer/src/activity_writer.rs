// ABOUTME: Bounded, coalescing activity writer for relay-based NIP-46 requests
// ABOUTME: Keeps successful relay operations from spawning unbounded database tasks

use async_trait::async_trait;
use keycast_core::{
    coalescing_activity::{
        CoalescingActivityHooks, CoalescingActivityLogger, CoalescingActivityWorker,
    },
    metrics::METRICS,
};
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Notify;

const DEFAULT_QUEUE_CAPACITY: usize = 4096;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_BATCH_IDS: usize = 256;
const MAX_RETAINED_IDS: usize = 4096;

type AuthorizationKey = (i64, i64);

#[derive(Debug, Clone)]
pub struct RelayActivityLogger {
    logger: CoalescingActivityLogger<AuthorizationKey, RelayActivityHooks>,
}

impl RelayActivityLogger {
    pub fn new(pool: PgPool) -> (Self, RelayActivityWorker) {
        Self::with_config(
            pool,
            DEFAULT_QUEUE_CAPACITY,
            DEFAULT_FLUSH_INTERVAL,
            DEFAULT_MAX_BATCH_IDS,
        )
    }

    fn with_config(
        pool: PgPool,
        queue_capacity: usize,
        flush_interval: Duration,
        max_batch_ids: usize,
    ) -> (Self, RelayActivityWorker) {
        let (logger, worker) = CoalescingActivityLogger::new(
            pool,
            queue_capacity,
            flush_interval,
            max_batch_ids,
            RelayActivityHooks,
        );
        (Self { logger }, RelayActivityWorker { worker })
    }

    pub fn record(&self, tenant_id: i64, authorization_id: i64) {
        let _ = self.logger.record((tenant_id, authorization_id));
    }
}

pub struct RelayActivityWorker {
    worker: CoalescingActivityWorker<AuthorizationKey, RelayActivityHooks>,
}

impl RelayActivityWorker {
    pub async fn run_until_shutdown(self, shutdown: Arc<Notify>) {
        self.worker.run_until_shutdown(shutdown).await;
    }
}

#[derive(Debug, Clone)]
struct RelayActivityHooks;

#[async_trait]
impl CoalescingActivityHooks<AuthorizationKey> for RelayActivityHooks {
    fn accumulate(
        &self,
        pending: &mut BTreeMap<AuthorizationKey, i64>,
        key: AuthorizationKey,
        count: i64,
    ) {
        accumulate(pending, key, count);
    }

    fn queued(&self) {
        METRICS.inc_nip46_activity_queued();
    }

    fn dropped_full(&self) {
        METRICS.inc_nip46_activity_dropped("queue_full");
    }

    fn writer_stopped(&self) {
        METRICS.inc_nip46_activity_dropped("writer_stopped");
    }

    fn set_pending(&self, pending: usize) {
        METRICS.set_nip46_activity_pending(pending as u64);
    }

    fn final_flush_lost(&self, lost: u64) {
        METRICS.add_nip46_activity_dropped("shutdown_flush_failed", lost);
        tracing::error!(lost_events = lost, "Lost NIP-46 activity during shutdown");
    }

    fn flush_lost(&self, _lost: u64) {}

    async fn flush_pending(
        &self,
        pool: &PgPool,
        pending: &mut BTreeMap<AuthorizationKey, i64>,
    ) -> u64 {
        flush_pending(pool, pending).await
    }
}

fn accumulate(pending: &mut BTreeMap<AuthorizationKey, i64>, key: AuthorizationKey, count: i64) {
    if !pending.contains_key(&key) && pending.len() >= MAX_RETAINED_IDS {
        METRICS.add_nip46_activity_dropped("retention_limit", count as u64);
        return;
    }
    *pending.entry(key).or_insert(0) += count;
}

async fn flush_pending(pool: &PgPool, pending: &mut BTreeMap<AuthorizationKey, i64>) -> u64 {
    if pending.is_empty() {
        return 0;
    }

    let tenant_ids: Vec<i64> = pending.keys().map(|(tenant_id, _)| *tenant_id).collect();
    let authorization_ids: Vec<i64> = pending.keys().map(|(_, auth_id)| *auth_id).collect();
    let counts: Vec<i64> = pending.values().copied().collect();
    let batch = std::mem::take(pending);

    if let Err(error) = sqlx::query(
        "UPDATE oauth_authorizations AS oa
         SET last_activity = NOW(),
             activity_count = oa.activity_count + batch.count_delta::integer
         FROM (
             SELECT * FROM UNNEST($1::bigint[], $2::bigint[], $3::bigint[])
         ) AS batch(tenant_id, id, count_delta)
         WHERE oa.tenant_id = batch.tenant_id AND oa.id = batch.id",
    )
    .bind(&tenant_ids)
    .bind(&authorization_ids)
    .bind(&counts)
    .execute(pool)
    .await
    {
        METRICS.inc_nip46_activity_write_failure();
        for (key, count) in batch {
            accumulate(pending, key, count);
        }

        tracing::error!(error = %error, "Failed to flush NIP-46 activity; retaining batch");
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn full_queue_drops_without_spawning_work() {
        let pool =
            PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused").expect("lazy pool");
        let (logger, _worker) =
            RelayActivityLogger::with_config(pool, 1, Duration::from_secs(60), 256);
        logger.record(1, 1);
        let before = METRICS
            .nip46_activity_dropped_queue_full
            .load(Ordering::Relaxed);
        logger.record(1, 2);
        assert!(
            METRICS
                .nip46_activity_dropped_queue_full
                .load(Ordering::Relaxed)
                > before
        );
    }

    #[test]
    fn coalescing_keeps_one_pending_key() {
        let mut pending = BTreeMap::new();
        accumulate(&mut pending, (7, 11), 1);
        accumulate(&mut pending, (7, 11), 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.get(&(7, 11)), Some(&3));
    }

    #[test]
    fn retained_activity_ids_stay_bounded() {
        let mut pending = BTreeMap::new();
        for id in 0..(MAX_RETAINED_IDS as i64 + 100) {
            accumulate(&mut pending, (1, id), 1);
        }
        assert_eq!(pending.len(), MAX_RETAINED_IDS);
    }

    #[tokio::test]
    async fn shutdown_accounts_for_final_database_failure() {
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(20))
            .connect_lazy_with(
                "postgres://unused:unused@127.0.0.1:1/unused"
                    .parse::<PgConnectOptions>()
                    .expect("connect options"),
            );
        let (logger, worker) =
            RelayActivityLogger::with_config(pool, 4, Duration::from_secs(60), 256);
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_worker = shutdown.clone();
        let before = METRICS
            .nip46_activity_dropped_shutdown
            .load(Ordering::Relaxed);
        let worker_task = tokio::spawn(worker.run_until_shutdown(shutdown_for_worker));

        logger.record(1, 1);
        tokio::task::yield_now().await;
        shutdown.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), worker_task)
            .await
            .expect("worker must stop")
            .expect("worker task");

        assert!(
            METRICS
                .nip46_activity_dropped_shutdown
                .load(Ordering::Relaxed)
                > before
        );
    }
}
