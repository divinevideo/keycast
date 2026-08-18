// ABOUTME: Shared bounded coalescing writer for best-effort authorization activity
// ABOUTME: Keeps request paths from spawning unbounded database write work

use async_trait::async_trait;
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, Notify},
    time::MissedTickBehavior,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalescingRecordResult {
    Queued,
    Dropped,
    WriterStopped,
}

#[async_trait]
pub trait CoalescingActivityHooks<K>: Send + Sync + 'static
where
    K: Ord + Send + 'static,
{
    fn accumulate(&self, pending: &mut BTreeMap<K, i64>, key: K, count: i64);
    fn queued(&self);
    fn dropped_full(&self);
    fn writer_stopped(&self);
    fn set_pending(&self, pending: usize);
    fn final_flush_lost(&self, lost: u64);
    fn flush_lost(&self, lost: u64);
    async fn flush_pending(&self, pool: &PgPool, pending: &mut BTreeMap<K, i64>) -> u64;
}

#[derive(Debug, Clone)]
pub struct CoalescingActivityLogger<K, H>
where
    K: Ord + Send + 'static,
    H: CoalescingActivityHooks<K>,
{
    sender: mpsc::Sender<K>,
    hooks: Arc<H>,
}

impl<K, H> CoalescingActivityLogger<K, H>
where
    K: Ord + Send + 'static,
    H: CoalescingActivityHooks<K>,
{
    pub fn new(
        pool: PgPool,
        queue_capacity: usize,
        flush_interval: Duration,
        max_batch_ids: usize,
        hooks: H,
    ) -> (Self, CoalescingActivityWorker<K, H>) {
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let hooks = Arc::new(hooks);
        (
            Self {
                sender,
                hooks: hooks.clone(),
            },
            CoalescingActivityWorker {
                pool,
                receiver,
                flush_interval,
                max_batch_ids,
                hooks,
            },
        )
    }

    pub fn record(&self, key: K) -> CoalescingRecordResult {
        match self.sender.try_send(key) {
            Ok(()) => {
                self.hooks.queued();
                CoalescingRecordResult::Queued
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.hooks.dropped_full();
                CoalescingRecordResult::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.hooks.writer_stopped();
                CoalescingRecordResult::WriterStopped
            }
        }
    }
}

pub struct CoalescingActivityWorker<K, H>
where
    K: Ord + Send + 'static,
    H: CoalescingActivityHooks<K>,
{
    pool: PgPool,
    receiver: mpsc::Receiver<K>,
    flush_interval: Duration,
    max_batch_ids: usize,
    hooks: Arc<H>,
}

impl<K, H> CoalescingActivityWorker<K, H>
where
    K: Ord + Send + 'static,
    H: CoalescingActivityHooks<K>,
{
    pub async fn run_until_shutdown(mut self, shutdown: Arc<Notify>) {
        let mut pending = BTreeMap::new();
        let mut flush_interval = tokio::time::interval(self.flush_interval);
        flush_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // `Notify::notify_waiters` only wakes waiters already registered when
        // it fires; it stores no permit. A fresh `notified()` future per loop
        // can miss shutdown while the worker is inside `flush_pending`, and
        // process-lifetime senders mean `recv()` may never return `None`.
        // Register once, up front, and keep that registration across iterations.
        let shutdown_notified = shutdown.notified();
        tokio::pin!(shutdown_notified);
        shutdown_notified.as_mut().enable();

        // Failed flushes retain their batch. Without this latch the size
        // trigger would retry on every new event while the database is down,
        // competing for the same pool the coalescing writer protects.
        let mut last_flush_failed = false;

        loop {
            tokio::select! {
                event = self.receiver.recv() => {
                    match event {
                        Some(key) => self.hooks.accumulate(&mut pending, key, 1),
                        None => break,
                    }
                }
                _ = flush_interval.tick() => {
                    last_flush_failed = !self.flush(&mut pending).await;
                }
                _ = &mut shutdown_notified => break,
            }

            self.hooks.set_pending(pending.len());
            if !last_flush_failed && pending.len() >= self.max_batch_ids {
                last_flush_failed = !self.flush(&mut pending).await;
            }
        }

        while let Ok(key) = self.receiver.try_recv() {
            self.hooks.accumulate(&mut pending, key, 1);
        }
        self.flush(&mut pending).await;

        // Last chance is gone: the task is about to return and `pending` dies
        // with it, so anything still retained is lost and has to say so.
        if !pending.is_empty() {
            self.hooks.final_flush_lost(total_events(&pending));
        }
        self.hooks.set_pending(0);
    }

    /// Returns whether the write succeeded, so the caller can stop using the
    /// batch-size trigger while the database is failing.
    async fn flush(&self, pending: &mut BTreeMap<K, i64>) -> bool {
        let before = pending.len();
        let lost = self.hooks.flush_pending(&self.pool, pending).await;
        if lost > 0 {
            self.hooks.flush_lost(lost);
        }
        self.hooks.set_pending(pending.len());
        // A successful write always empties the map; a failure either retains
        // the batch or gives it up and reports the loss.
        before == 0 || (pending.is_empty() && lost == 0)
    }
}

pub fn accumulate_unbounded<K: Ord>(pending: &mut BTreeMap<K, i64>, key: K, count: i64) {
    *pending.entry(key).or_insert(0) += count;
}

pub fn total_events<K: Ord>(pending: &BTreeMap<K, i64>) -> u64 {
    pending.values().map(|count| *count as u64).sum()
}
