//! Process-wide bounded admission for bcrypt operations.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::metrics::METRICS;

/// Bounded request classes used for admission fairness and metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BcryptWorkload {
    Login,
    Pin,
    Signup,
    Claim,
    Account,
    OAuth,
    Signer,
    Background,
}

impl BcryptWorkload {
    pub(crate) const ALL: [Self; 8] = [
        Self::Login,
        Self::Pin,
        Self::Signup,
        Self::Claim,
        Self::Account,
        Self::OAuth,
        Self::Signer,
        Self::Background,
    ];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Login => 0,
            Self::Pin => 1,
            Self::Signup => 2,
            Self::Claim => 3,
            Self::Account => 4,
            Self::OAuth => 5,
            Self::Signer => 6,
            Self::Background => 7,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Pin => "pin",
            Self::Signup => "signup",
            Self::Claim => "claim",
            Self::Account => "account",
            Self::OAuth => "oauth",
            Self::Signer => "signer",
            Self::Background => "background",
        }
    }
}

/// Bcrypt operations exposed as bounded metric labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BcryptOperation {
    Hash,
    Verify,
    Dummy,
}

impl BcryptOperation {
    pub(crate) const ALL: [Self; 3] = [Self::Hash, Self::Verify, Self::Dummy];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Hash => 0,
            Self::Verify => 1,
            Self::Dummy => 2,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Verify => "verify",
            Self::Dummy => "dummy",
        }
    }
}

/// A bcrypt operation failed before producing its normal result.
#[derive(Debug, thiserror::Error)]
pub enum BcryptAdmissionError {
    /// The bounded wait or concurrency capacity is occupied.
    #[error("bcrypt admission is at capacity")]
    AtCapacity,
    /// Admission is closed for graceful shutdown.
    #[error("bcrypt admission is shutting down")]
    ShuttingDown,
    /// Tokio's blocking worker failed.
    #[error("bcrypt blocking worker failed")]
    WorkerFailed,
    /// bcrypt rejected the input or cost.
    #[error("bcrypt operation failed")]
    Bcrypt(#[from] bcrypt::BcryptError),
}

#[derive(Debug, Default)]
struct LifecycleState {
    shutting_down: bool,
    active: usize,
}

struct Inner {
    permits: Arc<Semaphore>,
    wait_slots: [Arc<Semaphore>; BcryptWorkload::ALL.len()],
    permit_wait: Duration,
    lifecycle: Mutex<LifecycleState>,
    idle: Notify,
}

/// Same-class waiters allowed after the shared CPU slots are full.
///
/// Two waiters absorb a double-submit plus one sibling without letting one
/// class dominate the FIFO permit queue. Depth 1 sheds that sibling
/// immediately. A much larger depth would let login starve PIN, signup, and
/// claim once those waiters share the same semaphore.
pub const PER_CLASS_WAIT_DEPTH: usize = 2;

/// One process-wide concurrency and waiting boundary for bcrypt.
#[derive(Clone)]
pub struct BcryptAdmission {
    inner: Arc<Inner>,
}

impl fmt::Debug for BcryptAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BcryptAdmission")
            .field("available_permits", &self.inner.permits.available_permits())
            .field("permit_wait", &self.inner.permit_wait)
            .finish_non_exhaustive()
    }
}

impl BcryptAdmission {
    /// Create one admission domain with bounded concurrency and per-class waiting.
    #[must_use]
    pub fn new(max_concurrency: usize, permit_wait: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                permits: Arc::new(Semaphore::new(max_concurrency.max(1))),
                wait_slots: std::array::from_fn(|_| Arc::new(Semaphore::new(PER_CLASS_WAIT_DEPTH))),
                permit_wait,
                lifecycle: Mutex::new(LifecycleState::default()),
                idle: Notify::new(),
            }),
        }
    }

    /// Hash a secret inside the shared blocking-work boundary.
    pub async fn hash(
        &self,
        workload: BcryptWorkload,
        secret: SecretString,
        cost: u32,
    ) -> Result<String, BcryptAdmissionError> {
        self.reserve(workload, BcryptOperation::Hash)
            .await?
            .hash(secret, cost)
            .await
    }

    /// Verify a secret inside the shared blocking-work boundary.
    pub async fn verify(
        &self,
        workload: BcryptWorkload,
        candidate: SecretString,
        stored_hash: String,
    ) -> Result<bool, BcryptAdmissionError> {
        self.reserve(workload, BcryptOperation::Verify)
            .await?
            .verify(candidate, stored_hash)
            .await
    }

    /// Spend one bcrypt hash without retaining its output.
    pub async fn burn_dummy(
        &self,
        workload: BcryptWorkload,
        cost: u32,
    ) -> Result<(), BcryptAdmissionError> {
        self.reserve(workload, BcryptOperation::Dummy)
            .await?
            .burn_dummy(cost)
            .await
    }

    /// Reserve CPU capacity before acquiring downstream state.
    pub async fn reserve(
        &self,
        workload: BcryptWorkload,
        operation: BcryptOperation,
    ) -> Result<BcryptPermit, BcryptAdmissionError> {
        self.acquire(workload, operation).await
    }

    /// Reject new and queued work without waiting for accepted work to finish.
    pub fn close(&self) {
        {
            let mut lifecycle = self
                .inner
                .lifecycle
                .lock()
                .expect("bcrypt lifecycle lock poisoned");
            lifecycle.shutting_down = true;
        }
        self.inner.permits.close();
        for wait_slot in &self.inner.wait_slots {
            wait_slot.close();
        }
    }

    /// Reject new and queued work, then wait for all accepted work to release admission.
    pub async fn shutdown(&self) {
        self.close();

        loop {
            let idle = self.inner.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self
                .inner
                .lifecycle
                .lock()
                .expect("bcrypt lifecycle lock poisoned")
                .active
                == 0
            {
                return;
            }
            idle.await;
        }
    }

    #[cfg(test)]
    async fn run<T, F>(
        &self,
        workload: BcryptWorkload,
        operation: BcryptOperation,
        work: F,
    ) -> Result<T, BcryptAdmissionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.acquire(workload, operation).await?.run(work).await
    }

    async fn acquire(
        &self,
        workload: BcryptWorkload,
        operation: BcryptOperation,
    ) -> Result<BcryptPermit, BcryptAdmissionError> {
        if self.is_shutting_down() {
            METRICS.inc_bcrypt_rejection(workload, operation, true);
            return Err(BcryptAdmissionError::ShuttingDown);
        }

        let permit = if workload == BcryptWorkload::Background {
            Arc::clone(&self.inner.permits)
                .try_acquire_owned()
                .map_err(|_| {
                    let shutting_down = self.inner.permits.is_closed();
                    METRICS.inc_bcrypt_rejection(workload, operation, shutting_down);
                    if shutting_down {
                        BcryptAdmissionError::ShuttingDown
                    } else {
                        BcryptAdmissionError::AtCapacity
                    }
                })?
        } else if let Ok(permit) = Arc::clone(&self.inner.permits).try_acquire_owned() {
            permit
        } else {
            if self.inner.permits.is_closed() {
                METRICS.inc_bcrypt_rejection(workload, operation, true);
                return Err(BcryptAdmissionError::ShuttingDown);
            }
            let wait_slot = Arc::clone(&self.inner.wait_slots[workload.index()])
                .try_acquire_owned()
                .map_err(|error| {
                    let shutting_down = matches!(error, TryAcquireError::Closed);
                    METRICS.inc_bcrypt_rejection(workload, operation, shutting_down);
                    if shutting_down {
                        BcryptAdmissionError::ShuttingDown
                    } else {
                        BcryptAdmissionError::AtCapacity
                    }
                })?;
            let waiting = WaitingMetricGuard::new(workload, operation);
            let acquired = tokio::time::timeout(
                self.inner.permit_wait,
                Arc::clone(&self.inner.permits).acquire_owned(),
            )
            .await;
            drop(waiting);
            drop(wait_slot);
            match acquired {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => {
                    METRICS.inc_bcrypt_rejection(workload, operation, true);
                    return Err(BcryptAdmissionError::ShuttingDown);
                }
                Err(_) => {
                    METRICS.inc_bcrypt_rejection(workload, operation, false);
                    return Err(BcryptAdmissionError::AtCapacity);
                }
            }
        };

        let mut lifecycle = self
            .inner
            .lifecycle
            .lock()
            .expect("bcrypt lifecycle lock poisoned");
        if lifecycle.shutting_down {
            drop(lifecycle);
            drop(permit);
            METRICS.inc_bcrypt_rejection(workload, operation, true);
            return Err(BcryptAdmissionError::ShuttingDown);
        }
        lifecycle.active += 1;
        drop(lifecycle);
        METRICS.inc_bcrypt_active(workload, operation);

        Ok(BcryptPermit {
            _permit: permit,
            inner: Arc::clone(&self.inner),
            workload,
            operation,
        })
    }

    fn is_shutting_down(&self) -> bool {
        self.inner
            .lifecycle
            .lock()
            .expect("bcrypt lifecycle lock poisoned")
            .shutting_down
    }
}

struct WaitingMetricGuard {
    workload: BcryptWorkload,
    operation: BcryptOperation,
}

impl WaitingMetricGuard {
    fn new(workload: BcryptWorkload, operation: BcryptOperation) -> Self {
        METRICS.inc_bcrypt_waiting(workload, operation);
        Self {
            workload,
            operation,
        }
    }
}

impl Drop for WaitingMetricGuard {
    fn drop(&mut self) {
        METRICS.dec_bcrypt_waiting(self.workload, self.operation);
    }
}

/// Capacity reserved for one bcrypt operation.
pub struct BcryptPermit {
    _permit: OwnedSemaphorePermit,
    inner: Arc<Inner>,
    workload: BcryptWorkload,
    operation: BcryptOperation,
}

impl fmt::Debug for BcryptPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BcryptPermit")
            .field("workload", &self.workload)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

impl BcryptPermit {
    /// Hash one secret and retain capacity until the blocking closure finishes.
    pub async fn hash(
        self,
        secret: SecretString,
        cost: u32,
    ) -> Result<String, BcryptAdmissionError> {
        self.run(move || bcrypt::hash(secret.expose_secret(), cost))
            .await?
            .map_err(Into::into)
    }

    /// Verify one secret and retain capacity until the blocking closure finishes.
    pub async fn verify(
        self,
        candidate: SecretString,
        stored_hash: String,
    ) -> Result<bool, BcryptAdmissionError> {
        self.run(move || bcrypt::verify(candidate.expose_secret(), &stored_hash))
            .await?
            .map_err(Into::into)
    }

    /// Execute a dummy hash and retain capacity until it finishes.
    pub async fn burn_dummy(self, cost: u32) -> Result<(), BcryptAdmissionError> {
        self.run(move || bcrypt::hash("dummy", cost).map(|_| ()))
            .await?
            .map_err(Into::into)
    }

    async fn run<T, F>(self, work: F) -> Result<T, BcryptAdmissionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let result = work();
            drop(self);
            result
        })
        .await
        .map_err(|_| BcryptAdmissionError::WorkerFailed)
    }
}

impl Drop for BcryptPermit {
    fn drop(&mut self) {
        METRICS.dec_bcrypt_active(self.workload, self.operation);
        let mut lifecycle = self
            .inner
            .lifecycle
            .lock()
            .expect("bcrypt lifecycle lock poisoned");
        lifecycle.active -= 1;
        let is_idle = lifecycle.active == 0;
        drop(lifecycle);
        if is_idle {
            self.inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn all_workloads_share_one_active_bound() {
        let admission = BcryptAdmission::new(2, Duration::from_secs(1));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        let (background_started_tx, background_started_rx) = tokio::sync::oneshot::channel();
        let (background_finish_tx, background_finish_rx) = std::sync::mpsc::channel();
        let background_admission = admission.clone();
        let background_active = Arc::clone(&active);
        let background_maximum = Arc::clone(&maximum);
        tasks.spawn(async move {
            background_admission
                .run(
                    BcryptWorkload::Background,
                    BcryptOperation::Hash,
                    move || {
                        let current = background_active.fetch_add(1, Ordering::SeqCst) + 1;
                        background_maximum.fetch_max(current, Ordering::SeqCst);
                        background_started_tx.send(()).expect("signal start");
                        background_finish_rx.recv().expect("finish background");
                        background_active.fetch_sub(1, Ordering::SeqCst);
                    },
                )
                .await
                .expect("admit background work");
        });
        background_started_rx
            .await
            .expect("background work started");

        for workload in BcryptWorkload::ALL
            .into_iter()
            .filter(|workload| *workload != BcryptWorkload::Background)
        {
            let admission = admission.clone();
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            tasks.spawn(async move {
                admission
                    .run(workload, BcryptOperation::Hash, move || {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum.fetch_max(current, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        active.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                    .expect("admit work");
            });
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        background_finish_tx.send(()).expect("finish background");

        while let Some(result) = tasks.join_next().await {
            result.expect("work task");
        }
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn request_classes_make_progress_under_cross_class_contention() {
        let admission = BcryptAdmission::new(1, Duration::from_secs(1));
        let first = admission
            .acquire(BcryptWorkload::Account, BcryptOperation::Hash)
            .await
            .expect("occupy capacity");
        let mut tasks = tokio::task::JoinSet::new();
        for workload in [
            BcryptWorkload::Login,
            BcryptWorkload::Pin,
            BcryptWorkload::Signup,
            BcryptWorkload::Claim,
        ] {
            let admission = admission.clone();
            tasks.spawn(async move {
                admission
                    .run(workload, BcryptOperation::Verify, || ())
                    .await
            });
        }
        tokio::task::yield_now().await;
        drop(first);

        let mut completed = 0;
        while let Some(result) = tasks.join_next().await {
            result.expect("work task").expect("request admitted");
            completed += 1;
        }
        assert_eq!(completed, 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_class_wait_depth_admits_the_bound_and_sheds_the_rest() {
        let admission = BcryptAdmission::new(1, Duration::from_secs(5));
        let held = admission
            .acquire(BcryptWorkload::Login, BcryptOperation::Hash)
            .await
            .expect("occupy capacity");

        let mut waiters = tokio::task::JoinSet::new();
        for _ in 0..PER_CLASS_WAIT_DEPTH {
            let admission = admission.clone();
            waiters.spawn(async move {
                admission
                    .acquire(BcryptWorkload::Login, BcryptOperation::Verify)
                    .await
            });
        }
        tokio::time::sleep(Duration::from_millis(30)).await;

        let started = std::time::Instant::now();
        let shed = admission
            .acquire(BcryptWorkload::Login, BcryptOperation::Dummy)
            .await
            .expect_err("same-class burst beyond the wait depth must shed");
        assert!(matches!(shed, BcryptAdmissionError::AtCapacity));
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "excess same-class work must shed without waiting for a permit"
        );

        drop(held);
        let mut admitted = 0;
        while let Some(result) = waiters.join_next().await {
            result.expect("waiter task").expect("waiter admitted");
            admitted += 1;
        }
        assert_eq!(admitted, PER_CLASS_WAIT_DEPTH);
    }

    #[tokio::test]
    async fn background_never_queues_ahead_of_request_work() {
        let admission = BcryptAdmission::new(1, Duration::from_secs(1));
        let held = admission
            .acquire(BcryptWorkload::Account, BcryptOperation::Hash)
            .await
            .expect("occupy capacity");
        let background = admission
            .acquire(BcryptWorkload::Background, BcryptOperation::Hash)
            .await
            .expect_err("background must yield while capacity is occupied");
        assert!(matches!(background, BcryptAdmissionError::AtCapacity));

        let request_admission = admission.clone();
        let request = tokio::spawn(async move {
            request_admission
                .run(BcryptWorkload::Login, BcryptOperation::Verify, || ())
                .await
        });
        tokio::task::yield_now().await;
        drop(held);
        request
            .await
            .expect("request task")
            .expect("request admitted");
    }

    #[tokio::test]
    async fn cancellation_retains_capacity_until_blocking_work_finishes() {
        let admission = BcryptAdmission::new(1, Duration::from_millis(10));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let running = admission.clone();
        let task = tokio::spawn(async move {
            running
                .run(BcryptWorkload::Login, BcryptOperation::Verify, move || {
                    started_tx.send(()).expect("signal start");
                    std::thread::sleep(Duration::from_millis(100));
                })
                .await
        });
        started_rx.await.expect("blocking work started");
        task.abort();

        let rejected = admission
            .acquire(BcryptWorkload::Pin, BcryptOperation::Verify)
            .await
            .expect_err("running work retains capacity");
        assert!(matches!(rejected, BcryptAdmissionError::AtCapacity));
        tokio::time::sleep(Duration::from_millis(110)).await;
        admission
            .acquire(BcryptWorkload::Pin, BcryptOperation::Verify)
            .await
            .expect("capacity returns after blocking work");
    }

    #[tokio::test]
    async fn shutdown_rejects_queued_work_and_waits_for_running_work() {
        let admission = BcryptAdmission::new(1, Duration::from_secs(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let running = admission.clone();
        let task = tokio::spawn(async move {
            running
                .run(BcryptWorkload::Login, BcryptOperation::Verify, move || {
                    started_tx.send(()).expect("signal start");
                    finish_rx.recv().expect("finish signal");
                })
                .await
        });
        started_rx.await.expect("blocking work started");

        let queued_admission = admission.clone();
        let queued = tokio::spawn(async move {
            queued_admission
                .run(BcryptWorkload::Pin, BcryptOperation::Verify, || ())
                .await
        });
        tokio::task::yield_now().await;
        let shutdown_admission = admission.clone();
        let mut shutdown = tokio::spawn(async move { shutdown_admission.shutdown().await });

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err()
        );
        assert!(matches!(
            queued.await.expect("queued task"),
            Err(BcryptAdmissionError::ShuttingDown)
        ));
        assert!(matches!(
            admission
                .acquire(BcryptWorkload::Claim, BcryptOperation::Hash)
                .await,
            Err(BcryptAdmissionError::ShuttingDown)
        ));

        finish_tx.send(()).expect("finish work");
        task.await.expect("running task").expect("running work");
        shutdown.await.expect("shutdown task");
    }
}
