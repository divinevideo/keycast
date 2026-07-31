//! Runs request/response password verification without starving async workers.

use std::{fmt, sync::Arc, time::Duration};

/// A bounded password-verification admission failure.
#[derive(Debug, thiserror::Error)]
pub enum PasswordVerificationError {
    /// All verifier capacity remained occupied through the admission deadline.
    #[error("password verifier is at capacity")]
    AtCapacity,
    /// The blocking worker failed before returning a result.
    #[error("password verification worker failed")]
    WorkerFailed,
    /// The verifier is shutting down.
    #[error("password verifier is shutting down")]
    ShuttingDown,
    /// bcrypt rejected the stored hash.
    #[error("password verification failed")]
    Bcrypt(#[from] bcrypt::BcryptError),
}

/// Bounds concurrent password verification.
#[derive(Clone)]
pub struct PasswordVerifier {
    permits: Arc<tokio::sync::Semaphore>,
    permit_wait: Duration,
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordVerifier")
            .field("available_permits", &self.permits.available_permits())
            .field("permit_wait", &self.permit_wait)
            .finish()
    }
}

impl PasswordVerifier {
    /// Create a verifier with bounded concurrency and admission wait.
    #[must_use]
    pub fn new(max_concurrency: usize, permit_wait: Duration) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrency.max(1))),
            permit_wait,
        }
    }

    /// Acquire capacity before reserving any downstream resources.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordVerificationError::AtCapacity`] when capacity does not
    /// become available before `permit_wait`.
    pub async fn acquire(&self) -> Result<PasswordVerificationPermit, PasswordVerificationError> {
        let permit =
            tokio::time::timeout(self.permit_wait, Arc::clone(&self.permits).acquire_owned())
                .await
                .map_err(|_| PasswordVerificationError::AtCapacity)?
                .map_err(|_| PasswordVerificationError::ShuttingDown)?;
        Ok(PasswordVerificationPermit { permit })
    }
}

/// Capacity for one blocking password verification.
pub struct PasswordVerificationPermit {
    permit: tokio::sync::OwnedSemaphorePermit,
}

impl fmt::Debug for PasswordVerificationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordVerificationPermit")
            .field("permit", &"<held>")
            .finish_non_exhaustive()
    }
}

impl PasswordVerificationPermit {
    /// Verify one password on the blocking worker pool.
    ///
    /// # Errors
    ///
    /// Returns an error when bcrypt rejects the hash or the worker fails.
    pub async fn verify(
        self,
        password: String,
        password_hash: String,
    ) -> Result<bool, PasswordVerificationError> {
        self.run_blocking(move || bcrypt::verify(password, &password_hash))
            .await?
            .map_err(Into::into)
    }

    async fn run_blocking<T, F>(self, operation: F) -> Result<T, PasswordVerificationError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = self.permit;
        tokio::task::spawn_blocking(move || {
            let result = operation();
            drop(permit);
            result
        })
        .await
        .map_err(|_| PasswordVerificationError::WorkerFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_blocking_work_never_exceeds_the_permit_bound() {
        let verifier = PasswordVerifier::new(2, Duration::from_secs(1));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..8 {
            let verifier = verifier.clone();
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            tasks.spawn(async move {
                let permit = verifier.acquire().await.expect("acquire verifier");
                permit
                    .run_blocking(move || {
                        let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum.fetch_max(now_active, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(25));
                        active.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                    .expect("blocking work");
            });
        }

        while let Some(result) = tasks.join_next().await {
            result.expect("verification task");
        }

        assert_eq!(maximum.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn occupied_capacity_load_sheds_after_the_wait_bound() {
        let verifier = PasswordVerifier::new(1, Duration::from_millis(10));
        let held = verifier.acquire().await.expect("first permit");

        let error = verifier
            .acquire()
            .await
            .expect_err("second admission must load-shed");
        assert!(matches!(error, PasswordVerificationError::AtCapacity));

        drop(held);
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_release_a_still_running_blocking_job() {
        let verifier = PasswordVerifier::new(1, Duration::from_millis(10));
        let permit = verifier.acquire().await.expect("first permit");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            permit
                .run_blocking(move || {
                    started_tx.send(()).expect("signal blocking start");
                    std::thread::sleep(Duration::from_millis(100));
                })
                .await
        });
        started_rx.await.expect("blocking job started");
        task.abort();

        let error = verifier
            .acquire()
            .await
            .expect_err("detached blocking work must retain its permit");
        assert!(matches!(error, PasswordVerificationError::AtCapacity));

        tokio::time::sleep(Duration::from_millis(110)).await;
        verifier
            .acquire()
            .await
            .expect("permit returns when blocking work actually finishes");
    }
}
