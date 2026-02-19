// ABOUTME: Async bcrypt queue for high-scale signup handling
// ABOUTME: Defers password hashing to background workers, using email verification latency as natural buffer

use bcrypt::{hash, DEFAULT_COST};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;

/// Queue capacity for surge buffering
/// At cost 12 (~300ms/hash), 4 cores can process ~13 hashes/sec
/// 350 items = ~27 seconds of buffer at full throughput
const QUEUE_CAPACITY: usize = 350;

/// Job sent to worker pool - contains only what's needed to hash
pub struct BcryptJob {
    /// Email verification token (used to UPDATE the user row)
    pub token: String,
    /// Password wrapped in SecretString for automatic zeroization
    pub password: SecretString,
}

/// Async bcrypt queue for deferring password hashing to background workers
pub struct BcryptQueue {
    tx: Sender<BcryptJob>,
    rx: Receiver<BcryptJob>,
}

impl BcryptQueue {
    /// Create a new bcrypt queue with bounded capacity
    pub fn new() -> Self {
        let (tx, rx) = bounded(QUEUE_CAPACITY);
        Self { tx, rx }
    }

    /// Get a sender handle for queuing jobs
    pub fn sender(&self) -> BcryptSender {
        BcryptSender {
            tx: self.tx.clone(),
        }
    }

    /// Spawn bcrypt workers
    ///
    /// Worker count = CPU cores (bcrypt is CPU-bound)
    /// Each worker blocks on the channel and processes jobs sequentially
    pub fn spawn_workers(&self, pool: PgPool) -> Vec<tokio::task::JoinHandle<()>> {
        let num_workers = num_cpus::get();
        tracing::info!(
            "Spawning {} bcrypt workers (queue capacity: {})",
            num_workers,
            QUEUE_CAPACITY
        );

        (0..num_workers)
            .map(|worker_id| {
                let rx = self.rx.clone();
                let pool = pool.clone();

                tokio::spawn(async move {
                    bcrypt_worker_loop(worker_id, rx, pool).await;
                })
            })
            .collect()
    }
}

impl Default for BcryptQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Sender handle for the bcrypt queue
#[derive(Clone)]
pub struct BcryptSender {
    tx: Sender<BcryptJob>,
}

impl BcryptSender {
    /// Try to queue a bcrypt job
    /// Returns error if queue is full (backpressure) or disconnected
    pub fn try_send(&self, job: BcryptJob) -> Result<(), BcryptQueueError> {
        self.tx.try_send(job).map_err(|e| match e {
            TrySendError::Full(_) => BcryptQueueError::AtCapacity,
            TrySendError::Disconnected(_) => BcryptQueueError::ShuttingDown,
        })
    }

    /// Get current queue length (approximate, for metrics)
    pub fn len(&self) -> usize {
        self.tx.len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.tx.is_empty()
    }
}

/// Errors from bcrypt queue operations
#[derive(Debug, thiserror::Error)]
pub enum BcryptQueueError {
    #[error("Bcrypt queue is full - server at capacity")]
    AtCapacity,
    #[error("Bcrypt queue disconnected - server shutting down")]
    ShuttingDown,
}

/// Worker loop that processes bcrypt jobs from the queue
async fn bcrypt_worker_loop(worker_id: usize, rx: Receiver<BcryptJob>, pool: PgPool) {
    tracing::debug!("Bcrypt worker {} started", worker_id);

    loop {
        // Block on receiving next job (in spawn_blocking to not block async runtime)
        let job = {
            let rx = rx.clone();
            match tokio::task::spawn_blocking(move || rx.recv()).await {
                Ok(Ok(job)) => job,
                Ok(Err(_)) => {
                    // Channel disconnected - shutdown
                    tracing::info!("Bcrypt worker {} shutting down (channel closed)", worker_id);
                    break;
                }
                Err(e) => {
                    tracing::error!("Bcrypt worker {} spawn_blocking panicked: {}", worker_id, e);
                    continue;
                }
            }
        };

        let token = job.token.clone();

        // Hash password (CPU-bound operation)
        // SecretString auto-zeroizes when dropped after closure completes
        let hash_result = tokio::task::spawn_blocking({
            let password = job.password;
            move || {
                let result = hash(password.expose_secret(), DEFAULT_COST);
                // password (SecretString) dropped here, auto-zeroized
                result
            }
        })
        .await;

        let password_hash = match hash_result {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::error!(
                    "Bcrypt worker {}: hash error for token {}: {}",
                    worker_id,
                    &token[..8],
                    e
                );
                continue;
            }
            Err(e) => {
                tracing::error!(
                    "Bcrypt worker {}: spawn_blocking panicked for token {}: {}",
                    worker_id,
                    &token[..8],
                    e
                );
                continue;
            }
        };

        // Update user row with the hash
        let update_result = sqlx::query(
            "UPDATE users SET password_hash = $1, updated_at = NOW()
             WHERE email_verification_token = $2",
        )
        .bind(&password_hash)
        .bind(&token)
        .execute(&pool)
        .await;

        match update_result {
            Ok(result) => {
                if result.rows_affected() == 0 {
                    // Row was deleted (TTL cleanup) before we could update it
                    tracing::warn!(
                        "Bcrypt worker {}: no row found for token {} (likely expired)",
                        worker_id,
                        &token[..8]
                    );
                } else {
                    tracing::debug!(
                        "Bcrypt worker {}: updated password hash for token {}",
                        worker_id,
                        &token[..8]
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    "Bcrypt worker {}: DB update failed for token {}: {}",
                    worker_id,
                    &token[..8],
                    e
                );
            }
        }
    }

    tracing::debug!("Bcrypt worker {} exited", worker_id);
}

/// Spawn a cleanup task that periodically removes stale email signup rows
/// where the bcrypt hash was never computed (password_hash still NULL).
///
/// Only targets rows with email IS NOT NULL (email signups), excluding:
/// - Preloaded users (vine_id IS NOT NULL) awaiting account claim
/// - Pubkey-only users added to teams via find_or_create (no email)
pub fn spawn_cleanup_task(pool: PgPool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes

        loop {
            interval.tick().await;

            let result = sqlx::query(
                "DELETE FROM users WHERE password_hash IS NULL
                 AND vine_id IS NULL
                 AND email IS NOT NULL
                 AND created_at < NOW() - INTERVAL '10 minutes'",
            )
            .execute(&pool)
            .await;

            match result {
                Ok(result) => {
                    let deleted = result.rows_affected();
                    if deleted > 0 {
                        tracing::info!("Cleanup task: deleted {} stale signup rows", deleted);
                    }
                }
                Err(e) => {
                    tracing::error!("Cleanup task: failed to delete stale rows: {}", e);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_queue_creation() {
        let queue = BcryptQueue::new();
        let sender = queue.sender();
        assert!(sender.is_empty());
        assert_eq!(sender.len(), 0);
    }

    #[test]
    fn test_bcrypt_sender_clone() {
        let queue = BcryptQueue::new();
        let sender1 = queue.sender();
        let sender2 = sender1.clone();

        // Both senders should work with the same queue
        assert!(sender1.is_empty());
        assert!(sender2.is_empty());
    }

    #[test]
    fn test_queue_backpressure() {
        let (tx, _rx) = bounded::<BcryptJob>(2);
        let sender = BcryptSender { tx };

        // Fill the queue
        sender
            .try_send(BcryptJob {
                token: "token1".to_string(),
                password: SecretString::from("pass1".to_string()),
            })
            .unwrap();
        sender
            .try_send(BcryptJob {
                token: "token2".to_string(),
                password: SecretString::from("pass2".to_string()),
            })
            .unwrap();

        // Third should fail with AtCapacity
        let result = sender.try_send(BcryptJob {
            token: "token3".to_string(),
            password: SecretString::from("pass3".to_string()),
        });
        assert!(matches!(result, Err(BcryptQueueError::AtCapacity)));
    }
}
