// ABOUTME: Pre-computed secret pool for zero-latency authorization creation
// ABOUTME: Background producer generates (secret, bcrypt_hash) pairs ahead of time

use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};
use rand::Rng;
use secrecy::SecretString;

use crate::bcrypt_admission::{BcryptAdmission, BcryptAdmissionError, BcryptWorkload};

/// Default pool capacity - enough for typical burst while limiting memory usage
const DEFAULT_POOL_CAPACITY: usize = 100;

/// Bcrypt cost factor for secret hashing
/// Cost 10 = ~100ms per hash on modern CPU (good balance of security vs performance)
const BCRYPT_COST: u32 = 10;

/// Length of generated secrets (48 alphanumeric chars = ~284 bits entropy)
const SECRET_LENGTH: usize = 48;

/// How long [`SecretPoolReceiver::get`] waits for a produced secret pair.
///
/// Background hashing yields to request work, so an empty pool during a login
/// storm may never refill. One second matches bcrypt admission's permit wait:
/// long enough for one cost-10 hash if a CPU slot frees, then a retryable
/// overload instead of an unbounded recv. Do not reserve a background CPU
/// slot; that would cut request hashing capacity on the serving instances.
pub const SECRET_POOL_GET_TIMEOUT: Duration = Duration::from_secs(1);

/// Pre-computed (secret, hash) pair
pub struct SecretPair {
    /// The plaintext secret (to be included in bunker URL)
    pub secret: SecretString,
    /// The bcrypt hash (to be stored in database)
    pub hash: String,
}

/// Pre-computed secret pool with background producer
///
/// The producer continuously generates (secret, bcrypt_hash) pairs in the background.
/// Consumers (authorization endpoints) pop from the pool for instant authorization creation.
pub struct SecretPool {
    tx: Sender<SecretPair>,
    rx: Receiver<SecretPair>,
}

impl SecretPool {
    /// Create a new secret pool with the given capacity
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = bounded(capacity);
        Self { tx, rx }
    }

    /// Get a receiver handle that can be cloned and shared across handlers
    pub fn receiver(&self) -> SecretPoolReceiver {
        SecretPoolReceiver {
            rx: self.rx.clone(),
        }
    }

    /// Spawn the background producer task
    ///
    /// The producer generates secrets, hashes them with bcrypt, and pushes to the pool.
    /// When the pool is full, the producer blocks (backpressure).
    /// Returns when the channel is closed (pool dropped).
    pub fn spawn_producer(&self, bcrypt: BcryptAdmission) -> tokio::task::JoinHandle<()> {
        let tx = self.tx.clone();

        tokio::spawn(async move {
            tracing::info!(
                "Secret pool producer started (capacity: {}, bcrypt cost: {})",
                DEFAULT_POOL_CAPACITY,
                BCRYPT_COST
            );

            loop {
                // Generate random secret
                let secret: String = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(SECRET_LENGTH)
                    .map(char::from)
                    .collect();

                let secret_hash = match bcrypt
                    .hash(
                        BcryptWorkload::Background,
                        SecretString::from(secret.clone()),
                        BCRYPT_COST,
                    )
                    .await
                {
                    Ok(hash) => hash,
                    Err(BcryptAdmissionError::AtCapacity) => {
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                        continue;
                    }
                    Err(BcryptAdmissionError::ShuttingDown) => break,
                    Err(e) => {
                        tracing::error!("Secret pool producer: bcrypt error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let pair = SecretPair {
                    secret: SecretString::from(secret),
                    hash: secret_hash,
                };

                // Keep backpressure async so a full pool never parks one of
                // Tokio's shared blocking workers.
                let mut pending = pair;
                loop {
                    match tx.try_send(pending) {
                        Ok(()) => break,
                        Err(TrySendError::Full(pair)) => {
                            pending = pair;
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            tracing::info!("Secret pool producer shutting down (channel closed)");
                            return;
                        }
                    }
                }
            }

            tracing::info!("Secret pool producer exited");
        })
    }

    /// Get current pool size (approximate, for metrics)
    pub fn len(&self) -> usize {
        self.rx.len()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }
}

impl Default for SecretPool {
    fn default() -> Self {
        Self::new(DEFAULT_POOL_CAPACITY)
    }
}

/// Cloneable receiver handle for the secret pool
///
/// Multiple handlers can hold clones of this receiver.
/// Each `get()` call returns a unique (secret, hash) pair to exactly one caller.
#[derive(Clone)]
pub struct SecretPoolReceiver {
    rx: Receiver<SecretPair>,
}

impl SecretPoolReceiver {
    /// Get a pre-computed (secret, hash) pair from the pool.
    ///
    /// Waits up to [`SECRET_POOL_GET_TIMEOUT`] when the pool is empty.
    /// Times out as [`SecretPoolError::Exhausted`] so callers can return a
    /// retryable overload instead of parking the request. A closed pool
    /// returns [`SecretPoolError::Closed`].
    pub async fn get(&self) -> Result<SecretPair, SecretPoolError> {
        let deadline = tokio::time::Instant::now() + SECRET_POOL_GET_TIMEOUT;
        loop {
            match self.rx.try_recv() {
                Ok(pair) => return Ok(pair),
                Err(TryRecvError::Disconnected) => return Err(SecretPoolError::Closed),
                Err(TryRecvError::Empty) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(SecretPoolError::Exhausted);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Try to get a pair without blocking
    ///
    /// Returns None if pool is empty or closed.
    /// Useful for fallback scenarios where you want to hash inline if pool is empty.
    pub fn try_get(&self) -> Option<SecretPair> {
        match self.rx.try_recv() {
            Ok(pair) => Some(pair),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }

    /// Get current pool size (approximate, for metrics/debugging)
    pub fn len(&self) -> usize {
        self.rx.len()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }
}

/// Error type for secret pool operations
#[derive(Debug, thiserror::Error)]
pub enum SecretPoolError {
    #[error("Secret pool exhausted - server at capacity")]
    Exhausted,
    #[error("Secret pool closed - server shutting down")]
    Closed,
}

/// Verify a provided secret against a stored hash
///
/// Uses bcrypt::verify which is constant-time internally.
/// Returns true if the secret matches the hash.
pub async fn verify_secret(
    bcrypt: &BcryptAdmission,
    provided_secret: &str,
    stored_hash: &str,
) -> Result<bool, BcryptAdmissionError> {
    bcrypt
        .verify(
            BcryptWorkload::Signer,
            SecretString::from(provided_secret.to_string()),
            stored_hash.to_string(),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_secret_pool_creation() {
        let pool = SecretPool::new(10);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_receiver_clone() {
        let pool = SecretPool::new(10);
        let receiver1 = pool.receiver();
        let receiver2 = receiver1.clone();

        // Both receivers should see the same pool state
        assert!(receiver1.is_empty());
        assert!(receiver2.is_empty());
    }

    #[tokio::test]
    async fn test_verify_secret_wrong_secret() {
        let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
        let pool = SecretPool::new(1);
        let receiver = pool.receiver();
        let producer_handle = pool.spawn_producer(bcrypt.clone());
        let pair = receiver.get().await.unwrap();

        // Wrong secret should fail
        assert!(!verify_secret(&bcrypt, "wrong_secret", &pair.hash)
            .await
            .unwrap());

        drop(receiver);
        drop(pool);
        tokio::time::timeout(std::time::Duration::from_secs(5), producer_handle)
            .await
            .expect("Producer should exit within timeout")
            .expect("Producer should not panic");
    }

    #[tokio::test]
    async fn test_pool_producer_and_consumer() {
        let pool = SecretPool::new(5);
        let receiver = pool.receiver();
        let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));

        // Start producer
        let producer_handle = pool.spawn_producer(bcrypt.clone());

        // Wait a bit for producer to fill pool (bcrypt is slow)
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        // Pool should have some items
        assert!(!receiver.is_empty());

        // Get a pair
        let pair = receiver.get().await.unwrap();
        assert_eq!(pair.secret.expose_secret().len(), SECRET_LENGTH);
        assert!(pair.hash.starts_with("$2"));

        // Verify works
        assert!(
            verify_secret(&bcrypt, pair.secret.expose_secret(), &pair.hash)
                .await
                .unwrap()
        );

        // Cleanup - must drop receiver first so channel disconnects
        drop(receiver);
        drop(pool);

        // Producer should exit when channel disconnects (with timeout)
        tokio::time::timeout(std::time::Duration::from_secs(5), producer_handle)
            .await
            .expect("Producer should exit within timeout")
            .expect("Producer should not panic");
    }

    #[tokio::test]
    async fn get_times_out_when_the_producer_never_refills() {
        let pool = SecretPool::new(1);
        let receiver = pool.receiver();
        let started = std::time::Instant::now();

        let error = match receiver.get().await {
            Ok(_) => panic!("an empty live pool must not return a pair"),
            Err(error) => error,
        };
        assert!(matches!(error, SecretPoolError::Exhausted));
        assert!(started.elapsed() >= SECRET_POOL_GET_TIMEOUT);
        assert!(started.elapsed() < SECRET_POOL_GET_TIMEOUT + Duration::from_millis(500));
    }

    #[tokio::test]
    async fn get_reports_closed_when_the_pool_is_dropped() {
        let pool = SecretPool::new(1);
        let receiver = pool.receiver();
        drop(pool);

        let error = match receiver.get().await {
            Ok(_) => panic!("a disconnected pool must not return a pair"),
            Err(error) => error,
        };
        assert!(matches!(error, SecretPoolError::Closed));
    }
}
