// ABOUTME: Pre-computed secret pool for zero-latency authorization creation
// ABOUTME: Background producer generates (secret, bcrypt_hash) pairs ahead of time

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
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

                // Send to pool - blocks if full (backpressure)
                // Use spawn_blocking since crossbeam send is sync
                let tx_clone = tx.clone();
                let send_result = tokio::task::spawn_blocking(move || tx_clone.send(pair)).await;

                match send_result {
                    Ok(Ok(())) => {
                        // Successfully added to pool
                    }
                    Ok(Err(_)) => {
                        // Channel disconnected - pool dropped, shutdown
                        tracing::info!("Secret pool producer shutting down (channel closed)");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("Secret pool producer: spawn_blocking panicked: {}", e);
                        break;
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
    /// Get a pre-computed (secret, hash) pair from the pool
    ///
    /// Blocks if pool is empty (waits for producer to generate more).
    /// Returns None if the pool is closed (shutdown).
    pub async fn get(&self) -> Option<SecretPair> {
        let rx = self.rx.clone();
        tokio::task::spawn_blocking(move || rx.recv().ok())
            .await
            .ok()
            .flatten()
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

/// Utility function to generate a secret and hash it inline (for fallback/migration)
///
/// This is slower than using the pool but useful for:
/// - Fallback when pool is empty
/// - Migration scripts that need to hash existing secrets
/// - Tests
pub async fn generate_secret_hash_inline(
    bcrypt: &BcryptAdmission,
) -> Result<SecretPair, BcryptAdmissionError> {
    let secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(SECRET_LENGTH)
        .map(char::from)
        .collect();

    let hash = bcrypt
        .hash(
            BcryptWorkload::OAuth,
            SecretString::from(secret.clone()),
            BCRYPT_COST,
        )
        .await?;
    Ok(SecretPair {
        secret: SecretString::from(secret),
        hash,
    })
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
    async fn test_generate_secret_hash_inline() {
        let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
        let pair = generate_secret_hash_inline(&bcrypt).await.unwrap();

        // Secret should be the expected length
        assert_eq!(pair.secret.expose_secret().len(), SECRET_LENGTH);

        // Hash should be a valid bcrypt hash (starts with $2b$ or similar)
        assert!(pair.hash.starts_with("$2"));

        // Verify should succeed
        assert!(
            verify_secret(&bcrypt, pair.secret.expose_secret(), &pair.hash)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_verify_secret_wrong_secret() {
        let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
        let pair = generate_secret_hash_inline(&bcrypt).await.unwrap();

        // Wrong secret should fail
        assert!(!verify_secret(&bcrypt, "wrong_secret", &pair.hash)
            .await
            .unwrap());
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
}
