use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const DEFAULT_KMS_CONCURRENCY: usize = 16;

static KMS_PERMITS: Lazy<Arc<Semaphore>> = Lazy::new(|| {
    let capacity = std::env::var("KMS_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_KMS_CONCURRENCY);
    Arc::new(Semaphore::new(capacity))
});
static KMS_ACTIVE: AtomicU64 = AtomicU64::new(0);
static KMS_REJECTIONS: AtomicU64 = AtomicU64::new(0);

/// Applies one process-wide operation-scoped concurrency boundary to every
/// key-manager implementation used by the API and signer.
pub struct BoundedKeyManager {
    inner: Box<dyn KeyManager>,
}

impl BoundedKeyManager {
    pub fn new(inner: Box<dyn KeyManager>) -> Self {
        Self { inner }
    }

    fn admit() -> Result<KmsPermit, KeyManagerError> {
        let permit = KMS_PERMITS.clone().try_acquire_owned().map_err(|_| {
            KMS_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            KeyManagerError::AtCapacity
        })?;
        KMS_ACTIVE.fetch_add(1, Ordering::Relaxed);
        Ok(KmsPermit { _permit: permit })
    }
}

struct KmsPermit {
    _permit: OwnedSemaphorePermit,
}

impl Drop for KmsPermit {
    fn drop(&mut self) {
        KMS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn active() -> u64 {
    KMS_ACTIVE.load(Ordering::Relaxed)
}

pub fn rejections() -> u64 {
    KMS_REJECTIONS.load(Ordering::Relaxed)
}

#[async_trait]
impl KeyManager for BoundedKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let _permit = Self::admit()?;
        self.inner.encrypt(plaintext_bytes).await
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        let _permit = Self::admit()?;
        self.inner.decrypt(ciphertext_bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Notify;

    struct BlockingKeyManager {
        started: AtomicUsize,
        release: Notify,
    }

    #[async_trait]
    impl KeyManager for BlockingKeyManager {
        async fn encrypt(&self, _: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Ok(Vec::new())
        }

        async fn decrypt(&self, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn sheds_only_while_kms_operations_are_in_flight() {
        let inner = Arc::new(BlockingKeyManager {
            started: AtomicUsize::new(0),
            release: Notify::new(),
        });
        let manager = Arc::new(BoundedKeyManager::new(Box::new(SharedManager(
            inner.clone(),
        ))));

        let mut tasks = Vec::new();
        for _ in 0..DEFAULT_KMS_CONCURRENCY {
            let manager = manager.clone();
            tasks.push(tokio::spawn(async move { manager.encrypt(&[]).await }));
        }
        while inner.started.load(Ordering::SeqCst) < DEFAULT_KMS_CONCURRENCY {
            tokio::task::yield_now().await;
        }

        assert!(matches!(
            manager.encrypt(&[]).await,
            Err(KeyManagerError::AtCapacity)
        ));

        inner.release.notify_waiters();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }

    struct SharedManager(Arc<BlockingKeyManager>);

    #[async_trait]
    impl KeyManager for SharedManager {
        async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
            self.0.encrypt(plaintext).await
        }

        async fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
            self.0.decrypt(ciphertext).await
        }
    }
}
