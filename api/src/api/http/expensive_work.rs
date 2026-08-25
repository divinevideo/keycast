use once_cell::sync::Lazy;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const HTTP_BODY_LIMIT: usize = 64 * 1024;
pub const BATCH_LOOKUP_BODY_LIMIT: usize = 320 * 1024;

const REMOTE_FETCH_CAPACITY: usize = 16;

static REMOTE_FETCHES: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(REMOTE_FETCH_CAPACITY)));
static REMOTE_ACTIVE: AtomicU64 = AtomicU64::new(0);
static REMOTE_REJECTIONS: AtomicU64 = AtomicU64::new(0);

pub use keycast_core::bcrypt_admission::CpuAdmissionError as CpuWorkError;

/// Run CPU-heavy work inside the same process-wide boundary used by bcrypt.
pub async fn spawn_cpu<F, T>(
    admission: &keycast_core::bcrypt_admission::BcryptAdmission,
    job: F,
) -> Result<T, CpuWorkError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    admission.run_cpu(job).await
}

/// Admit one outbound fetch. Hold this permit only while the network operation
/// and its bounded response body are in flight.
pub fn admit_remote_fetch() -> Result<RemoteFetchPermit, RemoteFetchAtCapacity> {
    match REMOTE_FETCHES.clone().try_acquire_owned() {
        Ok(permit) => {
            REMOTE_ACTIVE.fetch_add(1, Ordering::Relaxed);
            Ok(RemoteFetchPermit { _permit: permit })
        }
        Err(_) => {
            REMOTE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            Err(RemoteFetchAtCapacity)
        }
    }
}

pub struct RemoteFetchPermit {
    _permit: OwnedSemaphorePermit,
}

impl Drop for RemoteFetchPermit {
    fn drop(&mut self) {
        REMOTE_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("remote fetch admission is at capacity")]
pub struct RemoteFetchAtCapacity;

pub fn prometheus_metrics() -> String {
    let cpu_active = keycast_core::bcrypt_admission::general_cpu_active();
    let cpu_rejections = keycast_core::bcrypt_admission::general_cpu_rejections();
    let kms_active = keycast_core::encryption::bounded_key_manager::active();
    let kms_rejections = keycast_core::encryption::bounded_key_manager::rejections();
    let authorization_active = keycast_core::secret_pool::active_waiters();
    let authorization_rejections = keycast_core::secret_pool::exhaustion_count();
    format!(
        "\n# HELP keycast_expensive_resource_active Current admitted expensive operations by resource\n\
# TYPE keycast_expensive_resource_active gauge\n\
keycast_expensive_resource_active{{resource=\"remote_fetch\"}} {}\n\
keycast_expensive_resource_active{{resource=\"cpu\"}} {}\n\
keycast_expensive_resource_active{{resource=\"kms\"}} {}\n\
keycast_expensive_resource_active{{resource=\"authorization\"}} {}\n\
# HELP keycast_expensive_resource_rejections_total Expensive operations rejected before work\n\
# TYPE keycast_expensive_resource_rejections_total counter\n\
keycast_expensive_resource_rejections_total{{resource=\"remote_fetch\",outcome=\"saturated\"}} {}\n\
keycast_expensive_resource_rejections_total{{resource=\"cpu\",outcome=\"saturated\"}} {}\n\
keycast_expensive_resource_rejections_total{{resource=\"kms\",outcome=\"saturated\"}} {}\n\
keycast_expensive_resource_rejections_total{{resource=\"authorization\",outcome=\"saturated\"}} {}\n",
        REMOTE_ACTIVE.load(Ordering::Relaxed),
        cpu_active,
        kms_active,
        authorization_active,
        REMOTE_REJECTIONS.load(Ordering::Relaxed),
        cpu_rejections,
        kms_rejections,
        authorization_rejections,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use keycast_core::bcrypt_admission::{BcryptAdmission, BcryptAdmissionError, BcryptWorkload};
    use secrecy::SecretString;
    use std::{sync::Mutex, time::Duration};

    #[tokio::test]
    async fn activitypub_and_bcrypt_share_one_cpu_budget() {
        let admission = BcryptAdmission::new(1, Duration::from_millis(10));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let running = {
            let admission = admission.clone();
            tokio::spawn(async move {
                spawn_cpu(&admission, move || {
                    let _ = started_tx.send(());
                    release_rx.lock().unwrap().recv().unwrap();
                })
                .await
            })
        };
        started_rx.await.unwrap();

        let bcrypt = admission
            .hash(BcryptWorkload::Login, SecretString::from("secret"), 4)
            .await;
        assert!(matches!(bcrypt, Err(BcryptAdmissionError::AtCapacity)));

        release_tx.send(()).unwrap();
        running.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn blocking_cpu_keeps_permit_after_caller_cancellation() {
        let admission = BcryptAdmission::new(1, Duration::from_millis(10));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let task_admission = admission.clone();
        let task = tokio::spawn(async move {
            let _ = spawn_cpu(&task_admission, move || {
                let _ = started_tx.send(());
                release_rx.lock().unwrap().recv().unwrap();
            })
            .await;
        });
        started_rx.await.unwrap();
        task.abort();
        task.await.unwrap_err();

        assert!(matches!(
            spawn_cpu(&admission, || ()).await,
            Err(CpuWorkError::AtCapacity)
        ));
        release_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        spawn_cpu(&admission, || ()).await.unwrap();
    }

    #[test]
    fn metric_families_are_contiguous() {
        let output = prometheus_metrics();
        let active_sample = output.find("keycast_expensive_resource_active{").unwrap();
        let rejection_help = output
            .find("# HELP keycast_expensive_resource_rejections_total")
            .unwrap();
        assert!(active_sample < rejection_help);
    }
}
