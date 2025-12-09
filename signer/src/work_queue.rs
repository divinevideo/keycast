// ABOUTME: Work queue infrastructure for bounded concurrency and future batch verification
// ABOUTME: Two-queue architecture: VerifyQueue (stub for batching) + RpcQueue (bounded workers)

use crate::error::{SignerError, SignerResult};
use crate::signer_daemon::Nip46Handler;
use cluster_hashring::ClusterCoordinator;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use keycast_core::encryption::KeyManager;
use keycast_core::metrics::METRICS;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use sqlx::PgPool;
use std::sync::Arc;

const QUEUE_CAPACITY: usize = 4096;

/// NIP-46 request item for the RPC queue
/// Contains all data needed to process a single NIP-46 request
pub struct Nip46RpcItem {
    /// The original NIP-46 event from the relay
    pub event: Box<Event>,
    /// The bunker pubkey (target of the request, extracted from p-tag)
    pub bunker_pubkey: String,
}

/// RPC Queue for bounded concurrency on sign/encrypt/decrypt operations
///
/// Provides backpressure when the system is overloaded by using a bounded channel.
/// Workers process items one at a time, using spawn_blocking for CPU-bound crypto.
pub struct RpcQueue {
    tx: Sender<Nip46RpcItem>,
    rx: Receiver<Nip46RpcItem>,
}

impl RpcQueue {
    /// Create a new RPC queue with bounded capacity
    pub fn new() -> Self {
        let (tx, rx) = bounded(QUEUE_CAPACITY);
        Self { tx, rx }
    }

    /// Get a sender handle for enqueueing items
    pub fn sender(&self) -> RpcSender {
        RpcSender {
            tx: self.tx.clone(),
        }
    }

    /// Spawn RPC workers (one per CPU core)
    ///
    /// Workers block on the channel and process items sequentially.
    /// CPU-bound crypto operations use spawn_blocking to avoid starving the async runtime.
    pub fn spawn_workers(
        &self,
        num_workers: usize,
        handlers: Cache<String, Nip46Handler>,
        client: Client,
        pool: PgPool,
        key_manager: Arc<Box<dyn KeyManager>>,
        coordinator: Arc<ClusterCoordinator>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        tracing::info!(
            "Spawning {} RPC workers (queue capacity: {})",
            num_workers,
            QUEUE_CAPACITY
        );

        (0..num_workers)
            .map(|worker_id| {
                let rx = self.rx.clone();
                let handlers = handlers.clone();
                let client = client.clone();
                let pool = pool.clone();
                let key_manager = key_manager.clone();
                let coordinator = coordinator.clone();

                tokio::spawn(async move {
                    rpc_worker_loop(
                        worker_id,
                        rx,
                        handlers,
                        client,
                        pool,
                        key_manager,
                        coordinator,
                    )
                    .await
                })
            })
            .collect()
    }
}

impl Default for RpcQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Sender handle for the RPC queue
#[derive(Clone)]
pub struct RpcSender {
    tx: Sender<Nip46RpcItem>,
}

impl RpcSender {
    /// Try to send an item to the queue
    /// Returns error if queue is full (backpressure)
    pub fn try_send(&self, item: Nip46RpcItem) -> Result<(), RpcQueueError> {
        match self.tx.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                METRICS.inc_queue_dropped();
                Err(RpcQueueError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => Err(RpcQueueError::Disconnected),
        }
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

/// Errors from RPC queue operations
#[derive(Debug, thiserror::Error)]
pub enum RpcQueueError {
    #[error("RPC queue is full - system overloaded")]
    QueueFull,
    #[error("RPC queue disconnected")]
    Disconnected,
}

/// Worker loop that processes RPC items from the queue
async fn rpc_worker_loop(
    worker_id: usize,
    rx: Receiver<Nip46RpcItem>,
    handlers: Cache<String, Nip46Handler>,
    client: Client,
    pool: PgPool,
    key_manager: Arc<Box<dyn KeyManager>>,
    coordinator: Arc<ClusterCoordinator>,
) {
    tracing::debug!("RPC worker {} started", worker_id);

    loop {
        // Block on receiving next item (in spawn_blocking to not block async runtime)
        let item = {
            let rx = rx.clone();
            match tokio::task::spawn_blocking(move || rx.recv()).await {
                Ok(Ok(item)) => item,
                Ok(Err(_)) => {
                    // Channel disconnected - shutdown
                    tracing::info!("RPC worker {} shutting down (channel closed)", worker_id);
                    break;
                }
                Err(e) => {
                    tracing::error!("RPC worker {} spawn_blocking panicked: {}", worker_id, e);
                    continue;
                }
            }
        };

        // Process the item
        if let Err(e) =
            process_nip46_item(&item, &handlers, &client, &pool, &key_manager, &coordinator).await
        {
            // Filter out expected noise
            match &e {
                SignerError::MissingParameter("p-tag") => {
                    tracing::trace!("Worker {}: Ignoring malformed request: {}", worker_id, e);
                }
                _ => {
                    tracing::error!("Worker {}: Error processing request: {}", worker_id, e);
                }
            }
        }
    }

    tracing::debug!("RPC worker {} exited", worker_id);
}

/// Process a single NIP-46 RPC item
///
/// This is extracted from UnifiedSigner::handle_nip46_request to be called from workers.
/// CPU-bound crypto operations (decrypt, sign, encrypt) use spawn_blocking.
async fn process_nip46_item(
    item: &Nip46RpcItem,
    handlers: &Cache<String, Nip46Handler>,
    client: &Client,
    pool: &PgPool,
    key_manager: &Arc<Box<dyn KeyManager>>,
    coordinator: &Arc<ClusterCoordinator>,
) -> SignerResult<()> {
    use crate::signer_daemon::UnifiedSigner;

    // Delegate to the existing handler which has all the complex logic
    UnifiedSigner::handle_nip46_request(
        handlers.clone(),
        client.clone(),
        item.event.clone(),
        pool,
        key_manager,
        coordinator,
    )
    .await
}

// ============================================================================
// VERIFY QUEUE (stub for future batch signature verification)
// ============================================================================

/// Stub for future batch verification queue
///
/// Currently, signature verification happens before items reach this queue:
/// - NIP-46 relay events: nostr-sdk verifies internally
/// - HTTP UCAN tokens: middleware verifies inline
///
/// Future: Move verification here for batch Schnorr verification under load.
/// The drain strategy (try_recv loop) will naturally batch items when queue fills.
pub struct VerifyQueue {
    // Placeholder - not yet implemented
    _marker: std::marker::PhantomData<()>,
}

impl VerifyQueue {
    /// Create a new verify queue (stub)
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl Default for VerifyQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_queue_creation() {
        let queue = RpcQueue::new();
        let sender = queue.sender();
        assert!(sender.is_empty());
    }

    #[test]
    fn test_rpc_sender_clone() {
        let queue = RpcQueue::new();
        let sender1 = queue.sender();
        let sender2 = sender1.clone();

        // Both senders should work with the same queue
        assert!(sender1.is_empty());
        assert!(sender2.is_empty());
    }

    #[test]
    fn test_verify_queue_stub() {
        let _queue = VerifyQueue::new();
        // Just ensure it compiles and creates
    }
}
