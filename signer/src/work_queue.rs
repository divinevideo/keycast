// ABOUTME: Work queue infrastructure for bounded concurrency and future batch verification
// ABOUTME: Two-queue architecture: VerifyQueue (stub for batching) + RelayQueue (bounded workers)

use crate::error::{SignerError, SignerResult};
use crate::signer_daemon::RelayWorkerContext;
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender, TrySendError};
use keycast_core::metrics::METRICS;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_QUEUE_CAPACITY: usize = 4096;
const DEFAULT_FLOW_QUEUE_LIMIT: usize = 64;
const WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);

/// NIP-46 request item for the relay queue
/// Contains all data needed to process a single NIP-46 request
pub struct Nip46RpcItem {
    /// The original NIP-46 event from the relay
    pub event: Box<Event>,
    /// The bunker pubkey (target of the request, extracted from p-tag)
    pub bunker_pubkey: String,
    enqueued_at: Instant,
    flow_permit: Option<FlowPermit>,
}

/// Relay queue for bounded concurrency on NIP-46 sign/encrypt/decrypt operations
///
/// Provides backpressure when the system is overloaded by using a bounded channel.
/// Queue (4096) buffers relay events; workers control processing rate.
pub struct RelayQueue {
    tx: Sender<Nip46RpcItem>,
    rx: Receiver<Nip46RpcItem>,
    closed: Arc<Mutex<bool>>,
    admission: FlowAdmission,
    capacity: usize,
}

impl RelayQueue {
    /// Create a new relay queue with bounded capacity
    pub fn new() -> Self {
        let capacity = configured_usize("RELAY_QUEUE_CAPACITY", DEFAULT_QUEUE_CAPACITY);
        let flow_queue_limit = configured_usize("RELAY_FLOW_QUEUE_LIMIT", DEFAULT_FLOW_QUEUE_LIMIT);
        Self::with_config(capacity, flow_queue_limit)
    }

    fn with_config(capacity: usize, flow_queue_limit: usize) -> Self {
        assert!(capacity > 0, "relay queue capacity must be positive");
        assert!(flow_queue_limit > 0, "relay flow limit must be positive");
        let (tx, rx) = bounded(capacity);
        Self {
            tx,
            rx,
            closed: Arc::new(Mutex::new(false)),
            admission: FlowAdmission::new(flow_queue_limit),
            capacity,
        }
    }

    /// Close the queue to new work while allowing workers to drain queued items.
    pub fn close(&self) {
        *self
            .closed
            .lock()
            .expect("relay queue close state mutex poisoned") = true;
    }

    /// Check whether the queue has been explicitly closed.
    pub fn is_closed(&self) -> bool {
        *self
            .closed
            .lock()
            .expect("relay queue close state mutex poisoned")
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get a sender handle for enqueueing items
    pub fn sender(&self) -> RelaySender {
        RelaySender {
            tx: self.tx.clone(),
            closed: self.closed.clone(),
            admission: self.admission.clone(),
        }
    }

    /// Spawn relay workers for NIP-46 request processing
    ///
    /// Worker count balances throughput vs CPU contention with HTTP RPC.
    /// Workers block on the channel and process items sequentially.
    pub(crate) fn spawn_workers(
        &self,
        num_workers: usize,
        context: RelayWorkerContext,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        tracing::info!(
            "Spawning {} relay workers (queue capacity: {})",
            num_workers,
            self.capacity
        );
        METRICS.set_nip46_queue_capacity(self.capacity as u64);

        (0..num_workers)
            .map(|worker_id| {
                let rx = self.rx.clone();
                let closed = self.closed.clone();
                let context = context.clone();

                tokio::spawn(async move {
                    let worker_queue = RelayWorkerQueue { rx, closed };
                    relay_worker_loop(worker_id, worker_queue, context).await
                })
            })
            .collect()
    }
}

impl Default for RelayQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Sender handle for the relay queue
#[derive(Clone)]
pub struct RelaySender {
    tx: Sender<Nip46RpcItem>,
    closed: Arc<Mutex<bool>>,
    admission: FlowAdmission,
}

impl RelaySender {
    /// Try to send an item to the queue
    /// Returns error if queue is full (backpressure)
    pub fn try_send(
        &self,
        event: Box<Event>,
        bunker_pubkey: String,
    ) -> Result<(), RelayQueueError> {
        self.try_send_with_open_queue_probe(event, bunker_pubkey, || {})
    }

    fn try_send_with_open_queue_probe<F>(
        &self,
        event: Box<Event>,
        bunker_pubkey: String,
        after_open_check: F,
    ) -> Result<(), RelayQueueError>
    where
        F: FnOnce(),
    {
        let close_guard = self
            .closed
            .lock()
            .expect("relay queue close state mutex poisoned");
        if *close_guard {
            // Distinct from the queue-full counter below: a closed queue means
            // we are draining for graceful shutdown, not overloaded. Conflating
            // the two would make shutdown look like a capacity incident.
            METRICS.inc_queue_closed();
            return Err(RelayQueueError::Closed);
        }

        after_open_check();

        let client_pubkey = event.pubkey.to_hex();
        let flow_permit = match self.admission.try_acquire(&bunker_pubkey, &client_pubkey) {
            Ok(permit) => permit,
            Err(FlowLimit::Target) => {
                METRICS.inc_nip46_noisy_flow_shed("target");
                return Err(RelayQueueError::NoisyTarget);
            }
            Err(FlowLimit::Client) => {
                METRICS.inc_nip46_noisy_flow_shed("client");
                return Err(RelayQueueError::NoisyClient);
            }
        };
        let item = Nip46RpcItem {
            event,
            bunker_pubkey,
            enqueued_at: Instant::now(),
            flow_permit: Some(flow_permit),
        };

        let result = match self.tx.try_send(item) {
            Ok(()) => {
                METRICS.set_nip46_queue_depth(self.tx.len() as u64);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                METRICS.inc_queue_dropped();
                Err(RelayQueueError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => Err(RelayQueueError::Disconnected),
        };
        drop(close_guard);
        result
    }

    /// Check whether the queue has been explicitly closed.
    pub fn is_closed(&self) -> bool {
        *self
            .closed
            .lock()
            .expect("relay queue close state mutex poisoned")
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

/// Errors from relay queue operations
#[derive(Debug, thiserror::Error)]
pub enum RelayQueueError {
    #[error("Relay queue is full - system overloaded")]
    QueueFull,
    #[error("Relay queue is closed")]
    Closed,
    #[error("Relay target flow has too much work in flight")]
    NoisyTarget,
    #[error("Relay client flow has too much work in flight")]
    NoisyClient,
    #[error("Relay queue disconnected")]
    Disconnected,
}

struct RelayWorkerQueue {
    rx: Receiver<Nip46RpcItem>,
    closed: Arc<Mutex<bool>>,
}

/// Worker loop that processes NIP-46 items from the relay queue
async fn relay_worker_loop(worker_id: usize, queue: RelayWorkerQueue, context: RelayWorkerContext) {
    relay_worker_loop_with(worker_id, queue, move |item| {
        let context = context.clone();
        async move { process_nip46_item(&item, &context).await }
    })
    .await;
}

async fn relay_worker_loop_with<P, F>(worker_id: usize, queue: RelayWorkerQueue, process: P)
where
    P: Fn(Nip46RpcItem) -> F,
    F: std::future::Future<Output = SignerResult<()>>,
{
    tracing::debug!("Relay worker {} started", worker_id);

    loop {
        if *queue
            .closed
            .lock()
            .expect("relay queue close state mutex poisoned")
            && queue.rx.is_empty()
        {
            tracing::info!(
                "Relay worker {} shutting down (queue closed and empty)",
                worker_id
            );
            break;
        }

        // Block on receiving next item (in spawn_blocking to not block async runtime)
        let mut item = {
            let rx = queue.rx.clone();
            match tokio::task::spawn_blocking(move || rx.recv_timeout(WORKER_RECV_TIMEOUT)).await {
                Ok(Ok(item)) => item,
                Ok(Err(RecvTimeoutError::Disconnected)) => {
                    // Channel disconnected - shutdown
                    tracing::info!("Relay worker {} shutting down (channel closed)", worker_id);
                    break;
                }
                Ok(Err(RecvTimeoutError::Timeout)) => continue,
                Err(e) => {
                    tracing::error!("Relay worker {} spawn_blocking panicked: {}", worker_id, e);
                    continue;
                }
            }
        };

        METRICS.set_nip46_queue_depth(queue.rx.len() as u64);
        METRICS.observe_nip46_queue_wait(item.enqueued_at.elapsed());
        // The limit protects queue headroom, not worker utilization. Release it
        // as soon as work leaves the queue so an otherwise idle worker can
        // continue serving a busy flow.
        drop(item.flow_permit.take());
        METRICS.inc_nip46_workers_active();
        let processing_started = Instant::now();

        // Process the item
        if let Err(e) = process(item).await {
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
        METRICS.dec_nip46_workers_active();
        METRICS.observe_nip46_worker_duration(processing_started.elapsed());
    }

    tracing::debug!("Relay worker {} exited", worker_id);
}

fn configured_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[derive(Clone)]
struct FlowAdmission {
    state: Arc<Mutex<FlowState>>,
    queue_limit: usize,
}

#[derive(Default)]
struct FlowState {
    targets: HashMap<String, usize>,
    clients: HashMap<String, usize>,
}

enum FlowLimit {
    Target,
    Client,
}

impl FlowAdmission {
    fn new(queue_limit: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(FlowState::default())),
            queue_limit,
        }
    }

    fn try_acquire(&self, target: &str, client: &str) -> Result<FlowPermit, FlowLimit> {
        let mut state = self.state.lock().expect("relay flow state mutex poisoned");
        if state.targets.get(target).copied().unwrap_or_default() >= self.queue_limit {
            return Err(FlowLimit::Target);
        }
        if state.clients.get(client).copied().unwrap_or_default() >= self.queue_limit {
            return Err(FlowLimit::Client);
        }
        *state.targets.entry(target.to_string()).or_default() += 1;
        *state.clients.entry(client.to_string()).or_default() += 1;
        Ok(FlowPermit {
            admission: self.clone(),
            target: target.to_string(),
            client: client.to_string(),
        })
    }
}

struct FlowPermit {
    admission: FlowAdmission,
    target: String,
    client: String,
}

impl Drop for FlowPermit {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .expect("relay flow state mutex poisoned");
        decrement_flow(&mut state.targets, &self.target);
        decrement_flow(&mut state.clients, &self.client);
    }
}

fn decrement_flow(flows: &mut HashMap<String, usize>, key: &str) {
    if let Some(count) = flows.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            flows.remove(key);
        }
    }
}

/// Process a single NIP-46 RPC item
///
/// This is extracted from UnifiedSigner::handle_nip46_request to be called from workers.
/// CPU-bound crypto operations (decrypt, sign, encrypt) use spawn_blocking.
async fn process_nip46_item(item: &Nip46RpcItem, context: &RelayWorkerContext) -> SignerResult<()> {
    use crate::signer_daemon::UnifiedSigner;

    // Delegate to the existing handler which has all the complex logic
    UnifiedSigner::handle_nip46_request(context, item.event.clone()).await
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
    use crate::signer_daemon::{admits_owned_request, enqueue_owned_relay_event, OwnershipStage};

    async fn test_event() -> Box<Event> {
        let keys = Keys::generate();
        let unsigned = EventBuilder::text_note("test").build(keys.public_key());
        let event = keys
            .sign_event(unsigned)
            .await
            .expect("test event should sign");
        Box::new(event)
    }

    #[test]
    fn test_relay_queue_creation() {
        let queue = RelayQueue::new();
        let sender = queue.sender();
        assert!(sender.is_empty());
    }

    #[test]
    fn test_relay_sender_clone() {
        let queue = RelayQueue::new();
        let sender1 = queue.sender();
        let sender2 = sender1.clone();

        // Both senders should work with the same queue
        assert!(sender1.is_empty());
        assert!(sender2.is_empty());
    }

    #[test]
    fn test_relay_queue_close_is_visible_to_sender_clones() {
        let queue = RelayQueue::new();
        let sender1 = queue.sender();
        let sender2 = sender1.clone();

        queue.close();

        assert!(queue.is_closed());
        assert!(sender1.is_closed());
        assert!(sender2.is_closed());
    }

    #[tokio::test]
    async fn test_relay_sender_rejects_new_work_after_close() {
        let queue = RelayQueue::new();
        let sender = queue.sender();

        queue.close();

        let result = sender.try_send(test_event().await, Keys::generate().public_key().to_hex());
        assert!(
            matches!(result, Err(RelayQueueError::Closed)),
            "expected closed queue error, got {:?}",
            result
        );
        assert!(sender.is_empty());
    }

    #[tokio::test]
    async fn test_closed_queue_rejection_counts_as_closed_not_overload() {
        use std::sync::atomic::Ordering;

        let queue = RelayQueue::new();
        let sender = queue.sender();
        queue.close();

        // Global process metrics: other tests may run concurrently, so assert a
        // strict increase (monotonic counter) rather than an exact value.
        let before = METRICS.nip46_requests_queue_closed.load(Ordering::Relaxed);
        let result = sender.try_send(test_event().await, Keys::generate().public_key().to_hex());
        assert!(matches!(result, Err(RelayQueueError::Closed)));
        let after = METRICS.nip46_requests_queue_closed.load(Ordering::Relaxed);
        assert!(
            after > before,
            "a closed-queue rejection must increment the queue_closed (shutdown) counter, not the overload drop counter"
        );
    }

    #[tokio::test]
    async fn test_relay_sender_blocks_close_until_enqueue_attempt_completes() {
        let queue = RelayQueue::new();
        let sender = queue.sender();

        let result = sender.try_send_with_open_queue_probe(
            test_event().await,
            Keys::generate().public_key().to_hex(),
            || {
                assert!(
                    matches!(
                        sender.closed.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ),
                    "close state mutex must stay locked until the enqueue attempt finishes"
                );
            },
        );

        assert!(result.is_ok(), "send should complete before close wins");
        queue.close();
        assert!(queue.is_closed());
        assert_eq!(sender.len(), 1);
    }

    #[tokio::test]
    async fn noisy_target_cannot_consume_unrelated_headroom() {
        let queue = RelayQueue::with_config(4, 2);
        let sender = queue.sender();
        let target = Keys::generate().public_key().to_hex();

        assert!(sender.try_send(test_event().await, target.clone()).is_ok());
        assert!(sender.try_send(test_event().await, target.clone()).is_ok());
        assert!(matches!(
            sender.try_send(test_event().await, target),
            Err(RelayQueueError::NoisyTarget)
        ));
        assert!(sender
            .try_send(test_event().await, Keys::generate().public_key().to_hex())
            .is_ok());
        assert_eq!(sender.len(), 3);
    }

    #[tokio::test]
    async fn noisy_client_cannot_fill_queue_with_varied_targets() {
        let queue = RelayQueue::with_config(4, 2);
        let sender = queue.sender();
        let event = test_event().await;

        assert!(sender
            .try_send(event.clone(), Keys::generate().public_key().to_hex())
            .is_ok());
        assert!(sender
            .try_send(event.clone(), Keys::generate().public_key().to_hex())
            .is_ok());
        assert!(matches!(
            sender.try_send(event, Keys::generate().public_key().to_hex()),
            Err(RelayQueueError::NoisyClient)
        ));
        assert_eq!(sender.len(), 2);
    }

    #[tokio::test]
    async fn mixed_overload_keeps_resources_bounded_and_unrelated_headroom_available() {
        let queue = RelayQueue::with_config(8, 2);
        let sender = queue.sender();
        let noisy_target = "noisy-target".to_string();
        let unrelated_target = "unrelated-valid".to_string();

        assert!(!enqueue_owned_relay_event(
            &sender,
            test_event().await,
            "peer-owned".to_string(),
            false,
        ));
        assert_eq!(sender.len(), 0, "peer-owned work must not enter the queue");

        assert!(sender
            .try_send(test_event().await, noisy_target.clone())
            .is_ok());
        assert!(sender
            .try_send(test_event().await, noisy_target.clone())
            .is_ok());
        assert!(matches!(
            sender.try_send(test_event().await, noisy_target),
            Err(RelayQueueError::NoisyTarget)
        ));

        for index in 0..3 {
            assert!(sender
                .try_send(test_event().await, format!("unknown-{index}"))
                .is_ok());
        }
        assert!(sender
            .try_send(test_event().await, "peer-after-rebalance".to_string())
            .is_ok());
        assert!(sender
            .try_send(test_event().await, unrelated_target.clone())
            .is_ok());
        assert!(sender.len() <= queue.capacity());

        let lookup_permits = Arc::new(tokio::sync::Semaphore::new(1));
        let active_lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak_lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let shed_lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
        let make_processor = || {
            let lookup_permits = lookup_permits.clone();
            let active_lookups = active_lookups.clone();
            let peak_lookups = peak_lookups.clone();
            let shed_lookups = shed_lookups.clone();
            let progress_tx = progress_tx.clone();
            move |item: Nip46RpcItem| {
                let lookup_permits = lookup_permits.clone();
                let active_lookups = active_lookups.clone();
                let peak_lookups = peak_lookups.clone();
                let shed_lookups = shed_lookups.clone();
                let progress_tx = progress_tx.clone();
                async move {
                    match item.bunker_pubkey.as_str() {
                        "noisy-target" => tokio::time::sleep(Duration::from_millis(20)).await,
                        "peer-after-rebalance" => {
                            assert!(!admits_owned_request(false, OwnershipStage::Worker));
                        }
                        target if target.starts_with("unknown-") => {
                            if let Ok(_permit) = lookup_permits.try_acquire_owned() {
                                let active = active_lookups
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                    + 1;
                                peak_lookups.fetch_max(active, std::sync::atomic::Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_millis(30)).await;
                                active_lookups.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                            } else {
                                shed_lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        "unrelated-valid" => {
                            progress_tx.send(()).expect("record valid progress");
                        }
                        _ => {}
                    }
                    Ok(())
                }
            }
        };

        queue.close();
        let worker_queue = || RelayWorkerQueue {
            rx: queue.rx.clone(),
            closed: queue.closed.clone(),
        };
        let workers = [
            tokio::spawn(relay_worker_loop_with(0, worker_queue(), make_processor())),
            tokio::spawn(relay_worker_loop_with(1, worker_queue(), make_processor())),
        ];

        tokio::time::timeout(Duration::from_secs(1), progress_rx.recv())
            .await
            .expect("unrelated valid work must progress")
            .expect("progress channel closed");
        for worker in workers {
            worker.await.expect("worker task");
        }
        assert!(peak_lookups.load(std::sync::atomic::Ordering::SeqCst) <= 1);
        assert!(shed_lookups.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert_eq!(sender.len(), 0);
    }

    #[test]
    fn test_verify_queue_stub() {
        let _queue = VerifyQueue::new();
        // Just ensure it compiles and creates
    }
}
