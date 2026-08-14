// ABOUTME: Google Cloud KMS key manager implementation for secure key encryption
// ABOUTME: Uses envelope encryption pattern with KMS for data encryption keys

use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest};
use std::env;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// Maximum retry attempts for KMS operations before failing.
const MAX_KMS_RETRIES: u32 = 3;

/// Base delay for exponential backoff (doubles each attempt: 100ms, 200ms, 400ms).
const KMS_BASE_DELAY_MS: u64 = 100;

/// Per-attempt wall clock bound for Google Cloud KMS calls.
///
/// Sized so the whole retry loop fits inside the HTTP RPC request budget. A
/// cold-path signing request reaches `decrypt` behind an 8s handler bound
/// (`HANDLER_TIMEOUT` in `api/src/api/http/nostr_rpc.rs`), and with
/// [`MAX_KMS_RETRIES`] attempts plus [`KMS_BASE_DELAY_MS`] backoff the worst
/// case here is 2s + 0.1s + 2s + 0.2s + 2s = 6.3s. At 5s per attempt the second
/// and third attempts could never deliver a response inside that budget, so the
/// retries were dead weight on the hot path: the request was cancelled mid-loop
/// instead of failing over. `kms_retry_loop_fits_inside_the_http_rpc_request_bound`
/// holds that arithmetic against
/// [`crate::request_bounds::HTTP_RPC_HANDLER_TIMEOUT`] if any of these are
/// retuned.
///
/// 6.3s reserves the KMS loop alone. A cold handler load does its database work
/// before it reaches `decrypt`, so more than ~1.7s of database latency ahead of
/// this still cancels the request mid-loop, and the cold path does up to three
/// pool queries before it gets here. That reservation is real but unenforced: see
/// [`crate::request_bounds::SQLX_ACQUIRE_TIMEOUT`] for why the per-step budgets
/// on this path cannot be summed into a guarantee, and what would close it.
const KMS_ATTEMPT_TIMEOUT_SECS: u64 = 2;

/// Worst-case wall clock for a full [`MAX_KMS_RETRIES`] loop, asserted below so
/// a change to any of the three constants has to face the request bound.
#[cfg(test)]
const KMS_TOTAL_BUDGET: Duration = Duration::from_millis(
    KMS_ATTEMPT_TIMEOUT_SECS * 1000 * MAX_KMS_RETRIES as u64
        + KMS_BASE_DELAY_MS
        + KMS_BASE_DELAY_MS * 2,
);

pub struct GcpKeyManager {
    client: Client,
    key_name: String,
}

impl GcpKeyManager {
    pub async fn new() -> Result<Self, KeyManagerError> {
        let project_id = env::var("GCP_PROJECT_ID").map_err(|_| {
            KeyManagerError::ConfigurationError("GCP_PROJECT_ID not set".to_string())
        })?;

        let location = env::var("GCP_KMS_LOCATION").unwrap_or_else(|_| "global".to_string());

        let key_ring = env::var("GCP_KMS_KEY_RING").unwrap_or_else(|_| "keycast-keys".to_string());

        let key_name = env::var("GCP_KMS_KEY_NAME").unwrap_or_else(|_| "master-key".to_string());

        Self::from_config(&project_id, &location, &key_ring, &key_name).await
    }

    pub async fn from_config(
        project_id: &str,
        location: &str,
        key_ring: &str,
        key_name: &str,
    ) -> Result<Self, KeyManagerError> {
        info!("Initializing Google Cloud KMS client");
        debug!(
            "Project: {}, Location: {}, Key Ring: {}, Key: {}",
            project_id, location, key_ring, key_name
        );

        let config = ClientConfig::default()
            .with_auth()
            .await
            .map_err(|e| KeyManagerError::ConfigurationError(format!("GCP auth failed: {}", e)))?;

        let client = Client::new(config).await.map_err(|e| {
            KeyManagerError::ConfigurationError(format!("GCP client creation failed: {}", e))
        })?;

        let full_key_name = format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            project_id, location, key_ring, key_name
        );

        info!("Google Cloud KMS client initialized successfully");

        Ok(Self {
            client,
            key_name: full_key_name,
        })
    }
}

#[async_trait]
impl KeyManager for GcpKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        debug!(
            "Encrypting {} bytes with Google Cloud KMS",
            plaintext_bytes.len()
        );

        let request = EncryptRequest {
            name: self.key_name.clone(),
            plaintext: plaintext_bytes.to_vec(),
            additional_authenticated_data: vec![],
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let mut attempt = 0u32;
        let response = loop {
            attempt += 1;
            match tokio::time::timeout(
                Duration::from_secs(KMS_ATTEMPT_TIMEOUT_SECS),
                self.client.encrypt(request.clone(), None),
            )
            .await
            {
                Ok(Ok(resp)) => break resp,
                Ok(Err(e)) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        delay_ms = delay_ms,
                        "KMS encrypt failed, retrying: {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Ok(Err(e)) => {
                    error!("KMS encrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::EncryptionError(format!(
                        "KMS encryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
                Err(_) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        timeout_secs = KMS_ATTEMPT_TIMEOUT_SECS,
                        delay_ms = delay_ms,
                        "KMS encrypt timed out, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(_) => {
                    error!(
                        attempt = attempt,
                        timeout_secs = KMS_ATTEMPT_TIMEOUT_SECS,
                        "KMS encrypt timed out after all attempts"
                    );
                    return Err(KeyManagerError::EncryptionError(format!(
                        "KMS encryption timed out after {} attempts",
                        attempt
                    )));
                }
            }
        };

        let ciphertext = response.ciphertext;
        debug!("Successfully encrypted to {} bytes", ciphertext.len());

        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        debug!(
            "Decrypting {} bytes with Google Cloud KMS",
            ciphertext_bytes.len()
        );

        let request = DecryptRequest {
            name: self.key_name.clone(),
            ciphertext: ciphertext_bytes.to_vec(),
            additional_authenticated_data: vec![],
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let mut attempt = 0u32;
        let response = loop {
            attempt += 1;
            match tokio::time::timeout(
                Duration::from_secs(KMS_ATTEMPT_TIMEOUT_SECS),
                self.client.decrypt(request.clone(), None),
            )
            .await
            {
                Ok(Ok(resp)) => break resp,
                Ok(Err(e)) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        delay_ms = delay_ms,
                        "KMS decrypt failed, retrying: {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Ok(Err(e)) => {
                    error!("KMS decrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::DecryptionError(format!(
                        "KMS decryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
                Err(_) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        timeout_secs = KMS_ATTEMPT_TIMEOUT_SECS,
                        delay_ms = delay_ms,
                        "KMS decrypt timed out, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(_) => {
                    error!(
                        attempt = attempt,
                        timeout_secs = KMS_ATTEMPT_TIMEOUT_SECS,
                        "KMS decrypt timed out after all attempts"
                    );
                    return Err(KeyManagerError::DecryptionError(format!(
                        "KMS decryption timed out after {} attempts",
                        attempt
                    )));
                }
            }
        };

        let plaintext = response.plaintext;
        debug!("Successfully decrypted to {} bytes", plaintext.len());

        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    /// The KMS retry loop sits under the HTTP RPC handler bound on the cold
    /// signing path. If it can outlast that bound the later attempts can never
    /// produce a response, so retuning any of the three constants has to keep
    /// this true.
    #[test]
    fn kms_retry_loop_fits_inside_the_http_rpc_request_bound() {
        use crate::request_bounds::HTTP_RPC_HANDLER_TIMEOUT;

        assert!(
            KMS_TOTAL_BUDGET < HTTP_RPC_HANDLER_TIMEOUT,
            "KMS retry loop worst case {KMS_TOTAL_BUDGET:?} must stay under the \
             {HTTP_RPC_HANDLER_TIMEOUT:?} HTTP RPC handler bound"
        );
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // Skip test if GCP credentials not available
        if env::var("GCP_PROJECT_ID").is_err() {
            return;
        }

        let manager = GcpKeyManager::new()
            .await
            .expect("Failed to create GCP key manager");
        let plaintext = b"test data for encryption";

        let ciphertext = manager.encrypt(plaintext).await.expect("Encryption failed");
        let decrypted = manager
            .decrypt(&ciphertext)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
