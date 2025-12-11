// ABOUTME: Google Cloud KMS key manager implementation for secure key encryption
// ABOUTME: Uses envelope encryption pattern with KMS for data encryption keys

use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest};
use std::env;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Maximum retry attempts for KMS operations before failing.
const MAX_KMS_RETRIES: u32 = 3;

/// Base delay for exponential backoff (doubles each attempt: 100ms, 200ms, 400ms).
const KMS_BASE_DELAY_MS: u64 = 100;

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
            match self.client.encrypt(request.clone(), None).await {
                Ok(resp) => break resp,
                Err(e) if attempt < MAX_KMS_RETRIES => {
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
                Err(e) => {
                    error!("KMS encrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::EncryptionError(format!(
                        "KMS encryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
            }
        };

        let ciphertext = response.ciphertext;
        debug!("Successfully encrypted to {} bytes", ciphertext.len());

        Ok(ciphertext)
    }

    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
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
            match self.client.decrypt(request.clone(), None).await {
                Ok(resp) => break resp,
                Err(e) if attempt < MAX_KMS_RETRIES => {
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
                Err(e) => {
                    error!("KMS decrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::DecryptionError(format!(
                        "KMS decryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
            }
        };

        let plaintext = response.plaintext;
        debug!("Successfully decrypted to {} bytes", plaintext.len());

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

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

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
