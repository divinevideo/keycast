#[cfg(feature = "aws")]
pub mod aws_key_manager;
pub mod bounded_key_manager;
pub mod file_key_manager;
pub mod gcp_key_manager;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Key manager is at capacity")]
    AtCapacity,
    #[error("Failed to load key")]
    LoadKey(String),
    #[error("Failed to encrypt")]
    Encrypt(String),
    #[error("Failed to decrypt")]
    Decrypt(String),
    #[error("Failed to generate master key")]
    GenerateMasterKey(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

#[async_trait]
pub trait KeyManager: Send + Sync {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError>;
    async fn decrypt(&self, ciphertext_bytes: &[u8])
        -> Result<Zeroizing<Vec<u8>>, KeyManagerError>;
}
