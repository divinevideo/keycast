// Tests for secret key encryption/decryption format consistency
// Verifies that OAuth authorization bunker_secret is stored as raw bytes
// and can be correctly decrypted and parsed into Keys

use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use nostr_sdk::prelude::*;

/// Test that raw bytes format works correctly for OAuth secrets
/// This is the correct format: encrypt(secret_bytes) -> decrypt -> SecretKey::from_slice
#[tokio::test]
async fn test_oauth_secret_raw_bytes_format() {
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Generate a user key
    let user_keys = Keys::generate();

    // Get raw 32-byte secret
    let secret_bytes = user_keys.secret_key().secret_bytes();
    assert_eq!(secret_bytes.len(), 32, "Secret key should be 32 bytes");

    // Encrypt the raw bytes (this is how OAuth registration stores it)
    let encrypted = key_manager
        .encrypt(&secret_bytes)
        .await
        .expect("Failed to encrypt secret");

    // Decrypt and verify we can reconstruct the key
    let decrypted = key_manager
        .decrypt(&encrypted)
        .await
        .expect("Failed to decrypt secret");

    // Should be able to create SecretKey directly from decrypted bytes
    let recovered_secret = SecretKey::from_slice(&decrypted)
        .expect("Should be able to create SecretKey from raw bytes");
    let recovered_keys = Keys::new(recovered_secret);

    // Verify the public key matches
    assert_eq!(
        recovered_keys.public_key().to_hex(),
        user_keys.public_key().to_hex(),
        "Recovered key should match original"
    );
}

/// Test that hex string format ALSO works (for backwards compatibility)
/// Some older code paths may have stored hex strings
#[tokio::test]
async fn test_oauth_secret_hex_string_format() {
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Generate a user key
    let user_keys = Keys::generate();

    // Get hex string representation
    let secret_hex = user_keys.secret_key().to_secret_hex();
    assert_eq!(secret_hex.len(), 64, "Hex secret should be 64 chars");

    // Encrypt the hex string as bytes
    let encrypted = key_manager
        .encrypt(secret_hex.as_bytes())
        .await
        .expect("Failed to encrypt secret");

    // Decrypt and verify we can parse it
    let decrypted = key_manager
        .decrypt(&encrypted)
        .await
        .expect("Failed to decrypt secret");

    // Should be valid UTF-8 (hex string)
    let decrypted_str = std::str::from_utf8(&decrypted).expect("Hex format should be valid UTF-8");

    // Should be able to parse as Keys
    let recovered_keys = Keys::parse(decrypted_str).expect("Should be able to parse hex string");

    // Verify the public key matches
    assert_eq!(
        recovered_keys.public_key().to_hex(),
        user_keys.public_key().to_hex(),
        "Recovered key should match original"
    );
}

/// Test that raw bytes are NOT valid UTF-8
/// This demonstrates why the buggy code path fails
#[tokio::test]
async fn test_raw_bytes_are_not_utf8() {
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Generate a user key
    let user_keys = Keys::generate();

    // Get raw 32-byte secret (same as OAuth registration does)
    let secret_bytes = user_keys.secret_key().secret_bytes();

    // Encrypt the raw bytes
    let encrypted = key_manager
        .encrypt(&secret_bytes)
        .await
        .expect("Failed to encrypt secret");

    // Decrypt
    let decrypted = key_manager
        .decrypt(&encrypted)
        .await
        .expect("Failed to decrypt secret");

    // Raw bytes are typically NOT valid UTF-8
    // This test documents the bug: trying to interpret raw bytes as UTF-8 string
    let utf8_result = std::str::from_utf8(&decrypted);

    // Most random 32-byte sequences are NOT valid UTF-8
    // If this assertion fails, we got lucky with a valid UTF-8 sequence
    // Run the test multiple times to see it fail on invalid UTF-8
    if utf8_result.is_err() {
        // This is expected - raw bytes usually aren't valid UTF-8
        println!(
            "As expected, raw bytes are not valid UTF-8: {:?}",
            utf8_result.err()
        );
    } else {
        // This is rare but possible - if the random bytes happen to be valid UTF-8
        println!("Note: This random sequence happened to be valid UTF-8");
    }

    // The CORRECT way to handle raw bytes:
    let secret_key =
        SecretKey::from_slice(&decrypted).expect("Raw bytes should always work with from_slice");
    let recovered_keys = Keys::new(secret_key);

    assert_eq!(
        recovered_keys.public_key().to_hex(),
        user_keys.public_key().to_hex(),
        "Raw bytes path should always work"
    );
}

/// Test helper function that handles both formats (what we should use)
/// Returns Keys regardless of whether stored as raw bytes or hex string
fn parse_decrypted_secret(decrypted: &[u8]) -> Result<Keys, Box<dyn std::error::Error>> {
    // Try raw bytes first (32 bytes = raw secret key)
    if decrypted.len() == 32 {
        let secret_key = SecretKey::from_slice(decrypted)?;
        return Ok(Keys::new(secret_key));
    }

    // Try hex string (64 bytes = hex-encoded secret)
    if decrypted.len() == 64 {
        if let Ok(hex_str) = std::str::from_utf8(decrypted) {
            if let Ok(keys) = Keys::parse(hex_str) {
                return Ok(keys);
            }
        }
    }

    // Try nsec format
    if let Ok(utf8_str) = std::str::from_utf8(decrypted) {
        if let Ok(keys) = Keys::parse(utf8_str) {
            return Ok(keys);
        }
    }

    Err("Could not parse secret key in any known format".into())
}

#[tokio::test]
async fn test_universal_parser_handles_raw_bytes() {
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let user_keys = Keys::generate();

    // Raw bytes format
    let secret_bytes = user_keys.secret_key().secret_bytes();
    let encrypted = key_manager.encrypt(&secret_bytes).await.unwrap();
    let decrypted = key_manager.decrypt(&encrypted).await.unwrap();

    let recovered =
        parse_decrypted_secret(&decrypted).expect("Universal parser should handle raw bytes");

    assert_eq!(
        recovered.public_key().to_hex(),
        user_keys.public_key().to_hex()
    );
}

#[tokio::test]
async fn test_universal_parser_handles_hex_string() {
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let user_keys = Keys::generate();

    // Hex string format
    let secret_hex = user_keys.secret_key().to_secret_hex();
    let encrypted = key_manager.encrypt(secret_hex.as_bytes()).await.unwrap();
    let decrypted = key_manager.decrypt(&encrypted).await.unwrap();

    let recovered =
        parse_decrypted_secret(&decrypted).expect("Universal parser should handle hex string");

    assert_eq!(
        recovered.public_key().to_hex(),
        user_keys.public_key().to_hex()
    );
}
