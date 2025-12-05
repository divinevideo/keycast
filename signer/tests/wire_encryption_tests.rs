// ABOUTME: Tests for NIP-46 wire encryption (transport layer)
// ABOUTME: Verifies NIP-44 encrypt/decrypt round-trip for bunker communication

use nostr_sdk::nips::{nip04, nip44};
use nostr_sdk::prelude::*;

// ============================================================================
// Wire Encryption Tests
// These test the transport layer encryption used in NIP-46 communication
// ============================================================================

/// Test NIP-44 wire encryption round-trip
/// This simulates client → bunker → client communication
#[test]
fn test_nip44_wire_encryption_round_trip() {
    // Bunker keys (used for transport encryption)
    let bunker_keys = Keys::generate();
    // Client keys (ephemeral, used by connecting app)
    let client_keys = Keys::generate();

    let plaintext = r#"{"method":"sign_event","params":[{"kind":1,"content":"test"}],"id":"123"}"#;

    // Client encrypts request TO bunker using bunker's pubkey
    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        &bunker_keys.public_key(),
        plaintext,
        nip44::Version::V2,
    )
    .expect("Client encryption should succeed");

    // Bunker decrypts request FROM client using bunker's secret and client's pubkey
    let decrypted = nip44::decrypt(
        bunker_keys.secret_key(),
        &client_keys.public_key(),
        &encrypted,
    )
    .expect("Bunker decryption should succeed");

    assert_eq!(
        decrypted, plaintext,
        "Decrypted content should match original"
    );
}

/// Test NIP-44 response encryption (bunker → client)
#[test]
fn test_nip44_response_encryption() {
    let bunker_keys = Keys::generate();
    let client_keys = Keys::generate();

    let response = r#"{"result":"signed_event_json","id":"123"}"#;

    // Bunker encrypts response TO client
    let encrypted = nip44::encrypt(
        bunker_keys.secret_key(),
        &client_keys.public_key(),
        response,
        nip44::Version::V2,
    )
    .expect("Bunker encryption should succeed");

    // Client decrypts response FROM bunker
    let decrypted = nip44::decrypt(
        client_keys.secret_key(),
        &bunker_keys.public_key(),
        &encrypted,
    )
    .expect("Client decryption should succeed");

    assert_eq!(
        decrypted, response,
        "Decrypted response should match original"
    );
}

/// Test NIP-04 fallback (backwards compatibility)
#[test]
fn test_nip04_fallback_encryption() {
    let bunker_keys = Keys::generate();
    let client_keys = Keys::generate();

    let plaintext = r#"{"method":"get_public_key","params":[],"id":"456"}"#;

    // Client uses NIP-04 (older protocol)
    let encrypted = nip04::encrypt(
        client_keys.secret_key(),
        &bunker_keys.public_key(),
        plaintext,
    )
    .expect("NIP-04 encryption should succeed");

    // Bunker tries NIP-44 first (should fail for NIP-04 ciphertext)
    let nip44_result = nip44::decrypt(
        bunker_keys.secret_key(),
        &client_keys.public_key(),
        &encrypted,
    );
    assert!(
        nip44_result.is_err(),
        "NIP-44 should fail on NIP-04 ciphertext"
    );

    // Bunker falls back to NIP-04
    let decrypted = nip04::decrypt(
        bunker_keys.secret_key(),
        &client_keys.public_key(),
        &encrypted,
    )
    .expect("NIP-04 decryption should succeed as fallback");

    assert_eq!(
        decrypted, plaintext,
        "NIP-04 decrypted content should match"
    );
}

/// Test that wrong keys fail decryption
#[test]
fn test_wrong_keys_fail_decryption() {
    let bunker_keys = Keys::generate();
    let client_keys = Keys::generate();
    let wrong_keys = Keys::generate();

    let plaintext = "secret message";

    // Encrypt with correct keys
    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        &bunker_keys.public_key(),
        plaintext,
        nip44::Version::V2,
    )
    .expect("Encryption should succeed");

    // Try to decrypt with wrong keys
    let result = nip44::decrypt(
        wrong_keys.secret_key(),
        &client_keys.public_key(),
        &encrypted,
    );

    assert!(result.is_err(), "Decryption with wrong keys should fail");
}

/// Test encryption of various JSON-RPC message types
#[test]
fn test_various_nip46_message_encryption() {
    let bunker_keys = Keys::generate();
    let client_keys = Keys::generate();

    let messages = vec![
        // connect request
        r#"{"method":"connect","params":["bunker_pubkey","secret"],"id":"1"}"#,
        // sign_event request
        r#"{"method":"sign_event","params":[{"kind":1,"content":"hello","tags":[],"created_at":1234567890,"pubkey":"abc123"}],"id":"2"}"#,
        // get_public_key request
        r#"{"method":"get_public_key","params":[],"id":"3"}"#,
        // nip44_encrypt request
        r#"{"method":"nip44_encrypt","params":["recipient_pubkey","plaintext to encrypt"],"id":"4"}"#,
        // nip44_decrypt request
        r#"{"method":"nip44_decrypt","params":["sender_pubkey","ciphertext_here"],"id":"5"}"#,
    ];

    for msg in messages {
        // Client → Bunker
        let encrypted = nip44::encrypt(
            client_keys.secret_key(),
            &bunker_keys.public_key(),
            msg,
            nip44::Version::V2,
        )
        .unwrap_or_else(|_| panic!("Failed to encrypt: {}", msg));

        let decrypted = nip44::decrypt(
            bunker_keys.secret_key(),
            &client_keys.public_key(),
            &encrypted,
        )
        .unwrap_or_else(|_| panic!("Failed to decrypt: {}", msg));

        assert_eq!(decrypted, msg, "Round-trip failed for message");

        // Verify we can parse the JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&decrypted).expect("Decrypted content should be valid JSON");
        assert!(parsed.get("method").is_some(), "Should have method field");
    }
}

// ============================================================================
// Payload Encryption Tests (NIP-44 encrypt/decrypt RPC methods)
// These test the user_keys encryption for third-party communication
// ============================================================================

/// Test nip44_encrypt RPC payload encryption
/// This is the user_keys encryption to third parties
#[test]
fn test_nip44_rpc_encrypt_decrypt() {
    // User keys (for signing and third-party encryption)
    let user_keys = Keys::generate();
    // Third party (recipient)
    let third_party_keys = Keys::generate();

    let plaintext = "Message to encrypt for third party";

    // Simulates RPC nip44_encrypt: user encrypts TO third party
    let ciphertext = nip44::encrypt(
        user_keys.secret_key(),
        &third_party_keys.public_key(),
        plaintext,
        nip44::Version::V2,
    )
    .expect("nip44_encrypt should succeed");

    // Third party decrypts FROM user
    let decrypted = nip44::decrypt(
        third_party_keys.secret_key(),
        &user_keys.public_key(),
        &ciphertext,
    )
    .expect("Third party should decrypt successfully");

    assert_eq!(decrypted, plaintext);
}

/// Test nip44_decrypt RPC payload decryption
/// This is the user_keys decryption from third parties
#[test]
fn test_nip44_rpc_decrypt() {
    let user_keys = Keys::generate();
    let third_party_keys = Keys::generate();

    let plaintext = "Message from third party";

    // Third party encrypts TO user
    let ciphertext = nip44::encrypt(
        third_party_keys.secret_key(),
        &user_keys.public_key(),
        plaintext,
        nip44::Version::V2,
    )
    .expect("Third party encryption should succeed");

    // Simulates RPC nip44_decrypt: user decrypts FROM third party
    let decrypted = nip44::decrypt(
        user_keys.secret_key(),
        &third_party_keys.public_key(),
        &ciphertext,
    )
    .expect("nip44_decrypt should succeed");

    assert_eq!(decrypted, plaintext);
}

/// Test that wire encryption keys (bunker) are different from payload encryption keys (user)
/// This is crucial for the dual-key architecture
#[test]
fn test_dual_key_separation() {
    // Bunker keys (transport layer)
    let bunker_keys = Keys::generate();
    // User keys (signing/payload)
    let user_keys = Keys::generate();
    // Client keys
    let client_keys = Keys::generate();
    // Third party (for payload encryption)
    let third_party_keys = Keys::generate();

    // Wire-level: Client → Bunker using bunker_keys
    let wire_message = "wire layer message";
    let wire_encrypted = nip44::encrypt(
        client_keys.secret_key(),
        &bunker_keys.public_key(),
        wire_message,
        nip44::Version::V2,
    )
    .expect("Wire encryption should use bunker_keys");

    // Payload-level: User → Third Party using user_keys
    let payload_message = "payload layer message";
    let payload_encrypted = nip44::encrypt(
        user_keys.secret_key(),
        &third_party_keys.public_key(),
        payload_message,
        nip44::Version::V2,
    )
    .expect("Payload encryption should use user_keys");

    // Verify bunker can decrypt wire but NOT payload
    let wire_decrypted = nip44::decrypt(
        bunker_keys.secret_key(),
        &client_keys.public_key(),
        &wire_encrypted,
    )
    .expect("Bunker should decrypt wire messages");
    assert_eq!(wire_decrypted, wire_message);

    // Bunker cannot decrypt payload (wrong keys)
    let bunker_payload_result = nip44::decrypt(
        bunker_keys.secret_key(),
        &third_party_keys.public_key(),
        &payload_encrypted,
    );
    assert!(
        bunker_payload_result.is_err(),
        "Bunker should NOT be able to decrypt payload messages"
    );

    // Third party can decrypt payload
    let payload_decrypted = nip44::decrypt(
        third_party_keys.secret_key(),
        &user_keys.public_key(),
        &payload_encrypted,
    )
    .expect("Third party should decrypt payload messages");
    assert_eq!(payload_decrypted, payload_message);
}
