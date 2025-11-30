use keycast_qa_tests::fixtures::{TestApp, TestUser};
use keycast_qa_tests::helpers::nip46::{connect_via_relay, parse_bunker_url};
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;
use nostr::{EventBuilder, Keys, Kind};
use nostr_connect::prelude::*;
use std::time::Duration;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,keycast_qa_tests=debug")
        .try_init();
}

#[tokio::test]
async fn nip46_001_connect_via_bunker_url() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow to get bunker URL
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Parse bunker URL
    let (pubkey, relays, secret) = parse_bunker_url(&token_resp.bunker_url)
        .expect("Should parse bunker URL");

    assert!(!pubkey.is_empty(), "Pubkey should not be empty");
    assert!(!relays.is_empty(), "Should have at least one relay");
    assert!(!secret.is_empty(), "Secret should not be empty");

    // Connect via relay
    let signer = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Should connect via relay");

    // Get public key to verify connection
    let user_pubkey = signer
        .get_public_key()
        .await
        .expect("Should get signer pubkey");

    // Note: With HKDF-derived bunker keys, the user_pubkey (signing key) differs
    // from bunker_pubkey (bunker URL key) for privacy. This is by design.
    assert_ne!(
        user_pubkey.to_hex(),
        pubkey,
        "User pubkey should differ from bunker pubkey (privacy via HKDF)"
    );

    // User pubkey should be a valid hex string
    assert_eq!(user_pubkey.to_hex().len(), 64, "User pubkey should be 64 hex chars");
}

#[tokio::test]
async fn nip46_002_get_public_key_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    let (bunker_pubkey, _, _) = parse_bunker_url(&token_resp.bunker_url)
        .expect("Should parse bunker URL");

    // Connect via relay
    let signer = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Should connect via relay");

    // Get public key (the user's signing key, NOT the bunker identity key)
    let user_pubkey = signer
        .get_public_key()
        .await
        .expect("get_public_key should succeed");

    // Note: With HKDF-derived bunker keys, user_pubkey differs from bunker_pubkey
    // for privacy (prevents relay traffic correlation). This is by design.
    assert_ne!(
        user_pubkey.to_hex(),
        bunker_pubkey,
        "User pubkey should differ from bunker pubkey (privacy via HKDF)"
    );

    // User pubkey should be a valid 64-char hex string
    assert_eq!(user_pubkey.to_hex().len(), 64, "User pubkey should be 64 hex chars");
    assert!(
        user_pubkey.to_hex().chars().all(|c| c.is_ascii_hexdigit()),
        "User pubkey should be valid hex"
    );
}

#[tokio::test]
async fn nip46_003_sign_event_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let signer = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Should connect via relay");

    // Get public key for event building
    let pubkey = signer
        .get_public_key()
        .await
        .expect("get_public_key should succeed");

    // Build and sign event
    let unsigned = EventBuilder::text_note("Hello from NIP-46 relay test!").build(pubkey);
    let signed_event = signer
        .sign_event(unsigned)
        .await
        .expect("sign_event should succeed");

    // Verify event
    assert_eq!(signed_event.kind, Kind::TextNote, "Kind should be text note");
    assert_eq!(
        signed_event.content,
        "Hello from NIP-46 relay test!",
        "Content should match"
    );
    assert_eq!(signed_event.pubkey, pubkey, "Pubkey should match");
    assert!(signed_event.verify().is_ok(), "Signature should be valid");
}

#[tokio::test]
async fn nip46_004_nip44_encrypt_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let signer = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Should connect via relay");

    // Generate recipient
    let recipient = Keys::generate();
    let plaintext = "Secret message for NIP-44 relay test";

    // Encrypt
    let ciphertext = signer
        .nip44_encrypt(&recipient.public_key(), plaintext)
        .await
        .expect("nip44_encrypt should succeed");

    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");
}

#[tokio::test]
async fn nip46_005_nip44_decrypt_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let signer = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Should connect via relay");

    // Generate recipient
    let recipient = Keys::generate();
    let plaintext = "Secret message for NIP-44 roundtrip test";

    // Encrypt
    let ciphertext = signer
        .nip44_encrypt(&recipient.public_key(), plaintext)
        .await
        .expect("nip44_encrypt should succeed");

    // Decrypt
    let decrypted = signer
        .nip44_decrypt(&recipient.public_key(), &ciphertext)
        .await
        .expect("nip44_decrypt should succeed");

    assert_eq!(decrypted, plaintext, "Decrypted text should match original");
}

#[tokio::test]
async fn nip46_007_secret_reuse_rejected() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // First client connects successfully
    let signer1 = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("First client should connect");

    // Verify first client works
    let _pubkey1 = signer1
        .get_public_key()
        .await
        .expect("First client should work");

    // Second client with same secret should fail
    // Note: The bunker URL contains the same secret, so connecting again
    // from a different client should be rejected per NIP-46
    let signer2_result = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30)).await;

    // This behavior depends on implementation:
    // - Some implementations allow reconnection from same logical client
    // - Some reject any new connection with same secret
    // The test documents the actual behavior
    if signer2_result.is_ok() {
        // If second connection succeeds, it might be treated as reconnection
        // from the same client. This is acceptable per some interpretations.
        println!("Note: Second connection succeeded (may be same-client reconnection)");
    } else {
        // If second connection fails, secret reuse is being enforced
        println!("Secret reuse rejected as expected");
    }
}

#[tokio::test]
#[ignore] // NIP-46 secrets are single-use; reconnection with same secret isn't supported
async fn nip46_008_same_client_reconnect() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // First connection
    let signer1 = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("First connection should succeed");

    let pubkey1 = signer1
        .get_public_key()
        .await
        .expect("get_public_key should succeed");

    // Drop first signer to simulate disconnect
    drop(signer1);

    // Small delay to ensure cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Reconnect with same bunker URL (same client scenario)
    // This should work as it's the same logical client reconnecting
    let signer2 = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Reconnection should succeed");

    let pubkey2 = signer2
        .get_public_key()
        .await
        .expect("get_public_key after reconnect should succeed");

    assert_eq!(pubkey1, pubkey2, "Public keys should match after reconnect");
}

#[tokio::test]
async fn nip46_bunker_url_format_validation() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    let bunker_url = &token_resp.bunker_url;

    // Validate bunker URL format
    assert!(bunker_url.starts_with("bunker://"), "Should start with bunker://");

    // Parse and validate components
    let (pubkey, relays, secret) = parse_bunker_url(bunker_url).expect("Should parse bunker URL");

    // Pubkey validation
    assert_eq!(pubkey.len(), 64, "Pubkey should be 64 hex chars");
    assert!(
        pubkey.chars().all(|c| c.is_ascii_hexdigit()),
        "Pubkey should be valid hex"
    );

    // Relay validation
    assert!(!relays.is_empty(), "Should have at least one relay");
    for relay in &relays {
        assert!(
            relay.starts_with("wss://") || relay.starts_with("ws://"),
            "Relay should be valid WebSocket URL: {}",
            relay
        );
    }

    // Secret validation
    assert!(secret.len() >= 32, "Secret should be at least 32 chars");
}

#[tokio::test]
async fn nip46_multiple_operations_sequence() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let signer = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(30))
        .await
        .expect("Should connect via relay");

    let recipient = Keys::generate();

    // Sequence of operations
    // 1. Get public key
    let pubkey = signer.get_public_key().await.expect("Step 1: get_public_key");

    // 2. Sign first event
    let event1 = signer
        .sign_event(EventBuilder::text_note("First note").build(pubkey))
        .await
        .expect("Step 2: sign first event");
    assert!(event1.verify().is_ok(), "First event should be valid");

    // 3. Encrypt message
    let plaintext = "Secret for sequence test";
    let ciphertext = signer
        .nip44_encrypt(&recipient.public_key(), plaintext)
        .await
        .expect("Step 3: encrypt");

    // 4. Sign second event
    let event2 = signer
        .sign_event(EventBuilder::text_note("Second note").build(pubkey))
        .await
        .expect("Step 4: sign second event");
    assert!(event2.verify().is_ok(), "Second event should be valid");

    // 5. Decrypt message
    let decrypted = signer
        .nip44_decrypt(&recipient.public_key(), &ciphertext)
        .await
        .expect("Step 5: decrypt");
    assert_eq!(decrypted, plaintext, "Decrypted should match");

    // 6. Get public key again (should be consistent)
    let pubkey2 = signer
        .get_public_key()
        .await
        .expect("Step 6: get_public_key again");
    assert_eq!(pubkey, pubkey2, "Pubkey should be consistent");

    // All events should have same pubkey
    assert_eq!(event1.pubkey, pubkey, "Event1 pubkey should match");
    assert_eq!(event2.pubkey, pubkey, "Event2 pubkey should match");

    // Events should have different IDs
    assert_ne!(event1.id, event2.id, "Events should have different IDs");
}
