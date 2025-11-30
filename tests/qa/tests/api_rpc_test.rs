use keycast_qa_tests::fixtures::{TestApp, TestUser};
use keycast_qa_tests::helpers::nip46::Nip46Client;
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;
use nostr::Keys;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,keycast_qa_tests=debug")
        .try_init();
}

#[tokio::test]
async fn api_rpc_006_get_public_key() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Get public key
    let pubkey = nip46.get_public_key().await.expect("get_public_key should succeed");

    // Verify it's a valid hex pubkey
    assert_eq!(pubkey.len(), 64, "Public key should be 64 hex chars");
    assert!(
        pubkey.chars().all(|c| c.is_ascii_hexdigit()),
        "Public key should be valid hex"
    );

    // Note: user pubkey (from get_public_key) differs from bunker_pubkey (from bunker URL)
    // due to HKDF derivation for privacy. This is by design.
    let bunker_pubkey = nip46.bunker_pubkey();
    assert_ne!(
        pubkey, bunker_pubkey,
        "User pubkey should differ from bunker pubkey (privacy via HKDF)"
    );
}

#[tokio::test]
async fn api_rpc_007_sign_event() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Sign a text note
    let signed_event = nip46
        .sign_text_note("Hello from QA test!")
        .await
        .expect("sign_event should succeed");

    // Get the actual user pubkey (different from bunker_pubkey after HKDF derivation)
    let user_pubkey = nip46.get_public_key().await.expect("Should get user pubkey");

    // Verify event properties
    assert_eq!(signed_event.kind.as_u16(), 1, "Event kind should be 1");
    assert_eq!(
        signed_event.content,
        "Hello from QA test!",
        "Content should match"
    );
    assert_eq!(
        signed_event.pubkey.to_hex(),
        user_pubkey,
        "Signed event pubkey should match user's actual pubkey"
    );

    // Verify signature is present and valid format
    let sig = signed_event.sig.to_string();
    assert_eq!(sig.len(), 128, "Signature should be 128 hex chars");

    // Verify event ID is present and valid format
    let id = signed_event.id.to_hex();
    assert_eq!(id.len(), 64, "Event ID should be 64 hex chars");

    // Verify the event signature (nostr-sdk validates on deserialization)
    assert!(
        signed_event.verify().is_ok(),
        "Event signature should be valid"
    );
}

#[tokio::test]
async fn api_rpc_nip44_encrypt_decrypt_roundtrip() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Generate a recipient keypair
    let recipient_keys = Keys::generate();
    let recipient_pubkey = recipient_keys.public_key().to_hex();

    let plaintext = "This is a secret message for NIP-44 testing";

    // Encrypt
    let ciphertext = nip46
        .nip44_encrypt(&recipient_pubkey, plaintext)
        .await
        .expect("nip44_encrypt should succeed");

    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");

    // Decrypt
    let decrypted = nip46
        .nip44_decrypt(&recipient_pubkey, &ciphertext)
        .await
        .expect("nip44_decrypt should succeed");

    assert_eq!(decrypted, plaintext, "Decrypted text should match original");
}

#[tokio::test]
async fn api_rpc_nip04_encrypt_decrypt_roundtrip() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Generate a recipient keypair
    let recipient_keys = Keys::generate();
    let recipient_pubkey = recipient_keys.public_key().to_hex();

    let plaintext = "This is a secret message for NIP-04 testing";

    // Encrypt
    let ciphertext = nip46
        .nip04_encrypt(&recipient_pubkey, plaintext)
        .await
        .expect("nip04_encrypt should succeed");

    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");

    // Decrypt
    let decrypted = nip46
        .nip04_decrypt(&recipient_pubkey, &ciphertext)
        .await
        .expect("nip04_decrypt should succeed");

    assert_eq!(decrypted, plaintext, "Decrypted text should match original");
}

#[tokio::test]
async fn api_rpc_without_auth_fails() {
    init_tracing();
    let server = TestServer::from_env();
    let client = reqwest::Client::new();

    // Try RPC call without authentication
    let url = format!("{}/api/nostr", server.base_url);
    let request = serde_json::json!({
        "method": "get_public_key",
        "params": []
    });

    let resp = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .expect("Request should complete");

    // Should fail with 401 Unauthorized
    assert!(
        resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
        "Should return 401 or 403 without auth, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn api_rpc_with_invalid_token_fails() {
    init_tracing();
    let server = TestServer::from_env();
    let client = reqwest::Client::new();

    // Try RPC call with invalid token
    let url = format!("{}/api/nostr", server.base_url);
    let request = serde_json::json!({
        "method": "get_public_key",
        "params": []
    });

    let resp = client
        .post(&url)
        .header("Authorization", "Bearer invalid_token_12345")
        .json(&request)
        .send()
        .await
        .expect("Request should complete");

    // Should fail with 401 Unauthorized
    assert!(
        resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
        "Should return 401 or 403 with invalid token, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn api_rpc_unsupported_method_fails() {
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

    // Try unsupported method
    let client = reqwest::Client::new();
    let url = format!("{}/api/nostr", server.base_url);
    let request = serde_json::json!({
        "method": "unsupported_method",
        "params": []
    });

    let resp = client
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", token_resp.access_token.unwrap_or_default()),
        )
        .json(&request)
        .send()
        .await
        .expect("Request should complete");

    // Should return error (400 or error in response)
    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("error").is_some(),
            "Should return error for unsupported method"
        );
    } else {
        assert!(
            resp.status().as_u16() == 400 || resp.status().as_u16() == 404,
            "Should return 400 or 404 for unsupported method, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn api_rpc_sign_event_invalid_format_fails() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Try to sign invalid event (missing required fields)
    let invalid_event = serde_json::json!({
        "content": "Missing kind and created_at"
    });

    let result = nip46.sign_event(invalid_event).await;
    assert!(result.is_err(), "Should fail to sign invalid event");
}

#[tokio::test]
async fn api_rpc_pubkey_consistency() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Get public key multiple times
    let pubkey1 = nip46.get_public_key().await.expect("First call should succeed");
    let pubkey2 = nip46.get_public_key().await.expect("Second call should succeed");
    let pubkey3 = nip46.get_public_key().await.expect("Third call should succeed");

    // All should be the same
    assert_eq!(pubkey1, pubkey2, "Public keys should be consistent");
    assert_eq!(pubkey2, pubkey3, "Public keys should be consistent");
}

#[tokio::test]
async fn api_rpc_sign_multiple_events() {
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

    // Create NIP-46 client
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Sign multiple events
    let events: Vec<_> = futures::future::join_all((0..5).map(|i| {
        let client = &nip46;
        async move { client.sign_text_note(&format!("Test message {}", i)).await }
    }))
    .await;

    // All should succeed
    for (i, result) in events.iter().enumerate() {
        assert!(result.is_ok(), "Event {} should be signed successfully", i);
    }

    // All should have unique IDs
    let ids: Vec<_> = events.iter().filter_map(|r| r.as_ref().ok()).map(|e| e.id.to_hex()).collect();
    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique_ids.len(), "All events should have unique IDs");
}
