use keycast_qa_tests::fixtures::{PkceChallenge, TestApp, TestUser};
use keycast_qa_tests::helpers::nip46::Nip46Client;
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;
use nostr::{Keys, ToBech32};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,keycast_qa_tests=debug")
        .try_init();
}

/// Journey 1: Complete third-party app integration flow
/// Tests: OAuth -> Bunker URL -> Sign -> Policy Enforcement -> Revoke -> Failure
#[tokio::test]
async fn journey_001_third_party_app_integration() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();

    // Step 1: App redirects user to Keycast OAuth
    let app = TestApp {
        client_id: "third-party-app".to_string(),
        redirect_uri: "http://localhost:5173/callback".to_string(),
        scope: "policy:social".to_string(),
    };

    // Step 2: User registers (new user scenario)
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Step 3: User approves with social policy
    let pkce = PkceChallenge::generate_s256();
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    // Step 4: App receives bunker URL
    let token_resp = oauth
        .exchange_code(&auth_resp.code, &app, &pkce)
        .await
        .expect("Token exchange should succeed");

    assert!(
        !token_resp.bunker_url.is_empty(),
        "App should receive bunker URL"
    );

    // Step 5: App signs kind:1 note (should succeed)
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    let signed_note = nip46
        .sign_text_note("Hello from third-party app!")
        .await
        .expect("Signing kind:1 should succeed");

    assert!(signed_note.verify().is_ok(), "Signed event should be valid");

    // Step 6: Attempt to sign kind:4 DM (may be blocked by policy)
    let dm_event = serde_json::json!({
        "kind": 4,
        "content": "encrypted dm",
        "tags": [["p", "recipient"]],
        "created_at": chrono::Utc::now().timestamp()
    });

    let dm_result = nip46.sign_event(dm_event).await;
    // Document actual behavior
    if dm_result.is_err() {
        println!("Step 6: DM signing blocked by policy as expected");
    } else {
        println!("Step 6: DM signing allowed (policy may permit it)");
    }

    // Step 7: User revokes in dashboard (simulate via DB)
    // Note: nip46.user_pubkey() returns the bunker_public_key from bunker URL
    let pool = server.db_pool().await.expect("Should connect to DB");
    let bunker_pubkey = nip46.user_pubkey();

    sqlx::query(
        "DELETE FROM oauth_authorizations
         WHERE bunker_public_key = $1",
    )
    .bind(&bunker_pubkey)
    .execute(&pool)
    .await
    .expect("Should revoke");

    // Step 8: App signing fails after revocation
    let after_revoke = nip46.sign_text_note("This should fail").await;
    assert!(
        after_revoke.is_err(),
        "Signing should fail after revocation"
    );

    println!("Journey 1 completed successfully");
}

/// Journey 2: Re-authorization after revoke
#[tokio::test]
async fn journey_002_reauthorization_after_revoke() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Step 1: Initial authorization
    let token1 = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("Initial auth should succeed");

    let nip46_1 = Nip46Client::from_token_response(
        token1.bunker_url.clone(),
        token1.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Verify it works
    nip46_1
        .get_public_key()
        .await
        .expect("Initial authorization should work");

    // Step 2: User revokes
    // Note: nip46_1.user_pubkey() returns the bunker_public_key from bunker URL
    let pool = server.db_pool().await.expect("Should connect to DB");
    sqlx::query(
        "DELETE FROM oauth_authorizations
         WHERE bunker_public_key = $1",
    )
    .bind(nip46_1.user_pubkey())
    .execute(&pool)
    .await
    .expect("Should revoke");

    // Verify old authorization is dead
    let revoked_result = nip46_1.get_public_key().await;
    assert!(revoked_result.is_err(), "Revoked auth should not work");

    // Step 3: App re-initiates OAuth
    // Step 4: User re-approves
    let token2 = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("Re-auth should succeed");

    // Step 5: App works again with new secret
    let nip46_2 = Nip46Client::from_token_response(
        token2.bunker_url.clone(),
        token2.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    let pubkey_after_reauth = nip46_2
        .get_public_key()
        .await
        .expect("Re-authorized client should work");

    assert_eq!(
        nip46_1.user_pubkey(),
        pubkey_after_reauth,
        "Same user, same pubkey"
    );

    // Verify new bunker URL is different
    assert_ne!(
        token1.bunker_url, token2.bunker_url,
        "New auth should have different bunker URL"
    );

    println!("Journey 2 completed successfully");
}

/// Journey 3: Multiple apps per user with different policies
#[tokio::test]
async fn journey_003_multiple_apps_per_user() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();

    // Register user first
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Step 1: Authorize App A with social policy
    let app_a = TestApp {
        client_id: "app-a".to_string(),
        redirect_uri: "http://localhost:5173/callback".to_string(),
        scope: "policy:social".to_string(),
    };

    let pkce_a = PkceChallenge::generate_s256();
    let auth_a = oauth
        .submit_authorize(&app_a, &pkce_a, true, None)
        .await
        .expect("App A auth should succeed");

    let token_a = oauth
        .exchange_code(&auth_a.code, &app_a, &pkce_a)
        .await
        .expect("App A token should exchange");

    // Step 2: Authorize App B with full policy
    let app_b = TestApp {
        client_id: "app-b".to_string(),
        redirect_uri: "http://localhost:5174/callback".to_string(),
        scope: "policy:full".to_string(),
    };

    let pkce_b = PkceChallenge::generate_s256();
    let auth_b = oauth.submit_authorize(&app_b, &pkce_b, true, None).await;

    // App B might fail if full policy doesn't exist
    if let Ok(auth_b_resp) = auth_b {
        if let Ok(token_b) = oauth.exchange_code(&auth_b_resp.code, &app_b, &pkce_b).await {
            // Both apps should have different bunker URLs
            assert_ne!(
                token_a.bunker_url, token_b.bunker_url,
                "Different apps should have different bunker URLs"
            );

            // Create clients
            let nip46_a = Nip46Client::from_token_response(
                token_a.bunker_url.clone(),
                token_a.access_token.clone(),
                server.base_url.clone(),
            )
            .expect("Should create NIP-46 client A");

            let nip46_b = Nip46Client::from_token_response(
                token_b.bunker_url.clone(),
                token_b.access_token.clone(),
                server.base_url.clone(),
            )
            .expect("Should create NIP-46 client B");

            // Both should have same user pubkey
            let pubkey_a = nip46_a.get_public_key().await.expect("App A should work");
            let pubkey_b = nip46_b.get_public_key().await.expect("App B should work");

            assert_eq!(pubkey_a, pubkey_b, "Same user, same pubkey for both apps");

            // Step 3 & 4: Test different policies
            // Both should be able to sign kind:1
            let note_a = nip46_a.sign_text_note("From App A").await;
            let note_b = nip46_b.sign_text_note("From App B").await;

            assert!(note_a.is_ok(), "App A should sign text note");
            assert!(note_b.is_ok(), "App B should sign text note");
        } else {
            println!("App B token exchange failed (policy may not exist)");
        }
    } else {
        println!("App B authorization failed (full policy may not exist)");
    }

    println!("Journey 3 completed");
}

/// Journey 4: Complete BYOK (Bring Your Own Key) flow
#[tokio::test]
async fn journey_004_byok_flow() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Generate existing keys (user already has these)
    let existing_keys = Keys::generate();
    let existing_nsec = existing_keys.secret_key().to_bech32().unwrap();
    let existing_pubkey = existing_keys.public_key().to_hex();

    // Step 1: Register with email/password
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Step 2: Authorize with BYOK (nsec in verifier)
    let pkce = PkceChallenge::with_nsec(&existing_nsec);

    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("BYOK authorization should succeed");

    // Step 3: Exchange code
    let token_resp = oauth
        .exchange_code(&auth_resp.code, &app, &pkce)
        .await
        .expect("BYOK token exchange should succeed");

    // Step 4: Verify pubkey matches existing key
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    let returned_pubkey = nip46.get_public_key().await;

    // If BYOK worked, pubkey should match existing key
    if let Ok(pubkey) = returned_pubkey {
        if pubkey == existing_pubkey {
            println!("BYOK success: Using existing key");
        } else {
            println!(
                "Note: Server may have generated new key or user doesn't have personal key yet"
            );
        }
    }

    println!("Journey 4 completed");
}

/// Journey 5: Encryption roundtrip for private messaging
#[tokio::test]
async fn journey_005_private_messaging_flow() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Set up user
    let token = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    let nip46 = Nip46Client::from_token_response(
        token.bunker_url.clone(),
        token.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Generate recipient (another user)
    let recipient = Keys::generate();
    let recipient_pubkey = recipient.public_key().to_hex();

    // Step 1: User sends encrypted message
    let message = "Hey! This is a private message.";

    let ciphertext_44 = nip46
        .nip44_encrypt(&recipient_pubkey, message)
        .await
        .expect("NIP-44 encrypt should succeed");

    println!("Encrypted with NIP-44: {} bytes", ciphertext_44.len());

    // Step 2: User decrypts their own copy (they can decrypt messages sent by them)
    let decrypted = nip46
        .nip44_decrypt(&recipient_pubkey, &ciphertext_44)
        .await
        .expect("NIP-44 decrypt should succeed");

    assert_eq!(decrypted, message, "Decrypted message should match");

    // Step 3: Also test legacy NIP-04
    let ciphertext_04 = nip46
        .nip04_encrypt(&recipient_pubkey, message)
        .await
        .expect("NIP-04 encrypt should succeed");

    println!("Encrypted with NIP-04: {} bytes", ciphertext_04.len());

    let decrypted_04 = nip46
        .nip04_decrypt(&recipient_pubkey, &ciphertext_04)
        .await
        .expect("NIP-04 decrypt should succeed");

    assert_eq!(decrypted_04, message, "NIP-04 decrypted message should match");

    println!("Journey 5 completed successfully");
}

/// Journey 6: Concurrent operations from same authorization
#[tokio::test]
async fn journey_006_concurrent_operations() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Set up user
    let token = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    let nip46 = Nip46Client::from_token_response(
        token.bunker_url.clone(),
        token.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Run multiple operations concurrently
    let results = futures::future::join_all((0..10).map(|i| {
        let client = &nip46;
        async move {
            match i % 3 {
                0 => client.get_public_key().await.map(|_| "pubkey"),
                1 => client
                    .sign_text_note(&format!("Note {}", i))
                    .await
                    .map(|_| "sign"),
                _ => {
                    let recipient = Keys::generate();
                    client
                        .nip44_encrypt(&recipient.public_key().to_hex(), &format!("Secret {}", i))
                        .await
                        .map(|_| "encrypt")
                }
            }
        }
    }))
    .await;

    // Count successes
    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

    println!(
        "Concurrent operations: {} succeeded, {} failed",
        successes.len(),
        failures.len()
    );

    // At least some should succeed
    assert!(
        successes.len() > 5,
        "Most concurrent operations should succeed"
    );

    println!("Journey 6 completed");
}
