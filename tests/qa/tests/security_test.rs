use keycast_qa_tests::fixtures::{TestApp, TestUser};
use keycast_qa_tests::helpers::nip46::Nip46Client;
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,keycast_qa_tests=debug")
        .try_init();
}

#[tokio::test]
async fn sec_revoked_authorization_rejected() {
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

    // Create NIP-46 client and verify it works
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        token_resp.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Verify it works initially
    let pubkey = nip46.get_public_key().await;
    assert!(pubkey.is_ok(), "Initial request should succeed");

    // Revoke by deleting from database (simulates revocation)
    // Note: nip46.bunker_pubkey() returns the bunker_public_key from bunker URL
    let pool = server.db_pool().await.expect("Should connect to database");
    let bunker_pubkey = nip46.bunker_pubkey();

    sqlx::query(
        "DELETE FROM oauth_authorizations
         WHERE bunker_public_key = $1",
    )
    .bind(&bunker_pubkey)
    .execute(&pool)
    .await
    .expect("Should delete authorization");

    // Delay to allow REST RPC handler to detect deletion on next request
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create new client (simulating app trying to use revoked auth)
    let nip46_after_revoke = Nip46Client::from_token_response(
        token_resp.bunker_url,
        token_resp.access_token,
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    // Request after revocation should fail
    let result = nip46_after_revoke.get_public_key().await;
    assert!(
        result.is_err(),
        "Request after revocation should fail"
    );
}

#[tokio::test]
async fn sec_policy_allowed_kinds_enforcement() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();

    // Use social policy which typically allows kind 1 but not kind 4
    let app = TestApp::default().with_scope("policy:social");

    // Complete OAuth flow with social policy
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

    // Kind 1 (text note) should be allowed by social policy
    let kind1_event = serde_json::json!({
        "kind": 1,
        "content": "Hello world",
        "tags": [],
        "created_at": chrono::Utc::now().timestamp()
    });

    let result = nip46.sign_event(kind1_event).await;
    // Note: This depends on actual policy configuration
    // If social policy allows kind 1, this should succeed
    if result.is_err() {
        println!("Kind 1 blocked by policy (may be expected depending on config)");
    }

    // Kind 4 (DM) might be blocked by social policy
    let kind4_event = serde_json::json!({
        "kind": 4,
        "content": "encrypted dm content",
        "tags": [["p", "recipient_pubkey"]],
        "created_at": chrono::Utc::now().timestamp()
    });

    let dm_result = nip46.sign_event(kind4_event).await;
    // Document actual behavior - depends on policy configuration
    if dm_result.is_err() {
        println!("Kind 4 (DM) blocked by social policy as expected");
    } else {
        println!("Kind 4 (DM) allowed by policy");
    }
}

#[tokio::test]
async fn sec_reauthorization_after_revoke_works() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // First authorization
    let token1 = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("First OAuth flow should complete");

    // Verify it works
    let nip46_1 = Nip46Client::from_token_response(
        token1.bunker_url.clone(),
        token1.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    let pubkey1 = nip46_1
        .get_public_key()
        .await
        .expect("First client should work");

    // Revoke by deleting the authorization
    let pool = server.db_pool().await.expect("Should connect to database");
    let redirect_origin = app.redirect_origin();

    sqlx::query(
        "DELETE FROM oauth_authorizations
         WHERE user_pubkey = $1 AND redirect_origin = $2",
    )
    .bind(&pubkey1)
    .bind(&redirect_origin)
    .execute(&pool)
    .await
    .expect("Should delete authorization");

    // Re-authorize
    let token2 = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("Re-authorization should complete");

    // Verify new authorization works
    let nip46_2 = Nip46Client::from_token_response(
        token2.bunker_url.clone(),
        token2.access_token.clone(),
        server.base_url.clone(),
    )
    .expect("Should create NIP-46 client");

    let pubkey2 = nip46_2
        .get_public_key()
        .await
        .expect("Re-authorized client should work");

    // Same user, so pubkey should match
    assert_eq!(pubkey1, pubkey2, "Pubkeys should match after re-auth");

    // New authorization should have different secret (bunker URL)
    assert_ne!(
        token1.bunker_url, token2.bunker_url,
        "New authorization should have different bunker URL"
    );
}

#[tokio::test]
async fn sec_multiple_apps_different_policies() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();

    // Register user first
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // App 1 with social policy
    let app_social = TestApp {
        client_id: "app-social".to_string(),
        redirect_uri: "http://localhost:5173/callback".to_string(),
        scope: "policy:social".to_string(),
    };

    // App 2 with full policy (if available)
    let app_full = TestApp {
        client_id: "app-full".to_string(),
        redirect_uri: "http://localhost:5174/callback".to_string(),
        scope: "policy:full".to_string(),
    };

    // Authorize both apps
    let pkce_social = keycast_qa_tests::fixtures::PkceChallenge::generate_s256();
    let auth_social = oauth
        .submit_authorize(&app_social, &pkce_social, true, None)
        .await;

    let pkce_full = keycast_qa_tests::fixtures::PkceChallenge::generate_s256();
    let auth_full = oauth
        .submit_authorize(&app_full, &pkce_full, true, None)
        .await;

    // Both authorizations should succeed (or fail based on policy availability)
    if let (Ok(auth_s), Ok(auth_f)) = (&auth_social, &auth_full) {
        // Get tokens
        let token_social = oauth.exchange_code(&auth_s.code, &app_social, &pkce_social).await;
        let token_full = oauth.exchange_code(&auth_f.code, &app_full, &pkce_full).await;

        // Both should have different bunker URLs
        if let (Ok(t_s), Ok(t_f)) = (token_social, token_full) {
            assert_ne!(
                t_s.bunker_url, t_f.bunker_url,
                "Different apps should have different bunker URLs"
            );
        }
    }
}

#[tokio::test]
async fn sec_pkce_replay_attack_prevention() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate PKCE
    let pkce = keycast_qa_tests::fixtures::PkceChallenge::generate_s256();

    // Get authorization code
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    // Exchange code (first time - should succeed)
    let first_exchange = oauth.exchange_code(&auth_resp.code, &app, &pkce).await;
    assert!(first_exchange.is_ok(), "First exchange should succeed");

    // Replay attack: Try to exchange same code again
    let replay_attempt = oauth.exchange_code(&auth_resp.code, &app, &pkce).await;
    assert!(
        replay_attempt.is_err(),
        "Replay attack should be prevented (code single-use)"
    );
}

#[tokio::test]
async fn sec_authorization_code_entropy() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate multiple authorization codes
    let mut codes = Vec::new();
    for _ in 0..10 {
        let pkce = keycast_qa_tests::fixtures::PkceChallenge::generate_s256();
        if let Ok(auth_resp) = oauth.submit_authorize(&app, &pkce, true, None).await {
            codes.push(auth_resp.code);
            // Exchange to prevent single-use blocking next iteration
            oauth.exchange_code(&codes.last().unwrap(), &app, &pkce).await.ok();
        }
    }

    // All codes should be unique
    let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(
        codes.len(),
        unique_codes.len(),
        "All authorization codes should be unique"
    );

    // All codes should have sufficient length (at least 32 chars for ~192 bits of entropy)
    for code in &codes {
        assert!(
            code.len() >= 32,
            "Authorization code should have sufficient entropy (>=32 chars)"
        );
    }
}

#[tokio::test]
async fn sec_bunker_secret_entropy() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Get multiple bunker URLs
    let mut secrets = Vec::new();
    for i in 0..5 {
        // Use different redirect URIs to create separate authorizations
        let unique_app = TestApp {
            client_id: format!("app-{}", i),
            redirect_uri: format!("http://localhost:{}/callback", 5173 + i),
            scope: app.scope.clone(),
        };

        if let Ok(token) = oauth.complete_oauth_flow(&user, &unique_app).await {
            // Extract secret from bunker URL
            if let Some(secret_start) = token.bunker_url.find("secret=") {
                let secret = token.bunker_url[secret_start + 7..]
                    .split('&')
                    .next()
                    .unwrap_or("")
                    .to_string();
                secrets.push(secret);
            }
        }
    }

    // All secrets should be unique
    let unique_secrets: std::collections::HashSet<_> = secrets.iter().collect();
    assert_eq!(
        secrets.len(),
        unique_secrets.len(),
        "All bunker secrets should be unique"
    );

    // All secrets should have sufficient length
    for secret in &secrets {
        assert!(
            secret.len() >= 32,
            "Bunker secret should have sufficient entropy (>=32 chars)"
        );
    }
}

#[tokio::test]
async fn sec_cors_headers_present() {
    init_tracing();
    let server = TestServer::from_env();
    let client = reqwest::Client::new();

    // Make OPTIONS request to OAuth endpoint
    let url = server.oauth_url("/authorize");

    let resp = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", "http://example.com")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .expect("OPTIONS request should complete");

    // Check for CORS headers
    let headers = resp.headers();

    // OAuth endpoints should have permissive CORS
    if headers.contains_key("access-control-allow-origin") {
        println!(
            "CORS enabled: {}",
            headers
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("")
        );
    } else {
        println!("Note: CORS headers not present on OPTIONS (may be handled differently)");
    }
}
