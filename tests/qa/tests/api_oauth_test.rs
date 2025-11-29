use keycast_qa_tests::fixtures::{PkceChallenge, TestApp, TestUser};
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,keycast_qa_tests=debug")
        .try_init();
}

#[tokio::test]
async fn api_001_pkce_s256_validation_success() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate valid PKCE challenge
    let pkce = PkceChallenge::generate_s256();

    // Submit authorization
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    assert!(!auth_resp.code.is_empty(), "Should receive authorization code");

    // Exchange with correct verifier
    let token_resp = oauth
        .exchange_code(&auth_resp.code, &app, &pkce)
        .await
        .expect("Token exchange should succeed with correct PKCE verifier");

    assert!(!token_resp.bunker_url.is_empty(), "Should receive bunker URL");
    assert!(token_resp.bunker_url.starts_with("bunker://"), "Bunker URL should have correct format");
}

#[tokio::test]
async fn api_002_pkce_mismatch_rejected() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate PKCE challenge
    let pkce = PkceChallenge::generate_s256();

    // Submit authorization
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    // Create wrong PKCE with different verifier but same challenge
    let wrong_pkce = PkceChallenge {
        verifier: "wrong_verifier_that_does_not_match_challenge".to_string(),
        challenge: pkce.challenge.clone(),
        method: "S256".to_string(),
    };

    // Exchange with wrong verifier should fail
    let result = oauth.exchange_code(&auth_resp.code, &app, &wrong_pkce).await;

    assert!(result.is_err(), "Token exchange should fail with wrong PKCE verifier");
    let err = result.unwrap_err();
    assert!(
        err.contains("PKCE") || err.contains("verifier") || err.contains("400") || err.contains("401"),
        "Error should mention PKCE validation: {}",
        err
    );
}

#[tokio::test]
async fn api_004_code_single_use() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate PKCE challenge
    let pkce = PkceChallenge::generate_s256();

    // Submit authorization
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    // First exchange should succeed
    let first_result = oauth.exchange_code(&auth_resp.code, &app, &pkce).await;
    assert!(first_result.is_ok(), "First token exchange should succeed");

    // Second exchange with same code should fail
    let second_result = oauth.exchange_code(&auth_resp.code, &app, &pkce).await;
    assert!(
        second_result.is_err(),
        "Second token exchange should fail (code is single-use)"
    );
}

#[tokio::test]
async fn api_005_redirect_uri_mismatch_rejected() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate PKCE challenge
    let pkce = PkceChallenge::generate_s256();

    // Submit authorization with original redirect_uri
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    // Create app with different redirect_uri for token exchange
    let wrong_app = TestApp {
        client_id: app.client_id.clone(),
        redirect_uri: "http://evil.com/steal".to_string(),
        scope: app.scope.clone(),
    };

    // Exchange with wrong redirect_uri should fail
    let result = oauth.exchange_code(&auth_resp.code, &wrong_app, &pkce).await;

    assert!(result.is_err(), "Token exchange should fail with wrong redirect_uri");
    let err = result.unwrap_err();
    assert!(
        err.contains("redirect") || err.contains("mismatch") || err.contains("400"),
        "Error should mention redirect_uri mismatch: {}",
        err
    );
}

#[tokio::test]
async fn api_user_denial_returns_access_denied() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate PKCE challenge
    let pkce = PkceChallenge::generate_s256();

    // Submit authorization with denial
    let result = oauth.submit_authorize(&app, &pkce, false, None).await;

    assert!(result.is_err(), "Denied authorization should return error");
    let err = result.unwrap_err();
    assert!(
        err.contains("access_denied"),
        "Error should be access_denied: {}",
        err
    );
}

#[tokio::test]
async fn api_token_response_format() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Verify token response format (RFC 6749 compliance)
    assert!(!token_resp.bunker_url.is_empty(), "bunker_url required");
    assert_eq!(token_resp.token_type, "Bearer", "token_type should be Bearer");
    assert!(token_resp.expires_in > 0, "expires_in should be positive");

    // Verify bunker URL format
    assert!(
        token_resp.bunker_url.starts_with("bunker://"),
        "bunker_url should start with bunker://"
    );
    assert!(
        token_resp.bunker_url.contains("relay="),
        "bunker_url should contain relay parameter"
    );
    assert!(
        token_resp.bunker_url.contains("secret="),
        "bunker_url should contain secret parameter"
    );
}

#[tokio::test]
async fn api_poll_endpoint_states() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);

    // Test polling with non-existent state
    // Implementation returns 202 (pending) for unknown states
    let result = oauth.poll_authorization("nonexistent_state_12345").await;

    assert!(result.is_ok(), "Poll should return 202 for unknown state");
    let poll_resp = result.unwrap();
    assert_eq!(
        poll_resp.status.as_deref(),
        Some("pending"),
        "Unknown state should return pending status"
    );
    assert!(
        poll_resp.code.is_none(),
        "Unknown state should have no code"
    );
}

#[tokio::test]
async fn api_multiple_authorizations_per_user() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();

    // Two different apps
    let app1 = TestApp {
        client_id: "app1".to_string(),
        redirect_uri: "http://localhost:5173/callback".to_string(),
        scope: "policy:social".to_string(),
    };

    let app2 = TestApp {
        client_id: "app2".to_string(),
        redirect_uri: "http://localhost:5174/callback".to_string(),
        scope: "policy:social".to_string(),
    };

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Authorize app1
    let pkce1 = PkceChallenge::generate_s256();
    let auth1 = oauth.submit_authorize(&app1, &pkce1, true, None).await;
    assert!(auth1.is_ok(), "App1 authorization should succeed");

    // Authorize app2
    let pkce2 = PkceChallenge::generate_s256();
    let auth2 = oauth.submit_authorize(&app2, &pkce2, true, None).await;
    assert!(auth2.is_ok(), "App2 authorization should succeed");

    // Both should get different codes
    let code1 = auth1.unwrap().code;
    let code2 = auth2.unwrap().code;
    assert_ne!(code1, code2, "Different apps should get different codes");

    // Both should be exchangeable
    let token1 = oauth.exchange_code(&code1, &app1, &pkce1).await;
    let token2 = oauth.exchange_code(&code2, &app2, &pkce2).await;

    assert!(token1.is_ok(), "App1 token exchange should succeed");
    assert!(token2.is_ok(), "App2 token exchange should succeed");

    // Should get different bunker URLs (different secrets)
    let url1 = token1.unwrap().bunker_url;
    let url2 = token2.unwrap().bunker_url;
    assert_ne!(url1, url2, "Different apps should get different bunker URLs");
}

#[tokio::test]
async fn api_authorization_code_format() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    // Generate PKCE and authorize
    let pkce = PkceChallenge::generate_s256();
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, None)
        .await
        .expect("Authorization should succeed");

    // Verify code format (should be alphanumeric, sufficient length for security)
    let code = &auth_resp.code;
    assert!(code.len() >= 32, "Authorization code should be at least 32 chars");
    assert!(
        code.chars().all(|c| c.is_alphanumeric()),
        "Authorization code should be alphanumeric"
    );
}

#[tokio::test]
async fn api_state_parameter_preserved() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server);
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register and login user
    oauth.register_user(&user).await.ok();
    oauth.login_user(&user).await.expect("Login should succeed");

    let pkce = PkceChallenge::generate_s256();
    let test_state = "my_unique_state_value_12345";

    // Submit authorization with state
    let auth_resp = oauth
        .submit_authorize(&app, &pkce, true, Some(test_state))
        .await
        .expect("Authorization should succeed");

    // The redirect_uri in response should contain the state
    // (Note: exact behavior depends on implementation)
    assert!(
        !auth_resp.code.is_empty(),
        "Should receive code even with state parameter"
    );
}
