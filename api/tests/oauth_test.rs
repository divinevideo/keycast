// ABOUTME: Integration tests for OAuth authorization flow
// ABOUTME: Tests the complete OAuth 2.0 authorization code flow for bunker URL generation
// TODO: Migrate from SQLite to PostgreSQL - these tests are temporarily disabled
#![cfg(feature = "sqlite-tests")]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use keycast_core::encryption::{KeyManager, KeyManagerError};
use rand::Rng;
use serde_json::json;
use sqlx::SqlitePool;
use std::sync::Arc;
use tower::ServiceExt;

/// Test key manager that uses an in-memory key for encryption/decryption
struct TestKeyManager {
    cipher: Aes256Gcm,
}

impl TestKeyManager {
    fn new() -> Self {
        // Generate a random 256-bit key for testing
        let key: [u8; 32] = rand::thread_rng().gen();
        let cipher = Aes256Gcm::new(&key.into());
        Self { cipher }
    }
}

#[async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext_bytes)
            .map_err(|e| KeyManagerError::Encrypt(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        if ciphertext_bytes.len() < 12 {
            return Err(KeyManagerError::Decrypt("Ciphertext too short".to_string()));
        }

        let nonce = Nonce::from_slice(&ciphertext_bytes[..12]);
        let ciphertext = &ciphertext_bytes[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyManagerError::Decrypt(e.to_string()))
    }
}

/// Test the complete OAuth authorization flow
/// 1. Register a user
/// 2. Request OAuth authorization with client_id and redirect_uri
/// 3. User approves and receives authorization code
/// 4. Exchange code for bunker URL
#[tokio::test]
async fn test_oauth_authorization_flow() {
    use keycast_api::state::KeycastState;

    // Setup test database
    let pool = SqlitePool::connect(":memory:").await.unwrap();

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Initialize KeycastState for testing
    let key_manager = Box::new(TestKeyManager::new());
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager,
    });

    // Build app
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Step 1: Register a new user
    let register_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": "test@example.com",
                "password": "testpass123"
            })
            .to_string(),
        ))
        .unwrap();

    let register_response = app.clone().oneshot(register_req).await.unwrap();
    assert_eq!(register_response.status(), StatusCode::OK);

    let register_body = register_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let register_json: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
    let ucan_token = register_json["token"].as_str().unwrap();

    // Step 2: Request OAuth authorization
    let authorize_req = Request::builder()
        .method("GET")
        .uri("/oauth/authorize?client_id=testapp&redirect_uri=http://localhost:3000/callback&scope=sign_event")
        .header("cookie", format!("session={}", ucan_token))
        .body(Body::empty())
        .unwrap();

    let authorize_response = app.clone().oneshot(authorize_req).await.unwrap();

    // Should return 200 with approval page or redirect with code
    assert_eq!(authorize_response.status(), StatusCode::OK);

    // Step 3: Approve authorization (simulate user clicking "approve")
    let approve_req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", ucan_token))
        .body(Body::from(
            json!({
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "sign_event",
                "approved": true
            })
            .to_string(),
        ))
        .unwrap();

    let approve_response = app.clone().oneshot(approve_req).await.unwrap();

    // Should return JSON with authorization code
    assert_eq!(approve_response.status(), StatusCode::OK);

    let approve_body = approve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let approve_json: serde_json::Value = serde_json::from_slice(&approve_body).unwrap();

    // Extract authorization code from JSON response
    let code = approve_json["code"].as_str().unwrap();

    // Step 4: Exchange code for bunker URL
    let token_req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": code,
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback"
            })
            .to_string(),
        ))
        .unwrap();

    let token_response = app.oneshot(token_req).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);

    let token_body = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();

    // Verify we got a bunker URL
    let bunker_url = token_json["bunker_url"].as_str().unwrap();
    assert!(bunker_url.starts_with("bunker://"));
    assert!(bunker_url.contains("relay="));
    assert!(bunker_url.contains("secret="));

    // Verify authorization was created in database
    let auth_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(auth_count, 1);
}

#[tokio::test]
async fn test_oauth_without_login_redirects() {
    use keycast_api::state::KeycastState;

    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Initialize KeycastState for testing
    let key_manager = Box::new(TestKeyManager::new());
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager,
    });

    let app = keycast_api::api::http::routes::routes(pool, state);

    // Try to authorize without being logged in
    let req = Request::builder()
        .method("GET")
        .uri("/oauth/authorize?client_id=testapp&redirect_uri=http://localhost:3000/callback")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    // Currently returns OK (TODO: should redirect to login when auth middleware is implemented)
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_oauth_invalid_code_returns_error() {
    use keycast_api::state::KeycastState;

    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Initialize KeycastState for testing
    let key_manager = Box::new(TestKeyManager::new());
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager,
    });

    let app = keycast_api::api::http::routes::routes(pool, state);

    // Try to exchange invalid code
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": "invalid_code",
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_oauth_bunker_uses_personal_key() {
    use keycast_api::state::KeycastState;

    // Setup test database
    let pool = SqlitePool::connect(":memory:").await.unwrap();

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Initialize KeycastState for testing
    let key_manager = Box::new(TestKeyManager::new());
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager,
    });

    // Build app
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Step 1: Register a new user
    let register_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": "test@example.com",
                "password": "testpass123"
            })
            .to_string(),
        ))
        .unwrap();

    let register_response = app.clone().oneshot(register_req).await.unwrap();
    assert_eq!(register_response.status(), StatusCode::OK);

    let register_body = register_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let register_json: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
    let ucan_token = register_json["token"].as_str().unwrap();

    // Get the user's actual public key from database
    let user_pubkey: String = sqlx::query_scalar(
        "SELECT pubkey FROM users WHERE email = 'test@example.com')"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // Step 2: Go through OAuth flow
    let authorize_req = Request::builder()
        .method("GET")
        .uri("/oauth/authorize?client_id=testapp&redirect_uri=http://localhost:3000/callback&scope=sign_event")
        .header("cookie", format!("session={}", ucan_token))
        .body(Body::empty())
        .unwrap();

    let authorize_response = app.clone().oneshot(authorize_req).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::OK);

    let approve_req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", ucan_token))
        .body(Body::from(
            json!({
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "sign_event",
                "approved": true
            })
            .to_string(),
        ))
        .unwrap();

    let approve_response = app.clone().oneshot(approve_req).await.unwrap();
    assert_eq!(approve_response.status(), StatusCode::OK);

    let approve_body = approve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let approve_json: serde_json::Value = serde_json::from_slice(&approve_body).unwrap();
    let code = approve_json["code"].as_str().unwrap();

    // Step 3: Exchange code for bunker URL
    let token_req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": code,
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback"
            })
            .to_string(),
        ))
        .unwrap();

    let token_response = app.oneshot(token_req).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);

    let token_body = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();

    // Step 4: Verify bunker URL contains user's actual public key
    let bunker_url = token_json["bunker_url"].as_str().unwrap();
    assert!(bunker_url.starts_with(&format!("bunker://{}", user_pubkey)),
        "Bunker URL should contain user's actual public key. Expected bunker://{}, got {}",
        user_pubkey, bunker_url);

    // Step 5: Verify oauth_authorizations table has user's key
    let (bunker_pubkey_in_db, ): (String, ) = sqlx::query_as(
        "SELECT bunker_public_key FROM oauth_authorizations WHERE user_pubkey = ?1"
    )
    .bind(&user_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(bunker_pubkey_in_db, user_pubkey,
        "bunker_public_key in database should match user's actual public key");
}

#[tokio::test]
async fn test_oauth_authorize_uses_authenticated_user_not_most_recent() {
    use keycast_api::state::KeycastState;

    // Setup test database
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let key_manager = Box::new(TestKeyManager::new());
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager,
    });

    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register FIRST user (Alice)
    let alice_email = "alice@example.com";
    let alice_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": alice_email,
                "password": "alicepass"
            })
            .to_string(),
        ))
        .unwrap();

    let alice_resp = app.clone().oneshot(alice_req).await.unwrap();
    assert_eq!(alice_resp.status(), StatusCode::OK);

    let alice_body = alice_resp.into_body().collect().await.unwrap().to_bytes();
    let alice_json: serde_json::Value = serde_json::from_slice(&alice_body).unwrap();
    let alice_token = alice_json["token"].as_str().unwrap();
    let alice_pubkey = alice_json["pubkey"].as_str().unwrap();

    // Register SECOND user (Bob) - he becomes the "most recent" user
    let bob_email = "bob@example.com";
    let bob_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": bob_email,
                "password": "bobpass"
            })
            .to_string(),
        ))
        .unwrap();

    let bob_resp = app.clone().oneshot(bob_req).await.unwrap();
    assert_eq!(bob_resp.status(), StatusCode::OK);

    let bob_body = bob_resp.into_body().collect().await.unwrap().to_bytes();
    let bob_json: serde_json::Value = serde_json::from_slice(&bob_body).unwrap();
    let _bob_token = bob_json["token"].as_str().unwrap();
    let bob_pubkey = bob_json["pubkey"].as_str().unwrap();

    // Verify they're different users
    assert_ne!(alice_pubkey, bob_pubkey);

    // CRITICAL TEST: Alice approves OAuth with HER token
    // The buggy code uses "ORDER BY created_at DESC LIMIT 1" which would return Bob (most recent)
    // The correct code should use Alice's token to identify HER as the authenticated user
    let approve_req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", alice_token))  // Alice's UCAN
        .body(Body::from(
            json!({
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "sign_event",
                "approved": true
            })
            .to_string(),
        ))
        .unwrap();

    let approve_resp = app.clone().oneshot(approve_req).await.unwrap();
    assert_eq!(approve_resp.status(), StatusCode::OK);

    let approve_body = approve_resp.into_body().collect().await.unwrap().to_bytes();
    let approve_json: serde_json::Value = serde_json::from_slice(&approve_body).unwrap();
    let code = approve_json["code"].as_str().unwrap();

    // Verify the authorization code was created for ALICE, not Bob
    let (code_user_pubkey,): (String,) = sqlx::query_as(
        "SELECT user_pubkey FROM oauth_codes WHERE code = ?1"
    )
    .bind(code)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        code_user_pubkey, alice_pubkey,
        "SECURITY BUG: OAuth code should be for Alice (authenticated user), not Bob (most recent user)"
    );
}

#[tokio::test]
async fn test_nostr_connect_uses_authenticated_user_not_most_recent() {
    use keycast_api::state::KeycastState;

    // Setup test database
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let key_manager = Box::new(TestKeyManager::new());
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager,
    });

    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register FIRST user (Alice)
    let alice_email = "alice@example.com";
    let alice_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": alice_email,
                "password": "alicepass"
            })
            .to_string(),
        ))
        .unwrap();

    let alice_resp = app.clone().oneshot(alice_req).await.unwrap();
    assert_eq!(alice_resp.status(), StatusCode::OK);

    let alice_body = alice_resp.into_body().collect().await.unwrap().to_bytes();
    let alice_json: serde_json::Value = serde_json::from_slice(&alice_body).unwrap();
    let alice_token = alice_json["token"].as_str().unwrap();
    let alice_pubkey = alice_json["pubkey"].as_str().unwrap();

    // Register SECOND user (Bob) - he becomes the "most recent" user
    let bob_email = "bob@example.com";
    let bob_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": bob_email,
                "password": "bobpass"
            })
            .to_string(),
        ))
        .unwrap();

    let bob_resp = app.clone().oneshot(bob_req).await.unwrap();
    assert_eq!(bob_resp.status(), StatusCode::OK);

    let bob_body = bob_resp.into_body().collect().await.unwrap().to_bytes();
    let bob_json: serde_json::Value = serde_json::from_slice(&bob_body).unwrap();
    let _bob_token = bob_json["token"].as_str().unwrap();
    let bob_pubkey = bob_json["pubkey"].as_str().unwrap();

    // Verify they're different users
    assert_ne!(alice_pubkey, bob_pubkey);

    // CRITICAL TEST: Alice approves nostr-login connection with HER token
    // The buggy code uses "ORDER BY created_at DESC LIMIT 1" which would return Bob (most recent)
    // The correct code should use Alice's token to identify HER as the authenticated user
    use axum::http::header;
    let connect_req = Request::builder()
        .method("POST")
        .uri("/oauth/connect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Bearer {}", alice_token))  // Alice's UCAN
        .body(Body::from(
            "client_pubkey=abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab&relay=wss://relay.damus.io&secret=test_secret&approved=true"
        ))
        .unwrap();

    let connect_resp = app.clone().oneshot(connect_req).await.unwrap();
    assert_eq!(connect_resp.status(), StatusCode::OK);

    // Verify OAuth authorization was created for ALICE, not Bob
    let (auth_user_pubkey,): (String,) = sqlx::query_as(
        "SELECT user_pubkey FROM oauth_authorizations
         WHERE client_pubkey = 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab'
         ORDER BY created_at DESC LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        auth_user_pubkey, alice_pubkey,
        "SECURITY BUG: nostr-login authorization should be for Alice (authenticated user), not Bob (most recent user)"
    );
}
