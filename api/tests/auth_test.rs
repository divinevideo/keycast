// ABOUTME: Integration tests for personal authentication (register, login, bunker URL)
// ABOUTME: Tests JWT token generation and user-specific bunker URL retrieval
// TODO: Migrate from SQLite to PostgreSQL - these tests are temporarily disabled
#![cfg(feature = "sqlite-tests")]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
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

#[tokio::test]
async fn test_register_login_and_bunker_url() {
    use keycast_api::state::KeycastState;

    // Setup test database
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

    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Test 1: Register a new user
    let email = format!("test_{}@example.com", chrono::Utc::now().timestamp());
    let password = "testpass123";

    let register_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "password": password
            })
            .to_string(),
        ))
        .unwrap();

    let register_resp = app.clone().oneshot(register_req).await.unwrap();
    assert_eq!(register_resp.status(), StatusCode::OK);

    let register_body = register_resp.into_body().collect().await.unwrap().to_bytes();
    let register_data: serde_json::Value = serde_json::from_slice(&register_body).unwrap();

    let token = register_data["token"].as_str().unwrap();
    let user_pubkey = register_data["pubkey"].as_str().unwrap();

    println!("Registered user: {}", user_pubkey);
    println!("Got token: {}", token);

    // Test 2: Get bunker URL with JWT token
    let bunker_req = Request::builder()
        .method("GET")
        .uri("/user/bunker")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let bunker_resp = app.clone().oneshot(bunker_req).await.unwrap();
    assert_eq!(
        bunker_resp.status(),
        StatusCode::OK,
        "Bunker URL request should succeed with valid JWT"
    );

    let bunker_body = bunker_resp.into_body().collect().await.unwrap().to_bytes();
    let bunker_data: serde_json::Value = serde_json::from_slice(&bunker_body).unwrap();

    let bunker_url = bunker_data["bunker_url"].as_str().unwrap();
    println!("Got bunker URL: {}", bunker_url);

    // Verify bunker URL format
    assert!(bunker_url.starts_with("bunker://"));
    assert!(bunker_url.contains("relay="));
    assert!(bunker_url.contains("secret="));

    // Test 3: Login with same credentials
    let login_req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "password": password
            })
            .to_string(),
        ))
        .unwrap();

    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_resp.status(), StatusCode::OK);

    let login_body = login_resp.into_body().collect().await.unwrap().to_bytes();
    let login_data: serde_json::Value = serde_json::from_slice(&login_body).unwrap();

    let login_token = login_data["token"].as_str().unwrap();
    let login_pubkey = login_data["pubkey"].as_str().unwrap();

    assert_eq!(login_pubkey, user_pubkey, "Login should return same pubkey");

    // Test 4: Get bunker URL with login token
    let bunker_req2 = Request::builder()
        .method("GET")
        .uri("/user/bunker")
        .header(header::AUTHORIZATION, format!("Bearer {}", login_token))
        .body(Body::empty())
        .unwrap();

    let bunker_resp2 = app.clone().oneshot(bunker_req2).await.unwrap();
    assert_eq!(bunker_resp2.status(), StatusCode::OK);

    let bunker_body2 = bunker_resp2.into_body().collect().await.unwrap().to_bytes();
    let bunker_data2: serde_json::Value = serde_json::from_slice(&bunker_body2).unwrap();

    let bunker_url2 = bunker_data2["bunker_url"].as_str().unwrap();

    // Should get same bunker URL for same user
    assert_eq!(bunker_url, bunker_url2, "Same user should get same bunker URL");

    println!("✅ All auth tests passed!");
}

#[tokio::test]
async fn test_bunker_url_without_auth() {
    use keycast_api::state::KeycastState;

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

    let app = keycast_api::api::http::routes::routes(pool, state);

    // Try to get bunker URL without Authorization header
    let bunker_req = Request::builder()
        .method("GET")
        .uri("/user/bunker")
        .body(Body::empty())
        .unwrap();

    let bunker_resp = app.clone().oneshot(bunker_req).await.unwrap();
    assert_eq!(
        bunker_resp.status(),
        StatusCode::UNAUTHORIZED,
        "Should reject request without Authorization header"
    );
}

#[tokio::test]
async fn test_bunker_url_with_invalid_token() {
    use keycast_api::state::KeycastState;

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

    let app = keycast_api::api::http::routes::routes(pool, state);

    // Try with invalid token
    let bunker_req = Request::builder()
        .method("GET")
        .uri("/user/bunker")
        .header(header::AUTHORIZATION, "Bearer invalid_token_here")
        .body(Body::empty())
        .unwrap();

    let bunker_resp = app.clone().oneshot(bunker_req).await.unwrap();
    assert_eq!(
        bunker_resp.status(),
        StatusCode::UNAUTHORIZED,
        "Should reject request with invalid token"
    );
}

#[tokio::test]
async fn test_register_creates_oauth_authorization() {
    use keycast_api::state::KeycastState;

    // Setup test database
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

    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register a new user
    let email = format!("oauth_test_{}@example.com", chrono::Utc::now().timestamp());
    let password = "testpass123";

    let register_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "password": password
            })
            .to_string(),
        ))
        .unwrap();

    let register_resp = app.clone().oneshot(register_req).await.unwrap();
    assert_eq!(register_resp.status(), StatusCode::OK);

    let register_body = register_resp.into_body().collect().await.unwrap().to_bytes();
    let register_data: serde_json::Value = serde_json::from_slice(&register_body).unwrap();

    let user_pubkey = register_data["pubkey"].as_str().unwrap();

    // Verify OAuth authorization was created in database
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT bunker_public_key FROM oauth_authorizations
         WHERE user_public_key = ?1
         AND application_id = (SELECT id FROM oauth_applications WHERE client_id = 'keycast-login')"
    )
    .bind(user_pubkey)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        result.is_some(),
        "OAuth authorization should be created for new user"
    );

    let (bunker_pubkey,) = result.unwrap();
    println!("OAuth authorization created with bunker pubkey: {}", bunker_pubkey);
}

#[tokio::test]
async fn test_password_reset_then_login() {
    use keycast_api::state::KeycastState;

    // Setup test database
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

    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Step 1: Register a new user with initial password
    let email = format!("reset_test_{}@example.com", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
    let initial_password = "initial_password_123";

    let register_req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "password": initial_password
            })
            .to_string(),
        ))
        .unwrap();

    let register_resp = app.clone().oneshot(register_req).await.unwrap();
    assert_eq!(register_resp.status(), StatusCode::OK, "Registration should succeed");

    let register_body = register_resp.into_body().collect().await.unwrap().to_bytes();
    let register_data: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
    let user_pubkey = register_data["pubkey"].as_str().unwrap().to_string();
    println!("Registered user: {}", user_pubkey);

    // Step 2: Request password reset (this generates a token in the DB)
    let forgot_req = Request::builder()
        .method("POST")
        .uri("/auth/forgot-password")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email
            })
            .to_string(),
        ))
        .unwrap();

    let forgot_resp = app.clone().oneshot(forgot_req).await.unwrap();
    assert_eq!(forgot_resp.status(), StatusCode::OK, "Forgot password should succeed");

    // Step 3: Get the reset token directly from database (simulating email link)
    let reset_token: Option<(String,)> = sqlx::query_as(
        "SELECT password_reset_token FROM users WHERE email = ?1"
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .unwrap();

    let (token,) = reset_token.expect("Reset token should exist in database");
    println!("Got reset token from DB: {}", token);

    // Step 4: Reset password with new password
    let new_password = "new_password_456";

    // Log the password we're about to set (hash only for debugging)
    let password_hash_preview = format!("{:x}", md5::compute(new_password.as_bytes()));
    println!("Setting new password (md5 for debug): {}", password_hash_preview);

    let reset_req = Request::builder()
        .method("POST")
        .uri("/auth/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "token": token,
                "new_password": new_password
            })
            .to_string(),
        ))
        .unwrap();

    let reset_resp = app.clone().oneshot(reset_req).await.unwrap();
    let reset_status = reset_resp.status();
    let reset_body = reset_resp.into_body().collect().await.unwrap().to_bytes();
    let reset_data: serde_json::Value = serde_json::from_slice(&reset_body).unwrap();

    println!("Reset response: {:?}", reset_data);
    assert_eq!(reset_status, StatusCode::OK, "Password reset should succeed");
    assert_eq!(reset_data["success"], true, "Reset should report success");

    // Step 5: Verify password was actually stored in DB
    let stored_hash: Option<(String,)> = sqlx::query_as(
        "SELECT password_hash FROM users WHERE email = ?1"
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .unwrap();

    let (password_hash,) = stored_hash.expect("Password hash should exist");
    println!("Stored password hash: {}", &password_hash[..20]); // Just first 20 chars

    // Verify directly with bcrypt that the password matches
    let direct_verify = bcrypt::verify(new_password, &password_hash).unwrap();
    println!("Direct bcrypt verify result: {}", direct_verify);
    assert!(direct_verify, "Direct bcrypt verification should pass");

    // Step 6: Login with NEW password (this is the flow that's failing in prod)
    println!("Attempting login with password (md5 for debug): {}", password_hash_preview);

    let login_req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "password": new_password
            })
            .to_string(),
        ))
        .unwrap();

    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    let login_status = login_resp.status();
    let login_body = login_resp.into_body().collect().await.unwrap().to_bytes();
    let login_data: serde_json::Value = serde_json::from_slice(&login_body).unwrap();

    println!("Login response status: {}", login_status);
    println!("Login response body: {:?}", login_data);

    assert_eq!(login_status, StatusCode::OK, "Login with new password should succeed");
    assert_eq!(login_data["pubkey"].as_str().unwrap(), user_pubkey, "Should login as same user");

    // Step 7: Verify OLD password no longer works
    let old_login_req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "password": initial_password
            })
            .to_string(),
        ))
        .unwrap();

    let old_login_resp = app.clone().oneshot(old_login_req).await.unwrap();
    assert_eq!(old_login_resp.status(), StatusCode::UNAUTHORIZED, "Old password should NOT work");

    println!("✅ Password reset -> login test passed!");
}
