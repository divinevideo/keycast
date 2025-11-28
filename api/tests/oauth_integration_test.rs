// ABOUTME: Additional integration tests for OAuth edge cases and error handling
// ABOUTME: Tests denial flows, expired codes, redirect URI mismatches, and multiple apps
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

fn init_test_state(pool: SqlitePool) -> Arc<keycast_api::state::KeycastState> {
    use keycast_api::state::KeycastState;

    let key_manager = Box::new(TestKeyManager::new());
    Arc::new(KeycastState {
        db: pool,
        key_manager,
    })
}

/// Test user denying OAuth authorization
#[tokio::test]
async fn test_oauth_user_denies_authorization() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let state = init_test_state(pool.clone());
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register a user first
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

    // User denies authorization
    let deny_req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "client_id": "testapp",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "sign_event",
                "approved": false
            })
            .to_string(),
        ))
        .unwrap();

    let deny_response = app.oneshot(deny_req).await.unwrap();

    // Should redirect with error
    assert!(
        deny_response.status() == StatusCode::FOUND
            || deny_response.status() == StatusCode::SEE_OTHER
    );

    let location = deny_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=access_denied"));
}

/// Test OAuth with mismatched redirect_uri
#[tokio::test]
async fn test_oauth_redirect_uri_mismatch() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let state = init_test_state(pool.clone());
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register and get approval code with one redirect_uri
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

    // Approve with specific redirect_uri
    let approve_req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
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

    // Try to exchange code with different redirect_uri
    let token_req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": code,
                "client_id": "testapp",
                "redirect_uri": "http://evil.com/callback"  // Different redirect_uri
            })
            .to_string(),
        ))
        .unwrap();

    let token_response = app.oneshot(token_req).await.unwrap();

    // Should fail with 400 Bad Request
    assert_eq!(token_response.status(), StatusCode::BAD_REQUEST);

    let body = token_response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("redirect_uri"));
}

/// Test that authorization code can only be used once
#[tokio::test]
async fn test_oauth_code_single_use() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let state = init_test_state(pool.clone());
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register user
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

    // Get authorization code
    let approve_req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
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
    let approve_body = approve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let approve_json: serde_json::Value = serde_json::from_slice(&approve_body).unwrap();
    let code = approve_json["code"].as_str().unwrap();

    // Exchange code successfully the first time
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

    let token_response = app.clone().oneshot(token_req).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);

    // Try to use the same code again
    let token_req2 = Request::builder()
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

    let token_response2 = app.oneshot(token_req2).await.unwrap();

    // Should fail with unauthorized
    assert_eq!(token_response2.status(), StatusCode::UNAUTHORIZED);
}

/// Test multiple OAuth applications for same user
#[tokio::test]
async fn test_oauth_multiple_applications() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let state = init_test_state(pool.clone());
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register user
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

    // Authorize first app
    let approve_req1 = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "client_id": "testapp1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "sign_event",
                "approved": true
            })
            .to_string(),
        ))
        .unwrap();

    let approve_response1 = app.clone().oneshot(approve_req1).await.unwrap();
    let approve_body1 = approve_response1
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let approve_json1: serde_json::Value = serde_json::from_slice(&approve_body1).unwrap();
    let code1 = approve_json1["code"].as_str().unwrap();

    // Exchange code for first app
    let token_req1 = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": code1,
                "client_id": "testapp1",
                "redirect_uri": "http://localhost:3000/callback"
            })
            .to_string(),
        ))
        .unwrap();

    let token_response1 = app.clone().oneshot(token_req1).await.unwrap();
    assert_eq!(token_response1.status(), StatusCode::OK);

    let body1 = token_response1.into_body().collect().await.unwrap().to_bytes();
    let json1: serde_json::Value = serde_json::from_slice(&body1).unwrap();
    let bunker_url1 = json1["bunker_url"].as_str().unwrap();

    // Authorize second app
    let approve_req2 = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "client_id": "testapp2",
                "redirect_uri": "http://localhost:4000/callback",
                "scope": "sign_event",
                "approved": true
            })
            .to_string(),
        ))
        .unwrap();

    let approve_response2 = app.clone().oneshot(approve_req2).await.unwrap();
    let approve_body2 = approve_response2
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let approve_json2: serde_json::Value = serde_json::from_slice(&approve_body2).unwrap();
    let code2 = approve_json2["code"].as_str().unwrap();

    // Exchange code for second app
    let token_req2 = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": code2,
                "client_id": "testapp2",
                "redirect_uri": "http://localhost:4000/callback"
            })
            .to_string(),
        ))
        .unwrap();

    let token_response2 = app.oneshot(token_req2).await.unwrap();
    assert_eq!(token_response2.status(), StatusCode::OK);

    let body2 = token_response2.into_body().collect().await.unwrap().to_bytes();
    let json2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    let bunker_url2 = json2["bunker_url"].as_str().unwrap();

    // Verify different bunker URLs were generated
    assert_ne!(bunker_url1, bunker_url2);

    // Verify both authorizations exist in database
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

/// Test OAuth with different scopes
#[tokio::test]
async fn test_oauth_different_scopes() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    let state = init_test_state(pool.clone());
    let app = keycast_api::api::http::routes::routes(pool.clone(), state);

    // Register user
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

    // Test with multiple scopes
    let scopes = vec!["sign_event", "encrypt", "decrypt", "sign_event encrypt decrypt"];

    for scope in scopes {
        let approve_req = Request::builder()
            .method("POST")
            .uri("/oauth/authorize")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "client_id": format!("testapp_{}", scope.replace(' ', "_")),
                    "redirect_uri": "http://localhost:3000/callback",
                    "scope": scope,
                    "approved": true
                })
                .to_string(),
            ))
            .unwrap();

        let approve_response = app.clone().oneshot(approve_req).await.unwrap();
        assert_eq!(
            approve_response.status(),
            StatusCode::OK,
            "Failed for scope: {}",
            scope
        );

        let approve_body = approve_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let approve_json: serde_json::Value = serde_json::from_slice(&approve_body).unwrap();
        let code = approve_json["code"].as_str().unwrap();

        // Exchange code
        let token_req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "code": code,
                    "client_id": format!("testapp_{}", scope.replace(' ', "_")),
                    "redirect_uri": "http://localhost:3000/callback"
                })
                .to_string(),
            ))
            .unwrap();

        let token_response = app.clone().oneshot(token_req).await.unwrap();
        assert_eq!(token_response.status(), StatusCode::OK, "Failed for scope: {}", scope);
    }
}
