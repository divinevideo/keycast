#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests binding an OAuth authorization code to the client it was issued to.
// ABOUTME: Verifies RFC 6749 section 4.1.3 client_id matching at the token endpoint.

mod common;

use axum::{body::to_bytes, extract::State, http::StatusCode, response::Response};
use chrono::{Duration, Utc};
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

use keycast_api::api::http::oauth;

const ISSUED_CLIENT_ID: &str = "Code Binding Test Client";
const REDIRECT_URI: &str = "https://test.example.com/callback";

/// Insert a pending-registration authorization code issued to `ISSUED_CLIENT_ID`.
async fn insert_authorization_code(pool: &PgPool, code: &str, user_pubkey: &str, email: &str) {
    sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
            pending_email, pending_password_hash, pending_email_verification_token,
            pending_encrypted_secret
         ) VALUES ($1, $2, $3, $4, 'policy:social', $5, 1, NOW(), $6, 'test-password-hash', $7, $8)",
    )
    .bind(code)
    .bind(user_pubkey)
    .bind(ISSUED_CLIENT_ID)
    .bind(REDIRECT_URI)
    .bind(Utc::now() + Duration::minutes(10))
    .bind(email)
    .bind(format!("verify-{code}"))
    .bind(Keys::generate().secret_key().to_secret_bytes().to_vec())
    .execute(pool)
    .await
    .expect("Should insert authorization code");
}

/// Redeem `code` at the token endpoint while presenting `presented_client_id`.
async fn redeem_code(pool: &PgPool, code: &str, presented_client_id: &str) -> Response {
    let (auth_state, producer_handle) = common::create_test_auth_state(pool.clone());

    let result = oauth::token(
        common::test_tenant(),
        State(auth_state),
        oauth::TokenRequestBody(oauth::TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(code.to_string()),
            client_id: presented_client_id.to_string(),
            redirect_uri: Some(REDIRECT_URI.to_string()),
            code_verifier: None,
            refresh_token: None,
        }),
    )
    .await;

    producer_handle.abort();

    match result {
        Ok(response) => response,
        Err(error) => axum::response::IntoResponse::into_response(error),
    }
}

async fn response_json(response: Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Response body should be readable");
    serde_json::from_slice(&bytes).expect("Response body should be JSON")
}

#[tokio::test]
async fn redemption_by_a_different_client_is_rejected_and_leaves_the_code_unspent() {
    let pool = common::setup_oauth_test_db().await;
    let user_pubkey = Keys::generate().public_key().to_hex();
    let code = format!("binding-mismatch-{}", Uuid::new_v4());
    let email = format!("binding-mismatch-{}@example.com", Uuid::new_v4());

    insert_authorization_code(&pool, &code, &user_pubkey, &email).await;

    let response = redeem_code(&pool, &code, "Some Other Client").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["error"],
        serde_json::json!("invalid_grant")
    );

    // The code must survive the rejected redemption so the client it was issued
    // to can still redeem it.
    let code_still_present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_codes WHERE tenant_id = 1 AND code = $1)",
    )
    .bind(&code)
    .fetch_one(&pool)
    .await
    .expect("Query should succeed");
    assert!(
        code_still_present,
        "Rejected redemption must not spend code"
    );

    let user_created: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = 1 AND email = $1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");
    assert!(
        !user_created,
        "Rejected redemption must not complete the pending registration"
    );

    let _ = sqlx::query("DELETE FROM oauth_codes WHERE code = $1")
        .bind(&code)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn redemption_by_the_issued_client_succeeds() {
    let pool = common::setup_oauth_test_db().await;
    let user_pubkey = Keys::generate().public_key().to_hex();
    let code = format!("binding-match-{}", Uuid::new_v4());
    let email = format!("binding-match-{}@example.com", Uuid::new_v4());

    insert_authorization_code(&pool, &code, &user_pubkey, &email).await;

    let response = redeem_code(&pool, &code, ISSUED_CLIENT_ID).await;
    assert_eq!(response.status(), StatusCode::OK);
}
