#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for scoping verifier-embedded nsec handling to browser BYOK registration.
// ABOUTME: Verifies headless registration keeps its stored key while browser BYOK stores the verifier key.

mod common;

use axum::{extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use keycast_api::api::http::oauth;
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_pending_registration(
    pool: &PgPool,
    code: &str,
    user_pubkey: &str,
    email: &str,
    verifier: &str,
    pending_encrypted_secret: Option<&[u8]>,
    is_headless: bool,
) {
    sqlx::query(
        "INSERT INTO oauth_codes (
            code, user_pubkey, client_id, redirect_uri, scope, expires_at, tenant_id, created_at,
            code_challenge, code_challenge_method, pending_email, pending_password_hash,
            pending_email_verification_token, pending_encrypted_secret, is_headless
         ) VALUES (
            $1, $2, 'Verifier Scope Test', 'https://test.example.com/callback', 'policy:social',
            $3, 1, NOW(), $4, 'plain', $5, 'test-password-hash', $6, $7, $8
         )",
    )
    .bind(code)
    .bind(user_pubkey)
    .bind(Utc::now() + Duration::minutes(10))
    .bind(verifier)
    .bind(email)
    .bind(format!("verify-{code}"))
    .bind(pending_encrypted_secret)
    .bind(is_headless)
    .execute(pool)
    .await
    .expect("Should insert pending OAuth registration");
}

async fn exchange_code(pool: &PgPool, code: &str, verifier: &str) -> StatusCode {
    let (auth_state, producer_handle) = common::create_test_auth_state(pool.clone());

    let result = oauth::token(
        common::test_tenant(),
        State(auth_state),
        oauth::TokenRequestBody(oauth::TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(code.to_string()),
            client_id: "Verifier Scope Test".to_string(),
            redirect_uri: Some("https://test.example.com/callback".to_string()),
            code_verifier: Some(verifier.to_string()),
            refresh_token: None,
        }),
    )
    .await;

    producer_handle.abort();
    result.expect("Token exchange should succeed").status()
}

#[tokio::test]
async fn headless_exchange_ignores_mismatching_verifier_nsec_and_uses_stored_secret() {
    let pool = common::setup_oauth_test_db().await;
    let registration_keys = Keys::generate();
    let unrelated_keys = Keys::generate();
    let registration_pubkey = registration_keys.public_key().to_hex();
    let registration_secret = registration_keys.secret_key().to_secret_bytes();
    let verifier = format!(
        "headless-verifier.{}",
        unrelated_keys.secret_key().to_bech32().expect("nsec")
    );
    let code = format!("headless-code-{}", Uuid::new_v4());
    let email = format!("headless-verifier-scope-{}@example.com", Uuid::new_v4());

    insert_pending_registration(
        &pool,
        &code,
        &registration_pubkey,
        &email,
        &verifier,
        Some(&registration_secret),
        true,
    )
    .await;

    assert_eq!(exchange_code(&pool, &code, &verifier).await, StatusCode::OK);

    let stored_user_pubkey: String =
        sqlx::query_scalar("SELECT pubkey FROM users WHERE tenant_id = 1 AND email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("Registration should create the user");
    let stored_secret: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = 1 AND user_pubkey = $1",
    )
    .bind(&registration_pubkey)
    .fetch_one(&pool)
    .await
    .expect("Registration should create personal keys");

    assert_eq!(stored_user_pubkey, registration_pubkey);
    assert_eq!(stored_secret, registration_secret);
}

#[tokio::test]
async fn browser_byok_exchange_extracts_validates_and_stores_verifier_nsec() {
    let pool = common::setup_oauth_test_db().await;
    let browser_keys = Keys::generate();
    let browser_pubkey = browser_keys.public_key().to_hex();
    let browser_secret = browser_keys.secret_key().to_secret_bytes();
    let verifier = format!(
        "browser-verifier.{}",
        browser_keys.secret_key().to_bech32().expect("nsec")
    );
    let code = format!("browser-code-{}", Uuid::new_v4());
    let email = format!("browser-verifier-scope-{}@example.com", Uuid::new_v4());

    insert_pending_registration(
        &pool,
        &code,
        &browser_pubkey,
        &email,
        &verifier,
        None,
        false,
    )
    .await;

    assert_eq!(exchange_code(&pool, &code, &verifier).await, StatusCode::OK);

    let stored_secret: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = 1 AND user_pubkey = $1",
    )
    .bind(&browser_pubkey)
    .fetch_one(&pool)
    .await
    .expect("BYOK registration should store personal keys");

    assert_eq!(stored_secret, browser_secret);
}
