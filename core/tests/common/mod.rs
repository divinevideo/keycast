#![cfg(feature = "integration-tests")]
// ABOUTME: Shared seed helpers for claim-token integration tests (staging + confirm).
// ABOUTME: Included via `mod common;` -- not a test binary of its own.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// The default tenant seeded by `database/migrations`.
pub const TENANT_ID: i64 = 1;

#[allow(dead_code)]
pub fn claim_audit_record(
    pubkey: &str,
    email: &str,
) -> keycast_core::repositories::AuthEventRecord {
    use sha2::{Digest, Sha256};
    keycast_core::repositories::AuthEventRecord {
        tenant_id: TENANT_ID,
        request_id: "repository-test".to_string(),
        endpoint: "/api/claim/confirm".to_string(),
        event_type: "account_claim".to_string(),
        outcome: "success".to_string(),
        reason_code: None,
        http_status: None,
        email: None,
        email_hash: format!("{:x}", Sha256::digest(email.as_bytes())),
        pubkey: Some(pubkey.to_string()),
        pubkey_prefix: None,
        client_id: None,
        redirect_origin: None,
        user_agent: None,
        metadata_json: serde_json::json!({}),
    }
}

#[allow(dead_code)]
pub fn unique_pubkey() -> String {
    Uuid::new_v4().simple().to_string().repeat(2)
}

#[allow(dead_code)]
pub async fn insert_bare_user(pool: &PgPool, pubkey: &str) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("insert bare user");
}

/// Inserts a user and an unused, non-invalidated, not-yet-expired claim
/// token. Returns `(token, pubkey)`.
#[allow(dead_code)]
pub async fn seed_valid_claim_token(pool: &PgPool) -> (String, String) {
    let pubkey = unique_pubkey();
    insert_bare_user(pool, &pubkey).await;

    let token = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO account_claim_tokens (token, user_pubkey, expires_at, created_at, tenant_id)
         VALUES ($1, $2, $3, NOW(), $4)",
    )
    .bind(&token)
    .bind(&pubkey)
    .bind(Utc::now() + Duration::days(1))
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("insert valid claim token");

    (token, pubkey)
}

/// Same as `seed_valid_claim_token`, but the token has already been used.
#[allow(dead_code)]
pub async fn seed_used_claim_token(pool: &PgPool) -> (String, String) {
    let pubkey = unique_pubkey();
    insert_bare_user(pool, &pubkey).await;

    let token = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO account_claim_tokens
             (token, user_pubkey, expires_at, used_at, created_at, tenant_id)
         VALUES ($1, $2, $3, NOW(), NOW(), $4)",
    )
    .bind(&token)
    .bind(&pubkey)
    .bind(Utc::now() + Duration::days(1))
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("insert used claim token");

    (token, pubkey)
}

/// Inserts an unrelated, already-verified user occupying `email`, so a
/// confirm attempt that lands on this address collides on the unique index.
/// Returns the new user's pubkey.
#[allow(dead_code)]
pub async fn seed_other_user_with_email(pool: &PgPool, email: &str) -> String {
    let pubkey = unique_pubkey();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert other user with email");

    pubkey
}
