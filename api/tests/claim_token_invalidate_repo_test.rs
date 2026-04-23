#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for ClaimTokenRepository::invalidate_valid_for_user
// ABOUTME: Happy path, idempotent no-op, skips used/already-invalidated tokens

use chrono::{Duration, Utc};
use keycast_core::repositories::ClaimTokenRepository;
use sqlx::PgPool;

mod common;

fn pk64(label: &str) -> String {
    let mut s = label.to_string();
    while s.len() < 64 {
        s.push('0');
    }
    s.truncate(64);
    s
}

async fn ensure_user(pool: &PgPool, pubkey: &str, tenant_id: i64) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id) VALUES ($1, $2)
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(pubkey)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("ensure_user failed");
}

async fn cleanup(pool: &PgPool, user_pubkey: &str) {
    sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
        .bind(user_pubkey)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(user_pubkey)
        .execute(pool)
        .await
        .ok();
}

#[tokio::test]
async fn invalidate_valid_for_user_marks_single_valid_token() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let pk = pk64("pk_inv_repo_1");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    ensure_user(&pool, pk, 1).await;

    let created = repo
        .create("tok_live_inv", pk, Some("admin1"), 1)
        .await
        .expect("create");
    assert_eq!(created.invalidated_at, None);

    let count = repo
        .invalidate_valid_for_user(pk, 1, "admin2", Some("security"))
        .await
        .expect("invalidate");
    assert_eq!(count, 1);

    let after = sqlx::query_as::<_, keycast_core::types::claim_token::ClaimToken>(
        "SELECT * FROM account_claim_tokens WHERE token = $1",
    )
    .bind("tok_live_inv")
    .fetch_one(&pool)
    .await
    .expect("fetch");
    assert!(after.invalidated_at.is_some());
    assert_eq!(after.invalidated_by.as_deref(), Some("admin2"));
    assert_eq!(after.invalidation_reason.as_deref(), Some("security"));
    assert!(after.expires_at <= Utc::now() + Duration::seconds(5));

    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn invalidate_valid_for_user_is_idempotent_when_no_valid_token() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let pk = pk64("pk_inv_repo_2");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    ensure_user(&pool, pk, 1).await;

    let count = repo
        .invalidate_valid_for_user(pk, 1, "admin1", None)
        .await
        .expect("invalidate");
    assert_eq!(count, 0);

    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn invalidate_valid_for_user_skips_used_and_already_invalidated() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let pk = pk64("pk_inv_repo_3");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    ensure_user(&pool, pk, 1).await;

    // Used token (should be skipped)
    sqlx::query(
        "INSERT INTO account_claim_tokens
         (token, user_pubkey, expires_at, created_at, tenant_id, used_at)
         VALUES ($1, $2, $3, NOW(), 1, NOW())",
    )
    .bind("tok_used_skip")
    .bind(pk)
    .bind(Utc::now() + Duration::days(7))
    .execute(&pool)
    .await
    .expect("insert used");

    // Already-invalidated token (should be skipped)
    sqlx::query(
        "INSERT INTO account_claim_tokens
         (token, user_pubkey, expires_at, created_at, tenant_id, invalidated_at, invalidated_by)
         VALUES ($1, $2, $3, NOW(), 1, NOW(), $4)",
    )
    .bind("tok_already_inv_skip")
    .bind(pk)
    .bind(Utc::now() + Duration::days(7))
    .bind("prior_admin")
    .execute(&pool)
    .await
    .expect("insert inv");

    let count = repo
        .invalidate_valid_for_user(pk, 1, "admin_new", Some("explicit"))
        .await
        .expect("invalidate");
    assert_eq!(count, 0);

    cleanup(&pool, pk).await;
}
