#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for ClaimTokenRepository::classify
// ABOUTME: Verifies the five discriminated ClaimTokenState variants

use chrono::{DateTime, Duration, Utc};
use keycast_core::repositories::ClaimTokenRepository;
use keycast_core::types::claim_token::ClaimTokenState;
use sqlx::PgPool;

mod common;

/// Pad a label into a 64-char pubkey-shaped string so users.pubkey (CHAR(64)) accepts it.
fn pk64(label: &str) -> String {
    let mut s = label.to_string();
    while s.len() < 64 {
        s.push('0');
    }
    s.truncate(64);
    s
}

/// Ensure a user row exists for the given pubkey so FK constraints on
/// account_claim_tokens.user_pubkey are satisfied.
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

async fn insert_raw_token(
    pool: &PgPool,
    token: &str,
    user_pubkey: &str,
    tenant_id: i64,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    invalidated_at: Option<DateTime<Utc>>,
) {
    ensure_user(pool, user_pubkey, tenant_id).await;
    sqlx::query(
        "INSERT INTO account_claim_tokens
         (token, user_pubkey, expires_at, created_at, tenant_id, used_at, invalidated_at)
         VALUES ($1, $2, $3, NOW(), $4, $5, $6)",
    )
    .bind(token)
    .bind(user_pubkey)
    .bind(expires_at)
    .bind(tenant_id)
    .bind(used_at)
    .bind(invalidated_at)
    .execute(pool)
    .await
    .expect("insert failed");
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
async fn classify_returns_unrecognized_for_missing_token() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let state = repo
        .classify("nope-does-not-exist", 1)
        .await
        .expect("query ok");
    assert!(matches!(state, ClaimTokenState::Unrecognized));
}

#[tokio::test]
async fn classify_returns_valid_for_fresh_token() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let token = "t_classify_valid";
    let pk = pk64("pk_classify_valid");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    insert_raw_token(
        &pool,
        token,
        pk,
        1,
        Utc::now() + Duration::days(7),
        None,
        None,
    )
    .await;
    let state = repo.classify(token, 1).await.expect("query ok");
    assert!(
        matches!(state, ClaimTokenState::Valid(_)),
        "expected Valid, got {:?}",
        state
    );
    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn classify_returns_already_claimed_when_used_at_set() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let token = "t_classify_used";
    let pk = pk64("pk_classify_used");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    insert_raw_token(
        &pool,
        token,
        pk,
        1,
        Utc::now() + Duration::days(7),
        Some(Utc::now()),
        None,
    )
    .await;
    let state = repo.classify(token, 1).await.expect("query ok");
    assert!(
        matches!(state, ClaimTokenState::AlreadyClaimed(_)),
        "expected AlreadyClaimed, got {:?}",
        state
    );
    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn classify_returns_admin_invalidated_when_invalidated_at_set() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let token = "t_classify_inv";
    let pk = pk64("pk_classify_inv");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    insert_raw_token(&pool, token, pk, 1, Utc::now(), None, Some(Utc::now())).await;
    let state = repo.classify(token, 1).await.expect("query ok");
    assert!(
        matches!(state, ClaimTokenState::AdminInvalidated(_)),
        "expected AdminInvalidated, got {:?}",
        state
    );
    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn classify_returns_expired_when_past_with_no_newer() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let token = "t_classify_exp";
    let pk = pk64("pk_classify_exp");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    insert_raw_token(
        &pool,
        token,
        pk,
        1,
        Utc::now() - Duration::hours(1),
        None,
        None,
    )
    .await;
    let state = repo.classify(token, 1).await.expect("query ok");
    assert!(
        matches!(state, ClaimTokenState::Expired(_)),
        "expected Expired, got {:?}",
        state
    );
    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn classify_returns_replaced_when_newer_valid_token_exists() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let old_token = "t_classify_replaced_old";
    let new_token = "t_classify_replaced_new";
    let pk = pk64("pk_classify_replaced");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    // Old, expired
    insert_raw_token(
        &pool,
        old_token,
        pk,
        1,
        Utc::now() - Duration::hours(1),
        None,
        None,
    )
    .await;
    // Small sleep so created_at differs (NOW() resolution)
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    // New, valid
    insert_raw_token(
        &pool,
        new_token,
        pk,
        1,
        Utc::now() + Duration::days(7),
        None,
        None,
    )
    .await;
    let state = repo.classify(old_token, 1).await.expect("query ok");
    assert!(
        matches!(state, ClaimTokenState::Replaced { .. }),
        "expected Replaced, got {:?}",
        state
    );
    cleanup(&pool, pk).await;
}
