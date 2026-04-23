#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for ClaimTokenRepository::create_with_prior_invalidation
// ABOUTME: Regenerate path — transactional insert + invalidate priors

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
async fn create_with_prior_invalidation_invalidates_existing_and_inserts_new() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let pk = pk64("pk_regen_1");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    ensure_user(&pool, pk, 1).await;

    let original = repo
        .create("tok_v1_regen", pk, Some("admin1"), 1)
        .await
        .expect("create");
    assert_eq!(original.invalidated_at, None);

    let (new_tok, invalidated_count) = repo
        .create_with_prior_invalidation("tok_v2_regen", pk, Some("admin2"), 1)
        .await
        .expect("create_with_prior_invalidation");

    assert_eq!(invalidated_count, 1);
    assert_eq!(new_tok.token, "tok_v2_regen");
    assert!(new_tok.expires_at > Utc::now() + Duration::days(6));
    assert_eq!(new_tok.invalidated_at, None);

    let v1 = sqlx::query_as::<_, keycast_core::types::claim_token::ClaimToken>(
        "SELECT * FROM account_claim_tokens WHERE token = $1",
    )
    .bind("tok_v1_regen")
    .fetch_one(&pool)
    .await
    .expect("fetch v1");
    assert!(v1.invalidated_at.is_some());
    assert_eq!(v1.invalidated_by.as_deref(), Some("admin2"));
    assert_eq!(
        v1.invalidation_reason.as_deref(),
        Some("replaced_by_regenerate")
    );

    cleanup(&pool, pk).await;
}

#[tokio::test]
async fn create_with_prior_invalidation_noops_when_no_priors() {
    let pool = common::setup_test_db().await;
    let repo = ClaimTokenRepository::new(pool.clone());
    let pk = pk64("pk_regen_2");
    let pk = pk.as_str();
    cleanup(&pool, pk).await;
    ensure_user(&pool, pk, 1).await;

    let (new_tok, invalidated_count) = repo
        .create_with_prior_invalidation("tok_fresh_regen", pk, Some("admin1"), 1)
        .await
        .expect("create_with_prior_invalidation");

    assert_eq!(invalidated_count, 0);
    assert_eq!(new_tok.token, "tok_fresh_regen");

    cleanup(&pool, pk).await;
}
