#![cfg(feature = "integration-tests")]
// ABOUTME: Tests for ClaimTokenRepository::stage_pending_claim -- the guarded
// ABOUTME: write that stages pending email/password/confirmation state on a claim token.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::{seed_used_claim_token, seed_valid_claim_token, TENANT_ID};
use keycast_core::repositories::{ClaimTokenRepository, StagePendingOutcome};
use keycast_core::types::claim_token::CLAIM_CONFIRMATION_EXPIRY_HOURS;
use sqlx::PgPool;

// Stages pending state on a valid token; a used/expired/invalidated token stages nothing.
#[sqlx::test(migrations = "../database/migrations")]
async fn stage_pending_claim_writes_pending_state_on_valid_token(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_valid_claim_token(&pool).await; // helper inserts user + unused, unexpired token

    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    let outcome = repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "new@example.com",
            "hash",
            "conf-tok-1",
            expires,
        )
        .await
        .unwrap();

    assert_eq!(outcome, StagePendingOutcome::Staged);

    let row: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT pending_email, pending_password_hash, confirmation_token \
         FROM account_claim_tokens WHERE token = $1 AND tenant_id = $2",
    )
    .bind(&token)
    .bind(TENANT_ID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            Some("new@example.com".into()),
            Some("hash".into()),
            Some("conf-tok-1".into())
        )
    );

    // used_at is NOT set by staging -- the token is not yet consumed.
    let used: (Option<DateTime<Utc>>,) =
        sqlx::query_as("SELECT used_at FROM account_claim_tokens WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(used.0.is_none());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn stage_pending_claim_refuses_used_token(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_used_claim_token(&pool).await; // used_at set
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    let outcome = repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "new@example.com",
            "hash",
            "conf-tok-1",
            expires,
        )
        .await
        .unwrap();
    assert_eq!(outcome, StagePendingOutcome::TokenNotStageable);
}
