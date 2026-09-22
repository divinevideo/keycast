#![cfg(feature = "integration-tests")]
// ABOUTME: Tests for ClaimTokenRepository::stage_pending_claim -- the guarded
// ABOUTME: write that stages pending email/password/confirmation state on a claim token.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::{seed_used_claim_token, seed_valid_claim_token, TENANT_ID};
use keycast_core::repositories::{ClaimTokenRepository, StagePendingOutcome};
use keycast_core::types::claim_token::{
    CLAIM_CONFIRMATION_EXPIRY_HOURS, CLAIM_CONFIRMATION_SEND_LIMIT,
};
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

// Each stage consumes one of the token's lifetime confirmation sends, so a
// re-submit loop cannot keep sending mail forever. This is the guard that stops
// a claim-token holder using POST /api/claim as an outbound-email primitive.
#[sqlx::test(migrations = "../database/migrations")]
async fn stage_pending_claim_stops_at_the_lifetime_send_limit(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_valid_claim_token(&pool).await;
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);

    // Every send up to the limit is allowed, so a real claimer correcting a
    // typo is never blocked.
    for attempt in 0..CLAIM_CONFIRMATION_SEND_LIMIT {
        let outcome = repo
            .stage_pending_claim(
                &token,
                TENANT_ID,
                "new@example.com",
                "hash",
                &format!("conf-tok-{attempt}"),
                expires,
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            StagePendingOutcome::Staged,
            "attempt {attempt} of {CLAIM_CONFIRMATION_SEND_LIMIT} should be within budget"
        );
    }

    let outcome = repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "new@example.com",
            "hash",
            "conf-tok-over",
            expires,
        )
        .await
        .unwrap();
    assert_eq!(outcome, StagePendingOutcome::SendLimitReached);

    // The refused attempt must not have staged its confirmation token, or the
    // caller could still mail a working link past the cap.
    let staged: (Option<String>, i32) = sqlx::query_as(
        "SELECT confirmation_token, confirmation_send_count \
         FROM account_claim_tokens WHERE token = $1 AND tenant_id = $2",
    )
    .bind(&token)
    .bind(TENANT_ID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        staged.0,
        Some(format!("conf-tok-{}", CLAIM_CONFIRMATION_SEND_LIMIT - 1)),
        "the over-budget attempt must not overwrite the confirmation token"
    );
    assert_eq!(
        staged.1, CLAIM_CONFIRMATION_SEND_LIMIT,
        "the over-budget attempt must not increment the counter further"
    );
}

// The budget is per claim token, not per recipient address. Without this, the
// cap would be trivially bypassed by alternating addresses -- which is exactly
// how a per-address cooldown would have failed.
#[sqlx::test(migrations = "../database/migrations")]
async fn stage_pending_claim_send_limit_is_not_per_recipient(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_valid_claim_token(&pool).await;
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);

    // Spend the whole budget across distinct addresses, alternating every time.
    for attempt in 0..CLAIM_CONFIRMATION_SEND_LIMIT {
        let outcome = repo
            .stage_pending_claim(
                &token,
                TENANT_ID,
                &format!("victim-{attempt}@example.com"),
                "hash",
                &format!("conf-tok-{attempt}"),
                expires,
            )
            .await
            .unwrap();
        assert_eq!(outcome, StagePendingOutcome::Staged);
    }

    // A brand-new address gets no fresh budget.
    let outcome = repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "another-victim@example.com",
            "hash",
            "conf-tok-over",
            expires,
        )
        .await
        .unwrap();
    assert_eq!(outcome, StagePendingOutcome::SendLimitReached);
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
