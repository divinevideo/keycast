#![cfg(feature = "integration-tests")]
// ABOUTME: Tests for UserRepository::confirm_claim_consuming_token -- the atomic
// ABOUTME: guarded consume-and-apply that finishes a staged claim (Task 4).

mod common;

use chrono::{DateTime, Duration, Utc};
use common::{seed_other_user_with_email, seed_valid_claim_token, TENANT_ID};
use keycast_core::repositories::{ClaimConsumeOutcome, ClaimTokenRepository, UserRepository};
use keycast_core::types::claim_token::CLAIM_CONFIRMATION_EXPIRY_HOURS;
use sqlx::PgPool;

#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_completes_claim_and_consumes_token(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    ct_repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "new@example.com",
            "hash",
            "conf-1",
            expires,
        )
        .await
        .unwrap();

    let outcome = repo
        .confirm_claim_consuming_token("conf-1", TENANT_ID)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ClaimConsumeOutcome::Claimed {
            user_pubkey: pubkey.clone()
        }
    );

    let (email, verified, used): (Option<String>, bool, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT u.email, u.email_verified, t.used_at \
         FROM users u JOIN account_claim_tokens t ON t.user_pubkey = u.pubkey \
         WHERE u.pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(email.as_deref(), Some("new@example.com"));
    assert!(verified);
    assert!(used.is_some());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_refuses_after_admin_invalidation(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    ct_repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "new@example.com",
            "hash",
            "conf-2",
            expires,
        )
        .await
        .unwrap();

    // Admin invalidates between staging and confirm.
    sqlx::query("UPDATE account_claim_tokens SET invalidated_at = NOW() WHERE token = $1")
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();

    let outcome = repo
        .confirm_claim_consuming_token("conf-2", TENANT_ID)
        .await
        .unwrap();
    assert_eq!(outcome, ClaimConsumeOutcome::TokenNotConsumable);

    let email: (Option<String>,) = sqlx::query_as("SELECT email FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        email.0.is_none(),
        "user must not be mutated when the token was invalidated"
    );
}

#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_maps_duplicate_email_to_email_taken(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, _pubkey) = seed_valid_claim_token(&pool).await;
    seed_other_user_with_email(&pool, "taken@example.com").await; // occupies the address
    let expires = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    ct_repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "taken@example.com",
            "hash",
            "conf-3",
            expires,
        )
        .await
        .unwrap();

    let outcome = repo
        .confirm_claim_consuming_token("conf-3", TENANT_ID)
        .await
        .unwrap();
    assert_eq!(outcome, ClaimConsumeOutcome::EmailTaken);
}
