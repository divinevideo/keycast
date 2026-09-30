#![cfg(feature = "integration-tests")]
// ABOUTME: Tests for UserRepository::confirm_claim_consuming_token -- the atomic
// ABOUTME: guarded consume-and-apply that finishes a staged claim.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::{seed_other_user_with_email, seed_valid_claim_token, TENANT_ID};
use keycast_core::repositories::{ClaimConsumeOutcome, ClaimTokenRepository, UserRepository};
use keycast_core::types::claim_token::CLAIM_CONFIRMATION_EXPIRY_HOURS;
use sqlx::PgPool;

#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_completes_claim_and_consumes_token(pool: PgPool) {
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let repo = UserRepository::new(single);
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

    let (event_type, event_email, hash, metadata): (
        String,
        Option<String>,
        String,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT event_type, email, email_hash, metadata_json FROM auth_events WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event_type, "account_claim");
    assert!(event_email.is_none());
    assert_eq!(hash.len(), 64);
    assert_eq!(metadata, serde_json::json!({}));
    assert_eq!(
        repo.confirm_claim_consuming_token("conf-1", TENANT_ID)
            .await
            .unwrap(),
        ClaimConsumeOutcome::TokenNotConsumable
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_events WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "../database/migrations")]
async fn failed_audit_rolls_back_claim(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let ct_repo = ClaimTokenRepository::new(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    ct_repo
        .stage_pending_claim(
            &token,
            TENANT_ID,
            "new@example.com",
            "hash",
            "audit-fails",
            Utc::now() + Duration::hours(24),
        )
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE auth_events ADD CONSTRAINT reject_claim CHECK (event_type <> 'account_claim')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(repo
        .confirm_claim_consuming_token("audit-fails", TENANT_ID)
        .await
        .is_err());
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(email.is_none());
    assert!(ct_repo.find_valid(&token).await.unwrap().is_some());
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

/// The confirm guard checks `confirmation_expires_at > NOW()` as well as the
/// claim token's own `expires_at`. Backdate only `confirmation_expires_at`
/// (leave the claim token's `expires_at` valid) so a confirm attempt exercises
/// that conjunct specifically, rather than the outer claim-token expiry.
#[sqlx::test(migrations = "../database/migrations")]
async fn confirm_refuses_after_confirmation_window_expires(pool: PgPool) {
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
            "conf-expired-window",
            expires,
        )
        .await
        .unwrap();

    // Backdate ONLY the confirmation window; the claim token's own expires_at
    // (seeded 1 day out by seed_valid_claim_token) stays valid.
    sqlx::query(
        "UPDATE account_claim_tokens SET confirmation_expires_at = NOW() - INTERVAL '1 minute' WHERE token = $1",
    )
    .bind(&token)
    .execute(&pool)
    .await
    .unwrap();

    let outcome = repo
        .confirm_claim_consuming_token("conf-expired-window", TENANT_ID)
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
        "user must not be mutated when only the confirmation window (not the claim token) expired"
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
