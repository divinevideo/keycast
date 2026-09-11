// ABOUTME: Regression tests for the claim-token consume race (#280 review)
// ABOUTME: Token consumption must be atomic with validity; a dead token must never mutate the user

#![cfg(feature = "integration-tests")]

mod common;

use chrono::{Duration, Utc};
use keycast_core::repositories::{
    ClaimConsumeOutcome, ClaimTokenRepository, StagePendingOutcome, UserRepository,
};
use keycast_core::types::claim_token::CLAIM_CONFIRMATION_EXPIRY_HOURS;
use nostr_sdk::Keys;
use sqlx::PgPool;

const TENANT_ID: i64 = 1;
const ADMIN_PUBKEY: &str = "adminadminadminadminadminadminadminadminadminadminadminadmin1234";

fn generate_token() -> String {
    Keys::generate().public_key().to_hex()
}

/// Stage a pending claim on `token` (submit-step equivalent of the removed
/// single-step `claim_account_consuming_token`) and return the freshly
/// minted confirmation token. The confirm-step tests below feed that
/// confirmation token to `confirm_claim_consuming_token`, mirroring the real
/// claim_post -> claim_confirm_get two-step flow.
async fn stage_claim(
    claim_repo: &ClaimTokenRepository,
    token: &str,
    email: &str,
    password_hash: &str,
) -> String {
    let confirmation_token = generate_token();
    let expires_at = Utc::now() + Duration::hours(CLAIM_CONFIRMATION_EXPIRY_HOURS);
    let outcome = claim_repo
        .stage_pending_claim(
            token,
            TENANT_ID,
            email,
            password_hash,
            &confirmation_token,
            expires_at,
        )
        .await
        .expect("stage pending claim");
    assert_eq!(
        outcome,
        StagePendingOutcome::Staged,
        "fixture setup: staging must succeed while the token is still valid"
    );
    confirmation_token
}

/// Unique per-user email — the users table has a unique email index and the
/// test database is shared across (parallel) tests and runs.
fn email_for(pubkey: &str) -> String {
    format!("{}@example.com", &pubkey[..12])
}

/// Unclaimed verified-minor user: the population the clear-verified-minor
/// endpoint revokes, and whose outstanding claim link it invalidates.
async fn create_unclaimed_minor(pool: &PgPool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, TRUE, NOW(), NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("create unclaimed minor user");
    pubkey
}

async fn create_token_for(pool: &PgPool, pubkey: &str) -> String {
    let token = generate_token();
    ClaimTokenRepository::new(pool.clone())
        .create(&token, pubkey, Some(ADMIN_PUBKEY), TENANT_ID)
        .await
        .expect("create claim token");
    token
}

async fn user_email(pool: &PgPool, pubkey: &str) -> Option<String> {
    sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
        .bind(pubkey)
        .bind(TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("read user email")
}

/// (used_at set?, invalidated_at set?)
async fn token_flags(pool: &PgPool, token: &str) -> (bool, bool) {
    let row: (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as("SELECT used_at, invalidated_at FROM account_claim_tokens WHERE token = $1")
        .bind(token)
        .fetch_one(pool)
        .await
        .expect("read token flags");
    (row.0.is_some(), row.1.is_some())
}

#[tokio::test]
async fn test_valid_token_consumed_and_account_claimed() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let confirmation_token = stage_claim(&claim_repo, &token, &email_for(&pubkey), "hash").await;

    let outcome = UserRepository::new(pool.clone())
        .confirm_claim_consuming_token(&confirmation_token, TENANT_ID)
        .await
        .expect("consume+claim");

    match outcome {
        ClaimConsumeOutcome::Claimed { user_pubkey } => assert_eq!(user_pubkey, pubkey),
        other => panic!("expected Claimed, got {:?}", other),
    }
    assert_eq!(
        user_email(&pool, &pubkey).await.as_deref(),
        Some(email_for(&pubkey).as_str())
    );
    let (used, invalidated) = token_flags(&pool, &token).await;
    assert!(used, "token must be consumed");
    assert!(!invalidated);
}

/// Liz's exact sequence (#280 review): token classifies Valid, admin
/// invalidation lands (clear-verified-minor revoking the outstanding link),
/// then the claim flow tries to proceed. The consume must fail and the user
/// must be untouched.
///
/// Staged before the two-step split, this test's "claim flow tries to
/// proceed" step is now `confirm_claim_consuming_token` (`claim_confirm_get`)
/// rather than the single-step consume: staging happens first (mirroring
/// `claim_post`, which itself re-checks validity and would already refuse a
/// dead token), so the window this test targets -- a concurrent admin
/// invalidation landing between staging and confirmation -- is the real
/// vulnerability window in the two-step flow.
#[tokio::test]
async fn test_invalidated_token_not_consumed_user_untouched() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;

    let claim_repo = ClaimTokenRepository::new(pool.clone());

    // Mimic the handler: token is Valid at classification time.
    use keycast_core::types::claim_token::ClaimTokenState;
    assert!(matches!(
        claim_repo
            .classify(&token, TENANT_ID)
            .await
            .expect("classify"),
        ClaimTokenState::Valid(_)
    ));

    // claim_post stages the pending claim while the token is still valid.
    let confirmation_token = stage_claim(&claim_repo, &token, &email_for(&pubkey), "hash").await;

    // Concurrent admin action: revoke invalidates the outstanding link.
    let invalidated = claim_repo
        .invalidate_valid_for_user(&pubkey, TENANT_ID, ADMIN_PUBKEY, Some("revoked"))
        .await
        .expect("invalidate");
    assert_eq!(invalidated, 1);

    // The claimer clicks the confirmation link — and must be refused with no
    // side effects.
    let outcome = UserRepository::new(pool.clone())
        .confirm_claim_consuming_token(&confirmation_token, TENANT_ID)
        .await
        .expect("consume attempt");

    assert!(matches!(outcome, ClaimConsumeOutcome::TokenNotConsumable));
    assert_eq!(
        user_email(&pool, &pubkey).await,
        None,
        "user must not be mutated"
    );
    let (used, invalidated) = token_flags(&pool, &token).await;
    assert!(!used, "dead token must not be marked used");
    assert!(invalidated);
}

/// The token is staged while still valid (mirroring `claim_post`, which
/// itself would refuse to stage an already-expired token), then expires
/// before the claimer confirms. `confirm_claim_consuming_token`'s own
/// `expires_at > NOW()` guard on the underlying claim-token row must catch
/// this even though the confirmation window itself hasn't lapsed.
#[tokio::test]
async fn test_expired_token_not_consumed() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let confirmation_token = stage_claim(&claim_repo, &token, &email_for(&pubkey), "hash").await;

    sqlx::query(
        "UPDATE account_claim_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE token = $1",
    )
    .bind(&token)
    .execute(&pool)
    .await
    .expect("expire token");

    let outcome = UserRepository::new(pool.clone())
        .confirm_claim_consuming_token(&confirmation_token, TENANT_ID)
        .await
        .expect("consume attempt");

    assert!(matches!(outcome, ClaimConsumeOutcome::TokenNotConsumable));
    assert_eq!(user_email(&pool, &pubkey).await, None);
    let (used, _) = token_flags(&pool, &token).await;
    assert!(!used);
}

/// A second confirm against the same confirmation token (e.g. the claimer
/// re-clicking the emailed link after already completing the claim) must not
/// re-consume or overwrite anything. This is the two-step analog of replaying
/// the same claim token twice against the removed single-step consume:
/// `confirm_claim_consuming_token` nulls out `confirmation_token` on success,
/// so the replay naturally finds no matching row.
#[tokio::test]
async fn test_used_token_not_consumed_again() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;
    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let confirmation_token = stage_claim(&claim_repo, &token, &email_for(&pubkey), "hash").await;

    let repo = UserRepository::new(pool.clone());
    let first = repo
        .confirm_claim_consuming_token(&confirmation_token, TENANT_ID)
        .await
        .expect("first confirm");
    assert!(matches!(first, ClaimConsumeOutcome::Claimed { .. }));

    let second = repo
        .confirm_claim_consuming_token(&confirmation_token, TENANT_ID)
        .await
        .expect("second confirm attempt");
    assert!(matches!(second, ClaimConsumeOutcome::TokenNotConsumable));
    assert_eq!(
        user_email(&pool, &pubkey).await.as_deref(),
        Some(email_for(&pubkey).as_str()),
        "second attempt must not overwrite the claim"
    );
}

/// If the user row is not claimable (already has an email), the token consume
/// must ROLL BACK — a failed claim must not burn the token.
#[tokio::test]
async fn test_unclaimable_user_rolls_back_token_consume() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;
    let existing_email = format!("existing-{}", email_for(&pubkey));
    sqlx::query("UPDATE users SET email = $3 WHERE pubkey = $1 AND tenant_id = $2")
        .bind(&pubkey)
        .bind(TENANT_ID)
        .bind(&existing_email)
        .execute(&pool)
        .await
        .expect("pre-claim user");

    let claim_repo = ClaimTokenRepository::new(pool.clone());
    let confirmation_token = stage_claim(&claim_repo, &token, &email_for(&pubkey), "hash").await;

    let outcome = UserRepository::new(pool.clone())
        .confirm_claim_consuming_token(&confirmation_token, TENANT_ID)
        .await
        .expect("consume attempt");

    assert!(matches!(outcome, ClaimConsumeOutcome::UserNotClaimable));
    let (used, invalidated) = token_flags(&pool, &token).await;
    assert!(
        !used,
        "token consume must roll back when the user claim fails"
    );
    assert!(!invalidated);
    assert_eq!(
        user_email(&pool, &pubkey).await.as_deref(),
        Some(existing_email.as_str())
    );
}

/// True concurrency: revoke-invalidation racing the claim confirm. Exactly one
/// side may win, and the user is mutated iff the confirm won. Run several
/// rounds to exercise both orderings.
///
/// The claim is staged sequentially, before the race starts -- staging isn't
/// the operation under test here, `confirm_claim_consuming_token` is, since
/// that's now the atomic consume-and-apply the #280 guarantee protects.
#[tokio::test]
async fn test_concurrent_invalidate_vs_claim_exactly_one_wins() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    for round in 0..20 {
        let pubkey = create_unclaimed_minor(&pool).await;
        let token = create_token_for(&pool, &pubkey).await;
        let claim_repo = ClaimTokenRepository::new(pool.clone());
        let confirmation_token =
            stage_claim(&claim_repo, &token, &email_for(&pubkey), "hash").await;

        let user_repo = UserRepository::new(pool.clone());
        let pk = pubkey.clone();

        let ct = confirmation_token.clone();
        let claim_task = tokio::spawn(async move {
            user_repo
                .confirm_claim_consuming_token(&ct, TENANT_ID)
                .await
                .expect("consume attempt")
        });
        let pk2 = pubkey.clone();
        let invalidate_task = tokio::spawn(async move {
            claim_repo
                .invalidate_valid_for_user(&pk2, TENANT_ID, ADMIN_PUBKEY, Some("revoked"))
                .await
                .expect("invalidate attempt")
        });

        let (claim_outcome, invalidated_rows) =
            (claim_task.await.unwrap(), invalidate_task.await.unwrap());

        let consumed = matches!(claim_outcome, ClaimConsumeOutcome::Claimed { .. });
        assert!(
            consumed ^ (invalidated_rows == 1),
            "round {}: exactly one side must win (consumed={}, invalidated_rows={})",
            round,
            consumed,
            invalidated_rows
        );
        assert_eq!(
            user_email(&pool, &pk).await.is_some(),
            consumed,
            "round {}: user mutated iff consume won",
            round
        );
    }
}
