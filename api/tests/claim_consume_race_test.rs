// ABOUTME: Regression tests for the claim-token consume race (#280 review)
// ABOUTME: Token consumption must be atomic with validity; a dead token must never mutate the user

#![cfg(feature = "integration-tests")]

mod common;

use keycast_core::repositories::{ClaimConsumeOutcome, ClaimTokenRepository, UserRepository};
use nostr_sdk::Keys;
use sqlx::PgPool;

const TENANT_ID: i64 = 1;
const ADMIN_PUBKEY: &str = "adminadminadminadminadminadminadminadminadminadminadminadmin1234";

fn generate_token() -> String {
    Keys::generate().public_key().to_hex()
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

    let outcome = UserRepository::new(pool.clone())
        .claim_account_consuming_token(&token, TENANT_ID, &email_for(&pubkey), "hash")
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

    // Concurrent admin action: revoke invalidates the outstanding link.
    let invalidated = claim_repo
        .invalidate_valid_for_user(&pubkey, TENANT_ID, ADMIN_PUBKEY, Some("revoked"))
        .await
        .expect("invalidate");
    assert_eq!(invalidated, 1);

    // The claim flow proceeds — and must be refused with no side effects.
    let outcome = UserRepository::new(pool.clone())
        .claim_account_consuming_token(&token, TENANT_ID, &email_for(&pubkey), "hash")
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

#[tokio::test]
async fn test_expired_token_not_consumed() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;
    sqlx::query(
        "UPDATE account_claim_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE token = $1",
    )
    .bind(&token)
    .execute(&pool)
    .await
    .expect("expire token");

    let outcome = UserRepository::new(pool.clone())
        .claim_account_consuming_token(&token, TENANT_ID, &email_for(&pubkey), "hash")
        .await
        .expect("consume attempt");

    assert!(matches!(outcome, ClaimConsumeOutcome::TokenNotConsumable));
    assert_eq!(user_email(&pool, &pubkey).await, None);
    let (used, _) = token_flags(&pool, &token).await;
    assert!(!used);
}

#[tokio::test]
async fn test_used_token_not_consumed_again() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let pubkey = create_unclaimed_minor(&pool).await;
    let token = create_token_for(&pool, &pubkey).await;

    let repo = UserRepository::new(pool.clone());
    let first = repo
        .claim_account_consuming_token(&token, TENANT_ID, &email_for(&pubkey), "hash")
        .await
        .expect("first consume");
    assert!(matches!(first, ClaimConsumeOutcome::Claimed { .. }));

    let second = repo
        .claim_account_consuming_token(
            &token,
            TENANT_ID,
            &format!("other-{}", email_for(&pubkey)),
            "hash2",
        )
        .await
        .expect("second consume attempt");
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

    let outcome = UserRepository::new(pool.clone())
        .claim_account_consuming_token(&token, TENANT_ID, &email_for(&pubkey), "hash")
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

/// True concurrency: revoke-invalidation racing the claim consume. Exactly one
/// side may win, and the user is mutated iff the consume won. Run several
/// rounds to exercise both orderings.
#[tokio::test]
async fn test_concurrent_invalidate_vs_claim_exactly_one_wins() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    for round in 0..20 {
        let pubkey = create_unclaimed_minor(&pool).await;
        let token = create_token_for(&pool, &pubkey).await;

        let user_repo = UserRepository::new(pool.clone());
        let claim_repo = ClaimTokenRepository::new(pool.clone());
        let (t, pk) = (token.clone(), pubkey.clone());

        let claim_email = email_for(&pubkey);
        let claim_task = tokio::spawn(async move {
            user_repo
                .claim_account_consuming_token(&t, TENANT_ID, &claim_email, "hash")
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
