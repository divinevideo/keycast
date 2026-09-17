#![cfg(feature = "integration-tests")]

// ABOUTME: Verifies OG Diviner eligibility uses the frozen signup policy.
// ABOUTME: Guards the cutoff and excludes preloaded-but-unclaimed accounts.

use keycast_core::repositories::{og_diviner_cutoff, UserRepository};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

const TENANT_ID: i64 = 1;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    assert!(url.contains("localhost") || url.contains("127.0.0.1"));
    PgPool::connect(&url)
        .await
        .expect("connect to test database")
}

/// Fixture pubkeys carry a prefix unique to this test.
///
/// Generic fillers are shared across the suite -- `api/tests/`
/// `divine_name_promotion_timeout_test.rs` binds `"1".repeat(64)` against this
/// same database in the same run -- so a row leaked from here would collide on
/// the users primary key and fail an unrelated crate's test.
fn pubkey(seed: char) -> String {
    format!("06d1{}", std::iter::repeat_n(seed, 60).collect::<String>())
}

/// Removes every fixture row, scoped to this test's tenant.
async fn purge(pool: &PgPool, keys: &[&str]) {
    for key in keys {
        sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1 AND tenant_id = $2")
            .bind(key)
            .bind(TENANT_ID)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1 AND tenant_id = $2")
            .bind(key)
            .bind(TENANT_ID)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(key)
            .bind(TENANT_ID)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[serial]
async fn eligibility_uses_signup_claim_and_mobile_authorization_timestamps() {
    let pool = pool().await;
    let repository = UserRepository::new(pool.clone());
    // The real policy value, not a restatement of it: if the cutoff moves, this
    // test moves with it instead of silently testing a date nothing ships.
    let cutoff = og_diviner_cutoff();
    let ordinary = pubkey('1');
    let unclaimed = pubkey('2');
    let claimed_late = pubkey('3');
    let claimed_early = pubkey('a');
    let mobile_authorized = pubkey('4');
    let ordinary_completed_late = pubkey('6');
    let ordinary_at_cutoff = pubkey('7');
    let mobile_at_cutoff = pubkey('8');
    let preloaded_mobile_authorized = pubkey('f');
    let preloaded_mobile_at_cutoff = pubkey('0');
    let preloaded_without_token = pubkey('b');
    let claimed_after_cutoff_token_deleted = pubkey('c');
    let suspended_ordinary = pubkey('d');
    let banned_claimed_early = pubkey('e');
    let keys = [
        ordinary.as_str(),
        unclaimed.as_str(),
        claimed_late.as_str(),
        claimed_early.as_str(),
        mobile_authorized.as_str(),
        ordinary_completed_late.as_str(),
        ordinary_at_cutoff.as_str(),
        mobile_at_cutoff.as_str(),
        preloaded_mobile_authorized.as_str(),
        preloaded_mobile_at_cutoff.as_str(),
        preloaded_without_token.as_str(),
        claimed_after_cutoff_token_deleted.as_str(),
        suspended_ordinary.as_str(),
        banned_claimed_early.as_str(),
    ];

    purge(&pool, &keys).await;

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at)
         VALUES ($1, 1, 'ordinary@example.invalid', TRUE, 'hash', $2, $2)",
    )
    .bind(&ordinary)
    .bind(cutoff - chrono::Duration::seconds(1))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, status, created_at, updated_at)
         VALUES ($1, 1, 'suspended@example.invalid', TRUE, 'hash', 'suspended', $2, $2)",
    )
    .bind(&suspended_ordinary)
    .bind(cutoff - chrono::Duration::seconds(1))
    .execute(&pool)
    .await
    .unwrap();

    // vine_id is the durable preload marker. These rows deliberately have no
    // token: one models create_preloaded_user before token issuance; the other
    // models a post-cutoff claim whose consumed token was later cleaned up.
    for (key, vine_id) in [
        (&preloaded_without_token, "vine-without-token"),
        (
            &claimed_after_cutoff_token_deleted,
            "vine-deleted-consumed-token",
        ),
    ] {
        sqlx::query(
            "INSERT INTO users
             (pubkey, tenant_id, vine_id, email, email_verified, password_hash,
              created_at, updated_at)
             VALUES ($1, 1, $2, $3, TRUE, 'hash', $4, $4)",
        )
        .bind(key)
        .bind(vine_id)
        .bind(format!("{vine_id}@example.invalid"))
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at)
         VALUES
         ($1, 1, 'completed-late@example.invalid', FALSE, 'hash', $3, $2),
         ($4, 1, 'at-cutoff@example.invalid', TRUE, 'hash', $2, $2)",
    )
    .bind(&ordinary_completed_late)
    .bind(cutoff)
    .bind(cutoff - chrono::Duration::seconds(1))
    .bind(&ordinary_at_cutoff)
    .execute(&pool)
    .await
    .unwrap();

    // Observed while the row is still unverified; asserted after teardown so a
    // failure here cannot leak fixtures into the shared test database.
    let completed_late_while_unverified = repository
        .is_og_diviner(&ordinary_completed_late, TENANT_ID, cutoff)
        .await
        .unwrap();

    sqlx::query(
        "UPDATE users
         SET email_verified = TRUE, updated_at = $1
         WHERE pubkey = $2 AND tenant_id = 1",
    )
    .bind(cutoff + chrono::Duration::seconds(1))
    .bind(&ordinary_completed_late)
    .execute(&pool)
    .await
    .unwrap();

    for key in [
        &unclaimed,
        &claimed_late,
        &claimed_early,
        &banned_claimed_early,
    ] {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, vine_id, created_at, updated_at)
             VALUES ($1, 1, $2, $3, $3)",
        )
        .bind(key)
        .bind(format!("vine-{key}"))
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    for (key, used_at) in [
        (&unclaimed, None),
        (&claimed_late, Some(cutoff)),
        (&claimed_early, Some(cutoff - chrono::Duration::seconds(1))),
        (
            &banned_claimed_early,
            Some(cutoff - chrono::Duration::seconds(1)),
        ),
    ] {
        sqlx::query(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, tenant_id, expires_at, used_at, created_at)
             VALUES ($1, $2, 1, $3, $4, $5)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(key)
        .bind(cutoff + chrono::Duration::days(1))
        .bind(used_at)
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::query("UPDATE users SET status = 'banned' WHERE pubkey = $1 AND tenant_id = 1")
        .bind(&banned_claimed_early)
        .execute(&pool)
        .await
        .unwrap();

    for (key, bunker, created_at, vine_id) in [
        (
            &mobile_authorized,
            pubkey('5'),
            cutoff - chrono::Duration::seconds(1),
            None,
        ),
        (&mobile_at_cutoff, pubkey('9'), cutoff, None),
        (
            &preloaded_mobile_authorized,
            pubkey('b'),
            cutoff - chrono::Duration::seconds(1),
            Some("vine-mobile-before-cutoff"),
        ),
        (
            &preloaded_mobile_at_cutoff,
            pubkey('c'),
            cutoff,
            Some("vine-mobile-at-cutoff"),
        ),
    ] {
        // This matches completed headless materialization: the user and first
        // mobile authorization are created together at verification time.
        // Preloaded fixtures have no claim token and cannot use the ordinary
        // signup branch, isolating authorization evidence and its cutoff.
        sqlx::query(
            "INSERT INTO users
             (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at, vine_id)
             VALUES ($1, 1, $2, TRUE, 'hash', $3, $3, $4)",
        )
        .bind(key)
        .bind(format!("mobile-{key}@example.invalid"))
        .bind(created_at)
        .bind(vine_id)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO oauth_authorizations
             (user_pubkey, redirect_origin, client_id, bunker_public_key,
              secret_hash, relays, created_at, updated_at, tenant_id,
              handle_expires_at)
             VALUES ($1, 'https://divine.video', 'divine-mobile', $2,
                     'hash', '[]', $3, $3, 1, $4)",
        )
        .bind(key)
        .bind(bunker)
        .bind(created_at)
        .bind(cutoff + chrono::Duration::days(1))
        .execute(&pool)
        .await
        .unwrap();
    }

    let mut observed = Vec::new();
    for key in keys {
        observed.push(
            repository
                .is_og_diviner(key, TENANT_ID, cutoff)
                .await
                .unwrap(),
        );
    }

    // Teardown before the assertions, so the shared database is left clean even
    // when one of them fails.
    purge(&pool, &keys).await;

    let [ordinary_eligible, unclaimed_eligible, claimed_late_eligible, claimed_early_eligible, mobile_authorized_eligible, completed_late_eligible, at_cutoff_eligible, mobile_at_cutoff_eligible, preloaded_mobile_authorized_eligible, preloaded_mobile_at_cutoff_eligible, preloaded_without_token_eligible, deleted_claim_token_eligible, suspended_ordinary_eligible, banned_claimed_early_eligible] =
        observed[..]
    else {
        panic!("expected one observation per fixture");
    };

    assert!(
        !completed_late_while_unverified,
        "an unverified account is not yet complete, so it does not qualify"
    );
    assert!(ordinary_eligible, "pre-cutoff completed signup qualifies");
    assert!(
        preloaded_mobile_authorized_eligible,
        "a preloaded account without claim tokens qualifies through pre-cutoff mobile authorization"
    );
    assert!(
        !preloaded_mobile_at_cutoff_eligible,
        "mobile authorization at the cutoff does not qualify a preloaded account"
    );
    assert!(
        !unclaimed_eligible,
        "a preloaded account nobody claimed does not qualify"
    );
    assert!(
        !claimed_late_eligible,
        "a preloaded account claimed at or after the cutoff does not qualify"
    );
    assert!(
        claimed_early_eligible,
        "a preloaded account claimed before the cutoff qualifies on the claim timestamp"
    );
    assert!(
        mobile_authorized_eligible,
        "a pre-cutoff first-party mobile authorization qualifies"
    );
    assert!(
        completed_late_eligible,
        "completing verification after the cutoff does not forfeit a pre-cutoff signup"
    );
    assert!(
        !at_cutoff_eligible,
        "the cutoff is exclusive: a signup exactly at it does not qualify"
    );
    assert!(
        !mobile_at_cutoff_eligible,
        "the cutoff is exclusive for mobile authorizations too"
    );
    assert!(
        !preloaded_without_token_eligible,
        "a preloaded row without a claim token cannot fall through to ordinary eligibility"
    );
    assert!(
        !deleted_claim_token_eligible,
        "deleting a post-cutoff consumed token cannot make a preloaded account ordinary"
    );
    assert!(
        suspended_ordinary_eligible,
        "suspension does not rewrite historical cohort membership"
    );
    assert!(
        banned_claimed_early_eligible,
        "a ban does not rewrite historical cohort membership"
    );
}
