#![cfg(feature = "integration-tests")]

// ABOUTME: Verifies OG Diviner eligibility uses the frozen signup policy.
// ABOUTME: Guards the cutoff and excludes preloaded-but-unclaimed accounts.

use keycast_core::repositories::{og_diviner_cutoff, UserRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    assert!(url.contains("localhost") || url.contains("127.0.0.1"));
    PgPool::connect(&url)
        .await
        .expect("connect to test database")
}

fn pubkey(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

#[tokio::test]
async fn eligibility_uses_signup_claim_and_mobile_authorization_timestamps() {
    let pool = pool().await;
    let repository = UserRepository::new(pool.clone());
    // The real policy value, not a restatement of it: if the cutoff moves, this
    // test moves with it instead of silently testing a date nothing ships.
    let cutoff = og_diviner_cutoff();
    let ordinary = pubkey('1');
    let unclaimed = pubkey('2');
    let claimed_late = pubkey('3');
    let mobile_authorized = pubkey('4');
    let ordinary_completed_late = pubkey('6');
    let ordinary_at_cutoff = pubkey('7');
    let mobile_at_cutoff = pubkey('8');
    let keys = [
        &ordinary,
        &unclaimed,
        &claimed_late,
        &mobile_authorized,
        &ordinary_completed_late,
        &ordinary_at_cutoff,
        &mobile_at_cutoff,
    ];

    for key in keys {
        sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
    }

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

    assert!(!repository
        .is_og_diviner(&ordinary_completed_late, 1, cutoff)
        .await
        .unwrap());

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
        &mobile_authorized,
        &mobile_at_cutoff,
    ] {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, $2, $2)",
        )
        .bind(key)
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    for (key, used_at) in [(&unclaimed, None), (&claimed_late, Some(cutoff))] {
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

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key,
          secret_hash, relays, created_at, updated_at, tenant_id,
          handle_expires_at)
         VALUES ($1, 'https://divine.video', 'divine-mobile', $2,
                 'hash', '[]', $3, $3, 1, $4)",
    )
    .bind(&mobile_authorized)
    .bind(pubkey('5'))
    .bind(cutoff - chrono::Duration::seconds(1))
    .bind(cutoff + chrono::Duration::days(1))
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
    .bind(&mobile_at_cutoff)
    .bind(pubkey('9'))
    .bind(cutoff)
    .bind(cutoff + chrono::Duration::days(1))
    .execute(&pool)
    .await
    .unwrap();

    assert!(repository
        .is_og_diviner(&ordinary, 1, cutoff)
        .await
        .unwrap());
    assert!(!repository
        .is_og_diviner(&unclaimed, 1, cutoff)
        .await
        .unwrap());
    assert!(!repository
        .is_og_diviner(&claimed_late, 1, cutoff)
        .await
        .unwrap());
    assert!(repository
        .is_og_diviner(&mobile_authorized, 1, cutoff)
        .await
        .unwrap());
    assert!(repository
        .is_og_diviner(&ordinary_completed_late, 1, cutoff)
        .await
        .unwrap());
    assert!(!repository
        .is_og_diviner(&ordinary_at_cutoff, 1, cutoff)
        .await
        .unwrap());
    assert!(!repository
        .is_og_diviner(&mobile_at_cutoff, 1, cutoff)
        .await
        .unwrap());

    for key in keys {
        sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
    }
}
