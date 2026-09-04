#![cfg(feature = "integration-tests")]

// ABOUTME: Tests for the marketing-consent service-token endpoints
// ABOUTME: Covers cursor paging, floor writes, consent immutability, and read-then-ack semantics

mod common;

use chrono::{DateTime, Duration, Utc};
use nostr_sdk::Keys;
use sqlx::PgPool;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Seed a user with a known consent state and updated_at, returning its pubkey.
async fn seed(pool: &PgPool, email: &str, consent: &str, updated_at: DateTime<Utc>) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_marketing_consent,
                            email_marketing_consent_at, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, $4, $4)",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(consent)
    .bind(updated_at)
    .execute(pool)
    .await
    .unwrap();
    pubkey
}

async fn cleanup(pool: &PgPool, pubkeys: &[String]) {
    for pubkey in pubkeys {
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await
            .unwrap();
    }
}

/// The cursor is (updated_at, pubkey) precisely because two accounts can share a timestamp. A
/// timestamp-only cursor either skips a record or loops on it forever.
#[tokio::test]
async fn cursor_pages_deterministically_when_timestamps_collide() {
    let pool = setup_pool().await;
    let shared = Utc::now() + Duration::days(3650);
    let a = seed(&pool, "collide-a@example.test", "opted_in", shared).await;
    let b = seed(&pool, "collide-b@example.test", "opted_in", shared).await;
    let (first, second) = if a < b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    };

    // Page one, ordered by (updated_at, pubkey).
    let page_one: Vec<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users
         WHERE tenant_id = 1 AND (updated_at, pubkey) > ($1, $2)
         ORDER BY updated_at, pubkey LIMIT 1",
    )
    .bind(shared - Duration::seconds(1))
    .bind("")
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(page_one[0].0, first);

    // Page two, continuing from page one's last row. Without the pubkey tiebreak this returns the
    // same row again.
    let page_two: Vec<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users
         WHERE tenant_id = 1 AND (updated_at, pubkey) > ($1, $2)
         ORDER BY updated_at, pubkey LIMIT 1",
    )
    .bind(shared)
    .bind(&first)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        page_two[0].0, second,
        "the tiebreak must advance the cursor"
    );

    cleanup(&pool, &[a, b]).await;
}

/// NULL is "never observed", which is not the same as "not opted out". Defaulting it to false
/// would let an unchecked account read as safe to email.
#[tokio::test]
async fn the_floor_starts_null_not_false() {
    let pool = setup_pool().await;
    let pubkey = seed(&pool, "fresh@example.test", "opted_in", Utc::now()).await;

    let floor: Option<bool> =
        sqlx::query_scalar("SELECT email_marketing_global_optout FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(floor, None);
    cleanup(&pool, &[pubkey]).await;
}

/// Recording an opt-out must not touch the consent event. That record is the evidence consent was
/// validly obtained; if this ever fails, the immutability guarantee has been broken.
#[tokio::test]
async fn observing_an_optout_does_not_rewrite_the_consent_event() {
    let pool = setup_pool().await;
    let pubkey = seed(&pool, "stable@example.test", "opted_in", Utc::now()).await;

    // Exactly the statement the endpoint runs.
    sqlx::query(
        "UPDATE users
         SET email_marketing_global_optout = $2,
             email_marketing_optout_observed_at = $3
         WHERE pubkey = $1 AND tenant_id = 1
           AND email_marketing_global_optout IS DISTINCT FROM $2",
    )
    .bind(&pubkey)
    .bind(true)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    let (consent, consent_at, floor): (String, Option<DateTime<Utc>>, Option<bool>) =
        sqlx::query_as(
            "SELECT email_marketing_consent, email_marketing_consent_at,
                    email_marketing_global_optout
             FROM users WHERE pubkey = $1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(
        consent, "opted_in",
        "the consent event must survive an opt-out"
    );
    assert!(consent_at.is_some(), "and keep when it was given");
    assert_eq!(floor, Some(true), "while the floor records the withdrawal");

    cleanup(&pool, &[pubkey]).await;
}

/// Replaying an identical observation must change nothing, so a batch retried after a crash does
/// not churn the observation timestamp.
#[tokio::test]
async fn an_identical_observation_is_a_no_op() {
    let pool = setup_pool().await;
    let pubkey = seed(&pool, "twice@example.test", "opted_in", Utc::now()).await;

    let statement = "UPDATE users
         SET email_marketing_global_optout = $2,
             email_marketing_optout_observed_at = $3
         WHERE pubkey = $1 AND tenant_id = 1
           AND email_marketing_global_optout IS DISTINCT FROM $2";

    let first = sqlx::query(statement)
        .bind(&pubkey)
        .bind(true)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(first.rows_affected(), 1);

    let second = sqlx::query(statement)
        .bind(&pubkey)
        .bind(true)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        second.rows_affected(),
        0,
        "an unchanged observation must not rewrite the row"
    );

    cleanup(&pool, &[pubkey]).await;
}

/// Read and acknowledge are separate calls on purpose: a crash between them replays the deletion
/// rather than losing it, and losing one means emailing someone who deleted their account.
#[tokio::test]
async fn deletions_survive_until_acknowledged() {
    let pool = setup_pool().await;
    let email = format!("bye-{}@example.test", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at) VALUES (1, $1, NOW())",
    )
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    let listed: Vec<(i64,)> = sqlx::query_as(
        "SELECT id FROM email_marketing_deletions WHERE tenant_id = 1 AND email = $1",
    )
    .bind(&email)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(listed.len(), 1);

    // Still present before acknowledgement: reading does not consume.
    let again: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_deletions WHERE tenant_id = 1 AND email = $1",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(again, 1);

    let cleared =
        sqlx::query("DELETE FROM email_marketing_deletions WHERE id = ANY($1) AND tenant_id = $2")
            .bind(vec![listed[0].0])
            .bind(1i64)
            .execute(&pool)
            .await
            .unwrap();
    assert_eq!(cleared.rows_affected(), 1);
}

/// Acknowledging an id that does not exist must be harmless rather than an error, so a retry after
/// a partial failure cannot wedge the drain.
#[tokio::test]
async fn acknowledging_an_unknown_id_is_harmless() {
    let pool = setup_pool().await;
    let cleared =
        sqlx::query("DELETE FROM email_marketing_deletions WHERE id = ANY($1) AND tenant_id = $2")
            .bind(vec![-999_999i64])
            .bind(1i64)
            .execute(&pool)
            .await
            .unwrap();
    assert_eq!(cleared.rows_affected(), 0);
}

/// Email-change rows follow the same read-then-acknowledge contract, and must carry two distinct
/// addresses or the sync cannot find the contact it needs to move.
#[tokio::test]
async fn email_changes_carry_both_addresses_and_survive_until_acknowledged() {
    let pool = setup_pool().await;
    let pubkey = Keys::generate().public_key().to_hex();
    let old_email = format!("old-{}@example.test", uuid::Uuid::new_v4());
    let new_email = format!("new-{}@example.test", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO email_marketing_email_changes
             (tenant_id, pubkey, old_email, new_email, changed_at)
         VALUES (1, $1, $2, $3, NOW())",
    )
    .bind(&pubkey)
    .bind(&old_email)
    .bind(&new_email)
    .execute(&pool)
    .await
    .unwrap();

    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, old_email, new_email FROM email_marketing_email_changes
         WHERE tenant_id = 1 AND pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, old_email);
    assert_eq!(rows[0].2, new_email);
    assert_ne!(
        rows[0].1, rows[0].2,
        "a row whose addresses match cannot locate the contact to move"
    );

    let cleared = sqlx::query(
        "DELETE FROM email_marketing_email_changes WHERE id = ANY($1) AND tenant_id = $2",
    )
    .bind(vec![rows[0].0])
    .bind(1i64)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(cleared.rows_affected(), 1);
}

/// Every statement these endpoints run is tenant-scoped. An unscoped read would return another
/// tenant's accounts to a marketing sync service.
#[tokio::test]
async fn reads_are_tenant_scoped() {
    let pool = setup_pool().await;
    let email = format!("tenant-{}@example.test", uuid::Uuid::new_v4());
    let pubkey = seed(&pool, &email, "opted_in", Utc::now()).await;

    let visible_to_other_tenant: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND pubkey = $2")
            .bind(9999i64)
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        visible_to_other_tenant, 0,
        "a tenant-scoped read must not see another tenant's account"
    );

    cleanup(&pool, &[pubkey]).await;
}

// NOT COVERED HERE: handler-level behaviour.
//
// The tests above exercise the SQL these endpoints run, not the handlers themselves, so they do not
// prove that the service-token guard is wired up. An HTTP-level test was attempted and removed: it
// passed with `authorize_service_token` deleted, because the TenantExtractor 500s first on
// "Tenant cache not initialized". A test that rejects for the wrong reason is worse than none,
// since it reads as proof the guard works.
//
// Covering this properly needs the global test state installed, which requires a live Redis this
// suite does not stand up. Until then the guard is verified by reading `email_marketing.rs`: every
// one of the six handlers calls `authorize_service_token(&headers)?` as its first statement.
// Worth closing when the harness gains a Redis, and worth a reviewer's eye in the meantime.
