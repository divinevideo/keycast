// ABOUTME: Repository tests for token-gated email-change confirm/cancel (#223 review fix)
// ABOUTME: Proves a token superseded by a concurrent re-initiation cannot mutate the fresh change

use chrono::{Duration, Utc};
use keycast_core::repositories::{PendingEmailSide, UserRepository};
use sqlx::PgPool;
use uuid::Uuid;

const TENANT_ID: i64 = 1;

fn assert_test_database_url() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    assert!(
        url.contains("localhost") || url.contains("127.0.0.1"),
        "Tests must run against localhost database"
    );
}

async fn setup_pool() -> PgPool {
    assert_test_database_url();
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

async fn create_user(pool: &PgPool, pubkey: &str, email: &str) {
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, 'x', true, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .execute(pool)
    .await
    .expect("create user");
}

/// (pending_email, old_confirmed_at, new_confirmed_at)
async fn pending_state(
    pool: &PgPool,
    pubkey: &str,
) -> (
    Option<String>,
    Option<chrono::DateTime<Utc>>,
    Option<chrono::DateTime<Utc>>,
) {
    sqlx::query_as(
        "SELECT pending_email, pending_email_old_confirmed_at, pending_email_new_confirmed_at
         FROM users WHERE pubkey = $1",
    )
    .bind(pubkey)
    .fetch_one(pool)
    .await
    .expect("read pending state")
}

fn new_pubkey() -> String {
    format!("{:0>64}", Uuid::new_v4().simple())
}

/// A confirm token resolved before a concurrent re-initiation rotated the tokens must NOT mark
/// the fresh change confirmed. The handler resolves token->side first, so the stale write would
/// otherwise land on the new pending change keyed only by pubkey+tenant.
#[tokio::test]
async fn stale_confirm_token_does_not_confirm_fresh_change() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = new_pubkey();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email).await;

    let expires = Utc::now() + Duration::hours(1);
    let stale_old = format!("stale-old-{}", Uuid::new_v4());
    repo.set_pending_email_change(
        &pubkey,
        TENANT_ID,
        "a@example.com",
        &stale_old,
        "stale-new",
        expires,
    )
    .await
    .unwrap();

    // Concurrent re-initiation to a different address rotates both tokens in place.
    let fresh_old = format!("fresh-old-{}", Uuid::new_v4());
    repo.set_pending_email_change(
        &pubkey,
        TENANT_ID,
        "b@example.com",
        &fresh_old,
        "fresh-new",
        expires,
    )
    .await
    .unwrap();

    // Stale confirm (side already resolved to Old before rotation) must not touch the fresh change.
    let updated = repo
        .mark_pending_email_confirmed(&pubkey, TENANT_ID, PendingEmailSide::Old, &stale_old)
        .await
        .unwrap();
    assert!(!updated, "stale token should update no rows");

    let (pending, old_conf, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending.as_deref(), Some("b@example.com"));
    assert!(
        old_conf.is_none(),
        "fresh change's old side must remain unconfirmed"
    );

    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
}

/// A current confirm token marks its side and reports a row was updated.
#[tokio::test]
async fn valid_confirm_token_marks_side() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = new_pubkey();
    create_user(
        &pool,
        &pubkey,
        &format!("old-{}@example.com", Uuid::new_v4()),
    )
    .await;

    let expires = Utc::now() + Duration::hours(1);
    let old_tok = format!("old-{}", Uuid::new_v4());
    repo.set_pending_email_change(
        &pubkey,
        TENANT_ID,
        "new@example.com",
        &old_tok,
        "new-tok",
        expires,
    )
    .await
    .unwrap();

    let updated = repo
        .mark_pending_email_confirmed(&pubkey, TENANT_ID, PendingEmailSide::Old, &old_tok)
        .await
        .unwrap();
    assert!(updated, "current token should update one row");

    let (_, old_conf, _) = pending_state(&pool, &pubkey).await;
    assert!(old_conf.is_some(), "old side should be confirmed");

    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
}

/// A cancel token superseded by a concurrent re-initiation must NOT wipe the fresh change.
#[tokio::test]
async fn stale_cancel_token_does_not_clear_fresh_change() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = new_pubkey();
    create_user(
        &pool,
        &pubkey,
        &format!("old-{}@example.com", Uuid::new_v4()),
    )
    .await;

    let expires = Utc::now() + Duration::hours(1);
    let stale_old = format!("stale-old-{}", Uuid::new_v4());
    repo.set_pending_email_change(
        &pubkey,
        TENANT_ID,
        "a@example.com",
        &stale_old,
        "stale-new",
        expires,
    )
    .await
    .unwrap();
    let fresh_old = format!("fresh-old-{}", Uuid::new_v4());
    repo.set_pending_email_change(
        &pubkey,
        TENANT_ID,
        "b@example.com",
        &fresh_old,
        "fresh-new",
        expires,
    )
    .await
    .unwrap();

    let cleared = repo
        .clear_pending_email_change_by_token(&pubkey, TENANT_ID, &stale_old)
        .await
        .unwrap();
    assert!(!cleared, "stale token should clear no rows");

    let (pending, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(
        pending.as_deref(),
        Some("b@example.com"),
        "fresh change must survive"
    );

    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
}

/// A current cancel token clears the pending change.
#[tokio::test]
async fn valid_cancel_token_clears_change() {
    let pool = setup_pool().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = new_pubkey();
    create_user(
        &pool,
        &pubkey,
        &format!("old-{}@example.com", Uuid::new_v4()),
    )
    .await;

    let expires = Utc::now() + Duration::hours(1);
    let new_tok = format!("new-{}", Uuid::new_v4());
    repo.set_pending_email_change(
        &pubkey,
        TENANT_ID,
        "new@example.com",
        "old-tok",
        &new_tok,
        expires,
    )
    .await
    .unwrap();

    let cleared = repo
        .clear_pending_email_change_by_token(&pubkey, TENANT_ID, &new_tok)
        .await
        .unwrap();
    assert!(cleared, "current token should clear one row");

    let (pending, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending, None, "pending change should be cleared");

    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await;
}
