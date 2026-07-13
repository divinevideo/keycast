// ABOUTME: Repository-layer tests for the approved-minor flag on the account-status query
// ABOUTME: Covers get_account_status_with_minor backing GET /user/account (keycast#263)

#![cfg(feature = "integration-tests")]

mod common;

use keycast_core::repositories::{AccountStatusWithMinorRow, UserRepository};
use nostr_sdk::Keys;
use sqlx::PgPool;

const TENANT_ID: i64 = 1;

async fn insert_user(pool: &PgPool, verified_minor: bool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    if verified_minor {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at) \
             VALUES ($1, $2, TRUE, NOW(), NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(TENANT_ID)
        .execute(pool)
        .await
        .expect("insert minor user");
    } else {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(TENANT_ID)
        .execute(pool)
        .await
        .expect("insert regular user");
    }
    pubkey
}

#[tokio::test]
async fn approved_minor_surfaces_flag_while_active() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = insert_user(&pool, true).await;

    let AccountStatusWithMinorRow {
        status,
        verified_minor,
        verified_minor_at,
        ..
    } = repo
        .get_account_status_with_minor(&pubkey, TENANT_ID)
        .await
        .expect("query ok")
        .expect("user exists");

    // The whole point of keycast#263: an approved minor is `active`, yet the flag must
    // still come through so clients can detect the protected-minor state.
    assert!(
        status.is_active(),
        "approved minor account should be active"
    );
    assert!(verified_minor, "verified_minor should be true");
    assert!(
        verified_minor_at.is_some(),
        "verified_minor_at should be populated"
    );
}

#[tokio::test]
async fn regular_user_reports_not_a_minor() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let pubkey = insert_user(&pool, false).await;

    let AccountStatusWithMinorRow {
        verified_minor,
        verified_minor_at,
        ..
    } = repo
        .get_account_status_with_minor(&pubkey, TENANT_ID)
        .await
        .expect("query ok")
        .expect("user exists");

    assert!(!verified_minor, "regular user must not read as a minor");
    assert!(verified_minor_at.is_none());
}

#[tokio::test]
async fn returns_none_for_unknown_user() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let unknown = Keys::generate().public_key().to_hex();

    let row = repo
        .get_account_status_with_minor(&unknown, TENANT_ID)
        .await
        .expect("query ok");

    assert!(row.is_none(), "unknown pubkey must yield None");
}
