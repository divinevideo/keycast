#![cfg(feature = "integration-tests")]
// ABOUTME: Integration tests for the Postgres-backed support admin grant list.
// ABOUTME: Covers CRUD, tenant scoping, idempotent grants, and single-connection pools.

mod common;

use keycast_core::repositories::{RepositoryError, SupportAdminRepository};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

use common::TENANT_ID;

/// A pool with one connection, so any nested acquisition fails instead of
/// depending on load.
async fn single_connection_repo(pool: &PgPool) -> SupportAdminRepository {
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    SupportAdminRepository::new(single)
}

async fn insert_tenant(pool: &PgPool, domain: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $1, NOW(), NOW())
         RETURNING id",
    )
    .bind(domain)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../database/migrations")]
async fn add_list_check_and_remove_round_trip(pool: PgPool) {
    let repo = single_connection_repo(&pool).await;
    let grantee = common::unique_pubkey();
    let full_admin = common::unique_pubkey();

    assert!(!repo.is_support_admin(TENANT_ID, &grantee).await.unwrap());
    assert!(repo.list(TENANT_ID).await.unwrap().is_empty());

    assert!(repo.add(TENANT_ID, &grantee, &full_admin).await.unwrap());
    assert!(repo.is_support_admin(TENANT_ID, &grantee).await.unwrap());

    let admins = repo.list(TENANT_ID).await.unwrap();
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].pubkey, grantee);
    assert_eq!(
        admins[0].added_by_pubkey.as_deref(),
        Some(full_admin.as_str())
    );
    assert_eq!(admins[0].email, None);

    assert!(repo.remove(TENANT_ID, &grantee).await.unwrap());
    assert!(!repo.is_support_admin(TENANT_ID, &grantee).await.unwrap());
    assert!(repo.list(TENANT_ID).await.unwrap().is_empty());
    assert!(!repo.remove(TENANT_ID, &grantee).await.unwrap());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn repeated_grant_is_a_no_op_that_keeps_the_original_grantor(pool: PgPool) {
    let repo = single_connection_repo(&pool).await;
    let grantee = common::unique_pubkey();
    let first_admin = common::unique_pubkey();
    let second_admin = common::unique_pubkey();

    assert!(repo.add(TENANT_ID, &grantee, &first_admin).await.unwrap());
    assert!(!repo.add(TENANT_ID, &grantee, &second_admin).await.unwrap());

    let admins = repo.list(TENANT_ID).await.unwrap();
    assert_eq!(admins.len(), 1);
    assert_eq!(
        admins[0].added_by_pubkey.as_deref(),
        Some(first_admin.as_str())
    );
}

#[sqlx::test(migrations = "../database/migrations")]
async fn grants_are_scoped_to_their_tenant(pool: PgPool) {
    let repo = single_connection_repo(&pool).await;
    let other_tenant = insert_tenant(&pool, "other-tenant.example").await;
    let grantee = common::unique_pubkey();
    let full_admin = common::unique_pubkey();

    repo.add(TENANT_ID, &grantee, &full_admin).await.unwrap();

    assert!(repo.is_support_admin(TENANT_ID, &grantee).await.unwrap());
    assert!(!repo.is_support_admin(other_tenant, &grantee).await.unwrap());
    assert!(repo.list(other_tenant).await.unwrap().is_empty());
    assert!(!repo.remove(other_tenant, &grantee).await.unwrap());
    assert!(repo.is_support_admin(TENANT_ID, &grantee).await.unwrap());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn list_reports_the_grantees_email_from_the_same_tenant(pool: PgPool) {
    let repo = single_connection_repo(&pool).await;
    let with_account = common::unique_pubkey();
    let without_account = common::unique_pubkey();
    let full_admin = common::unique_pubkey();
    common::insert_bare_user(&pool, &with_account).await;
    sqlx::query("UPDATE users SET email = 'support@example.com' WHERE pubkey = $1")
        .bind(&with_account)
        .execute(&pool)
        .await
        .unwrap();

    repo.add(TENANT_ID, &with_account, &full_admin)
        .await
        .unwrap();
    repo.add(TENANT_ID, &without_account, &full_admin)
        .await
        .unwrap();

    let admins = repo.list(TENANT_ID).await.unwrap();
    assert_eq!(admins.len(), 2);
    let email_of = |pubkey: &str| {
        admins
            .iter()
            .find(|row| row.pubkey == pubkey)
            .map(|row| row.email.clone())
            .expect("grant listed")
    };
    assert_eq!(
        email_of(&with_account).as_deref(),
        Some("support@example.com")
    );
    assert_eq!(email_of(&without_account), None);
}

#[sqlx::test(migrations = "../database/migrations")]
async fn rejects_pubkeys_that_are_not_lowercase_hex(pool: PgPool) {
    let repo = SupportAdminRepository::new(pool.clone());
    let full_admin = common::unique_pubkey();
    let uppercase = common::unique_pubkey().to_ascii_uppercase();

    let err = repo
        .add(TENANT_ID, &uppercase, &full_admin)
        .await
        .unwrap_err();
    assert!(matches!(err, RepositoryError::Integrity(_)), "{err:?}");
    assert!(matches!(
        repo.add(TENANT_ID, "not-a-pubkey", &full_admin).await,
        Err(RepositoryError::Integrity(_))
    ));
}
