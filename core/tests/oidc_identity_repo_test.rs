#![cfg(feature = "integration-tests")]
// ABOUTME: Tests for OidcIdentityRepository (upstream OIDC sign-in links) and for
// ABOUTME: UserRepository::get_optional_email, which the token exchange uses for such accounts.

mod common;

use common::{insert_bare_user, seed_other_user_with_email, unique_pubkey, TENANT_ID};
use keycast_core::repositories::{OidcIdentityRepository, OidcLinkOutcome, UserRepository};
use sqlx::PgPool;

const ISSUER: &str = "https://idp.example/";

#[sqlx::test(migrations = "../database/migrations")]
async fn first_login_links_and_repeats_are_idempotent(pool: PgPool) {
    let repo = OidcIdentityRepository::new(pool.clone());
    let pubkey = unique_pubkey();
    insert_bare_user(&pool, &pubkey).await;

    assert_eq!(
        repo.find_pubkey(TENANT_ID, ISSUER, "sub-1").await.unwrap(),
        None
    );
    assert_eq!(
        repo.link(TENANT_ID, ISSUER, "sub-1", &pubkey)
            .await
            .unwrap(),
        OidcLinkOutcome::Linked
    );
    assert_eq!(
        repo.link(TENANT_ID, ISSUER, "sub-1", &pubkey)
            .await
            .unwrap(),
        OidcLinkOutcome::AlreadyLinked
    );
    assert_eq!(
        repo.find_pubkey(TENANT_ID, ISSUER, "sub-1")
            .await
            .unwrap()
            .as_deref(),
        Some(pubkey.as_str())
    );

    repo.touch(TENANT_ID, ISSUER, "sub-1").await.unwrap();
    let touched: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_login_at FROM oidc_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(ISSUER)
    .bind("sub-1")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(touched.is_some());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn links_are_never_repointed(pool: PgPool) {
    let repo = OidcIdentityRepository::new(pool.clone());
    let alice = unique_pubkey();
    let bob = unique_pubkey();
    insert_bare_user(&pool, &alice).await;
    insert_bare_user(&pool, &bob).await;
    repo.link(TENANT_ID, ISSUER, "sub-alice", &alice)
        .await
        .unwrap();

    // the subject already belongs to another account
    assert_eq!(
        repo.link(TENANT_ID, ISSUER, "sub-alice", &bob)
            .await
            .unwrap(),
        OidcLinkOutcome::Conflict
    );
    // the account already has a subject at this issuer
    assert_eq!(
        repo.link(TENANT_ID, ISSUER, "sub-other", &alice)
            .await
            .unwrap(),
        OidcLinkOutcome::Conflict
    );
    assert_eq!(
        repo.find_pubkey(TENANT_ID, ISSUER, "sub-alice")
            .await
            .unwrap()
            .as_deref(),
        Some(alice.as_str())
    );
    assert_eq!(
        repo.find_pubkey(TENANT_ID, ISSUER, "sub-other")
            .await
            .unwrap(),
        None
    );

    // another issuer is a separate namespace
    assert_eq!(
        repo.link(TENANT_ID, "https://other-idp.example/", "sub-alice", &bob)
            .await
            .unwrap(),
        OidcLinkOutcome::Linked
    );
}

#[sqlx::test(migrations = "../database/migrations")]
async fn deleting_the_account_removes_its_links(pool: PgPool) {
    let repo = OidcIdentityRepository::new(pool.clone());
    let pubkey = unique_pubkey();
    insert_bare_user(&pool, &pubkey).await;
    repo.link(TENANT_ID, ISSUER, "sub-gone", &pubkey)
        .await
        .unwrap();

    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        repo.find_pubkey(TENANT_ID, ISSUER, "sub-gone")
            .await
            .unwrap(),
        None
    );
}

#[sqlx::test(migrations = "../database/migrations")]
async fn optional_email_is_none_for_accounts_without_one(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let bare = unique_pubkey();
    insert_bare_user(&pool, &bare).await;
    assert_eq!(
        repo.get_optional_email(&bare, TENANT_ID).await.unwrap(),
        None
    );

    let with_email = seed_other_user_with_email(&pool, "someone@example.org").await;
    assert_eq!(
        repo.get_optional_email(&with_email, TENANT_ID)
            .await
            .unwrap()
            .as_deref(),
        Some("someone@example.org")
    );
    assert!(repo
        .get_optional_email(&unique_pubkey(), TENANT_ID)
        .await
        .is_err());
}
