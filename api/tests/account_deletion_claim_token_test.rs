#![cfg(feature = "integration-tests")]

// ABOUTME: Regression coverage for account deletion against account_claim_tokens (keycast#296)
// ABOUTME: Pins the repository delete, the ON DELETE CASCADE constraint, and the users FK audit

use keycast_core::repositories::{ClaimTokenRepository, UserRepository};
use nostr_sdk::Keys;
use sqlx::PgPool;

mod common;

const TENANT_ID: i64 = 1;

/// Foreign keys to `users` that intentionally use NO ACTION because
/// `UserRepository::delete_account` removes the rows itself before deleting the
/// user. Anything else must cascade, or account deletion breaks the way #296
/// broke it.
const NO_ACTION_FKS_HANDLED_IN_DELETE_ACCOUNT: &[&str] = &["team_users"];

async fn create_test_user(pool: &PgPool, pubkey: &str) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id) VALUES ($1, $2)
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("insert test user");
}

#[tokio::test]
async fn delete_account_succeeds_and_removes_claim_tokens() {
    let pool = common::setup_test_db().await;

    let pubkey = Keys::generate().public_key().to_hex();
    create_test_user(&pool, &pubkey).await;

    let claim_tokens = ClaimTokenRepository::new(pool.clone());
    for token in ["claim_296_first", "claim_296_second"] {
        claim_tokens
            .create(
                &format!("{token}_{pubkey}"),
                &pubkey,
                Some("admin"),
                TENANT_ID,
            )
            .await
            .expect("create claim token");
    }

    UserRepository::new(pool.clone())
        .delete_account(&pubkey, TENANT_ID)
        .await
        .expect("account deletion must succeed with claim tokens present");

    let remaining_tokens: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM account_claim_tokens WHERE user_pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .expect("count claim tokens");
    assert_eq!(
        remaining_tokens, 0,
        "claim tokens must be deleted with the account"
    );

    let remaining_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .expect("count users");
    assert_eq!(remaining_users, 0, "the user row must be deleted");
}

/// The repository also deletes claim tokens explicitly, so this asserts the
/// schema directly. Without it, dropping the migration would leave the test
/// above passing while production deletes still failed on an un-migrated
/// database.
#[tokio::test]
async fn account_claim_tokens_user_fk_cascades_on_delete() {
    let pool = common::setup_test_db().await;

    let delete_action: String = sqlx::query_scalar(
        "SELECT confdeltype::text
         FROM pg_constraint
         WHERE conname = 'account_claim_tokens_user_pubkey_fkey'
           AND conrelid = 'public.account_claim_tokens'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("account_claim_tokens_user_pubkey_fkey must exist");

    assert_eq!(
        delete_action, "c",
        "account_claim_tokens.user_pubkey must be ON DELETE CASCADE, not NO ACTION"
    );
}

/// #296 happened because a table added later referenced `users` with the
/// default NO ACTION. This fails the next time that happens, instead of waiting
/// for a production account deletion to roll back.
#[tokio::test]
async fn no_unhandled_no_action_foreign_keys_reference_users() {
    let pool = common::setup_test_db().await;

    let offenders: Vec<String> = sqlx::query_scalar(
        "SELECT conrelid::regclass::text
         FROM pg_constraint
         WHERE contype = 'f'
           AND confrelid = 'public.users'::regclass
           AND confdeltype = 'a'
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("query foreign keys referencing users");

    let unhandled: Vec<&String> = offenders
        .iter()
        .filter(|table| !NO_ACTION_FKS_HANDLED_IN_DELETE_ACCOUNT.contains(&table.as_str()))
        .collect();

    assert!(
        unhandled.is_empty(),
        "these tables reference users with ON DELETE NO ACTION and will block \
         account deletion: {unhandled:?}. Either add ON DELETE CASCADE, or delete \
         the rows in UserRepository::delete_account and add the table to \
         NO_ACTION_FKS_HANDLED_IN_DELETE_ACCOUNT."
    );
}
