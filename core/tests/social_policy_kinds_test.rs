#![cfg(feature = "integration-tests")]
// ABOUTME: Tests the event kinds the seeded `social` policy lets an app sign,
// ABOUTME: loaded from a migrated database the way signing loads them.

use keycast_core::traits::CustomPermission;
use keycast_core::types::policy::Policy;
use nostr_sdk::{Keys, Kind, Tag, Timestamp, UnsignedEvent};
use sqlx::PgPool;

async fn social_policy(pool: &PgPool) -> Vec<Box<dyn CustomPermission>> {
    let policy = sqlx::query_as::<_, Policy>(
        "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
         FROM policies WHERE slug = 'social' AND team_id IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("the social policy is seeded");
    policy
        .permissions(pool)
        .await
        .expect("social policy permissions load")
        .iter()
        .map(|p| p.to_custom_permission().expect("known permission"))
        .collect()
}

// Signing requires every permission on the policy to allow the event. An empty
// list counts as refused here, though signing treats it as allowing everything,
// so the refusal checks below can't pass on a policy that failed to load.
fn allows(permissions: &[Box<dyn CustomPermission>], kind: u16) -> bool {
    let event = UnsignedEvent::new(
        Keys::generate().public_key(),
        Timestamp::now(),
        Kind::from(kind),
        Vec::<Tag>::new(),
        "",
    );
    !permissions.is_empty() && permissions.iter().all(|p| p.can_sign(&event))
}

// Kind 10011 is the NIP-39 list where people publish their linked accounts.
#[sqlx::test(migrations = "../database/migrations")]
async fn social_policy_allows_the_linked_accounts_list(pool: PgPool) {
    let permissions = social_policy(&pool).await;
    assert!(allows(&permissions, 10011));
}

#[sqlx::test(migrations = "../database/migrations")]
async fn social_policy_keeps_its_other_kinds_and_limits(pool: PgPool) {
    let permissions = social_policy(&pool).await;
    // These mirror the seeded social policy; change them with any deliberate
    // change to what it allows.
    for kind in [0, 1, 3, 4, 7, 44, 1059, 9735, 22242] {
        assert!(
            allows(&permissions, kind),
            "kind {kind} should stay allowed"
        );
    }
    for kind in [5, 10002, 30023] {
        assert!(
            !allows(&permissions, kind),
            "kind {kind} should stay refused"
        );
    }
}

const LINKED_ACCOUNTS_MIGRATION: &str = include_str!(
    "../../database/migrations/20261007120000_social_policy_allows_linked_accounts.sql"
);

async fn social_messaging_config(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT config FROM permissions WHERE identifier = 'allowed_kinds_social_messaging'",
    )
    .fetch_one(pool)
    .await
    .expect("social messaging permission exists")
}

#[sqlx::test(migrations = "../database/migrations")]
async fn linked_accounts_migration_is_safe_to_run_again(pool: PgPool) {
    let before = social_messaging_config(&pool).await;
    sqlx::raw_sql(LINKED_ACCOUNTS_MIGRATION)
        .execute(&pool)
        .await
        .expect("migration runs again");
    assert_eq!(social_messaging_config(&pool).await, before);
}

// A missing or null allowed_kinds means any kind; the migration must not narrow that.
#[sqlx::test(migrations = "../database/migrations")]
async fn linked_accounts_migration_leaves_an_unrestricted_permission_alone(pool: PgPool) {
    for unrestricted in [r#"{"allowed_kinds": null}"#, "{}"] {
        sqlx::query(
            "UPDATE permissions SET config = $1
             WHERE identifier = 'allowed_kinds_social_messaging'",
        )
        .bind(unrestricted)
        .execute(&pool)
        .await
        .expect("permission reset to unrestricted");
        sqlx::raw_sql(LINKED_ACCOUNTS_MIGRATION)
            .execute(&pool)
            .await
            .expect("migration runs");
        assert_eq!(social_messaging_config(&pool).await, unrestricted);
        assert!(allows(&social_policy(&pool).await, 30023));
    }
}
