#![cfg(feature = "integration-tests")]

mod common;

use keycast_core::repositories::{AdminAuditEventRepository, ClaimTokenRepository};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

#[sqlx::test(migrations = "../database/migrations")]
async fn issuance_and_regeneration_audit_actor_target_without_credentials(pool: PgPool) {
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let repo = ClaimTokenRepository::new(single);
    let pubkey = common::unique_pubkey();
    let actor = common::unique_pubkey();
    common::insert_bare_user(&pool, &pubkey).await;
    repo.create("synthetic-first-token", &pubkey, Some(&actor), 1)
        .await
        .unwrap();
    repo.create_with_prior_invalidation("synthetic-replacement-token", &pubkey, Some(&actor), 1)
        .await
        .unwrap();
    let events = AdminAuditEventRepository::new(pool.clone())
        .list_recent(1, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_eq!(event.action, "claim_token_created");
        assert_eq!(event.actor_pubkey, actor);
        assert_eq!(event.target_resource_id.as_deref(), Some(pubkey.as_str()));
        assert!(event.metadata_json.get("expires_at").is_some());
        let metadata = event.metadata_json.to_string();
        assert!(!metadata.contains("synthetic-first-token"));
        assert!(!metadata.contains("synthetic-replacement-token"));
        assert!(event.metadata_json.get("email").is_none());
    }
    assert_eq!(events[0].metadata_json["invalidated_prior"], 1);
}

#[sqlx::test(migrations = "../database/migrations")]
async fn failed_audit_rolls_back_issuance_and_regeneration(pool: PgPool) {
    let repo = ClaimTokenRepository::new(pool.clone());
    let pubkey = common::unique_pubkey();
    let actor = common::unique_pubkey();
    common::insert_bare_user(&pool, &pubkey).await;
    repo.create("original-token", &pubkey, Some(&actor), 1)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE admin_audit_events ADD CONSTRAINT reject_new_audit CHECK (action <> 'claim_token_created') NOT VALID").execute(&pool).await.unwrap();
    assert!(repo
        .create("failed-token", &pubkey, Some(&actor), 1)
        .await
        .is_err());
    assert!(repo
        .create_with_prior_invalidation("failed-replacement", &pubkey, Some(&actor), 1)
        .await
        .is_err());
    assert!(repo.find_valid("original-token").await.unwrap().is_some());
    assert!(repo.find_valid("failed-token").await.unwrap().is_none());
    assert!(repo
        .find_valid("failed-replacement")
        .await
        .unwrap()
        .is_none());
}
