#![cfg(feature = "integration-tests")]

mod common;

use axum::{extract::State, Extension, Json};
use chrono::Utc;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::admin::{self, BatchCreateClaimTokensRequest, CreateClaimTokenRequest},
        tenant::{Tenant, TenantExtractor},
    },
    email_service::{DevEmailSender, EmailSender},
};
use keycast_core::repositories::{AdminAuditEventRepository, UserRepository};
use nostr_sdk::Keys;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::Duration};

fn tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".into(),
        name: "Test".into(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn auth(actor: &str) -> UcanAuth {
    UcanAuth {
        pubkey: actor.to_string(),
        admin_role: Some("full".into()),
    }
}

#[sqlx::test(migrations = "../database/migrations")]
async fn single_and_batch_issuance_audit_only_created_links(pool: PgPool) {
    common::assert_test_database_url();
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let repo = UserRepository::new(single.clone());
    let actor = Keys::generate().public_key().to_hex();
    let pubkey = Keys::generate().public_key().to_hex();
    let batch_pubkey = Keys::generate().public_key().to_hex();
    repo.create_preloaded_user(
        &pubkey,
        1,
        "single-import",
        "single-name",
        None,
        b"synthetic-key",
    )
    .await
    .unwrap();
    repo.create_preloaded_user(
        &batch_pubkey,
        1,
        "batch-import",
        "batch-name",
        None,
        b"synthetic-key",
    )
    .await
    .unwrap();
    let (state, _producer) = common::create_test_auth_state(single);
    let issued = admin::create_claim_token(
        tenant(),
        State(state.clone()),
        auth(&actor),
        Json(CreateClaimTokenRequest {
            vine_id: "single-import".into(),
        }),
    )
    .await
    .unwrap();
    assert!(issued.claim_url.contains("/api/claim?token="));
    let sender: Arc<dyn EmailSender> = Arc::new(DevEmailSender::new());
    let batch = admin::batch_create_claim_tokens(
        tenant(),
        State(state),
        Extension(sender),
        auth(&actor),
        Json(BatchCreateClaimTokensRequest {
            vine_ids: vec![
                "single-import".into(),
                "batch-import".into(),
                "batch-import".into(),
                "missing-import".into(),
            ],
            delivery_email: None,
        }),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(batch.tokens.len(), 1);
    assert_eq!(batch.skipped.len(), 2);
    assert!(batch.errors.is_empty());
    let events = AdminAuditEventRepository::new(pool)
        .list_recent(1, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_eq!(event.actor_pubkey, actor);
        assert_eq!(event.action, "claim_token_created");
        assert!(event.metadata_json.get("delivery_email").is_none());
        assert!(event.metadata_json.get("token").is_none());
    }
    assert!(events
        .iter()
        .any(|event| event.target_resource_id.as_deref() == Some(pubkey.as_str())));
    assert!(events
        .iter()
        .any(|event| event.target_resource_id.as_deref() == Some(batch_pubkey.as_str())));
}
