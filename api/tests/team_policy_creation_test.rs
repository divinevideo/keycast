#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    extract::{Path, State},
    Json,
};
use keycast_api::api::{
    error::ApiError, extractors::UcanAuth, http::teams::add_policy, types::CreatePolicyRequest,
};
use nostr_sdk::Keys;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn admin_team(pool: &PgPool) -> (i32, String) {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query("INSERT INTO users(pubkey,tenant_id) VALUES($1,1)")
        .bind(&pubkey)
        .execute(pool)
        .await
        .unwrap();
    let team: i32 = sqlx::query_scalar(
        "INSERT INTO teams(name,tenant_id) VALUES('Synthetic policy management',1) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO team_users(team_id,user_pubkey,role) VALUES($1,$2,'admin')")
        .bind(team)
        .bind(&pubkey)
        .execute(pool)
        .await
        .unwrap();
    (team, pubkey)
}
async fn row_counts(pool: &PgPool) -> (i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM policies),(SELECT count(*) FROM permissions),(SELECT count(*) FROM policy_permissions)").fetch_one(pool).await.unwrap()
}
async fn create(
    pool: &PgPool,
    team: i32,
    pubkey: &str,
    permissions: Value,
) -> Result<axum::Json<keycast_core::types::policy::PolicyWithPermissions>, ApiError> {
    let request: CreatePolicyRequest = serde_json::from_value(
        json!({"name":format!("Synthetic-{}",Uuid::new_v4()),"permissions":permissions}),
    )
    .unwrap();
    add_policy(
        common::test_tenant(),
        State(pool.clone()),
        UcanAuth {
            pubkey: pubkey.into(),
            admin_role: None,
        },
        Path(team),
        Json(request),
    )
    .await
}
#[tokio::test]
async fn stage_one_team_policy_creation_rejects_held_permissions_atomically() {
    let pool = common::setup_test_db().await;
    let (team, pubkey) = admin_team(&pool).await;
    let known = json!({"identifier":"allowed_kinds","config":{"allowed_kinds":[1]}});
    for permissions in [
        json!([{"identifier":"challenge_actions","config":{}}]),
        json!([known.clone(),{"identifier":"challenge_actions","config":{}}]),
    ] {
        let before = row_counts(&pool).await;
        let result = create(&pool, team, &pubkey, permissions).await;
        assert!(
            matches!(result, Err(ApiError::BadRequest(_))),
            "request must reject rather than dropping permissions"
        );
        assert_eq!(
            row_counts(&pool).await,
            before,
            "rejection must persist no policy, permission or link rows"
        );
    }
}
#[tokio::test]
async fn team_policy_creation_preserves_valid_existing_and_empty_policy_semantics() {
    let pool = common::setup_test_db().await;
    let (team, pubkey) = admin_team(&pool).await;
    let Json(policy)=create(&pool,team,&pubkey,json!([{"identifier":"allowed_kinds","config":{"allowed_kinds":[1]}},{"identifier":"content_filter","config":{"blocked_words":["synthetic"]}}])).await.unwrap();
    assert_eq!(policy.permissions.len(), 2);
    let loaded = policy.policy.permissions(&pool).await.unwrap();
    assert_eq!(loaded.len(), 2);
    for p in loaded {
        p.to_custom_permission().unwrap();
    }
    let Json(empty) = create(&pool, team, &pubkey, json!([])).await.unwrap();
    assert!(empty.permissions.is_empty());
    assert!(empty
        .policy
        .permission_displays(&pool)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn team_policy_creation_rejects_unknown_and_invalid_configuration_atomically() {
    let pool = common::setup_test_db().await;
    let (team, pubkey) = admin_team(&pool).await;
    let known = json!({"identifier":"allowed_kinds","config":{"allowed_kinds":[1]}});
    for permissions in [
        json!([{"identifier":"unknown_permission","config":{}}]),
        json!([known.clone(),{"identifier":"unknown_permission","config":{}}]),
        json!([known,{"identifier":"allowed_kinds","config":{"allowed_kinds":"invalid"}}]),
    ] {
        let before = row_counts(&pool).await;
        assert!(matches!(
            create(&pool, team, &pubkey, permissions).await,
            Err(ApiError::BadRequest(_))
        ));
        assert_eq!(row_counts(&pool).await, before);
    }
}
