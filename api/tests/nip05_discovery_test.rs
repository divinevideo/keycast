mod common;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::api::http::nostr_discovery_public;
use keycast_api::api::tenant::{Tenant, TenantExtractor};
use nostr_sdk::Keys;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

fn test_tenant(tenant_id: i64, domain: &str) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: tenant_id,
        domain: domain.to_string(),
        name: "Test".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

#[tokio::test]
async fn nostr_discovery_returns_names_mapping_for_existing_user() {
    let pool = common::setup_test_db().await;
    let tenant_id = 1_i64;
    let pubkey = Keys::generate().public_key().to_hex();
    let username = format!("nip05lookup-{}", &pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let mut params = HashMap::new();
    params.insert("name".to_string(), username.clone());

    let response = nostr_discovery_public(
        test_tenant(tenant_id, "login.divine.video"),
        State(pool),
        Query(params),
        HeaderMap::new(),
    )
    .await
    .into_response();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).expect("response must be valid JSON");

    assert_eq!(payload["names"][username.as_str()], pubkey);
}

#[tokio::test]
async fn nostr_discovery_returns_empty_names_for_unknown_user() {
    let pool = common::setup_test_db().await;
    let tenant_id = 1_i64;

    let mut params = HashMap::new();
    params.insert("name".to_string(), "missing-user".to_string());

    let response = nostr_discovery_public(
        test_tenant(tenant_id, "login.divine.video"),
        State(pool),
        Query(params),
        HeaderMap::new(),
    )
    .await
    .into_response();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).expect("response must be valid JSON");

    assert!(payload["names"].is_object());
    assert_eq!(
        payload["names"].as_object().map(|names| names.len()),
        Some(0),
        "unknown usernames should return an empty names map"
    );
}
