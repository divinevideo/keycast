mod common;

// ABOUTME: Covers the public OG Diviner eligibility endpoint end to end.
// ABOUTME: Pins pubkey parsing, the response shape, tenant scoping, and headers.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::api::http::og_diviner::get_og_diviner_eligibility;
use keycast_api::api::tenant::{Tenant, TenantExtractor};
use keycast_core::repositories::og_diviner_cutoff;
use nostr_sdk::{Keys, ToBech32};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;

fn tenant(id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

/// Inserts a completed signup one second before the cutoff, which qualifies.
async fn insert_eligible_user(pool: &PgPool, pubkey: &str, tenant_id: i64) {
    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at)
         VALUES ($1, $2, $3, TRUE, 'hash', $4, $4)",
    )
    .bind(pubkey)
    .bind(tenant_id)
    // Full pubkey, not a prefix: AGENTS.md forbids truncating one even in a
    // test fixture, and it also guarantees the unique-email constraint holds.
    .bind(format!("og-route-{pubkey}@example.invalid"))
    .bind(og_diviner_cutoff() - chrono::Duration::seconds(1))
    .execute(pool)
    .await
    .expect("insert eligible user");
}

async fn call(tenant_id: i64, pool: PgPool, pubkey: &str) -> axum::response::Response {
    get_og_diviner_eligibility(tenant(tenant_id), State(pool), Path(pubkey.to_string()))
        .await
        .into_response()
}

async fn json_body(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("response must be valid JSON")
}

#[tokio::test]
async fn rejects_a_pubkey_it_cannot_parse() {
    let pool = common::setup_test_db().await;

    let response = call(1, pool, "not-a-pubkey").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "Invalid public key");
}

#[tokio::test]
async fn reports_false_for_a_pubkey_with_no_signup_records() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();

    let response = call(1, pool, &pubkey).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["eligible"], false);
}

#[tokio::test]
async fn reports_true_for_a_pre_cutoff_signup_and_marks_the_response_cacheable() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    insert_eligible_user(&pool, &pubkey, 1).await;

    let response = call(1, pool.clone(), &pubkey).await;

    assert_eq!(response.status(), StatusCode::OK);
    // Presence, not the exact lifetime: this pins that the header survives the
    // handler's response construction, without freezing a value still in review.
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .expect("success response carries a Cache-Control header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        cache_control.contains("max-age"),
        "expected a max-age directive, got {cache_control}"
    );
    assert_eq!(json_body(response).await["eligible"], true);

    sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = 1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn accepts_the_npub_form_of_the_same_key() {
    let pool = common::setup_test_db().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let npub = keys.public_key().to_bech32().unwrap();
    insert_eligible_user(&pool, &pubkey, 1).await;

    let response = call(1, pool.clone(), &npub).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["eligible"],
        true,
        "npub and hex must resolve to the same account"
    );

    sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = 1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn does_not_leak_one_tenant_s_answer_to_another() {
    let pool = common::setup_test_db().await;
    let pubkey = Keys::generate().public_key().to_hex();
    insert_eligible_user(&pool, &pubkey, 1).await;

    let other_tenant = call(2, pool.clone(), &pubkey).await;

    assert_eq!(other_tenant.status(), StatusCode::OK);
    assert_eq!(
        json_body(other_tenant).await["eligible"],
        false,
        "eligibility is scoped to the tenant the request resolved to"
    );

    sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = 1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
}
