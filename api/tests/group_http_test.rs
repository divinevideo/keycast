#![cfg(feature = "integration-tests")]
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use keycast_api::{
    api::{
        http::{auth::generate_server_signed_ucan, routes::api_routes},
        tenant::Tenant,
    },
    email_delivery::EmailDeliveryService,
    email_service::DevEmailSender,
    state::KEYCAST_STATE,
};
use nostr_sdk::{Keys, ToBech32};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(if body.is_null() {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn account(pool: &PgPool, server: &Keys, first_party: bool) -> (Keys, String) {
    let keys = Keys::generate();
    sqlx::query("INSERT INTO users (pubkey,tenant_id) VALUES ($1,1)")
        .bind(keys.public_key().to_hex())
        .execute(pool)
        .await
        .unwrap();
    let token = generate_server_signed_ucan(
        &keys.public_key(),
        1,
        "synthetic@example.test",
        "https://client.example.test",
        Some(&Keys::generate().public_key().to_hex()),
        server,
        first_party,
        None,
        None,
    )
    .await
    .unwrap();
    (keys, token)
}
#[tokio::test]
async fn real_ucan_group_routes_cover_lifecycle_custody_and_fresh_enrollment() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let server = Keys::generate();
    std::env::set_var("SERVER_NSEC", server.secret_key().to_bech32().unwrap());
    std::env::set_var("BUNKER_RELAYS", "ws://127.0.0.1:8080");
    let (auth_state, producer) = common::create_test_auth_state(pool.clone());
    auth_state
        .state
        .tenant_cache
        .insert(
            "localhost".into(),
            Arc::new(Tenant {
                id: 1,
                domain: "localhost".into(),
                name: "Test".into(),
                settings: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }),
        )
        .await;
    KEYCAST_STATE
        .set(auth_state.state.clone())
        .unwrap_or_else(|_| panic!("one initialization per process"));
    let app = api_routes(
        pool.clone(),
        auth_state.state,
        EmailDeliveryService::unrestricted_for_tests(Arc::new(DevEmailSender::new())),
        CorsLayer::permissive(),
        CorsLayer::permissive(),
        None,
    );
    let (admin, token) = account(&pool, &server, true).await;
    let (second, second_token) = account(&pool, &server, true).await;
    let (_, outsider) = account(&pool, &server, true).await;
    let delegated = generate_server_signed_ucan(
        &admin.public_key(),
        1,
        "synthetic@example.test",
        "https://client.example.test",
        Some(&Keys::generate().public_key().to_hex()),
        &server,
        false,
        None,
        None,
    )
    .await
    .unwrap();
    let (status, cap) = call(&app, "GET", "/groups/capabilities", None, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cap["self_managed"]["keycast_required"], false);
    assert_eq!(
        call(&app, "GET", "/groups", None, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/groups",
            Some(&delegated),
            json!({"request_id":"unauthorized","name":"Denied"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let request =
        json!({"request_id":uuid::Uuid::new_v4().to_string(),"name":"Synthetic HTTP group"});
    let (status, group) = call(&app, "POST", "/groups", Some(&token), request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert!(group.get("secret_key").is_none());
    assert!(group.get("bunker_url").is_none());
    let id = group["id"].as_i64().unwrap();
    let base = format!("/groups/{id}");
    assert_eq!(
        call(&app, "POST", "/groups", Some(&token), request).await.1["pubkey"],
        group["pubkey"]
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/teams",
            Some(&token),
            json!({"name":"Ordinary users cannot create administrative teams"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/teams/{id}"),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    for path in [&base, &format!("{base}/backups")] {
        assert_eq!(
            call(&app, "GET", path, Some(&outsider), Value::Null)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "GET", path, Some(&delegated), Value::Null)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/access"),
            Some(&outsider),
            json!({"client_pubkey":Keys::generate().public_key().to_hex()})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/members"),
            Some(&token),
            json!({"admin_pubkey":second.public_key().to_hex()})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/groups/invitations",
            Some(&second_token),
            Value::Null
        )
        .await
        .1
        .as_array()
        .unwrap()
        .len(),
        1
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/accept"),
            Some(&second_token),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    let enrollment = json!({"client_pubkey":Keys::generate().public_key().to_hex()});
    let (status, access) = call(
        &app,
        "POST",
        &format!("{base}/access"),
        Some(&second_token),
        enrollment,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{access}");
    assert_eq!(access["group_pubkey"], group["pubkey"]);
    let (status, restored) = call(
        &app,
        "POST",
        &format!("{base}/recover"),
        Some(&second_token),
        json!({"client_pubkey":Keys::generate().public_key().to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert_eq!(restored["group_pubkey"], group["pubkey"]);
    assert_ne!(access["authorization_id"], restored["authorization_id"]);
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM group_grants WHERE authorization_id=$1",
    )
    .bind(access["authorization_id"].as_i64().unwrap() as i32)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(revoked);
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("{base}/members/{}", second.public_key().to_hex()),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/recover"),
            Some(&second_token),
            json!({"client_pubkey":Keys::generate().public_key().to_hex()})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{base}/backups"),
            Some(&second_token),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    producer.abort();
}
