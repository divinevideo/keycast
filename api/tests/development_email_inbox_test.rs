#![cfg(feature = "integration-tests")]

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::Utc;
use keycast_api::{
    api::{http::routes::api_routes, tenant::Tenant},
    email_delivery::EmailDeliveryService,
    email_service::DevEmailSender,
    state::KEYCAST_STATE,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

mod common;

async fn request(app: &Router, path: &str, body: Option<Value>) -> Value {
    let request = Request::builder().uri(path).header("host", "localhost");
    let request = if let Some(body) = body {
        request
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    } else {
        request.body(Body::empty()).unwrap()
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn registration_and_pin_resend_are_visible_in_development_inbox() {
    // This integration binary has one test, so environment and global router state are isolated.
    std::env::set_var("ENABLE_DEV_EMAIL_INBOX", "true");
    std::env::set_var("NODE_ENV", "development");
    std::env::set_var("RUST_ENV", "development");
    std::env::remove_var("SENDGRID_API_KEY");
    let pool = common::setup_test_db().await;
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
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }),
        )
        .await;
    KEYCAST_STATE
        .set(auth_state.state.clone())
        .unwrap_or_else(|_| panic!("fresh integration process"));
    let sender = Arc::new(DevEmailSender::new());
    let app = api_routes(
        pool.clone(),
        auth_state.state,
        EmailDeliveryService::unrestricted_for_tests(sender),
        CorsLayer::permissive(),
        CorsLayer::permissive(),
        None,
    );
    let browser_email = format!("browser-{}@example.com", Uuid::new_v4());
    request(
        &app,
        "/auth/register",
        Some(json!({"email": browser_email, "password": "test-password-123"})),
    )
    .await;
    let inbox = request(&app, "/dev/emails", None).await;
    assert!(
        inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|email| email["to"] == browser_email && email["verification_url"].is_string()),
        "browser registration verification must be available in the inbox"
    );

    let headless_email = format!("headless-{}@example.com", Uuid::new_v4());
    let registration = request(
        &app,
        "/headless/register",
        Some(json!({
            "email": headless_email, "password": "test-password-123", "client_id": "inbox-test",
            "redirect_uri": "https://example.com/callback", "scope": "policy:full"
        })),
    )
    .await;
    let inbox = request(&app, "/dev/emails", None).await;
    let first = inbox
        .as_array()
        .unwrap()
        .iter()
        .find(|email| email["to"] == headless_email)
        .expect("headless registration must be in inbox");
    assert_eq!(first["pin"].as_str().unwrap().len(), 6);
    let original_link = first["verification_url"].clone();
    sqlx::query("UPDATE oauth_codes SET pin_sent_at = NOW() - INTERVAL '10 minutes', pin_resend_at = NULL WHERE device_code = $1")
        .bind(registration["device_code"].as_str().unwrap()).execute(&pool).await.unwrap();
    request(
        &app,
        "/headless/resend-pin",
        Some(json!({"device_code": registration["device_code"]})),
    )
    .await;
    let inbox = request(&app, "/dev/emails", None).await;
    let emails: Vec<_> = inbox
        .as_array()
        .unwrap()
        .iter()
        .filter(|email| email["to"] == headless_email)
        .collect();
    assert_eq!(
        emails.len(),
        2,
        "PIN resend must append an accessible message"
    );
    assert_eq!(emails[1]["pin"].as_str().unwrap().len(), 6);
    assert_ne!(emails[1]["verification_url"], original_link);
    let oauth_email = format!("oauth-{}@example.com", Uuid::new_v4());
    request(
        &app,
        "/oauth/register",
        Some(json!({
            "email": oauth_email, "password": "test-password-123", "client_id": "inbox-test",
            "redirect_uri": "https://example.com/callback", "scope": "policy:full"
        })),
    )
    .await;
    let inbox = request(&app, "/dev/emails", None).await;
    assert!(
        inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|email| email["to"] == oauth_email && email["verification_url"].is_string()),
        "OAuth registration verification must be available in the inbox"
    );

    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey IN (SELECT pubkey FROM users WHERE email = $1)").bind(&browser_email).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&browser_email)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM oauth_codes WHERE pending_email = $1 OR pending_email = $2")
        .bind(&headless_email)
        .bind(&oauth_email)
        .execute(&pool)
        .await
        .unwrap();
    producer.abort();
}
