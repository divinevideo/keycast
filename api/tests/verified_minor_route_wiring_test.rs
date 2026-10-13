// ABOUTME: Pins the PUT and DELETE verified-minor routes through the real api_routes
// ABOUTME: A dropped method registration would be a 405 that handler-level tests cannot see

#![cfg(feature = "integration-tests")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use keycast_api::{
    api::{http::routes::api_routes, tenant::Tenant},
    email_delivery::EmailDeliveryService,
    email_service::DevEmailSender,
    state::KEYCAST_STATE,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

mod common;

#[tokio::test]
async fn verified_minor_routes_are_wired_through_api_routes() {
    common::assert_test_database_url();
    // Service-token auth answers 500 when unconfigured; set it so 401 is the unauthenticated answer.
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", "wiring-test-token") };
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPoolOptions::new()
        .connect_lazy(&database_url)
        .expect("local test database URL should parse");
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());
    auth_state
        .state
        .tenant_cache
        .insert(
            "localhost".to_string(),
            Arc::new(Tenant {
                id: 1,
                domain: "localhost".to_string(),
                name: "Test Tenant".to_string(),
                settings: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }),
        )
        .await;
    KEYCAST_STATE
        .set(auth_state.state.clone())
        .unwrap_or_else(|_| panic!("test process must initialize Keycast state exactly once"));

    let app = api_routes(
        pool,
        auth_state.state,
        EmailDeliveryService::unrestricted_for_tests(Arc::new(DevEmailSender::new())),
        CorsLayer::permissive(),
        CorsLayer::permissive(),
        None,
    );

    let pubkey = "a".repeat(64);
    for method in ["PUT", "DELETE"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/admin/users/{pubkey}/verified-minor"))
                    .header("host", "localhost")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} verified-minor must be routed and reach service-token auth (405 means the method is unregistered)"
        );
    }
}
