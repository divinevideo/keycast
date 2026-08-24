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
async fn bcrypt_handlers_are_wired_through_api_routes() {
    common::assert_test_database_url();
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:password@localhost/keycast_test")
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

    for path in [
        "/auth/reset-password",
        "/user/verify-password",
        "/user/change-password",
        "/user/change-email",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "localhost")
                    .header("content-type", "application/json")
                    .body(Body::from("{"))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{path} must reach JSON extraction instead of failing on a missing bcrypt extension"
        );
    }
}
