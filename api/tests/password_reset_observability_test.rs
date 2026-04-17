#![cfg(feature = "integration-tests")]

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware,
    routing::post,
    Json, Router,
};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use keycast_api::api::{
    http::{
        auth::{forgot_password, reset_password, ForgotPasswordRequest, ResetPasswordRequest},
        auth_observability::request_id_middleware,
    },
    tenant::{Tenant, TenantExtractor},
};
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

fn create_test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn cleanup_by_email(pool: &PgPool, email: &str) {
    let _ = sqlx::query("DELETE FROM auth_events WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn test_forgot_password_records_accepted_event_for_missing_email() {
    let pool = setup_pool().await;
    let email = format!("missing-reset-{}@example.com", Uuid::new_v4());
    let request_id = format!("trace-{}", Uuid::new_v4());

    cleanup_by_email(&pool, &email).await;

    let app = {
        let pool = pool.clone();
        Router::new()
            .route(
                "/auth/forgot-password",
                post(
                    move |headers: HeaderMap, Json(req): Json<ForgotPasswordRequest>| {
                        let pool = pool.clone();
                        async move {
                            forgot_password(create_test_tenant(), State(pool), headers, Json(req))
                                .await
                        }
                    },
                ),
            )
            .layer(middleware::from_fn(request_id_middleware))
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/forgot-password")
                .header("content-type", "application/json")
                .header("x-trace-id", &request_id)
                .body(Body::from(
                    serde_json::json!({ "email": email }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-request-id").unwrap(), &request_id);

    let event: Option<common::AuthEventRow> = sqlx::query_as(
        "SELECT endpoint, event_type, outcome, reason_code, request_id, http_status
             FROM auth_events
             WHERE tenant_id = 1 AND email = $1
             ORDER BY occurred_at DESC, id DESC
             LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .expect("auth event query should succeed");

    assert_eq!(
        event,
        Some((
            "/api/auth/forgot-password".to_string(),
            "password_reset_request".to_string(),
            "accepted".to_string(),
            Some("user_not_found".to_string()),
            request_id,
            Some(200),
        ))
    );

    cleanup_by_email(&pool, &email).await;
}

#[tokio::test]
async fn test_reset_password_records_success_event_and_updates_hash() {
    let pool = setup_pool().await;
    let email = format!("reset-success-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    let request_id = format!("trace-{}", Uuid::new_v4());
    let reset_token = format!("reset-{}", Uuid::new_v4());
    let new_password = "new-password-123!";
    let old_password_hash = hash("old-password-123!", 4).unwrap();

    cleanup_by_email(&pool, &email).await;

    sqlx::query(
        "INSERT INTO users (
            pubkey, tenant_id, email, password_hash, email_verified,
            password_reset_token, password_reset_expires_at, created_at, updated_at
         ) VALUES ($1, 1, $2, $3, false, $4, $5, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&old_password_hash)
    .bind(&reset_token)
    .bind(Utc::now() + Duration::hours(1))
    .execute(&pool)
    .await
    .expect("Should create resettable user");

    let app = {
        let pool = pool.clone();
        Router::new()
            .route(
                "/auth/reset-password",
                post(
                    move |headers: HeaderMap, Json(req): Json<ResetPasswordRequest>| {
                        let pool = pool.clone();
                        async move {
                            reset_password(create_test_tenant(), State(pool), headers, Json(req))
                                .await
                        }
                    },
                ),
            )
            .layer(middleware::from_fn(request_id_middleware))
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/reset-password")
                .header("content-type", "application/json")
                .header("x-trace-id", &request_id)
                .body(Body::from(
                    serde_json::json!({
                        "token": reset_token,
                        "new_password": new_password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-request-id").unwrap(), &request_id);

    let user_row: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT password_hash, email_verified, password_reset_token
         FROM users
         WHERE pubkey = $1 AND tenant_id = 1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .expect("updated user row should exist");

    assert!(verify(new_password, &user_row.0).unwrap());
    assert!(user_row.1);
    assert!(user_row.2.is_none());

    let event: Option<common::AuthEventRow> = sqlx::query_as(
        "SELECT endpoint, event_type, outcome, reason_code, request_id, http_status
             FROM auth_events
             WHERE tenant_id = 1 AND email = $1
             ORDER BY occurred_at DESC, id DESC
             LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .expect("auth event query should succeed");

    assert_eq!(
        event,
        Some((
            "/api/auth/reset-password".to_string(),
            "password_reset".to_string(),
            "success".to_string(),
            Some("password_hash_updated".to_string()),
            request_id,
            Some(200),
        ))
    );

    cleanup_by_email(&pool, &email).await;
}
