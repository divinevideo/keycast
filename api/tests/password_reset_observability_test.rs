#![cfg(feature = "integration-tests")]

use axum::{
    body::{to_bytes, Body},
    extract::{Extension, State},
    http::{HeaderMap, Request, StatusCode},
    middleware,
    routing::post,
    Json, Router,
};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use keycast_api::api::{
    http::{
        auth::{
            forgot_password, resend_verification, reset_password, ForgotPasswordRequest,
            ResendVerificationRequest, ResetPasswordRequest,
        },
        auth_observability::request_id_middleware,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::{
    email_delivery::{EmailAdmissionRefusal, EmailDeliveryService},
    email_service::{DevEmailSender, EmailSender},
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

fn public_recovery_app(pool: PgPool, delivery: EmailDeliveryService) -> Router {
    let reset_pool = pool.clone();
    let resend_pool = pool;
    let reset_delivery = delivery.clone();
    Router::new()
        .route(
            "/auth/forgot-password",
            post(
                move |headers: HeaderMap, Json(req): Json<ForgotPasswordRequest>| {
                    let pool = reset_pool.clone();
                    let delivery = reset_delivery.clone();
                    async move {
                        forgot_password(
                            create_test_tenant(),
                            State(pool),
                            Extension(delivery),
                            headers,
                            Json(req),
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/auth/resend-verification",
            post(
                move |headers: HeaderMap, Json(req): Json<ResendVerificationRequest>| {
                    let pool = resend_pool.clone();
                    let delivery = delivery.clone();
                    async move {
                        resend_verification(
                            create_test_tenant(),
                            State(pool),
                            Extension(delivery),
                            headers,
                            Json(req),
                        )
                        .await
                    }
                },
            ),
        )
}

async fn public_recovery_response(app: &Router, uri: &str, email: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
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
async fn public_recovery_responses_match_for_existing_missing_admitted_and_suppressed() {
    let pool = setup_pool().await;
    let existing = format!("public-recovery-existing-{}@example.com", Uuid::new_v4());
    let missing = format!("public-recovery-missing-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    cleanup_by_email(&pool, &existing).await;
    cleanup_by_email(&pool, &missing).await;
    sqlx::query(
        "INSERT INTO users (
            pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at
         ) VALUES ($1, 1, $2, $3, false, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&existing)
    .bind(hash("old-password", 4).unwrap())
    .execute(&pool)
    .await
    .expect("create existing recovery account");

    let sender = Arc::new(DevEmailSender::new());
    let admitted = public_recovery_app(
        pool.clone(),
        EmailDeliveryService::unrestricted_for_tests(sender.clone()),
    );
    let suppressed = public_recovery_app(
        pool.clone(),
        EmailDeliveryService::denying_for_tests(
            sender.clone(),
            EmailAdmissionRefusal::DestinationCooldown,
        ),
    );

    for uri in ["/auth/forgot-password", "/auth/resend-verification"] {
        let responses = [
            public_recovery_response(&admitted, uri, &existing).await,
            public_recovery_response(&admitted, uri, &missing).await,
            public_recovery_response(&suppressed, uri, &existing).await,
            public_recovery_response(&suppressed, uri, &missing).await,
        ];
        assert!(responses
            .iter()
            .all(|(status, _)| *status == StatusCode::OK));
        assert!(responses.windows(2).all(|pair| pair[0].1 == pair[1].1));
    }

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while sender.get_captured_emails().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("password-reset and verification sends should both run");

    cleanup_by_email(&pool, &existing).await;
    cleanup_by_email(&pool, &missing).await;
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
                            forgot_password(
                                create_test_tenant(),
                                State(pool),
                                Extension(EmailDeliveryService::unrestricted_for_tests(Arc::new(
                                    DevEmailSender::new(),
                                ))),
                                headers,
                                Json(req),
                            )
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
async fn suppressed_forgot_password_preserves_token_and_skips_provider() {
    let pool = setup_pool().await;
    let email = format!("suppressed-reset-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    let prior_token = format!("prior-reset-{}", Uuid::new_v4());
    let request_id = format!("trace-{}", Uuid::new_v4());
    cleanup_by_email(&pool, &email).await;
    sqlx::query(
        "INSERT INTO users (
            pubkey, tenant_id, email, password_hash, email_verified,
            password_reset_token, password_reset_expires_at, created_at, updated_at
         ) VALUES ($1, 1, $2, $3, true, $4, $5, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(hash("old-password", 4).unwrap())
    .bind(&prior_token)
    .bind(Utc::now() + Duration::hours(1))
    .execute(&pool)
    .await
    .expect("create user");

    let sender = Arc::new(DevEmailSender::new());
    sender.clear_captured_emails();
    let delivery = EmailDeliveryService::denying_for_tests(
        sender.clone(),
        EmailAdmissionRefusal::DestinationCooldown,
    );
    let app = {
        let pool = pool.clone();
        Router::new()
            .route(
                "/auth/forgot-password",
                post(
                    move |headers: HeaderMap, Json(req): Json<ForgotPasswordRequest>| {
                        let pool = pool.clone();
                        let delivery = delivery.clone();
                        async move {
                            forgot_password(
                                create_test_tenant(),
                                State(pool),
                                Extension(delivery),
                                headers,
                                Json(req),
                            )
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
    let stored_token: Option<String> = sqlx::query_scalar(
        "SELECT password_reset_token FROM users WHERE pubkey = $1 AND tenant_id = 1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .expect("read preserved token");
    assert_eq!(stored_token.as_deref(), Some(prior_token.as_str()));
    assert!(sender.get_captured_emails().is_empty());

    let delivery_event: (String, Option<String>) = sqlx::query_as(
        "SELECT outcome, reason_code FROM auth_events
         WHERE request_id = $1 AND event_type = 'email_delivery'",
    )
    .bind(&request_id)
    .fetch_one(&pool)
    .await
    .expect("suppressed delivery event");
    assert_eq!(
        delivery_event,
        (
            "suppressed".to_string(),
            Some("destination_cooldown".to_string())
        )
    );

    sqlx::query("DELETE FROM auth_events WHERE request_id = $1")
        .bind(&request_id)
        .execute(&pool)
        .await
        .expect("delete test event");
    cleanup_by_email(&pool, &email).await;
}

#[tokio::test]
async fn suppressed_verification_resend_preserves_token_and_skips_provider() {
    let pool = setup_pool().await;
    let email = format!("suppressed-verification-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    let prior_token = format!("prior-verification-{}", Uuid::new_v4());
    let request_id = format!("trace-{}", Uuid::new_v4());
    cleanup_by_email(&pool, &email).await;
    sqlx::query(
        "INSERT INTO users (
            pubkey, tenant_id, email, password_hash, email_verified,
            email_verification_token, email_verification_expires_at,
            email_verification_sent_at, created_at, updated_at
         ) VALUES ($1, 1, $2, $3, false, $4, $5, $6, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(hash("old-password", 4).unwrap())
    .bind(&prior_token)
    .bind(Utc::now() + Duration::hours(1))
    .bind(Utc::now() - Duration::hours(1))
    .execute(&pool)
    .await
    .expect("create unverified user");

    let sender = Arc::new(DevEmailSender::new());
    sender.clear_captured_emails();
    let delivery = EmailDeliveryService::denying_for_tests(
        sender.clone(),
        EmailAdmissionRefusal::DestinationCooldown,
    );
    let app = {
        let pool = pool.clone();
        Router::new()
            .route(
                "/auth/resend-verification",
                post(
                    move |headers: HeaderMap, Json(req): Json<ResendVerificationRequest>| {
                        let pool = pool.clone();
                        let delivery = delivery.clone();
                        async move {
                            resend_verification(
                                create_test_tenant(),
                                State(pool),
                                Extension(delivery),
                                headers,
                                Json(req),
                            )
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
                .uri("/auth/resend-verification")
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
    let stored_token: Option<String> = sqlx::query_scalar(
        "SELECT email_verification_token FROM users WHERE pubkey = $1 AND tenant_id = 1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .expect("read preserved verification token");
    assert_eq!(stored_token.as_deref(), Some(prior_token.as_str()));
    assert!(sender.get_captured_emails().is_empty());

    let delivery_event: (String, Option<String>) = sqlx::query_as(
        "SELECT outcome, reason_code FROM auth_events
         WHERE request_id = $1 AND event_type = 'email_delivery'",
    )
    .bind(&request_id)
    .fetch_one(&pool)
    .await
    .expect("suppressed delivery event");
    assert_eq!(
        delivery_event,
        (
            "suppressed".to_string(),
            Some("destination_cooldown".to_string())
        )
    );

    sqlx::query("DELETE FROM auth_events WHERE request_id = $1")
        .bind(&request_id)
        .execute(&pool)
        .await
        .expect("delete test event");
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
                            reset_password(
                                create_test_tenant(),
                                State(pool),
                                axum::Extension(keycast_api::BcryptAdmission::new(
                                    1,
                                    std::time::Duration::from_secs(1),
                                )),
                                headers,
                                Json(req),
                            )
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
