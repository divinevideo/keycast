#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the self-serve email change flow (#223)
// ABOUTME: Covers initiate (authenticated), dual confirmation, cancel, expiry, and anti-enumeration

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware,
    routing::post,
    Json, Router,
};
use bcrypt::hash;
use chrono::{Duration, Utc};
use keycast_api::api::{
    http::{
        auth::{
            cancel_email_change, change_email, confirm_email_change, ChangeEmailRequest,
            ConfirmEmailChangeRequest,
        },
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

const TENANT_ID: i64 = 1;

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
        id: TENANT_ID,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

/// Mint a self-issued UCAN session token for the given keys (mirrors generate_ucan_token).
async fn mint_session_token(keys: &Keys) -> String {
    use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use ucan::builder::UcanBuilder;

    let key_material = NostrKeyMaterial::from_keys(keys.clone());
    let user_did = nostr_pubkey_to_did(&keys.public_key());
    let facts = serde_json::json!({
        "tenant_id": TENANT_ID,
        "email": "session@example.com",
        "redirect_origin": "https://localhost",
    });
    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("build UCAN")
        .sign()
        .await
        .expect("sign UCAN");
    format!("Bearer {}", ucan.encode().expect("encode UCAN"))
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

async fn create_user(pool: &PgPool, pubkey: &str, email: &str, password: &str) {
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
    let password_hash = hash(password, 4).unwrap();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, $4, true, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("create user");
}

/// Router mounting all three handlers.
fn build_app(pool: PgPool) -> Router {
    let p1 = pool.clone();
    let p2 = pool.clone();
    let p3 = pool;
    Router::new()
        .route(
            "/user/change-email",
            post(move |headers: HeaderMap, Json(req): Json<ChangeEmailRequest>| {
                let pool = p1.clone();
                async move { change_email(create_test_tenant(), State(pool), headers, Json(req)).await }
            }),
        )
        .route(
            "/auth/confirm-email-change",
            post(
                move |headers: HeaderMap, Json(req): Json<ConfirmEmailChangeRequest>| {
                    let pool = p2.clone();
                    async move {
                        confirm_email_change(create_test_tenant(), State(pool), headers, Json(req)).await
                    }
                },
            ),
        )
        .route(
            "/auth/cancel-email-change",
            post(
                move |headers: HeaderMap, Json(req): Json<ConfirmEmailChangeRequest>| {
                    let pool = p3.clone();
                    async move {
                        cancel_email_change(create_test_tenant(), State(pool), headers, Json(req)).await
                    }
                },
            ),
        )
        .layer(middleware::from_fn(request_id_middleware))
}

async fn post_json(app: &Router, uri: &str, auth: Option<&str>, body: serde_json::Value) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

/// Read the pending_email_* state for assertions.
async fn pending_state(
    pool: &PgPool,
    pubkey: &str,
) -> (Option<String>, Option<String>, Option<String>, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>) {
    sqlx::query_as(
        "SELECT pending_email, pending_email_old_token, pending_email_new_token,
                pending_email_old_confirmed_at, pending_email_new_confirmed_at
         FROM users WHERE pubkey = $1",
    )
    .bind(pubkey)
    .fetch_one(pool)
    .await
    .expect("read pending state")
}

async fn current_email(pool: &PgPool, pubkey: &str) -> String {
    sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(pool)
        .await
        .expect("read email")
}

#[tokio::test]
async fn test_happy_path_dual_confirm_finalizes() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
    create_user(&pool, &pubkey, &old_email, "correct-horse-battery").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;

    // Initiate.
    let resp = post_json(
        &app,
        "/user/change-email",
        Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "correct-horse-battery" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let (pending, old_tok, new_tok, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending.as_deref(), Some(new_email.as_str()));
    let old_tok = old_tok.expect("old token");
    let new_tok = new_tok.expect("new token");
    assert_eq!(current_email(&pool, &pubkey).await, old_email);

    // Confirm new address only — must not finalize.
    let resp = post_json(&app, "/auth/confirm-email-change", None, serde_json::json!({ "token": new_tok })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(current_email(&pool, &pubkey).await, old_email);

    // Confirm old address — now both confirmed, finalize.
    let resp = post_json(&app, "/auth/confirm-email-change", None, serde_json::json!({ "token": old_tok })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(current_email(&pool, &pubkey).await, new_email);

    // Pending state cleared.
    let (pending, _, _, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending, None);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
}

#[tokio::test]
async fn test_finalizes_regardless_of_confirmation_order() {
    // Old-then-new ordering (happy path covers new-then-old). The atomic finalize must apply
    // the swap once both are confirmed, whichever order they arrive.
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "pw-order-test").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;
    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "pw-order-test" })).await;

    let (_, old_tok, new_tok, _, _) = pending_state(&pool, &pubkey).await;

    // Confirm OLD first.
    post_json(&app, "/auth/confirm-email-change", None,
        serde_json::json!({ "token": old_tok.unwrap() })).await;
    assert_eq!(current_email(&pool, &pubkey).await, old_email);

    // Then NEW — finalizes.
    post_json(&app, "/auth/confirm-email-change", None,
        serde_json::json!({ "token": new_tok.unwrap() })).await;
    assert_eq!(current_email(&pool, &pubkey).await, new_email);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
}

#[tokio::test]
async fn test_partial_confirmation_does_not_finalize() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "pw-pw-pw-pw").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;
    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "pw-pw-pw-pw" })).await;

    let (_, old_tok, _, _, _) = pending_state(&pool, &pubkey).await;
    post_json(&app, "/auth/confirm-email-change", None,
        serde_json::json!({ "token": old_tok.unwrap() })).await;

    assert_eq!(current_email(&pool, &pubkey).await, old_email);
    let (_, _, _, old_conf, new_conf) = pending_state(&pool, &pubkey).await;
    assert!(old_conf.is_some());
    assert!(new_conf.is_none());

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
}

#[tokio::test]
async fn test_wrong_password_rejected_no_pending() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "the-real-password").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;
    let resp = post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "WRONG-password" })).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let (pending, _, _, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending, None);

    cleanup_by_email(&pool, &old_email).await;
}

#[tokio::test]
async fn test_duplicate_email_anti_enumeration() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let taken_email = format!("taken-{}@example.com", Uuid::new_v4());
    let other_pubkey = Keys::generate().public_key().to_hex();
    create_user(&pool, &pubkey, &old_email, "pw-initiator-1").await;
    create_user(&pool, &other_pubkey, &taken_email, "pw-other-1").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;
    // Returns success even though the target is taken...
    let resp = post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": taken_email, "password": "pw-initiator-1" })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // ...but no pending change is written.
    let (pending, _, _, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending, None);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &taken_email).await;
}

#[tokio::test]
async fn test_expired_token_rejected() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "pw-expire-test").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;
    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "pw-expire-test" })).await;

    let (_, old_tok, _, _, _) = pending_state(&pool, &pubkey).await;
    // Force expiry.
    sqlx::query("UPDATE users SET pending_email_expires_at = $1 WHERE pubkey = $2")
        .bind(Utc::now() - Duration::hours(1))
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

    let resp = post_json(&app, "/auth/confirm-email-change", None,
        serde_json::json!({ "token": old_tok.unwrap() })).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(current_email(&pool, &pubkey).await, old_email);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
}

#[tokio::test]
async fn test_cancel_clears_pending() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "pw-cancel-test").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;
    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "pw-cancel-test" })).await;

    let (_, old_tok, _, _, _) = pending_state(&pool, &pubkey).await;
    let resp = post_json(&app, "/auth/cancel-email-change", None,
        serde_json::json!({ "token": old_tok.unwrap() })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let (pending, _, _, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(pending, None);
    assert_eq!(current_email(&pool, &pubkey).await, old_email);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
}

#[tokio::test]
async fn test_invalid_confirm_token_rejected() {
    let pool = setup_pool().await;
    let app = build_app(pool.clone());
    let resp = post_json(&app, "/auth/confirm-email-change", None,
        serde_json::json!({ "token": "this-token-does-not-exist" })).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_new_change_cancels_prior() {
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let email_a = format!("a-{}@example.com", Uuid::new_v4());
    let email_b = format!("b-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "pw-rotate-test").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;

    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": email_a, "password": "pw-rotate-test" })).await;
    let (_, old_tok_a, _, _, _) = pending_state(&pool, &pubkey).await;

    // Second initiation to a DIFFERENT address supersedes the first immediately — the resend
    // cooldown is scoped to same-target resends, so a corrected address is not rate-limited.
    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": email_b, "password": "pw-rotate-test" })).await;
    let (pending, old_tok_b, _, _, _) = pending_state(&pool, &pubkey).await;

    assert_eq!(pending.as_deref(), Some(email_b.as_str()));
    assert_ne!(old_tok_a, old_tok_b);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &email_a).await;
    cleanup_by_email(&pool, &email_b).await;
}

#[tokio::test]
async fn test_same_target_resend_within_cooldown_does_not_resend() {
    // Re-initiating the SAME target within the cooldown window must not rotate tokens or re-send.
    let pool = setup_pool().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let old_email = format!("old-{}@example.com", Uuid::new_v4());
    let new_email = format!("new-{}@example.com", Uuid::new_v4());
    create_user(&pool, &pubkey, &old_email, "pw-cooldown-test").await;

    let app = build_app(pool.clone());
    let auth = mint_session_token(&keys).await;

    post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "pw-cooldown-test" })).await;
    let (_, old_tok_1, new_tok_1, _, _) = pending_state(&pool, &pubkey).await;

    // Same target again, immediately — cooldown applies, tokens unchanged.
    let resp = post_json(&app, "/user/change-email", Some(&auth),
        serde_json::json!({ "new_email": new_email, "password": "pw-cooldown-test" })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, old_tok_2, new_tok_2, _, _) = pending_state(&pool, &pubkey).await;
    assert_eq!(old_tok_1, old_tok_2);
    assert_eq!(new_tok_1, new_tok_2);

    cleanup_by_email(&pool, &old_email).await;
    cleanup_by_email(&pool, &new_email).await;
}
