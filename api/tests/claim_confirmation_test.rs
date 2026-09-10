// ABOUTME: HTTP-layer tests for the staged-claim submit + confirm paths (Tasks 6-7)
// ABOUTME: POST /claim stages + emails; GET /claim/confirm completes the claim and issues the session

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::api::http::{claim, routes::AuthState};
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const TENANT_ID: i64 = 1;

fn test_tenant() -> keycast_api::api::tenant::TenantExtractor {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};

    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "localhost".to_string(),
        name: "Test".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

/// Mirrors create_minor_account_test.rs / clear_verified_minor_test.rs:
/// mount the real handlers directly and hand them a manually-built
/// `TenantExtractor`, bypassing the Host-header/DB tenant lookup entirely.
fn build_app(auth_state: AuthState) -> Router {
    let post_state = auth_state.clone();
    let get_state = auth_state.clone();
    Router::new()
        .route(
            "/api/claim",
            post(
                move |axum::extract::Form(form): axum::extract::Form<claim::ClaimForm>| {
                    let state = post_state.clone();
                    async move {
                        claim::claim_post(test_tenant(), State(state), axum::extract::Form(form))
                            .await
                    }
                },
            ),
        )
        .route(
            "/api/claim/confirm",
            get(
                move |axum::extract::Query(params): axum::extract::Query<claim::ClaimQuery>| {
                    let state = get_state.clone();
                    async move {
                        claim::claim_confirm_get(
                            test_tenant(),
                            State(state),
                            axum::extract::Query(params),
                        )
                        .await
                    }
                },
            ),
        )
}

fn post_claim_form(body: &str) -> Request<Body> {
    Request::post("/api/claim")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_claim_confirm(token: &str) -> Request<Body> {
    Request::get(format!("/api/claim/confirm?token={}", token))
        .body(Body::empty())
        .unwrap()
}

/// Seed an unclaimed preloaded user plus a valid (unused, non-invalidated,
/// not-yet-expired) claim token for it. Returns (token, pubkey).
async fn seed_valid_claim_token(pool: &PgPool) -> (String, String) {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at) \
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(format!("vine-{}", &pubkey[..12]))
    .execute(pool)
    .await
    .expect("create preloaded user");

    let token = format!("tok_{}", Keys::generate().public_key().to_hex());
    sqlx::query(
        "INSERT INTO account_claim_tokens (token, user_pubkey, expires_at, created_at, tenant_id) \
         VALUES ($1, $2, NOW() + INTERVAL '7 days', NOW(), $3)",
    )
    .bind(&token)
    .bind(&pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("create claim token");

    (token, pubkey)
}

#[derive(sqlx::FromRow)]
struct ClaimTokenRow {
    used_at: Option<chrono::DateTime<Utc>>,
    pending_email: Option<String>,
    confirmation_token: Option<String>,
}

async fn read_claim_token_row(pool: &PgPool, token: &str) -> ClaimTokenRow {
    sqlx::query_as::<_, ClaimTokenRow>(
        "SELECT used_at, pending_email, confirmation_token FROM account_claim_tokens WHERE token = $1",
    )
    .bind(token)
    .fetch_one(pool)
    .await
    .expect("read claim token row")
}

async fn read_user_email(pool: &PgPool, pubkey: &str) -> Option<String> {
    sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
        .bind(pubkey)
        .bind(TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("read user email")
}

async fn read_user_email_verified(pool: &PgPool, pubkey: &str) -> bool {
    sqlx::query_scalar("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2")
        .bind(pubkey)
        .bind(TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("read user email_verified")
}

async fn read_confirmation_token(pool: &PgPool, claim_token: &str) -> String {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT confirmation_token FROM account_claim_tokens WHERE token = $1",
    )
    .bind(claim_token)
    .fetch_one(pool)
    .await
    .expect("read confirmation token")
    .expect("confirmation_token must be staged after POST /api/claim")
}

async fn read_claim_token_used_at(
    pool: &PgPool,
    claim_token: &str,
) -> Option<chrono::DateTime<Utc>> {
    sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
        "SELECT used_at FROM account_claim_tokens WHERE token = $1",
    )
    .bind(claim_token)
    .fetch_one(pool)
    .await
    .expect("read used_at")
}

#[tokio::test]
async fn post_claim_stages_and_sends_without_mutating_user() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;

    // Unique per run: the users table has a unique email index and the test
    // database is shared across (parallel) tests and runs.
    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let resp = app.oneshot(post_claim_form(&body)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        !resp.headers().contains_key(header::SET_COOKIE),
        "staging a claim must not issue a session cookie"
    );

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Check Your Email"),
        "response must show the check-your-email interstitial, got: {html}"
    );
    // Fix round 1: the resend form's hidden token field must carry the real
    // claim token, not an empty value, or /api/claim/resend (Task 8) has
    // nothing to act on.
    assert!(
        html.contains(&format!(r#"name="token" value="{token}""#)),
        "resend form must carry the real claim token in its hidden field, got: {html}"
    );

    // User row must be untouched: no email, no password set by submitting the form.
    assert!(
        read_user_email(&pool, &pubkey).await.is_none(),
        "submitting the claim form must not mutate the user row"
    );

    // Claim token row: not consumed, but now carries the staged pending state.
    let row = read_claim_token_row(&pool, &token).await;
    assert!(row.used_at.is_none(), "token must not be marked used");
    assert_eq!(row.pending_email.as_deref(), Some(claim_email.as_str()));
    assert!(
        row.confirmation_token.is_some(),
        "a confirmation token must be staged for the emailed confirm link"
    );
}

#[tokio::test]
async fn confirm_completes_claim_and_sets_session() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;

    // get_server_keys() (claim.rs) reads SERVER_NSEC directly; the handler
    // needs a valid one to sign the session UCAN on a successful confirm.
    let server_keys = Keys::generate();
    std::env::set_var(
        "SERVER_NSEC",
        server_keys.secret_key().to_bech32().expect("server nsec"),
    );

    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let stage_resp = app.clone().oneshot(post_claim_form(&body)).await.unwrap();
    assert_eq!(stage_resp.status(), StatusCode::OK);

    let confirmation_token = read_confirmation_token(&pool, &token).await;

    let resp = app
        .oneshot(get_claim_confirm(&confirmation_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("confirm must set a session cookie")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.contains("keycast_session="),
        "set-cookie must carry the session token, got: {set_cookie}"
    );

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Account Claimed"),
        "response must show the success page, got: {html}"
    );

    assert_eq!(
        read_user_email(&pool, &pubkey).await.as_deref(),
        Some(claim_email.as_str())
    );
    assert!(
        read_user_email_verified(&pool, &pubkey).await,
        "confirming a claim must mark the email verified"
    );
    assert!(
        read_claim_token_used_at(&pool, &token).await.is_some(),
        "confirming a claim must mark the claim token used"
    );
}

#[tokio::test]
async fn confirm_with_unknown_token_is_unrecognized() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());

    let app = build_app(auth_state);
    let resp = app
        .oneshot(get_claim_confirm("does-not-exist"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Link not recognized"),
        "response must show the unrecognized-link page, got: {html}"
    );
}
