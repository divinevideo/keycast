// ABOUTME: HTTP-layer tests for the staged-claim submit + confirm + resend paths (Tasks 6-8)
// ABOUTME: POST /claim stages + emails; GET /claim/confirm completes the claim; POST /claim/resend re-sends, cooldown-gated

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
use keycast_api::ucan_auth::did_to_nostr_pubkey;
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use ucan::Ucan;

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
    let resend_state = auth_state.clone();
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
        .route(
            "/api/claim/resend",
            post(
                move |axum::extract::Form(form): axum::extract::Form<claim::ClaimResendForm>| {
                    let state = resend_state.clone();
                    async move {
                        claim::claim_resend_post(
                            test_tenant(),
                            State(state),
                            axum::extract::Form(form),
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

fn post_claim_resend(token: &str) -> Request<Body> {
    Request::post("/api/claim/resend")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("token={}", token)))
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

async fn read_confirmation_sent_at(
    pool: &PgPool,
    claim_token: &str,
) -> Option<chrono::DateTime<Utc>> {
    sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
        "SELECT confirmation_sent_at FROM account_claim_tokens WHERE token = $1",
    )
    .bind(claim_token)
    .fetch_one(pool)
    .await
    .expect("read confirmation_sent_at")
}

async fn read_confirmation_expires_at(
    pool: &PgPool,
    claim_token: &str,
) -> Option<chrono::DateTime<Utc>> {
    sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
        "SELECT confirmation_expires_at FROM account_claim_tokens WHERE token = $1",
    )
    .bind(claim_token)
    .fetch_one(pool)
    .await
    .expect("read confirmation_expires_at")
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

/// Seed an unrelated, already-verified user occupying `email`, so a confirm
/// attempt that lands on this address collides on the unique index.
async fn seed_other_user_with_email(pool: &PgPool, email: &str) {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert other user with email");
}

/// Pull the `keycast_session` value out of a `Set-Cookie` header, discarding
/// the `HttpOnly; Secure; ...` attributes that follow it.
fn extract_session_token(set_cookie: &str) -> &str {
    set_cookie
        .strip_prefix("keycast_session=")
        .expect("cookie must be the keycast_session cookie")
        .split(';')
        .next()
        .expect("cookie value")
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

    // Decode the session UCAN and check its audience (the subject the token
    // was issued for) is the confirmed user's own pubkey, not some other
    // account -- the whole point of binding the session to the claim.
    let session_token = extract_session_token(&set_cookie);
    let ucan = Ucan::try_from_token_string(session_token).expect("decode session UCAN");
    let audience_pubkey =
        did_to_nostr_pubkey(ucan.audience()).expect("session UCAN audience must be a nostr DID");
    assert_eq!(
        audience_pubkey.to_hex(),
        pubkey,
        "session UCAN must be issued for the confirmed user's own pubkey"
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

/// A resend requested immediately after staging is within the cooldown
/// window: the response is the same generic interstitial, but nothing is
/// touched -- `confirmation_sent_at` and `confirmation_token` stay exactly
/// as they were left by the original POST /api/claim.
#[tokio::test]
async fn resend_within_cooldown_does_not_bump() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let stage_resp = app.clone().oneshot(post_claim_form(&body)).await.unwrap();
    assert_eq!(stage_resp.status(), StatusCode::OK);

    let sent_at_before = read_confirmation_sent_at(&pool, &token)
        .await
        .expect("confirmation_sent_at must be set after staging");
    let confirmation_token_before = read_confirmation_token(&pool, &token).await;

    let resp = app.oneshot(post_claim_resend(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Check Your Email") || html.contains("Check your email"),
        "response must show the check-your-email interstitial, got: {html}"
    );
    assert!(
        !html.contains(&claim_email),
        "resend response must use enumeration-safe generic copy, not echo the staged email, got: {html}"
    );

    let sent_at_after = read_confirmation_sent_at(&pool, &token)
        .await
        .expect("confirmation_sent_at must still be set");
    let confirmation_token_after = read_confirmation_token(&pool, &token).await;
    assert_eq!(
        sent_at_before, sent_at_after,
        "a resend within cooldown must not bump confirmation_sent_at"
    );
    assert_eq!(
        confirmation_token_before, confirmation_token_after,
        "a resend within cooldown must not rotate the confirmation token"
    );
}

/// A resend requested after the cooldown window has passed bumps
/// `confirmation_sent_at`. The confirmation token itself is unchanged,
/// because it has not expired -- only an expired confirmation token gets
/// rotated (see the resend handler).
#[tokio::test]
async fn resend_after_cooldown_bumps() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let stage_resp = app.clone().oneshot(post_claim_form(&body)).await.unwrap();
    assert_eq!(stage_resp.status(), StatusCode::OK);

    let confirmation_token_before = read_confirmation_token(&pool, &token).await;

    // Backdate confirmation_sent_at past the resend cooldown window.
    sqlx::query(
        "UPDATE account_claim_tokens SET confirmation_sent_at = NOW() - INTERVAL '6 minutes' WHERE token = $1",
    )
    .bind(&token)
    .execute(&pool)
    .await
    .expect("backdate confirmation_sent_at");
    let sent_at_before = read_confirmation_sent_at(&pool, &token)
        .await
        .expect("confirmation_sent_at must be set");

    let resp = app.oneshot(post_claim_resend(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Check Your Email") || html.contains("Check your email"),
        "response must show the check-your-email interstitial, got: {html}"
    );

    let sent_at_after = read_confirmation_sent_at(&pool, &token)
        .await
        .expect("confirmation_sent_at must still be set");
    let confirmation_token_after = read_confirmation_token(&pool, &token).await;
    assert!(
        sent_at_after > sent_at_before,
        "a resend past cooldown must bump confirmation_sent_at (before={:?}, after={:?})",
        sent_at_before,
        sent_at_after
    );
    assert_eq!(
        confirmation_token_before, confirmation_token_after,
        "a resend of a still-valid (non-expired) confirmation token must not rotate it"
    );
}

/// When the previously-issued confirmation token has itself expired (past its
/// own 24h confirmation window) but the underlying claim token is still valid
/// (7-day `expires_at`, so the row is still stageable), a resend past cooldown
/// must rotate to a fresh confirmation token with a new, future expiry -- the
/// stale one can no longer be completed even if the claimer finds it.
#[tokio::test]
async fn resend_rotates_expired_confirmation_token() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let stage_resp = app.clone().oneshot(post_claim_form(&body)).await.unwrap();
    assert_eq!(stage_resp.status(), StatusCode::OK);

    let confirmation_token_before = read_confirmation_token(&pool, &token).await;

    // Past cooldown AND the confirmation window has expired, while the outer
    // claim token's own expires_at (7 days from seed_valid_claim_token) stays
    // valid, so the row is still a live, stageable pending claim.
    sqlx::query(
        "UPDATE account_claim_tokens \
         SET confirmation_sent_at = NOW() - INTERVAL '6 minutes', \
             confirmation_expires_at = NOW() - INTERVAL '1 minute' \
         WHERE token = $1",
    )
    .bind(&token)
    .execute(&pool)
    .await
    .expect("backdate confirmation_sent_at and expire the confirmation window");

    let resp = app.oneshot(post_claim_resend(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Check Your Email") || html.contains("Check your email"),
        "response must show the check-your-email interstitial, got: {html}"
    );

    let confirmation_token_after = read_confirmation_token(&pool, &token).await;
    assert_ne!(
        confirmation_token_before, confirmation_token_after,
        "a resend of an expired confirmation token must rotate to a fresh one"
    );

    let new_expires_at = read_confirmation_expires_at(&pool, &token)
        .await
        .expect("rotated confirmation_expires_at must be set");
    assert!(
        new_expires_at > Utc::now(),
        "the rotated confirmation token must carry a future expiry, got: {:?}",
        new_expires_at
    );
}

/// An unknown claim token must get the same generic interstitial as a real
/// one, so the endpoint cannot be used to probe for the existence of a
/// pending claim.
#[tokio::test]
async fn resend_unknown_token_is_enumeration_safe() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());

    let app = build_app(auth_state);
    let resp = app
        .oneshot(post_claim_resend("does-not-exist"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Check Your Email") || html.contains("Check your email"),
        "response must show the same generic interstitial for an unknown token, got: {html}"
    );
}

/// A confirm attempt against a link whose confirmation window has expired
/// must show the ConfirmationExpired page, distinct from the generic
/// "Link not recognized" unrecognized-token page.
#[tokio::test]
async fn confirm_with_expired_confirmation_window_shows_expired_page() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let stage_resp = app.clone().oneshot(post_claim_form(&body)).await.unwrap();
    assert_eq!(stage_resp.status(), StatusCode::OK);

    let confirmation_token = read_confirmation_token(&pool, &token).await;

    // Backdate ONLY the confirmation window; the claim token's own expires_at
    // stays valid.
    sqlx::query(
        "UPDATE account_claim_tokens SET confirmation_expires_at = NOW() - INTERVAL '1 minute' WHERE token = $1",
    )
    .bind(&token)
    .execute(&pool)
    .await
    .expect("backdate confirmation_expires_at");

    let resp = app
        .oneshot(get_claim_confirm(&confirmation_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Confirmation link expired"),
        "response must show the confirmation-expired page, got: {html}"
    );
    assert!(
        !html.contains("Link not recognized"),
        "an expired confirmation window is a distinct failure from an unrecognized link, got: {html}"
    );

    assert!(
        read_user_email(&pool, &pubkey).await.is_none(),
        "an expired confirmation must not mutate the user row"
    );
}

/// When the staged email was claimed by another account between staging and
/// confirmation, the confirm link must show the dedicated
/// ConfirmationEmailTaken page (there is no form to resubmit at this point,
/// unlike the submit-time EmailExists case), not a 500.
#[tokio::test]
async fn confirm_with_email_taken_by_another_account_shows_dedicated_page() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;
    let (auth_state, _producer_handle) = common::create_test_auth_state(pool.clone());
    let (token, pubkey) = seed_valid_claim_token(&pool).await;
    let claim_email = format!("new-{}@example.com", &pubkey[..12]);

    // Seed the other user BEFORE staging so the race is: staged first, then
    // occupied -- confirm-time is where this must be caught, since
    // claim_post's own submit-time check already passed at staging.
    let app = build_app(auth_state);
    let body = format!(
        "token={}&email={}&password=supersecret&password_confirmation=supersecret",
        token, claim_email
    );
    let stage_resp = app.clone().oneshot(post_claim_form(&body)).await.unwrap();
    assert_eq!(stage_resp.status(), StatusCode::OK);

    let confirmation_token = read_confirmation_token(&pool, &token).await;

    // Another account claims the same email after staging, before confirm.
    seed_other_user_with_email(&pool, &claim_email).await;

    let resp = app
        .oneshot(get_claim_confirm(&confirmation_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        html.contains("Email no longer available"),
        "response must show the dedicated confirm-time email-taken page, got: {html}"
    );
    assert!(
        html.contains("just claimed by another account"),
        "response must show the confirm-time email-taken message, got: {html}"
    );

    assert!(
        read_user_email(&pool, &pubkey).await.is_none(),
        "a confirm that loses the email race must not mutate the claiming user's row"
    );
}
