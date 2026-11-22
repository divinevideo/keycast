#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for headless sign-up with instant access before email confirmation.
// ABOUTME: Covers the instant session, the unchanged confirm-first flow, and the email hand-over.

mod common;

use axum::{
    body::to_bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_api::{
    api::http::{auth, headless, oauth, routes::AuthState},
    email_delivery::EmailDeliveryService,
    email_service::{DevEmailSender, EmailSender},
};
use nostr_sdk::Keys;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const CLIENT_ID: &str = "Instant Signup Test";
const REDIRECT_URI: &str = "https://example.com/callback";
const PASSWORD: &str = "a-long-test-password-9";
const TEST_SERVER_SECRET_HEX: &str =
    "5c3e55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d0456";

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    serde_json::from_slice(&bytes).expect("body should be JSON")
}

fn email_sender() -> Arc<dyn EmailSender> {
    Arc::new(DevEmailSender::new())
}

async fn auth_state_with_redis(pool: PgPool) -> AuthState {
    // The bunker-secret producer keeps running (dropping the handle detaches it): the token
    // exchange draws a secret from it.
    let (mut state, _producer) = common::create_test_auth_state(pool);
    let redis_url = std::env::var("TEST_REDIS_URL").expect("dedicated test Redis required");
    let redis = redis::aio::ConnectionManager::new(redis::Client::open(redis_url).unwrap())
        .await
        .unwrap();
    let inner = Arc::get_mut(&mut state.state).unwrap();
    inner.redis = Some(keycast_api::PrefixedRedis::new(
        redis,
        Some(format!("instant-signup:{}", Uuid::new_v4())),
    ));
    // Access tokens are server-signed, and validation reads the server key from SERVER_NSEC.
    let server_keys = Keys::parse(TEST_SERVER_SECRET_HEX).unwrap();
    std::env::set_var(
        "SERVER_NSEC",
        nostr_sdk::ToBech32::to_bech32(server_keys.secret_key()).unwrap(),
    );
    inner.server_keys = server_keys;
    state
}

async fn register(state: &AuthState, email: &str, instant_access: Option<bool>) -> Response {
    let mut request = json!({
        "email": email,
        "password": PASSWORD,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": "state-123",
        "marketing_consent": true,
        "app_version": "9.9.9",
    });
    if let Some(flag) = instant_access {
        request["instant_access"] = json!(flag);
    }
    match headless::headless_register(
        common::test_tenant(),
        State(state.clone()),
        Extension(email_sender()),
        Json(serde_json::from_value(request).unwrap()),
    )
    .await
    {
        Ok(response) => response.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn exchange(state: &AuthState, code: &str) -> Response {
    let result = oauth::token(
        common::test_tenant(),
        State(state.clone()),
        Extension(email_sender()),
        oauth::TokenRequestBody(oauth::TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(code.to_string()),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: Some(REDIRECT_URI.to_string()),
            code_verifier: None,
            refresh_token: None,
        }),
    )
    .await;
    match result {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn verify_link(state: &AuthState, token: &str) -> Response {
    match auth::verify_email(
        common::test_tenant(),
        State(state.clone()),
        HeaderMap::new(),
        Json(auth::VerifyEmailRequest {
            token: token.to_string(),
        }),
    )
    .await
    {
        Ok(response) => response.into_response(),
        Err(error) => error.into_response(),
    }
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid header"),
    );
    headers
}

#[derive(Debug, sqlx::FromRow)]
struct UserRow {
    email: Option<String>,
    email_verified: Option<bool>,
    has_password: bool,
    verification_token: Option<String>,
    consent: String,
}

async fn user_row(pool: &PgPool, pubkey: &str) -> UserRow {
    sqlx::query_as(
        "SELECT email, email_verified, password_hash IS NOT NULL AS has_password,
                email_verification_token AS verification_token,
                email_marketing_consent AS consent
         FROM users WHERE pubkey = $1 AND tenant_id = 1",
    )
    .bind(pubkey)
    .fetch_one(pool)
    .await
    .expect("users row should exist")
}

async fn cleanup(pool: &PgPool, pubkeys: &[String], email: &str) {
    for table in ["oauth_authorizations", "personal_keys"] {
        let _ = sqlx::query(&format!("DELETE FROM {table} WHERE user_pubkey = ANY($1)"))
            .bind(pubkeys)
            .execute(pool)
            .await;
    }
    let _ =
        sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = ANY($1) OR pending_email = $2")
            .bind(pubkeys)
            .bind(email)
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = ANY($1)")
        .bind(pubkeys)
        .execute(pool)
        .await;
}

/// An instant registration signs in straight away with an unconfirmed account whose token
/// answers account status and resend like any other session.
#[tokio::test]
async fn instant_access_returns_a_code_that_signs_in_before_confirmation() {
    let pool = common::setup_oauth_test_db().await;
    let state = auth_state_with_redis(pool.clone()).await;
    let email = format!("instant-{}@example.com", Uuid::new_v4());

    let response = register(&state, &email, Some(true)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["verification_required"], false);
    assert_eq!(body["email"], email.as_str());
    assert_eq!(body["state"], "state-123");
    assert!(
        body.get("device_code").is_none(),
        "instant access must not carry a device code: {body}"
    );
    let code = body["code"]
        .as_str()
        .expect("instant access returns a code");
    let pubkey = body["pubkey"].as_str().unwrap().to_string();

    let row = user_row(&pool, &pubkey).await;
    assert_eq!(row.email.as_deref(), Some(email.as_str()));
    assert_eq!(row.email_verified, Some(false));
    assert!(row.has_password);
    assert!(row.verification_token.is_some());
    assert_eq!(row.consent, "opted_in");

    let response = exchange(&state, code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let token_body = body_json(response).await;
    assert!(token_body["bunker_url"]
        .as_str()
        .is_some_and(|url| url.starts_with("bunker://")));
    let access_token = token_body["access_token"]
        .as_str()
        .expect("token exchange returns an access token")
        .to_string();

    let status = auth::get_account_status(
        common::test_tenant(),
        State(pool.clone()),
        bearer(&access_token),
    )
    .await
    .expect("account status should answer an unconfirmed account");
    assert_eq!(status.0.public_key, pubkey);
    assert!(!status.0.email_verified);

    let sent_before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT email_verification_sent_at FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    let resend = auth::resend_verification(
        common::test_tenant(),
        State(pool.clone()),
        Extension(EmailDeliveryService::unrestricted_for_tests(email_sender())),
        bearer(&access_token),
        Json(serde_json::from_value(json!({})).unwrap()),
    )
    .await;
    assert!(resend.0.success);
    let sent_after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT email_verification_sent_at FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        sent_after.is_some() && sent_after != sent_before,
        "a bearer resend must reach the unconfirmed account"
    );

    // The link confirms the address and re-stamps consent so the marketing sync can see it.
    let token = user_row(&pool, &pubkey).await.verification_token.unwrap();
    let consent_before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT email_marketing_consent_at FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(verify_link(&state, &token).await.status(), StatusCode::OK);
    assert_eq!(user_row(&pool, &pubkey).await.email_verified, Some(true));
    let consent_after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT email_marketing_consent_at FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(consent_after > consent_before);

    cleanup(&pool, &[pubkey], &email).await;
}

/// Clients that do not ask for instant access keep the confirm-first response exactly.
#[tokio::test]
async fn without_the_flag_registration_still_waits_for_confirmation() {
    let pool = common::setup_oauth_test_db().await;
    let state = auth_state_with_redis(pool.clone()).await;
    let email = format!("deferred-{}@example.com", Uuid::new_v4());

    for flag in [None, Some(false)] {
        let response = register(&state, &email, flag).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "device_code",
                "email",
                "pubkey",
                "success",
                "verification_required"
            ],
            "confirm-first response shape must not change: {body}"
        );
        assert_eq!(body["verification_required"], true);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 0, "no account exists before confirmation");
    }

    cleanup(&pool, &[], &email).await;
}

/// An unconfirmed holder does not reserve the address. A second registration has to confirm,
/// and confirming hands the address over and kills the first holder's link.
#[tokio::test]
async fn confirming_an_address_takes_it_from_an_unconfirmed_holder() {
    let pool = common::setup_oauth_test_db().await;
    let state = auth_state_with_redis(pool.clone()).await;
    let email = format!("handover-{}@example.com", Uuid::new_v4());

    let first = body_json(register(&state, &email, Some(true)).await).await;
    let first_pubkey = first["pubkey"].as_str().unwrap().to_string();
    let first_token = user_row(&pool, &first_pubkey)
        .await
        .verification_token
        .unwrap();

    let second = body_json(register(&state, &email, Some(true)).await).await;
    assert_eq!(second["verification_required"], true, "{second}");
    assert!(second.get("code").is_none());
    let device_code = second["device_code"].as_str().unwrap().to_string();
    let second_pubkey = second["pubkey"].as_str().unwrap().to_string();
    let pending_token: String = sqlx::query_scalar(
        "SELECT pending_email_verification_token FROM oauth_codes WHERE device_code = $1",
    )
    .bind(&device_code)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        verify_link(&state, &pending_token).await.status(),
        StatusCode::OK
    );

    let released = user_row(&pool, &first_pubkey).await;
    assert_eq!(released.email, None);
    assert!(!released.has_password);
    assert_eq!(released.verification_token, None);
    assert_eq!(released.consent, "never_asked");
    let has_key: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM personal_keys WHERE user_pubkey = $1)")
            .bind(&first_pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(has_key, "the released account keeps its key");

    let claimant = user_row(&pool, &second_pubkey).await;
    assert_eq!(claimant.email.as_deref(), Some(email.as_str()));
    assert_eq!(claimant.email_verified, Some(true));

    // The first holder's old link no longer confirms anything for it.
    let _ = verify_link(&state, &first_token).await;
    let released = user_row(&pool, &first_pubkey).await;
    assert_eq!(released.email, None);
    assert_eq!(released.email_verified, Some(false));

    cleanup(&pool, &[first_pubkey, second_pubkey], &email).await;
}

/// A confirmed owner keeps the address, with or without the flag.
#[tokio::test]
async fn a_confirmed_owner_still_blocks_registration() {
    let pool = common::setup_oauth_test_db().await;
    let state = auth_state_with_redis(pool.clone()).await;
    let email = format!("owned-{}@example.com", Uuid::new_v4());
    let owner = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, true, NOW(), NOW())",
    )
    .bind(&owner)
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    for flag in [Some(true), None] {
        let response = register(&state, &email, flag).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(response).await["code"], "EMAIL_ALREADY_EXISTS");
    }

    cleanup(&pool, &[owner], &email).await;
}

/// Headless sign-in no longer waits on confirmation and reports the state.
#[tokio::test]
async fn headless_login_signs_in_an_unconfirmed_account() {
    let pool = common::setup_oauth_test_db().await;
    let state = auth_state_with_redis(pool.clone()).await;
    let email = format!("login-{}@example.com", Uuid::new_v4());
    let pubkey = body_json(register(&state, &email, Some(true)).await).await["pubkey"]
        .as_str()
        .unwrap()
        .to_string();

    let response = headless::headless_login(
        common::test_tenant(),
        State(state.clone()),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "email": email,
                "password": PASSWORD,
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
            }))
            .unwrap(),
        ),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["email_verified"], false);
    assert_eq!(body["pubkey"], pubkey.as_str());
    assert!(body["code"].as_str().is_some_and(|code| !code.is_empty()));

    cleanup(&pool, &[pubkey], &email).await;
}

/// Both transaction-owning paths work with a single connection, so neither acquires a second
/// connection while holding its transaction.
#[tokio::test]
async fn instant_register_and_handover_do_not_nest_pool_acquisition() {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL").unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&database_url)
        .await
        .unwrap();
    let state = auth_state_with_redis(pool.clone()).await;
    let email = format!("single-conn-{}@example.com", Uuid::new_v4());

    let first = body_json(register(&state, &email, Some(true)).await).await;
    assert_eq!(first["verification_required"], false, "{first}");
    let second = body_json(register(&state, &email, Some(true)).await).await;
    let device_code = second["device_code"].as_str().unwrap().to_string();
    let pending_token: String = sqlx::query_scalar(
        "SELECT pending_email_verification_token FROM oauth_codes WHERE device_code = $1",
    )
    .bind(&device_code)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        verify_link(&state, &pending_token).await.status(),
        StatusCode::OK
    );

    let pubkeys = [
        first["pubkey"].as_str().unwrap().to_string(),
        second["pubkey"].as_str().unwrap().to_string(),
    ];
    cleanup(&pool, &pubkeys, &email).await;
}
