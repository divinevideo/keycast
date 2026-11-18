#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
    Router,
};
use keycast_api::{
    api::http::{
        auth::generate_server_signed_ucan,
        routes::{api_routes, device_verification_route},
    },
    email_delivery::EmailDeliveryService,
    state::KEYCAST_STATE,
};
use keycast_core::{
    repositories::oauth_device::DEVICE_GRANT_TYPE, types::refresh_token::hash_refresh_token,
};
use nostr_sdk::Keys;
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

const HOST: &str = "login.divine.test";
const ORIGIN: &str = "https://login.divine.test";
const TV_ORIGIN: &str = "https://tv.example";
const START: &str = "/api/oauth/device_authorization";
const TOKEN: &str = "/api/oauth/token";
const SESSION: &str = "/api/oauth/device_session";
const REVOKE: &str = "/api/oauth/device_revoke";

async fn request(
    app: &Router,
    method: Method,
    path: &str,
    body: &str,
    headers: &[(header::HeaderName, &str)],
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    for (name, value) in headers {
        builder = builder.header(name, *value);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn payload(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

async fn start(app: &Router) -> Value {
    let response = request(
        app,
        Method::POST,
        START,
        "client_id=divine-tv",
        &[(header::ORIGIN, TV_ORIGIN)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert!(!response
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    payload(response).await
}

async fn poll(app: &Router, device_code: &str, client: &str) -> Response {
    request(
        app,
        Method::POST,
        TOKEN,
        &format!(
            "grant_type={}&client_id={client}&device_code={device_code}",
            urlencoding::encode(DEVICE_GRANT_TYPE),
        ),
        &[],
    )
    .await
}

async fn decision(
    app: &Router,
    code: &str,
    decision: &str,
    account: &str,
    origin: &str,
    cookie: &str,
) -> Response {
    request(
        app,
        Method::POST,
        "/device",
        &format!("user_code={code}&decision={decision}&account={account}"),
        &[(header::ORIGIN, origin), (header::COOKIE, cookie)],
    )
    .await
}

async fn advance_poll(pool: &PgPool, device_code: &str) {
    sqlx::query("UPDATE oauth_device_grants SET next_poll_at = NOW() WHERE device_code_hash = $1")
        .bind(hash_refresh_token(device_code))
        .execute(pool)
        .await
        .unwrap();
}

async fn json_error(response: Response, status: StatusCode, error: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(payload(response).await["error"], error);
}

#[tokio::test]
async fn phone_approval_yields_a_single_read_only_session_that_can_rotate_and_revoke() {
    std::env::set_var("APP_URL", ORIGIN);
    let bootstrap_pool = common::setup_test_db().await;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(bootstrap_pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    common::install_global_test_state_with_redis(pool.clone());
    let state = KEYCAST_STATE.get().unwrap().clone();
    std::env::set_var(
        "SERVER_NSEC",
        state.server_keys.secret_key().to_secret_hex(),
    );
    let mut tenant = common::test_tenant().0.as_ref().clone();
    tenant.domain = HOST.to_string();
    state
        .tenant_cache
        .insert(HOST.to_string(), Arc::new(tenant))
        .await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let app = Router::new()
        .merge(device_verification_route(state.clone()))
        .nest(
            "/api",
            api_routes(
                pool.clone(),
                state.clone(),
                EmailDeliveryService::unrestricted_for_tests(common::test_email_sender()),
                CorsLayer::new(),
                cors,
                None,
            ),
        );
    let user = Keys::generate().public_key();
    let pubkey = user.to_hex();
    let email = format!("tv-{}@example.test", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified) VALUES ($1, 1, $2, true)",
    )
    .bind(&pubkey)
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();
    let cookie = format!(
        "keycast_session={}",
        generate_server_signed_ucan(
            &user,
            1,
            &email,
            ORIGIN,
            None,
            &state.server_keys,
            false,
            None,
            None,
        )
        .await
        .unwrap()
    );

    let preflight = request(
        &app,
        Method::OPTIONS,
        REVOKE,
        "",
        &[
            (header::ORIGIN, TV_ORIGIN),
            (header::ACCESS_CONTROL_REQUEST_METHOD, "POST"),
            (header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization"),
        ],
    )
    .await;
    assert_eq!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "*"
    );
    assert!(!preflight
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
    let manual = request(&app, Method::GET, "/device", "", &[]).await;
    assert_eq!(manual.status(), StatusCode::OK);
    let manual_body = to_bytes(manual.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&manual_body).contains("Enter the code shown on your TV."));

    let grant = start(&app).await;
    assert_eq!(grant["verification_uri"], format!("{ORIGIN}/device"));
    assert_eq!(grant["expires_in"], 600);
    assert_eq!(grant["interval"], 5);
    let device_code = grant["device_code"].as_str().unwrap();
    let user_code = grant["user_code"].as_str().unwrap();
    assert_eq!(device_code.len(), 64);
    assert_eq!(user_code.len(), 9);
    let full_uri = grant["verification_uri_complete"].as_str().unwrap();
    let verification_path = full_uri.strip_prefix(ORIGIN).unwrap();
    assert_eq!(verification_path, format!("/device?user_code={user_code}"));
    let browser_redirect = request(&app, Method::GET, verification_path, "", &[]).await;
    assert_eq!(browser_redirect.status(), StatusCode::SEE_OTHER);
    assert!(browser_redirect.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .starts_with("/login?redirect="));
    assert_eq!(
        browser_redirect.headers()[header::REFERRER_POLICY],
        "no-referrer"
    );

    json_error(
        poll(&app, device_code, "other-client").await,
        StatusCode::BAD_REQUEST,
        "invalid_client",
    )
    .await;
    json_error(
        poll(&app, device_code, "divine-tv").await,
        StatusCode::BAD_REQUEST,
        "slow_down",
    )
    .await;
    let interval: i32 = sqlx::query_scalar(
        "SELECT poll_interval_seconds FROM oauth_device_grants WHERE device_code_hash = $1",
    )
    .bind(hash_refresh_token(device_code))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(interval, 10);
    advance_poll(&pool, device_code).await;
    json_error(
        poll(&app, device_code, "divine-tv").await,
        StatusCode::BAD_REQUEST,
        "authorization_pending",
    )
    .await;

    let page = request(
        &app,
        Method::GET,
        verification_path,
        "",
        &[(header::COOKIE, &cookie)],
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(!page
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    let page_body = to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let page = String::from_utf8_lossy(&page_body);
    assert!(page.contains(user_code));
    assert!(page.contains(&email));
    assert!(!page.contains(device_code));
    assert_eq!(
        decision(&app, user_code, "approve", &pubkey, TV_ORIGIN, &cookie)
            .await
            .status(),
        StatusCode::FORBIDDEN,
    );
    assert_eq!(
        decision(
            &app,
            user_code,
            "approve",
            "different-account",
            ORIGIN,
            &cookie
        )
        .await
        .status(),
        StatusCode::CONFLICT,
    );
    assert_eq!(
        decision(&app, user_code, "approve", &pubkey, ORIGIN, &cookie)
            .await
            .status(),
        StatusCode::OK,
    );

    advance_poll(&pool, device_code).await;
    let (first, second) = tokio::join!(
        poll(&app, device_code, "divine-tv"),
        poll(&app, device_code, "divine-tv")
    );
    let (success, replay) = if first.status() == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(success.status(), StatusCode::OK);
    json_error(replay, StatusCode::BAD_REQUEST, "invalid_grant").await;
    let access = payload(success).await;
    assert_eq!(access["pubkey"], pubkey);
    assert_eq!(access["scope"], "tv:read");
    assert_eq!(access["token_type"], "Bearer");
    assert!(!access.as_object().unwrap().contains_key("bunker_url"));
    let bearer = format!("Bearer {}", access["access_token"].as_str().unwrap());
    let auth = [(header::AUTHORIZATION, bearer.as_str())];
    assert_eq!(
        payload(request(&app, Method::GET, SESSION, "", &auth).await).await["pubkey"],
        pubkey
    );
    assert_eq!(
        request(&app, Method::GET, "/api/user/pubkey", "", &auth)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, Method::POST, REVOKE, "", &[(header::COOKIE, &cookie)])
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let refresh = format!(
        "grant_type=refresh_token&client_id=divine-tv&refresh_token={}",
        access["refresh_token"].as_str().unwrap()
    );
    let rotated = request(&app, Method::POST, TOKEN, &refresh, &[]).await;
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotated = payload(rotated).await;
    assert_eq!(rotated["pubkey"], pubkey);
    assert_ne!(rotated["refresh_token"], access["refresh_token"]);
    json_error(
        request(&app, Method::POST, TOKEN, &refresh, &[]).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await;
    assert_eq!(
        request(&app, Method::POST, REVOKE, "", &auth)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let rotated_auth = format!("Bearer {}", rotated["access_token"].as_str().unwrap());
    json_error(
        request(
            &app,
            Method::GET,
            SESSION,
            "",
            &[(header::AUTHORIZATION, &rotated_auth)],
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
    )
    .await;
    let latest = format!(
        "grant_type=refresh_token&client_id=divine-tv&refresh_token={}",
        rotated["refresh_token"].as_str().unwrap()
    );
    json_error(
        request(&app, Method::POST, TOKEN, &latest, &[]).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await;

    let denied = start(&app).await;
    assert_eq!(
        decision(
            &app,
            denied["user_code"].as_str().unwrap(),
            "deny",
            &pubkey,
            ORIGIN,
            &cookie
        )
        .await
        .status(),
        StatusCode::OK
    );
    json_error(
        poll(&app, denied["device_code"].as_str().unwrap(), "divine-tv").await,
        StatusCode::BAD_REQUEST,
        "access_denied",
    )
    .await;

    let expired = start(&app).await;
    let expired_code = expired["device_code"].as_str().unwrap();
    sqlx::query("UPDATE oauth_device_grants SET expires_at = NOW() WHERE device_code_hash = $1")
        .bind(hash_refresh_token(expired_code))
        .execute(&pool)
        .await
        .unwrap();
    json_error(
        poll(&app, expired_code, "divine-tv").await,
        StatusCode::BAD_REQUEST,
        "expired_token",
    )
    .await;
}
