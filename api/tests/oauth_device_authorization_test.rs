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
    ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial},
};
use keycast_core::{
    repositories::oauth_device::{DEVICE_GRANT_TYPE, DEVICE_TOKEN_ORIGIN},
    types::refresh_token::hash_refresh_token,
};
use nostr_sdk::Keys;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::{Any, CorsLayer};
use ucan::builder::UcanBuilder;
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
    if !body.is_empty() && !headers.iter().any(|(name, _)| name == header::CONTENT_TYPE) {
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

async fn pair(app: &Router, pool: &PgPool, pubkey: &str, cookie: &str) -> Value {
    let grant = start(app).await;
    assert_eq!(
        decision(
            app,
            grant["user_code"].as_str().unwrap(),
            "approve",
            pubkey,
            ORIGIN,
            cookie,
        )
        .await
        .status(),
        StatusCode::OK,
    );
    let device = grant["device_code"].as_str().unwrap();
    advance_poll(pool, device).await;
    let response = poll(app, device, "divine-tv").await;
    assert_eq!(response.status(), StatusCode::OK);
    payload(response).await
}

async fn refresh_with(app: &Router, refresh_token: &str) -> Response {
    request(
        app,
        Method::POST,
        TOKEN,
        &format!("grant_type=refresh_token&client_id=divine-tv&refresh_token={refresh_token}"),
        &[],
    )
    .await
}

async fn session_expiry(pool: &PgPool, refresh_token: &str) -> chrono::DateTime<chrono::Utc> {
    sqlx::query_scalar("SELECT expires_at FROM oauth_device_sessions WHERE refresh_token_hash = $1")
        .bind(hash_refresh_token(refresh_token))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn session_id(pool: &PgPool, refresh_token: &str) -> String {
    sqlx::query_scalar("SELECT id FROM oauth_device_sessions WHERE refresh_token_hash = $1")
        .bind(hash_refresh_token(refresh_token))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn set_account_status(pool: &PgPool, pubkey: &str, status: &str) {
    sqlx::query("UPDATE users SET status = $2 WHERE pubkey = $1")
        .bind(pubkey)
        .bind(status)
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
        .max_connections(2)
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
    let user_keys = Keys::generate();
    let user = user_keys.public_key();
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
    // Exercise the polling transaction with one available connection.
    let reserved_connection = pool.acquire().await.unwrap();
    json_error(
        poll(&app, device_code, "divine-tv").await,
        StatusCode::BAD_REQUEST,
        "authorization_pending",
    )
    .await;
    drop(reserved_connection);

    let page = request(
        &app,
        Method::GET,
        verification_path,
        "",
        &[(header::COOKIE, &cookie)],
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    // A no-referrer form document sends Origin: null even on same-origin POST.
    assert_eq!(page.headers()[header::REFERRER_POLICY], "strict-origin");
    assert!(!page
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    let page_body = to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let page = String::from_utf8_lossy(&page_body);
    assert!(page.contains(user_code));
    assert!(page.contains(&email));
    assert!(!page.contains(device_code));
    assert_eq!(
        decision(&app, user_code, "approve", &pubkey, "null", &cookie)
            .await
            .status(),
        StatusCode::FORBIDDEN,
    );
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

    let redis = state.redis.as_ref().unwrap();
    let tenant_before = redis.get("oauth_device:create:1").await.unwrap();
    for _ in 0..30 {
        assert_eq!(
            request(
                &app,
                Method::POST,
                START,
                "client_id=divine-tv",
                &[(
                    header::HeaderName::from_static("x-forwarded-for"),
                    "192.0.2.91"
                )],
            )
            .await
            .status(),
            StatusCode::OK,
        );
    }
    let tenant_after = redis.get("oauth_device:create:1").await.unwrap();
    assert_eq!(
        tenant_after.as_deref().unwrap().parse::<u64>().unwrap(),
        tenant_before.as_deref().unwrap().parse::<u64>().unwrap() + 30,
    );
    for forwarded in [
        "192.0.2.92",
        "198.51.100.1, 192.0.2.91",
        "203.0.113.1, 192.0.2.91",
    ] {
        let limited = request(
            &app,
            Method::POST,
            START,
            "client_id=divine-tv",
            &[(
                header::HeaderName::from_static("x-forwarded-for"),
                forwarded,
            )],
        )
        .await;
        assert_eq!(limited.headers()[header::RETRY_AFTER], "60");
        json_error(
            limited,
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
        )
        .await;
    }
    assert_eq!(
        redis.get("oauth_device:create:1").await.unwrap(),
        tenant_after
    );
    assert_eq!(
        request(
            &app,
            Method::POST,
            START,
            "client_id=divine-tv",
            &[(
                header::HeaderName::from_static("x-forwarded-for"),
                "198.51.100.1"
            )],
        )
        .await
        .status(),
        StatusCode::OK,
    );
    for _ in 0..30 {
        assert_eq!(
            request(
                &app,
                Method::POST,
                START,
                "client_id=divine-tv",
                &[(
                    header::HeaderName::from_static("x-forwarded-for"),
                    "2001:db8:1234:100::1"
                )],
            )
            .await
            .status(),
            StatusCode::OK,
        );
    }
    let tenant_after_ipv6 = redis.get("oauth_device:create:1").await.unwrap();
    for forwarded in ["2001:db8:1234:ab00::1", "2001:db8:1234:ffff::1"] {
        json_error(
            request(
                &app,
                Method::POST,
                START,
                "client_id=divine-tv",
                &[(
                    header::HeaderName::from_static("x-forwarded-for"),
                    forwarded,
                )],
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
        )
        .await;
    }
    assert_eq!(
        redis.get("oauth_device:create:1").await.unwrap(),
        tenant_after_ipv6
    );
    assert_eq!(
        request(
            &app,
            Method::POST,
            START,
            "client_id=divine-tv",
            &[(
                header::HeaderName::from_static("x-forwarded-for"),
                "2001:db8:5678::1"
            )],
        )
        .await
        .status(),
        StatusCode::OK,
    );

    let verify_budget = format!("oauth_device:verify:1:{pubkey}");
    redis.del(&verify_budget).await.unwrap();
    account_manages_only_its_own_tv_sessions(&app, &pool, &pubkey, &cookie).await;
    account_status_is_checked_at_every_transition(&app, &pool, &pubkey, &cookie).await;
    session_expiry_is_fixed_and_limits_access_tokens(&app, &pool, &pubkey, &cookie).await;

    let stale = start(&app).await;
    sqlx::query("UPDATE oauth_device_grants SET expires_at = NOW() WHERE device_code_hash = $1")
        .bind(hash_refresh_token(stale["device_code"].as_str().unwrap()))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        decision(
            &app,
            stale["user_code"].as_str().unwrap(),
            "approve",
            &pubkey,
            ORIGIN,
            &cookie,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
    );

    let guarded = start(&app).await;
    redis.setex(&verify_budget, 600, "20").await.unwrap();
    let limited = decision(
        &app,
        guarded["user_code"].as_str().unwrap(),
        "approve",
        &pubkey,
        ORIGIN,
        &cookie,
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()[header::RETRY_AFTER], "600");
    redis.del(&verify_budget).await.unwrap();

    json_error(
        request(
            &app,
            Method::POST,
            START,
            "client_id=divine-tv&scope=tv%3Awrite",
            &[],
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
    )
    .await;

    let bunker_cookie = format!(
        "keycast_session={}",
        generate_server_signed_ucan(
            &user,
            1,
            &email,
            ORIGIN,
            Some(&Keys::generate().public_key().to_hex()),
            &state.server_keys,
            false,
            None,
            None,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            &format!(
                "/device?user_code={}",
                guarded["user_code"].as_str().unwrap()
            ),
            "",
            &[(header::COOKIE, bunker_cookie.as_str())],
        )
        .await
        .status(),
        StatusCode::SEE_OTHER,
    );
    assert_eq!(
        decision(
            &app,
            guarded["user_code"].as_str().unwrap(),
            "approve",
            &pubkey,
            ORIGIN,
            &bunker_cookie,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
    );

    let live = pair(&app, &pool, &pubkey, &cookie).await;
    let live_session = session_id(&pool, live["refresh_token"].as_str().unwrap()).await;
    let self_signed = UcanBuilder::default()
        .issued_by(&NostrKeyMaterial::from_keys(user_keys))
        .for_audience(&nostr_pubkey_to_did(&user))
        .with_lifetime(900)
        .with_fact(json!({
            "tenant_id": 1,
            "redirect_origin": DEVICE_TOKEN_ORIGIN,
            "device_session": live_session,
        }))
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap()
        .encode()
        .unwrap();
    let forged_bearer = format!("Bearer {self_signed}");
    assert_eq!(
        request(
            &app,
            Method::GET,
            SESSION,
            "",
            &[(header::AUTHORIZATION, forged_bearer.as_str())],
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
    );
}

async fn account_status_is_checked_at_every_transition(
    app: &Router,
    pool: &PgPool,
    pubkey: &str,
    cookie: &str,
) {
    for status in ["suspended", "banned"] {
        let held = start(app).await;
        let held_code = held["user_code"].as_str().unwrap();
        let held_device = held["device_code"].as_str().unwrap();
        set_account_status(pool, pubkey, status).await;
        assert_eq!(
            decision(app, held_code, "approve", pubkey, ORIGIN, cookie)
                .await
                .status(),
            StatusCode::BAD_REQUEST,
        );
        set_account_status(pool, pubkey, "active").await;
        assert_eq!(
            decision(app, held_code, "approve", pubkey, ORIGIN, cookie)
                .await
                .status(),
            StatusCode::OK,
        );
        set_account_status(pool, pubkey, status).await;
        advance_poll(pool, held_device).await;
        json_error(
            poll(app, held_device, "divine-tv").await,
            StatusCode::BAD_REQUEST,
            "access_denied",
        )
        .await;

        set_account_status(pool, pubkey, "active").await;
        let live = pair(app, pool, pubkey, cookie).await;
        let bearer = format!("Bearer {}", live["access_token"].as_str().unwrap());
        let auth = [(header::AUTHORIZATION, bearer.as_str())];
        assert_eq!(
            request(app, Method::GET, SESSION, "", &auth).await.status(),
            StatusCode::OK,
        );
        set_account_status(pool, pubkey, status).await;
        json_error(
            request(app, Method::GET, SESSION, "", &auth).await,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
        )
        .await;
        let refresh = live["refresh_token"].as_str().unwrap();
        json_error(
            refresh_with(app, refresh).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        )
        .await;
        // Rejection must not consume the refresh credential.
        set_account_status(pool, pubkey, "active").await;
        assert_eq!(refresh_with(app, refresh).await.status(), StatusCode::OK);
    }
}

async fn session_expiry_is_fixed_and_limits_access_tokens(
    app: &Router,
    pool: &PgPool,
    pubkey: &str,
    cookie: &str,
) {
    let first = pair(app, pool, pubkey, cookie).await;
    let first_refresh = first["refresh_token"].as_str().unwrap();
    let paired_until = session_expiry(pool, first_refresh).await;
    let renewed = refresh_with(app, first_refresh).await;
    assert_eq!(renewed.status(), StatusCode::OK);
    let renewed = payload(renewed).await;
    let renewed_refresh = renewed["refresh_token"].as_str().unwrap();
    assert_eq!(session_expiry(pool, renewed_refresh).await, paired_until);

    // Leave minutes of margin rather than racing a sub-second expiry boundary.
    let shortened_until: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "UPDATE oauth_device_sessions SET expires_at = clock_timestamp() + INTERVAL '5 minutes'
         WHERE refresh_token_hash = $1 RETURNING expires_at",
    )
    .bind(hash_refresh_token(renewed_refresh))
    .fetch_one(pool)
    .await
    .unwrap();
    let clamped = refresh_with(app, renewed_refresh).await;
    assert_eq!(clamped.status(), StatusCode::OK);
    let clamped = payload(clamped).await;
    let expires_in = clamped["expires_in"].as_i64().unwrap();
    assert!((1..=300).contains(&expires_in));
    let clamped_refresh = clamped["refresh_token"].as_str().unwrap();
    assert_eq!(session_expiry(pool, clamped_refresh).await, shortened_until);
    let clamped_token =
        ucan::ucan::Ucan::try_from_token_string(clamped["access_token"].as_str().unwrap()).unwrap();
    assert!(*clamped_token.expires_at() <= shortened_until.timestamp() as u64);

    sqlx::query(
        "UPDATE oauth_device_sessions SET expires_at = clock_timestamp() - INTERVAL '1 second'
         WHERE refresh_token_hash = $1",
    )
    .bind(hash_refresh_token(clamped_refresh))
    .execute(pool)
    .await
    .unwrap();
    json_error(
        refresh_with(app, clamped_refresh).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await;
    let still_stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_device_sessions WHERE refresh_token_hash = $1",
    )
    .bind(hash_refresh_token(clamped_refresh))
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(still_stored, 1);
    let bearer = format!("Bearer {}", clamped["access_token"].as_str().unwrap());
    json_error(
        request(
            app,
            Method::GET,
            SESSION,
            "",
            &[(header::AUTHORIZATION, bearer.as_str())],
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
    )
    .await;
}

async fn insert_session_fixture(
    pool: &PgPool,
    tenant_id: i64,
    pubkey: &str,
    expired: bool,
    revoked: bool,
) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO oauth_device_sessions
         (id, tenant_id, user_pubkey, refresh_token_hash, expires_at, revoked_at)
         VALUES ($1, $2, $3, $4,
                 clock_timestamp() + CASE WHEN $5 THEN INTERVAL '-1 day' ELSE INTERVAL '1 day' END,
                 CASE WHEN $6 THEN clock_timestamp() END)",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(pubkey)
    .bind(hash_refresh_token(&Uuid::new_v4().to_string()))
    .bind(expired)
    .bind(revoked)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn browser_revoke(app: &Router, cookie: &str, id: &str) -> Response {
    request(
        app,
        Method::POST,
        "/api/user/device-sessions/revoke",
        &json!({"id": id}).to_string(),
        &[
            (header::COOKIE, cookie),
            (header::CONTENT_TYPE, "application/json"),
        ],
    )
    .await
}

async fn account_manages_only_its_own_tv_sessions(
    app: &Router,
    pool: &PgPool,
    pubkey: &str,
    cookie: &str,
) {
    let live = pair(app, pool, pubkey, cookie).await;
    let refresh = live["refresh_token"].as_str().unwrap();
    let id = session_id(pool, refresh).await;
    let expires_at = session_expiry(pool, refresh).await;
    let other_live = pair(app, pool, pubkey, cookie).await;
    let other_live_id = session_id(pool, other_live["refresh_token"].as_str().unwrap()).await;
    let bearer = format!("Bearer {}", live["access_token"].as_str().unwrap());
    let auth = [(header::AUTHORIZATION, bearer.as_str())];

    for (index, protected_minor) in [false, true, false].into_iter().enumerate() {
        if index > 0 {
            sqlx::query("UPDATE users SET verified_minor = $2 WHERE pubkey = $1 AND tenant_id = 1")
                .bind(pubkey)
                .bind(protected_minor)
                .execute(pool)
                .await
                .unwrap();
        }
        let response = request(app, Method::GET, SESSION, "", &auth).await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = payload(response).await;
        assert_eq!(session["pubkey"], pubkey);
        assert_eq!(session["protected_minor"], protected_minor);
        for path in [
            "/api/user/account",
            "/api/user/pubkey",
            "/api/user/sessions",
        ] {
            assert_eq!(
                request(app, Method::GET, path, "", &auth).await.status(),
                StatusCode::UNAUTHORIZED,
            );
        }
    }
    assert_eq!(
        request(
            app,
            Method::POST,
            "/api/user/device-sessions/revoke",
            &json!({"id": id}).to_string(),
            &[
                (header::AUTHORIZATION, bearer.as_str()),
                (header::CONTENT_TYPE, "application/json"),
            ],
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
    );

    let foreign_user = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified) VALUES ($1, 1, $2, true)",
    )
    .bind(&foreign_user)
    .bind(format!("tv-other-{}@example.test", Uuid::new_v4()))
    .execute(pool)
    .await
    .unwrap();
    let foreign_tenant: i64 = sqlx::query_scalar(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, 'TV isolation test', NOW(), NOW()) RETURNING id",
    )
    .bind(format!("tv-{}.example.test", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .unwrap();
    let expired_id = insert_session_fixture(pool, 1, pubkey, true, false).await;
    let revoked_id = insert_session_fixture(pool, 1, pubkey, false, true).await;
    let foreign_id = insert_session_fixture(pool, 1, &foreign_user, false, false).await;
    let foreign_tenant_id =
        insert_session_fixture(pool, foreign_tenant, pubkey, false, false).await;

    let response = request(
        app,
        Method::GET,
        "/api/user/sessions",
        "",
        &[(header::COOKIE, cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let listed = payload(response).await;
    assert!(listed["sessions"].is_array());
    let device_sessions = listed["device_sessions"].as_array().unwrap();
    assert_eq!(device_sessions.len(), 2);
    let own = device_sessions.iter().find(|row| row["id"] == id).unwrap();
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(own["expires_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc),
        expires_at,
    );
    assert!(device_sessions.iter().any(|row| row["id"] == other_live_id));

    set_account_status(pool, pubkey, "suspended").await;
    let response = request(
        app,
        Method::GET,
        "/api/user/sessions",
        "",
        &[(header::COOKIE, cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(payload(response).await["device_sessions"]
        .as_array()
        .unwrap()
        .is_empty());
    set_account_status(pool, pubkey, "active").await;

    let unknown_id = Uuid::new_v4().to_string();
    for forbidden_id in [&foreign_id, &foreign_tenant_id, &unknown_id] {
        assert!(browser_revoke(app, cookie, forbidden_id)
            .await
            .status()
            .is_client_error());
    }
    assert!(browser_revoke(app, cookie, &id).await.status().is_success());
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM oauth_device_sessions WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(revoked);
    for untouched_id in [&other_live_id, &foreign_id, &foreign_tenant_id, &expired_id] {
        let untouched: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NULL FROM oauth_device_sessions WHERE id = $1",
        )
        .bind(untouched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(untouched);
    }
    let response = request(
        app,
        Method::GET,
        "/api/user/sessions",
        "",
        &[(header::COOKIE, cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let remaining = payload(response).await;
    let remaining = remaining["device_sessions"].as_array().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["id"], other_live_id);
    assert!(!remaining.iter().any(|row| row["id"] == revoked_id));
    json_error(
        request(app, Method::GET, SESSION, "", &auth).await,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
    )
    .await;
    json_error(
        refresh_with(app, refresh).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await;
}
