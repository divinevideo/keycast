#![cfg(feature = "integration-tests")]

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware,
    routing::post,
    Json, Router,
};
use bcrypt::hash;
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::{
        http::{
            auth::login,
            auth_observability::request_id_middleware,
            oauth::{oauth_login, OAuthLoginRequest},
        },
        tenant::{Tenant, TenantExtractor},
    },
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
    BcryptAdmission,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

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

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

async fn create_test_auth_state(pool: PgPool) -> keycast_api::api::http::routes::AuthState {
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".to_string());
    let client = redis::Client::open(redis_url).expect("valid test Redis URL");
    let connection = redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect to test Redis");
    let redis = keycast_api::PrefixedRedis::new(
        connection,
        Some(format!("login-observability:{}", Uuid::new_v4())),
    );

    keycast_api::api::http::routes::AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt: bcrypt.clone(),
            redis: Some(redis),
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
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

async fn password_attempt(
    app: Router,
    email: &str,
    password: &str,
) -> (StatusCode, String, Option<String>) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .header("origin", "https://app.divine.video")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let retry_after = response
        .headers()
        .get("Retry-After")
        .map(|value| value.to_str().unwrap().to_string());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8(body.to_vec()).unwrap(),
        retry_after,
    )
}

#[tokio::test]
async fn test_login_records_auth_event_for_missing_user() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone()).await;
    let email = format!("missing-login-{}@example.com", Uuid::new_v4());
    let request_id = format!("trace-{}", Uuid::new_v4());

    cleanup_by_email(&pool, &email).await;

    let app = {
        let auth_state = auth_state.clone();
        Router::new()
            .route(
                "/auth/login",
                post(move |headers: HeaderMap, body: String| {
                    let auth_state = auth_state.clone();
                    async move { login(create_test_tenant(), State(auth_state), headers, body).await }
                }),
            )
            .layer(middleware::from_fn(request_id_middleware))
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .header("origin", "https://app.divine.video")
                .header("x-trace-id", &request_id)
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "wrong-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
            "/api/auth/login".to_string(),
            "login".to_string(),
            "failure".to_string(),
            Some("user_not_found".to_string()),
            request_id,
            Some(401),
        ))
    );

    cleanup_by_email(&pool, &email).await;
}

#[tokio::test]
async fn login_limit_is_identical_for_registered_and_missing_emails() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone()).await;
    let registered_email = format!("limited-registered-{}@example.com", Uuid::new_v4());
    let missing_email = format!("limited-missing-{}@example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    let password_hash = hash("correct-password", 4).unwrap();

    cleanup_by_email(&pool, &registered_email).await;
    cleanup_by_email(&pool, &missing_email).await;
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&registered_email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("create registered login subject");

    let app = Router::new().route(
        "/auth/login",
        post(move |headers: HeaderMap, body: String| {
            let auth_state = auth_state.clone();
            async move { login(create_test_tenant(), State(auth_state), headers, body).await }
        }),
    );

    for _ in 0..keycast_core::login_attempts::LOGIN_FREE_FAILURES {
        let registered = password_attempt(app.clone(), &registered_email, "wrong-password").await;
        let missing = password_attempt(app.clone(), &missing_email, "wrong-password").await;
        assert_eq!(registered, missing);
        assert_eq!(registered.0, StatusCode::UNAUTHORIZED);
    }

    let registered = password_attempt(app.clone(), &registered_email, "wrong-password").await;
    let missing = password_attempt(app, &missing_email, "wrong-password").await;
    assert_eq!(registered, missing);
    assert_eq!(registered.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(registered.2.as_deref(), Some("1"));

    cleanup_by_email(&pool, &registered_email).await;
    cleanup_by_email(&pool, &missing_email).await;
}

#[tokio::test]
async fn successful_login_resets_the_failure_budget() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone()).await;
    let email = format!("successful-reset-{}@example.com", Uuid::new_v4());
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let password = "correct-password";
    let password_hash = hash(password, 4).unwrap();

    cleanup_by_email(&pool, &email).await;
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("create login subject");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, 1)",
    )
    .bind(&pubkey)
    .bind(keys.secret_key().secret_bytes().to_vec())
    .execute(&pool)
    .await
    .expect("create personal key");

    let app = Router::new().route(
        "/auth/login",
        post(move |headers: HeaderMap, body: String| {
            let auth_state = auth_state.clone();
            async move { login(create_test_tenant(), State(auth_state), headers, body).await }
        }),
    );

    for _ in 0..2 {
        assert_eq!(
            password_attempt(app.clone(), &email, "wrong-password")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        password_attempt(app.clone(), &email, password).await.0,
        StatusCode::OK
    );
    for _ in 0..keycast_core::login_attempts::LOGIN_FREE_FAILURES {
        assert_eq!(
            password_attempt(app.clone(), &email, "wrong-password")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        password_attempt(app, &email, "wrong-password").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );

    cleanup_by_email(&pool, &email).await;
}

#[tokio::test]
async fn test_oauth_login_records_auth_event_for_unverified_user() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone()).await;
    let email = format!("oauth-unverified-{}@example.com", Uuid::new_v4());
    let request_id = format!("trace-{}", Uuid::new_v4());
    let pubkey = Keys::generate().public_key().to_hex();
    let password_hash = hash("test-password", 4).unwrap();

    cleanup_by_email(&pool, &email).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, false, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("Should create user");

    let app = {
        let auth_state = auth_state.clone();
        Router::new()
            .route(
                "/oauth/login",
                post(
                    move |headers: HeaderMap, Json(req): Json<OAuthLoginRequest>| {
                        let auth_state = auth_state.clone();
                        async move {
                            oauth_login(create_test_tenant(), State(auth_state), headers, Json(req))
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
                .uri("/oauth/login")
                .header("content-type", "application/json")
                .header("x-trace-id", &request_id)
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "test-password",
                        "client_id": "WebPopupTest",
                        "redirect_uri": "https://app.divine.video/callback",
                        "scope": "policy:full"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
            "/api/oauth/login".to_string(),
            "login".to_string(),
            "failure".to_string(),
            Some("email_not_verified".to_string()),
            request_id,
            Some(400),
        ))
    );

    cleanup_by_email(&pool, &email).await;
}
