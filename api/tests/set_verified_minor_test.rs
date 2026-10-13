// ABOUTME: HTTP-layer tests for the service-token set-verified_minor endpoint
// ABOUTME: Tests PUT /admin/users/:pubkey/verified-minor auth, set, audit, refusals

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::put,
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::{
        admin::{set_verified_minor_admin, UserStatusResponse, VerifiedMinorParams},
        routes::AuthState,
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
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const SERVICE_TOKEN: &str = "test-service-token-secret";

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

fn create_test_auth_state(pool: PgPool) -> AuthState {
    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));
    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            account_status_cache: keycast_api::state::new_account_status_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt: bcrypt.clone(),
            redis: None,
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

fn build_app(auth_state: AuthState) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};
    let put_state = auth_state.clone();
    Router::new().route(
        "/admin/users/:pubkey/verified-minor",
        put(
            move |axum::extract::Path(pubkey): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  axum::extract::Query(params): axum::extract::Query<VerifiedMinorParams>| {
                let state = put_state.clone();
                let tenant = TenantExtractor(Arc::new(Tenant {
                    id: TENANT_ID,
                    domain: "localhost".to_string(),
                    name: "Test".to_string(),
                    settings: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }));
                async move {
                    set_verified_minor_admin(
                        tenant,
                        State(state),
                        headers,
                        axum::extract::Path(pubkey),
                        axum::extract::Query(params),
                    )
                    .await
                }
            },
        ),
    )
}

async fn create_user(pool: &PgPool, minor: bool, with_credentials: bool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, verified_minor, verified_minor_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 THEN NOW() END, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(with_credentials.then(|| format!("{}@example.test", &pubkey[..16])))
    .bind(with_credentials.then(|| "$2b$04$placeholderhashplaceholderhashplaceholderha".to_string()))
    .bind(minor)
    .execute(pool)
    .await
    .expect("create user");
    pubkey
}

async fn put_set(
    app: Router,
    pubkey: &str,
    query: &str,
    token: Option<&str>,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!("/admin/users/{}/verified-minor{}", pubkey, query));
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {}", token));
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    action: String,
    target_resource_type: String,
    target_resource_id: Option<String>,
    metadata_json: serde_json::Value,
}

async fn read_audit_rows(pool: &PgPool, actor_pubkey: &str) -> Vec<AuditRow> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT action, target_resource_type, target_resource_id, metadata_json \
         FROM admin_audit_events WHERE tenant_id = $1 AND actor_pubkey = $2",
    )
    .bind(TENANT_ID)
    .bind(actor_pubkey)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn test_set_verified_minor_sets_and_invalidates_cache() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = create_test_auth_state(pool.clone());
    let pubkey = create_user(&pool, false, true).await;
    auth_state
        .state
        .account_status_cache
        .insert(
            (TENANT_ID, pubkey.clone()),
            keycast_api::state::AccountGateState::Present {
                status: "active".to_string(),
                verified_minor: false,
            },
        )
        .await;

    let resp = put_set(
        build_app(auth_state.clone()),
        &pubkey,
        "",
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let status: UserStatusResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(status.verified_minor);
    assert!(status.verified_minor_at.is_some());
    assert_eq!(status.status, "active");
    assert!(
        auth_state
            .state
            .account_status_cache
            .get(&(TENANT_ID, pubkey))
            .await
            .is_none(),
        "setting verified_minor must invalidate the account-status cache so the DM gate sees it"
    );
}

#[tokio::test]
async fn test_set_with_actor_writes_one_audit_row_across_retries() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let actor = Keys::generate().public_key().to_hex();
    let query = format!("?actor={}&reason=age_review_approved", actor);

    let first = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        &query,
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let retry = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        &query,
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);

    let rows = read_audit_rows(&pool, &actor).await;
    assert_eq!(
        rows.len(),
        1,
        "a retry must not append a second audit event"
    );
    assert_eq!(rows[0].action, "set_verified_minor");
    assert_eq!(rows[0].target_resource_type, "user");
    assert_eq!(rows[0].target_resource_id.as_deref(), Some(pubkey.as_str()));
    assert_eq!(rows[0].metadata_json["reason"], "age_review_approved");
}

#[tokio::test]
async fn test_set_without_actor_writes_no_audit_row() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let resp = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        "",
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM admin_audit_events WHERE target_resource_id = $1 AND action = 'set_verified_minor'",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn test_set_credentialless_row_is_409_account_unclaimed() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, false).await;
    let resp = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        "",
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert_eq!(
        body["error"],
        "account_unclaimed: account has no login credentials"
    );
    let flagged: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!flagged.0);
}

#[tokio::test]
async fn test_set_onboarded_unclaimed_minor_is_200() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, true, false).await;
    let resp = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        "",
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_set_unknown_pubkey_is_404_user_not_found() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let fake = Keys::generate().public_key().to_hex();
    let resp = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &fake,
        "",
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // relay-manager's not_applicable discriminator matches this body exactly.
    assert_eq!(body_json(resp).await["error"], "user not found");
}

#[tokio::test]
async fn test_set_requires_service_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let missing = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        "",
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let wrong = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        "",
        Some("wrong-token"),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let flagged: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!flagged.0, "an unauthorized request must not set the flag");
}

#[tokio::test]
async fn test_set_malformed_or_empty_actor_is_400_and_flag_untouched() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    for query in ["?actor=not-hex", "?actor="] {
        let resp = put_set(
            build_app(create_test_auth_state(pool.clone())),
            &pubkey,
            query,
            Some(SERVICE_TOKEN),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query}");
    }
    let flagged: (bool,) = sqlx::query_as("SELECT verified_minor FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!flagged.0);
}

#[tokio::test]
async fn test_set_reason_sanitized_in_audit() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;
    let pubkey = create_user(&pool, false, true).await;
    let actor = Keys::generate().public_key().to_hex();
    // %E2%80%AE is U+202E (right-to-left override); %0A is a newline.
    let query = format!("?actor={}&reason=approved%E2%80%AE%0Aminor", actor);
    let resp = put_set(
        build_app(create_test_auth_state(pool.clone())),
        &pubkey,
        &query,
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = read_audit_rows(&pool, &actor).await;
    assert_eq!(rows[0].metadata_json["reason"], "approvedminor");
}
