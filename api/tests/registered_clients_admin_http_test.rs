// ABOUTME: HTTP-layer negative tests for the registered_clients admin endpoints
// ABOUTME: Locks down the is_full_admin gate so support-admin and non-admin callers are rejected

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::{
            admin::{
                create_registered_client, delete_registered_client, list_registered_clients,
                test_registered_client_pattern, update_registered_client,
                CreateRegisteredClientRequest, TestRedirectPatternRequest,
                UpdateRegisteredClientRequest,
            },
            routes::AuthState,
        },
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::RegisteredClientRepository,
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

// -----------------------------------------------------------------------------
// Auth + tenant fixtures
// -----------------------------------------------------------------------------

/// Identity passed to the handlers in lieu of a real UCAN extraction.
///
/// Each handler under test calls `is_full_admin(&auth)` which returns true only
/// when `admin_role == "full"` or the pubkey is in `ALLOWED_PUBKEYS`. Tests use
/// fresh random pubkeys so they never accidentally match a polluted env var.
#[derive(Clone)]
struct AuthConfig {
    pubkey: String,
    admin_role: Option<String>,
}

impl AuthConfig {
    fn full_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("full".to_string()),
        }
    }

    fn support_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("support".to_string()),
        }
    }

    fn non_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: None,
        }
    }

    fn into_auth(self) -> UcanAuth {
        UcanAuth {
            pubkey: self.pubkey,
            admin_role: self.admin_role,
        }
    }
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
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
        }),
        auth_tx: None,
    }
}

// -----------------------------------------------------------------------------
// Router under test
// -----------------------------------------------------------------------------

/// Build a Router that mirrors the production `/admin/registered-clients` mount,
/// but injects `TenantExtractor` and `UcanAuth` from the test-controlled
/// `AuthConfig` instead of resolving them from request headers + global state.
///
/// The handler bodies (auth gate, repo calls, error mapping) are unchanged, so
/// status codes and bodies match what production would emit for the same
/// identity.
fn build_app(auth_state: AuthState, config: AuthConfig) -> Router {
    let list_state = auth_state.clone();
    let list_cfg = config.clone();
    let create_state = auth_state.clone();
    let create_cfg = config.clone();
    let update_state = auth_state.clone();
    let update_cfg = config.clone();
    let delete_state = auth_state.clone();
    let delete_cfg = config.clone();
    let test_cfg = config.clone();

    Router::new()
        .route(
            "/admin/registered-clients",
            get(move || {
                let state = list_state.clone();
                let cfg = list_cfg.clone();
                async move {
                    list_registered_clients(create_test_tenant(), State(state), cfg.into_auth())
                        .await
                }
            })
            .post(move |Json(body): Json<CreateRegisteredClientRequest>| {
                let state = create_state.clone();
                let cfg = create_cfg.clone();
                async move {
                    create_registered_client(
                        create_test_tenant(),
                        State(state),
                        cfg.into_auth(),
                        Json(body),
                    )
                    .await
                }
            }),
        )
        .route(
            "/admin/registered-clients/test",
            post(move |Json(body): Json<TestRedirectPatternRequest>| {
                let cfg = test_cfg.clone();
                async move {
                    test_registered_client_pattern(
                        create_test_tenant(),
                        cfg.into_auth(),
                        Json(body),
                    )
                    .await
                }
            }),
        )
        .route(
            "/admin/registered-clients/:id",
            patch(
                move |Path(id): Path<i32>, Json(body): Json<UpdateRegisteredClientRequest>| {
                    let state = update_state.clone();
                    let cfg = update_cfg.clone();
                    async move {
                        update_registered_client(
                            create_test_tenant(),
                            State(state),
                            cfg.into_auth(),
                            Path(id),
                            Json(body),
                        )
                        .await
                    }
                },
            )
            .delete(move |Path(id): Path<i32>| {
                let state = delete_state.clone();
                let cfg = delete_cfg.clone();
                async move {
                    delete_registered_client(
                        create_test_tenant(),
                        State(state),
                        cfg.into_auth(),
                        Path(id),
                    )
                    .await
                }
            }),
        )
}

// -----------------------------------------------------------------------------
// Request helpers
// -----------------------------------------------------------------------------

fn json_body(value: serde_json::Value) -> Body {
    Body::from(value.to_string())
}

fn request(method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let builder = Request::builder().method(method).uri(uri);
    match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(json_body(value))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn read_body_string(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn create_body() -> serde_json::Value {
    // Unique client_id so a leaked write (gate failure) is detectable in DB.
    let id = format!("forbidden-test-{}", Uuid::new_v4());
    serde_json::json!({
        "client_id": id,
        "name": "Forbidden Test",
        "allowed_redirect_uris": ["https://example.com/cb"]
    })
}

fn update_body() -> serde_json::Value {
    serde_json::json!({ "name": "Forbidden Renamed" })
}

fn test_pattern_body() -> serde_json::Value {
    serde_json::json!({
        "pattern": "https://app.example.com/cb",
        "uri": "https://app.example.com/cb",
    })
}

// -----------------------------------------------------------------------------
// Negative tests: support-admin is rejected on every endpoint
// -----------------------------------------------------------------------------

#[tokio::test]
async fn list_rejects_support_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::support_admin());

    let response = app
        .oneshot(request("GET", "/admin/registered-clients", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        read_body_string(response)
            .await
            .contains("Full admin access required"),
        "support-admin GET should report the gate's exact message"
    );
}

#[tokio::test]
async fn create_rejects_support_admin() {
    let pool = common::setup_test_db().await;
    let body = create_body();
    let new_client_id = body["client_id"].as_str().unwrap().to_string();

    let app = build_app(
        create_test_auth_state(pool.clone()),
        AuthConfig::support_admin(),
    );

    let response = app
        .oneshot(request("POST", "/admin/registered-clients", Some(body)))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Strong assertion: the gate must fire before any DB write.
    let repo = RegisteredClientRepository::new(pool);
    assert!(
        repo.get_allowed_redirect_uris(&new_client_id, TENANT_ID)
            .await
            .unwrap()
            .is_none(),
        "forbidden create must not have inserted a row"
    );
}

#[tokio::test]
async fn update_rejects_support_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::support_admin());

    let response = app
        .oneshot(request(
            "PATCH",
            "/admin/registered-clients/1",
            Some(update_body()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_rejects_support_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::support_admin());

    let response = app
        .oneshot(request("DELETE", "/admin/registered-clients/1", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pattern_test_rejects_support_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::support_admin());

    let response = app
        .oneshot(request(
            "POST",
            "/admin/registered-clients/test",
            Some(test_pattern_body()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -----------------------------------------------------------------------------
// Negative tests: non-admin (no role) is rejected on every endpoint
// -----------------------------------------------------------------------------

#[tokio::test]
async fn list_rejects_non_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::non_admin());

    let response = app
        .oneshot(request("GET", "/admin/registered-clients", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_rejects_non_admin() {
    let pool = common::setup_test_db().await;
    let body = create_body();
    let new_client_id = body["client_id"].as_str().unwrap().to_string();

    let app = build_app(
        create_test_auth_state(pool.clone()),
        AuthConfig::non_admin(),
    );

    let response = app
        .oneshot(request("POST", "/admin/registered-clients", Some(body)))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let repo = RegisteredClientRepository::new(pool);
    assert!(
        repo.get_allowed_redirect_uris(&new_client_id, TENANT_ID)
            .await
            .unwrap()
            .is_none(),
        "forbidden create must not have inserted a row"
    );
}

#[tokio::test]
async fn update_rejects_non_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::non_admin());

    let response = app
        .oneshot(request(
            "PATCH",
            "/admin/registered-clients/1",
            Some(update_body()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_rejects_non_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::non_admin());

    let response = app
        .oneshot(request("DELETE", "/admin/registered-clients/1", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pattern_test_rejects_non_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::non_admin());

    let response = app
        .oneshot(request(
            "POST",
            "/admin/registered-clients/test",
            Some(test_pattern_body()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -----------------------------------------------------------------------------
// Positive sanity checks: full admin must NOT receive 403, otherwise the
// negative tests above could pass for the wrong reason (e.g., a misrouted URL
// or a mistakenly-removed handler).
// -----------------------------------------------------------------------------

#[tokio::test]
async fn list_allows_full_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::full_admin());

    let response = app
        .oneshot(request("GET", "/admin/registered-clients", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn pattern_test_allows_full_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::full_admin());

    let response = app
        .oneshot(request(
            "POST",
            "/admin/registered-clients/test",
            Some(test_pattern_body()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
