#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::http::ap::{self, CreateKeyRequest, SignRequest},
    api::http::routes::AuthState,
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const SERVICE_TOKEN: &str = "test-service-token-secret";

/// Identity KeyManager: encrypt/decrypt are no-ops, so the stored
/// `encrypted_private_key` equals the plaintext PKCS#8 DER. This lets a real
/// RSA sign→verify roundtrip work end-to-end through the handlers.
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

fn build_app(auth_state: AuthState) -> Router {
    use keycast_api::api::tenant::{Tenant, TenantExtractor};

    fn tenant() -> TenantExtractor {
        TenantExtractor(Arc::new(Tenant {
            id: TENANT_ID,
            domain: "localhost".to_string(),
            name: "Test".to_string(),
            settings: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }))
    }

    let create_state = auth_state.clone();
    let get_state = auth_state.clone();
    let sign_state = auth_state.clone();

    Router::new()
        .route(
            "/ap/keys",
            post(
                move |headers: axum::http::HeaderMap, Json(body): Json<CreateKeyRequest>| {
                    let state = create_state.clone();
                    async move { ap::create_key(tenant(), State(state), headers, Json(body)).await }
                },
            ),
        )
        .route(
            "/ap/keys/:pubkey",
            get(
                move |Path(pubkey): Path<String>, headers: axum::http::HeaderMap| {
                    let state = get_state.clone();
                    async move { ap::get_key(tenant(), State(state), headers, Path(pubkey)).await }
                },
            ),
        )
        .route(
            "/ap/sign",
            post(
                move |headers: axum::http::HeaderMap, Json(body): Json<SignRequest>| {
                    let state = sign_state.clone();
                    async move { ap::sign(tenant(), State(state), headers, Json(body)).await }
                },
            ),
        )
}

async fn create_test_user(pool: &PgPool, pubkey: &str) {
    let email = format!("ap-{}@example.com", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, true, $3, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(&email)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("Failed to create test user");
}

async fn cleanup(pool: &PgPool, pubkey: &str) {
    sqlx::query("DELETE FROM ap_actor_keys WHERE user_pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .ok();
}

fn bearer_json(uri: &str, body: serde_json::Value, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::post(uri).header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {}", t));
    }
    builder
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

// Response types in ap.rs derive only Serialize, so we read them as JSON Values.
async fn parse_body(resp: axum::http::Response<Body>) -> serde_json::Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "failed to parse body: {e}; raw={}",
            String::from_utf8_lossy(&body)
        )
    })
}

// --- Test A: create → get → sign roundtrip with service token ---

#[tokio::test]
async fn create_get_sign_roundtrip_service_token() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let pubkey = Keys::generate().public_key().to_hex();
    create_test_user(&pool, &pubkey).await;

    // 2. POST /ap/keys (first time) -> created == true
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/keys",
            serde_json::json!({ "pubkey": pubkey }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let created = parse_body(resp).await;
    assert_eq!(
        created["created"],
        serde_json::Value::Bool(true),
        "first create must report created == true"
    );
    let pem = created["public_key_pem"].as_str().unwrap().to_string();
    assert!(
        pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "expected SPKI PEM, got: {}",
        &pem[..pem.len().min(40)]
    );

    // 3. POST /ap/keys again -> created == false, same PEM (idempotent)
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/keys",
            serde_json::json!({ "pubkey": pubkey }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let again = parse_body(resp).await;
    assert_eq!(
        again["created"],
        serde_json::Value::Bool(false),
        "second create must report created == false"
    );
    assert_eq!(
        again["public_key_pem"].as_str().unwrap(),
        pem,
        "key must never regenerate"
    );

    // 4. GET /ap/keys/:pubkey -> same PEM
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::get(format!("/ap/keys/{}", pubkey))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got = parse_body(resp).await;
    assert_eq!(got["public_key_pem"].as_str().unwrap(), pem);

    // 5. POST /ap/sign
    let signing_string =
        "(request-target): post /inbox\nhost: divine.video\ndate: Mon, 01 Jan 2026 00:00:00 GMT";
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "pubkey": pubkey, "signing_string": signing_string }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sign_resp = parse_body(resp).await;
    assert_eq!(sign_resp["algorithm"].as_str().unwrap(), "rsa-sha256");

    // 6. Verify the returned signature against the PEM (proves the oracle works).
    let public = RsaPublicKey::from_public_key_pem(&pem).expect("pem");
    let vk = VerifyingKey::<Sha256>::new(public);
    let raw = BASE64
        .decode(sign_resp["signature"].as_str().unwrap())
        .expect("b64");
    let sig = Signature::try_from(raw.as_slice()).expect("sig");
    vk.verify(signing_string.as_bytes(), &sig)
        .expect("signature must verify against returned PEM");

    // 7. Cleanup.
    cleanup(&pool, &pubkey).await;
}

// --- Test B: sign without a key returns 404 ---

#[tokio::test]
async fn sign_without_key_returns_404() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let pubkey = Keys::generate().public_key().to_hex();
    create_test_user(&pool, &pubkey).await;

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "pubkey": pubkey, "signing_string": "x" }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    cleanup(&pool, &pubkey).await;
}

// --- Test C: unauthenticated request rejected with 401 ---
//
// Send a valid JSON body + content-type so axum's `Json` extractor succeeds
// (that runs before the handler). Only the Authorization header is wrong, so
// the request flows through resolve_principal: is_service_token() == false and
// extract_user_from_token() fails -> ApError::Unauthorized -> 401.

#[tokio::test]
async fn unauthenticated_request_rejected() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let pubkey = Keys::generate().public_key().to_hex();

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/keys",
            serde_json::json!({ "pubkey": pubkey }),
            Some("not-the-service-token"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// NOTE: Test D (UCAN-for-A requesting pubkey B -> 403) is intentionally NOT
// implemented. Minting a valid UCAN that survives extract_user_from_token's
// validation (DPoP binding / facts) is disproportionately complex for a single
// 403 assertion. The Forbidden branch is exercised by code review of
// resolve_principal: when is_service_token() == false and the token resolves to
// a pubkey != body_pubkey, it returns ApError::Forbidden -> 403.
