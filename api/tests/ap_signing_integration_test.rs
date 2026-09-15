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
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
    BcryptAdmission,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::{ApActorKeysRepository, UserRepository},
    secret_pool::SecretPool,
    types::user::UserStatus,
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
use ucan::builder::UcanBuilder;
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

async fn create_test_user_with_username(pool: &PgPool, pubkey: &str, username: &str) {
    let email = format!("ap-{}@example.com", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO users (pubkey, email, email_verified, username, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, true, $3, $4, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(&email)
    .bind(username)
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

async fn create_test_oauth_authorization(
    pool: &PgPool,
    user_pubkey: &str,
    bunker_pubkey: &str,
    revoked: bool,
) {
    let auth_handle = hex::encode(rand::random::<[u8; 32]>());
    let revoked_at = if revoked { Some(Utc::now()) } else { None };
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, tenant_id, revoked_at, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'test_hash', $4, $5, $6, $7, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(user_pubkey)
    .bind("https://ap-test.example.com")
    .bind(bunker_pubkey)
    .bind(serde_json::json!(["wss://relay.example.com"]).to_string())
    .bind(TENANT_ID)
    .bind(revoked_at)
    .bind(&auth_handle)
    .execute(pool)
    .await
    .expect("Failed to create oauth authorization");
}

async fn build_self_signed_ucan(user_keys: &Keys, bunker_pubkey: Option<&str>) -> String {
    use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};

    let user_did = nostr_pubkey_to_did(&user_keys.public_key());
    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let mut facts = serde_json::json!({
        "tenant_id": TENANT_ID,
        "redirect_origin": "https://ap-test.example.com",
    });
    if let Some(bunker_pubkey) = bunker_pubkey {
        facts["bunker_pubkey"] = serde_json::json!(bunker_pubkey);
    }

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("Failed to build UCAN")
        .sign()
        .await
        .expect("Failed to sign UCAN");

    ucan.encode().expect("Failed to encode UCAN")
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

// --- Test B: sign without a key lazily creates the actor key ---

#[tokio::test]
async fn sign_without_key_lazily_creates_key() {
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
    assert_eq!(resp.status(), StatusCode::OK);

    let key_exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM ap_actor_keys WHERE user_pubkey = $1")
            .bind(&pubkey)
            .fetch_optional(&pool)
            .await
            .expect("query AP key");
    assert!(key_exists.is_some(), "sign should lazily create AP key");

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

#[tokio::test]
async fn gateway_actor_shape_lazily_creates_key_and_signs() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let pubkey = Keys::generate().public_key().to_hex();
    let username = format!("ap-actor-{}", &pubkey[..8]);
    let actor = format!("https://divine.video/ap/users/{username}");
    create_test_user_with_username(&pool, &pubkey, &username).await;

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::get(format!("/ap/keys/{}", urlencoding::encode(&actor)))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key_body = parse_body(resp).await;
    let pem = key_body["public_key_pem"].as_str().unwrap().to_string();

    let signing_string =
        "(request-target): post /inbox\nhost: divine.video\ndate: Mon, 01 Jan 2026 00:00:00 GMT";
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "actor": actor, "signing_string": signing_string }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sign_resp = parse_body(resp).await;
    assert_eq!(sign_resp["pubkey"].as_str().unwrap(), pubkey);

    let public = RsaPublicKey::from_public_key_pem(&pem).expect("pem");
    let vk = VerifyingKey::<Sha256>::new(public);
    let raw = BASE64
        .decode(sign_resp["signature"].as_str().unwrap())
        .expect("b64");
    let sig = Signature::try_from(raw.as_slice()).expect("sig");
    vk.verify(signing_string.as_bytes(), &sig)
        .expect("signature must verify against actor PEM");

    cleanup(&pool, &pubkey).await;
}

#[tokio::test]
async fn deleted_user_removes_key_and_later_sign_returns_404() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let pubkey = Keys::generate().public_key().to_hex();
    create_test_user(&pool, &pubkey).await;

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

    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .delete_account(&pubkey, TENANT_ID)
        .await
        .expect("delete account");

    let key_exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM ap_actor_keys WHERE user_pubkey = $1")
            .bind(&pubkey)
            .fetch_optional(&pool)
            .await
            .expect("query AP key");
    assert!(key_exists.is_none(), "AP key must be deleted with account");

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
}

#[tokio::test]
/// ActivityPub keys represent Divine-hosted actors, so both suspended and banned
/// accounts remain unable to create, retrieve, or use them (keycast#374).
async fn restricted_users_cannot_create_get_or_sign() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    for status in [UserStatus::Suspended, UserStatus::Banned] {
        let pubkey = Keys::generate().public_key().to_hex();
        create_test_user(&pool, &pubkey).await;
        UserRepository::new(pool.clone())
            .set_user_status(&pubkey, TENANT_ID, &status, Some("ap test"))
            .await
            .expect("restrict user");

        let app = build_app(create_test_auth_state(pool.clone()));
        let resp = app
            .oneshot(bearer_json(
                "/ap/keys",
                serde_json::json!({ "pubkey": pubkey }),
                Some(SERVICE_TOKEN),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "status: {status:?}");

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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "status: {status:?}");

        let app = build_app(create_test_auth_state(pool.clone()));
        let resp = app
            .oneshot(bearer_json(
                "/ap/sign",
                serde_json::json!({ "pubkey": pubkey, "signing_string": "x" }),
                Some(SERVICE_TOKEN),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "status: {status:?}");

        cleanup(&pool, &pubkey).await;
    }
}

#[tokio::test]
async fn ucan_pubkey_mismatch_returns_403() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let other_pubkey = Keys::generate().public_key().to_hex();
    let bunker_pubkey = Keys::generate().public_key().to_hex();
    create_test_user(&pool, &user_pubkey).await;
    create_test_user(&pool, &other_pubkey).await;
    create_test_oauth_authorization(&pool, &user_pubkey, &bunker_pubkey, false).await;

    let token = build_self_signed_ucan(&user_keys, Some(&bunker_pubkey)).await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "pubkey": other_pubkey, "signing_string": "x" }),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    cleanup(&pool, &user_pubkey).await;
    cleanup(&pool, &other_pubkey).await;
}

#[tokio::test]
async fn revoked_oauth_ucan_cannot_sign() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let bunker_pubkey = Keys::generate().public_key().to_hex();
    create_test_user(&pool, &user_pubkey).await;
    create_test_oauth_authorization(&pool, &user_pubkey, &bunker_pubkey, true).await;

    let token = build_self_signed_ucan(&user_keys, Some(&bunker_pubkey)).await;
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "pubkey": user_pubkey, "signing_string": "x" }),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    cleanup(&pool, &user_pubkey).await;
}

#[tokio::test]
async fn key_rotation_preserves_ap_public_pem_on_new_pubkey() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let old_keys = Keys::generate();
    let old_pubkey = old_keys.public_key().to_hex();
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    let username = format!("ap-rotate-{}", &old_pubkey[..8]);
    let actor = format!("https://divine.video/ap/users/{username}");
    create_test_user_with_username(&pool, &old_pubkey, &username).await;

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/keys",
            serde_json::json!({ "actor": actor.clone() }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let created = parse_body(resp).await;
    let original_pem = created["public_key_pem"].as_str().unwrap().to_string();
    assert_eq!(created["pubkey"].as_str().unwrap(), old_pubkey);

    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            TENANT_ID,
            "rotated-ap@example.com",
            "password-hash",
            &[1, 2, 3, 4],
        )
        .await
        .expect("change key");

    let resolved_pubkey = user_repo
        .find_pubkey_by_username(&username, TENANT_ID)
        .await
        .expect("username lookup")
        .expect("username should still resolve after key rotation");
    assert_eq!(resolved_pubkey, new_pubkey);

    let repo = ApActorKeysRepository::new(pool.clone());
    assert!(
        repo.find_public_pem(TENANT_ID, &old_pubkey)
            .await
            .expect("old AP key lookup")
            .is_none(),
        "old pubkey should no longer own the AP key"
    );
    let (rotated_pem, _) = repo
        .find_public_pem(TENANT_ID, &new_pubkey)
        .await
        .expect("new AP key lookup")
        .expect("new pubkey should own the existing AP key");
    assert_eq!(rotated_pem, original_pem);

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::get(format!("/ap/keys/{}", urlencoding::encode(&actor)))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key_body = parse_body(resp).await;
    assert_eq!(key_body["pubkey"].as_str().unwrap(), new_pubkey);
    assert_eq!(key_body["public_key_pem"].as_str().unwrap(), original_pem);

    let signing_string =
        "(request-target): post /inbox\nhost: divine.video\ndate: Mon, 01 Jan 2026 00:00:00 GMT";
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "actor": actor.clone(), "signing_string": signing_string }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sign_resp = parse_body(resp).await;
    assert_eq!(sign_resp["pubkey"].as_str().unwrap(), new_pubkey);

    let public = RsaPublicKey::from_public_key_pem(&original_pem).expect("pem");
    let vk = VerifyingKey::<Sha256>::new(public);
    let raw = BASE64
        .decode(sign_resp["signature"].as_str().unwrap())
        .expect("b64");
    let sig = Signature::try_from(raw.as_slice()).expect("sig");
    vk.verify(signing_string.as_bytes(), &sig)
        .expect("signature must verify against pre-rotation actor PEM");

    cleanup(&pool, &old_pubkey).await;
    cleanup(&pool, &new_pubkey).await;
}

/// Rotation transfers the identity — username and AP key — to the new pubkey, so
/// it must transfer the account restrictions too. Otherwise a suspended actor
/// rotates its Nostr key onto a row that defaults to `active` and gets its
/// ActivityPub signing oracle back.
#[tokio::test]
async fn key_rotation_preserves_suspension_for_ap_actor() {
    common::assert_test_database_url();
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", SERVICE_TOKEN) };
    let pool = common::setup_test_db().await;

    let old_pubkey = Keys::generate().public_key().to_hex();
    let new_pubkey = Keys::generate().public_key().to_hex();
    let username = format!("ap-susp-{}", uuid::Uuid::new_v4());
    let actor = format!("https://divine.video/ap/users/{username}");
    create_test_user_with_username(&pool, &old_pubkey, &username).await;

    // Mint the AP key while the account is still active, then suspend it.
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/keys",
            serde_json::json!({ "actor": actor.clone() }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .set_user_status(
            &old_pubkey,
            TENANT_ID,
            &UserStatus::Suspended,
            Some("ap rotation test"),
        )
        .await
        .expect("suspend user");

    user_repo
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            TENANT_ID,
            &format!("suspended-ap-{}@example.com", uuid::Uuid::new_v4()),
            "password-hash",
            &[1, 2, 3, 4],
        )
        .await
        .expect("change key");

    let (status, reason, suspended_at) = user_repo
        .get_user_status(&new_pubkey, TENANT_ID)
        .await
        .expect("status lookup")
        .expect("replacement user should exist");
    assert_eq!(
        status,
        UserStatus::Suspended,
        "rotation must not reset the account to active"
    );
    assert_eq!(reason.as_deref(), Some("ap rotation test"));
    assert!(
        suspended_at.is_some(),
        "suspended_at should carry to the new pubkey"
    );

    // The actor URL now resolves to the new pubkey; both AP paths must stay closed.
    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::get(format!("/ap/keys/{}", urlencoding::encode(&actor)))
                .header("authorization", format!("Bearer {}", SERVICE_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let app = build_app(create_test_auth_state(pool.clone()));
    let resp = app
        .oneshot(bearer_json(
            "/ap/sign",
            serde_json::json!({ "actor": actor.clone(), "signing_string": "(request-target): post /inbox" }),
            Some(SERVICE_TOKEN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    cleanup(&pool, &old_pubkey).await;
    cleanup(&pool, &new_pubkey).await;
}
