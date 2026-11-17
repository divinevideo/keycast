#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::to_bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use chrono::Utc;
use keycast_api::{
    api::{
        http::{auth, claim, headless, oauth},
        tenant::{Tenant, TenantExtractor},
    },
    email_delivery::EmailDeliveryService,
    email_service::{DevEmailSender, EmailSender},
};
use nostr_sdk::Keys;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

fn tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".into(),
        name: "Test".into(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn assert_weak(response: Response) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value,
        json!({
            "code": "WEAK_PASSWORD",
            "error": "Use at least 8 characters and avoid common passwords."
        })
    );
}

async fn stored_hash(pool: &PgPool, pubkey: &str) -> String {
    sqlx::query_scalar("SELECT password_hash FROM users WHERE pubkey = $1 AND tenant_id = 1")
        .bind(pubkey)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn session(keys: &Keys) -> HeaderMap {
    use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
    use ucan::builder::UcanBuilder;
    let material = NostrKeyMaterial::from_keys(keys.clone());
    let did = nostr_pubkey_to_did(&keys.public_key());
    let token = UcanBuilder::default()
        .issued_by(&material)
        .for_audience(&did)
        .with_lifetime(3600)
        .with_fact(json!({"tenant_id": 1, "redirect_origin": "https://example.com"}))
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap()
        .encode()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    headers
}

#[tokio::test]
async fn all_new_password_paths_share_policy_without_changing_legacy_login() {
    let pool = common::setup_test_db().await;
    let (mut state, producer) = common::create_test_auth_state(pool.clone());
    // This test does not consume generated bunker secrets; avoid competing background hashing.
    producer.abort();
    let redis_url = std::env::var("TEST_REDIS_URL").expect("dedicated test Redis required");
    let redis = redis::aio::ConnectionManager::new(redis::Client::open(redis_url).unwrap())
        .await
        .unwrap();
    Arc::get_mut(&mut state.state).unwrap().redis = Some(keycast_api::PrefixedRedis::new(
        redis,
        Some(format!("password-policy:{}", Uuid::new_v4())),
    ));
    let sender: Arc<dyn EmailSender> = Arc::new(DevEmailSender::new());
    let delivery = EmailDeliveryService::unrestricted_for_tests(sender.clone());
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("policy-{}@example.com", Uuid::new_v4());
    let reset_token = Uuid::new_v4().to_string();
    let claim_token = Uuid::new_v4().to_string();
    let original_hash = bcrypt::hash("1234", 4).unwrap();
    sqlx::query("INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, password_reset_token, password_reset_expires_at) VALUES ($1, 1, $2, $3, true, $4, NOW() + INTERVAL '1 hour')")
        .bind(&pubkey).bind(&email).bind(&original_hash).bind(keycast_core::token_hash::hash_token(&reset_token))
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO personal_keys (user_pubkey, tenant_id, encrypted_secret_key) VALUES ($1, 1, $2)")
        .bind(&pubkey).bind(keys.secret_key().to_secret_bytes().to_vec())
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO account_claim_tokens (token, user_pubkey, tenant_id, expires_at) VALUES ($1, $2, 1, NOW() + INTERVAL '1 day')")
        .bind(keycast_core::token_hash::hash_token(&claim_token)).bind(&pubkey).execute(&pool).await.unwrap();
    let headers = session(&keys).await;

    // Exercise actual login handlers, not just bcrypt: old weak credentials remain usable.
    let mut login_headers = HeaderMap::new();
    login_headers.insert("origin", "https://example.com".parse().unwrap());
    let response = auth::login(
        tenant(),
        State(state.clone()),
        login_headers,
        json!({"email": email, "password": "1234"}).to_string(),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("set-cookie"));
    let response = headless::headless_login(tenant(), State(state.clone()), HeaderMap::new(),
        Json(serde_json::from_value(json!({"email": email, "password": "1234", "client_id": "policy-test", "redirect_uri": "https://example.com/callback"})).unwrap()))
        .await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    for password in ["1234", "password", "password123", " PASSWORD123 ", "éééé"] {
        let new_email = format!("policy-new-{}@example.com", Uuid::new_v4());
        let request = json!({"email": new_email, "password": password, "client_id": "policy-test", "redirect_uri": "https://example.com/callback"});
        assert_weak(
            auth::register(
                tenant(),
                State(state.clone()),
                Extension(sender.clone()),
                HeaderMap::new(),
                Json(serde_json::from_value(request.clone()).unwrap()),
            )
            .await
            .into_response(),
        )
        .await;
        assert_weak(
            headless::headless_register(
                tenant(),
                State(state.clone()),
                Extension(sender.clone()),
                Json(serde_json::from_value(request.clone()).unwrap()),
            )
            .await
            .into_response(),
        )
        .await;
        assert_weak(
            oauth::oauth_register(
                tenant(),
                State(state.clone()),
                Extension(sender.clone()),
                Json(serde_json::from_value(request).unwrap()),
            )
            .await
            .into_response(),
        )
        .await;
        assert_weak(
            auth::reset_password(
                tenant(),
                State(state.clone()),
                HeaderMap::new(),
                Json(auth::ResetPasswordRequest {
                    token: reset_token.clone(),
                    new_password: password.into(),
                }),
            )
            .await
            .into_response(),
        )
        .await;
        assert_weak(
            auth::change_password(
                tenant(),
                State(pool.clone()),
                Extension(state.state.bcrypt.clone()),
                headers.clone(),
                Json(auth::ChangePasswordRequest {
                    current_password: "1234".into(),
                    new_password: password.into(),
                }),
            )
            .await
            .into_response(),
        )
        .await;
        let response = claim::claim_post(
            tenant(),
            State(state.clone()),
            Extension(delivery.clone()),
            HeaderMap::new(),
            Form(claim::ClaimForm {
                token: claim_token.clone(),
                email: new_email.clone(),
                password: password.into(),
                password_confirmation: password.into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["x-error-code"], "WEAK_PASSWORD");
        let body = to_bytes(response.into_body(), 16384).await.unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("Use at least 8 characters and avoid common passwords."));
        assert_eq!(stored_hash(&pool, &pubkey).await, original_hash);
        let untouched: bool = sqlx::query_scalar(
            "SELECT password_reset_token = $2 FROM users WHERE pubkey = $1 AND tenant_id = 1",
        )
        .bind(&pubkey)
        .bind(keycast_core::token_hash::hash_token(&reset_token))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(untouched);
        let user_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND tenant_id = 1)",
        )
        .bind(&new_email)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!user_exists);
        let pending_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_codes WHERE pending_email = $1 AND tenant_id = 1)",
        )
        .bind(&new_email)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!pending_exists);
        let unstaged: bool = sqlx::query_scalar("SELECT pending_password_hash IS NULL AND confirmation_token IS NULL FROM account_claim_tokens WHERE token = $1")
            .bind(keycast_core::token_hash::hash_token(&claim_token)).fetch_one(&pool).await.unwrap();
        assert!(unstaged);
    }

    // All registration paths accept the same passphrase and preserve its padding when hashing.
    let new_password = "  violet otters share teacups  ";
    for path in ["browser", "headless", "oauth"] {
        let new_email = format!("policy-accepted-{}@example.com", Uuid::new_v4());
        let request = json!({"email": new_email, "password": new_password, "client_id": "policy-test", "redirect_uri": "https://example.com/callback"});
        let response = match path {
            "browser" => auth::register(
                tenant(),
                State(state.clone()),
                Extension(sender.clone()),
                HeaderMap::new(),
                Json(serde_json::from_value(request).unwrap()),
            )
            .await
            .into_response(),
            "headless" => headless::headless_register(
                tenant(),
                State(state.clone()),
                Extension(sender.clone()),
                Json(serde_json::from_value(request).unwrap()),
            )
            .await
            .into_response(),
            _ => oauth::oauth_register(
                tenant(),
                State(state.clone()),
                Extension(sender.clone()),
                Json(serde_json::from_value(request).unwrap()),
            )
            .await
            .into_response(),
        };
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let hash: String = if path == "browser" {
            sqlx::query_scalar("SELECT password_hash FROM users WHERE email = $1 AND tenant_id = 1")
                .bind(&new_email)
                .fetch_one(&pool)
                .await
                .unwrap()
        } else {
            sqlx::query_scalar("SELECT pending_password_hash FROM oauth_codes WHERE pending_email = $1 AND tenant_id = 1")
                .bind(&new_email).fetch_one(&pool).await.unwrap()
        };
        assert!(bcrypt::verify(new_password, &hash).unwrap());
        assert!(!bcrypt::verify(new_password.trim(), &hash).unwrap());
        sqlx::query("DELETE FROM oauth_codes WHERE pending_email = $1 AND tenant_id = 1")
            .bind(&new_email)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM personal_keys WHERE user_pubkey IN (SELECT pubkey FROM users WHERE email = $1 AND tenant_id = 1)")
            .bind(&new_email).execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM users WHERE email = $1 AND tenant_id = 1")
            .bind(&new_email)
            .execute(&pool)
            .await
            .unwrap();
    }
    let response = claim::claim_post(
        tenant(),
        State(state.clone()),
        Extension(delivery),
        HeaderMap::new(),
        Form(claim::ClaimForm {
            token: claim_token.clone(),
            email: format!("claim-{}@example.com", Uuid::new_v4()),
            password: new_password.into(),
            password_confirmation: new_password.into(),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let pending_hash: String = sqlx::query_scalar(
        "SELECT pending_password_hash FROM account_claim_tokens WHERE token = $1",
    )
    .bind(keycast_core::token_hash::hash_token(&claim_token))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(bcrypt::verify(new_password, &pending_hash).unwrap());

    let response = auth::change_password(
        tenant(),
        State(pool.clone()),
        Extension(state.state.bcrypt.clone()),
        headers,
        Json(auth::ChangePasswordRequest {
            current_password: "1234".into(),
            new_password: new_password.into(),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(bcrypt::verify(new_password, &stored_hash(&pool, &pubkey).await).unwrap());
    let reset_password = "eight uncommon words work too";
    let response = auth::reset_password(
        tenant(),
        State(state),
        HeaderMap::new(),
        Json(auth::ResetPasswordRequest {
            token: reset_token,
            new_password: reset_password.into(),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let final_hash = stored_hash(&pool, &pubkey).await;
    assert!(bcrypt::verify(reset_password, &final_hash).unwrap());
    assert!(!bcrypt::verify("1234", &final_hash).unwrap());

    sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM oauth_codes WHERE user_pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM auth_events WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
}
