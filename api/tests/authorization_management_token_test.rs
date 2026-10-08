#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for which UCAN tokens may manage an account's authorizations
// ABOUTME: OAuth access tokens need first-party status; user-signed and non-OAuth sessions keep access

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use chrono::{Duration, Utc};
use keycast_api::api::http::{
    auth::{
        create_bunker, disconnect_client, generate_server_signed_ucan, list_permissions,
        list_sessions, revoke_session, CreateBunkerRequest, DisconnectClientRequest,
        RevokeSessionRequest,
    },
    oauth::{connect_post, ConnectApprovalForm},
    routes::AuthState,
};
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_core::repositories::{CreateOAuthAuthorizationParams, OAuthAuthorizationRepository};
use nostr_sdk::{Keys, ToBech32};
use sqlx::PgPool;
use std::sync::OnceLock;
use tokio::task::JoinHandle;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

mod common;

const TENANT_ID: i64 = 1;

/// One server key for the whole test binary, so parallel tests never race on SERVER_NSEC.
fn server_keys() -> &'static Keys {
    static SERVER_KEYS: OnceLock<Keys> = OnceLock::new();
    SERVER_KEYS.get_or_init(|| {
        let keys = Keys::generate();
        std::env::set_var(
            "SERVER_NSEC",
            keys.secret_key().to_bech32().expect("server nsec"),
        );
        keys
    })
}

struct Account {
    keys: Keys,
    pubkey: String,
    email: String,
    /// Bunker pubkey of an existing third-party authorization with a restricted policy.
    app_bunker_pubkey: String,
}

struct Harness {
    pool: PgPool,
    auth_state: AuthState,
    _secret_producer: JoinHandle<()>,
}

impl Harness {
    async fn new() -> Self {
        server_keys();
        let pool = common::setup_oauth_test_db().await;
        let (auth_state, secret_producer) = common::create_test_auth_state(pool.clone());
        Self {
            pool,
            auth_state,
            _secret_producer: secret_producer,
        }
    }

    async fn seed_account(&self) -> Account {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let email = format!("auth-mgmt-{}@example.test", Uuid::new_v4());

        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, true, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(TENANT_ID)
        .bind(&email)
        .execute(&self.pool)
        .await
        .expect("create user");

        // TestKeyManager is the identity transform, so the stored ciphertext is the raw secret.
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
             VALUES ($1, $2, $3)",
        )
        .bind(&pubkey)
        .bind(keys.secret_key().secret_bytes().to_vec())
        .bind(TENANT_ID)
        .execute(&self.pool)
        .await
        .expect("create personal key");

        let readonly_policy_id: i32 =
            sqlx::query_scalar("SELECT id FROM policies WHERE slug = 'readonly'")
                .fetch_one(&self.pool)
                .await
                .expect("readonly policy exists");

        let secret_hash = format!("connection-secret-{}", Uuid::new_v4());
        let app_bunker_pubkey =
            keycast_core::bunker_key::derive_bunker_keys(keys.secret_key(), &secret_hash)
                .public_key()
                .to_hex();

        OAuthAuthorizationRepository::new(self.pool.clone())
            .create(CreateOAuthAuthorizationParams {
                tenant_id: TENANT_ID,
                user_pubkey: pubkey.clone(),
                redirect_origin: "https://app.example.test".to_string(),
                client_id: "Example App".to_string(),
                bunker_public_key: app_bunker_pubkey.clone(),
                secret_hash,
                relays: "[]".to_string(),
                policy_id: Some(readonly_policy_id),
                is_first_party: false,
                client_pubkey: None,
                authorization_handle: None,
                handle_expires_at: Utc::now() + Duration::days(30),
            })
            .await
            .expect("create app authorization");

        Account {
            keys,
            pubkey,
            email,
            app_bunker_pubkey,
        }
    }

    async fn active_authorizations(&self, account: &Account) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_authorizations
             WHERE user_pubkey = $1 AND tenant_id = $2 AND revoked_at IS NULL",
        )
        .bind(&account.pubkey)
        .bind(TENANT_ID)
        .fetch_one(&self.pool)
        .await
        .expect("count authorizations")
    }

    async fn cleanup(&self, account: &Account) {
        for statement in [
            "DELETE FROM oauth_authorizations WHERE user_pubkey = $1",
            "DELETE FROM personal_keys WHERE user_pubkey = $1",
            "DELETE FROM users WHERE pubkey = $1",
        ] {
            let _ = sqlx::query(statement)
                .bind(&account.pubkey)
                .execute(&self.pool)
                .await;
        }
    }

    async fn create_bunker(&self, headers: HeaderMap) -> StatusCode {
        create_bunker(
            common::test_tenant(),
            State(self.auth_state.clone()),
            headers,
            Json(CreateBunkerRequest {
                app_name: "Manual".to_string(),
                origin: None,
                policy_slug: None,
            }),
        )
        .await
        .into_response()
        .status()
    }

    async fn connect(&self, headers: HeaderMap) -> StatusCode {
        connect_post(
            common::test_tenant(),
            State(self.auth_state.clone()),
            headers,
            Form(ConnectApprovalForm {
                client_pubkey: Keys::generate().public_key().to_hex(),
                relay: "wss://relay.test.example".to_string(),
                secret: "client-chosen-secret".to_string(),
                perms: None,
                approved: true,
            }),
        )
        .await
        .into_response()
        .status()
    }

    async fn list_sessions(&self, headers: HeaderMap) -> StatusCode {
        list_sessions(common::test_tenant(), State(self.pool.clone()), headers)
            .await
            .into_response()
            .status()
    }

    async fn list_permissions(&self, headers: HeaderMap) -> StatusCode {
        list_permissions(common::test_tenant(), State(self.pool.clone()), headers)
            .await
            .into_response()
            .status()
    }

    async fn revoke(&self, headers: HeaderMap, bunker_pubkey: &str) -> StatusCode {
        revoke_session(
            common::test_tenant(),
            State(self.auth_state.clone()),
            headers,
            Json(RevokeSessionRequest {
                bunker_pubkey: bunker_pubkey.to_string(),
            }),
        )
        .await
        .into_response()
        .status()
    }

    async fn disconnect(&self, headers: HeaderMap, bunker_pubkey: &str) -> StatusCode {
        disconnect_client(
            common::test_tenant(),
            State(self.pool.clone()),
            headers,
            Json(DisconnectClientRequest {
                bunker_pubkey: bunker_pubkey.to_string(),
            }),
        )
        .await
        .into_response()
        .status()
    }
}

/// An access token as `/oauth/token` mints it: server-signed with the authorization's bunker pubkey.
async fn oauth_access_token(account: &Account, is_first_party: bool) -> String {
    generate_server_signed_ucan(
        &account.keys.public_key(),
        TENANT_ID,
        &account.email,
        "https://app.example.test",
        Some(&account.app_bunker_pubkey),
        server_keys(),
        is_first_party,
        None,
        None,
    )
    .await
    .expect("mint access token")
}

/// A server-signed session without a bunker pubkey, as the account-claim flow mints it.
async fn claim_session_token(account: &Account) -> String {
    generate_server_signed_ucan(
        &account.keys.public_key(),
        TENANT_ID,
        &account.email,
        "claim",
        None,
        server_keys(),
        false,
        None,
        None,
    )
    .await
    .expect("mint claim session")
}

async fn user_signed_token(account: &Account, bunker_pubkey: Option<&str>) -> String {
    let mut facts = serde_json::json!({
        "tenant_id": TENANT_ID,
        "email": account.email,
        "redirect_origin": "https://login.example.test",
    });
    if let Some(bunker_pubkey) = bunker_pubkey {
        facts["bunker_pubkey"] = serde_json::json!(bunker_pubkey);
    }

    UcanBuilder::default()
        .issued_by(&NostrKeyMaterial::from_keys(account.keys.clone()))
        .for_audience(&nostr_pubkey_to_did(&account.keys.public_key()))
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("build session UCAN")
        .sign()
        .await
        .expect("sign session UCAN")
        .encode()
        .expect("encode session UCAN")
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token)).expect("header value"),
    );
    headers
}

fn session_cookie(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("keycast_session={}", token)).expect("header value"),
    );
    headers
}

#[tokio::test]
async fn third_party_access_token_cannot_manage_authorizations() {
    let harness = Harness::new().await;
    let account = harness.seed_account().await;
    let token = oauth_access_token(&account, false).await;
    let before = harness.active_authorizations(&account).await;

    assert_eq!(
        harness.create_bunker(bearer(&token)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        harness.connect(bearer(&token)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness.list_sessions(bearer(&token)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        harness.list_permissions(bearer(&token)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        harness
            .disconnect(bearer(&token), &account.app_bunker_pubkey)
            .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        harness
            .revoke(bearer(&token), &account.app_bunker_pubkey)
            .await,
        StatusCode::FORBIDDEN
    );

    assert_eq!(harness.active_authorizations(&account).await, before);

    harness.cleanup(&account).await;
}

#[tokio::test]
async fn first_party_access_token_can_manage_authorizations() {
    let harness = Harness::new().await;
    let account = harness.seed_account().await;
    let token = oauth_access_token(&account, true).await;
    let before = harness.active_authorizations(&account).await;

    assert_eq!(harness.list_sessions(bearer(&token)).await, StatusCode::OK);
    assert_eq!(
        harness.list_permissions(bearer(&token)).await,
        StatusCode::OK
    );
    assert_eq!(harness.create_bunker(bearer(&token)).await, StatusCode::OK);
    assert_eq!(harness.connect(bearer(&token)).await, StatusCode::OK);
    assert_eq!(harness.active_authorizations(&account).await, before + 2);

    assert_eq!(
        harness
            .disconnect(bearer(&token), &account.app_bunker_pubkey)
            .await,
        StatusCode::OK
    );
    assert_eq!(
        harness
            .revoke(bearer(&token), &account.app_bunker_pubkey)
            .await,
        StatusCode::OK
    );
    assert_eq!(harness.active_authorizations(&account).await, before + 1);

    harness.cleanup(&account).await;
}

#[tokio::test]
async fn user_signed_session_can_manage_authorizations() {
    let harness = Harness::new().await;
    let account = harness.seed_account().await;
    let token = user_signed_token(&account, None).await;
    let before = harness.active_authorizations(&account).await;

    assert_eq!(
        harness.list_sessions(session_cookie(&token)).await,
        StatusCode::OK
    );
    assert_eq!(
        harness.create_bunker(session_cookie(&token)).await,
        StatusCode::OK
    );
    assert_eq!(
        harness.connect(session_cookie(&token)).await,
        StatusCode::OK
    );
    assert_eq!(harness.active_authorizations(&account).await, before + 2);
    assert_eq!(
        harness
            .revoke(session_cookie(&token), &account.app_bunker_pubkey)
            .await,
        StatusCode::OK
    );
    assert_eq!(harness.active_authorizations(&account).await, before + 1);

    harness.cleanup(&account).await;
}

#[tokio::test]
async fn user_signed_token_with_bunker_fact_can_manage_authorizations() {
    let harness = Harness::new().await;
    let account = harness.seed_account().await;
    let token = user_signed_token(&account, Some(&account.app_bunker_pubkey)).await;

    assert_eq!(harness.list_sessions(bearer(&token)).await, StatusCode::OK);
    assert_eq!(harness.create_bunker(bearer(&token)).await, StatusCode::OK);

    harness.cleanup(&account).await;
}

#[tokio::test]
async fn server_signed_session_without_bunker_fact_can_manage_authorizations() {
    let harness = Harness::new().await;
    let account = harness.seed_account().await;
    let token = claim_session_token(&account).await;

    assert_eq!(
        harness.list_sessions(session_cookie(&token)).await,
        StatusCode::OK
    );
    assert_eq!(
        harness.create_bunker(session_cookie(&token)).await,
        StatusCode::OK
    );

    harness.cleanup(&account).await;
}
