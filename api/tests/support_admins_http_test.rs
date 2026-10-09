// ABOUTME: Handler tests for Postgres-backed support admins: grant management and NIP-98 login
// ABOUTME: A grant in support_admins is what lets a pubkey log in with admin_role "support"

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::api::{
    extractors::UcanAuth,
    http::{
        admin::{
            add_support_admin, get_admin_status, is_support_admin, list_support_admins,
            remove_support_admin, AddSupportAdminRequest,
        },
        auth::login,
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_core::repositories::SupportAdminRepository;
use nostr_sdk::{EventBuilder, JsonUtil, Keys, Kind, Tag, ToBech32};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const TENANT_ID: i64 = 1;

fn full_admin() -> UcanAuth {
    UcanAuth {
        pubkey: Keys::generate().public_key().to_hex(),
        admin_role: Some("full".to_string()),
    }
}

fn copy(auth: &UcanAuth) -> UcanAuth {
    UcanAuth {
        pubkey: auth.pubkey.clone(),
        admin_role: auth.admin_role.clone(),
    }
}

fn session_without_role(pubkey: &str) -> UcanAuth {
    UcanAuth {
        pubkey: pubkey.to_string(),
        admin_role: None,
    }
}

fn tenant_extractor(id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn auth_state(pool: PgPool) -> AuthState {
    let (state, _producer) = common::create_test_auth_state(pool);
    state
}

async fn cleanup(pool: &PgPool, pubkey: &str) {
    sqlx::query("DELETE FROM support_admins WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_tenant(pool: &PgPool) -> i64 {
    let domain = format!("support-admins-{}.example", Uuid::new_v4().simple());
    sqlx::query_scalar(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $1, NOW(), NOW())
         RETURNING id",
    )
    .bind(domain)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn delete_tenant(pool: &PgPool, tenant_id: i64) {
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await
        .unwrap();
}

fn ensure_server_nsec() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var("SERVER_NSEC").is_err() {
            let keys = Keys::generate();
            std::env::set_var("SERVER_NSEC", keys.secret_key().to_bech32().unwrap());
        }
    });
}

/// Headers for a NIP-98 admin login signed by `keys` against `https://localhost`.
fn nip98_login_headers(keys: &Keys) -> HeaderMap {
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags([
            Tag::parse(["u", "https://localhost/api/auth/login"]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap();
    let header = format!("Nostr {}", STANDARD.encode(event.as_json()));

    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("localhost"));
    headers.insert("origin", HeaderValue::from_static("https://localhost"));
    headers.insert("authorization", HeaderValue::from_str(&header).unwrap());
    headers
}

/// The decoded claims of the UCAN in a login response's session cookie.
async fn session_claims(response: axum::response::Response) -> String {
    let cookie = response
        .headers()
        .get("set-cookie")
        .expect("session cookie")
        .to_str()
        .unwrap()
        .to_string();
    let _ = response.into_body().collect().await.unwrap();
    let token = cookie
        .strip_prefix("keycast_session=")
        .and_then(|rest| rest.split(';').next())
        .expect("keycast_session cookie");
    let payload = token.split('.').nth(1).expect("UCAN payload");
    String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
async fn grants_are_listed_and_revoked_through_postgres() {
    let pool = common::setup_test_db().await;
    let state = auth_state(pool.clone()).await;
    let admin = full_admin();
    let grantee = Keys::generate().public_key().to_hex();

    let Json(added) = add_support_admin(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&admin),
        Json(AddSupportAdminRequest {
            identifier: grantee.to_ascii_uppercase(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(added.pubkey, grantee, "hex grants are stored lowercase");
    assert!(added.added);

    let Json(again) = add_support_admin(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&admin),
        Json(AddSupportAdminRequest {
            identifier: grantee.clone(),
        }),
    )
    .await
    .unwrap();
    assert!(!again.added);

    let Json(list) = list_support_admins(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&admin),
    )
    .await
    .unwrap();
    assert!(list.admins.iter().any(|entry| entry.pubkey == grantee));

    let added_by: Option<String> = sqlx::query_scalar(
        "SELECT added_by_pubkey FROM support_admins WHERE tenant_id = $1 AND pubkey = $2",
    )
    .bind(TENANT_ID)
    .bind(&grantee)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(added_by.as_deref(), Some(admin.pubkey.as_str()));

    let Json(removed) = remove_support_admin(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&admin),
        Path(grantee.clone()),
    )
    .await
    .unwrap();
    assert_eq!(removed["removed"], true);

    let Json(list) = list_support_admins(tenant_extractor(TENANT_ID), State(state), admin)
        .await
        .unwrap();
    assert!(!list.admins.iter().any(|entry| entry.pubkey == grantee));
}

#[tokio::test]
async fn support_admins_cannot_manage_grants() {
    let pool = common::setup_test_db().await;
    let state = auth_state(pool.clone()).await;
    let grantee = Keys::generate().public_key().to_hex();
    let support = UcanAuth {
        pubkey: Keys::generate().public_key().to_hex(),
        admin_role: Some("support".to_string()),
    };

    let err = add_support_admin(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&support),
        Json(AddSupportAdminRequest {
            identifier: grantee.clone(),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
    assert!(!SupportAdminRepository::new(pool.clone())
        .is_support_admin(TENANT_ID, &grantee)
        .await
        .unwrap());

    let err = list_support_admins(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&support),
    )
    .await
    .unwrap_err();
    assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);

    let err = remove_support_admin(
        tenant_extractor(TENANT_ID),
        State(state),
        support,
        Path(grantee),
    )
    .await
    .unwrap_err();
    assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn granted_pubkey_is_a_support_admin_only_in_its_tenant() {
    let pool = common::setup_test_db().await;
    let state = auth_state(pool.clone()).await;
    let other_tenant = insert_tenant(&pool).await;
    let grantee = Keys::generate().public_key().to_hex();
    let session = session_without_role(&grantee);

    assert!(!is_support_admin(&pool, TENANT_ID, &session).await.unwrap());

    SupportAdminRepository::new(pool.clone())
        .add(TENANT_ID, &grantee, &full_admin().pubkey)
        .await
        .unwrap();

    assert!(is_support_admin(&pool, TENANT_ID, &session).await.unwrap());
    assert!(!is_support_admin(&pool, other_tenant, &session)
        .await
        .unwrap());

    let Json(status) = get_admin_status(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        copy(&session),
    )
    .await
    .unwrap();
    assert_eq!(status.role.as_deref(), Some("support"));

    let Json(status) = get_admin_status(tenant_extractor(other_tenant), State(state), session)
        .await
        .unwrap();
    assert_eq!(status.role, None);

    cleanup(&pool, &grantee).await;
    delete_tenant(&pool, other_tenant).await;
}

#[tokio::test]
async fn support_gate_checks_grants_on_a_single_connection_pool() {
    let pool = common::setup_test_db().await;
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let state = auth_state(single.clone()).await;
    let grantee = Keys::generate().public_key().to_hex();
    SupportAdminRepository::new(pool.clone())
        .add(TENANT_ID, &grantee, &full_admin().pubkey)
        .await
        .unwrap();

    let session = session_without_role(&grantee);
    assert!(is_support_admin(&single, TENANT_ID, &session)
        .await
        .unwrap());
    let Json(status) = get_admin_status(tenant_extractor(TENANT_ID), State(state), session)
        .await
        .unwrap();
    assert_eq!(status.role.as_deref(), Some("support"));

    cleanup(&pool, &grantee).await;
}

#[tokio::test]
async fn nip98_login_derives_the_support_role_from_a_postgres_grant() {
    ensure_server_nsec();
    let pool = common::setup_test_db().await;
    let state = auth_state(pool.clone()).await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    let denied = login(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        nip98_login_headers(&keys),
        String::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.into_response().status(), StatusCode::FORBIDDEN);

    SupportAdminRepository::new(pool.clone())
        .add(TENANT_ID, &pubkey, &full_admin().pubkey)
        .await
        .unwrap();

    let response = login(
        tenant_extractor(TENANT_ID),
        State(state.clone()),
        nip98_login_headers(&keys),
        String::new(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let claims = session_claims(response).await;
    assert!(
        claims.contains(r#""admin_role":"support""#),
        "session carries the support role: {claims}"
    );

    SupportAdminRepository::new(pool.clone())
        .remove(TENANT_ID, &pubkey)
        .await
        .unwrap();
    let revoked = login(
        tenant_extractor(TENANT_ID),
        State(state),
        nip98_login_headers(&keys),
        String::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(revoked.into_response().status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn nip98_login_ignores_grants_from_another_tenant() {
    ensure_server_nsec();
    let pool = common::setup_test_db().await;
    let state = auth_state(pool.clone()).await;
    let other_tenant = insert_tenant(&pool).await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();

    SupportAdminRepository::new(pool.clone())
        .add(other_tenant, &pubkey, &full_admin().pubkey)
        .await
        .unwrap();

    let denied = login(
        tenant_extractor(TENANT_ID),
        State(state),
        nip98_login_headers(&keys),
        String::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.into_response().status(), StatusCode::FORBIDDEN);

    cleanup(&pool, &pubkey).await;
    delete_tenant(&pool, other_tenant).await;
}
