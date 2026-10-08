#![cfg(feature = "integration-tests")]
// ABOUTME: Tests when /api/oauth/authorize approves a returning app without the
// ABOUTME: consent screen: only for the same app asking for the same policy.

mod common;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::oauth::{authorize_get, AuthorizeRequest};
use keycast_core::repositories::{CreateOAuthAuthorizationParams, OAuthAuthorizationRepository};
use nostr_sdk::Keys;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

const APP: &str = "https://app.example";
const OTHER_APP: &str = "https://other-app.example";

struct SignedInUser {
    pubkey: String,
    cookie: String,
    handle: String,
    approval_id: Option<i32>,
}

// What a silent approval stored on the code it issued.
#[derive(Debug, PartialEq)]
struct IssuedCode {
    scope: String,
    previous_auth_id: Option<i32>,
}

#[derive(Debug, PartialEq)]
enum Page {
    ApprovedSilently,
    Consent,
    AccountChooser,
    Other(String),
}

async fn policy_id(pool: &PgPool, slug: &str) -> i32 {
    sqlx::query_scalar("SELECT id FROM policies WHERE slug = $1 AND team_id IS NULL")
        .bind(slug)
        .fetch_one(pool)
        .await
        .expect("seeded policy")
}

async fn add_authorization(pool: &PgPool, pubkey: &str, policy: Option<&str>) -> (i32, String) {
    let policy_id = match policy {
        Some(slug) => Some(policy_id(pool, slug).await),
        None => None,
    };
    let handle = format!("handle-{}", Uuid::new_v4());
    let id = OAuthAuthorizationRepository::new(pool.clone())
        .create(CreateOAuthAuthorizationParams {
            tenant_id: 1,
            user_pubkey: pubkey.to_string(),
            redirect_origin: APP.to_string(),
            client_id: "test-app".to_string(),
            bunker_public_key: Keys::generate().public_key().to_hex(),
            secret_hash: "unused".to_string(),
            relays: "[]".to_string(),
            policy_id,
            is_first_party: false,
            client_pubkey: None,
            authorization_handle: Some(handle.clone()),
            handle_expires_at: Utc::now() + Duration::days(30),
        })
        .await
        .expect("authorization created");
    (id, handle)
}

// A signed-in person who hasn't approved any app yet.
async fn signed_in_user(pool: &PgPool, server_keys: &Keys) -> SignedInUser {
    let user = Keys::generate();
    let pubkey = user.public_key().to_hex();
    let email = format!("reconsent-{}@example.com", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&email)
    .execute(pool)
    .await
    .expect("user inserted");

    let session = generate_server_signed_ucan(
        &user.public_key(),
        1,
        &email,
        "https://login.divine.video",
        None,
        server_keys,
        true,
        None,
        None,
    )
    .await
    .expect("session signed");

    SignedInUser {
        pubkey,
        cookie: format!("keycast_session={session}"),
        handle: String::new(),
        approval_id: None,
    }
}

// A signed-in person who earlier approved `APP` with the given policy.
async fn returning_user(pool: &PgPool, server_keys: &Keys, policy: Option<&str>) -> SignedInUser {
    let mut user = signed_in_user(pool, server_keys).await;
    let (id, handle) = add_authorization(pool, &user.pubkey, policy).await;
    user.approval_id = Some(id);
    user.handle = handle;
    user
}

async fn page_for(
    pool: &PgPool,
    user: &SignedInUser,
    origin: &str,
    scope: Option<&str>,
    with_handle: bool,
    prompt: Option<&str>,
) -> Page {
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, HeaderValue::from_str(&user.cookie).unwrap());
    let request: AuthorizeRequest = serde_json::from_value(serde_json::json!({
        "client_id": "test-app",
        "redirect_uri": format!("{origin}/callback"),
        "scope": scope,
        "authorization_handle": with_handle.then(|| user.handle.clone()),
        "prompt": prompt,
    }))
    .unwrap();
    let response = authorize_get(
        common::test_tenant(),
        State(auth_state),
        headers,
        Query(request),
    )
    .await
    .unwrap_or_else(|e| panic!("authorize failed: {e:?}"));
    page(response).await
}

async fn page(response: Response) -> Page {
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .map(str::to_string);
    if response.status().is_redirection() {
        return match location {
            Some(l) if l.contains("code=") => Page::ApprovedSilently,
            other => Page::Other(format!("redirect to {other:?}")),
        };
    }
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body);
    if status != StatusCode::OK {
        return Page::Other(format!("status {status}"));
    }
    if html.contains("<title>Choose Account</title>") {
        Page::AccountChooser
    } else if html.contains(r#"<button class="btn_approve""#) {
        Page::Consent
    } else {
        Page::Other(html.chars().take(200).collect())
    }
}

// Removes and returns the one code issued to this person since the last call.
async fn take_issued_code(pool: &PgPool, user: &SignedInUser) -> IssuedCode {
    let mut codes: Vec<(String, Option<i32>)> = sqlx::query_as(
        "DELETE FROM oauth_codes WHERE user_pubkey = $1 RETURNING scope, previous_auth_id",
    )
    .bind(&user.pubkey)
    .fetch_all(pool)
    .await
    .expect("codes read");
    assert_eq!(codes.len(), 1, "expected exactly one issued code");
    let (scope, previous_auth_id) = codes.remove(0);
    IssuedCode {
        scope,
        previous_auth_id,
    }
}

async fn setup() -> (PgPool, Keys) {
    let server_keys = common::configure_atproto_env();
    let pool = common::setup_test_db().await;
    (pool, server_keys)
}

#[tokio::test]
#[serial]
async fn same_app_same_policy_is_approved_without_consent() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    for with_handle in [true, false] {
        let page = page_for(&pool, &user, APP, Some("policy:social"), with_handle, None).await;
        assert_eq!(page, Page::ApprovedSilently, "with_handle={with_handle}");
        // Only a sign-in through the handle replaces the authorization it names.
        assert_eq!(
            take_issued_code(&pool, &user).await,
            IssuedCode {
                scope: "policy:social".to_string(),
                previous_auth_id: if with_handle { user.approval_id } else { None },
            },
            "with_handle={with_handle}"
        );
    }
}

#[tokio::test]
#[serial]
async fn asking_the_same_app_for_a_different_policy_shows_consent() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    for with_handle in [true, false] {
        let page = page_for(&pool, &user, APP, Some("policy:full"), with_handle, None).await;
        assert_eq!(page, Page::Consent, "with_handle={with_handle}");
    }
}

// A handle that names no approval still lets the app's approval count, but
// that sign-in replaces nothing.
#[tokio::test]
#[serial]
async fn an_unknown_handle_replaces_no_approval() {
    let (pool, keys) = setup().await;
    let mut user = returning_user(&pool, &keys, Some("social")).await;
    user.handle = format!("handle-{}", Uuid::new_v4());
    let page = page_for(&pool, &user, APP, Some("policy:social"), true, None).await;
    assert_eq!(page, Page::ApprovedSilently);
    assert_eq!(
        take_issued_code(&pool, &user).await,
        IssuedCode {
            scope: "policy:social".to_string(),
            previous_auth_id: None,
        }
    );
}

// The handle was issued to APP, and nothing was approved for OTHER_APP, so it is
// treated as a first sign-in there.
#[tokio::test]
#[serial]
async fn another_app_presenting_the_handle_is_treated_as_new() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    let page = page_for(&pool, &user, OTHER_APP, Some("policy:social"), true, None).await;
    assert_eq!(page, Page::AccountChooser);
}

#[tokio::test]
#[serial]
async fn a_request_without_a_policy_shows_consent() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    let page = page_for(&pool, &user, APP, None, true, None).await;
    assert_eq!(page, Page::Consent);
}

// An authorization without a policy allows any kind. It never counts as an
// earlier approval of a named policy, nor of a request that names none.
#[tokio::test]
#[serial]
async fn an_authorization_without_a_policy_never_skips_consent() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, None).await;
    for scope in [Some("policy:full"), None] {
        for with_handle in [true, false] {
            let page = page_for(&pool, &user, APP, scope, with_handle, None).await;
            assert_eq!(
                page,
                Page::Consent,
                "scope={scope:?} with_handle={with_handle}"
            );
        }
    }
}

// Approvals from two devices can carry different policies; either one covers a
// request for its own policy. A handle whose authorization has another policy
// doesn't block that, and its authorization is left in place.
#[tokio::test]
#[serial]
async fn any_active_approval_for_the_app_with_that_policy_counts() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("full")).await;
    add_authorization(&pool, &user.pubkey, Some("social")).await;
    for (scope, with_handle) in [("policy:full", false), ("policy:social", true)] {
        let page = page_for(&pool, &user, APP, Some(scope), with_handle, None).await;
        assert_eq!(
            page,
            Page::ApprovedSilently,
            "scope={scope} with_handle={with_handle}"
        );
        assert_eq!(
            take_issued_code(&pool, &user).await,
            IssuedCode {
                scope: scope.to_string(),
                previous_auth_id: None,
            },
            "scope={scope} with_handle={with_handle}"
        );
    }
}

// prompt=consent asks the person again even when the request matches.
#[tokio::test]
#[serial]
async fn asking_for_consent_always_shows_it() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    for with_handle in [true, false] {
        let page = page_for(
            &pool,
            &user,
            APP,
            Some("policy:social"),
            with_handle,
            Some("consent"),
        )
        .await;
        assert_eq!(page, Page::Consent, "with_handle={with_handle}");
    }
}

// An approval that no longer covers this person and app doesn't count: they
// sign in as if for the first time.
async fn no_longer_counts(pool: &PgPool, user: &SignedInUser, change: &str) {
    for with_handle in [true, false] {
        let page = page_for(pool, user, APP, Some("policy:social"), with_handle, None).await;
        assert_eq!(
            page,
            Page::AccountChooser,
            "{change}, with_handle={with_handle}"
        );
    }
}

#[tokio::test]
#[serial]
async fn a_revoked_approval_does_not_skip_sign_in() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE user_pubkey = $1")
        .bind(&user.pubkey)
        .execute(&pool)
        .await
        .expect("authorization revoked");
    no_longer_counts(&pool, &user, "revoked").await;
}

#[tokio::test]
#[serial]
async fn an_expired_approval_does_not_skip_sign_in() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    sqlx::query(
        "UPDATE oauth_authorizations SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_pubkey = $1",
    )
    .bind(&user.pubkey)
    .execute(&pool)
    .await
    .expect("authorization expired");
    no_longer_counts(&pool, &user, "expired").await;
}

#[tokio::test]
#[serial]
async fn an_approval_in_another_tenant_does_not_skip_sign_in() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    let domain = format!("reconsent-{}.example", Uuid::new_v4());
    let other_tenant: i64 =
        sqlx::query_scalar("INSERT INTO tenants (domain, name) VALUES ($1, $1) RETURNING id")
            .bind(&domain)
            .fetch_one(&pool)
            .await
            .expect("tenant created");
    sqlx::query("UPDATE oauth_authorizations SET tenant_id = $1 WHERE user_pubkey = $2")
        .bind(other_tenant)
        .bind(&user.pubkey)
        .execute(&pool)
        .await
        .expect("authorization moved");
    no_longer_counts(&pool, &user, "other tenant").await;
}

#[tokio::test]
#[serial]
async fn an_approval_whose_handle_expired_does_not_skip_sign_in() {
    let (pool, keys) = setup().await;
    let user = returning_user(&pool, &keys, Some("social")).await;
    sqlx::query(
        "UPDATE oauth_authorizations SET handle_expires_at = NOW() - INTERVAL '1 minute' WHERE user_pubkey = $1",
    )
    .bind(&user.pubkey)
    .execute(&pool)
    .await
    .expect("handle expired");
    no_longer_counts(&pool, &user, "handle expired").await;
}

// Another person's approval of the app, or their remembered handle, doesn't
// sign someone in.
#[tokio::test]
#[serial]
async fn another_persons_approval_does_not_skip_sign_in() {
    let (pool, keys) = setup().await;
    let owner = returning_user(&pool, &keys, Some("social")).await;
    let mut someone_else = signed_in_user(&pool, &keys).await;
    someone_else.handle = owner.handle.clone();
    no_longer_counts(&pool, &someone_else, "another person").await;
}
