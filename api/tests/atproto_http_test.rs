mod common;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use chrono::{Duration, Utc};
use keycast_api::api::http::atproto::{
    disable_user_atproto, disable_user_atproto_and_revoke_sessions,
    disable_user_atproto_with_trigger, enable_user_atproto, enable_user_atproto_with_trigger,
    get_user_atproto_status, reenable_user_atproto_with_trigger,
    resolve_username_with_fallback_enabled, set_user_atproto_crosspost,
    sync_user_atproto_state_by_pubkey, SetCrosspostContext, UsernameResolution,
};
use keycast_api::api::http::auth::AuthError;
use keycast_api::divine_names::{DivineNameError, PubkeyLookupResponse};
use keycast_core::repositories::{
    AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams, IssueAtprotoTokensParams,
    UserRepository,
};
use keycast_core::types::refresh_token::hash_refresh_token;
use nostr_sdk::Keys;
use reqwest::StatusCode;
use serial_test::serial;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use uuid::Uuid;

#[derive(Clone)]
struct NameLookupMock {
    pubkey: String,
    username: String,
}

#[derive(Clone)]
struct FlakyNameLookupMock {
    pubkey: String,
    username: String,
    calls: Arc<AtomicUsize>,
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

async fn mock_name_lookup(
    State(mock): State<NameLookupMock>,
    Path(pubkey): Path<String>,
) -> Json<serde_json::Value> {
    if pubkey == mock.pubkey {
        Json(serde_json::json!({
            "ok": true,
            "found": true,
            "name": mock.username,
            "canonical": mock.username,
            "pubkey": mock.pubkey,
        }))
    } else {
        Json(serde_json::json!({
            "ok": true,
            "found": false,
        }))
    }
}

async fn start_name_lookup_server(
    pubkey: String,
    username: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/username/by-pubkey/:pubkey", get(mock_name_lookup))
        .with_state(NameLookupMock { pubkey, username });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve divine name lookup app");
    });

    (format!("http://{}", address), handle)
}

async fn mock_name_lookup_failure() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": false,
        "found": false,
        "name": null,
        "canonical": null,
        "pubkey": null,
        "profile_url": null,
        "nip05": null,
        "error": "lookup failed",
    }))
}

async fn mock_name_lookup_failure_then_success(
    State(mock): State<FlakyNameLookupMock>,
    Path(pubkey): Path<String>,
) -> Json<serde_json::Value> {
    if mock.calls.fetch_add(1, Ordering::SeqCst) == 0 {
        return mock_name_lookup_failure().await;
    }

    if pubkey == mock.pubkey {
        Json(serde_json::json!({
            "ok": true,
            "found": true,
            "name": mock.username,
            "canonical": mock.username,
            "pubkey": mock.pubkey,
            "profile_url": null,
            "nip05": null,
            "error": null,
        }))
    } else {
        Json(serde_json::json!({
            "ok": true,
            "found": false,
            "name": null,
            "canonical": null,
            "pubkey": null,
            "profile_url": null,
            "nip05": null,
            "error": null,
        }))
    }
}

async fn start_name_lookup_failure_server() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/api/username/by-pubkey/:pubkey",
        get(mock_name_lookup_failure),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve failing Divine name lookup app");
    });

    (format!("http://{}", address), handle)
}

async fn start_name_lookup_failure_then_success_server(
    pubkey: String,
    username: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/api/username/by-pubkey/:pubkey",
            get(mock_name_lookup_failure_then_success),
        )
        .with_state(FlakyNameLookupMock {
            pubkey,
            username,
            calls: Arc::new(AtomicUsize::new(0)),
        });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve flaky Divine name lookup app");
    });

    (format!("http://{}", address), handle)
}

fn lookup_response(pubkey: &str, username: &str) -> PubkeyLookupResponse {
    PubkeyLookupResponse {
        ok: true,
        found: true,
        name: Some(username.to_string()),
        canonical: Some(username.to_string()),
        pubkey: Some(pubkey.to_string()),
        profile_url: None,
        nip05: None,
        error: None,
    }
}

#[tokio::test]
async fn enable_sets_pending_and_returns_accepted() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-enable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = enable_user_atproto(&repo, tenant_id, &user_pubkey, &username)
        .await
        .expect("enable should succeed");

    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("pending"));
    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert_eq!(response.did, None);
    assert_eq!(response.error, None);
}

#[tokio::test]
async fn disable_marks_disabled() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:testalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = disable_user_atproto(&repo, tenant_id, &user_pubkey)
        .await
        .expect("disable should succeed");

    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));
    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert_eq!(response.did, None);
    assert_eq!(response.error, None);
}

#[tokio::test]
async fn status_returns_username_and_lifecycle_fields() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-status-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, atproto_error, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NULL, 'provisioning failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");

    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("failed"));
    assert_eq!(response.did, None);
    assert_eq!(response.error.as_deref(), Some("provisioning failed"));
}

#[tokio::test]
async fn username_resolver_keeps_local_username_without_lookup() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-local-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let lookup_calls = Arc::new(AtomicUsize::new(0));
    let seen = lookup_calls.clone();

    let resolved =
        resolve_username_with_fallback_enabled(&repo, tenant_id, &user_pubkey, true, move |_| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok::<Option<PubkeyLookupResponse>, DivineNameError>(None)
            }
        })
        .await
        .expect("resolver should succeed");

    assert_eq!(resolved, UsernameResolution::Resolved(username.clone()));
    assert_eq!(lookup_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn username_resolver_persists_app_claimed_name() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-resolved-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let lookup_username = username.clone();
    let resolved = resolve_username_with_fallback_enabled(
        &repo,
        tenant_id,
        &user_pubkey,
        true,
        |pubkey| async move { Ok(Some(lookup_response(&pubkey, &lookup_username))) },
    )
    .await
    .expect("resolver should succeed");

    assert_eq!(resolved, UsernameResolution::Resolved(username.clone()));
    let persisted = repo
        .get_username(&user_pubkey, tenant_id)
        .await
        .expect("username query should succeed")
        .expect("user should exist");
    assert_eq!(persisted.as_deref(), Some(username.as_str()));
}

#[tokio::test]
async fn username_resolver_does_not_overwrite_concurrent_local_claim() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let user_pubkey = Keys::generate().public_key().to_hex();
    let remote_username = format!("alice-stale-{}", &user_pubkey[..8]);
    let concurrent_username = format!("alice-current-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let update_pool = pool.clone();
    let update_pubkey = user_pubkey.clone();
    let expected_current = concurrent_username.clone();
    let resolved = resolve_username_with_fallback_enabled(
        &repo,
        tenant_id,
        &user_pubkey,
        true,
        move |lookup_pubkey| async move {
            sqlx::query(
                "UPDATE users SET username = $1, updated_at = NOW()
                 WHERE pubkey = $2 AND tenant_id = $3",
            )
            .bind(&expected_current)
            .bind(&update_pubkey)
            .bind(tenant_id)
            .execute(&update_pool)
            .await
            .expect("concurrent username claim should succeed");

            Ok(Some(lookup_response(&lookup_pubkey, &remote_username)))
        },
    )
    .await
    .expect("resolver should preserve the concurrent claim");

    assert_eq!(
        resolved,
        UsernameResolution::Resolved(concurrent_username.clone())
    );
    let persisted = repo
        .get_username(&user_pubkey, tenant_id)
        .await
        .expect("username query should succeed")
        .expect("user should exist");
    assert_eq!(persisted.as_deref(), Some(concurrent_username.as_str()));
}

#[tokio::test]
async fn username_resolver_refuses_local_conflict() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let owner_pubkey = Keys::generate().public_key().to_hex();
    let conflicting_pubkey = Keys::generate().public_key().to_hex();
    let username = format!("alice-conflict-{}", &owner_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW()), ($4, $2, NULL, NOW(), NOW())",
    )
    .bind(&conflicting_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .bind(&owner_pubkey)
    .execute(&pool)
    .await
    .expect("failed to insert users");

    let lookup_username = username.clone();
    let resolved = resolve_username_with_fallback_enabled(
        &repo,
        tenant_id,
        &owner_pubkey,
        true,
        |pubkey| async move { Ok(Some(lookup_response(&pubkey, &lookup_username))) },
    )
    .await
    .expect("resolver should not fail on conflicts");

    assert_eq!(resolved, UsernameResolution::NotClaimed);
    let persisted = repo
        .get_username(&owner_pubkey, tenant_id)
        .await
        .expect("username query should succeed")
        .expect("user should exist");
    assert_eq!(persisted, None);
}

#[tokio::test]
async fn username_resolver_lookup_failure_returns_unavailable() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let resolved =
        resolve_username_with_fallback_enabled(&repo, tenant_id, &user_pubkey, true, |_| async {
            Err(DivineNameError::ResponseError("lookup failed".to_string()))
        })
        .await
        .expect("resolver should swallow lookup errors");

    assert_eq!(resolved, UsernameResolution::Unavailable);
}

#[tokio::test]
async fn username_resolver_missing_owner_returns_unavailable_without_persisting() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let user_pubkey = Keys::generate().public_key().to_hex();
    let username = format!("alice-unverified-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let lookup_username = username.clone();
    let resolved = resolve_username_with_fallback_enabled(
        &repo,
        tenant_id,
        &user_pubkey,
        true,
        |pubkey| async move {
            let mut response = lookup_response(&pubkey, &lookup_username);
            response.pubkey = None;
            Ok(Some(response))
        },
    )
    .await
    .expect("resolver should classify an unverifiable owner");

    assert_eq!(resolved, UsernameResolution::Unavailable);
    let persisted = repo
        .get_username(&user_pubkey, tenant_id)
        .await
        .expect("username query should succeed")
        .expect("user should exist");
    assert_eq!(persisted, None);
}

#[tokio::test]
#[serial]
async fn crosspost_enable_reconciles_app_claimed_username() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-app-claimed-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, false, NULL, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let (base_url, server_handle) =
        start_name_lookup_server(user_pubkey.clone(), username.clone()).await;
    let _divine_name_server = EnvGuard::set("DIVINE_NAME_SERVER_URL", &base_url);

    let expected_pubkey = user_pubkey.clone();
    let expected_username = username.clone();
    let response = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        move |pubkey, requested_username, crosspost_enabled| {
            let expected_pubkey = expected_pubkey.clone();
            let expected_username = expected_username.clone();
            async move {
                assert_eq!(pubkey, expected_pubkey);
                assert_eq!(requested_username, expected_username);
                assert!(crosspost_enabled);
                Ok(())
            }
        },
        |_pubkey| async { Ok(()) },
        |_pubkey| async { Ok(()) },
    )
    .await
    .expect("crosspost enable should succeed with app-claimed username");

    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("pending"));
    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    let persisted = repo
        .get_username(&user_pubkey, tenant_id)
        .await
        .expect("username query should succeed")
        .expect("user should exist");
    assert_eq!(persisted.as_deref(), Some(username.as_str()));

    server_handle.abort();
}

#[tokio::test]
async fn enable_dependency_failure_rolls_back_the_opt_in() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-enable-failed-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error = enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &username,
        |_pubkey, _username| async {
            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
    )
    .await
    .expect_err("enable should surface dependency failure");

    assert_eq!(
        error.to_string(),
        "ATProto enablement is temporarily unavailable. Please try again later."
    );

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    // The opt-in is written before the trigger runs, so a failed trigger must
    // take it back — otherwise the account reads as publishing with no repo
    // behind it, and switching it off needs the control plane that just failed.
    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("failed"));
    assert_eq!(response.did, None);
    assert_eq!(
        response.error.as_deref(),
        Some("ATProto enablement is temporarily unavailable. Please try again later."),
    );
}

#[tokio::test]
async fn enable_failure_keeps_the_did_so_disable_still_refuses() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-enable-provisioned-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:testprovisioned', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &username,
        |_pubkey, _username| async {
            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
    )
    .await
    .expect_err("enable should surface dependency failure");

    // The rollback must not blank the DID of an account the control plane has
    // already provisioned: that column is the only local record that a live
    // repo exists.
    let status = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(!status.enabled);
    assert_eq!(status.state.as_deref(), Some("failed"));
    assert_eq!(status.did.as_deref(), Some("did:plc:testprovisioned"));

    // And with the DID intact, turning it off still refuses to report "off"
    // while the control plane cannot confirm it.
    disable_user_atproto_with_trigger(
        &repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        |_pubkey| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured,
            )
        },
    )
    .await
    .expect_err("disable should refuse while a provisioned repo exists");
}

#[tokio::test]
async fn reenable_dependency_failure_rolls_back_the_opt_in() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-reenable-failed-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, false, 'disabled', 'did:plc:testreenable', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error = reenable_user_atproto_with_trigger(&repo, tenant_id, &user_pubkey, |_pubkey| async {
        Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
    })
    .await
    .expect_err("reenable should surface dependency failure");

    assert_eq!(
        error.to_string(),
        "ATProto enablement is temporarily unavailable. Please try again later."
    );

    let status = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(!status.enabled);
    assert_eq!(status.state.as_deref(), Some("failed"));
    assert_eq!(status.did.as_deref(), Some("did:plc:testreenable"));
    assert_eq!(
        status.error.as_deref(),
        Some("ATProto enablement is temporarily unavailable. Please try again later."),
    );
}

#[tokio::test]
async fn disable_trigger_failure_clears_a_stuck_unprovisioned_opt_in() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-stuck-{}", &user_pubkey[..8]);

    // The shape a failed enable left behind before the rollback above shipped.
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = disable_user_atproto_with_trigger(
        &repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        |_pubkey| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured,
            )
        },
    )
    .await
    .expect("disable should succeed without a provisioned account");

    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));

    let status = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(!status.enabled);
    assert_eq!(status.state.as_deref(), Some("disabled"));
}

/// The escape hatch must not act on a DID it read before calling the control
/// plane. Provisioning can attach one while that call is in flight, and the
/// account would then be reported off while a live repo can still publish.
///
/// The trigger closure performs the interleaving: it attaches a DID, as the
/// internal sync endpoint would, and only then reports the failure.
#[tokio::test]
async fn disable_refuses_when_a_did_lands_during_the_trigger() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-did-lands-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let trigger_pool = pool.clone();
    let trigger_pubkey = user_pubkey.clone();

    disable_user_atproto_with_trigger(
        &repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        move |_pubkey| async move {
            sqlx::query("UPDATE users SET atproto_did = $1 WHERE pubkey = $2")
                .bind("did:plc:landedmidflight")
                .bind(&trigger_pubkey)
                .execute(&trigger_pool)
                .await
                .expect("failed to simulate provisioning sync");

            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
    )
    .await
    .expect_err("disable must fail closed once the account is provisioned");

    // The account keeps its DID and is not reported as switched off.
    let status = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert_eq!(status.did.as_deref(), Some("did:plc:landedmidflight"));
    assert_ne!(status.state.as_deref(), Some("disabled"));
}

/// A rollback must not clobber provisioning that reported back while the
/// trigger call was still in flight. The opt-in is only taken back while the
/// row still holds the `pending` state the same request wrote.
#[tokio::test]
async fn enable_rollback_yields_to_a_sync_that_lands_during_the_trigger() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-sync-wins-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let trigger_pool = pool.clone();
    let trigger_pubkey = user_pubkey.clone();

    enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &username,
        move |_pubkey, _username| async move {
            sync_user_atproto_state_by_pubkey(
                &UserRepository::new(trigger_pool),
                &trigger_pubkey,
                true,
                Some("ready"),
                Some("did:plc:syncwins"),
                None,
            )
            .await
            .expect("internal sync should succeed");

            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
    )
    .await
    .expect_err("enable should still surface the dependency failure");

    // Provisioning won: the account stays ready instead of being rolled back.
    let status = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(status.enabled);
    assert_eq!(status.state.as_deref(), Some("ready"));
    assert_eq!(status.did.as_deref(), Some("did:plc:syncwins"));
}

/// Session revocation is required on every path that reports an account as
/// switched off, including the local release taken when the control plane is
/// unreachable. The other escape-hatch tests create no OAuth session, so none
/// of them would notice if that revocation were dropped from this branch.
#[tokio::test]
async fn disable_escape_hatch_revokes_atproto_oauth_refresh_sessions() {
    let pool = common::setup_test_db().await;
    let user_repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-hatch-revoke-{}", &user_pubkey[..8]);
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());
    let refresh_token_hash =
        hash_refresh_token(&format!("refresh-token-hatch-revoke-{}", Uuid::new_v4()));

    // Stuck and unprovisioned: the shape the escape hatch exists to release.
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    session_repo
        .create_par(CreateAtprotoOAuthSessionParams {
            tenant_id,
            client_id: "https://client.example".to_string(),
            redirect_uri: "https://client.example/callback".to_string(),
            scope: "atproto".to_string(),
            state: Some("csrf-state".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            request_uri: request_uri.clone(),
            par_expires_at: Utc::now() + Duration::minutes(10),
            dpop_jkt: Some("dpop-jkt".to_string()),
            dpop_nonce: Some("dpop-nonce".to_string()),
            client_auth_method: "none".to_string(),
            client_auth_alg: None,
            client_auth_kid: None,
            client_auth_jkt: None,
        })
        .await
        .expect("failed to create PAR session");

    session_repo
        .approve_request(&request_uri, &user_pubkey, "did:plc:testhatch")
        .await
        .expect("failed to approve PAR session");

    session_repo
        .store_token_artifacts(
            &request_uri,
            IssueAtprotoTokensParams {
                authorization_code: format!("auth-code-{}", Uuid::new_v4()),
                authorization_code_expires_at: Utc::now() + Duration::minutes(5),
                access_token_jti: format!("access-jti-{}", Uuid::new_v4()),
                access_token_expires_at: Utc::now() + Duration::minutes(15),
                refresh_token_hash: refresh_token_hash.clone(),
                refresh_token_expires_at: Utc::now() + Duration::days(30),
                dpop_jkt: Some("dpop-jkt".to_string()),
                dpop_nonce: Some("dpop-nonce-2".to_string()),
            },
        )
        .await
        .expect("failed to issue ATProto OAuth session tokens");

    let response = disable_user_atproto_with_trigger(
        &user_repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        |_pubkey| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured,
            )
        },
    )
    .await
    .expect("escape hatch should release an unprovisioned account");

    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));

    let revoked_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT refresh_token_revoked_at FROM atproto_oauth_sessions WHERE request_uri = $1",
    )
    .bind(&request_uri)
    .fetch_one(&pool)
    .await
    .expect("failed to load refresh revocation marker");
    assert!(
        revoked_at.is_some(),
        "the local release must still revoke refresh sessions"
    );
}

/// A conditional write that applies to no rows is ambiguous on its own: the
/// account may have become ineligible, or it may be gone. Those map to
/// different errors, and an account deleted while the trigger was in flight
/// must still read as a missing user rather than a provisioning outage.
#[tokio::test]
async fn disable_reports_user_not_found_when_deleted_during_the_trigger() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-deleted-disable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let trigger_pool = pool.clone();
    let trigger_pubkey = user_pubkey.clone();

    let error = disable_user_atproto_with_trigger(
        &repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        move |_pubkey| async move {
            sqlx::query("DELETE FROM users WHERE pubkey = $1")
                .bind(&trigger_pubkey)
                .execute(&trigger_pool)
                .await
                .expect("failed to simulate account deletion");

            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
    )
    .await
    .expect_err("disable should fail once the account is gone");

    assert_eq!(error.to_string(), "user not found");
}

/// Same classification requirement on the rollback path.
#[tokio::test]
async fn enable_rollback_reports_user_not_found_when_deleted_during_the_trigger() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-deleted-enable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let trigger_pool = pool.clone();
    let trigger_pubkey = user_pubkey.clone();

    let error = enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &username,
        move |_pubkey, _username| async move {
            sqlx::query("DELETE FROM users WHERE pubkey = $1")
                .bind(&trigger_pubkey)
                .execute(&trigger_pool)
                .await
                .expect("failed to simulate account deletion");

            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
    )
    .await
    .expect_err("enable should fail once the account is gone");

    assert_eq!(error.to_string(), "user not found");
}

#[tokio::test]
async fn disable_trigger_failure_preserves_existing_state() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-failed-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:testalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error = disable_user_atproto_with_trigger(
        &repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
        |_pubkey| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::UnexpectedStatus {
                    status: StatusCode::BAD_GATEWAY,
                    body: "disable failed".to_string(),
                },
            )
        },
    )
    .await
    .expect_err("disable should surface trigger failure");

    assert_eq!(
        error.to_string(),
        "ATProto enablement is temporarily unavailable. Please try again later."
    );

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("ready"));
    assert_eq!(response.did.as_deref(), Some("did:plc:testalice"));
}

#[tokio::test]
async fn internal_sync_updates_lifecycle_state_by_pubkey() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-sync-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'pending', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = sync_user_atproto_state_by_pubkey(
        &repo,
        &user_pubkey,
        true,
        Some("ready"),
        Some("did:plc:testalice"),
        None,
    )
    .await
    .expect("sync should succeed");

    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("ready"));
    assert_eq!(response.did.as_deref(), Some("did:plc:testalice"));
    assert_eq!(response.error, None);
}

#[tokio::test]
async fn disable_path_revokes_atproto_oauth_refresh_sessions() {
    let pool = common::setup_test_db().await;
    let user_repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-revoke-{}", &user_pubkey[..8]);
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());
    let refresh_token_hash =
        hash_refresh_token(&format!("refresh-token-disable-revoke-{}", Uuid::new_v4()));

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:testalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    session_repo
        .create_par(CreateAtprotoOAuthSessionParams {
            tenant_id,
            client_id: "https://client.example".to_string(),
            redirect_uri: "https://client.example/callback".to_string(),
            scope: "atproto".to_string(),
            state: Some("csrf-state".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            request_uri: request_uri.clone(),
            par_expires_at: Utc::now() + Duration::minutes(10),
            dpop_jkt: Some("dpop-jkt".to_string()),
            dpop_nonce: Some("dpop-nonce".to_string()),
            client_auth_method: "none".to_string(),
            client_auth_alg: None,
            client_auth_kid: None,
            client_auth_jkt: None,
        })
        .await
        .expect("failed to create PAR session");

    session_repo
        .approve_request(&request_uri, &user_pubkey, "did:plc:testalice")
        .await
        .expect("failed to approve PAR session");

    session_repo
        .store_token_artifacts(
            &request_uri,
            IssueAtprotoTokensParams {
                authorization_code: format!("auth-code-{}", Uuid::new_v4()),
                authorization_code_expires_at: Utc::now() + Duration::minutes(5),
                access_token_jti: format!("access-jti-{}", Uuid::new_v4()),
                access_token_expires_at: Utc::now() + Duration::minutes(15),
                refresh_token_hash: refresh_token_hash.clone(),
                refresh_token_expires_at: Utc::now() + Duration::days(30),
                dpop_jkt: Some("dpop-jkt".to_string()),
                dpop_nonce: Some("dpop-nonce-2".to_string()),
            },
        )
        .await
        .expect("failed to issue ATProto OAuth session tokens");

    let response = disable_user_atproto_and_revoke_sessions(
        &user_repo,
        &session_repo,
        tenant_id,
        &user_pubkey,
    )
    .await
    .expect("disable path should succeed");
    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));

    let revoked_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT refresh_token_revoked_at FROM atproto_oauth_sessions WHERE request_uri = $1",
    )
    .bind(&request_uri)
    .fetch_one(&pool)
    .await
    .expect("failed to load refresh revocation marker");
    assert!(revoked_at.is_some());
}

#[tokio::test]
async fn crosspost_enable_uses_opt_in_trigger_for_initial_enable() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-crosspost-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, false, NULL, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let opt_in_calls = Arc::new(AtomicUsize::new(0));
    let reenable_calls = Arc::new(AtomicUsize::new(0));
    let disable_calls = Arc::new(AtomicUsize::new(0));

    let expected_pubkey = user_pubkey.clone();
    let expected_username = username.clone();
    let opt_in_seen = opt_in_calls.clone();
    let reenable_seen = reenable_calls.clone();
    let disable_seen = disable_calls.clone();

    let response = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        move |pubkey, requested_username, crosspost_enabled| {
            let opt_in_seen = opt_in_seen.clone();
            let expected_pubkey = expected_pubkey.clone();
            let expected_username = expected_username.clone();
            async move {
                opt_in_seen.fetch_add(1, Ordering::SeqCst);
                assert_eq!(pubkey, expected_pubkey);
                assert_eq!(requested_username, expected_username);
                assert!(crosspost_enabled);
                Ok(())
            }
        },
        move |_pubkey| {
            let reenable_seen = reenable_seen.clone();
            async move {
                reenable_seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
        move |_pubkey| {
            let disable_seen = disable_seen.clone();
            async move {
                disable_seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
    )
    .await
    .expect("crosspost enable should succeed");

    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("pending"));
    assert_eq!(opt_in_calls.load(Ordering::SeqCst), 1);
    assert_eq!(reenable_calls.load(Ordering::SeqCst), 0);
    assert_eq!(disable_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn crosspost_enable_dependency_failure_returns_service_unavailable() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-crosspost-unavailable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, false, NULL, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        |_pubkey, _requested_username, _crosspost_enabled| async {
            Err(keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured)
        },
        |_pubkey| async { Ok(()) },
        |_pubkey| async { Ok(()) },
    )
    .await
    .expect_err("dependency failure should become service unavailable");

    assert!(matches!(
        error,
        AuthError::ServiceUnavailable {
            message,
            retry_after: Some(30),
        } if message == "ATProto enablement is temporarily unavailable. Please try again later."
    ));
}

#[tokio::test]
#[serial]
async fn crosspost_enable_lookup_failure_returns_service_unavailable() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let user_pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, false, NULL, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let (base_url, server_handle) = start_name_lookup_failure_server().await;
    let _divine_name_server = EnvGuard::set("DIVINE_NAME_SERVER_URL", &base_url);

    let error = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        |_pubkey, _requested_username, _crosspost_enabled| async { Ok(()) },
        |_pubkey| async { Ok(()) },
        |_pubkey| async { Ok(()) },
    )
    .await
    .expect_err("lookup failure should become service unavailable");

    assert!(matches!(
        error,
        AuthError::ServiceUnavailable {
            retry_after: Some(30),
            ..
        }
    ));

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn crosspost_enable_lookup_failure_returns_service_unavailable_when_already_pending() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let user_pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, true, 'pending', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let (base_url, server_handle) = start_name_lookup_failure_server().await;
    let _divine_name_server = EnvGuard::set("DIVINE_NAME_SERVER_URL", &base_url);

    let error = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        |_pubkey, _requested_username, _crosspost_enabled| async { Ok(()) },
        |_pubkey| async { Ok(()) },
        |_pubkey| async { Ok(()) },
    )
    .await
    .expect_err("lookup failure should not be hidden by the pending state");

    assert!(matches!(
        error,
        AuthError::ServiceUnavailable {
            retry_after: Some(30),
            ..
        }
    ));

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn crosspost_enable_uses_first_unavailable_resolution_when_disabled() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let user_pubkey = Keys::generate().public_key().to_hex();
    let username = format!("alice-flaky-{}", &user_pubkey[..8]);
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, false, 'disabled', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let (base_url, server_handle) =
        start_name_lookup_failure_then_success_server(user_pubkey.clone(), username).await;
    let _divine_name_server = EnvGuard::set("DIVINE_NAME_SERVER_URL", &base_url);

    let error = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        |_pubkey, _requested_username, _crosspost_enabled| async { Ok(()) },
        |_pubkey| async { Ok(()) },
        |_pubkey| async { Ok(()) },
    )
    .await
    .expect_err("the first unavailable resolution should remain authoritative");

    assert!(matches!(
        error,
        AuthError::ServiceUnavailable {
            retry_after: Some(30),
            ..
        }
    ));

    server_handle.abort();
}

#[tokio::test]
async fn crosspost_enable_uses_reenable_trigger_when_current_state_is_disabled() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-reenable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, false, 'disabled', 'did:plc:disabledalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let opt_in_calls = Arc::new(AtomicUsize::new(0));
    let reenable_calls = Arc::new(AtomicUsize::new(0));
    let disable_calls = Arc::new(AtomicUsize::new(0));

    let expected_pubkey = user_pubkey.clone();
    let opt_in_seen = opt_in_calls.clone();
    let reenable_seen = reenable_calls.clone();
    let disable_seen = disable_calls.clone();

    let response = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: true,
        },
        move |_pubkey, _requested_username, _crosspost_enabled| {
            let opt_in_seen = opt_in_seen.clone();
            async move {
                opt_in_seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
        move |pubkey| {
            let reenable_seen = reenable_seen.clone();
            let expected_pubkey = expected_pubkey.clone();
            async move {
                reenable_seen.fetch_add(1, Ordering::SeqCst);
                assert_eq!(pubkey, expected_pubkey);
                Ok(())
            }
        },
        move |_pubkey| {
            let disable_seen = disable_seen.clone();
            async move {
                disable_seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
    )
    .await
    .expect("crosspost re-enable should succeed");

    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("pending"));
    assert_eq!(opt_in_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reenable_calls.load(Ordering::SeqCst), 1);
    assert_eq!(disable_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn crosspost_disable_uses_disable_trigger() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-crosspost-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:readyalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let opt_in_calls = Arc::new(AtomicUsize::new(0));
    let reenable_calls = Arc::new(AtomicUsize::new(0));
    let disable_calls = Arc::new(AtomicUsize::new(0));

    let expected_pubkey = user_pubkey.clone();
    let opt_in_seen = opt_in_calls.clone();
    let reenable_seen = reenable_calls.clone();
    let disable_seen = disable_calls.clone();

    let response = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: false,
        },
        move |_pubkey, _requested_username, _crosspost_enabled| {
            let opt_in_seen = opt_in_seen.clone();
            async move {
                opt_in_seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
        move |_pubkey| {
            let reenable_seen = reenable_seen.clone();
            async move {
                reenable_seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
        move |pubkey| {
            let disable_seen = disable_seen.clone();
            let expected_pubkey = expected_pubkey.clone();
            async move {
                disable_seen.fetch_add(1, Ordering::SeqCst);
                assert_eq!(pubkey, expected_pubkey);
                Ok(())
            }
        },
    )
    .await
    .expect("crosspost disable should succeed");

    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));
    assert_eq!(opt_in_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reenable_calls.load(Ordering::SeqCst), 0);
    assert_eq!(disable_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn crosspost_disable_releases_a_stuck_account_during_an_outage() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-stuck-crosspost-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &user_pubkey,
            enabled: false,
        },
        |_pubkey, _requested_username, _crosspost_enabled| async { Ok(()) },
        |_pubkey| async { Ok(()) },
        |_pubkey| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::DependencyNotConfigured,
            )
        },
    )
    .await
    .expect("crosspost disable should not need a reachable control plane here");

    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));
}

#[tokio::test]
async fn crosspost_toggle_rejects_pubkey_mismatch() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let session_repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let owner_keys = Keys::generate();
    let user_pubkey = owner_keys.public_key().to_hex();
    let other_pubkey = Keys::generate().public_key().to_hex();
    let username = format!("alice-mismatch-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error = set_user_atproto_crosspost(
        SetCrosspostContext {
            user_repo: &repo,
            session_repo: &session_repo,
            tenant_id,
            authenticated_user_pubkey: &user_pubkey,
            requested_pubkey: &other_pubkey,
            enabled: true,
        },
        |_pubkey, _requested_username, _crosspost_enabled| async { Ok(()) },
        |_pubkey| async { Ok(()) },
        |_pubkey| async { Ok(()) },
    )
    .await
    .expect_err("mismatched pubkey should be rejected");

    assert!(matches!(error, AuthError::Forbidden(_)));
}
