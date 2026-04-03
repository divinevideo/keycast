mod common;

use chrono::{Duration, Utc};
use keycast_api::api::http::atproto::{
    disable_user_atproto, disable_user_atproto_and_revoke_sessions,
    disable_user_atproto_with_trigger, enable_user_atproto, enable_user_atproto_with_trigger,
    get_user_atproto_status, set_user_atproto_crosspost, sync_user_atproto_state_by_pubkey,
    SetCrosspostContext,
};
use keycast_api::api::http::auth::AuthError;
use keycast_core::repositories::{
    AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams, IssueAtprotoTokensParams,
    UserRepository,
};
use keycast_core::types::refresh_token::hash_refresh_token;
use nostr_sdk::Keys;
use reqwest::StatusCode;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use uuid::Uuid;

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
async fn enable_trigger_failure_marks_failed_state() {
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
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::UnexpectedStatus {
                    status: StatusCode::BAD_GATEWAY,
                    body: "gateway unavailable".to_string(),
                },
            )
        },
    )
    .await
    .expect_err("enable should surface trigger failure");

    assert!(error.to_string().contains("gateway unavailable"));

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("failed"));
    assert_eq!(response.did, None);
    assert_eq!(
        response.error.as_deref(),
        Some("provisioning service returned 502 Bad Gateway: gateway unavailable"),
    );
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

    assert!(error.to_string().contains("disable failed"));

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
