mod common;

use chrono::{Duration, Utc};
use keycast_core::repositories::{
    AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams, IssueAtprotoTokensParams,
};
use keycast_core::types::refresh_token::hash_refresh_token;
use nostr_sdk::Keys;
use uuid::Uuid;

#[tokio::test]
async fn stores_and_revokes_atproto_oauth_sessions() {
    let pool = common::setup_test_db().await;
    let repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let did = "did:plc:testalice";
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, true, 'ready', $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(did)
    .execute(&pool)
    .await
    .unwrap();

    let created = repo
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
            dpop_jkt: None,
            dpop_nonce: None,
            client_auth_method: "none".to_string(),
            client_auth_alg: None,
            client_auth_kid: None,
            client_auth_jkt: None,
        })
        .await
        .unwrap();

    assert_eq!(created.request_uri, request_uri);
    assert_eq!(created.user_pubkey, None);
    assert_eq!(created.atproto_did, None);

    let approved = repo
        .approve_request(&request_uri, &user_pubkey, did)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(approved.user_pubkey.as_deref(), Some(user_pubkey.as_str()));
    assert_eq!(approved.atproto_did.as_deref(), Some(did));

    let authorization_code = format!("auth-code-{}", Uuid::new_v4());
    let first_code = format!("first-code-{}", Uuid::new_v4());
    repo.store_authorization_code(&request_uri, &first_code, Utc::now() + Duration::minutes(5))
        .await
        .unwrap()
        .unwrap();
    let stored = repo
        .store_authorization_code(
            &request_uri,
            &authorization_code,
            Utc::now() + Duration::minutes(5),
        )
        .await
        .unwrap()
        .unwrap();
    let code_hash = keycast_core::token_hash::hash_token(&authorization_code);
    assert_eq!(
        stored.authorization_code_hash.as_deref(),
        Some(code_hash.as_str())
    );
    assert!(repo
        .find_by_authorization_code(&first_code)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .find_by_authorization_code(&code_hash)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .consume_authorization_code(&code_hash)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .consume_authorization_code(&authorization_code)
        .await
        .unwrap()
        .is_some());
    assert!(repo
        .consume_authorization_code(&authorization_code)
        .await
        .unwrap()
        .is_none());
    let access_token_jti = format!("access-jti-{}", Uuid::new_v4());
    let refresh_token = format!("refresh-token-{}", Uuid::new_v4());
    let refresh_token_hash = hash_refresh_token(&refresh_token);

    let issued = repo
        .store_token_artifacts(
            &request_uri,
            IssueAtprotoTokensParams {
                access_token_jti,
                access_token_expires_at: Utc::now() + Duration::minutes(15),
                refresh_token_hash: refresh_token_hash.clone(),
                refresh_token_expires_at: Utc::now() + Duration::days(30),
                dpop_jkt: Some("dpop-thumbprint".to_string()),
                dpop_nonce: Some("nonce-1".to_string()),
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert!(
        issued.authorization_code_hash.is_none(),
        "token artifacts must not restore a consumed code"
    );

    assert_eq!(
        issued.refresh_token_hash.as_deref(),
        Some(refresh_token_hash.as_str())
    );
    assert_eq!(issued.dpop_jkt.as_deref(), Some("dpop-thumbprint"));

    let revoked = repo
        .revoke_refresh_session(&refresh_token_hash)
        .await
        .unwrap()
        .unwrap();

    assert!(revoked.refresh_token_revoked_at.is_some());
    assert!(revoked.revoked_at.is_some());
}

#[tokio::test]
async fn consumes_and_rotates_refresh_token_artifacts() {
    let pool = common::setup_test_db().await;
    let repo = AtprotoOAuthSessionRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let did = "did:plc:testrotate";
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, true, 'ready', $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(did)
    .execute(&pool)
    .await
    .unwrap();

    repo.create_par(CreateAtprotoOAuthSessionParams {
        tenant_id,
        client_id: "https://client.example".to_string(),
        redirect_uri: "https://client.example/callback".to_string(),
        scope: "atproto".to_string(),
        state: Some("csrf-state".to_string()),
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: request_uri.clone(),
        par_expires_at: Utc::now() + Duration::minutes(10),
        dpop_jkt: Some("bound-jkt".to_string()),
        dpop_nonce: Some("nonce-1".to_string()),
        client_auth_method: "none".to_string(),
        client_auth_alg: None,
        client_auth_kid: None,
        client_auth_jkt: None,
    })
    .await
    .unwrap();

    repo.approve_request(&request_uri, &user_pubkey, did)
        .await
        .unwrap();

    let refresh_token = format!("refresh-token-{}", Uuid::new_v4());
    let refresh_token_hash = hash_refresh_token(&refresh_token);
    let issued = repo
        .store_token_artifacts(
            &request_uri,
            IssueAtprotoTokensParams {
                access_token_jti: format!("access-jti-{}", Uuid::new_v4()),
                access_token_expires_at: Utc::now() + Duration::minutes(15),
                refresh_token_hash: refresh_token_hash.clone(),
                refresh_token_expires_at: Utc::now() + Duration::days(30),
                dpop_jkt: Some("bound-jkt".to_string()),
                dpop_nonce: Some("nonce-1".to_string()),
            },
        )
        .await
        .unwrap()
        .unwrap();

    let found = repo
        .find_by_refresh_token_hash(&refresh_token_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, issued.id);

    let next_refresh_hash = hash_refresh_token(&format!("refresh-token-{}", Uuid::new_v4()));
    let rotated = repo
        .rotate_refresh_token(
            &request_uri,
            &refresh_token_hash,
            IssueAtprotoTokensParams {
                access_token_jti: format!("access-jti-{}", Uuid::new_v4()),
                access_token_expires_at: Utc::now() + Duration::minutes(15),
                refresh_token_hash: next_refresh_hash.clone(),
                refresh_token_expires_at: Utc::now() + Duration::days(30),
                dpop_jkt: Some("bound-jkt".to_string()),
                dpop_nonce: Some("nonce-2".to_string()),
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        rotated.refresh_token_hash.as_deref(),
        Some(next_refresh_hash.as_str())
    );
    assert_eq!(rotated.dpop_jkt.as_deref(), Some("bound-jkt"));
    assert_eq!(rotated.dpop_nonce.as_deref(), Some("nonce-2"));

    let missing_old = repo
        .find_by_refresh_token_hash(&refresh_token_hash)
        .await
        .unwrap();
    assert!(missing_old.is_none());
}
