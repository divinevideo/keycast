#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http_body_util::BodyExt;
use keycast_api::api::http::atproto_oauth::{authorize, par, token};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::rand_core::OsRng,
};
use serde_json::Value;
use serial_test::serial;
use tower::ServiceExt;

fn http_uri(path: &str) -> String {
    format!("https://login.divine.video{path}")
}

fn dpop_proof(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }
    });
    let claims = serde_json::json!({
        "jti": format!("fail-closed-{}", uuid::Uuid::new_v4()),
        "htm": "POST",
        "htu": http_uri("/atproto/oauth/par"),
        "iat": chrono::Utc::now().timestamp(),
    });

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = signing_key.sign(signing_input.as_bytes());

    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

async fn app_with_failing_replay_store(pool: sqlx::PgPool) -> Router {
    common::install_global_test_state_with_failing_redis(pool.clone());
    Router::new()
        .route("/atproto/oauth/par", post(par))
        .route("/atproto/oauth/authorize", get(authorize))
        .route("/atproto/oauth/token", post(token))
        .with_state(pool)
}

/// When shared replay storage fails, protected ATProto OAuth endpoints must
/// fail closed with a retryable, non-sensitive OAuth error response instead
/// of accepting the request without replay protection.
#[tokio::test]
#[serial]
async fn replay_storage_outage_fails_closed_with_retryable_temporarily_unavailable() {
    common::configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app_with_failing_replay_store(pool).await;

    let signing_key = SigningKey::random(&mut OsRng);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("DPoP", dpop_proof(&signing_key))
                .body(Body::from(
                    "client_id=https%3A%2F%2Fclient.example&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=atproto&code_challenge=fail-closed-challenge&code_challenge_method=S256",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "temporarily_unavailable");
    assert!(
        payload["error_description"]
            .as_str()
            .is_some_and(|description| !description.is_empty()),
        "retry guidance must be present and non-sensitive: {payload}"
    );
}

/// A replay-storage outage during a confidential-client code exchange must not
/// revoke the grant: the 503 response promises a retry, and that retry has to
/// be able to succeed once storage recovers (keycast#367).
#[tokio::test]
#[serial]
async fn replay_storage_outage_does_not_revoke_confidential_client_grant() {
    use keycast_core::repositories::{
        AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams,
    };

    common::configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app_with_failing_replay_store(pool.clone()).await;

    let redirect_uri = "https://client.example/confidential/callback";
    let client_auth_key = common::client_auth_key_material();
    let client_id =
        common::start_confidential_client_metadata_server(redirect_uri, &client_auth_key, true)
            .await;

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let repo = AtprotoOAuthSessionRepository::new(pool.clone());
    repo.create_par(CreateAtprotoOAuthSessionParams {
        tenant_id: 1,
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.to_string(),
        scope: "atproto".to_string(),
        state: None,
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: request_uri.clone(),
        par_expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        dpop_jkt: Some("a".repeat(43)),
        dpop_nonce: Some("nonce".to_string()),
        client_auth_method: "private_key_jwt".to_string(),
        client_auth_alg: Some("ES256".to_string()),
        client_auth_kid: Some(client_auth_key.kid.clone()),
        client_auth_jkt: Some(client_auth_key.jkt.clone()),
    })
    .await
    .unwrap();
    let code = format!("code-{}", uuid::Uuid::new_v4());
    repo.store_authorization_code(
        &request_uri,
        &code,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    )
    .await
    .unwrap();

    let assertion = common::private_key_jwt_assertion(
        &client_auth_key,
        &client_id,
        "https://login.divine.video",
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier=verifier&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&code),
                    urlencoding::encode(&client_id),
                    urlencoding::encode(redirect_uri),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&assertion),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "temporarily_unavailable");

    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM atproto_oauth_sessions WHERE request_uri = $1")
            .bind(&request_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        revoked_at.is_none(),
        "a replay-storage outage must not revoke the grant the 503 says to retry"
    );
}

/// The refresh-token grant must keep its refresh token through a replay-storage
/// outage for the same reason: the retryable response must stay retryable.
#[tokio::test]
#[serial]
async fn replay_storage_outage_does_not_revoke_confidential_client_refresh_token() {
    use keycast_core::repositories::{
        AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams,
    };
    use keycast_core::types::refresh_token::hash_refresh_token;

    common::configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app_with_failing_replay_store(pool.clone()).await;

    let redirect_uri = "https://client.example/confidential/callback";
    let client_auth_key = common::client_auth_key_material();
    let client_id =
        common::start_confidential_client_metadata_server(redirect_uri, &client_auth_key, true)
            .await;

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let repo = AtprotoOAuthSessionRepository::new(pool.clone());
    repo.create_par(CreateAtprotoOAuthSessionParams {
        tenant_id: 1,
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.to_string(),
        scope: "atproto".to_string(),
        state: None,
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: request_uri.clone(),
        par_expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        dpop_jkt: Some("a".repeat(43)),
        dpop_nonce: Some("nonce".to_string()),
        client_auth_method: "private_key_jwt".to_string(),
        client_auth_alg: Some("ES256".to_string()),
        client_auth_kid: Some(client_auth_key.kid.clone()),
        client_auth_jkt: Some(client_auth_key.jkt.clone()),
    })
    .await
    .unwrap();

    let refresh_token = format!("refresh-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "UPDATE atproto_oauth_sessions
         SET refresh_token_hash = $2,
             refresh_token_expires_at = NOW() + INTERVAL '30 days'
         WHERE request_uri = $1",
    )
    .bind(&request_uri)
    .bind(hash_refresh_token(&refresh_token))
    .execute(&pool)
    .await
    .unwrap();

    let assertion = common::private_key_jwt_assertion(
        &client_auth_key,
        &client_id,
        "https://login.divine.video",
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&refresh_token),
                    urlencoding::encode(&client_id),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&assertion),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "temporarily_unavailable");

    let (revoked_at, refresh_revoked_at): (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT revoked_at, refresh_token_revoked_at FROM atproto_oauth_sessions WHERE request_uri = $1",
    )
    .bind(&request_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        revoked_at.is_none() && refresh_revoked_at.is_none(),
        "a replay-storage outage must not destroy the refresh token the 503 says to retry with"
    );
}
