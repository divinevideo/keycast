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
