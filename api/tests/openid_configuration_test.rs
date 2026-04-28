// ABOUTME: regression test for the `/.well-known/openid-configuration` discovery
// document. The endpoint MUST return JSON (not the SPA index HTML) so OIDC
// autodiscovery clients can find the keycast OAuth endpoints. The bug this
// guards against was reported on 2026-04-28: keycast had no handler at this
// path, the SPA fallback served index.html, and any OIDC client that did
// autodiscovery received a JSON parse error.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use http_body_util::BodyExt;
use keycast_api::api::http::openid_configuration::openid_configuration_metadata;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn openid_configuration_returns_json_with_issuer() {
    unsafe {
        std::env::set_var("APP_URL", "https://login.divine.video");
    }

    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get(openid_configuration_metadata),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body)
        .expect("response body must be JSON, not HTML — this is the regression");

    // Required by the reliability suite probe (see keycast.yaml).
    assert_eq!(payload["issuer"], "https://login.divine.video");

    // Endpoints MUST be absolute URLs anchored at the issuer so clients
    // doing autodiscovery don't have to guess the base.
    assert_eq!(
        payload["authorization_endpoint"],
        "https://login.divine.video/api/oauth/authorize"
    );
    assert_eq!(
        payload["token_endpoint"],
        "https://login.divine.video/api/oauth/token"
    );

    // OIDC discovery is required by spec to advertise these capability lists.
    // Empty arrays here would let a strict client reject the document.
    assert!(payload["response_types_supported"]
        .as_array()
        .expect("response_types_supported must be an array")
        .iter()
        .any(|v| v == "code"));
    assert!(payload["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array")
        .iter()
        .any(|v| v == "authorization_code"));
    assert!(payload["subject_types_supported"]
        .as_array()
        .expect("subject_types_supported must be an array")
        .iter()
        .any(|v| v == "public"));
    assert!(payload["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("id_token_signing_alg_values_supported must be an array")
        .iter()
        .any(|v| v == "ES256"));
    assert!(payload["code_challenge_methods_supported"]
        .as_array()
        .expect("code_challenge_methods_supported must be an array")
        .iter()
        .any(|v| v == "S256"));
}

#[tokio::test]
async fn openid_configuration_strips_trailing_slash_from_issuer() {
    // Defensive: APP_URL is configured by deploys and humans; tolerate a
    // trailing slash without producing `https://login.divine.video//api/...`
    // links that violate spec.
    unsafe {
        std::env::set_var("APP_URL", "https://login.divine.video/");
    }

    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get(openid_configuration_metadata),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(payload["issuer"], "https://login.divine.video");
    let token = payload["token_endpoint"].as_str().unwrap();
    assert!(
        !token.contains("//api/"),
        "endpoint URL has a double slash: {token}"
    );
}
