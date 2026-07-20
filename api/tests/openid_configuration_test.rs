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
use serial_test::serial;
use tower::ServiceExt;

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn openid_configuration_returns_json_with_issuer() {
    let _entryway = EnvGuard::remove("ATPROTO_ENTRYWAY_ORIGIN");
    let _app = EnvGuard::set("APP_URL", "https://login.divine.video");

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

    // Keycast is not an OpenID Provider yet, so this compatibility document
    // must stay honest about the OAuth capabilities it actually has.
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
    assert!(payload["code_challenge_methods_supported"]
        .as_array()
        .expect("code_challenge_methods_supported must be an array")
        .iter()
        .any(|v| v == "S256"));
    assert!(
        payload.get("scopes_supported").is_none(),
        "Keycast scopes are policy:slug values, not OpenID scopes"
    );
    assert!(
        payload.get("subject_types_supported").is_none(),
        "subject_types_supported would imply OpenID Provider support"
    );
    assert!(
        payload
            .get("id_token_signing_alg_values_supported")
            .is_none(),
        "Keycast does not issue OIDC ID Tokens"
    );
    assert!(
        payload.get("jwks_uri").is_none(),
        "Keycast does not publish OIDC signing keys"
    );
}

#[tokio::test]
#[serial]
async fn openid_configuration_strips_trailing_slash_from_issuer() {
    // Defensive: APP_URL is configured by deploys and humans; tolerate a
    // trailing slash without producing `https://login.divine.video//api/...`
    // links that violate spec.
    let _entryway = EnvGuard::remove("ATPROTO_ENTRYWAY_ORIGIN");
    let _app = EnvGuard::set("APP_URL", "https://login.divine.video/");

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

#[tokio::test]
#[serial]
async fn openid_configuration_uses_app_origin_not_atproto_entryway_origin() {
    let _app = EnvGuard::set("APP_URL", "https://login.divine.video");
    let _entryway = EnvGuard::set(
        "ATPROTO_ENTRYWAY_ORIGIN",
        "https://entryway.divine.video/ignored/path",
    );

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
    assert_eq!(
        payload["authorization_endpoint"],
        "https://login.divine.video/api/oauth/authorize"
    );
    assert_eq!(
        payload["token_endpoint"],
        "https://login.divine.video/api/oauth/token"
    );
}
