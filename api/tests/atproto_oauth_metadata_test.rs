use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use http_body_util::BodyExt;
use keycast_api::api::http::atproto_oauth_metadata::authorization_server_metadata;
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
async fn metadata_endpoint_exposes_required_atproto_fields() {
    let _entryway = EnvGuard::remove("ATPROTO_ENTRYWAY_ORIGIN");
    let _app = EnvGuard::set("APP_URL", "https://login.divine.video");

    let app = Router::new().route(
        "/.well-known/oauth-authorization-server",
        get(authorization_server_metadata),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
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
    let payload: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(payload["issuer"], "https://login.divine.video");
    assert_eq!(
        payload["authorization_endpoint"],
        "https://login.divine.video/api/atproto/oauth/authorize"
    );
    assert_eq!(
        payload["token_endpoint"],
        "https://login.divine.video/api/atproto/oauth/token"
    );
    assert_eq!(
        payload["pushed_authorization_request_endpoint"],
        "https://login.divine.video/api/atproto/oauth/par"
    );
    assert!(payload["scopes_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::String("atproto".to_string())));
    assert_eq!(
        payload["authorization_response_iss_parameter_supported"],
        true
    );
    assert_eq!(payload["require_pushed_authorization_requests"], true);
    assert!(payload["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::String("none".to_string())));
    assert!(payload["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::String("private_key_jwt".to_string())));
    assert!(payload["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::String("ES256".to_string())));
    assert_eq!(payload["client_id_metadata_document_supported"], true);
    assert!(payload["dpop_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::String("ES256".to_string())));
}

#[tokio::test]
#[serial]
async fn metadata_prefers_configured_entryway_origin_over_human_login_origin() {
    let _app = EnvGuard::set("APP_URL", "https://login.divine.video");
    let _entryway = EnvGuard::set(
        "ATPROTO_ENTRYWAY_ORIGIN",
        "https://entryway.divine.video/ignored/path",
    );

    let app = Router::new().route(
        "/.well-known/oauth-authorization-server",
        get(authorization_server_metadata),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(payload["issuer"], "https://entryway.divine.video");
    assert_eq!(
        payload["authorization_endpoint"],
        "https://entryway.divine.video/api/atproto/oauth/authorize"
    );
    assert_eq!(
        payload["token_endpoint"],
        "https://entryway.divine.video/api/atproto/oauth/token"
    );
    assert_eq!(
        payload["pushed_authorization_request_endpoint"],
        "https://entryway.divine.video/api/atproto/oauth/par"
    );
}
