// ABOUTME: Token request decoding coverage for the OAuth endpoint.
// ABOUTME: Standard OAuth clients submit token grants as form data, while
// existing Keycast clients still use JSON.

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Request, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use http_body_util::BodyExt;
use keycast_api::api::http::oauth::TokenRequestBody;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn echo_token_request(TokenRequestBody(req): TokenRequestBody) -> impl IntoResponse {
    Json(json!({
        "grant_type": req.grant_type,
        "code": req.code,
        "client_id": req.client_id,
        "redirect_uri": req.redirect_uri,
        "code_verifier": req.code_verifier,
        "refresh_token": req.refresh_token,
    }))
}

fn test_app() -> Router {
    Router::new().route("/api/oauth/token", post(echo_token_request))
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn token_request_accepts_form_encoded_oauth_body() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/oauth/token")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=authorization_code&code=code-123&client_id=client-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code_verifier=verifier-123",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["grant_type"], "authorization_code");
    assert_eq!(body["code"], "code-123");
    assert_eq!(body["client_id"], "client-123");
    assert_eq!(body["redirect_uri"], "https://client.example/callback");
    assert_eq!(body["code_verifier"], "verifier-123");
}

#[tokio::test]
async fn token_request_keeps_existing_json_body_support() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/oauth/token")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "grant_type": "refresh_token",
                        "client_id": "client-123",
                        "refresh_token": "refresh-123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["client_id"], "client-123");
    assert_eq!(body["refresh_token"], "refresh-123");
}

#[tokio::test]
async fn token_request_rejects_unsupported_content_type() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/oauth/token")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from("grant_type=authorization_code"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
