// ABOUTME: Catches a panic raised while handling one HTTP request and answers it with a 500,
// ABOUTME: so one failing request does not take the process down with it

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::FutureExt;
use keycast_core::panic_scope;
use serde_json::json;
use std::panic::AssertUnwindSafe;

/// Run the rest of the request as request work and answer a panic with a 500.
///
/// The process panic hook ([`panic_scope::install_hook`]) has already logged
/// and counted the panic by the time it is caught here, and lets it unwind only
/// because this middleware runs the request inside [`panic_scope::scope`].
pub async fn contain_request_panics(request: Request, next: Next) -> Response {
    panic_scope::scope(async move {
        match AssertUnwindSafe(next.run(request)).catch_unwind().await {
            Ok(response) => response,
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({ "error": "Something went wrong. Please try again." })),
            )
                .into_response(),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn panicking_handler() -> &'static str {
        panic!("handler failure")
    }

    fn app() -> Router {
        Router::new()
            .route("/panic", get(panicking_handler))
            .route("/ok", get(|| async { "ok" }))
            .route(
                "/in-request",
                get(|| async { panic_scope::in_request().to_string() }),
            )
            .layer(middleware::from_fn(contain_request_panics))
    }

    async fn send(path: &str) -> Response {
        app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn get_path(path: &str) -> (StatusCode, String) {
        let response = send(path).await;
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_panicking_handler_is_answered_with_a_500() {
        let response = send("/panic").await;
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let (status, body) = get_path("/panic").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"], "Something went wrong. Please try again.");
    }

    #[tokio::test]
    async fn other_responses_pass_through() {
        assert_eq!(get_path("/ok").await, (StatusCode::OK, "ok".to_string()));
    }

    #[tokio::test]
    async fn handlers_run_as_request_work() {
        assert_eq!(
            get_path("/in-request").await,
            (StatusCode::OK, "true".to_string())
        );
    }
}
