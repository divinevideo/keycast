use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Debug, PartialEq)]
struct CapturedRequest {
    path: String,
    authorization: Option<String>,
    body: Option<Value>,
}

#[derive(Clone, Default)]
struct CaptureState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
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

async fn capture_opt_in(
    State(state): State<CaptureState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> StatusCode {
    state.requests.lock().unwrap().push(CapturedRequest {
        path: "/api/account-links/opt-in".to_string(),
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        body: Some(body),
    });
    StatusCode::ACCEPTED
}

async fn capture_enable(
    State(state): State<CaptureState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    state.requests.lock().unwrap().push(CapturedRequest {
        path: format!("/api/account-links/{pubkey}/enable"),
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        body: None,
    });
    StatusCode::OK
}

async fn start_capture_server() -> (String, CaptureState) {
    let state = CaptureState::default();
    let app = Router::new()
        .route("/api/account-links/opt-in", post(capture_opt_in))
        .route("/api/account-links/:pubkey/enable", post(capture_enable))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve capture app");
    });

    (format!("http://{}", address), state)
}

#[tokio::test]
#[serial]
async fn request_enable_posts_crosspost_enabled_flag() {
    let (base_url, state) = start_capture_server().await;
    let _base = EnvGuard::set("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", &base_url);
    let _domain = EnvGuard::set("DIVINE_HANDLE_DOMAIN", "bsky.example");
    let _token = EnvGuard::set("KEYCAST_ATPROTO_TOKEN", "crosspost-token");

    keycast_api::atproto_provisioning::request_enable("npub1crosspost", "Alice", false)
        .await
        .expect("opt-in request should succeed");

    let requests = state.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0],
        CapturedRequest {
            path: "/api/account-links/opt-in".to_string(),
            authorization: Some("Bearer crosspost-token".to_string()),
            body: Some(json!({
                "nostr_pubkey": "npub1crosspost",
                "handle": "alice.bsky.example",
                "crosspost_enabled": false
            })),
        }
    );
}

#[tokio::test]
#[serial]
async fn request_reenable_posts_enable_endpoint() {
    let (base_url, state) = start_capture_server().await;
    let _base = EnvGuard::set("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", &base_url);
    let _token = EnvGuard::set("KEYCAST_ATPROTO_TOKEN", "reenable-token");

    keycast_api::atproto_provisioning::request_reenable("npub1reenable")
        .await
        .expect("re-enable request should succeed");

    let requests = state.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0],
        CapturedRequest {
            path: "/api/account-links/npub1reenable/enable".to_string(),
            authorization: Some("Bearer reenable-token".to_string()),
            body: None,
        }
    );
}
