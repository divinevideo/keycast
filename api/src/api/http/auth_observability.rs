use axum::{
    body::Body,
    http::{
        header::{HeaderName, HeaderValue},
        HeaderMap, Request,
    },
    middleware::Next,
    response::Response,
};
use keycast_core::{
    metrics::METRICS,
    repositories::{AuthEventRecord, AuthEventRepository},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Instant;
use uuid::Uuid;

pub const REQUEST_ID_HEADER: &str = "x-request-id";
pub const TRACE_ID_HEADER: &str = "x-trace-id";

#[derive(Clone, Debug)]
pub struct RequestContext {
    pub request_id: String,
    pub started_at: Instant,
}

impl RequestContext {
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            started_at: Instant::now(),
        }
    }
}

pub fn request_context(request: &Request<Body>) -> Option<&RequestContext> {
    request.extensions().get::<RequestContext>()
}

pub fn request_id_from_headers(headers: &HeaderMap) -> Option<String> {
    for header_name in [REQUEST_ID_HEADER, TRACE_ID_HEADER] {
        let Some(value) = headers.get(header_name) else {
            continue;
        };

        let Ok(value) = value.to_str() else {
            continue;
        };

        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    None
}

pub fn generate_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn hash_email(email: Option<&str>) -> String {
    let Some(email) = email else {
        return "none".to_string();
    };

    let normalized = email.trim().to_lowercase();
    if normalized.is_empty() {
        return "none".to_string();
    }

    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn pubkey_prefix(pubkey: Option<&str>) -> Option<String> {
    pubkey.map(|value| value.chars().take(12).collect::<String>())
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub struct AuthEvent<'a> {
    pub tenant_id: i64,
    pub endpoint: &'static str,
    pub event_type: &'static str,
    pub outcome: &'static str,
    pub reason_code: Option<&'a str>,
    pub http_status: i32,
    pub email: Option<&'a str>,
    pub pubkey: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub redirect_origin: Option<&'a str>,
    pub metadata_json: Value,
}

pub async fn record_auth_event_and_log(
    pool: &PgPool,
    headers: &HeaderMap,
    request_context: Option<&RequestContext>,
    event: AuthEvent<'_>,
) {
    let request_id = request_context
        .map(|context| context.request_id.clone())
        .or_else(|| request_id_from_headers(headers))
        .unwrap_or_else(generate_request_id);
    let latency = request_context
        .map(|context| context.started_at.elapsed())
        .unwrap_or_default();
    let email_hash = hash_email(event.email);
    let pubkey_prefix = pubkey_prefix(event.pubkey);
    let user_agent = user_agent(headers);

    METRICS.observe_auth_request(event.endpoint, event.outcome, event.reason_code, latency);

    match event.outcome {
        "success" | "accepted" => tracing::info!(
            event = "auth_event",
            endpoint = event.endpoint,
            event_type = event.event_type,
            outcome = event.outcome,
            reason_code = event.reason_code.unwrap_or("none"),
            http_status = event.http_status,
            tenant_id = event.tenant_id,
            request_id = %request_id,
            email_hash = %email_hash,
            pubkey_prefix = pubkey_prefix.as_deref().unwrap_or("none"),
            client_id = event.client_id.unwrap_or("none"),
            redirect_origin = event.redirect_origin.unwrap_or("none"),
            latency_ms = latency.as_millis() as u64,
            "Auth event"
        ),
        "failure" => tracing::warn!(
            event = "auth_event",
            endpoint = event.endpoint,
            event_type = event.event_type,
            outcome = event.outcome,
            reason_code = event.reason_code.unwrap_or("none"),
            http_status = event.http_status,
            tenant_id = event.tenant_id,
            request_id = %request_id,
            email_hash = %email_hash,
            pubkey_prefix = pubkey_prefix.as_deref().unwrap_or("none"),
            client_id = event.client_id.unwrap_or("none"),
            redirect_origin = event.redirect_origin.unwrap_or("none"),
            latency_ms = latency.as_millis() as u64,
            "Auth event"
        ),
        _ => tracing::error!(
            event = "auth_event",
            endpoint = event.endpoint,
            event_type = event.event_type,
            outcome = event.outcome,
            reason_code = event.reason_code.unwrap_or("none"),
            http_status = event.http_status,
            tenant_id = event.tenant_id,
            request_id = %request_id,
            email_hash = %email_hash,
            pubkey_prefix = pubkey_prefix.as_deref().unwrap_or("none"),
            client_id = event.client_id.unwrap_or("none"),
            redirect_origin = event.redirect_origin.unwrap_or("none"),
            latency_ms = latency.as_millis() as u64,
            "Auth event"
        ),
    }

    let repo = AuthEventRepository::new(pool.clone());
    if let Err(error) = repo
        .record(AuthEventRecord {
            tenant_id: event.tenant_id,
            request_id,
            endpoint: event.endpoint.to_string(),
            event_type: event.event_type.to_string(),
            outcome: event.outcome.to_string(),
            reason_code: event.reason_code.map(str::to_string),
            http_status: Some(event.http_status),
            email: event.email.map(str::to_string),
            email_hash,
            pubkey: event.pubkey.map(str::to_string),
            pubkey_prefix,
            client_id: event.client_id.map(str::to_string),
            redirect_origin: event.redirect_origin.map(str::to_string),
            user_agent,
            metadata_json: event.metadata_json,
        })
        .await
    {
        METRICS.inc_auth_audit_write_failure(event.endpoint);
        tracing::error!(
            endpoint = event.endpoint,
            tenant_id = event.tenant_id,
            error = %error,
            "Failed to write auth audit event"
        );
    }
}

pub async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request_id_from_headers(request.headers()).unwrap_or_else(generate_request_id);
    let request_context = RequestContext::new(request_id.clone());
    let request_id_value =
        HeaderValue::from_str(&request_id).expect("generated request id must be ASCII");

    request.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        request_id_value.clone(),
    );
    request.headers_mut().insert(
        HeaderName::from_static(TRACE_ID_HEADER),
        request_id_value.clone(),
    );
    request.extensions_mut().insert(request_context);

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        request_id_value.clone(),
    );
    headers.insert(HeaderName::from_static(TRACE_ID_HEADER), request_id_value);

    response
}
