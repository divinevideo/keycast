pub mod auth;
pub mod nostr_rpc;
pub mod oauth;
pub mod policies;
pub mod routes;
pub mod teams;

use axum::{body::Body, http::Request, middleware::Next, response::Response};
pub use routes::*;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nostr_sdk::prelude::*;
use thiserror::Error;

/// Common HTTP authentication header names
pub const AUTHORIZATION_HEADER: &str = "Authorization";

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Invalid base64")]
    InvalidBase64,
    #[error("Invalid utf8")]
    InvalidUtf8,
    #[error("Invalid json")]
    InvalidJson,
    #[error("Invalid event: {0}")]
    InvalidEvent(String),
}

pub async fn auth_middleware(request: Request<Body>, next: Next) -> Response {
    // Get the authorization header
    let auth_header = match request.headers().get(AUTHORIZATION_HEADER) {
        Some(header) => header,
        None => {
            return Response::builder()
                .status(401)
                .body("Missing authentication header".into())
                .unwrap();
        }
    };

    // Convert header to string and validate
    let auth_str = match auth_header.to_str() {
        Ok(str) => str,
        Err(_) => {
            return Response::builder()
                .status(401)
                .body("Invalid authentication format".into())
                .unwrap();
        }
    };

    // Validate the token
    if !is_valid_token(auth_str, &request) {
        return Response::builder()
            .status(401)
            .body("Invalid credentials".into())
            .unwrap();
    }

    next.run(request).await
}

fn is_valid_token(token: &str, request: &Request<Body>) -> bool {
    // Check prefix
    if !token.starts_with("Nostr ") {
        tracing::debug!("Token validation failed: Invalid token prefix");
        return false;
    }

    let event = match extract_auth_event_from_header(token) {
        Ok(event) => event,
        Err(e) => {
            tracing::debug!("Event extraction failed: {}", e);
            return false;
        }
    };

    if validate_auth_event(event, request).is_err() {
        return false;
    }
    tracing::debug!("Token validation successful");
    true
}

pub fn extract_auth_event_from_header(token: &str) -> Result<Event, AuthenticationError> {
    // Get the base64 part
    let base64_str = token.trim_start_matches("Nostr ").trim();

    // Decode base64
    let decoded = match BASE64.decode(base64_str) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::debug!("Token validation failed: Invalid base64");
            return Err(AuthenticationError::InvalidBase64);
        }
    };

    // Convert bytes to string
    let json_str = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => {
            tracing::debug!("Token validation failed: Invalid utf8");
            return Err(AuthenticationError::InvalidUtf8);
        }
    };

    // Parse JSON into Event
    let event: Event = match Event::from_json(&json_str) {
        Ok(evt) => evt,
        Err(_) => {
            tracing::debug!(
                "Token validation failed: Invalid NIP-98 event json: {:#?}",
                json_str
            );
            return Err(AuthenticationError::InvalidJson);
        }
    };

    Ok(event)
}

pub fn validate_auth_event(
    event: Event,
    request: &Request<Body>,
) -> Result<(), AuthenticationError> {
    if event.verify().is_err() {
        tracing::debug!("Token validation failed: Event verification failed");
        return Err(AuthenticationError::InvalidEvent(
            "Event verification failed".to_string(),
        ));
    }

    if event.kind != Kind::HttpAuth {
        tracing::debug!("Token validation failed: Invalid event kind");
        return Err(AuthenticationError::InvalidEvent(
            "Event kind is not HttpAuth".to_string(),
        ));
    }

    if event.created_at.as_secs() < (chrono::Utc::now().timestamp() - 60) as u64 {
        tracing::debug!("Token validation failed: Event too old");
        return Err(AuthenticationError::InvalidEvent(
            "Event too old".to_string(),
        ));
    }

    if let Some(u_tag) = event
        .tags
        .find(TagKind::SingleLetter(SingleLetterTag::lowercase(
            nostr_sdk::Alphabet::U,
        )))
    {
        let host = request
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        let scheme = if request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .map(|p| p == "https")
            .unwrap_or(false)
        {
            "https"
        } else {
            "http"
        };

        // Get the original URI from the x-forwarded-prefix header or use /api as default
        let prefix = request
            .headers()
            .get("x-forwarded-prefix")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("/api");

        let full_url = format!("{}://{}{}{}", scheme, host, prefix, request.uri());

        if u_tag.content().unwrap() != full_url {
            tracing::debug!("Token validation failed: Invalid u tag");
            return Err(AuthenticationError::InvalidEvent(
                "Invalid u tag".to_string(),
            ));
        }
    }

    if let Some(method_tag) = event.tags.find(TagKind::Method) {
        if method_tag.content().unwrap() != request.method() {
            tracing::debug!("Token validation failed: Invalid method tag");
            return Err(AuthenticationError::InvalidEvent(
                "Invalid method tag".to_string(),
            ));
        }
    }

    Ok(())
}
