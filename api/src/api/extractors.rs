use crate::api::http::extract_auth_event_from_header;
use axum::http::StatusCode;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use nostr_sdk::Event;

// Create a local wrapper type
pub struct AuthEvent(pub Event);

// Dual authentication extractor - accepts NIP-98 or UCAN
pub struct DualAuthEvent(pub String); // Returns pubkey as hex string

// Extract the auth event from the request
#[async_trait]
impl<S> FromRequestParts<S> for AuthEvent
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing authorization header".to_string(),
            ))?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid authorization header".to_string(),
                )
            })?;

        if !auth_header.starts_with("Nostr ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid authorization scheme".to_string(),
            ));
        }

        // Extract pubkey from the auth header
        let event = extract_auth_event_from_header(auth_header)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

        tracing::debug!("Extracted auth event: {:#?}", event);
        Ok(AuthEvent(event))
    }
}

// Dual authentication extractor - accepts NIP-98 headers or UCAN tokens (Bearer/Cookie)
#[async_trait]
impl<S> FromRequestParts<S> for DualAuthEvent
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try 1: NIP-98 Header (Nostr base64-encoded event)
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Nostr ") {
                    let event = extract_auth_event_from_header(auth_str).map_err(|e| {
                        (
                            StatusCode::UNAUTHORIZED,
                            format!("Invalid NIP-98 event: {}", e),
                        )
                    })?;

                    tracing::debug!(
                        "DualAuth: Authenticated via NIP-98 header for pubkey: {}",
                        event.pubkey
                    );
                    return Ok(DualAuthEvent(event.pubkey.to_hex()));
                }
            }
        }

        // Try 2: UCAN Bearer Token
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    // Use tenant_id = 0 for now (will validate in endpoint if needed)
                    let (pubkey, _redirect_origin, _bunker_pubkey, _ucan) =
                        crate::ucan_auth::validate_ucan_token(auth_str, 0)
                            .await
                            .map_err(|e| {
                                (
                                    StatusCode::UNAUTHORIZED,
                                    format!("Invalid UCAN token: {}", e),
                                )
                            })?;

                    tracing::debug!(
                        "DualAuth: Authenticated via UCAN Bearer token for pubkey: {}",
                        pubkey
                    );
                    return Ok(DualAuthEvent(pubkey));
                }
            }
        }

        // Try 3: UCAN Cookie
        if let Some(cookie_header) = parts.headers.get("Cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                // Parse cookies manually to find keycast_session
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some(value) = cookie.strip_prefix("keycast_session=") {
                        // Validate UCAN token from cookie
                        let (pubkey, _redirect_origin, _bunker_pubkey, _ucan) =
                            crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", value), 0)
                                .await
                                .map_err(|e| {
                                    (
                                        StatusCode::UNAUTHORIZED,
                                        format!("Invalid UCAN cookie: {}", e),
                                    )
                                })?;

                        tracing::debug!(
                            "DualAuth: Authenticated via UCAN cookie for pubkey: {}",
                            pubkey
                        );
                        return Ok(DualAuthEvent(pubkey));
                    }
                }
            }
        }

        Err((
            StatusCode::UNAUTHORIZED,
            "Missing authentication - expected NIP-98 header, UCAN Bearer token, or UCAN cookie"
                .to_string(),
        ))
    }
}
