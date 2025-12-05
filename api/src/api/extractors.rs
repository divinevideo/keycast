use axum::http::StatusCode;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};

/// UCAN authentication extractor - extracts user pubkey from UCAN token
/// Accepts Bearer token or keycast_session cookie
pub struct UcanAuth(pub String); // Returns pubkey as hex string

#[async_trait]
impl<S> FromRequestParts<S> for UcanAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try 1: UCAN Bearer Token
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
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
                        "UcanAuth: Authenticated via Bearer token for pubkey: {}",
                        pubkey
                    );
                    return Ok(UcanAuth(pubkey));
                }
            }
        }

        // Try 2: UCAN Cookie
        if let Some(cookie_header) = parts.headers.get("Cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some(value) = cookie.strip_prefix("keycast_session=") {
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
                            "UcanAuth: Authenticated via cookie for pubkey: {}",
                            pubkey
                        );
                        return Ok(UcanAuth(pubkey));
                    }
                }
            }
        }

        Err((
            StatusCode::UNAUTHORIZED,
            "Missing authentication - expected UCAN Bearer token or keycast_session cookie"
                .to_string(),
        ))
    }
}
