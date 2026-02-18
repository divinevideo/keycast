use axum::http::StatusCode;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};

/// UCAN authentication extractor - extracts user pubkey from UCAN token
/// Accepts Bearer token or keycast_session cookie
pub struct UcanAuth {
    pub pubkey: String,
    /// Set only for Cloudflare Access admins (from server-signed UCAN facts)
    pub cf_admin_email: Option<String>,
    /// Admin role from server-signed UCAN: "full" or "support"
    pub admin_role: Option<String>,
}

/// Extract cf_admin_email from a server-signed UCAN's facts
fn extract_cf_admin_email(ucan: &ucan::Ucan) -> Option<String> {
    if !crate::ucan_auth::is_server_signed(ucan) {
        return None;
    }
    ucan.facts()
        .iter()
        .find_map(|fact| fact.get("cf_admin_email").and_then(|v| v.as_str()))
        .map(String::from)
}

/// Extract admin_role from a server-signed UCAN's facts
fn extract_admin_role(ucan: &ucan::Ucan) -> Option<String> {
    if !crate::ucan_auth::is_server_signed(ucan) {
        return None;
    }
    ucan.facts()
        .iter()
        .find_map(|fact| fact.get("admin_role").and_then(|v| v.as_str()))
        .map(String::from)
}

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
                    let (pubkey, _redirect_origin, _bunker_pubkey, ucan) =
                        crate::ucan_auth::validate_ucan_token(auth_str, 0)
                            .await
                            .map_err(|e| {
                                (
                                    StatusCode::UNAUTHORIZED,
                                    format!("Invalid UCAN token: {}", e),
                                )
                            })?;

                    let cf_admin_email = extract_cf_admin_email(&ucan);
                    let admin_role = extract_admin_role(&ucan);

                    tracing::debug!(
                        "UcanAuth: Authenticated via Bearer token for pubkey: {}",
                        pubkey
                    );
                    return Ok(UcanAuth {
                        pubkey,
                        cf_admin_email,
                        admin_role,
                    });
                }
            }
        }

        // Try 2: UCAN Cookie
        if let Some(cookie_header) = parts.headers.get("Cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some(value) = cookie.strip_prefix("keycast_session=") {
                        let (pubkey, _redirect_origin, _bunker_pubkey, ucan) =
                            crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", value), 0)
                                .await
                                .map_err(|e| {
                                    (
                                        StatusCode::UNAUTHORIZED,
                                        format!("Invalid UCAN cookie: {}", e),
                                    )
                                })?;

                        let cf_admin_email = extract_cf_admin_email(&ucan);
                        let admin_role = extract_admin_role(&ucan);

                        tracing::debug!(
                            "UcanAuth: Authenticated via cookie for pubkey: {}",
                            pubkey
                        );
                        return Ok(UcanAuth {
                            pubkey,
                            cf_admin_email,
                            admin_role,
                        });
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
