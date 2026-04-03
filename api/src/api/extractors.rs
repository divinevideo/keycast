use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};

/// UCAN authentication extractor - extracts user pubkey from UCAN token
/// Accepts Bearer token or keycast_session cookie
/// Enforces DPoP binding when UCAN contains cnf.jkt
pub struct UcanAuth {
    pub pubkey: String,
    /// Admin role from server-signed UCAN: "full" or "support"
    pub admin_role: Option<String>,
}

pub struct AuthError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, axum::Json(body)).into_response()
    }
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

/// Enforce DPoP binding if the UCAN has a cnf.jkt claim.
/// Constructs the htu from the request method and path.
fn enforce_dpop_if_bound(
    parts: &Parts,
    ucan: &ucan::Ucan,
) -> Result<(), AuthError> {
    let cnf_jkt = crate::ucan_auth::extract_cnf_jkt_from_ucan(ucan);
    if cnf_jkt.is_none() {
        return Ok(()); // No DPoP binding, nothing to enforce
    }

    let method = parts.method.as_str();
    // Reconstruct the request URL for htu verification
    // Use the path as-is; the DPoP proof htu should match the full URL
    let htu = parts.uri.to_string();

    crate::ucan_auth::enforce_dpop_binding(&parts.headers, ucan, method, &htu).map_err(|e| {
        let msg = format!("DPoP binding enforcement failed: {}", e);
        tracing::warn!("{} (path: {})", msg, parts.uri.path());
        AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: msg,
        }
    })
}

#[async_trait]
impl<S> FromRequestParts<S> for UcanAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let path = parts.uri.path();

        // Try 1: UCAN Bearer Token
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let (pubkey, _redirect_origin, _bunker_pubkey, ucan) =
                        crate::ucan_auth::validate_ucan_token(auth_str, 0)
                            .await
                            .map_err(|e| {
                                let msg = format!("Invalid UCAN token: {}", e);
                                tracing::warn!("{} (path: {})", msg, path);
                                AuthError {
                                    status: StatusCode::UNAUTHORIZED,
                                    message: msg,
                                }
                            })?;

                    // Enforce DPoP binding if UCAN contains cnf.jkt
                    enforce_dpop_if_bound(parts, &ucan)?;

                    let admin_role = extract_admin_role(&ucan);

                    tracing::debug!(
                        "UcanAuth: Authenticated via Bearer token for pubkey: {}",
                        pubkey
                    );
                    return Ok(UcanAuth { pubkey, admin_role });
                }
            }
        }

        // Try 2: UCAN Cookie (cookies are not DPoP-bound, skip DPoP check)
        if let Some(cookie_header) = parts.headers.get("Cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some(value) = cookie.strip_prefix("keycast_session=") {
                        let (pubkey, _redirect_origin, _bunker_pubkey, ucan) =
                            crate::ucan_auth::validate_ucan_token(&format!("Bearer {}", value), 0)
                                .await
                                .map_err(|e| {
                                    let msg = format!("Invalid UCAN cookie: {}", e);
                                    tracing::warn!("{} (path: {})", msg, path);
                                    AuthError {
                                        status: StatusCode::UNAUTHORIZED,
                                        message: msg,
                                    }
                                })?;

                        let admin_role = extract_admin_role(&ucan);

                        tracing::debug!(
                            "UcanAuth: Authenticated via cookie for pubkey: {}",
                            pubkey
                        );
                        return Ok(UcanAuth { pubkey, admin_role });
                    }
                }
            }
        }

        tracing::warn!("Missing authentication (path: {})", path);
        Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message:
                "Missing authentication - expected UCAN Bearer token or keycast_session cookie"
                    .to_string(),
        })
    }
}
