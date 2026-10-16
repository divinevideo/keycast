use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};

/// UCAN authentication extractor - extracts user pubkey from UCAN token
/// Accepts Bearer token or keycast_session cookie
/// Always validates the tenant_id from the Host header against the token's tenant claim
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
fn map_dpop_error_to_auth_error(error: anyhow::Error, path: &str) -> AuthError {
    let message = format!("DPoP binding enforcement failed: {}", error);
    if crate::ucan_auth::is_replay_cache_unavailable_error(&error) {
        tracing::error!("{} (path: {})", message, path);
        AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "DPoP replay protection temporarily unavailable. Please retry.".to_string(),
        }
    } else {
        tracing::warn!("{} (path: {})", message, path);
        AuthError {
            status: StatusCode::UNAUTHORIZED,
            message,
        }
    }
}

/// Enforce DPoP binding if the UCAN has a cnf.jkt claim.
/// Constructs the htu from the request method and path.
async fn enforce_dpop_if_bound(parts: &Parts, ucan: &ucan::Ucan) -> Result<(), AuthError> {
    let cnf_jkt = crate::ucan_auth::extract_cnf_jkt_from_ucan(ucan);
    if cnf_jkt.is_none() {
        return Ok(()); // No DPoP binding, nothing to enforce
    }

    let method = parts.method.as_str();
    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let path = parts.uri.path();
    let htu = format!("{}://{}{}", scheme, host, path);

    crate::ucan_auth::enforce_dpop_binding(&parts.headers, ucan, method, &htu)
        .await
        .map_err(|e| map_dpop_error_to_auth_error(e, parts.uri.path()))
}

/// Resolve tenant_id from the Host header using the tenant cache/database
async fn resolve_tenant_id_from_parts(parts: &Parts) -> Result<i64, AuthError> {
    let host = parts
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| parts.uri.host().map(|h| h.to_string()))
        .ok_or_else(|| AuthError {
            status: StatusCode::BAD_REQUEST,
            message: "Missing Host header for tenant resolution".to_string(),
        })?;

    let domain = host.split(':').next().unwrap_or(&host);

    let tenant_cache = crate::state::get_tenant_cache().map_err(|_| AuthError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "Tenant cache not initialized".to_string(),
    })?;

    if let Some(tenant) = tenant_cache.get(domain).await {
        return Ok(tenant.id);
    }

    let pool = crate::state::get_db_pool().map_err(|_| AuthError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "Database not initialized".to_string(),
    })?;

    let tenant = crate::api::tenant::get_or_create_tenant(pool, domain)
        .await
        .map_err(|e| {
            tracing::error!("Failed to resolve tenant for domain {}: {}", domain, e);
            AuthError {
                status: StatusCode::BAD_REQUEST,
                message: format!("Failed to resolve tenant for domain: {}", domain),
            }
        })?;

    let tenant_id = tenant.id;
    let tenant = std::sync::Arc::new(tenant);
    tenant_cache.insert(domain.to_string(), tenant).await;

    Ok(tenant_id)
}

#[async_trait]
impl<S> FromRequestParts<S> for UcanAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let path = parts.uri.path();

        // Resolve tenant_id from Host header before validating any UCAN token
        let tenant_id = resolve_tenant_id_from_parts(parts).await?;

        // Try 1: UCAN Bearer Token
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let (pubkey, _redirect_origin, _bunker_pubkey, ucan) =
                        crate::ucan_auth::validate_ucan_token(auth_str, tenant_id)
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
                    enforce_dpop_if_bound(parts, &ucan).await?;

                    let admin_role = extract_admin_role(&ucan);

                    tracing::debug!(
                        "UcanAuth: Authenticated via Bearer token for pubkey: {} (tenant: {})",
                        pubkey,
                        tenant_id
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
                            crate::ucan_auth::validate_ucan_token(
                                &format!("Bearer {}", value),
                                tenant_id,
                            )
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
                            "UcanAuth: Authenticated via cookie for pubkey: {} (tenant: {})",
                            pubkey,
                            tenant_id
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

/// Group custody uses the existing account-management authority, rather than
/// allowing an app's delegated signing token to enroll devices or recover shares.
pub struct GroupAuth {
    pub pubkey: String,
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for GroupAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = UcanAuth::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let tenant_id = resolve_tenant_id_from_parts(parts)
            .await
            .map_err(IntoResponse::into_response)?;
        let pubkey = crate::api::http::auth::extract_user_for_authorization_management(
            &parts.headers,
            tenant_id,
        )
        .await
        .map_err(IntoResponse::into_response)?;
        if pubkey != auth.pubkey {
            return Err((StatusCode::UNAUTHORIZED, "Account principal differs").into_response());
        }
        Ok(Self { pubkey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_dpop_error_to_auth_error_replay_cache_unavailable_is_503() {
        let error = anyhow::Error::new(crate::ucan_auth::dpop::ReplayCacheUnavailableError::new(
            "DPoP replay protection unavailable",
        ));
        let auth_error = map_dpop_error_to_auth_error(error, "/api/test");
        assert_eq!(auth_error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(auth_error.message.contains("temporarily unavailable"));
    }

    #[test]
    fn test_map_dpop_error_to_auth_error_invalid_proof_is_401() {
        let auth_error =
            map_dpop_error_to_auth_error(anyhow::anyhow!("invalid dpop proof"), "/api/test");
        assert_eq!(auth_error.status, StatusCode::UNAUTHORIZED);
        assert!(auth_error.message.contains("invalid dpop proof"));
    }
}
