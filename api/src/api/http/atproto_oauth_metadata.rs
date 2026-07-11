use axum::Json;
use reqwest::Url;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    pushed_authorization_request_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    dpop_signing_alg_values_supported: Vec<String>,
    client_id_metadata_document_supported: bool,
    authorization_response_iss_parameter_supported: bool,
    require_pushed_authorization_requests: bool,
}

pub fn authorization_server_origin() -> String {
    std::env::var("ATPROTO_ENTRYWAY_ORIGIN")
        .ok()
        .or_else(|| std::env::var("APP_URL").ok())
        .or_else(|| std::env::var("VITE_DOMAIN").ok())
        .and_then(|raw| {
            Url::parse(&raw).ok().and_then(|url| {
                let host = url.host_str()?;
                let scheme = url.scheme();
                let mut origin = format!("{scheme}://{host}");

                if let Some(port) = url.port() {
                    let is_default_port =
                        (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
                    if !is_default_port {
                        origin.push_str(&format!(":{port}"));
                    }
                }

                Some(origin)
            })
        })
        .unwrap_or_else(|| "http://localhost:3000".to_string())
}

fn endpoint(origin: &str, path: &str) -> String {
    format!(
        "{}/{}",
        origin.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

pub async fn authorization_server_metadata() -> Json<AuthorizationServerMetadata> {
    let origin = authorization_server_origin();

    Json(AuthorizationServerMetadata {
        issuer: origin.clone(),
        authorization_endpoint: endpoint(&origin, "/api/atproto/oauth/authorize"),
        token_endpoint: endpoint(&origin, "/api/atproto/oauth/token"),
        pushed_authorization_request_endpoint: endpoint(&origin, "/api/atproto/oauth/par"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        scopes_supported: vec!["atproto".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ],
        token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        client_id_metadata_document_supported: true,
        authorization_response_iss_parameter_supported: true,
        require_pushed_authorization_requests: true,
    })
}
