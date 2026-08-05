// ABOUTME: Compatibility metadata for OpenID autodiscovery clients.
// ABOUTME: Keeps the OpenID well-known path from falling through to the SPA
// fallback while advertising only Keycast's current OAuth behavior.
//
// Keycast is primarily an OAuth 2.0 + Nostr Bunker (NIP-46) provider rather
// than an OpenID Provider: it does not issue ID Tokens, expose UserInfo, or
// publish signing keys for OIDC token validation. Even so, some clients and
// reliability probes hit `/.well-known/openid-configuration` first. Returning
// this small OAuth-shaped JSON document is more useful than serving the SPA
// index HTML, while avoiding unsupported `openid`/`id_token` claims.

use axum::Json;
use serde::Serialize;

use super::atproto_oauth_metadata::{app_origin, endpoint};

#[derive(Debug, Serialize)]
pub struct OpenIdConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

pub async fn openid_configuration_metadata() -> Json<OpenIdConfiguration> {
    let origin = app_origin();

    Json(OpenIdConfiguration {
        issuer: origin.clone(),
        authorization_endpoint: endpoint(&origin, "/api/oauth/authorize"),
        token_endpoint: endpoint(&origin, "/api/oauth/token"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
    })
}
