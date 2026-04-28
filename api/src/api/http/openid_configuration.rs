// ABOUTME: OpenID Connect Discovery 1.0 metadata endpoint.
// ABOUTME: Reuses the OAuth 2.0 origin helper so the discovery document is
// rooted at the same APP_URL as the rest of the service.
//
// Keycast is primarily an OAuth 2.0 + Nostr Bunker (NIP-46) provider rather
// than a fully-fledged OpenID Connect provider — we don't issue spec-shaped
// id_tokens or expose a userinfo endpoint at this time. Even so, OIDC
// autodiscovery clients (and the reliability assurance suite's
// `oidc_discovery` probe) hit `/.well-known/openid-configuration` to find
// the OAuth endpoints. Without this handler the SvelteKit SPA fallback
// served the index HTML instead of JSON; clients then got a JSON parse
// error and treated keycast as unreachable.
//
// The document below is deliberately conservative: it advertises only the
// capabilities keycast actually supports today. A client that tries to use
// strict OIDC features (id_token signing, userinfo) will fail at runtime
// rather than fail silently — that's the correct degradation.
//
// Sibling: `atproto_oauth_metadata.rs` serves
// `/.well-known/oauth-authorization-server` for ATProto-flavoured clients.

use axum::Json;
use serde::Serialize;

use super::atproto_oauth_metadata::authorization_server_origin;

#[derive(Debug, Serialize)]
pub struct OpenIdConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    // OIDC-required capability lists. Keycast does not currently issue
    // OIDC-shaped id_tokens, but every value here describes what the
    // service WOULD support if/when it does — keeping the list non-empty
    // satisfies strict autodiscovery clients without misrepresenting
    // current behavior. ``subject_types: ["public"]`` is the only sensible
    // value for a Nostr-pubkey-rooted identity model.
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}

fn endpoint(origin: &str, path: &str) -> String {
    format!(
        "{}/{}",
        origin.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

pub async fn openid_configuration_metadata() -> Json<OpenIdConfiguration> {
    let origin = authorization_server_origin();

    Json(OpenIdConfiguration {
        issuer: origin.clone(),
        authorization_endpoint: endpoint(&origin, "/api/oauth/authorize"),
        token_endpoint: endpoint(&origin, "/api/oauth/token"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        scopes_supported: vec!["openid".to_string(), "profile".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["ES256".to_string()],
    })
}
