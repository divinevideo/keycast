use axum::{
    routing::{delete, get, post, put},
    Router,
};
use keycast_core::authorization_channel::AuthorizationSender;
use sqlx::PgPool;
use std::sync::Arc;

use crate::api::http::{auth, nostr_rpc, oauth, policies, teams};
use crate::state::KeycastState;
use axum::response::Json as AxumJson;
use serde_json::Value as JsonValue;

// State wrapper to pass state to auth handlers
#[derive(Clone)]
pub struct AuthState {
    pub state: Arc<KeycastState>,
    pub auth_tx: Option<AuthorizationSender>,
}

/// Build API routes - pure JSON endpoints, no HTML
/// Returns unrooted Router that can be nested at any path (e.g., /api, /v1, etc.)
pub fn api_routes(pool: PgPool, state: Arc<KeycastState>, auth_cors: tower_http::cors::CorsLayer, public_cors: tower_http::cors::CorsLayer, auth_tx: Option<AuthorizationSender>) -> Router {
    tracing::debug!("Building routes");

    let auth_state = AuthState {
        state,
        auth_tx,
    };

    // Routes that need restricted CORS (first-party only + credentials)
    // These endpoints accept user credentials and must prevent phishing
    let first_party_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/oauth/login", post(oauth::oauth_login))
        .route("/oauth/register", post(oauth::oauth_register))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    let email_routes = Router::new()
        .route("/auth/verify-email", post(auth::verify_email))
        .route("/auth/forgot-password", post(auth::forgot_password))
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(pool.clone());

    // OAuth routes (no authentication required for initial authorize request)
    // Public CORS - third parties use authorization_code grant (never see passwords)
    let oauth_routes = Router::new()
        .route("/oauth/auth-status", get(oauth::auth_status))
        .route("/oauth/authorize", get(oauth::authorize_get))
        .route("/oauth/authorize", post(oauth::authorize_post))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/poll", get(oauth::poll))  // iOS PWA polling endpoint
        .route("/oauth/connect", post(oauth::connect_post))
        .layer(public_cors.clone())
        .with_state(auth_state.clone());

    // nostr-login connect routes (wildcard path to capture nostrconnect:// URI)
    let connect_routes = Router::new()
        .route("/connect/*nostrconnect", get(oauth::connect_get))
        .with_state(auth_state.clone());

    // Fast signing endpoint (needs AuthState for key_manager access)
    let signing_routes = Router::new()
        .route("/user/sign", post(auth::sign_event))
        .with_state(auth_state.clone());

    // NIP-46 RPC endpoint (OAuth access token auth, public CORS for third-party apps)
    let nostr_rpc_routes = Router::new()
        .route("/nostr", post(nostr_rpc::nostr_rpc))
        .with_state(auth_state.clone());

    // Protected user routes (authentication required via UCAN cookie)
    // Need auth_cors (restricted origins + credentials) since they use cookies
    let user_routes = Router::new()
        .route("/user/bunker", get(auth::get_bunker_url))
        .route("/user/pubkey", get(auth::get_pubkey))
        .route("/user/account", get(auth::get_account_status))
        .route("/auth/resend-verification", post(auth::resend_verification))
        .route("/user/profile", get(auth::get_profile))
        .route("/user/sessions", get(auth::list_sessions))
        .route("/user/permissions", get(auth::list_permissions))
        .route("/user/sessions/:secret/activity", get(auth::get_session_activity))
        .route("/user/profile", post(auth::update_profile))
        .route("/user/sessions/disconnect", post(auth::disconnect_client))
        .route("/user/verify-password", post(auth::verify_password_for_export))
        .route("/user/request-key-export", post(auth::request_key_export))
        .route("/user/verify-export-code", post(auth::verify_export_code))
        .layer(auth_cors.clone())
        .with_state(pool.clone());

    // Bunker routes (need AuthState for key_manager and auth_tx)
    let bunker_routes = Router::new()
        .route("/user/bunker/create", post(auth::create_bunker))
        .route("/user/sessions/revoke", post(auth::revoke_session))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // Key export routes (need AuthState for key_manager)
    let key_export_routes = Router::new()
        .route("/user/export-key", post(auth::export_key))
        .route("/user/export-key-simple", post(auth::export_key_simple))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // Change key route (needs AuthState for key_manager and auth_tx)
    let change_key_route = Router::new()
        .route("/user/change-key", post(auth::change_key))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // NIP-05 discovery route (public, no auth required)
    let discovery_route = Router::new()
        .route("/.well-known/nostr.json", get(nostr_discovery_public))
        .with_state(pool.clone());

    // Policy discovery routes (public, no auth required)
    let policy_routes = Router::new()
        .route("/policies", get(policies::list_policies))
        .route("/policies/:slug", get(policies::get_policy))
        .with_state(pool.clone());

    // API documentation route (public)
    let docs_route = Router::new()
        .route("/docs/openapi.json", get(openapi_spec));

    // Protected team routes (authentication required)
    let team_routes = Router::new()
        .route("/teams", get(teams::list_teams))
        .route("/teams", post(teams::create_team))
        .route("/teams/:id", get(teams::get_team))
        .route("/teams/:id", put(teams::update_team))
        .route("/teams/:id", delete(teams::delete_team))
        .route("/teams/:id/users", post(teams::add_user))
        .route(
            "/teams/:id/users/:user_public_key",
            delete(teams::remove_user),
        )
        .route("/teams/:id/keys", post(teams::add_key))
        .route("/teams/:id/keys/:pubkey", get(teams::get_key))
        .route("/teams/:id/keys/:pubkey", delete(teams::remove_key))
        .route(
            "/teams/:id/keys/:pubkey/authorizations",
            post(teams::add_authorization),
        )
        .route("/teams/:id/policies", post(teams::add_policy))
        .with_state(pool);

    // Combine routes
    // First-party routes have restricted CORS (prevent phishing)
    // Authenticated routes have restricted CORS (need cookies)
    // Public routes have wildcard CORS (third-party safe, no credentials)
    Router::new()
        .merge(first_party_routes)      // Has auth_cors (credentials, needs cookies)
        .merge(user_routes)              // Has auth_cors (authenticated, needs cookies)
        .merge(bunker_routes)            // Has auth_cors (bunker creation)
        .merge(key_export_routes)        // Has auth_cors (authenticated, needs cookies)
        .merge(change_key_route)         // Has auth_cors (authenticated, needs cookies)
        .merge(email_routes.layer(public_cors.clone()))
        .merge(oauth_routes)             // Has public_cors (third-party safe)
        .merge(connect_routes.layer(public_cors.clone()))
        .merge(signing_routes.layer(public_cors.clone()))
        .merge(nostr_rpc_routes.layer(public_cors.clone()))  // NIP-46 RPC for OAuth apps
        .merge(team_routes.layer(auth_cors.clone()))       // Team routes need credentials
        .merge(discovery_route.layer(public_cors.clone()))
        .merge(policy_routes.layer(public_cors.clone()))   // Public - available to third-party OAuth apps
        .merge(docs_route.layer(public_cors))
}

/// Serve OpenAPI specification as JSON
async fn openapi_spec() -> AxumJson<JsonValue> {
    let yaml_content = include_str!("../../../openapi.yaml");
    let spec: JsonValue = serde_yaml::from_str(yaml_content)
        .expect("Failed to parse OpenAPI spec");
    AxumJson(spec)
}

/// NIP-05 discovery endpoint for nostr-login integration
/// This should be mounted at root level in main.rs, not under /api
pub async fn nostr_discovery_public(
    tenant: crate::api::tenant::TenantExtractor,
    axum::extract::State(pool): axum::extract::State<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl axum::response::IntoResponse {
    use axum::http::{header, StatusCode};
    use axum::body::Body;
    use axum::response::Response;

    let tenant_id = tenant.0.id;

    // Check if "name" query parameter is provided
    if let Some(name) = params.get("name") {
        // Look up user by username in this tenant
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT public_key FROM users WHERE username = $1 AND tenant_id = $2"
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();

        if let Some((pubkey,)) = result {
            // Return NIP-05 response with user's pubkey
            let response = serde_json::json!({
                "names": {
                    name: pubkey
                }
            });

            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(serde_json::to_string(&response).unwrap()))
                .unwrap();
        }
    }

    // Return default nostr-login discovery info if no name or name not found
    let discovery = serde_json::json!({
        "nip46": {
            "relay": "wss://relay.damus.io",
            "nostrconnect_url": "http://localhost:3000/api/connect/<nostrconnect>"
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(Body::from(serde_json::to_string(&discovery).unwrap()))
        .unwrap()
}
