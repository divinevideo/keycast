use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post, put},
    BoxError, Router,
};
use keycast_core::authorization_channel::AuthorizationSender;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower::{timeout::error::Elapsed, ServiceBuilder};

use crate::api::http::{
    admin, ap, atproto, atproto_oauth, auth, claim, headless, metrics, nostr_rpc, oauth, policies,
    teams,
};
use crate::state::KeycastState;
use axum::response::Json as AxumJson;
use serde_json::Value as JsonValue;

async fn nostr_rpc_timeout_error(error: BoxError) -> axum::response::Response {
    if error.is::<Elapsed>() {
        (
            StatusCode::GATEWAY_TIMEOUT,
            AxumJson(serde_json::json!({ "error": "RPC request timed out" })),
        )
            .into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(serde_json::json!({ "error": "Unhandled RPC service error" })),
        )
            .into_response()
    }
}

// State wrapper to pass state to auth handlers
#[derive(Clone)]
pub struct AuthState {
    pub state: Arc<KeycastState>,
    pub auth_tx: Option<AuthorizationSender>,
}

/// Build API routes - pure JSON endpoints, no HTML
/// Returns unrooted Router that can be nested at any path (e.g., /api, /v1, etc.)
pub fn api_routes(
    pool: PgPool,
    state: Arc<KeycastState>,
    auth_cors: tower_http::cors::CorsLayer,
    public_cors: tower_http::cors::CorsLayer,
    auth_tx: Option<AuthorizationSender>,
) -> Router {
    tracing::debug!("Building routes");

    let auth_state = AuthState { state, auth_tx };

    // Routes that need restricted CORS (first-party only + credentials)
    // These endpoints accept user credentials and must prevent phishing
    let first_party_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/oauth/login", post(oauth::oauth_login))
        .route("/oauth/register", post(oauth::oauth_register))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // Logout route - public CORS so third-party OAuth apps can revoke sessions
    // Protected by Bearer token (UCAN), not cookies
    let logout_route = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(auth_state.clone());

    // verify_email needs auth_state for key_manager (to decrypt keys and issue UCAN)
    let verify_email_route = Router::new()
        // GET is the link target in verification emails: it verifies server-side (no client JS),
        // which is what fixes sandboxed in-app browsers (keycast#262). POST stays for the SPA page.
        .route(
            "/auth/verify-email",
            post(auth::verify_email).get(auth::verify_email_get),
        )
        .with_state(auth_state.clone());

    let email_routes = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/resend-verification", post(auth::resend_verification))
        .route(
            "/auth/confirm-email-change",
            post(auth::confirm_email_change),
        )
        .route("/auth/cancel-email-change", post(auth::cancel_email_change))
        .with_state(pool.clone());

    // OAuth routes (no authentication required for initial authorize request)
    // Public CORS - third parties use authorization_code grant (never see passwords)
    let oauth_routes = Router::new()
        .route("/oauth/auth-status", get(oauth::auth_status))
        .route("/oauth/authorize", get(oauth::authorize_get))
        .route("/oauth/authorize", post(oauth::authorize_post))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/poll", get(oauth::poll)) // iOS PWA polling endpoint
        .route("/oauth/connect", post(oauth::connect_post))
        .layer(public_cors.clone())
        .with_state(auth_state.clone());

    let atproto_oauth_routes = Router::new()
        .route("/atproto/oauth/par", post(atproto_oauth::par))
        .route("/atproto/oauth/authorize", get(atproto_oauth::authorize))
        .route("/atproto/oauth/token", post(atproto_oauth::token))
        .layer(public_cors.clone())
        .with_state(pool.clone());

    // nostr-login connect routes (wildcard path to capture nostrconnect:// URI)
    let connect_routes = Router::new()
        .route("/connect/*nostrconnect", get(oauth::connect_get))
        .with_state(auth_state.clone());

    // Fast signing endpoint (needs AuthState for key_manager access)
    let signing_routes = Router::new()
        .route("/user/sign", post(auth::sign_event))
        .with_state(auth_state.clone());

    // NIP-46 RPC endpoint (OAuth access token auth, public CORS for third-party apps)
    // Backstop only. The handler carries its own 8s bound so timed-out requests
    // still land in the RPC latency histogram with their method label; this
    // layer covers what runs outside the handler (body read, extractors) and
    // sits above that bound so it does not pre-empt the observed path.
    let nostr_rpc_timeout = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(nostr_rpc_timeout_error))
        .layer(tower::timeout::TimeoutLayer::new(Duration::from_secs(10)));

    let nostr_rpc_routes = Router::new()
        .route("/nostr", post(nostr_rpc::nostr_rpc))
        .layer(nostr_rpc_timeout)
        .with_state(auth_state.clone());

    // ActivityPub RSA signing endpoints (service-token OR UCAN auth; tenant from Host)
    // Public CORS: server-to-server (the AP gateway), not browser-credentialed.
    let ap_routes = Router::new()
        .route("/ap/keys", post(ap::create_key))
        .route("/ap/keys/:pubkey", get(ap::get_key))
        .route("/ap/sign", post(ap::sign))
        .with_state(auth_state.clone());

    // Protected user routes (authentication required via UCAN cookie)
    // Need auth_cors (restricted origins + credentials) since they use cookies
    let user_routes = Router::new()
        .route("/user/bunker", get(auth::get_bunker_url))
        .route("/user/pubkey", get(auth::get_pubkey))
        .route("/user/account", get(auth::get_account_status))
        .route("/user/profile", get(auth::get_profile))
        .route("/user/atproto/status", get(atproto::atproto_status))
        .route("/user/sessions", get(auth::list_sessions))
        .route("/user/permissions", get(auth::list_permissions))
        .route("/user/sessions/disconnect", post(auth::disconnect_client))
        .route("/user/atproto/enable", post(atproto::enable_atproto))
        .route("/user/atproto/disable", post(atproto::disable_atproto))
        .route(
            "/account/:pubkey/crosspost",
            put(atproto::account_crosspost),
        )
        .route(
            "/user/verify-password",
            post(auth::verify_password_for_export),
        )
        .route("/user/change-password", post(auth::change_password))
        .route("/user/change-email", post(auth::change_email))
        .layer(auth_cors.clone())
        .with_state(pool.clone());

    let internal_service_routes = Router::new()
        .route(
            "/internal/atproto/state",
            post(atproto::internal_sync_atproto),
        )
        .with_state(pool.clone());

    // Profile update route needs auth_state for key access (divine-name-server NIP-98 auth)
    let profile_update_routes = Router::new()
        .route("/user/profile", post(auth::update_profile))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // Bunker routes (need AuthState for key_manager and auth_tx)
    let bunker_routes = Router::new()
        .route("/user/bunker/create", post(auth::create_bunker))
        .route("/user/sessions/revoke", post(auth::revoke_session))
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // Account deletion - public CORS so third-party OAuth apps can delete accounts
    // Protected by Bearer token (UCAN), not cookies
    let account_delete_route = Router::new()
        .route("/user/account", delete(auth::delete_account))
        .with_state(auth_state.clone());

    // Key export route (needs AuthState for key_manager)
    let key_export_routes = Router::new()
        .route("/user/export-key", post(auth::export_key))
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

    // Headless auth routes (embedded flow for web + native mobile apps)
    // Public CORS - token exchange still requires PKCE for security
    let headless_routes = Router::new()
        .route("/headless/register", post(headless::headless_register))
        .route("/headless/login", post(headless::headless_login))
        .route("/headless/authorize", post(headless::headless_authorize))
        .route("/headless/verify-pin", post(headless::headless_verify_pin))
        .route("/headless/resend-pin", post(headless::headless_resend_pin))
        .with_state(auth_state.clone());

    // Admin routes (for preloaded accounts and claim tokens)
    // Restricted CORS - requires UCAN auth with ALLOWED_PUBKEYS whitelist
    let admin_routes = Router::new()
        .route("/admin/status", get(admin::get_admin_status))
        .route("/admin/token", get(admin::get_admin_token))
        .route("/admin/preload-user", post(admin::preload_user))
        .route("/admin/user-token", post(admin::get_user_token))
        .route(
            "/admin/claim-tokens",
            get(admin::get_claim_token).post(admin::create_claim_token),
        )
        .route(
            "/admin/claim-tokens/batch",
            post(admin::batch_create_claim_tokens),
        )
        .route(
            "/admin/claim-tokens/invalidate",
            post(admin::invalidate_claim_token),
        )
        .route(
            "/admin/claim-tokens/stats",
            get(admin::get_claim_token_stats),
        )
        .route("/admin/auth-debug", get(admin::get_auth_debug))
        .route("/admin/user-lookup", get(admin::get_user_lookup))
        .route(
            "/admin/support-admins",
            get(admin::list_support_admins).post(admin::add_support_admin),
        )
        .route(
            "/admin/support-admins/:pubkey",
            delete(admin::remove_support_admin),
        )
        .route(
            "/admin/registered-clients",
            get(admin::list_registered_clients).post(admin::create_registered_client),
        )
        .route(
            "/admin/registered-clients/test",
            post(admin::test_registered_client_pattern),
        )
        .route(
            "/admin/registered-clients/:id",
            patch(admin::update_registered_client).delete(admin::delete_registered_client),
        )
        .layer(auth_cors.clone())
        .with_state(auth_state.clone());

    // Service-authenticated admin routes (for relay-manager, COOP)
    // Uses KEYCAST_SERVICE_TOKEN Bearer auth, not UCAN
    let service_admin_routes = Router::new()
        .route(
            "/admin/users/:pubkey/status",
            get(admin::get_user_status_admin).put(admin::set_user_status_admin),
        )
        .route(
            "/admin/users/:pubkey/verified-minor",
            delete(admin::clear_verified_minor_admin),
        )
        .route("/admin/users/batch-lookup", post(admin::batch_lookup_users))
        .route(
            "/admin/create-minor-account",
            post(admin::create_minor_account),
        )
        .with_state(auth_state.clone());

    // Claim routes (public, accessed via email link)
    // Users claim preloaded accounts by setting email/password
    let claim_routes = Router::new()
        .route("/claim", get(claim::claim_get).post(claim::claim_post))
        .with_state(auth_state.clone());

    // Prometheus metrics endpoint (public, no auth required)
    // Uses in-memory atomic counters - no database access needed
    let metrics_route = Router::new().route("/metrics", get(metrics::metrics));

    // API documentation route (public)
    let docs_route = Router::new().route("/docs/openapi.json", get(openapi_spec));

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
        .route(
            "/teams/:id/keys/:pubkey/authorizations/:auth_id",
            delete(teams::delete_authorization),
        )
        .route("/teams/:id/policies", post(teams::add_policy))
        .with_state(pool);

    // Combine routes
    // First-party routes have restricted CORS (prevent phishing)
    // Authenticated routes have restricted CORS (need cookies)
    // Public routes have wildcard CORS (third-party safe, no credentials)
    Router::new()
        .merge(first_party_routes) // Has auth_cors (credentials, accepts passwords)
        .merge(user_routes) // Has auth_cors (authenticated, needs cookies)
        .merge(internal_service_routes) // Service-authenticated route, not browser-facing
        .merge(profile_update_routes) // Has auth_cors (needs key_manager for divine-names)
        .merge(bunker_routes) // Has auth_cors (bunker creation)
        .merge(key_export_routes) // Has auth_cors (authenticated, needs cookies)
        .merge(change_key_route) // Has auth_cors (authenticated, needs cookies)
        .merge(logout_route.layer(public_cors.clone())) // Public CORS - Bearer token auth, third-party apps
        .merge(account_delete_route.layer(public_cors.clone())) // Public CORS - Bearer token auth, third-party apps
        .merge(verify_email_route.layer(public_cors.clone())) // Public CORS - same-origin sets cookie, cross-origin uses Bearer
        .merge(email_routes.layer(public_cors.clone()))
        .merge(oauth_routes) // Has public_cors (third-party safe)
        .merge(atproto_oauth_routes)
        .merge(connect_routes.layer(public_cors.clone()))
        .merge(signing_routes.layer(public_cors.clone()))
        .merge(nostr_rpc_routes.layer(public_cors.clone())) // NIP-46 RPC for OAuth apps
        .merge(ap_routes.layer(public_cors.clone())) // AP RSA signing (gateway service-to-service)
        .merge(team_routes.layer(auth_cors.clone())) // Team routes need credentials
        .merge(discovery_route.layer(public_cors.clone()))
        .merge(policy_routes.layer(public_cors.clone())) // Public - available to third-party OAuth apps
        .merge(headless_routes.layer(public_cors.clone())) // Public CORS - embedded flow for web + mobile (PKCE protects token exchange)
        .merge(admin_routes) // Admin routes for preloaded accounts (has auth_cors)
        .merge(service_admin_routes) // Service-token admin routes (no CORS, server-to-server)
        .merge(claim_routes.layer(public_cors.clone())) // Public - claim preloaded accounts
        .merge(metrics_route.layer(public_cors.clone())) // Public - Prometheus metrics
        .merge(docs_route.layer(public_cors))
        .fallback(api_not_found) // Return 404 for unmatched API routes
}

/// Serve OpenAPI specification as JSON
async fn openapi_spec() -> AxumJson<JsonValue> {
    let yaml_content = include_str!("../../../openapi.yaml");
    let spec: JsonValue = serde_yaml::from_str(yaml_content).expect("Failed to parse OpenAPI spec");
    AxumJson(spec)
}

/// Fallback handler for unmatched API routes - returns 404
async fn api_not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Not found")
}

/// NIP-05 discovery endpoint for nostr-login integration
/// This should be mounted at root level in main.rs, not under /api
pub async fn nostr_discovery_public(
    tenant: crate::api::tenant::TenantExtractor,
    axum::extract::State(pool): axum::extract::State<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> impl axum::response::IntoResponse {
    use axum::body::Body;
    use axum::http::{header, StatusCode};
    use axum::response::Response;
    use keycast_core::repositories::UserRepository;

    let tenant_id = tenant.0.id;

    // Check if "name" query parameter is provided
    if let Some(name) = params.get("name") {
        let name_trimmed = name.trim();
        let canonical_name = name_trimmed.to_lowercase();
        // Look up user by username in this tenant (case-insensitive; JSON key is canonical lowercase)
        let user_repo = UserRepository::new(pool.clone());
        let result = if canonical_name.is_empty() {
            None
        } else {
            user_repo
                .find_pubkey_by_username(&canonical_name, tenant_id)
                .await
                .ok()
                .flatten()
        };
        let response = if let Some(pubkey) = result {
            serde_json::json!({
                "names": {
                    canonical_name: pubkey
                }
            })
        } else {
            serde_json::json!({
                "names": {}
            })
        };

        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::from(serde_json::to_string(&response).unwrap()))
            .unwrap();
    }

    // Get relay URL from tenant settings or BUNKER_RELAYS env var
    let relay_url = tenant.0.relay_url();

    // Get API base URL from headers or APP_URL env var
    let api_base_url = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .map(|host| {
            let proto = headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_else(|| {
                    if host.contains(":443") || !host.contains(":") {
                        "https"
                    } else {
                        "http"
                    }
                });
            format!("{}://{}", proto, host)
        })
        .or_else(|| std::env::var("APP_URL").ok())
        .or_else(|| std::env::var("VITE_DOMAIN").ok())
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    // Return default nostr-login discovery info if no name is requested.
    let discovery = serde_json::json!({
        "names": {},
        "nip46": {
            "relay": relay_url,
            "nostrconnect_url": format!("{}/api/connect/<nostrconnect>", api_base_url.trim_end_matches('/'))
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(Body::from(serde_json::to_string(&discovery).unwrap()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn nostr_rpc_timeout_layer_maps_elapsed_to_504() {
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    "ok"
                }),
            )
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(nostr_rpc_timeout_error))
                    .layer(tower::timeout::TimeoutLayer::new(Duration::from_millis(1))),
            );

        let response = app
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .expect("timeout response");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(body["error"], "RPC request timed out");
    }
}
