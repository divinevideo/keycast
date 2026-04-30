// ABOUTME: Unified binary that runs both API server and Signer daemon in one process
// ABOUTME: API uses HttpRpcHandler cache, NIP-46 signer uses Nip46Handler cache

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use cluster_hashring::ClusterCoordinator;
use dotenv::dotenv;
use keycast_api::api::tenant::Tenant;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::TenantCache;
use keycast_core::authorization_channel;
use keycast_core::database::Database;
#[cfg(feature = "aws")]
use keycast_core::encryption::aws_key_manager::AwsKeyManager;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_signer::{RelayQueue, UnifiedSigner};
use moka::future::Cache;
use nostr_sdk::Keys;
use serde_json::json;
use std::env;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::signal;
use tokio::sync::Notify;
use tokio_util::task::TaskTracker;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zeroize::Zeroizing;

/// Maximum time the readiness probe will wait on the database before failing.
/// Kept well under typical kubelet `timeoutSeconds` so a stalled connection
/// fails the probe fast instead of hanging it.
const READYZ_DB_TIMEOUT: Duration = Duration::from_millis(800);

/// Duration the process pauses between flipping the readiness probe to 503
/// and starting to drain accepted connections. This is the window during which
/// Kubernetes observes the failing probe and removes the pod from the Service
/// EndpointSlice so the load balancer stops routing new traffic to us. Keeping
/// this out of the drain budget is critical — otherwise new NIP-46 sign
/// requests arriving during these seconds would be rejected mid-request and
/// trigger client-side reconnect storms on scale-down. Override with
/// `SHUTDOWN_PRE_DRAIN_SECS` (e.g. `0` in local dev / tests).
const DEFAULT_SHUTDOWN_PRE_DRAIN_SECS: u64 = 10;

/// Maximum time we wait for axum to drain in-flight HTTP requests after we
/// stop accepting new connections. The sum of `pre_drain + http_drain +
/// signer_drain` plus ~5–10s of teardown headroom must fit inside the
/// Deployment's `terminationGracePeriodSeconds` — otherwise the kubelet
/// SIGKILLs us mid-drain. Default sized for `terminationGracePeriodSeconds: 75`.
/// Override with `SHUTDOWN_HTTP_DRAIN_SECS`.
const DEFAULT_SHUTDOWN_HTTP_DRAIN_SECS: u64 = 45;

/// Maximum time we wait for the NIP-46 signer + tracked background tasks to
/// finish after we tear down the relay client. Override with
/// `SHUTDOWN_SIGNER_DRAIN_SECS`.
const DEFAULT_SHUTDOWN_SIGNER_DRAIN_SECS: u64 = 10;

/// Conservative upper bound on the Deployment's `terminationGracePeriodSeconds`
/// used at startup to sanity-check the shutdown phase budgets. The iac repo
/// (TODO(#692): track in divinevideo/divine-iac-coreconfig sibling PR) targets
/// 75s but the issue spec accepts 60–90s; 120s covers the full range with
/// headroom. If an operator bumps grace higher they can raise this via
/// `SHUTDOWN_GRACE_PERIOD_CEILING_SECS`. This constant does NOT change the
/// kubelet behavior — it is purely a misconfig guardrail.
const DEFAULT_SHUTDOWN_GRACE_CEILING_SECS: u64 = 120;

/// Headroom reserved between the end of the phased drain and the kubelet
/// SIGKILL for DB pool close, tracing flush, and other post-drain cleanup.
/// Subtracted from the ceiling when validating that the configured phase
/// budgets fit.
const SHUTDOWN_TEARDOWN_MARGIN: Duration = Duration::from_secs(10);

/// Parsed shutdown phase timings. See the `DEFAULT_SHUTDOWN_*` constants and
/// the graceful-shutdown sequence in `async_main` for the phase breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShutdownTimings {
    /// Sleep between setting readiness=503 and closing the accept loop.
    pre_drain: Duration,
    /// Maximum wait for axum HTTP drain.
    http_drain: Duration,
    /// Maximum wait for signer + tracked background tasks.
    signer_drain: Duration,
}

impl ShutdownTimings {
    /// Sum of all three phase durations. Does NOT include
    /// `SHUTDOWN_TEARDOWN_MARGIN` — add that separately when comparing
    /// against a grace-period ceiling.
    fn total_budget(&self) -> Duration {
        self.pre_drain + self.http_drain + self.signer_drain
    }
}

/// Read a non-negative integer duration (in seconds) from the given env var,
/// falling back to `default_secs` if unset or unparseable. Zero is a valid
/// value and is respected (not treated as "use default").
fn parse_duration_secs_env(var: &str, default_secs: u64) -> Duration {
    match env::var(var) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => {
                tracing::warn!(
                    env_var = var,
                    value = %raw,
                    default_secs,
                    "Invalid value for shutdown timing env var; using default"
                );
                Duration::from_secs(default_secs)
            }
        },
        Err(_) => Duration::from_secs(default_secs),
    }
}

/// Parse all three shutdown phase durations from the environment.
fn parse_shutdown_timings() -> ShutdownTimings {
    ShutdownTimings {
        pre_drain: parse_duration_secs_env(
            "SHUTDOWN_PRE_DRAIN_SECS",
            DEFAULT_SHUTDOWN_PRE_DRAIN_SECS,
        ),
        http_drain: parse_duration_secs_env(
            "SHUTDOWN_HTTP_DRAIN_SECS",
            DEFAULT_SHUTDOWN_HTTP_DRAIN_SECS,
        ),
        signer_drain: parse_duration_secs_env(
            "SHUTDOWN_SIGNER_DRAIN_SECS",
            DEFAULT_SHUTDOWN_SIGNER_DRAIN_SECS,
        ),
    }
}

/// Parse the configured `terminationGracePeriodSeconds` ceiling against
/// which the phased shutdown budget is validated at startup. Override with
/// `SHUTDOWN_GRACE_PERIOD_CEILING_SECS` when the Deployment's grace period
/// changes without a keycast release.
fn parse_shutdown_grace_ceiling() -> Duration {
    parse_duration_secs_env(
        "SHUTDOWN_GRACE_PERIOD_CEILING_SECS",
        DEFAULT_SHUTDOWN_GRACE_CEILING_SECS,
    )
}

/// Check that `timings.total_budget() + SHUTDOWN_TEARDOWN_MARGIN <= ceiling`.
/// The margin is the reserved headroom for DB pool close, tracing flush, and
/// process teardown between the end of the phased drain and the kubelet
/// SIGKILL at `terminationGracePeriodSeconds`. Exact equality is accepted
/// (the margin fully fits); anything larger is rejected.
///
/// Returned `Err(String)` is operator-actionable and includes the current
/// budget, margin, and ceiling so it can be dropped straight into a log
/// line. We deliberately warn (not abort) on violation at the call site:
/// the ceiling is cross-repo-coupled to the iac repo, and an operator may
/// legitimately need to boot ahead of an iac-side grace bump.
///
/// TODO(#692): remove the soft-warning fallback in `async_main` once the
/// sibling divinevideo/divine-iac-coreconfig PR lands and `terminationGracePeriodSeconds`
/// is pinned at ≥75s in all environments.
fn validate_shutdown_timings(timings: &ShutdownTimings, ceiling: Duration) -> Result<(), String> {
    let total = timings.total_budget();
    let required = total + SHUTDOWN_TEARDOWN_MARGIN;
    if required > ceiling {
        Err(format!(
            "shutdown phase budget ({total_secs}s) + teardown margin ({margin_secs}s) \
             = {required_secs}s does not fit inside SHUTDOWN_GRACE_PERIOD_CEILING_SECS \
             = {ceiling_secs}s (pre_drain={pre}s, http_drain={http}s, signer_drain={sig}s); \
             the kubelet will SIGKILL mid-drain on terminationGracePeriodSeconds",
            total_secs = total.as_secs(),
            margin_secs = SHUTDOWN_TEARDOWN_MARGIN.as_secs(),
            required_secs = required.as_secs(),
            ceiling_secs = ceiling.as_secs(),
            pre = timings.pre_drain.as_secs(),
            http = timings.http_drain.as_secs(),
            sig = timings.signer_drain.as_secs(),
        ))
    } else {
        Ok(())
    }
}

/// Flip the unready flag (so `/healthz/ready` returns 503) and then sleep for
/// `duration` to give Kubernetes time to remove us from the Service
/// EndpointSlice before we close the accept loop. Must set the flag **before**
/// awaiting anything so the next readiness probe sees the new value.
async fn pre_drain_pause(unready: &Arc<AtomicBool>, duration: Duration) {
    unready.store(true, Ordering::Relaxed);
    if duration > Duration::ZERO {
        tokio::time::sleep(duration).await;
    }
}

/// Result of awaiting the DB pool's close future with the documented
/// teardown margin as an upper bound.
#[derive(Debug)]
enum PoolCloseOutcome {
    /// The pool finished closing before the margin elapsed. The caller can
    /// emit the clean "Graceful shutdown complete" log.
    Completed,
    /// The margin elapsed before the pool finished. The caller logs a
    /// warning and proceeds — the kubelet SIGKILL at
    /// `terminationGracePeriodSeconds` is the final backstop.
    TimedOut,
}

/// Await `close_fut` for up to `margin`. If it finishes in time, return
/// `Completed`; otherwise return `TimedOut`. The close future is dropped on
/// timeout — sqlx's `Pool::close()` is cancellation-safe, and we would not
/// gain anything by continuing to await past the documented margin when the
/// kubelet is about to SIGKILL us anyway.
///
/// This enforces `SHUTDOWN_TEARDOWN_MARGIN` as a real bound on phase 4 so a
/// stuck DB connection (e.g. a preload task mid-query when
/// `task_tracker.wait()` timed out and `signer_handle.abort()` was called
/// but not awaited) cannot block past `terminationGracePeriodSeconds` and
/// swallow the final "Graceful shutdown complete" log.
///
/// Generic over `F: Future<Output = ()>` so we can exercise the timeout
/// behaviour deterministically with `tokio::time::pause` in tests without
/// standing up a real Postgres pool.
async fn close_within_margin<F>(close_fut: F, margin: Duration) -> PoolCloseOutcome
where
    F: std::future::Future<Output = ()>,
{
    match tokio::time::timeout(margin, close_fut).await {
        Ok(()) => PoolCloseOutcome::Completed,
        Err(_) => PoolCloseOutcome::TimedOut,
    }
}

/// Result of awaiting the axum HTTP server's graceful-shutdown future with a
/// bounded budget.
#[derive(Debug)]
enum HttpDrainOutcome {
    /// The server finished its graceful-shutdown future before the budget ran
    /// out. Join errors are logged by the caller but do not change the phase.
    Completed,
    /// The budget expired before the server finished. The task was aborted
    /// and awaited to cancellation; the caller can safely proceed to phase 3
    /// (relay teardown) and phase 4 (DB pool close) without racing a
    /// still-live accept loop.
    AbortedAfterTimeout,
}

/// Await the axum server's `JoinHandle` for up to `budget`. If it finishes
/// in time, return `Completed`. Otherwise call `abort()` on the task,
/// await its cancellation, and return `AbortedAfterTimeout`.
///
/// This exists because dropping a `tokio::task::JoinHandle` does NOT cancel
/// the underlying task — the axum server would keep running concurrently
/// with the relay-teardown and DB-pool-close phases, causing decode errors
/// on late-arriving requests and forcing the kubelet SIGKILL to be the
/// ultimate stop. The abort makes the HTTP drain budget a real bound on
/// axum's lifetime.
async fn drain_http_or_abort(
    mut handle: tokio::task::JoinHandle<()>,
    budget: Duration,
) -> HttpDrainOutcome {
    // `JoinHandle<T>` is `Unpin` and implements `Future<Output = Result<T,
    // JoinError>>`, so `&mut handle` can be awaited by `timeout` without
    // consuming it. This lets us still call `abort()` on the same handle on
    // the timeout path.
    match tokio::time::timeout(budget, &mut handle).await {
        Ok(join_result) => {
            if let Err(e) = join_result {
                tracing::warn!("API server task error: {:?}", e);
            }
            HttpDrainOutcome::Completed
        }
        Err(_) => {
            handle.abort();
            // Await cancellation so we don't return while the accept loop is
            // still being torn down. A cancelled task completes quickly; if
            // it somehow doesn't, the outer kubelet grace period is still
            // the final backstop, so no second timeout here.
            let _ = (&mut handle).await;
            HttpDrainOutcome::AbortedAfterTimeout
        }
    }
}

#[derive(Clone)]
struct LivenessState {
    shutting_down: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ReadinessState {
    pool: sqlx::PgPool,
    shutting_down: Arc<AtomicBool>,
}

fn readiness_response(is_shutting_down: bool, database_ready: bool) -> (StatusCode, &'static str) {
    if is_shutting_down {
        (StatusCode::SERVICE_UNAVAILABLE, "Shutting down")
    } else if database_ready {
        (StatusCode::OK, "OK")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
    }
}

async fn health_check() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({
            "status": "ok",
            "service": "keycast",
        })),
    )
}

async fn livez(state: Arc<LivenessState>) -> impl IntoResponse {
    if state.shutting_down.load(Ordering::Relaxed) {
        (StatusCode::OK, "OK (shutting down)")
    } else {
        (StatusCode::OK, "OK")
    }
}

async fn startupz() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn readyz(state: Arc<ReadinessState>) -> impl IntoResponse {
    let is_shutting_down = state.shutting_down.load(Ordering::Relaxed);
    let database_ready = if is_shutting_down {
        false
    } else {
        // Bound the DB check so a stalled connection or exhausted pool fails
        // the probe fast rather than blocking the kubelet probe past its
        // `timeoutSeconds`. Both timeout and query error => not ready.
        let query = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool);
        matches!(
            tokio::time::timeout(READYZ_DB_TIMEOUT, query).await,
            Ok(Ok(_))
        )
    };

    readiness_response(is_shutting_down, database_ready)
}

/// Run database migrations and exit
/// Used by Kubernetes Jobs to run migrations before app startup
fn run_migrations() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Running database migrations...");

    let database_url =
        env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set for migrations")?;

    // Build minimal runtime just for migrations
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;

        // Run migrations using SQLx's built-in migrator
        // Uses advisory locks to prevent concurrent migrations
        sqlx::migrate!("../database/migrations").run(&pool).await?;

        pool.close().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    println!("✅ Migrations complete!");
    Ok(())
}

/// Inject runtime environment variables into HTML via window.__ENV__
/// Injects a <script> tag before </head> with runtime config
fn inject_runtime_env(html: &str) -> String {
    // Build runtime environment object
    let mut env_obj = json!({});

    // VITE_DOMAIN - API domain for frontend (from APP_URL)
    if let Ok(domain) = env::var("APP_URL") {
        env_obj["VITE_DOMAIN"] = json!(domain);
    }

    // ALLOWED_PUBKEYS - comma-separated admin pubkeys
    if let Ok(pubkeys) = env::var("ALLOWED_PUBKEYS") {
        env_obj["ALLOWED_PUBKEYS"] = json!(pubkeys);
    }

    // SHOW_TEAMS_FUNCTIONALITY - enable teams UI (optional, default: hidden)
    if let Ok(val) = env::var("SHOW_TEAMS_FUNCTIONALITY") {
        env_obj["SHOW_TEAMS_FUNCTIONALITY"] = json!(val);
    }

    // If no env vars to inject, return original HTML
    if env_obj.as_object().is_none_or(|o| o.is_empty()) {
        return html.to_string();
    }

    // Serialize to JSON (serde_json properly escapes)
    let env_json = serde_json::to_string(&env_obj).unwrap_or_else(|_| "{}".to_string());

    // Create injection script
    let injection_script = format!(r#"<script>window.__ENV__={};</script>"#, env_json);

    // Inject before </head> tag, or at the beginning if no </head> found
    if let Some(head_end_pos) = html.rfind("</head>") {
        let mut injected = html[..head_end_pos].to_string();
        injected.push_str(&injection_script);
        injected.push('\n');
        injected.push_str(&html[head_end_pos..]);
        injected
    } else if let Some(body_start_pos) = html.find("<body>") {
        // Fallback: inject before <body> if no </head>
        let mut injected = html[..body_start_pos].to_string();
        injected.push_str(&injection_script);
        injected.push('\n');
        injected.push_str(&html[body_start_pos..]);
        injected
    } else {
        // Last resort: prepend to HTML
        format!("{}\n{}", injection_script, html)
    }
}

fn origin_is_allowed(origin: &str, allowed_origins: &str) -> bool {
    if origin.starts_with("http://localhost:") || origin == "http://localhost" {
        return true;
    }

    allowed_origins
        .split(',')
        .map(|value| value.trim())
        .any(|allowed| origin_matches_allowed_pattern(origin, allowed))
}

fn origin_matches_allowed_pattern(origin: &str, allowed: &str) -> bool {
    if !allowed.contains('*') {
        return origin == allowed;
    }

    let Some((origin_scheme, origin_host)) = parse_origin(origin) else {
        return false;
    };
    let Some((allowed_scheme, allowed_host)) = parse_origin(allowed) else {
        return false;
    };

    if origin_scheme != allowed_scheme {
        return false;
    }

    let Some(host_suffix) = allowed_host.strip_prefix("*.") else {
        return false;
    };

    origin_host.len() > host_suffix.len()
        && origin_host.ends_with(host_suffix)
        && origin_host
            .strip_suffix(host_suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn parse_origin(origin: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = origin.split_once("://")?;
    let host = rest.split('/').next()?;
    Some((scheme, host))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KmsProvider {
    File,
    Gcp,
    Aws,
}

fn resolve_kms_provider() -> Result<KmsProvider, String> {
    let use_gcp_kms = env::var("USE_GCP_KMS").ok().map(|v| v == "true");

    if let Ok(provider) = env::var("KMS_PROVIDER") {
        let resolved_provider = match provider.trim().to_ascii_lowercase().as_str() {
            "file" => Ok(KmsProvider::File),
            "gcp" => Ok(KmsProvider::Gcp),
            "aws" => Ok(KmsProvider::Aws),
            invalid => Err(format!(
                "KMS_PROVIDER must be one of: file, gcp, aws (got '{}')",
                invalid
            )),
        }?;

        if let Some(use_gcp) = use_gcp_kms {
            let legacy_provider = if use_gcp {
                KmsProvider::Gcp
            } else {
                KmsProvider::File
            };

            if legacy_provider != resolved_provider {
                tracing::warn!(
                    kms_provider = kms_provider_label(resolved_provider),
                    use_gcp_kms = use_gcp,
                    legacy_provider = kms_provider_label(legacy_provider),
                    "KMS_PROVIDER and USE_GCP_KMS disagree; using KMS_PROVIDER as source of truth"
                );
            }
        }

        return Ok(resolved_provider);
    }

    if use_gcp_kms.unwrap_or(false) {
        Ok(KmsProvider::Gcp)
    } else {
        Ok(KmsProvider::File)
    }
}

fn kms_provider_label(provider: KmsProvider) -> &'static str {
    match provider {
        KmsProvider::File => "file",
        KmsProvider::Gcp => "gcp",
        KmsProvider::Aws => "aws",
    }
}

async fn build_key_manager(
    kms_provider: KmsProvider,
) -> Result<Box<dyn KeyManager>, Box<dyn std::error::Error>> {
    match kms_provider {
        KmsProvider::File => Ok(Box::new(FileKeyManager::new()?)),
        KmsProvider::Gcp => Ok(Box::new(GcpKeyManager::new().await?)),
        KmsProvider::Aws => {
            #[cfg(feature = "aws")]
            {
                Ok(Box::new(AwsKeyManager::new().await?))
            }
            #[cfg(not(feature = "aws"))]
            {
                Err("KMS_PROVIDER=aws but keycast was built without --features aws".into())
            }
        }
    }
}

/// Serve Apple App Site Association file with correct content type
async fn apple_app_site_association(
    axum::extract::State(web_build_dir): axum::extract::State<String>,
) -> impl IntoResponse {
    let path = PathBuf::from(&web_build_dir).join(".well-known/apple-app-site-association");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

/// Serve Android Asset Links file with correct content type
async fn assetlinks_json(
    axum::extract::State(web_build_dir): axum::extract::State<String>,
) -> impl IntoResponse {
    let path = PathBuf::from(&web_build_dir).join(".well-known/assetlinks.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

/// Middleware to set Cache-Control headers for static assets
/// Browser caching reduces load and improves performance
async fn cache_control_middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;

    // Don't overwrite if route already set Cache-Control
    if response.headers().contains_key(header::CACHE_CONTROL) {
        return response;
    }

    let cache_value = if path.starts_with("/_app/") {
        // SvelteKit hash-versioned assets - cache forever (1 year)
        "public, max-age=31536000, immutable"
    } else if path.starts_with("/api/") || path.starts_with("/health") || path == "/livez" {
        // Dynamic content - no caching
        // (`/health`, `/healthz/startup`, `/healthz/ready` all match `/health`;
        //  `/livez` is the only probe route not under that prefix.)
        "no-store"
    } else if path == "/index.html" || path == "/" {
        // SPA entry - must revalidate to get latest app
        "public, max-age=0, must-revalidate"
    } else if path.starts_with("/.well-known/") || path == "/site.webmanifest" {
        // Config files - cache 24 hours
        "public, max-age=86400"
    } else if path.starts_with("/dist/") || path.starts_with("/examples/") {
        // Dev bundles - cache 1 hour
        "public, max-age=3600"
    } else if path.ends_with(".png") || path.ends_with(".ico") || path.ends_with(".svg") {
        // Static images - cache 30 days
        "public, max-age=2592000"
    } else {
        // Default for other static files (HTML fallback via SPA)
        "public, max-age=0, must-revalidate"
    };

    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, cache_value.parse().unwrap());

    response
}

/// Validate required environment variables at startup
fn validate_environment() -> Result<(), String> {
    let mut errors = Vec::new();

    // Required variables
    if env::var("DATABASE_URL").is_err() {
        errors.push("DATABASE_URL must be set (PostgreSQL connection string)");
    }

    if env::var("ALLOWED_ORIGINS").is_err() {
        errors.push("ALLOWED_ORIGINS must be set (comma-separated CORS origins)");
    }

    if env::var("SERVER_NSEC").is_err() {
        errors.push("SERVER_NSEC must be set (server's Nostr secret key for signing UCANs)");
    }

    if env::var("REDIS_URL").is_err() {
        errors.push("REDIS_URL must be set (Redis/Memorystore URL for cluster coordination)");
    }

    let kms_provider = resolve_kms_provider()?;
    match kms_provider {
        KmsProvider::File => {
            if env::var("MASTER_KEY_PATH").is_err() {
                errors.push("MASTER_KEY_PATH must be set when KMS_PROVIDER=file");
            }
        }
        KmsProvider::Gcp => {
            if env::var("GCP_PROJECT_ID").is_err() {
                errors.push("GCP_PROJECT_ID must be set when KMS_PROVIDER=gcp");
            }
        }
        KmsProvider::Aws => {
            if env::var("AWS_KMS_KEY_ID").is_err() {
                errors.push("AWS_KMS_KEY_ID must be set when KMS_PROVIDER=aws");
            }
            #[cfg(not(feature = "aws"))]
            {
                errors.push("KMS_PROVIDER=aws requires building keycast with --features aws");
            }
        }
    }

    // Tenant isolation configuration
    let has_allowed_domains = env::var("ALLOWED_TENANT_DOMAINS").is_ok();
    let has_auto_provisioning = env::var("ENABLE_TENANT_AUTO_PROVISIONING")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !has_allowed_domains && !has_auto_provisioning {
        tracing::warn!(
            "Neither ALLOWED_TENANT_DOMAINS nor ENABLE_TENANT_AUTO_PROVISIONING is configured. \
             All requests from unknown domains will be rejected. \
             Set ALLOWED_TENANT_DOMAINS for production or ENABLE_TENANT_AUTO_PROVISIONING=true for development."
        );
    }

    if has_auto_provisioning && !has_allowed_domains {
        tracing::warn!(
            "ENABLE_TENANT_AUTO_PROVISIONING=true without ALLOWED_TENANT_DOMAINS. \
             Any valid domain can auto-create a tenant. This should only be used in development."
        );
    }

    // Docker deployment requires additional vars
    if env::var("POSTGRES_PASSWORD").is_err() {
        // Only required for docker-compose, so just warn
        tracing::warn!("POSTGRES_PASSWORD not set (required for docker-compose deployments)");
    }

    // Validate email configuration (fail-closed in production)
    if let Err(e) = keycast_api::email_service::create_email_sender() {
        errors.push(Box::leak(e.into_boxed_str()));
    }

    warn_atproto_control_plane_config();

    if !errors.is_empty() {
        return Err(format!(
            "Missing required environment variables:\n  - {}\n\nSee .env.example for configuration guide.",
            errors.join("\n  - ")
        ));
    }

    Ok(())
}

fn warn_atproto_control_plane_config() {
    let configured = env::var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(url) = configured else {
        warn_atproto_control_plane_config_issue(
            "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL is not set; ATProto provisioning endpoints will return a scoped unavailable response",
        );
        return;
    };

    if let Err(error) = keycast_api::atproto_provisioning::validate_control_plane_base_url(&url) {
        warn_atproto_control_plane_config_issue(&format!(
            "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL {error}; ATProto provisioning endpoints will return a scoped unavailable response"
        ));
    }
}

fn warn_atproto_control_plane_config_issue(message: &str) {
    tracing::warn!("{}", message);
    eprintln!("Configuration warning: {message}");
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, initiating graceful shutdown"),
        _ = terminate => tracing::info!("Received SIGTERM, initiating graceful shutdown"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure panics in any thread (including spawned tasks) kill the process
    // This prevents the server from running in a broken state
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(1);
    }));

    dotenv().ok();

    // Check for --migrate flag (run migrations and exit)
    if std::env::args().any(|arg| arg == "--migrate") {
        return run_migrations();
    }

    // Use tokio default: 1 worker thread per CPU core
    // Override with TOKIO_WORKER_THREADS env var if needed
    let worker_threads = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(num_cpus::get);

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?
        .block_on(async_main(worker_threads))
}

async fn async_main(worker_threads: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n================================================");
    println!("🔑 Keycast Unified Service Starting...");
    println!("   Running API + Signer in single process");
    println!("   Tokio worker threads: {}", worker_threads);
    println!("================================================\n");

    // Validate environment variables before proceeding
    if let Err(e) = validate_environment() {
        eprintln!("\n❌ Configuration Error:\n{}\n", e);
        std::process::exit(1);
    }

    // Initialize tracing with JSON format in production for GCP Cloud Logging
    let is_production = std::env::var("NODE_ENV").unwrap_or_default() == "production";
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if is_production {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // Log instance capacity info for distributed tracing
    // Initialize global instance ID (combines revision + unique UUID)
    let instance_id = keycast_core::instance::instance_id();
    let cpu_count = num_cpus::get();
    let pool_size = env::var("SQLX_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);

    tracing::info!(
        event = "instance_startup",
        instance_id = %instance_id,
        cpu_count = cpu_count,
        worker_threads = worker_threads,
        pool_size = pool_size,
        "Instance starting: id={} cpus={} workers={} pool={}",
        instance_id, cpu_count, worker_threads, pool_size
    );

    // Validate the shutdown phase budget against the configured grace-period
    // ceiling as a startup-time sanity check. This is defense in depth against
    // (a) an operator setting e.g. `SHUTDOWN_HTTP_DRAIN_SECS=120` against a
    // 75s grace period and (b) the sibling divinevideo/divine-iac-coreconfig
    // PR (tracked in issue #692) landing with `terminationGracePeriodSeconds`
    // below the configured defaults. We log a loud warning rather than
    // refusing to boot: the ceiling is cross-repo-coupled, and an operator
    // may legitimately need to start before the iac repo catches up.
    // TODO(#692): remove the warn-only fallback once the iac-side PR pins
    // `terminationGracePeriodSeconds` to ≥75s in every environment.
    {
        let startup_timings = parse_shutdown_timings();
        let grace_ceiling = parse_shutdown_grace_ceiling();
        match validate_shutdown_timings(&startup_timings, grace_ceiling) {
            Ok(()) => {
                tracing::info!(
                    pre_drain_secs = startup_timings.pre_drain.as_secs(),
                    http_drain_secs = startup_timings.http_drain.as_secs(),
                    signer_drain_secs = startup_timings.signer_drain.as_secs(),
                    grace_ceiling_secs = grace_ceiling.as_secs(),
                    "Shutdown phase budget fits inside configured grace ceiling"
                );
            }
            Err(err) => {
                tracing::warn!(
                    event = "shutdown_budget_exceeds_grace_ceiling",
                    pre_drain_secs = startup_timings.pre_drain.as_secs(),
                    http_drain_secs = startup_timings.http_drain.as_secs(),
                    signer_drain_secs = startup_timings.signer_drain.as_secs(),
                    grace_ceiling_secs = grace_ceiling.as_secs(),
                    "{}",
                    err
                );
            }
        }
    }

    // Setup database
    let database = Database::new().await?;
    tracing::info!("✔︎ Database initialized");

    // Initialize cluster coordination with Redis/Valkey (Pub/Sub mode)
    // This handles instance registration, membership detection, and heartbeats
    // Uses Redis Pub/Sub for instant membership updates
    // Supports GCP Memorystore Valkey with IAM authentication
    let redis_url = env::var("REDIS_URL")?; // Validated above
    let redis_prefix = env::var("REDIS_KEY_PREFIX").ok();
    let use_valkey_iam =
        env::var("USE_VALKEY_IAM").unwrap_or_else(|_| "false".to_string()) == "true";

    let coordinator = Arc::new(
        ClusterCoordinator::start_with_config(&redis_url, redis_prefix.as_deref(), use_valkey_iam)
            .await?,
    );
    let instance_id = coordinator.instance_id();
    tracing::info!(
        "✔︎ Cluster coordinator started: {} ({}{})",
        instance_id,
        if use_valkey_iam {
            "Valkey IAM"
        } else {
            "Redis Pub/Sub"
        },
        redis_prefix
            .as_ref()
            .map(|p| format!(", prefix: {}", p))
            .unwrap_or_default()
    );

    // Create Redis connection for API using coordinator's factory (shares IAM auth)
    let factory = coordinator.factory();
    let redis_conn = factory.get_connection_manager().await?;
    let prefixed_redis =
        keycast_api::PrefixedRedis::new_with_factory(redis_conn, factory, redis_prefix);
    tracing::info!(
        "✔︎ Redis connection for API initialized{}",
        if use_valkey_iam {
            " (IAM auth enabled)"
        } else {
            ""
        }
    );

    // Setup key managers (one for signer, one for API - they're cheap to create)
    let kms_provider =
        resolve_kms_provider().map_err(|e| format!("Invalid KMS provider configuration: {}", e))?;
    tracing::info!(
        "Using {} KMS provider for encryption",
        kms_provider_label(kms_provider)
    );

    let signer_key_manager: Box<dyn KeyManager> = build_key_manager(kms_provider).await?;
    let api_key_manager: Box<dyn KeyManager> = build_key_manager(kms_provider).await?;

    // Load server keys for signing UCANs (wrap in Zeroizing for auto-zeroization)
    let server_nsec = Zeroizing::new(env::var("SERVER_NSEC")?); // Validated above
    let server_keys = Keys::parse(&server_nsec).map_err(|e| {
        format!(
            "Invalid SERVER_NSEC: {}. Must be valid hex (64 chars) or nsec bech32.",
            e
        )
    })?;
    // server_nsec is zeroized here when dropped
    tracing::info!(
        "✔︎ Server keys loaded (pubkey: {})",
        server_keys.public_key().to_hex()
    );

    // Create authorization channel for instant communication between API and Signer
    let (auth_tx, auth_rx) = authorization_channel::create_channel();
    tracing::info!(
        "✔︎ Authorization channel created (buffer size: {})",
        authorization_channel::CHANNEL_BUFFER_SIZE
    );

    // Create signer (relay connections deferred to background task for faster startup)
    let mut signer = UnifiedSigner::new(
        database.pool.clone(),
        signer_key_manager,
        auth_rx,
        coordinator.clone(),
    )
    .await?;
    signer.load_authorizations().await?;
    // Note: connect_to_relays() moved to signer daemon task to allow HTTP server to bind faster

    // Create relay queue for bounded concurrency on NIP-46 relay requests
    // Queue (4096) buffers relay events; workers control processing rate
    let relay_queue = RelayQueue::new();
    let relay_sender = relay_queue.sender();
    signer.set_relay_sender(relay_sender);

    // Spawn relay workers for NIP-46 request processing
    // Worker count balances throughput vs CPU contention with HTTP RPC
    // Can override with RELAY_WORKER_COUNT env var
    let num_workers = std::env::var("RELAY_WORKER_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| num_cpus::get().max(4) * 2);
    let _relay_worker_handles = relay_queue.spawn_workers(
        num_workers,
        signer.handlers(),
        signer.client(),
        signer.pool(),
        signer.key_manager(),
        signer.coordinator(),
    );
    tracing::info!(
        "✔︎ Signer daemon initialized (Tokio workers: {}, relay workers: {}, queue: 4096)",
        worker_threads,
        num_workers
    );

    // Create tenant cache (preload deferred to background task for faster startup)
    let tenant_cache: TenantCache = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(3600))
        .build();
    tracing::info!("✔︎ Tenant cache initialized (preload deferred)");

    // Create bcrypt queue for async password hashing during registration
    // Uses email verification latency as natural buffer for CPU-intensive work
    let bcrypt_queue = keycast_api::bcrypt_queue::BcryptQueue::new();
    let bcrypt_sender = bcrypt_queue.sender();
    let _bcrypt_worker_handles = bcrypt_queue.spawn_workers(database.pool.clone());
    let _bcrypt_cleanup_handle =
        keycast_api::bcrypt_queue::spawn_cleanup_task(database.pool.clone());
    tracing::info!(
        "✔︎ Bcrypt queue initialized ({} workers, cleanup every 5min)",
        num_cpus::get()
    );

    // Create secret pool for instant authorization creation
    // Background producer pre-computes (secret, bcrypt_hash) pairs
    let secret_pool = keycast_core::secret_pool::SecretPool::default();
    let secret_pool_receiver = secret_pool.receiver();
    let _secret_pool_producer = secret_pool.spawn_producer();
    tracing::info!("✔︎ Secret pool initialized (capacity: 100, bcrypt cost: 10)");

    // Create API state with http_handler_cache for on-demand loading
    // Note: api no longer depends on signer's handler cache (decoupled)
    let api_state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(api_key_manager),
        signer_handlers: None, // Deprecated: api uses http_handler_cache with on-demand loading
        http_handler_cache: new_http_handler_cache(),
        server_keys,
        tenant_cache,
        bcrypt_sender,
        redis: Some(prefixed_redis),
        secret_pool: secret_pool_receiver,
    });

    // Set global state for routes that use it
    keycast_api::state::KEYCAST_STATE
        .set(api_state.clone())
        .ok();

    // Get API port (default 3000)
    let api_port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    // Set up static file directories
    let root_dir = env!("CARGO_MANIFEST_DIR");

    // Use WEB_BUILD_DIR if set, otherwise use web/build for dev
    let web_build_dir = env::var("WEB_BUILD_DIR").unwrap_or_else(|_| {
        PathBuf::from(root_dir)
            .parent()
            .unwrap()
            .join("web/build")
            .to_string_lossy()
            .to_string()
    });

    tracing::info!("✔︎ Serving web frontend from: {}", web_build_dir);

    // CORS configuration
    use tower_http::cors::AllowOrigin;

    let allowed_origins_str = env::var("ALLOWED_ORIGINS")?; // Validated above
    let allowed_origins_for_closure = allowed_origins_str.clone();

    let auth_cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let origin_str = origin.to_str().unwrap_or("");
            origin_is_allowed(origin_str, &allowed_origins_for_closure)
        }))
        .allow_methods([
            axum::http::Method::POST,
            axum::http::Method::GET,
            axum::http::Method::OPTIONS,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(86400));

    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(false)
        .max_age(std::time::Duration::from_secs(86400));

    let shutting_down = Arc::new(AtomicBool::new(false));
    let livez_state = Arc::new(LivenessState {
        shutting_down: shutting_down.clone(),
    });
    let readyz_state = Arc::new(ReadinessState {
        pool: database.pool.clone(),
        shutting_down: shutting_down.clone(),
    });

    // Get pure API routes (JSON endpoints only) - pass authorization sender
    let api_routes = keycast_api::api::http::routes::api_routes(
        database.pool.clone(),
        api_state.clone(),
        auth_cors,
        public_cors,
        Some(auth_tx),
    );

    // Serve examples directory (only in development)
    let enable_examples = env::var("ENABLE_EXAMPLES")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Routes for Apple/Android app association files (with correct content type)
    let well_known_routes = Router::new()
        .route(
            "/apple-app-site-association",
            get(apple_app_site_association),
        )
        .route("/assetlinks.json", get(assetlinks_json))
        .route(
            "/oauth-authorization-server",
            get(keycast_api::api::http::atproto_oauth_metadata::authorization_server_metadata),
        )
        .with_state(web_build_dir.clone());

    let mut app = Router::new()
        // Health checks at root level (for k8s/Cloud Run)
        .route("/health", get(health_check))
        .route("/livez", get(move || livez(livez_state.clone())))
        .route("/healthz/startup", get(startupz))
        .route("/healthz/ready", get(move || readyz(readyz_state.clone())))
        // NIP-05 discovery at root level
        .route(
            "/.well-known/nostr.json",
            get(keycast_api::api::http::nostr_discovery_public),
        )
        .with_state(database.pool.clone())
        // Apple/Android app association files
        .nest("/.well-known", well_known_routes)
        // All API endpoints under /api prefix
        .nest("/api", api_routes);

    // Only serve examples when enabled
    if enable_examples {
        // In Docker, examples are at /app/examples; in dev, relative to workspace root
        let examples_path = if PathBuf::from("/app/examples").exists() {
            PathBuf::from("/app/examples")
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("examples")
        };
        tracing::info!(
            "✔︎ Examples directory enabled at /examples (serving from {:?})",
            examples_path
        );
        app = app.nest_service("/examples", ServeDir::new(&examples_path));

        // Serve keycast-client dist for examples (IIFE bundle)
        let client_dist_path = if PathBuf::from("/app/packages/keycast-client/dist").exists() {
            PathBuf::from("/app/packages/keycast-client/dist")
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("packages/keycast-client/dist")
        };
        if client_dist_path.exists() {
            tracing::info!(
                "✔︎ Keycast client served at /dist (from {:?})",
                client_dist_path
            );
            app = app.nest_service("/dist", ServeDir::new(&client_dist_path));
        }
    }

    // SvelteKit frontend - explicitly handle root and index.html with injection
    // This ensures index.html always goes through injection, not served as static file
    let index_path = PathBuf::from(&web_build_dir).join("index.html");
    let index_path_for_root = index_path.clone();
    let index_path_for_index = index_path.clone();

    // Handler that injects runtime env vars into index.html
    let inject_handler = move || {
        let index_path = index_path_for_root.clone();
        async move {
            match tokio::fs::read_to_string(&index_path).await {
                Ok(content) => {
                    // Inject runtime environment variables into HTML
                    let injected_content = inject_runtime_env(&content);
                    Html(injected_content).into_response()
                }
                Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
            }
        }
    };

    let inject_handler_index = move || {
        let index_path = index_path_for_index.clone();
        async move {
            match tokio::fs::read_to_string(&index_path).await {
                Ok(content) => {
                    // Inject runtime environment variables into HTML
                    let injected_content = inject_runtime_env(&content);
                    Html(injected_content).into_response()
                }
                Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
            }
        }
    };

    // Explicitly route root and index.html to injection handler
    let app = app
        .route("/", axum::routing::get(inject_handler))
        .route("/index.html", axum::routing::get(inject_handler_index));

    // Serve other static files, with fallback for SPA routes (non-file routes)
    let web_build_dir_for_fallback = web_build_dir.clone();
    let index_path_for_fallback = PathBuf::from(&web_build_dir).join("index.html");
    let app = app.fallback_service(ServeDir::new(&web_build_dir).fallback(axum::routing::get(
        move || {
            let index_path = index_path_for_fallback.clone();
            let _web_build_dir = web_build_dir_for_fallback.clone();
            async move {
                match tokio::fs::read_to_string(&index_path).await {
                    Ok(content) => {
                        // Inject runtime environment variables into HTML
                        let injected_content = inject_runtime_env(&content);
                        Html(injected_content).into_response()
                    }
                    Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
                }
            }
        },
    )));

    // Add request tracing with trace_id for debugging
    // TraceLayer creates a span for each request with method, uri, and trace_id
    // All logs within the request will automatically include these fields
    let app = app.layer(
        TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
            let trace_id = keycast_api::api::http::auth_observability::request_context(request)
                .map(|context| context.request_id.clone())
                .or_else(|| {
                    keycast_api::api::http::auth_observability::request_id_from_headers(
                        request.headers(),
                    )
                })
                .unwrap_or_else(|| "missing-request-id".to_string());

            tracing::span!(
                Level::INFO,
                "request",
                method = %request.method(),
                uri = %request.uri(),
                trace_id = %trace_id,
            )
        }),
    );

    let app = app.layer(middleware::from_fn(
        keycast_api::api::http::auth_observability::request_id_middleware,
    ));

    // Add Cache-Control headers for browser caching
    let app = app.layer(middleware::from_fn(cache_control_middleware));

    // Try dual-stack [::] first (accepts both IPv4 and IPv6), fall back to 0.0.0.0
    let dual_stack_addr = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, api_port));
    let ipv4_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, api_port));
    tracing::info!("✔︎ API server ready on port {}", api_port);

    // Setup graceful shutdown with TaskTracker for background tasks
    let shutdown_signal = Arc::new(Notify::new());
    let shutdown_for_api = shutdown_signal.clone();
    let client_for_shutdown = signer.client();
    let pool_for_shutdown = database.pool.clone();
    let task_tracker = TaskTracker::new();

    // Spawn API server with graceful shutdown
    let api_handle = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(dual_stack_addr).await {
            Ok(l) => {
                tracing::info!(
                    "🌐 API server listening on {} (dual-stack)",
                    dual_stack_addr
                );
                l
            }
            Err(_) => {
                tracing::info!(
                    "🌐 API server listening on {} (IPv4-only, IPv6 unavailable)",
                    ipv4_addr
                );
                tokio::net::TcpListener::bind(ipv4_addr)
                    .await
                    .expect("Failed to bind API server")
            }
        };
        axum::serve(listener, app)
            .tcp_nodelay(true)
            .with_graceful_shutdown(async move {
                shutdown_for_api.notified().await;
            })
            .await
            .unwrap();
    });

    // Spawn Signer daemon task (connects to relays in background for faster startup)
    let signer_handle = task_tracker.spawn(async move {
        let mut signer = signer;
        // Connect to relays in background (deferred from startup for faster health checks)
        if let Err(e) = signer.connect_to_relays().await {
            tracing::error!("Failed to connect to relays: {}", e);
        }
        tracing::info!("🤙 Signer daemon ready, listening for NIP-46 requests");
        signer.run().await.unwrap();
    });

    // Spawn tenant cache preload task (deferred from startup for faster health checks)
    let tenant_pool = database.pool.clone();
    let tenant_cache_for_preload = api_state.tenant_cache.clone();
    task_tracker.spawn(async move {
        let tenants: Vec<Tenant> = sqlx::query_as(
            "SELECT id, domain, name, settings, created_at, updated_at FROM tenants",
        )
        .fetch_all(&tenant_pool)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to preload tenants: {}", e);
            vec![]
        });

        for tenant in tenants {
            let domain = tenant.domain.clone();
            tenant_cache_for_preload
                .insert(domain.clone(), Arc::new(tenant))
                .await;
        }
        tracing::info!(
            "✔︎ Tenant cache preloaded ({} tenants)",
            tenant_cache_for_preload.entry_count()
        );
    });

    // Note: Heartbeat and hashring coordination is now handled internally by ClusterCoordinator
    // via Redis Pub/Sub for instant updates and 30s heartbeat for crash detection

    println!("✨ Unified service running!");
    println!("   API: http://0.0.0.0:{}", api_port);
    println!("   Signer: NIP-46 relay listener active");
    println!(
        "   Tokio workers: {}, relay workers: {} (queue: 4096)",
        worker_threads, num_workers
    );
    println!(
        "   Instance: {} (cluster-hashring Redis Pub/Sub enabled)",
        instance_id
    );
    println!("   HTTP handler cache: on-demand loading enabled\n");

    // Wait for shutdown signal
    wait_for_shutdown_signal().await;

    // --- Graceful shutdown ---
    //
    // Phase ordering matters. On scale-down events Kubernetes sends SIGTERM
    // and *also* starts removing the pod from the Service EndpointSlice based
    // on the readiness probe, but endpoint-slice propagation is asynchronous.
    // If we stop accepting connections the instant we see SIGTERM, the LB may
    // still be routing new NIP-46 / HTTP requests to us for several seconds
    // and those requests fail mid-flight — the exact client-reconnect storm
    // that issue #692 targets.
    //
    // So the sequence is:
    //   1. Flip `/healthz/ready` to 503 and sleep `pre_drain`. Kubelet observes
    //      the failing probe; the Service controller removes us from endpoints.
    //   2. Stop accepting new HTTP connections (axum `.with_graceful_shutdown`
    //      future resolves) and wait up to `http_drain` for in-flight requests.
    //   3. Tear down the NIP-46 relay client (which stops `signer.run()` and
    //      drains the relay worker queue) and wait up to `signer_drain` for
    //      tracked background tasks.
    //   4. Close the DB pool.
    //
    // Sum of `pre_drain + http_drain + signer_drain` + DB-pool-close headroom
    // must fit inside the Deployment's `terminationGracePeriodSeconds` or the
    // kubelet SIGKILLs us mid-drain.
    let timings = parse_shutdown_timings();
    let shutdown_started_at = std::time::Instant::now();
    tracing::info!(
        pre_drain_secs = timings.pre_drain.as_secs(),
        http_drain_secs = timings.http_drain.as_secs(),
        signer_drain_secs = timings.signer_drain.as_secs(),
        "Graceful shutdown: starting pre-drain phase (readiness now 503)"
    );

    // Phase 1: flip readiness and sleep so K8s can remove us from the Service
    // endpoints before we stop accepting.
    pre_drain_pause(&shutting_down, timings.pre_drain).await;

    // Phase 2: tell axum to stop accepting new HTTP connections and wait for
    // in-flight requests to finish.
    shutdown_signal.notify_waiters();
    // Close task tracker to prevent new tracked tasks from being spawned.
    task_tracker.close();

    tracing::info!(
        elapsed_secs = shutdown_started_at.elapsed().as_secs(),
        "Graceful shutdown: draining HTTP (axum with_graceful_shutdown)"
    );
    match drain_http_or_abort(api_handle, timings.http_drain).await {
        HttpDrainOutcome::Completed => {}
        HttpDrainOutcome::AbortedAfterTimeout => {
            // Axum did not finish its graceful-shutdown future in time, so
            // we aborted the task. Log at warn — this means either (a) a
            // handler hung for longer than the drain budget, or (b) there
            // are stuck upstream connections. Either way, phase 3 (relay
            // teardown) and phase 4 (DB pool close) can now proceed
            // without racing a still-live accept loop.
            tracing::warn!(
                http_drain_secs = timings.http_drain.as_secs(),
                "API server shutdown timed out; axum task aborted to prevent DB pool close from racing late requests"
            );
        }
    }

    // Phase 3: tear down the relay client (stops signer.run() subscription)
    // and wait for signer + other tracked tasks. We do this **after** HTTP
    // drain so NIP-46 requests that arrived before SIGTERM have a chance to
    // complete and publish responses back to the requesting client before we
    // disconnect from the relays. `ClusterCoordinator` will be dropped
    // automatically on return, triggering deregister.
    tracing::info!(
        elapsed_secs = shutdown_started_at.elapsed().as_secs(),
        "Graceful shutdown: tearing down NIP-46 relay client"
    );
    client_for_shutdown.shutdown().await;

    match tokio::time::timeout(timings.signer_drain, task_tracker.wait()).await {
        Ok(()) => {
            tracing::info!("All tracked tasks completed");
        }
        Err(_) => {
            tracing::warn!(
                signer_drain_secs = timings.signer_drain.as_secs(),
                "Task tracker wait timed out, aborting signer"
            );
            signer_handle.abort();
        }
    }

    // Phase 4: close database pool. Bounded by SHUTDOWN_TEARDOWN_MARGIN so
    // a connection stuck in a long-running query (e.g. a tenant-cache
    // preload task mid-query when task_tracker.wait() timed out and
    // signer_handle.abort() was called but not awaited) cannot block past
    // the kubelet SIGKILL and swallow the final "Graceful shutdown
    // complete" log. sqlx's Pool::close is cancellation-safe, so dropping
    // the future on timeout is safe.
    match close_within_margin(pool_for_shutdown.close(), SHUTDOWN_TEARDOWN_MARGIN).await {
        PoolCloseOutcome::Completed => {
            tracing::info!(
                total_shutdown_secs = shutdown_started_at.elapsed().as_secs(),
                "Graceful shutdown complete"
            );
        }
        PoolCloseOutcome::TimedOut => {
            tracing::warn!(
                total_shutdown_secs = shutdown_started_at.elapsed().as_secs(),
                teardown_margin_secs = SHUTDOWN_TEARDOWN_MARGIN.as_secs(),
                "Graceful shutdown complete with warning: DB pool close exceeded teardown margin; stuck checked-out connections were dropped"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request, StatusCode},
        routing::get,
        Router,
    };
    use keycast_api::api::http::auth_observability::request_id_middleware;
    use serial_test::serial;
    use tower::ServiceExt;

    fn set_minimal_valid_environment() {
        std::env::set_var(
            "DATABASE_URL",
            "postgres://postgres:password@localhost/keycast_test",
        );
        std::env::set_var("ALLOWED_ORIGINS", "http://localhost:5173");
        std::env::set_var("SERVER_NSEC", "a".repeat(64));
        std::env::set_var("REDIS_URL", "redis://localhost:16379");
        std::env::set_var("KMS_PROVIDER", "file");
        std::env::set_var("MASTER_KEY_PATH", "./master.key");
        std::env::set_var("DISABLE_EMAILS", "true");
    }

    fn clear_minimal_valid_environment() {
        for key in [
            "DATABASE_URL",
            "ALLOWED_ORIGINS",
            "SERVER_NSEC",
            "REDIS_URL",
            "KMS_PROVIDER",
            "MASTER_KEY_PATH",
            "DISABLE_EMAILS",
            "NODE_ENV",
            "RUST_ENV",
            "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_legacy_file_default() {
        std::env::remove_var("KMS_PROVIDER");
        std::env::set_var("USE_GCP_KMS", "false");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::File);

        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_legacy_gcp_fallback() {
        std::env::remove_var("KMS_PROVIDER");
        std::env::set_var("USE_GCP_KMS", "true");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::Gcp);

        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_explicit_aws() {
        std::env::set_var("KMS_PROVIDER", "aws");
        std::env::set_var("USE_GCP_KMS", "false");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::Aws);

        std::env::remove_var("KMS_PROVIDER");
        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_prefers_explicit_over_legacy() {
        std::env::set_var("KMS_PROVIDER", "file");
        std::env::set_var("USE_GCP_KMS", "true");

        let provider = resolve_kms_provider().expect("Failed to resolve kms provider");
        assert_eq!(provider, KmsProvider::File);

        std::env::remove_var("KMS_PROVIDER");
        std::env::remove_var("USE_GCP_KMS");
    }

    #[test]
    #[serial]
    fn test_resolve_kms_provider_rejects_invalid_value() {
        std::env::set_var("KMS_PROVIDER", "invalid");
        let result = resolve_kms_provider();
        assert!(result.is_err());
        std::env::remove_var("KMS_PROVIDER");
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_missing_atproto_control_plane_in_production() {
        set_minimal_valid_environment();
        std::env::set_var("NODE_ENV", "production");
        std::env::remove_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL");

        let result = validate_environment();

        assert!(result.is_ok());

        clear_minimal_valid_environment();
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_invalid_atproto_control_plane_url() {
        set_minimal_valid_environment();
        std::env::set_var("NODE_ENV", "production");
        std::env::set_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", "not a url");

        let result = validate_environment();

        assert!(result.is_ok());

        clear_minimal_valid_environment();
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_atproto_control_plane_url_with_query_or_fragment() {
        for url in [
            "https://control-plane.example?tenant=prod",
            "https://control-plane.example#provisioning",
        ] {
            set_minimal_valid_environment();
            std::env::set_var("NODE_ENV", "production");
            std::env::set_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", url);

            let result = validate_environment();

            assert!(result.is_ok(), "{url} should not block startup");

            clear_minimal_valid_environment();
        }
    }

    #[test]
    #[serial]
    fn test_validate_environment_allows_atproto_control_plane_url_with_path() {
        for url in [
            "https://control-plane.example/api",
            "https://control-plane.example/api/",
            "https://control-plane.example/nested/path",
        ] {
            set_minimal_valid_environment();
            std::env::set_var("NODE_ENV", "production");
            std::env::set_var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL", url);

            let result = validate_environment();

            assert!(result.is_ok(), "{url} should not block startup");

            clear_minimal_valid_environment();
        }
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_with_head_tag() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        // Set environment variables
        std::env::set_var("APP_URL", "https://example.com");
        std::env::set_var("ALLOWED_PUBKEYS", "pubkey1,pubkey2");

        let result = inject_runtime_env(html);

        // Should inject script before </head>
        assert!(result.contains("window.__ENV__"));
        assert!(result.contains("VITE_DOMAIN"));
        assert!(result.contains("https://example.com"));
        assert!(result.contains("ALLOWED_PUBKEYS"));
        assert!(result.contains("pubkey1,pubkey2"));
        assert!(result.contains("</head>"));

        // Clean up
        std::env::remove_var("APP_URL");
        std::env::remove_var("ALLOWED_PUBKEYS");
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_without_head_tag() {
        let html = r#"<!DOCTYPE html>
<html>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        std::env::set_var("APP_URL", "https://example.com");

        let result = inject_runtime_env(html);

        // Should inject before <body>
        assert!(result.contains("window.__ENV__"));
        assert!(result.contains("<body>"));

        std::env::remove_var("APP_URL");
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_no_env_vars() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        // Clear all env vars that might be set from other tests
        std::env::remove_var("APP_URL");
        std::env::remove_var("ALLOWED_PUBKEYS");
        std::env::remove_var("SHOW_TEAMS_FUNCTIONALITY");

        let result = inject_runtime_env(html);

        // Should return original HTML unchanged
        assert_eq!(result, html);
        assert!(!result.contains("window.__ENV__"));
    }

    #[test]
    #[serial]
    fn test_inject_runtime_env_all_vars() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

        std::env::set_var("APP_URL", "https://example.com");
        std::env::set_var("ALLOWED_PUBKEYS", "key1,key2");
        std::env::set_var("SHOW_TEAMS_FUNCTIONALITY", "true");

        let result = inject_runtime_env(html);

        assert!(result.contains("VITE_DOMAIN"));
        assert!(result.contains("ALLOWED_PUBKEYS"));
        assert!(result.contains("SHOW_TEAMS_FUNCTIONALITY"));

        std::env::remove_var("APP_URL");
        std::env::remove_var("ALLOWED_PUBKEYS");
        std::env::remove_var("SHOW_TEAMS_FUNCTIONALITY");
    }

    #[test]
    fn test_origin_is_allowed_for_exact_match() {
        assert!(origin_is_allowed(
            "https://login.divine.video",
            "https://login.divine.video,https://divine.video"
        ));
    }

    #[test]
    fn test_origin_is_allowed_for_pages_preview_wildcard() {
        assert!(origin_is_allowed(
            "https://f582401d.openvine-app.pages.dev",
            "https://login.divine.video,https://*.openvine-app.pages.dev"
        ));
    }

    #[test]
    fn test_origin_is_not_allowed_for_non_matching_wildcard_host() {
        assert!(!origin_is_allowed(
            "https://openvine-app.pages.dev",
            "https://login.divine.video,https://*.openvine-app.pages.dev"
        ));
        assert!(!origin_is_allowed(
            "https://evil.pages.dev",
            "https://login.divine.video,https://*.openvine-app.pages.dev"
        ));
    }

    #[tokio::test]
    async fn test_request_id_middleware_echoes_trace_header() {
        let app = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .header("x-trace-id", "trace-1234")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "trace-1234"
        );
    }

    #[tokio::test]
    async fn test_request_id_middleware_generates_request_id() {
        let app = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id_middleware));

        let response = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let request_id = response.headers().get("x-request-id").unwrap();
        assert!(!request_id.is_empty());
    }

    #[tokio::test]
    async fn test_health_check_returns_json_body() {
        let response = health_check().await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["service"], "keycast");
    }

    #[test]
    fn test_readiness_response_reports_shutdown_as_unavailable() {
        let (status, body) = readiness_response(true, true);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Shutting down");
    }

    #[test]
    fn test_readiness_response_reports_database_failures_as_unavailable() {
        let (status, body) = readiness_response(false, false);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Database unavailable");
    }

    /// Router-level smoke test: verifies the probe routes are mounted at the
    /// exact paths the kubelet hits. Catches typos like `/healthz/startup`
    /// vs `/healthz/start`. Skips `/healthz/ready` because that handler
    /// requires a live DB pool.
    #[tokio::test]
    async fn test_health_probe_routes_respond_ok() {
        let livez_state = Arc::new(LivenessState {
            shutting_down: Arc::new(AtomicBool::new(false)),
        });

        let app = Router::new()
            .route("/livez", get(move || livez(livez_state.clone())))
            .route("/healthz/startup", get(startupz));

        for path in ["/livez", "/healthz/startup"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {path} not OK");
        }
    }

    // --- Shutdown timings ---
    //
    // These tests exercise the env-var-driven shutdown phase durations used by
    // the graceful-shutdown sequence in `async_main`. Values must be stable
    // because the iac repo's `terminationGracePeriodSeconds` is tuned against
    // them: PRE_DRAIN + HTTP_DRAIN + SIGNER_DRAIN must fit inside the grace
    // period with margin for process teardown.

    fn clear_shutdown_env() {
        std::env::remove_var("SHUTDOWN_PRE_DRAIN_SECS");
        std::env::remove_var("SHUTDOWN_HTTP_DRAIN_SECS");
        std::env::remove_var("SHUTDOWN_SIGNER_DRAIN_SECS");
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_defaults() {
        clear_shutdown_env();

        let timings = parse_shutdown_timings();

        // Documented defaults — see main.rs docs on graceful shutdown.
        assert_eq!(timings.pre_drain, Duration::from_secs(10));
        assert_eq!(timings.http_drain, Duration::from_secs(45));
        assert_eq!(timings.signer_drain, Duration::from_secs(10));
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_overrides_each_field() {
        clear_shutdown_env();
        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "3");
        std::env::set_var("SHUTDOWN_HTTP_DRAIN_SECS", "20");
        std::env::set_var("SHUTDOWN_SIGNER_DRAIN_SECS", "5");

        let timings = parse_shutdown_timings();

        assert_eq!(timings.pre_drain, Duration::from_secs(3));
        assert_eq!(timings.http_drain, Duration::from_secs(20));
        assert_eq!(timings.signer_drain, Duration::from_secs(5));

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_accepts_zero() {
        // Zero is a legitimate value for tests and local dev: skip the
        // endpoint-propagation wait, drain as fast as possible. It must NOT
        // collapse back to the default.
        clear_shutdown_env();
        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "0");
        std::env::set_var("SHUTDOWN_HTTP_DRAIN_SECS", "0");
        std::env::set_var("SHUTDOWN_SIGNER_DRAIN_SECS", "0");

        let timings = parse_shutdown_timings();

        assert_eq!(timings.pre_drain, Duration::ZERO);
        assert_eq!(timings.http_drain, Duration::ZERO);
        assert_eq!(timings.signer_drain, Duration::ZERO);

        clear_shutdown_env();
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_timings_invalid_value_falls_back_to_default() {
        // An unparseable value should fall through to the default rather than
        // panic at startup — we'd rather ship with a sane default than crash.
        clear_shutdown_env();
        std::env::set_var("SHUTDOWN_PRE_DRAIN_SECS", "not-a-number");

        let timings = parse_shutdown_timings();

        assert_eq!(timings.pre_drain, Duration::from_secs(10));

        clear_shutdown_env();
    }

    #[tokio::test(start_paused = true)]
    async fn test_pre_drain_pause_flips_unready_before_sleeping() {
        // The pre-drain pause exists so K8s can remove the pod from the
        // Service EndpointSlice (readiness probe failing) BEFORE we stop
        // accepting new connections. The AtomicBool MUST be set to true
        // before the sleep — otherwise the probe never fails and the grace
        // window is wasted.

        let unready = Arc::new(AtomicBool::new(false));
        let unready_for_task = unready.clone();

        let pause_handle = tokio::spawn(async move {
            pre_drain_pause(&unready_for_task, Duration::from_secs(5)).await
        });

        // Yield once so the spawned task gets a chance to set the flag before
        // the `tokio::time` pause machinery advances. With start_paused=true
        // real time is frozen; only `tokio::time::advance` or awaiting a
        // sleep moves it. The flag is set synchronously before the first
        // `.await` inside `pre_drain_pause`, so a yield is enough.
        tokio::task::yield_now().await;

        assert!(
            unready.load(Ordering::Relaxed),
            "pre_drain_pause must flip unready before sleeping so /healthz/ready starts returning 503 immediately"
        );

        // Now advance virtual time past the sleep and confirm the function
        // returns (no hang, no early return before the sleep).
        tokio::time::advance(Duration::from_secs(5)).await;
        pause_handle.await.expect("pre_drain_pause panicked");
    }

    #[tokio::test(start_paused = true)]
    async fn test_pre_drain_pause_with_zero_duration_returns_immediately() {
        // Local dev / tests set SHUTDOWN_PRE_DRAIN_SECS=0 to skip the wait.
        // The function must still set the flag and then return without
        // requiring any time to pass.
        let unready = Arc::new(AtomicBool::new(false));

        pre_drain_pause(&unready, Duration::ZERO).await;

        assert!(unready.load(Ordering::Relaxed));
    }

    // --- Shutdown grace-period ceiling validation ---
    //
    // The iac repo pins `terminationGracePeriodSeconds` in the Deployment; the
    // kubelet SIGKILLs any pod whose graceful shutdown exceeds that. The three
    // shutdown env vars (`SHUTDOWN_PRE_DRAIN_SECS` / `HTTP_DRAIN` /
    // `SIGNER_DRAIN`) are independent u64s with no upper bound, so a misconfig
    // (e.g. `SHUTDOWN_HTTP_DRAIN_SECS=120` against a 75s grace) would silently
    // lose in-flight requests on scale-down — exactly the failure this
    // feature is supposed to prevent. We validate the total + teardown margin
    // against a configurable ceiling on startup and log a loud warning if it
    // exceeds. We deliberately warn rather than refuse to boot: the ceiling is
    // cross-repo-coupled and an operator may legitimately need to boot with a
    // larger grace period before the iac repo catches up.

    fn clear_shutdown_ceiling_env() {
        std::env::remove_var("SHUTDOWN_GRACE_PERIOD_CEILING_SECS");
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_grace_ceiling_default() {
        clear_shutdown_ceiling_env();

        // Default matches DEFAULT_SHUTDOWN_GRACE_CEILING_SECS. Chosen to be
        // an upper bound that covers the iac PR's 60–90s range with headroom.
        assert_eq!(
            parse_shutdown_grace_ceiling(),
            Duration::from_secs(DEFAULT_SHUTDOWN_GRACE_CEILING_SECS)
        );
    }

    #[test]
    #[serial]
    fn test_parse_shutdown_grace_ceiling_override() {
        clear_shutdown_ceiling_env();
        std::env::set_var("SHUTDOWN_GRACE_PERIOD_CEILING_SECS", "60");

        assert_eq!(parse_shutdown_grace_ceiling(), Duration::from_secs(60));

        clear_shutdown_ceiling_env();
    }

    #[test]
    fn test_shutdown_timings_total_budget() {
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };
        assert_eq!(t.total_budget(), Duration::from_secs(65));
    }

    #[test]
    fn test_validate_shutdown_timings_ok_when_under_ceiling() {
        // Default timings (65s) + teardown margin (10s) = 75s. A 75s or
        // larger ceiling must validate cleanly; this is the iac PR's target.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };

        assert!(validate_shutdown_timings(&t, Duration::from_secs(75)).is_ok());
        assert!(validate_shutdown_timings(&t, Duration::from_secs(90)).is_ok());
    }

    #[test]
    fn test_validate_shutdown_timings_error_when_over_ceiling() {
        // The 65s default budget + 10s margin does NOT fit a 60s grace
        // period. This is the concrete failure mode flagged in review:
        // if the sibling iac PR lands with terminationGracePeriodSeconds=60,
        // the kubelet will SIGKILL mid-signer-drain. Validation must catch
        // this and return a descriptive error string.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };

        let err = validate_shutdown_timings(&t, Duration::from_secs(60))
            .expect_err("65s budget + 10s margin must not fit in 60s ceiling");
        // Error message should be operator-actionable: include the total,
        // the margin, and the ceiling so they can tune either side.
        assert!(err.contains("65"), "error should name total budget: {err}");
        assert!(err.contains("60"), "error should name ceiling: {err}");
    }

    #[test]
    fn test_validate_shutdown_timings_error_when_single_field_exceeds_ceiling() {
        // Operator misconfig: SHUTDOWN_HTTP_DRAIN_SECS=120 against default
        // 75s ceiling. Single-field overshoot must still be caught.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(120),
            signer_drain: Duration::from_secs(10),
        };

        assert!(validate_shutdown_timings(&t, Duration::from_secs(75)).is_err());
    }

    // --- HTTP drain abort-on-timeout ---
    //
    // On shutdown, the HTTP drain phase waits up to `SHUTDOWN_HTTP_DRAIN_SECS`
    // for axum's `.with_graceful_shutdown()` future to complete. The axum
    // task is a raw `tokio::spawn`, NOT on TaskTracker. Previously the
    // timeout arm just logged "API server shutdown timed out" and fell
    // through — but dropping a JoinHandle does NOT cancel the underlying
    // task (std+tokio semantics). axum would keep running (potentially
    // still accepting / serving new connections) during phase 3 (relay
    // client teardown) and phase 4 (DB pool close), with pool-close
    // generating decode errors on late-arriving requests until the kubelet
    // SIGKILL finally stopped the process at terminationGracePeriodSeconds.
    // The abort-on-timeout helper below makes the budget a real bound.

    #[tokio::test(start_paused = true)]
    async fn test_drain_http_or_abort_returns_completed_when_task_finishes_before_budget() {
        // Fast path: if the spawned task completes inside the drain budget,
        // we should report Completed and not touch abort().
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let outcome = drain_http_or_abort(handle, Duration::from_secs(5)).await;

        assert!(
            matches!(outcome, HttpDrainOutcome::Completed),
            "expected Completed, got {:?}",
            outcome
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_drain_http_or_abort_aborts_task_when_budget_exceeded() {
        // The behavioral promise: if the axum task is still running at the
        // end of the HTTP drain budget, drain_http_or_abort must stop it
        // before returning so phase 3 (relay teardown) and phase 4 (DB pool
        // close) aren't racing a still-live accept loop.
        //
        // We spawn a task that would sleep for an hour; with a 5s drain
        // budget the helper must abort it. After the helper returns, the
        // spawned task must be finished (cancelled), NOT still pending.

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_flag_task = cancel_flag.clone();

        let handle = tokio::spawn(async move {
            // Use an async block with a drop guard so we can observe that
            // the task was actually cancelled, not just left pending.
            struct CancelSignal(Arc<AtomicBool>);
            impl Drop for CancelSignal {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let _guard = CancelSignal(cancel_flag_task);

            // Would sleep for an hour if not aborted.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        let outcome = drain_http_or_abort(handle, Duration::from_secs(5)).await;

        assert!(
            matches!(outcome, HttpDrainOutcome::AbortedAfterTimeout),
            "expected AbortedAfterTimeout, got {:?}",
            outcome
        );
        assert!(
            cancel_flag.load(Ordering::Relaxed),
            "drain_http_or_abort must abort the spawned task — task drop guard did not fire, meaning the task is still running past the HTTP drain budget"
        );
    }

    #[test]
    fn test_validate_shutdown_timings_boundary_exactly_at_ceiling() {
        // total_budget + SHUTDOWN_TEARDOWN_MARGIN = 65 + 10 = 75.
        // A ceiling of 75 means the teardown margin exactly fits — that is
        // precisely what the margin is reserved for, so accept. The iac
        // PR's terminationGracePeriodSeconds=75s should validate cleanly
        // against the defaults with no operator action.
        let t = ShutdownTimings {
            pre_drain: Duration::from_secs(10),
            http_drain: Duration::from_secs(45),
            signer_drain: Duration::from_secs(10),
        };

        // Exactly the ceiling: OK (margin fits).
        assert!(validate_shutdown_timings(&t, Duration::from_secs(75)).is_ok());
        // One second below: reject — margin no longer fits.
        assert!(validate_shutdown_timings(&t, Duration::from_secs(74)).is_err());
        // One second above: OK — extra headroom.
        assert!(validate_shutdown_timings(&t, Duration::from_secs(76)).is_ok());
    }

    // --- Phase 4 bounded DB pool close ---
    //
    // sqlx's `Pool::close()` waits for every checked-out connection to be
    // returned to the pool. If a long-running query is still outstanding
    // when we enter phase 4 (e.g. a tenant-cache preload task was mid-query
    // when task_tracker.wait() timed out and signer_handle.abort() was
    // called but did not await), close can block indefinitely into the
    // kubelet SIGKILL. That swallows the final "Graceful shutdown complete"
    // log, so operators have no positive signal of clean shutdown.
    // close_within_margin enforces the documented SHUTDOWN_TEARDOWN_MARGIN
    // as a real bound.

    #[tokio::test(start_paused = true)]
    async fn test_close_within_margin_returns_completed_when_future_finishes_before_margin() {
        // Fast path: close completes immediately. Should report Completed
        // so the caller can emit the clean "Graceful shutdown complete"
        // log with no warning.
        let close_fut = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        let outcome = close_within_margin(close_fut, Duration::from_secs(10)).await;

        assert!(
            matches!(outcome, PoolCloseOutcome::Completed),
            "expected Completed, got {:?}",
            outcome
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_close_within_margin_reports_timed_out_when_margin_exceeded() {
        // Slow path: close blocks past the margin. Should report TimedOut
        // so the caller logs a warning and proceeds — we cannot hang the
        // process on pool teardown when the kubelet SIGKILL is about to
        // hit us anyway.
        let close_fut = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };

        let outcome = close_within_margin(close_fut, Duration::from_secs(10)).await;

        assert!(
            matches!(outcome, PoolCloseOutcome::TimedOut),
            "expected TimedOut, got {:?}",
            outcome
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_close_within_margin_enforces_real_bound_past_margin() {
        // A close future that blocks well past the margin must NOT extend
        // the helper's runtime past `margin`. We measure virtual time
        // elapsed under start_paused: it must be exactly the margin (not
        // the 1h sleep). This is the safety property the reviewer asked
        // for — phase 4 cannot eat into the kubelet's SIGKILL window.
        let start = tokio::time::Instant::now();
        let margin = Duration::from_secs(10);
        let close_fut = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        };

        let _outcome = close_within_margin(close_fut, margin).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed <= margin + Duration::from_millis(100),
            "close_within_margin must return within the margin, not block on the inner future; elapsed={:?}, margin={:?}",
            elapsed,
            margin
        );
    }
}
