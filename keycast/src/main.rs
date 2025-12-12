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
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_signer::{RelayQueue, UnifiedSigner};
use moka::future::Cache;
use nostr_sdk::Keys;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::Notify;
use tokio_util::task::TaskTracker;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
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
    } else if path.starts_with("/api/") || path.starts_with("/health") {
        // Dynamic content - no caching
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

    // Master key validation (either file or GCP KMS)
    let use_gcp_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";
    if !use_gcp_kms && env::var("MASTER_KEY_PATH").is_err() {
        errors.push("MASTER_KEY_PATH must be set when USE_GCP_KMS=false");
    }

    if use_gcp_kms && env::var("GCP_PROJECT_ID").is_err() {
        errors.push("GCP_PROJECT_ID must be set when USE_GCP_KMS=true");
    }

    // Docker deployment requires additional vars
    if env::var("POSTGRES_PASSWORD").is_err() {
        // Only required for docker-compose, so just warn
        tracing::warn!("POSTGRES_PASSWORD not set (required for docker-compose deployments)");
    }

    if !errors.is_empty() {
        return Err(format!(
            "Missing required environment variables:\n  - {}\n\nSee .env.example for configuration guide.",
            errors.join("\n  - ")
        ));
    }

    Ok(())
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
    dotenv().ok();

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

    // Setup database
    let database_url = env::var("DATABASE_URL")?; // Validated above

    let database = Database::new().await?;
    tracing::info!("✔︎ Database initialized at {:?}", database_url);

    // Initialize cluster coordination with Redis (Pub/Sub mode)
    // This handles instance registration, membership detection, and heartbeats
    // Uses Redis Pub/Sub for instant membership updates
    let redis_url = env::var("REDIS_URL")?; // Validated above
    let coordinator = Arc::new(ClusterCoordinator::start(&redis_url).await?);
    let instance_id = coordinator.instance_id();
    tracing::info!(
        "✔︎ Cluster coordinator started: {} (Redis Pub/Sub)",
        instance_id
    );

    // Setup key managers (one for signer, one for API - they're cheap to create)
    let use_gcp_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";

    let signer_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
        tracing::info!("Using Google Cloud KMS for encryption");
        Box::new(GcpKeyManager::new().await?)
    } else {
        tracing::info!("Using file-based encryption");
        Box::new(FileKeyManager::new()?)
    };

    let api_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
        Box::new(GcpKeyManager::new().await?)
    } else {
        Box::new(FileKeyManager::new()?)
    };

    // Load server keys for signing UCANs
    let server_nsec = env::var("SERVER_NSEC")?; // Validated above
    let server_keys = Keys::parse(&server_nsec).map_err(|e| {
        format!(
            "Invalid SERVER_NSEC: {}. Must be valid hex (64 chars) or nsec bech32.",
            e
        )
    })?;
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

    // Create API state with http_handler_cache for on-demand loading
    // Note: api no longer depends on signer's handler cache (decoupled)
    let api_state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(api_key_manager),
        signer_handlers: None, // Deprecated: api uses http_handler_cache with on-demand loading
        http_handler_cache: new_http_handler_cache(),
        server_keys,
        tenant_cache,
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
            if origin_str.starts_with("http://localhost:") || origin_str == "http://localhost" {
                return true;
            }
            allowed_origins_for_closure
                .split(',')
                .map(|s| s.trim())
                .any(|allowed| origin_str == allowed)
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
        .allow_credentials(true);

    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(false);

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
        .with_state(web_build_dir.clone());

    let mut app = Router::new()
        // Health checks at root level (for k8s/Cloud Run)
        .route("/health", get(health_check))
        .route("/healthz/startup", get(health_check))
        .route("/healthz/ready", get(health_check))
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

    // SvelteKit frontend (fallback - catches all other routes)
    // SPA mode: serve index.html for all non-file routes
    let index_path = PathBuf::from(&web_build_dir).join("index.html");
    let app = app.fallback_service(ServeDir::new(&web_build_dir).fallback(axum::routing::get(
        move || {
            let index_path = index_path.clone();
            async move {
                match tokio::fs::read_to_string(&index_path).await {
                    Ok(content) => Html(content).into_response(),
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
            // Use incoming x-trace-id header or generate new 8-char UUID
            let trace_id = request
                .headers()
                .get("x-trace-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
                .unwrap_or_else(|| Uuid::new_v4().to_string()[..8].to_string());

            tracing::span!(
                Level::INFO,
                "request",
                method = %request.method(),
                uri = %request.uri(),
                trace_id = %trace_id,
            )
        }),
    );

    // Add Cache-Control headers for browser caching
    let app = app.layer(middleware::from_fn(cache_control_middleware));

    let api_addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port));
    tracing::info!("✔︎ API server ready on {}", api_addr);

    // Setup graceful shutdown with TaskTracker for background tasks
    let shutdown_signal = Arc::new(Notify::new());
    let shutdown_for_api = shutdown_signal.clone();
    let client_for_shutdown = signer.client();
    let pool_for_shutdown = database.pool.clone();
    let task_tracker = TaskTracker::new();

    // Spawn API server with graceful shutdown
    let api_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        tracing::info!("🌐 API server listening on {}", api_addr);
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
    shutdown_signal.notify_waiters();

    tracing::info!("Shutting down gracefully...");

    // Close task tracker to prevent new tasks from being spawned
    task_tracker.close();

    // Shutdown signer client (disconnect from relays)
    // Note: ClusterCoordinator will be dropped automatically, triggering deregister
    client_for_shutdown.shutdown().await;

    // Wait for API server to drain (max 15s to leave buffer before Cloud Run's 30s timeout)
    match tokio::time::timeout(Duration::from_secs(15), api_handle).await {
        Ok(result) => {
            if let Err(e) = result {
                tracing::warn!("API server task error: {:?}", e);
            }
        }
        Err(_) => {
            tracing::warn!("API server shutdown timed out after 15s");
        }
    }

    // Wait for signer and other tracked tasks to complete (max 10s)
    match tokio::time::timeout(Duration::from_secs(10), task_tracker.wait()).await {
        Ok(()) => {
            tracing::info!("All tracked tasks completed");
        }
        Err(_) => {
            tracing::warn!("Task tracker wait timed out after 10s, aborting signer");
            signer_handle.abort();
        }
    }

    // Close database pool
    pool_for_shutdown.close().await;

    tracing::info!("Graceful shutdown complete");

    Ok(())
}
