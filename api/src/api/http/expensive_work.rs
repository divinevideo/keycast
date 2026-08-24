use axum::{
    extract::{MatchedPath, Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use once_cell::sync::Lazy;
use serde_json::json;
use std::{
    array,
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const HTTP_BODY_LIMIT: usize = 64 * 1024;
const HTTP_REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const RETRY_AFTER_SECONDS: u64 = 1;

#[derive(Clone, Copy, Debug)]
enum Resource {
    Cpu,
    Kms,
    RemoteFetch,
    Authorization,
}

impl Resource {
    const ALL: [Self; 4] = [Self::Cpu, Self::Kms, Self::RemoteFetch, Self::Authorization];

    const fn index(self) -> usize {
        self as usize
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Kms => "kms",
            Self::RemoteFetch => "remote_fetch",
            Self::Authorization => "authorization",
        }
    }
}

#[derive(Clone, Copy)]
struct RouteSpec {
    name: &'static str,
    resources: &'static [Resource],
}

const CPU_KMS: &[Resource] = &[Resource::Cpu, Resource::Kms];
const CPU_REMOTE: &[Resource] = &[Resource::Cpu, Resource::RemoteFetch];
const KMS: &[Resource] = &[Resource::Kms];
const KMS_REMOTE: &[Resource] = &[Resource::Kms, Resource::RemoteFetch];
const KMS_AUTHORIZATION: &[Resource] = &[Resource::Kms, Resource::Authorization];
const REMOTE: &[Resource] = &[Resource::RemoteFetch];

fn route_spec(method: &Method, path: &str) -> Option<RouteSpec> {
    let (name, resources) = match (method, path) {
        (&Method::POST, "/ap/keys") => ("ap_keys_create", CPU_KMS),
        (&Method::GET, "/ap/keys/:pubkey") => ("ap_keys_get", CPU_KMS),
        (&Method::POST, "/ap/sign") => ("ap_sign", CPU_KMS),
        (&Method::POST, "/atproto/oauth/par") => ("atproto_oauth_par", CPU_REMOTE),
        (&Method::POST, "/atproto/oauth/token") => ("atproto_oauth_token", CPU_REMOTE),
        (&Method::POST, "/auth/register") => ("auth_register", KMS),
        (&Method::POST, "/auth/login") => ("auth_login", KMS),
        (&Method::POST, "/auth/verify-email") | (&Method::GET, "/auth/verify-email") => {
            ("auth_verify_email", KMS)
        }
        (&Method::GET, "/verify-email") => ("public_verify_email", KMS),
        (&Method::POST, "/oauth/login") => ("oauth_login", KMS),
        (&Method::POST, "/oauth/register") => ("oauth_register", KMS),
        (&Method::POST, "/oauth/token") => ("oauth_token", KMS_AUTHORIZATION),
        (&Method::POST, "/oauth/connect") => ("oauth_connect", KMS_AUTHORIZATION),
        (&Method::POST, "/user/bunker/create") => ("bunker_create", KMS_AUTHORIZATION),
        (&Method::POST, "/user/profile") => ("profile_update", KMS_REMOTE),
        (&Method::POST, "/user/sign") => ("user_sign", KMS),
        (&Method::POST, "/user/export-key") => ("key_export", KMS),
        (&Method::POST, "/user/change-key") => ("key_change", KMS),
        (&Method::POST, "/headless/register") => ("headless_register", KMS),
        (&Method::POST, "/admin/preload-user") => ("admin_preload_user", KMS_REMOTE),
        (&Method::POST, "/admin/create-minor-account") => ("minor_account_create", KMS_REMOTE),
        (&Method::POST, "/teams/:id/keys") => ("team_key_add", KMS),
        (&Method::POST, "/teams/:id/keys/:pubkey/authorizations") => {
            ("team_authorization_add", KMS_AUTHORIZATION)
        }
        (&Method::POST, "/user/atproto/enable") => ("atproto_enable", REMOTE),
        (&Method::POST, "/user/atproto/disable") => ("atproto_disable", REMOTE),
        (&Method::GET, "/user/atproto/status") => ("atproto_status", REMOTE),
        (&Method::PUT, "/account/:pubkey/crosspost") => ("atproto_crosspost", REMOTE),
        _ => return None,
    };
    Some(RouteSpec { name, resources })
}

#[derive(Clone)]
pub struct ResourceAdmission {
    permits: [Arc<Semaphore>; Resource::ALL.len()],
    deadline: Duration,
}

impl ResourceAdmission {
    fn new(capacities: [usize; Resource::ALL.len()]) -> Self {
        Self {
            permits: array::from_fn(|index| Arc::new(Semaphore::new(capacities[index]))),
            deadline: HTTP_REQUEST_DEADLINE,
        }
    }

    fn admit(&self, resources: &[Resource]) -> Result<Arc<RequestResources>, Resource> {
        let mut permits = Vec::new();
        for resource in resources {
            match self.permits[resource.index()].clone().try_acquire_owned() {
                Ok(permit) => {
                    METRICS.active[resource.index()].fetch_add(1, Ordering::Relaxed);
                    permits.push(TrackedPermit {
                        resource: *resource,
                        _permit: permit,
                    });
                }
                Err(_) => return Err(*resource),
            }
        }
        Ok(Arc::new(RequestResources {
            admission: self.clone(),
            permits: Mutex::new(permits),
            deadline: tokio::time::Instant::now() + self.deadline,
        }))
    }
}

impl Default for ResourceAdmission {
    fn default() -> Self {
        // CPU follows the serving instance's documented four-core capacity.
        // Each I/O class has a separate limit rather than one shared queue.
        Self::new([4, 16, 16, 16])
    }
}

struct TrackedPermit {
    resource: Resource,
    _permit: OwnedSemaphorePermit,
}

impl Drop for TrackedPermit {
    fn drop(&mut self) {
        METRICS.active[self.resource.index()].fetch_sub(1, Ordering::Relaxed);
    }
}

struct RequestResources {
    admission: ResourceAdmission,
    permits: Mutex<Vec<TrackedPermit>>,
    deadline: tokio::time::Instant,
}

tokio::task_local! {
    static REQUEST_RESOURCES: Arc<RequestResources>;
}

#[derive(Debug, thiserror::Error)]
pub enum CpuWorkError {
    #[error("CPU work is at capacity")]
    AtCapacity,
    #[error("CPU blocking task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, thiserror::Error)]
#[error("insufficient request budget")]
pub struct RequestBudgetExpired;

/// Run CPU-heavy work while retaining its permit until the blocking closure exits.
pub async fn spawn_cpu<F, T>(job: F) -> Result<T, CpuWorkError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let resources = match REQUEST_RESOURCES.try_with(Arc::clone) {
        Ok(resources) => resources,
        Err(_) => {
            let permit = ADMISSION.permits[Resource::Cpu.index()]
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CpuWorkError::AtCapacity)?;
            METRICS.active[Resource::Cpu.index()].fetch_add(1, Ordering::Relaxed);
            Arc::new(RequestResources {
                admission: ADMISSION.clone(),
                permits: Mutex::new(vec![TrackedPermit {
                    resource: Resource::Cpu,
                    _permit: permit,
                }]),
                deadline: tokio::time::Instant::now() + HTTP_REQUEST_DEADLINE,
            })
        }
    };
    let permit = {
        let mut permits = resources.permits.lock().expect("resource lock poisoned");
        if let Some(index) = permits
            .iter()
            .position(|permit| matches!(permit.resource, Resource::Cpu))
        {
            permits.swap_remove(index)
        } else {
            let permit = resources.admission.permits[Resource::Cpu.index()]
                .clone()
                .try_acquire_owned()
                .map_err(|_| CpuWorkError::AtCapacity)?;
            METRICS.active[Resource::Cpu.index()].fetch_add(1, Ordering::Relaxed);
            TrackedPermit {
                resource: Resource::Cpu,
                _permit: permit,
            }
        }
    };

    let (permit, output) = tokio::task::spawn_blocking(move || (permit, job())).await?;
    resources
        .permits
        .lock()
        .expect("resource lock poisoned")
        .push(permit);
    Ok(output)
}

pub fn remaining_timeout(maximum: Duration) -> Result<Duration, RequestBudgetExpired> {
    match REQUEST_RESOURCES.try_with(|resources| {
        let remaining = resources
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        (remaining >= Duration::from_millis(100)).then(|| remaining.min(maximum))
    }) {
        Ok(Some(timeout)) => Ok(timeout),
        Ok(None) => Err(RequestBudgetExpired),
        Err(_) => Ok(maximum),
    }
}

struct ResourceMetrics {
    active: [AtomicU64; Resource::ALL.len()],
    rejected: [AtomicU64; Resource::ALL.len()],
    deadline_expired: Mutex<BTreeMap<&'static str, u64>>,
}

static METRICS: Lazy<ResourceMetrics> = Lazy::new(|| ResourceMetrics {
    active: array::from_fn(|_| AtomicU64::new(0)),
    rejected: array::from_fn(|_| AtomicU64::new(0)),
    deadline_expired: Mutex::new(BTreeMap::new()),
});

pub static ADMISSION: Lazy<ResourceAdmission> = Lazy::new(ResourceAdmission::default);

pub async fn enforce(
    State(admission): State<ResourceAdmission>,
    request: Request,
    next: Next,
) -> Response {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_default();
    let Some(spec) = route_spec(request.method(), path) else {
        return next.run(request).await;
    };

    let resources = match admission.admit(spec.resources) {
        Ok(resources) => resources,
        Err(resource) => {
            METRICS.rejected[resource.index()].fetch_add(1, Ordering::Relaxed);
            return retryable_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server is busy. Please retry.",
            );
        }
    };

    let deadline = resources.deadline;
    match REQUEST_RESOURCES
        .scope(
            resources,
            tokio::time::timeout_at(deadline, next.run(request)),
        )
        .await
    {
        Ok(response) => response,
        Err(_) => {
            *METRICS
                .deadline_expired
                .lock()
                .expect("deadline metrics lock poisoned")
                .entry(spec.name)
                .or_insert(0) += 1;
            tracing::warn!(route = spec.name, "expensive HTTP request deadline expired");
            retryable_response(
                StatusCode::GATEWAY_TIMEOUT,
                "Request timed out. Please retry.",
            )
        }
    }
}

fn retryable_response(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, Json(json!({ "error": message }))).into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        RETRY_AFTER_SECONDS
            .to_string()
            .parse()
            .expect("integer Retry-After is valid"),
    );
    response
}

pub fn prometheus_metrics() -> String {
    let mut output = String::from(
        "\n# HELP keycast_http_resource_active Current admitted expensive HTTP requests by resource\n\
# TYPE keycast_http_resource_active gauge\n\
# HELP keycast_http_resource_rejections_total Expensive HTTP requests rejected before handler work\n\
# TYPE keycast_http_resource_rejections_total counter\n",
    );
    for resource in Resource::ALL {
        output.push_str(&format!(
            "keycast_http_resource_active{{resource=\"{}\"}} {}\n",
            resource.as_str(),
            METRICS.active[resource.index()].load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "keycast_http_resource_rejections_total{{resource=\"{}\",outcome=\"saturated\"}} {}\n",
            resource.as_str(),
            METRICS.rejected[resource.index()].load(Ordering::Relaxed)
        ));
    }
    output.push_str(
        "# HELP keycast_http_request_deadline_expired_total Expensive HTTP requests terminated by the application deadline\n\
# TYPE keycast_http_request_deadline_expired_total counter\n",
    );
    for (route, count) in METRICS
        .deadline_expired
        .lock()
        .expect("deadline metrics lock poisoned")
        .iter()
    {
        output.push_str(&format!(
            "keycast_http_request_deadline_expired_total{{route=\"{route}\",outcome=\"timeout\"}} {count}\n"
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body, extract::DefaultBodyLimit, middleware::from_fn_with_state, routing::post,
        Router,
    };
    use std::sync::atomic::AtomicBool;
    use tower::ServiceExt;

    #[tokio::test]
    async fn saturation_rejects_before_handler_work() {
        let admission = ResourceAdmission::new([0, 1, 1, 1]);
        let entered = Arc::new(AtomicBool::new(false));
        let handler_entered = entered.clone();
        let app = Router::new()
            .route(
                "/ap/sign",
                post(move || async move {
                    handler_entered.store(true, Ordering::Relaxed);
                    StatusCode::OK
                }),
            )
            .route_layer(from_fn_with_state(admission, enforce));

        let response = app
            .oneshot(Request::post("/ap/sign").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        assert!(!entered.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn permits_release_after_handler_error_and_cancellation() {
        let admission = ResourceAdmission::new([1, 1, 1, 1]);
        let guard = admission.admit(CPU_KMS).unwrap();
        assert!(admission.admit(CPU_KMS).is_err());
        drop(guard);
        assert!(admission.admit(CPU_KMS).is_ok());

        let guard = admission.admit(CPU_KMS).unwrap();
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        task.abort();
        task.await.unwrap_err();
        assert!(admission.admit(CPU_KMS).is_ok());
    }

    #[tokio::test]
    async fn application_deadline_returns_retryable_timeout() {
        let mut admission = ResourceAdmission::new([1, 1, 1, 1]);
        admission.deadline = Duration::from_millis(5);
        let app = Router::new()
            .route(
                "/ap/sign",
                post(|| async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    StatusCode::OK
                }),
            )
            .route_layer(from_fn_with_state(admission, enforce));

        let response = app
            .oneshot(Request::post("/ap/sign").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    }

    #[tokio::test]
    async fn body_limit_rejects_before_handler_work() {
        let entered = Arc::new(AtomicBool::new(false));
        let handler_entered = entered.clone();
        let app = Router::new()
            .route(
                "/auth/register",
                post(move |_: Json<serde_json::Value>| async move {
                    handler_entered.store(true, Ordering::Relaxed);
                    StatusCode::OK
                }),
            )
            .layer(DefaultBodyLimit::max(8));

        let response = app
            .oneshot(
                Request::post("/auth/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":"too large"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!entered.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn blocking_cpu_keeps_permit_after_request_cancellation() {
        let admission = ResourceAdmission::new([1, 1, 1, 1]);
        let admission_for_layer = admission.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let app = Router::new()
            .route(
                "/ap/sign",
                post(move || {
                    let started_tx = started_tx.clone();
                    let release_rx = release_rx.clone();
                    async move {
                        let _ = spawn_cpu(move || {
                            if let Some(tx) = started_tx.lock().unwrap().take() {
                                let _ = tx.send(());
                            }
                            release_rx.lock().unwrap().recv().unwrap();
                        })
                        .await;
                        StatusCode::OK
                    }
                }),
            )
            .route_layer(from_fn_with_state(admission_for_layer, enforce));

        let request =
            tokio::spawn(app.oneshot(Request::post("/ap/sign").body(Body::empty()).unwrap()));
        started_rx.await.unwrap();
        request.abort();
        request.await.unwrap_err();

        assert!(admission.admit(&[Resource::Cpu]).is_err());
        release_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(admission.admit(&[Resource::Cpu]).is_ok());
    }

    #[test]
    fn metrics_use_fixed_resource_and_outcome_labels() {
        let output = prometheus_metrics();
        assert!(output.contains(
            "keycast_http_resource_rejections_total{resource=\"cpu\",outcome=\"saturated\"}"
        ));
        assert!(!output.contains("/ap/keys/:pubkey"));
    }

    #[test]
    fn confirmed_expensive_routes_have_resource_classes() {
        for (method, path) in [
            (&Method::POST, "/ap/keys"),
            (&Method::GET, "/ap/keys/:pubkey"),
            (&Method::POST, "/ap/sign"),
            (&Method::POST, "/atproto/oauth/par"),
            (&Method::POST, "/atproto/oauth/token"),
            (&Method::POST, "/auth/register"),
            (&Method::POST, "/auth/login"),
            (&Method::POST, "/auth/verify-email"),
            (&Method::GET, "/verify-email"),
            (&Method::POST, "/oauth/login"),
            (&Method::POST, "/oauth/register"),
            (&Method::POST, "/oauth/token"),
            (&Method::POST, "/oauth/connect"),
            (&Method::POST, "/user/bunker/create"),
            (&Method::POST, "/user/profile"),
            (&Method::POST, "/user/sign"),
            (&Method::POST, "/user/export-key"),
            (&Method::POST, "/user/change-key"),
            (&Method::POST, "/headless/register"),
            (&Method::POST, "/admin/preload-user"),
            (&Method::POST, "/admin/create-minor-account"),
            (&Method::POST, "/teams/:id/keys"),
            (&Method::POST, "/teams/:id/keys/:pubkey/authorizations"),
            (&Method::POST, "/user/atproto/enable"),
            (&Method::POST, "/user/atproto/disable"),
            (&Method::GET, "/user/atproto/status"),
            (&Method::PUT, "/account/:pubkey/crosspost"),
        ] {
            assert!(
                route_spec(method, path).is_some(),
                "missing {method} {path}"
            );
        }
        assert!(route_spec(&Method::POST, "/nostr").is_none());
    }
}
