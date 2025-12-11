use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use keycast_core::metrics::METRICS;

/// GET /metrics - Prometheus-formatted metrics endpoint
///
/// Returns in-memory atomic counters that are incremented during operations.
/// This follows Prometheus best practices: no database queries on scrape.
pub async fn metrics() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(METRICS.to_prometheus())
        .unwrap()
}
