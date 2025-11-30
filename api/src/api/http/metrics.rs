use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;

/// GET /metrics - Prometheus-formatted metrics endpoint
pub async fn metrics(
    State(pool): State<PgPool>,
) -> impl IntoResponse {
    // Collect metrics from database
    let metrics = collect_metrics(&pool).await;

    match metrics {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
            .body(body)
            .unwrap(),
        Err(e) => {
            tracing::error!("Failed to collect metrics: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!("# Error collecting metrics: {}", e))
                .unwrap()
        }
    }
}

async fn collect_metrics(pool: &PgPool) -> Result<String, sqlx::Error> {
    let mut output = String::new();

    // Signing activity by source
    output.push_str("# HELP keycast_signing_total Total signing operations by source\n");
    output.push_str("# TYPE keycast_signing_total counter\n");

    let signing_stats: Vec<(String, i64)> = sqlx::query_as(
        "SELECT source, COUNT(*) as count FROM signing_activity GROUP BY source"
    )
    .fetch_all(pool)
    .await?;

    for (source, count) in &signing_stats {
        output.push_str(&format!("keycast_signing_total{{source=\"{}\"}} {}\n", source, count));
    }

    // Total signing (for convenience)
    let total_signing: i64 = signing_stats.iter().map(|(_, c)| c).sum();
    output.push_str(&format!("keycast_signing_total{{source=\"all\"}} {}\n", total_signing));

    // OAuth authorizations count
    output.push_str("\n# HELP keycast_oauth_authorizations_total Total OAuth authorizations\n");
    output.push_str("# TYPE keycast_oauth_authorizations_total gauge\n");

    let oauth_auth_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_authorizations"
    )
    .fetch_one(pool)
    .await?;

    output.push_str(&format!("keycast_oauth_authorizations_total {}\n", oauth_auth_count.0));

    // Active users (users with at least one authorization)
    output.push_str("\n# HELP keycast_active_users_total Users with active authorizations\n");
    output.push_str("# TYPE keycast_active_users_total gauge\n");

    let active_users: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT user_pubkey) FROM oauth_authorizations"
    )
    .fetch_one(pool)
    .await?;

    output.push_str(&format!("keycast_active_users_total {}\n", active_users.0));

    // Total users
    output.push_str("\n# HELP keycast_users_total Total registered users\n");
    output.push_str("# TYPE keycast_users_total gauge\n");

    let total_users: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users"
    )
    .fetch_one(pool)
    .await?;

    output.push_str(&format!("keycast_users_total {}\n", total_users.0));

    // Signing activity by event kind (top 10)
    output.push_str("\n# HELP keycast_signing_by_kind_total Signing operations by event kind\n");
    output.push_str("# TYPE keycast_signing_by_kind_total counter\n");

    let kind_stats: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT event_kind, COUNT(*) as count FROM signing_activity GROUP BY event_kind ORDER BY count DESC LIMIT 10"
    )
    .fetch_all(pool)
    .await?;

    for (kind, count) in kind_stats {
        output.push_str(&format!("keycast_signing_by_kind_total{{kind=\"{}\"}} {}\n", kind, count));
    }

    // Signing activity in last 24 hours
    output.push_str("\n# HELP keycast_signing_24h Signing operations in last 24 hours\n");
    output.push_str("# TYPE keycast_signing_24h gauge\n");

    let recent_signing: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM signing_activity WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(pool)
    .await?;

    output.push_str(&format!("keycast_signing_24h {}\n", recent_signing.0));

    // Applications count
    output.push_str("\n# HELP keycast_applications_total Total OAuth applications\n");
    output.push_str("# TYPE keycast_applications_total gauge\n");

    let apps_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_applications"
    )
    .fetch_one(pool)
    .await?;

    output.push_str(&format!("keycast_applications_total {}\n", apps_count.0));

    Ok(output)
}
