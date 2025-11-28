use axum::{extract::State, response::Json};
use keycast_core::{
    custom_permissions::PermissionDisplay,
    types::policy::{Policy, PolicyError},
};
use serde::Serialize;
use sqlx::PgPool;

use crate::api::tenant::TenantExtractor;

/// Response format for a single policy with its permissions
#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub permissions: Vec<PermissionDisplay>,
}

/// Response format for the policies list endpoint
#[derive(Debug, Serialize)]
pub struct PoliciesListResponse {
    pub policies: Vec<PolicyResponse>,
}

/// Error response format
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// GET /api/policies
/// Returns all available policies with their user-friendly permission descriptions.
/// This endpoint is public and allows developers to discover available policies.
pub async fn list_policies(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
) -> Result<Json<PoliciesListResponse>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant.0.id;

    // Get all policies with slugs (public policies)
    let policies = Policy::list_public(&pool, tenant_id)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: e.to_string(),
                }),
            )
        })?;

    // Build response with permission displays
    let mut policy_responses = Vec::new();
    for policy in policies {
        let permissions = policy.permission_displays(&pool).await.unwrap_or_default();

        policy_responses.push(PolicyResponse {
            slug: policy.slug.clone().unwrap_or_else(|| policy.id.to_string()),
            display_name: policy.display_name.clone().unwrap_or_else(|| policy.name.clone()),
            description: policy.description.clone().unwrap_or_default(),
            permissions,
        });
    }

    Ok(Json(PoliciesListResponse {
        policies: policy_responses,
    }))
}

/// GET /api/policies/:slug
/// Returns a single policy by slug with its permissions
pub async fn get_policy(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> Result<Json<PolicyResponse>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant.0.id;

    // Find policy by slug
    let policy = Policy::find_by_slug(&pool, tenant_id, &slug)
        .await
        .map_err(|e| match e {
            PolicyError::NotFound => (
                axum::http::StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: format!(
                        "Policy '{}' not found. Use GET /api/policies for available options.",
                        slug
                    ),
                }),
            ),
            _ => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: e.to_string(),
                }),
            ),
        })?;

    let permissions = policy.permission_displays(&pool).await.unwrap_or_default();

    Ok(Json(PolicyResponse {
        slug: policy.slug.clone().unwrap_or_else(|| policy.id.to_string()),
        display_name: policy.display_name.clone().unwrap_or_else(|| policy.name.clone()),
        description: policy.description.clone().unwrap_or_default(),
        permissions,
    }))
}
