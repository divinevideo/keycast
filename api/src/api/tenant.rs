// ABOUTME: Multi-tenancy support for domain-based tenant isolation
// ABOUTME: Extracts tenant from Host header and provides tenant context to all handlers

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

/// Error type for tenant operations
#[derive(Error, Debug)]
pub enum TenantError {
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Domain validation failed: {0}")]
    ValidationFailed(String),
}

/// Represents a tenant in the system
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: i64,
    pub domain: String,
    pub name: String,
    pub settings: Option<String>, // JSON
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Tenant settings parsed from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    pub relay: Option<String>,
    pub email_from: Option<String>,
    // Add more settings as needed
}

impl Tenant {
    /// Get parsed settings
    pub fn get_settings(&self) -> Result<TenantSettings, serde_json::Error> {
        match &self.settings {
            Some(json) => serde_json::from_str(json),
            None => Ok(TenantSettings {
                relay: None,
                email_from: None,
            }),
        }
    }

    /// Get relay URL with fallback to default
    pub fn relay_url(&self) -> String {
        self.get_settings()
            .ok()
            .and_then(|s| s.relay)
            .unwrap_or_else(|| "wss://relay.damus.io".to_string())
    }

    /// Get email from address with fallback
    pub fn email_from(&self) -> String {
        self.get_settings()
            .ok()
            .and_then(|s| s.email_from)
            .unwrap_or_else(|| format!("noreply@{}", self.domain))
    }
}

/// Extractor for tenant context
/// Usage in handlers: `async fn handler(tenant: TenantExtractor, ...)`
pub struct TenantExtractor(pub Arc<Tenant>);

#[async_trait]
impl<S> FromRequestParts<S> for TenantExtractor
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Host header
        let host = parts
            .headers
            .get("host")
            .ok_or((StatusCode::BAD_REQUEST, "Missing Host header".to_string()))?
            .to_str()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Host header".to_string()))?;

        // Remove port if present (e.g., "localhost:3000" -> "localhost")
        let domain = host.split(':').next().unwrap_or(host);

        // Get database pool from global state
        let pool = crate::state::get_db_pool().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database not initialized".to_string(),
            )
        })?;

        // Get or create tenant (auto-provision if needed)
        let tenant = get_or_create_tenant(pool, domain).await.map_err(|e| {
            tracing::error!("Failed to get/create tenant for domain {}: {}", domain, e);
            match e {
                TenantError::InvalidDomain(_) | TenantError::ValidationFailed(_) => {
                    tracing::warn!(
                        target: "tenant_validation",
                        domain = %domain,
                        error = %e,
                        "Domain validation failed"
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid domain: {}", domain),
                    )
                }
                TenantError::DatabaseError(_) => {
                    tracing::error!(
                        target: "tenant_auto_provision",
                        domain = %domain,
                        error = %e,
                        "Failed to provision tenant"
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to provision tenant".to_string(),
                    )
                }
            }
        })?;

        Ok(TenantExtractor(Arc::new(tenant)))
    }
}

/// Get tenant by domain from database
pub async fn get_tenant_by_domain(pool: &PgPool, domain: &str) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, domain, name, settings, created_at, updated_at
         FROM tenants
         WHERE domain = $1",
    )
    .bind(domain)
    .fetch_one(pool)
    .await
}

/// Get tenant by ID from database
pub async fn get_tenant_by_id(pool: &PgPool, tenant_id: i64) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, domain, name, settings, created_at, updated_at
         FROM tenants
         WHERE id = $1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
}

/// Create a new tenant
pub async fn create_tenant(
    pool: &PgPool,
    domain: &str,
    name: &str,
    settings: Option<&str>,
) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(domain)
    .bind(name)
    .bind(settings)
    .fetch_one(pool)
    .await
}

/// List all tenants
pub async fn list_tenants(pool: &PgPool) -> Result<Vec<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, domain, name, settings, created_at, updated_at
         FROM tenants
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

/// Validate domain format to prevent abuse
fn validate_domain(domain: &str) -> Result<(), TenantError> {
    // Basic validation rules
    if domain.is_empty() {
        return Err(TenantError::InvalidDomain(
            "Domain cannot be empty".to_string(),
        ));
    }

    // Length check (max 253 chars per DNS spec)
    if domain.len() > 253 {
        return Err(TenantError::InvalidDomain("Domain too long".to_string()));
    }

    // Allow localhost for local development and testing
    if domain == "localhost" {
        return Ok(());
    }

    // Must contain at least one dot (prevent localhost, etc)
    if !domain.contains('.') {
        return Err(TenantError::ValidationFailed(
            "Domain must contain at least one dot".to_string(),
        ));
    }

    // Basic character validation (alphanumeric, dots, hyphens)
    if !domain
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return Err(TenantError::InvalidDomain(
            "Domain contains invalid characters".to_string(),
        ));
    }

    // Reject internal IPs and special domains (but not localhost)
    let blocked_patterns = [
        "127.",
        "192.168.",
        "10.",
        "172.",
        ".local",
        ".internal",
        ".test",
    ];

    for pattern in &blocked_patterns {
        if domain.contains(pattern) {
            return Err(TenantError::ValidationFailed(format!(
                "Domain matches blocked pattern: {}",
                pattern
            )));
        }
    }

    Ok(())
}

/// Create default tenant settings JSON
fn get_default_settings(domain: &str) -> String {
    let settings = TenantSettings {
        relay: Some("wss://relay.damus.io".to_string()),
        email_from: Some(format!("noreply@{}", domain)),
    };

    serde_json::to_string(&settings).unwrap_or_else(|_| {
        r#"{"relay":"wss://relay.damus.io","auto_provisioned":true}"#.to_string()
    })
}

/// Generate friendly tenant name from domain
fn generate_tenant_name(domain: &str) -> String {
    // Extract primary domain (e.g., "example" from "example.com")
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() >= 2 {
        let base = parts[parts.len() - 2];
        // Capitalize first letter
        let mut chars = base.chars();
        match chars.next() {
            None => domain.to_string(),
            Some(f) => f.to_uppercase().chain(chars).collect(),
        }
    } else {
        domain.to_string()
    }
}

/// Get tenant by domain, creating it if it doesn't exist
///
/// This enables auto-provisioning: when a new domain hits the server via CNAME,
/// we automatically create a tenant record with default settings.
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `domain` - Domain from Host header (e.g., "example.com")
///
/// # Returns
/// * `Ok(Tenant)` - Existing or newly created tenant
/// * `Err(TenantError)` - Database error or validation failure
///
/// # Security Considerations
/// - Domain validation prevents obviously malicious inputs
/// - Auto-provisioned tenants use restrictive defaults
pub async fn get_or_create_tenant(pool: &PgPool, domain: &str) -> Result<Tenant, TenantError> {
    // 1. Validate domain format
    validate_domain(domain)?;

    let default_settings = get_default_settings(domain);
    let name = generate_tenant_name(domain);

    // 2. Use INSERT ... ON CONFLICT to handle race conditions atomically
    let tenant = sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(domain)
    .bind(&name)
    .bind(&default_settings)
    .fetch_one(pool)
    .await?;

    // 3. Log if this was a new tenant (created_at == updated_at approximately)
    let is_new = (tenant.updated_at - tenant.created_at).num_seconds().abs() < 2;
    if is_new {
        tracing::info!(
            target: "tenant_auto_provision",
            domain = %domain,
            tenant_id = tenant.id,
            tenant_name = %name,
            "Auto-provisioned new tenant"
        );
    } else {
        tracing::debug!("Found existing tenant for domain: {}", domain);
    }

    Ok(tenant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_settings_parsing() {
        use chrono::Utc;
        let tenant = Tenant {
            id: 1,
            domain: "test.com".to_string(),
            name: "Test".to_string(),
            settings: Some(
                r#"{"relay":"wss://test.relay","email_from":"noreply@test.com"}"#.to_string(),
            ),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let settings = tenant.get_settings().unwrap();
        assert_eq!(settings.relay, Some("wss://test.relay".to_string()));
        assert_eq!(settings.email_from, Some("noreply@test.com".to_string()));
    }

    #[test]
    fn test_tenant_relay_url_fallback() {
        use chrono::Utc;
        let tenant = Tenant {
            id: 1,
            domain: "test.com".to_string(),
            name: "Test".to_string(),
            settings: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(tenant.relay_url(), "wss://relay.damus.io");
    }

    #[test]
    fn test_tenant_email_from_fallback() {
        use chrono::Utc;
        let tenant = Tenant {
            id: 1,
            domain: "test.com".to_string(),
            name: "Test".to_string(),
            settings: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(tenant.email_from(), "noreply@test.com");
    }
}
