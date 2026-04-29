// ABOUTME: Repository for registered OAuth client operations
// ABOUTME: Validates redirect URIs against registered client patterns and provides admin CRUD

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::repositories::RepositoryError;

/// A registered OAuth client row.
///
/// Note: the database column `tenant_id` is `INTEGER NOT NULL` (i32) but is
/// surfaced as `i64` here for consistency with the rest of the codebase. PostgreSQL
/// performs the implicit widening on read.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RegisteredClient {
    pub id: i32,
    pub tenant_id: i64,
    pub client_id: String,
    pub name: String,
    pub allowed_redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository for registered OAuth client operations.
/// When a client_id is registered, only its allowed redirect URIs are accepted.
/// Unregistered client_ids fall back to accepting any HTTPS redirect_uri.
#[derive(Debug)]
pub struct RegisteredClientRepository {
    pool: PgPool,
}

impl RegisteredClientRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get allowed redirect URIs for a registered client.
    /// Returns None if client_id is not registered (unregistered clients are allowed).
    pub async fn get_allowed_redirect_uris(
        &self,
        client_id: &str,
        tenant_id: i64,
    ) -> Result<Option<Vec<String>>, RepositoryError> {
        let result = sqlx::query_scalar::<_, Vec<String>>(
            "SELECT allowed_redirect_uris FROM registered_clients
             WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Validate a redirect_uri against a registered client's allowed patterns.
    /// Returns Ok(()) if valid, Err if the redirect_uri is not allowed.
    /// If the client_id is not registered, returns Ok(()) (backward compatible).
    pub async fn validate_redirect_uri(
        &self,
        client_id: &str,
        redirect_uri: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        let allowed = self.get_allowed_redirect_uris(client_id, tenant_id).await?;

        match allowed {
            None => Ok(()), // Unregistered client — allow any HTTPS (existing behavior)
            Some(patterns) => {
                if patterns.is_empty() {
                    return Err(RepositoryError::NotFound(format!(
                        "Client '{}' has no allowed redirect URIs",
                        client_id
                    )));
                }
                for pattern in &patterns {
                    if matches_redirect_pattern(pattern, redirect_uri) {
                        return Ok(());
                    }
                }
                Err(RepositoryError::NotFound(format!(
                    "redirect_uri '{}' is not allowed for client '{}'",
                    redirect_uri, client_id
                )))
            }
        }
    }

    // ---- Admin CRUD ----------------------------------------------------------

    /// List all registered clients for a tenant, ordered by client_id.
    pub async fn list(&self, tenant_id: i64) -> Result<Vec<RegisteredClient>, RepositoryError> {
        let rows = sqlx::query_as::<_, RegisteredClient>(
            "SELECT id, tenant_id::BIGINT AS tenant_id, client_id, name,
                    allowed_redirect_uris, created_at, updated_at
             FROM registered_clients
             WHERE tenant_id = $1
             ORDER BY client_id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Get a single registered client by id, scoped to a tenant.
    pub async fn get(&self, id: i32, tenant_id: i64) -> Result<RegisteredClient, RepositoryError> {
        let row = sqlx::query_as::<_, RegisteredClient>(
            "SELECT id, tenant_id::BIGINT AS tenant_id, client_id, name,
                    allowed_redirect_uris, created_at, updated_at
             FROM registered_clients
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or_else(|| {
            RepositoryError::NotFound(format!(
                "registered_client id={} for tenant {}",
                id, tenant_id
            ))
        })
    }

    /// Create a new registered client.
    /// Validates: non-empty trimmed client_id, at least one redirect URI.
    /// Returns Duplicate on (tenant_id, client_id) collision.
    pub async fn create(
        &self,
        tenant_id: i64,
        client_id: &str,
        name: &str,
        allowed_redirect_uris: &[String],
    ) -> Result<RegisteredClient, RepositoryError> {
        validate_client_id(client_id)?;
        validate_name(name)?;
        validate_redirect_uri_list(allowed_redirect_uris)?;

        // Trim each redirect URI before persisting to ensure consistent matching.
        let trimmed_uris: Vec<String> = allowed_redirect_uris
            .iter()
            .map(|s| s.trim().to_string())
            .collect();

        let row = sqlx::query_as::<_, RegisteredClient>(
            "INSERT INTO registered_clients
                 (tenant_id, client_id, name, allowed_redirect_uris)
             VALUES ($1, $2, $3, $4)
             RETURNING id, tenant_id::BIGINT AS tenant_id, client_id, name,
                       allowed_redirect_uris, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(client_id.trim())
        .bind(name.trim())
        .bind(&trimmed_uris)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Update name and/or allowed_redirect_uris for a registered client.
    /// Tenant-scoped: returns NotFound when (id, tenant_id) does not match.
    pub async fn update(
        &self,
        id: i32,
        tenant_id: i64,
        name: Option<&str>,
        allowed_redirect_uris: Option<&[String]>,
    ) -> Result<RegisteredClient, RepositoryError> {
        if let Some(uris) = allowed_redirect_uris {
            validate_redirect_uri_list(uris)?;
        }
        if let Some(n) = name {
            validate_name(n)?;
        }

        // Trim each redirect URI before persisting to ensure consistent matching.
        let trimmed_uris: Option<Vec<String>> =
            allowed_redirect_uris.map(|uris| uris.iter().map(|s| s.trim().to_string()).collect());

        // COALESCE pattern lets us patch either field without separate queries.
        let row = sqlx::query_as::<_, RegisteredClient>(
            "UPDATE registered_clients
             SET name = COALESCE($3, name),
                 allowed_redirect_uris = COALESCE($4, allowed_redirect_uris),
                 updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2
             RETURNING id, tenant_id::BIGINT AS tenant_id, client_id, name,
                       allowed_redirect_uris, created_at, updated_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name.map(str::trim))
        .bind(trimmed_uris.as_deref())
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or_else(|| {
            RepositoryError::NotFound(format!(
                "registered_client id={} for tenant {}",
                id, tenant_id
            ))
        })
    }

    /// Delete a registered client. Tenant-scoped.
    /// Returns NotFound if no row matches (id, tenant_id).
    pub async fn delete(&self, id: i32, tenant_id: i64) -> Result<(), RepositoryError> {
        let result = sqlx::query("DELETE FROM registered_clients WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound(format!(
                "registered_client id={} for tenant {}",
                id, tenant_id
            )));
        }
        Ok(())
    }
}

// ---- Validation helpers ------------------------------------------------------

fn validate_client_id(client_id: &str) -> Result<(), RepositoryError> {
    if client_id.trim().is_empty() {
        return Err(RepositoryError::Integrity(
            "client_id must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), RepositoryError> {
    if name.trim().is_empty() {
        return Err(RepositoryError::Integrity(
            "name must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_redirect_uri_list(uris: &[String]) -> Result<(), RepositoryError> {
    if uris.is_empty() {
        return Err(RepositoryError::Integrity(
            "allowed_redirect_uris must contain at least one entry".to_string(),
        ));
    }
    for uri in uris {
        if uri.trim().is_empty() {
            return Err(RepositoryError::Integrity(
                "allowed_redirect_uris entries must not be empty".to_string(),
            ));
        }
        // Must have 0 or 1 asterisk (wildcard), not multiple.
        let asterisk_count = uri.matches('*').count();
        if asterisk_count > 1 {
            return Err(RepositoryError::Integrity(format!(
                "pattern '{}' has {} wildcards; expected 0 (exact) or 1 (wildcard)",
                uri, asterisk_count
            )));
        }
    }
    Ok(())
}

/// Match a redirect URI against an allowed pattern.
///
/// Supports:
/// - Exact match: "https://divine.video/app/callback"
/// - Wildcard subdomain: "https://*.openvine-app.pages.dev/callback"
/// - Localhost any port: "http://localhost:*/callback"
fn matches_redirect_pattern(pattern: &str, uri: &str) -> bool {
    // Exact match
    if pattern == uri {
        return true;
    }

    // Wildcard matching
    if !pattern.contains('*') {
        return false;
    }

    // Split pattern at wildcard and match prefix/suffix
    let parts: Vec<&str> = pattern.splitn(2, '*').collect();
    if parts.len() != 2 {
        return false;
    }

    let prefix = parts[0];
    let suffix = parts[1];

    if !uri.starts_with(prefix) || !uri.ends_with(suffix) {
        return false;
    }

    // Bounds check: if prefix + suffix exceeds uri.len(), slicing would panic.
    // This happens with patterns like "aaa*aaa" and uri="aaaa".
    if prefix.len() + suffix.len() > uri.len() {
        return false;
    }

    // The wildcard segment must not contain '/' (prevents path traversal)
    let matched_segment = &uri[prefix.len()..uri.len() - suffix.len()];
    !matched_segment.contains('/')
}

/// Public entry point that mirrors `matches_redirect_pattern`.
/// Used by the admin "test this URI" endpoint so the inline tester reports
/// exactly the same result the OAuth validator will produce.
pub fn test_redirect_pattern(pattern: &str, uri: &str) -> bool {
    matches_redirect_pattern(pattern, uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_redirect_pattern(
            "https://divine.video/app/callback",
            "https://divine.video/app/callback"
        ));
        assert!(!matches_redirect_pattern(
            "https://divine.video/app/callback",
            "https://evil.com/app/callback"
        ));
    }

    #[test]
    fn test_wildcard_subdomain() {
        assert!(matches_redirect_pattern(
            "https://*.openvine-app.pages.dev/callback",
            "https://pr-123.openvine-app.pages.dev/callback"
        ));
        assert!(matches_redirect_pattern(
            "https://*.openvine-app.pages.dev/callback",
            "https://staging.openvine-app.pages.dev/callback"
        ));
        // Must not allow path traversal in wildcard segment
        assert!(!matches_redirect_pattern(
            "https://*.openvine-app.pages.dev/callback",
            "https://evil.com/.openvine-app.pages.dev/callback"
        ));
    }

    #[test]
    fn test_localhost_wildcard_port() {
        assert!(matches_redirect_pattern(
            "http://localhost:*/callback",
            "http://localhost:3000/callback"
        ));
        assert!(matches_redirect_pattern(
            "http://localhost:*/callback",
            "http://localhost:8080/callback"
        ));
        assert!(!matches_redirect_pattern(
            "http://localhost:*/callback",
            "http://localhost:3000/evil"
        ));
    }

    #[test]
    fn test_no_wildcard_no_match() {
        assert!(!matches_redirect_pattern(
            "https://divine.video/callback",
            "https://evil.com/callback"
        ));
    }

    #[test]
    fn test_wildcard_no_path_traversal() {
        // Wildcard segment must not contain /
        assert!(!matches_redirect_pattern(
            "https://*.example.com/callback",
            "https://sub/domain.example.com/callback"
        ));
    }

    #[test]
    fn test_overlapping_prefix_suffix_no_panic() {
        // Pattern "aaa*aaa" with uri "aaaa" should NOT panic.
        // prefix="aaa", suffix="aaa", but uri.len()=4, so slice [3..1] would panic.
        assert!(!matches_redirect_pattern("aaa*aaa", "aaaa"));
        assert!(!matches_redirect_pattern("abc*bc", "abcc"));
    }

    #[test]
    fn test_overlapping_equal_length() {
        // prefix.len() + suffix.len() == uri.len() is valid (empty middle)
        assert!(matches_redirect_pattern("abc*xyz", "abcxyz"));
        // prefix.len() + suffix.len() > uri.len() is invalid
        assert!(!matches_redirect_pattern("abc*xyz", "abcz"));
    }
}
