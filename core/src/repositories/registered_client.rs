// ABOUTME: Repository for registered OAuth client operations
// ABOUTME: Validates redirect URIs against registered client patterns

use sqlx::PgPool;

use crate::repositories::RepositoryError;

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

    /// Check if a client_id is registered in the database.
    /// Returns true if the client is registered, false otherwise.
    pub async fn is_client_registered(
        &self,
        client_id: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let result = self.get_allowed_redirect_uris(client_id, tenant_id).await?;
        Ok(result.is_some())
    }

    /// Check whether strict client admission is enabled.
    /// In strict mode, only registered OAuth clients can initiate authorization flows.
    /// Controlled by `REQUIRE_REGISTERED_OAUTH_CLIENTS` env var.
    /// Defaults to `true` in release builds and `false` in debug builds.
    pub fn is_strict_client_mode() -> bool {
        std::env::var("REQUIRE_REGISTERED_OAUTH_CLIENTS")
            .map(|v| v == "true")
            .unwrap_or(cfg!(not(debug_assertions)))
    }

    /// In strict mode, verify the client_id is registered. Returns Err if not.
    /// In non-strict mode, always returns Ok(()).
    pub async fn require_registered_client(
        &self,
        client_id: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        if !Self::is_strict_client_mode() {
            return Ok(());
        }
        if self.is_client_registered(client_id, tenant_id).await? {
            Ok(())
        } else {
            Err(RepositoryError::NotFound(format!(
                "client_id '{}' is not registered. In production, only registered OAuth clients are allowed.",
                client_id
            )))
        }
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

    // The wildcard segment must not contain '/' (prevents path traversal)
    let matched_segment = &uri[prefix.len()..uri.len() - suffix.len()];
    !matched_segment.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_client_mode_env_true() {
        std::env::set_var("REQUIRE_REGISTERED_OAUTH_CLIENTS", "true");
        assert!(RegisteredClientRepository::is_strict_client_mode());
        std::env::remove_var("REQUIRE_REGISTERED_OAUTH_CLIENTS");
    }

    #[test]
    fn test_strict_client_mode_env_false() {
        std::env::set_var("REQUIRE_REGISTERED_OAUTH_CLIENTS", "false");
        assert!(!RegisteredClientRepository::is_strict_client_mode());
        std::env::remove_var("REQUIRE_REGISTERED_OAUTH_CLIENTS");
    }

    #[test]
    fn test_strict_client_mode_default() {
        // When env var is not set, defaults based on build profile
        std::env::remove_var("REQUIRE_REGISTERED_OAUTH_CLIENTS");
        let result = RegisteredClientRepository::is_strict_client_mode();
        if cfg!(debug_assertions) {
            assert!(!result, "Should default to false in debug builds");
        } else {
            assert!(result, "Should default to true in release builds");
        }
    }

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
}
