use crate::custom_permissions::PermissionDisplay;
use crate::types::permission::Permission;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Policy not found")]
    NotFound,

    #[error("Permission error: {0}")]
    Permission(String),
}

/// A policy is a set of permissions. Policies are global (team_id = NULL) or team-specific.
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Policy {
    /// The id of the policy
    pub id: i32,
    /// The name of the policy
    pub name: String,
    /// The id of the team the policy belongs to (None for global policies)
    pub team_id: Option<i32>,
    /// The date and time the policy was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the policy was last updated
    pub updated_at: DateTime<chrono::Utc>,
    /// URL-friendly identifier (e.g., "social", "readonly", "full")
    pub slug: Option<String>,
    /// User-friendly name (e.g., "Social App")
    pub display_name: Option<String>,
    /// Description of what this policy allows
    pub description: Option<String>,
}

/// User-friendly policy info for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub slug: String,
    pub display_name: String,
    pub description: String,
}

impl Policy {
    /// Find a policy by its slug
    pub async fn find_by_slug(pool: &PgPool, slug: &str) -> Result<Policy, PolicyError> {
        sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE slug = $1")
            .bind(slug)
            .fetch_optional(pool)
            .await?
            .ok_or(PolicyError::NotFound)
    }

    /// Find a policy by its ID
    pub async fn find_by_id(pool: &PgPool, id: i32) -> Result<Policy, PolicyError> {
        sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or(PolicyError::NotFound)
    }

    /// Get all global policies with slugs (for discovery endpoint)
    pub async fn list_public(pool: &PgPool) -> Result<Vec<Policy>, PolicyError> {
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies WHERE slug IS NOT NULL AND team_id IS NULL ORDER BY name",
        )
        .fetch_all(pool)
        .await?;
        Ok(policies)
    }

    /// Get the permissions for this policy
    pub async fn permissions(&self, pool: &PgPool) -> Result<Vec<Permission>, PolicyError> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT p.*
            FROM permissions p
            JOIN policy_permissions pp ON pp.permission_id = p.id
            WHERE pp.policy_id = $1
            "#,
        )
        .bind(self.id)
        .fetch_all(pool)
        .await?;
        Ok(permissions)
    }

    /// Get user-friendly display info for each permission in this policy
    pub async fn permission_displays(
        &self,
        pool: &PgPool,
    ) -> Result<Vec<PermissionDisplay>, PolicyError> {
        let permissions = self.permissions(pool).await?;
        let mut displays = Vec::new();

        for perm in &permissions {
            if let Ok(custom_perm) = perm.to_custom_permission() {
                displays.push(custom_perm.display());
            }
        }

        Ok(displays)
    }

    /// Convert to PolicyInfo for API responses
    pub fn to_info(&self) -> PolicyInfo {
        PolicyInfo {
            slug: self.slug.clone().unwrap_or_else(|| self.id.to_string()),
            display_name: self.display_name.clone().unwrap_or_else(|| self.name.clone()),
            description: self.description.clone().unwrap_or_default(),
        }
    }
}

/// Check if policy A is more restrictive than policy B.
/// A is more restrictive if it grants fewer permissions.
pub async fn is_more_restrictive(
    a: &Policy,
    b: &Policy,
    pool: &PgPool,
) -> Result<bool, PolicyError> {
    use crate::custom_permissions::allowed_kinds::AllowedKindsConfig;
    use crate::custom_permissions::content_filter::ContentFilterConfig;

    let a_perms = a.permissions(pool).await?;
    let b_perms = b.permissions(pool).await?;

    // Compare each permission type
    for a_perm in &a_perms {
        // Find matching permission in B
        for b_perm in &b_perms {
            if a_perm.identifier != b_perm.identifier {
                continue;
            }

            // Check restrictiveness based on permission type
            match a_perm.identifier.as_str() {
                "allowed_kinds" => {
                    // Parse configs directly from JSON
                    let a_config: AllowedKindsConfig =
                        serde_json::from_value(a_perm.config.0.clone()).unwrap_or_default();
                    let b_config: AllowedKindsConfig =
                        serde_json::from_value(b_perm.config.0.clone()).unwrap_or_default();

                    // A's allowed kinds must be subset of B's
                    match (&a_config.allowed_kinds, &b_config.allowed_kinds) {
                        (Some(a_kinds), Some(b_kinds)) => {
                            let a_set: HashSet<_> = a_kinds.iter().collect();
                            let b_set: HashSet<_> = b_kinds.iter().collect();
                            if !a_set.is_subset(&b_set) {
                                return Ok(false);
                            }
                        }
                        (Some(_), None) => {
                            // B allows all, A restricts - A is more restrictive (OK)
                        }
                        (None, Some(_)) => {
                            // A allows all, B restricts - A is less restrictive
                            return Ok(false);
                        }
                        (None, None) => {
                            // Both allow all - equal
                        }
                    }
                }
                "content_filter" => {
                    let a_config: ContentFilterConfig =
                        serde_json::from_value(a_perm.config.0.clone()).unwrap_or_default();
                    let b_config: ContentFilterConfig =
                        serde_json::from_value(b_perm.config.0.clone()).unwrap_or_default();

                    // A's blocked words must be superset of B's (A blocks more = more restrictive)
                    match (&a_config.blocked_words, &b_config.blocked_words) {
                        (Some(a_words), Some(b_words)) => {
                            let a_set: HashSet<_> = a_words.iter().collect();
                            let b_set: HashSet<_> = b_words.iter().collect();
                            if !a_set.is_superset(&b_set) {
                                return Ok(false);
                            }
                        }
                        (None, Some(_)) => {
                            // A has no filter, B has filter - A is less restrictive
                            return Ok(false);
                        }
                        (Some(_), None) | (None, None) => {
                            // A has filter or both have none - OK
                        }
                    }
                }
                "encrypt_to_self" => {
                    // encrypt_to_self is always a restriction when present
                    // If both have it, they're equal. If only A has it, A is more restrictive (OK).
                    // If only B has it, A is less restrictive - but this case won't happen
                    // since we're iterating A's permissions
                }
                _ => {}
            }
        }
    }

    // Check if B has permissions A doesn't have (A would be less restrictive)
    for b_perm in &b_perms {
        let has_matching = a_perms
            .iter()
            .any(|a_perm| a_perm.identifier == b_perm.identifier);
        if !has_matching && b_perm.identifier == "encrypt_to_self" {
            // B has encrypt_to_self but A doesn't - A is less restrictive
            return Ok(false);
        }
    }

    Ok(true)
}

/// A policy with its permissions, this is a join table between a policy and its permissions
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyWithPermissions {
    #[sqlx(flatten)]
    pub policy: Policy,
    #[sqlx(default)]
    pub permissions: Vec<Permission>,
}
