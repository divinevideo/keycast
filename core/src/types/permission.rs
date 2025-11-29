use crate::custom_permissions::{
    allowed_kinds::AllowedKinds, content_filter::ContentFilter, decrypt_only::DecryptOnly,
    encrypt_to_self::EncryptToSelf, full_access::FullAccess,
};
use crate::traits::CustomPermission;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PermissionError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Unknown permission type: {0}")]
    UnknownPermission(String),
    #[error("Invalid permission configuration: {0}")]
    InvalidConfig(String),
}

/// Wrapper for JSON config stored as TEXT in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonConfig(pub serde_json::Value);

impl TryFrom<String> for JsonConfig {
    type Error = serde_json::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(JsonConfig(serde_json::from_str(&s)?))
    }
}

/// A permission is database representation of a CustomPermission trait
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Permission {
    /// The id of the permission
    pub id: i32,
    /// The identifier of the permission
    pub identifier: String,
    /// The configuration of the permission
    #[sqlx(try_from = "String")]
    pub config: JsonConfig,
    /// The date and time the permission was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the permission was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

impl Permission {
    /// Get the config as serde_json::Value
    pub fn config_value(&self) -> &serde_json::Value {
        &self.config.0
    }

    /// Convert this database permission into a CustomPermission implementation
    pub fn to_custom_permission(&self) -> Result<Box<dyn CustomPermission>, PermissionError> {
        match self.identifier.as_str() {
            id if id.starts_with("allowed_kinds") => AllowedKinds::from_permission(self),
            "content_filter" => ContentFilter::from_permission(self),
            "decrypt_only" => DecryptOnly::from_permission(self),
            "encrypt_to_self" => EncryptToSelf::from_permission(self),
            "full_access" => FullAccess::from_permission(self),
            _ => Err(PermissionError::UnknownPermission(self.identifier.clone())),
        }
    }
}

/// A policy permission is a join table between a policy and a permission
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyPermission {
    /// The id of the policy permission
    pub id: i32,
    /// The id of the policy
    pub policy_id: i32,
    /// The id of the permission
    pub permission_id: i32,
    /// The date and time the policy permission was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the policy permission was last updated
    pub updated_at: DateTime<chrono::Utc>,
}
