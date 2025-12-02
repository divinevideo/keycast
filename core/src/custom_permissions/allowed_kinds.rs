use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AllowedKindsConfig {
    pub allowed_kinds: Option<Vec<u16>>,
}

pub struct AllowedKinds {
    config: AllowedKindsConfig,
}

impl AllowedKinds {
    /// Returns the set of allowed kinds, or None if all kinds are allowed
    pub fn allowed_kinds(&self) -> Option<&Vec<u16>> {
        self.config.allowed_kinds.as_ref()
    }
}

/// Event kind categories for DM-related kinds
const DM_KINDS: [u16; 3] = [4, 44, 1059];

/// Map a Nostr event kind to a user-friendly description
fn kind_to_friendly_name(kind: u16) -> &'static str {
    match kind {
        0 => "Update your profile",
        1 => "Post notes",
        3 => "Manage your contact list",
        4 => "Send and read private messages",
        7 => "React to posts",
        22 => "Upload videos",
        44 => "Send and read private messages",
        1059 => "Send and read private messages",
        9735 => "Send zaps",
        10002 => "Set your relay list",
        30023 => "Write long-form articles",
        _ => "Other actions",
    }
}

#[async_trait]
impl CustomPermission for AllowedKinds {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let parsed_config: AllowedKindsConfig = serde_json::from_value(permission.config.0.clone())
            .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;

        Ok(Box::new(Self {
            config: parsed_config,
        }))
    }

    fn identifier(&self) -> &'static str {
        "allowed_kinds"
    }

    fn can_sign(&self, event: &UnsignedEvent) -> bool {
        match &self.config.allowed_kinds {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }

    // We don't get event info from these requests, so we must always allow
    fn can_encrypt(
        &self,
        _plaintext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }
    // We don't get event info from these requests, so we must always allow
    fn can_decrypt(
        &self,
        _ciphertext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }

    fn display(&self) -> PermissionDisplay {
        match &self.config.allowed_kinds {
            None => PermissionDisplay {
                icon: "✏️",
                title: "Full access",
                description: "Can perform all actions on your behalf".to_string(),
            },
            Some(kinds) => {
                // Group kinds into user-friendly descriptions, deduplicating
                let mut abilities: Vec<&'static str> = Vec::new();
                let mut seen: HashSet<&'static str> = HashSet::new();

                // Check for DM capability (any DM kind)
                let can_dm = kinds.iter().any(|k| DM_KINDS.contains(k));
                if can_dm {
                    let desc = "Send and read private messages";
                    if seen.insert(desc) {
                        abilities.push(desc);
                    }
                }

                // Add other abilities, skipping DM kinds (already handled)
                for kind in kinds {
                    if DM_KINDS.contains(kind) {
                        continue;
                    }
                    let desc = kind_to_friendly_name(*kind);
                    if seen.insert(desc) {
                        abilities.push(desc);
                    }
                }

                if abilities.is_empty() {
                    abilities.push("Limited actions");
                }

                PermissionDisplay {
                    icon: "✏️",
                    title: "What this app can do",
                    description: abilities.join(", "),
                }
            }
        }
    }
}

#[test]
fn test_default() {
    let config = AllowedKindsConfig::default();
    assert!(config.allowed_kinds.is_none());
}
