use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};

/// NIP-42 relay authentication kind
const NIP42_AUTH_KIND: u16 = 22242;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DecryptOnlyConfig {}

pub struct DecryptOnly {
    #[allow(dead_code)]
    config: DecryptOnlyConfig,
}

#[async_trait]
impl CustomPermission for DecryptOnly {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let parsed_config: DecryptOnlyConfig =
            serde_json::from_value(permission.config.0.clone())
                .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;

        Ok(Box::new(Self {
            config: parsed_config,
        }))
    }

    fn identifier(&self) -> &'static str {
        "decrypt_only"
    }

    fn can_sign(&self, event: &UnsignedEvent) -> bool {
        // Only allow NIP-42 relay auth (required to authenticate with relays for reading)
        let kind: u16 = event.kind.into();
        kind == NIP42_AUTH_KIND
    }

    fn can_encrypt(
        &self,
        _plaintext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        false
    }

    fn can_decrypt(
        &self,
        _ciphertext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }

    fn display(&self) -> PermissionDisplay {
        PermissionDisplay {
            icon: "👁️",
            title: "Read only",
            description: "Can only read encrypted messages, cannot post or send messages".to_string(),
        }
    }
}
