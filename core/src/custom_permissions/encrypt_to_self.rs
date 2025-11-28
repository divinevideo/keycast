use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EncryptToSelfConfig {}

pub struct EncryptToSelf {}

#[async_trait]
impl CustomPermission for EncryptToSelf {
    fn from_permission(
        _permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        Ok(Box::new(Self {}))
    }

    fn identifier(&self) -> &'static str {
        "encrypt_to_self"
    }

    // This permission doesn't care about signing events
    fn can_sign(&self, _event: &UnsignedEvent) -> bool {
        true
    }

    fn can_encrypt(
        &self,
        _plaintext: &str,
        sender_pubkey: &PublicKey,
        recipient_pubkey: &PublicKey,
    ) -> bool {
        *sender_pubkey == *recipient_pubkey
    }

    fn can_decrypt(
        &self,
        _ciphertext: &str,
        sender_pubkey: &PublicKey,
        recipient_pubkey: &PublicKey,
    ) -> bool {
        *sender_pubkey == *recipient_pubkey
    }

    fn display(&self) -> PermissionDisplay {
        PermissionDisplay {
            icon: "🔒",
            title: "Private message restriction",
            description: "Can only send messages to yourself (for backups or notes)".to_string(),
        }
    }
}
