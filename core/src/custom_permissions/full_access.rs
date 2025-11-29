use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};

/// Full access permission - allows all operations without restriction
pub struct FullAccess;

#[async_trait]
impl CustomPermission for FullAccess {
    fn from_permission(
        _permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        Ok(Box::new(Self))
    }

    fn identifier(&self) -> &'static str {
        "full_access"
    }

    fn can_sign(&self, _event: &UnsignedEvent) -> bool {
        true
    }

    fn can_encrypt(
        &self,
        _plaintext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
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
            icon: "🔓",
            title: "Full access",
            description: "Sign, encrypt, and decrypt anything without restrictions".to_string(),
        }
    }
}
