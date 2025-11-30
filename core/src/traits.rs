use crate::custom_permissions::PermissionDisplay;
use crate::types::permission::{Permission, PermissionError};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};

/// A trait that represents a custom permission.
///
/// Permissions are evaluated using AND logic: when multiple permissions are configured,
/// ALL permissions must return `true` for the operation to be allowed. This provides
/// defense-in-depth security where permissions act as stacking restrictions.
///
/// # Permission Semantics
///
/// Each method returns `true` to allow the operation, `false` to deny it.
///
/// - If no permissions are configured: operation is allowed (permissive default)
/// - If any permission denies: operation is denied (AND logic)
/// - Only if all permissions allow: operation proceeds
///
/// # Example
///
/// With permissions `allowed_kinds: [1, 2]` and `content_filter: [deny: "bad"]`:
/// - Event kind 1 with content "hello" → allowed (both pass)
/// - Event kind 1 with content "bad word" → denied (content_filter fails)
/// - Event kind 3 with content "hello" → denied (allowed_kinds fails)
#[async_trait]
pub trait CustomPermission: Send + Sync {
    /// Create a new instance of the permission from a database Permission
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError>
    where
        Self: Sized;

    fn identifier(&self) -> &'static str;

    /// A function that returns true if allowed to sign the event.
    fn can_sign(&self, event: &UnsignedEvent) -> bool;

    /// A function that returns true if allowed to encrypt the content for the recipient.
    /// Sender is the pubkey of the user requesting the encryption
    fn can_encrypt(
        &self,
        plaintext: &str,
        sender_pubkey: &PublicKey,
        recipient_pubkey: &PublicKey,
    ) -> bool;

    /// A function that returns true if allowed to decrypt the content from the sender.
    /// Recipient is the pubkey of the user requesting the decryption
    fn can_decrypt(
        &self,
        ciphertext: &str,
        sender_pubkey: &PublicKey,
        recipient_pubkey: &PublicKey,
    ) -> bool;

    /// Returns a user-friendly description of this permission for display on authorization pages
    fn display(&self) -> PermissionDisplay;
}
