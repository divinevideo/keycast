pub mod allowed_kinds;
pub mod content_filter;
pub mod decrypt_only;
pub mod encrypt_to_self;
pub mod full_access;

use serde::Serialize;

/// The list of available permissions
pub static AVAILABLE_PERMISSIONS: [&str; 5] = [
    "allowed_kinds",
    "content_filter",
    "decrypt_only",
    "encrypt_to_self",
    "full_access",
];

/// User-friendly description of a permission for display on authorization pages
#[derive(Debug, Clone, Serialize)]
pub struct PermissionDisplay {
    pub icon: &'static str,
    pub title: &'static str,
    pub description: String,
}
