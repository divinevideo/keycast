pub mod allowed_kinds;
pub mod content_filter;
pub mod encrypt_to_self;

use serde::Serialize;

/// The list of available permissions
pub static AVAILABLE_PERMISSIONS: [&str; 3] =
    ["allowed_kinds", "content_filter", "encrypt_to_self"];

/// User-friendly description of a permission for display on authorization pages
#[derive(Debug, Clone, Serialize)]
pub struct PermissionDisplay {
    pub icon: &'static str,
    pub title: &'static str,
    pub description: String,
}
