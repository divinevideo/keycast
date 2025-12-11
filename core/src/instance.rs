// ABOUTME: Global instance identity for distributed tracing
// ABOUTME: Provides unique instance ID that persists for the lifetime of the process

use std::sync::OnceLock;
use uuid::Uuid;

/// Global instance identity, initialized once on first access
static INSTANCE_ID: OnceLock<String> = OnceLock::new();

/// Get the unique instance ID for this process.
///
/// Format: `{revision}-{short_uuid}` where:
/// - revision: Cloud Run K_REVISION or "local"
/// - short_uuid: First 8 chars of a UUID (unique per process)
///
/// Example: `keycast-00042-abc-a1b2c3d4`
pub fn instance_id() -> &'static str {
    INSTANCE_ID.get_or_init(|| {
        let revision = std::env::var("K_REVISION").unwrap_or_else(|_| "local".to_string());
        let uuid_short = &Uuid::new_v4().to_string()[..8];
        format!("{}-{}", revision, uuid_short)
    })
}

/// Get just the short unique part (8 char UUID)
/// Useful for compact logging
pub fn instance_short_id() -> &'static str {
    let full_id = instance_id();
    // Return the last 8 characters (the UUID part)
    &full_id[full_id.len().saturating_sub(8)..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_id_format() {
        let id = instance_id();
        assert!(id.contains('-'));
        assert!(id.len() >= 13); // "local-xxxxxxxx" minimum
    }

    #[test]
    fn test_instance_id_stable() {
        let id1 = instance_id();
        let id2 = instance_id();
        assert_eq!(id1, id2);
    }
}
