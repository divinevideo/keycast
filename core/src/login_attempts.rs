//! Password-login attempt policy shared by every credential login surface.

use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};

/// Failures allowed before the first delay is imposed.
pub const LOGIN_FREE_FAILURES: u32 = 3;
/// Sliding window used to count recent failures.
pub const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Maximum lifetime of an abandoned in-flight attempt.
pub const LOGIN_RESERVATION_TTL: Duration = Duration::from_secs(60);
/// Concurrent password checks admitted for one account identifier.
pub const LOGIN_MAX_IN_FLIGHT: u32 = 1;
/// Escalating delays selected after the free failures are spent.
pub const LOGIN_DELAYS_SECONDS: &[u32] = &[5, 10, 20, 40, 80, 160, 320, 640, 900];

/// Redis-safe identity for one tenant's normalized login email.
#[derive(Clone, Eq, PartialEq)]
pub struct LoginAttemptSubject(String);

impl LoginAttemptSubject {
    /// Build a subject without placing an email address in Redis key names.
    #[must_use]
    pub fn new(tenant_id: i64, normalized_email: &str) -> Self {
        let digest = Sha256::digest(normalized_email.as_bytes());
        Self(format!("login_attempt:{{{tenant_id}:{digest:x}}}"))
    }

    /// Return the storage key shared by this subject's Redis records.
    #[must_use]
    pub fn storage_key(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LoginAttemptSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LoginAttemptSubject")
            .field(&"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_schedule_escalates_to_fifteen_minutes() {
        assert_eq!(&LOGIN_DELAYS_SECONDS[..3], &[5, 10, 20]);
        assert_eq!(LOGIN_DELAYS_SECONDS.last(), Some(&900));
    }

    #[test]
    fn subject_does_not_expose_email_and_is_tenant_scoped() {
        let first = LoginAttemptSubject::new(1, "person@example.com");
        let second = LoginAttemptSubject::new(2, "person@example.com");

        assert!(!first.storage_key().contains("person@example.com"));
        assert_ne!(first, second);
        assert_eq!(format!("{first:?}"), "LoginAttemptSubject(\"<redacted>\")");
    }
}
