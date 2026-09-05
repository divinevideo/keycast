//! Password-login attempt policy shared by every credential login surface.

use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};

/// Failures allowed before the first delay is imposed.
pub const LOGIN_FREE_FAILURES: u32 = 3;
/// Longest delay imposed between password attempts.
pub const LOGIN_MAX_DELAY: Duration = Duration::from_secs(15 * 60);
/// Lifetime of failure history after the latest failed attempt.
pub const LOGIN_FAILURE_STATE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum lifetime of an abandoned in-flight attempt.
pub const LOGIN_RESERVATION_TTL: Duration = Duration::from_secs(60);
/// Concurrent password checks admitted for one account identifier.
pub const LOGIN_MAX_IN_FLIGHT: u32 = 5;

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

/// Return the delay imposed after a given number of failures.
#[must_use]
pub fn delay_after_failure(failures: u32) -> Option<Duration> {
    let exponent = failures.checked_sub(LOGIN_FREE_FAILURES)?;
    let seconds = 1_u64
        .checked_shl(exponent.min(63))
        .unwrap_or(u64::MAX)
        .min(LOGIN_MAX_DELAY.as_secs());
    Some(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_starts_at_boundary_and_escalates_to_cap() {
        assert_eq!(delay_after_failure(2), None);
        assert_eq!(delay_after_failure(3), Some(Duration::from_secs(1)));
        assert_eq!(delay_after_failure(4), Some(Duration::from_secs(2)));
        assert_eq!(delay_after_failure(5), Some(Duration::from_secs(4)));
        assert_eq!(delay_after_failure(20), Some(LOGIN_MAX_DELAY));
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
