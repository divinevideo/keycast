//! Policy for newly submitted passwords, independent of stored-hash verification.

/// A new password did not meet the shared requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Use at least 8 characters and avoid common passwords.")]
pub struct PasswordPolicyError;

impl PasswordPolicyError {
    /// Return the stable client-facing error code.
    pub const fn code(self) -> &'static str {
        "WEAK_PASSWORD"
    }

    /// Return the stable client-facing guidance.
    pub const fn message(self) -> &'static str {
        "Use at least 8 characters and avoid common passwords."
    }
}

// A deliberately bounded list of obvious common choices, not a breach-corpus check.
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "password1234",
    "12345678",
    "123456789",
    "1234567890",
    "12345678910",
    "11111111",
    "00000000",
    "87654321",
    "abcdefgh",
    "qwerty123",
    "qwertyuiop",
    "qwertyui",
    "asdfghjk",
    "asdfghjkl",
    "iloveyou",
    "letmein123",
    "welcome1",
    "admin123",
    "abc12345",
    "1q2w3e4r",
    "1qaz2wsx",
];

/// Validate a new password without changing the value that will be hashed.
///
/// No composition rules are imposed, so passphrases and Unicode remain supported.
/// Do not call this when verifying an existing password.
///
/// # Errors
/// Returns [`PasswordPolicyError`] for fewer than eight characters after trimming, or a common choice.
pub fn validate_new_password(password: &str) -> Result<(), PasswordPolicyError> {
    let trimmed = password.trim();
    if trimmed.chars().count() < 8
        || COMMON_PASSWORDS
            .iter()
            .any(|common| trimmed.eq_ignore_ascii_case(common))
    {
        return Err(PasswordPolicyError);
    }
    Ok(())
}
