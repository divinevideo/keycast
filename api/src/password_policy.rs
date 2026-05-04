// ABOUTME: Shared server-side password policy for all new password submissions
// ABOUTME: Keeps legacy login compatible by validating only newly submitted passwords

pub const WEAK_PASSWORD_CODE: &str = "WEAK_PASSWORD";
pub const WEAK_PASSWORD_MESSAGE: &str =
    "Password must be at least 12 characters and not be a common weak password.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicyError;

impl PasswordPolicyError {
    pub const fn code(self) -> &'static str {
        WEAK_PASSWORD_CODE
    }

    pub const fn message(self) -> &'static str {
        WEAK_PASSWORD_MESSAGE
    }
}

pub fn validate_new_password(password: &str) -> Result<(), PasswordPolicyError> {
    let normalized = password.trim().to_ascii_lowercase();

    if password.chars().count() < 12 {
        return Err(PasswordPolicyError);
    }

    if matches!(normalized.as_str(), "1234" | "password" | "password123") {
        return Err(PasswordPolicyError);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_new_password, WEAK_PASSWORD_CODE, WEAK_PASSWORD_MESSAGE};

    #[test]
    fn rejects_obvious_weak_passwords() {
        for password in ["1234", "password", "password123"] {
            let error = validate_new_password(password).expect_err("weak password should fail");

            assert_eq!(error.code(), WEAK_PASSWORD_CODE);
            assert_eq!(error.message(), WEAK_PASSWORD_MESSAGE);
        }
    }

    #[test]
    fn rejects_passwords_shorter_than_twelve_characters() {
        validate_new_password("🔑🔑🔑").expect_err("short password should fail");
    }

    #[test]
    fn accepts_representative_strong_password() {
        validate_new_password("correct-horse-42-battery").expect("strong password should pass");
    }
}
