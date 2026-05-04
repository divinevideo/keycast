// ABOUTME: Shared server-side password policy for all new password submissions
// ABOUTME: Keeps legacy login compatible by validating only newly submitted passwords

pub const WEAK_PASSWORD_CODE: &str = "WEAK_PASSWORD";
pub const WEAK_PASSWORD_MESSAGE: &str =
    "Password must be at least 12 characters and not be a common weak password.";
const BCRYPT_MAX_PASSWORD_BYTES: usize = 72;

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
    if password.len() > BCRYPT_MAX_PASSWORD_BYTES {
        return Err(PasswordPolicyError);
    }

    let normalized = password
        .trim()
        .chars()
        .filter(|ch| !is_invisible_format_character(*ch))
        .collect::<String>()
        .to_ascii_lowercase();

    if normalized.chars().count() < 12 {
        return Err(PasswordPolicyError);
    }

    if matches!(normalized.as_str(), "1234" | "password" | "password123") {
        return Err(PasswordPolicyError);
    }

    Ok(())
}

fn is_invisible_format_character(ch: char) -> bool {
    matches!(
        ch,
        '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
    )
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
    fn rejects_whitespace_only_passwords() {
        validate_new_password("            ").expect_err("whitespace-only password should fail");
    }

    #[test]
    fn rejects_obvious_weak_passwords_with_invisible_suffixes() {
        validate_new_password("password123\u{200b}")
            .expect_err("weak password with invisible suffix should fail");
    }

    #[test]
    fn rejects_passwords_over_bcrypt_byte_limit() {
        let password = "a".repeat(73);

        validate_new_password(&password).expect_err("overlong bcrypt input should fail");
    }

    #[test]
    fn accepts_representative_strong_password() {
        validate_new_password("correct-horse-42-battery").expect("strong password should pass");
    }
}
