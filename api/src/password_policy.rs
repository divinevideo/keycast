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
        .filter(|ch| !is_ignored_password_character(*ch))
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

fn is_ignored_password_character(ch: char) -> bool {
    matches!(
        ch,
        '\u{0300}'..='\u{036f}'
            | '\u{00ad}'
            | '\u{115f}'..='\u{1160}'
            | '\u{1ab0}'..='\u{1aff}'
            | '\u{1dc0}'..='\u{1dff}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{20d0}'..='\u{20ff}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{fe20}'..='\u{fe2f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e001f}'
            | '\u{e0020}'..='\u{e007f}'
            | '\u{e0080}'..='\u{e00ff}'
            | '\u{e0100}'..='\u{e01ef}'
            | '\u{e01f0}'..='\u{e0fff}'
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
        for password in [
            "password123\u{200b}",
            "password123\u{00ad}",
            "password123\u{fe0f}",
            "password123\u{180b}",
            "password123\u{115f}",
        ] {
            validate_new_password(password)
                .expect_err("weak password with invisible suffix should fail");
        }
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
