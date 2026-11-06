use keycast_core::password_policy::{validate_new_password, PasswordPolicyError};

#[test]
fn rejects_short_and_common_new_passwords() {
    for password in [
        "",
        "1234",
        "seven77",
        "password",
        "password123",
        " PASSWORD123 ",
        "12345678",
        "qwerty123",
        "        ",
        "  short  ",
    ] {
        assert_eq!(validate_new_password(password), Err(PasswordPolicyError));
    }
}

#[test]
fn counts_unicode_characters_not_bytes() {
    assert!(validate_new_password("éééé").is_err());
    assert!(validate_new_password("八文字の合言葉です").is_ok());
}

#[test]
fn accepts_passphrases_without_composition_rules() {
    for password in [
        "violet otters share teacups",
        "uncommon",
        "a7!M2#k9",
        "  violet otters  ",
    ] {
        assert!(validate_new_password(password).is_ok());
    }
}

#[test]
fn error_contract_is_stable_and_contains_no_input() {
    assert_eq!(PasswordPolicyError.code(), "WEAK_PASSWORD");
    assert_eq!(
        PasswordPolicyError.message(),
        PasswordPolicyError.to_string()
    );
    assert_eq!(
        PasswordPolicyError.to_string(),
        "Use at least 8 characters and avoid common passwords."
    );
}
