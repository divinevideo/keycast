// Unit test for password reset -> login flow
// This tests the bcrypt password hashing and verification logic directly

use bcrypt::{hash, verify, DEFAULT_COST};

#[test]
fn test_password_hash_and_verify_basic() {
    let password = "test_password_123";

    // Hash the password (like reset_password does)
    let password_hash = hash(password, DEFAULT_COST).unwrap();
    println!("Password hash: {}", &password_hash[..20]);

    // Verify the password (like login does)
    let is_valid = verify(password, &password_hash).unwrap();
    println!("Verification result: {}", is_valid);

    assert!(is_valid, "Password verification should succeed");
}

#[test]
fn test_password_with_special_characters() {
    // Test various password types that 1Password might generate
    let passwords = vec![
        "simple123",
        "Complex@Password#2024!",
        "with spaces in middle",
        "unicode: café résumé",
        "emoji: 🔐🔑",
        "very-long-password-that-goes-on-and-on-for-many-characters-1234567890",
        "MixedCase123ABC",
        "symbols!@#$%^&*()",
        "tabs\tand\nnewlines",
    ];

    for password in passwords {
        println!("\nTesting password: {:?}", password);

        let password_hash = hash(password, DEFAULT_COST).unwrap();
        println!("  Hash (first 20): {}", &password_hash[..20]);

        let is_valid = verify(password, &password_hash).unwrap();
        println!("  Verify result: {}", is_valid);

        assert!(is_valid, "Password '{}' should verify correctly", password);

        // Also verify wrong password fails
        let wrong_valid = verify("wrong_password", &password_hash).unwrap();
        assert!(!wrong_valid, "Wrong password should not verify");
    }
}

#[test]
fn test_password_reset_flow_simulation() {
    // Simulate the exact flow:
    // 1. User sets initial password during registration
    // 2. Password is hashed and stored
    // 3. User requests password reset
    // 4. New password is hashed and stored (overwrites old)
    // 5. User tries to login with new password

    let initial_password = "initial_password_123";
    let new_password = "new_password_456";

    println!("Step 1: Hash initial password");
    let initial_hash = hash(initial_password, DEFAULT_COST).unwrap();
    println!("  Initial hash: {}", &initial_hash[..30]);

    // Verify initial password works
    assert!(verify(initial_password, &initial_hash).unwrap(), "Initial password should work");

    println!("\nStep 2: Simulate password reset - hash new password");
    let new_hash = hash(new_password, DEFAULT_COST).unwrap();
    println!("  New hash: {}", &new_hash[..30]);

    // This is key: the database would now have new_hash stored
    // The "stored_hash" in the DB is new_hash
    let stored_hash = new_hash; // Simulating DB update

    println!("\nStep 3: Login attempt with new password");
    let login_result = verify(new_password, &stored_hash).unwrap();
    println!("  Login verify result: {}", login_result);
    assert!(login_result, "Login with new password should succeed");

    println!("\nStep 4: Verify old password no longer works");
    let old_login_result = verify(initial_password, &stored_hash).unwrap();
    println!("  Old password verify result: {}", old_login_result);
    assert!(!old_login_result, "Old password should NOT work");

    println!("\n✅ Password reset flow test passed!");
}

#[test]
fn test_password_with_json_encoding() {
    // This tests if there's any issue with how the password might be
    // serialized/deserialized through JSON
    use serde_json::json;

    let original_password = "test@password#123!";

    // Simulate what happens when password goes through JSON
    let json_body = json!({
        "email": "test@example.com",
        "password": original_password
    });

    let json_str = serde_json::to_string(&json_body).unwrap();
    println!("JSON string: {}", json_str);

    // Parse it back
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let recovered_password = parsed["password"].as_str().unwrap();

    println!("Original:  {:?}", original_password);
    println!("Recovered: {:?}", recovered_password);

    assert_eq!(original_password, recovered_password, "Password should survive JSON round-trip");

    // Now test the hash/verify with the recovered password
    let hash1 = hash(original_password, DEFAULT_COST).unwrap();
    let hash2 = hash(recovered_password, DEFAULT_COST).unwrap();

    // Both should verify against each other's hashes
    assert!(verify(original_password, &hash1).unwrap());
    assert!(verify(recovered_password, &hash1).unwrap());
    assert!(verify(original_password, &hash2).unwrap());
    assert!(verify(recovered_password, &hash2).unwrap());

    println!("✅ JSON encoding test passed!");
}

#[test]
fn test_password_bytes_vs_string() {
    // Check if there's any difference between how the password is passed
    let password_str = "test_password";
    let password_string = String::from("test_password");
    let password_bytes = password_str.as_bytes();

    // Hash using &str
    let hash_from_str = hash(password_str, DEFAULT_COST).unwrap();

    // Verify using String
    assert!(verify(&password_string, &hash_from_str).unwrap(), "String should verify against &str hash");

    // bcrypt::hash takes AsRef<[u8]>, so both should work identically
    println!("Password as str: {:?}", password_str);
    println!("Password as String: {:?}", password_string);
    println!("Password as bytes: {:?}", password_bytes);
    println!("Hash: {}", &hash_from_str[..30]);

    println!("✅ Bytes vs String test passed!");
}
