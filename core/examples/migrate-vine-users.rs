// ABOUTME: Migrate vine-imported users from openvine-co to dv-platform-prod
// ABOUTME: Re-encrypts personal keys with target KMS key
// ABOUTME: Run with: cargo run --example migrate-vine-users
//
// Phase 1: KMS round-trip test (current) - validates KMS access
// Phase 2: Single user migration - adds DB connectivity
// Phase 3: Full migration - batch process all vine users

use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest};

// Source: Cloud Run (openvine-co)
const SOURCE_PROJECT: &str = "openvine-co";
const SOURCE_LOCATION: &str = "global";
const SOURCE_KEYRING: &str = "keycast-keys";
const SOURCE_KEY: &str = "master-key";

// Target: GKE (dv-platform-prod)
const TARGET_PROJECT: &str = "dv-platform-prod";
const TARGET_LOCATION: &str = "us-central1";
const TARGET_KEYRING: &str = "app-keys-production";
const TARGET_KEY: &str = "keycast-master-key";

fn key_path(project: &str, location: &str, keyring: &str, key: &str) -> String {
    format!(
        "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
        project, location, keyring, key
    )
}

async fn test_encrypt_decrypt(client: &Client, key_path: &str) -> Result<(), String> {
    let test_data = format!(
        "migration-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    // Test encrypt
    println!("  🔒 Testing encrypt...");
    let encrypt_request = EncryptRequest {
        name: key_path.to_string(),
        plaintext: test_data.as_bytes().to_vec(),
        additional_authenticated_data: vec![],
        plaintext_crc32c: None,
        additional_authenticated_data_crc32c: None,
    };

    let encrypted = client
        .encrypt(encrypt_request, None)
        .await
        .map_err(|e| format!("Encrypt failed: {}", e))?;

    println!("  ✅ Encrypt OK ({} bytes)", encrypted.ciphertext.len());

    // Test decrypt
    println!("  🔓 Testing decrypt...");
    let decrypt_request = DecryptRequest {
        name: key_path.to_string(),
        ciphertext: encrypted.ciphertext,
        additional_authenticated_data: vec![],
        ciphertext_crc32c: None,
        additional_authenticated_data_crc32c: None,
    };

    let decrypted = client
        .decrypt(decrypt_request, None)
        .await
        .map_err(|e| format!("Decrypt failed: {}", e))?;

    if decrypted.plaintext == test_data.as_bytes() {
        println!("  ✅ Decrypt OK (verified)");
        Ok(())
    } else {
        Err("Decrypt succeeded but data mismatch".to_string())
    }
}

/// Test decrypt only (for source - we only need to read existing secrets)
async fn test_decrypt_with_sample(
    client: &Client,
    source_key: &str,
    target_key: &str,
) -> Result<(), String> {
    // First encrypt something with target key (which we have full access to)
    let test_data = format!(
        "migration-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    println!("  🔒 Creating test ciphertext with target key...");
    let encrypt_request = EncryptRequest {
        name: target_key.to_string(),
        plaintext: test_data.as_bytes().to_vec(),
        additional_authenticated_data: vec![],
        plaintext_crc32c: None,
        additional_authenticated_data_crc32c: None,
    };

    let encrypted = client
        .encrypt(encrypt_request, None)
        .await
        .map_err(|e| format!("Encrypt with target key failed: {}", e))?;

    // Now test that we can decrypt with source key
    // NOTE: This will fail because data encrypted with target key can't be decrypted with source key
    // Instead, we just test that we have decrypt permission by trying to decrypt garbage
    // (it will fail with decryption error, not permission error)

    println!("  🔓 Testing decrypt permission on source key...");
    let decrypt_request = DecryptRequest {
        name: source_key.to_string(),
        ciphertext: encrypted.ciphertext, // This is encrypted with wrong key, but tests permission
        additional_authenticated_data: vec![],
        ciphertext_crc32c: None,
        additional_authenticated_data_crc32c: None,
    };

    match client.decrypt(decrypt_request, None).await {
        Ok(_) => {
            // Unexpected success (shouldn't happen with wrong key)
            println!("  ✅ Decrypt OK (unexpected but good)");
            Ok(())
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("PermissionDenied") || err_str.contains("permission") {
                Err(format!("Decrypt permission denied: {}", e))
            } else {
                // Decryption failed for other reason (e.g., wrong key) - but we have permission!
                println!(
                    "  ✅ Decrypt permission OK (decryption failed as expected - different key)"
                );
                Ok(())
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Migration KMS Access Test");
    println!("============================");
    println!();
    println!("This tests if the current credentials can access BOTH KMS keys");
    println!("needed for cross-project migration.");
    println!();

    // Initialize KMS client (uses Application Default Credentials)
    println!("📡 Initializing GCP KMS client...");
    let config = ClientConfig::default()
        .with_auth()
        .await
        .map_err(|e| format!("Auth failed: {}", e))?;

    let client = Client::new(config)
        .await
        .map_err(|e| format!("Client creation failed: {}", e))?;

    println!("✅ KMS client initialized");
    println!();

    // Test target KMS first (dv-platform-prod) - we need full access here
    let target_path = key_path(TARGET_PROJECT, TARGET_LOCATION, TARGET_KEYRING, TARGET_KEY);
    println!("=== TARGET: dv-platform-prod (GKE) ===");
    println!("Key: {}", target_path);
    println!("Required: encrypt + decrypt (to store migrated secrets)");

    let target_result = test_encrypt_decrypt(&client, &target_path).await;
    let target_ok = target_result.is_ok();
    if let Err(e) = &target_result {
        println!("  ❌ FAILED: {}", e);
    }
    println!();

    // Test source KMS (openvine-co) - only need decrypt permission
    let source_path = key_path(SOURCE_PROJECT, SOURCE_LOCATION, SOURCE_KEYRING, SOURCE_KEY);
    println!("=== SOURCE: openvine-co (Cloud Run) ===");
    println!("Key: {}", source_path);
    println!("Required: decrypt only (to read existing secrets)");

    let source_result = if target_ok {
        test_decrypt_with_sample(&client, &source_path, &target_path).await
    } else {
        Err("Skipped - target test failed".to_string())
    };
    let source_ok = source_result.is_ok();
    if let Err(e) = source_result {
        println!("  ❌ FAILED: {}", e);
    }
    println!();

    // Summary
    println!("============================");
    println!("SUMMARY:");
    println!(
        "  Source (openvine-co):     {}",
        if source_ok { "✅ OK" } else { "❌ FAILED" }
    );
    println!(
        "  Target (dv-platform-prod): {}",
        if target_ok { "✅ OK" } else { "❌ FAILED" }
    );
    println!();

    if source_ok && target_ok {
        println!("🎉 Both KMS keys accessible!");
        println!("   You can use the cross-project migration approach.");
        println!("   A single job can decrypt from source and re-encrypt to target.");
    } else if source_ok && !target_ok {
        println!("⚠️  Only source accessible.");
        println!("   You'll need the HTTPS endpoint approach:");
        println!("   - Source decrypts and sends to target over HTTPS");
        println!("   - Target encrypts with its own KMS");
    } else if !source_ok && target_ok {
        println!("⚠️  Only target accessible.");
        println!("   You may need to run the migration from the source environment.");
    } else {
        println!("❌ Neither KMS key accessible.");
        println!("   Check your GCP authentication and IAM permissions.");
    }

    Ok(())
}
