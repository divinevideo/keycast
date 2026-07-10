#![cfg(feature = "integration-tests")]

// ABOUTME: Verified_minor DM containment gate tests for the NIP-46 signer daemon
// ABOUTME: path (support-trust-safety#183) — the relay-based signing surface.

use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use keycast_core::signing_handler::SigningHandler;
use keycast_core::verified_minor_dm::PINNED_MINOR_CONTACTABLE_PUBKEYS;
use keycast_signer::Nip46Handler;
use nostr_sdk::nips::nip44;
use nostr_sdk::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_test_db() -> PgPool {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set to run database tests");

    PgPool::connect(&database_url).await.expect(
        "Failed to connect to database. Make sure PostgreSQL is running and DATABASE_URL is set.",
    )
}

fn hq_pubkey() -> PublicKey {
    PublicKey::from_hex(PINNED_MINOR_CONTACTABLE_PUBKEYS[0]).unwrap()
}

/// Create a user (optionally verified_minor) with a personal key and an OAuth
/// authorization row, and return an OAuth-mode Nip46Handler for it.
async fn create_oauth_handler(
    pool: &PgPool,
    key_manager: &dyn KeyManager,
    verified_minor: bool,
) -> (Nip46Handler, Keys) {
    let user_keys = Keys::generate();
    let bunker_keys = Keys::generate();

    if verified_minor {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, verified_minor, verified_minor_at, created_at, updated_at)
             VALUES ($1, 1, TRUE, NOW(), NOW(), NOW())",
        )
        .bind(user_keys.public_key().to_hex())
        .execute(pool)
        .await
        .expect("Failed to create verified_minor user");
    } else {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(user_keys.public_key().to_hex())
        .execute(pool)
        .await
        .expect("Failed to create user");
    }

    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, 1)",
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    let secret_hash = bcrypt::hash(format!("secret_{}", Uuid::new_v4()), 4).expect("hash");
    let oauth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays, policy_id, tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Minor Gate Test App', $3, $4, $5, NULL, 1, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(user_keys.public_key().to_hex())
    .bind(format!("https://minor-daemon-{}.example.com", Uuid::new_v4()))
    .bind(bunker_keys.public_key().to_hex())
    .bind(&secret_hash)
    .bind(serde_json::json!(["wss://relay.example.com"]))
    .fetch_one(pool)
    .await
    .expect("Failed to create OAuth authorization");

    let handler = Nip46Handler::new_for_test(
        bunker_keys,
        user_keys.clone(),
        secret_hash,
        oauth_id,
        1,
        true, // OAuth: user-account-backed, subject to status + minor gates
        pool.clone(),
    );

    (handler, user_keys)
}

fn dm_rumor(kind: u16, author: &Keys, recipients: &[PublicKey]) -> UnsignedEvent {
    let tags: Vec<Tag> = recipients.iter().map(|pk| Tag::public_key(*pk)).collect();
    EventBuilder::new(Kind::from(kind), "daemon gate test")
        .tags(tags)
        .build(author.public_key())
}

fn assert_denied(err: impl std::fmt::Display) {
    let msg = err.to_string();
    assert!(
        msg.contains("Operation denied by policy"),
        "expected the uniform policy-denial message, got: {msg}"
    );
}

// ============================================================================
// sign path (sign_event_direct — shared gate with the relay dispatch)
// ============================================================================

#[tokio::test]
async fn daemon_minor_sign_rumor_to_arbitrary_recipient_refused() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = create_oauth_handler(&pool, &key_manager, true).await;
    let mallory = Keys::generate();

    let unsigned = dm_rumor(14, &user_keys, &[mallory.public_key()]);
    let err = handler
        .sign_event_direct(unsigned)
        .await
        .expect_err("minor DM rumor to arbitrary recipient must be refused");
    assert_denied(err);
}

#[tokio::test]
async fn daemon_minor_sign_rumor_to_pinned_official_allowed() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = create_oauth_handler(&pool, &key_manager, true).await;

    let unsigned = dm_rumor(14, &user_keys, &[hq_pubkey()]);
    let signed = handler
        .sign_event_direct(unsigned)
        .await
        .expect("minor DM rumor to pinned official must sign");
    signed.verify().expect("valid signature");
}

#[tokio::test]
async fn daemon_minor_sign_public_note_unaffected() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = create_oauth_handler(&pool, &key_manager, true).await;
    let mallory = Keys::generate();

    let unsigned = dm_rumor(1, &user_keys, &[mallory.public_key()]);
    handler
        .sign_event_direct(unsigned)
        .await
        .expect("minor public note must sign normally");
}

#[tokio::test]
async fn daemon_minor_seal_gate_enforced() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = create_oauth_handler(&pool, &key_manager, true).await;
    let mallory = Keys::generate();

    let rumor = serde_json::json!({
        "id": "0000000000000000000000000000000000000000000000000000000000000000",
        "pubkey": user_keys.public_key().to_hex(),
        "created_at": 1_700_000_000,
        "kind": 14,
        "tags": [["p", hq_pubkey().to_hex()]],
        "content": "sealed",
    })
    .to_string();

    // Legit: sealed to the official under the user's conversation key.
    let official_content = nip44::encrypt(
        user_keys.secret_key(),
        &hq_pubkey(),
        &rumor,
        nip44::Version::V2,
    )
    .expect("encrypt to official");
    let seal = EventBuilder::new(Kind::from(13u16), official_content).build(user_keys.public_key());
    handler
        .sign_event_direct(seal)
        .await
        .expect("seal to pinned official must sign");

    // Smuggled: sealed under the user<->mallory conversation key.
    let mallory_content = nip44::encrypt(
        mallory.secret_key(),
        &user_keys.public_key(),
        &rumor,
        nip44::Version::V2,
    )
    .expect("mallory-side encrypt");
    let seal = EventBuilder::new(Kind::from(13u16), mallory_content).build(user_keys.public_key());
    let err = handler
        .sign_event_direct(seal)
        .await
        .expect_err("seal to arbitrary recipient must be refused");
    assert_denied(err);
}

#[tokio::test]
async fn daemon_non_minor_sign_unaffected() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = create_oauth_handler(&pool, &key_manager, false).await;
    let mallory = Keys::generate();

    let unsigned = dm_rumor(14, &user_keys, &[mallory.public_key()]);
    handler
        .sign_event_direct(unsigned)
        .await
        .expect("non-minor DM rumor to anyone must sign");
}

// ============================================================================
// encrypt / decrypt validation path (relay nip04/nip44 dispatch)
// ============================================================================

#[tokio::test]
async fn daemon_minor_encrypt_to_arbitrary_recipient_refused() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, _user_keys) = create_oauth_handler(&pool, &key_manager, true).await;
    let mallory = Keys::generate();

    let err = handler
        .validate_permissions_for_encrypt("hello", &mallory.public_key())
        .await
        .expect_err("minor encrypt to arbitrary recipient must be refused");
    assert_denied(err);
}

#[tokio::test]
async fn daemon_minor_encrypt_to_official_and_self_allowed() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = create_oauth_handler(&pool, &key_manager, true).await;

    handler
        .validate_permissions_for_encrypt("hello hq", &hq_pubkey())
        .await
        .expect("minor encrypt to pinned official must be allowed");
    handler
        .validate_permissions_for_encrypt("note to self", &user_keys.public_key())
        .await
        .expect("minor encrypt to self must be allowed");
}

#[tokio::test]
async fn daemon_minor_decrypt_from_arbitrary_sender_still_allowed() {
    // #183 scopes containment to egress; decrypt (ingress) is out of scope.
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, _user_keys) = create_oauth_handler(&pool, &key_manager, true).await;
    let mallory = Keys::generate();

    handler
        .validate_permissions_for_decrypt("ciphertext", &mallory.public_key())
        .await
        .expect("minor decrypt from arbitrary sender stays allowed (egress-only gate)");
}

#[tokio::test]
async fn daemon_non_minor_encrypt_unaffected() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, _user_keys) = create_oauth_handler(&pool, &key_manager, false).await;
    let mallory = Keys::generate();

    handler
        .validate_permissions_for_encrypt("hello", &mallory.public_key())
        .await
        .expect("non-minor encrypt to anyone must be allowed");
}
