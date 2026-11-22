#![cfg(feature = "integration-tests")]

// ABOUTME: Unconfirmed-email DM gate tests for the NIP-46 signer daemon path,
// ABOUTME: the relay-based signing surface third-party clients use.

use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use keycast_core::signing_handler::SigningHandler;
use keycast_signer::Nip46Handler;
use nostr_sdk::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_test_db() -> PgPool {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set to run database tests");
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

/// An OAuth-mode handler for a user whose email is stored with `email_verified`.
async fn handler_with_email(
    pool: &PgPool,
    key_manager: &dyn KeyManager,
    email_verified: bool,
) -> (Nip46Handler, Keys) {
    let user_keys = Keys::generate();
    let bunker_keys = Keys::generate();
    let pubkey = user_keys.public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(format!("{pubkey}@example.com"))
    .bind(email_verified)
    .execute(pool)
    .await
    .expect("Failed to create user");

    let encrypted_secret = key_manager
        .encrypt(&user_keys.secret_key().secret_bytes())
        .await
        .expect("Failed to encrypt user secret");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, 1)",
    )
    .bind(&pubkey)
    .bind(&encrypted_secret)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    let secret_hash = bcrypt::hash(format!("secret_{}", Uuid::new_v4()), 4).expect("hash");
    let oauth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays, policy_id, tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Unconfirmed Gate Test App', $3, $4, $5, NULL, 1, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(&pubkey)
    .bind(format!("https://unconfirmed-daemon-{}.example.com", Uuid::new_v4()))
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
        true,
        pool.clone(),
    );
    (handler, user_keys)
}

fn event(kind: u16, author: &Keys, recipient: &PublicKey) -> UnsignedEvent {
    EventBuilder::new(Kind::from(kind), "daemon unconfirmed gate test")
        .tags([Tag::public_key(*recipient)])
        .build(author.public_key())
}

#[tokio::test]
async fn daemon_unconfirmed_dm_to_a_stranger_is_refused_with_its_code() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = handler_with_email(&pool, &key_manager, false).await;
    let stranger = Keys::generate().public_key();

    let err = handler
        .sign_event_direct(event(4, &user_keys, &stranger))
        .await
        .expect_err("an unconfirmed account must not DM a stranger");
    assert!(err.to_string().contains("EMAIL_NOT_CONFIRMED"), "{err}");

    let err = handler
        .validate_permissions_for_encrypt("hello", &stranger)
        .await
        .expect_err("encrypting to a stranger must be refused");
    assert!(err.to_string().contains("EMAIL_NOT_CONFIRMED"), "{err}");
}

#[tokio::test]
async fn daemon_unconfirmed_public_note_still_signs() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = handler_with_email(&pool, &key_manager, false).await;
    let stranger = Keys::generate().public_key();

    handler
        .sign_event_direct(event(1, &user_keys, &stranger))
        .await
        .expect("a public note signs");
}

#[tokio::test]
async fn daemon_confirmed_account_dms_as_before() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("key manager");
    let (handler, user_keys) = handler_with_email(&pool, &key_manager, true).await;
    let stranger = Keys::generate().public_key();

    handler
        .sign_event_direct(event(4, &user_keys, &stranger))
        .await
        .expect("a confirmed account DMs normally");
}
