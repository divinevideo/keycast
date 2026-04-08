mod common;

use keycast_core::repositories::UserRepository;
use nostr_sdk::Keys;

#[tokio::test]
async fn update_profile_claims_name_without_enabling_atproto() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let tenant_id = 1_i64;
    let username = format!("alice-update-profile-{}", &pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    repo.update_username(&pubkey, &username, tenant_id)
        .await
        .unwrap();

    let state = repo
        .get_atproto_state(&pubkey, tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!state.enabled);
    assert_eq!(state.state, None);
}

#[tokio::test]
async fn username_conflict_is_detected_in_local_repository_check() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let first_user = Keys::generate().public_key().to_hex();
    let second_user = Keys::generate().public_key().to_hex();
    let tenant_id = 1_i64;
    let username = format!("nip05-conflict-{}", &first_user[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&first_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert first user");

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&second_user)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert second user");

    repo.update_username(&first_user, &username, tenant_id)
        .await
        .expect("failed to set first username");

    let available_for_second = repo
        .check_username_available(&username, &second_user, tenant_id)
        .await
        .expect("failed to check username availability");
    assert!(!available_for_second, "username should be marked unavailable");
}
