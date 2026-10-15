#![cfg(feature = "integration-tests")]
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::groups::{CreateGroup, GroupMode, GroupService};
use nostr_sdk::Keys;
use sqlx::{postgres::PgPoolOptions, PgPool};

async fn user(pool: &PgPool) -> String {
    let key = Keys::generate().public_key().to_hex();
    sqlx::query("INSERT INTO users (tenant_id,pubkey) VALUES (1,$1)")
        .bind(&key)
        .execute(pool)
        .await
        .unwrap();
    key
}
#[tokio::test]
async fn hosted_creation_membership_retries_and_removal_with_one_connection() {
    let url = std::env::var("DATABASE_URL").unwrap();
    assert!(url.contains("127.0.0.1") || url.contains("localhost"));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let kms = FileKeyManager::new().unwrap();
    let service = GroupService::new(pool.clone(), &kms);
    let admin = user(&pool).await;
    let second = user(&pool).await;
    let outsider = user(&pool).await;
    let request = CreateGroup {
        request_id: uuid::Uuid::new_v4().to_string(),
        name: "Synthetic group".into(),
        mode: GroupMode::Hosted,
        pubkey: None,
    };
    let first = service.create(1, &admin, &request).await.unwrap();
    let retry = service.create(1, &admin, &request).await.unwrap();
    assert_eq!(first.id, retry.id);
    assert_eq!(first.pubkey, retry.pubkey);
    assert_eq!(first.mode, GroupMode::Hosted);
    assert!(first.signing_key_id.is_some());
    assert!(service.get(1, first.id, &outsider).await.is_err());
    assert!(service.get(2, first.id, &admin).await.is_err());
    assert!(service.remove(1, first.id, &admin, &admin).await.is_err());
    service.invite(1, first.id, &admin, &second).await.unwrap();
    assert!(service.get(1, first.id, &second).await.is_err());
    service.accept(1, first.id, &second).await.unwrap();
    assert_eq!(service.list(1, &second).await.unwrap().len(), 1);
    service.remove(1, first.id, &admin, &second).await.unwrap();
    assert!(service.get(1, first.id, &second).await.is_err());
    assert_eq!(
        service.get(1, first.id, &admin).await.unwrap().pubkey,
        first.pubkey
    );
    let mut conflict = request.clone();
    conflict.name = "Changed".into();
    assert!(service.create(1, &admin, &conflict).await.is_err());
}

#[tokio::test]
async fn concurrent_creation_and_reinvitation_preserve_identity_and_invalidate_old_grants() {
    let url = std::env::var("DATABASE_URL").unwrap();
    assert!(url.contains("127.0.0.1") || url.contains("localhost"));
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let kms = FileKeyManager::new().unwrap();
    let service = GroupService::new(pool.clone(), &kms);
    let admin = user(&pool).await;
    let second = user(&pool).await;
    let request = CreateGroup {
        request_id: uuid::Uuid::new_v4().to_string(),
        name: "Concurrent synthetic group".into(),
        mode: GroupMode::Hosted,
        pubkey: None,
    };
    let (left, right) = tokio::join!(
        service.create(1, &admin, &request),
        service.create(1, &admin, &request)
    );
    let group = left.unwrap();
    let retry = right.unwrap();
    assert_eq!(group.pubkey, retry.pubkey);
    assert_eq!(group.id, retry.id);
    service.invite(1, group.id, &admin, &second).await.unwrap();
    service.accept(1, group.id, &second).await.unwrap();
    let version = keycast_core::groups::require_admin(&pool, 1, group.id, &second)
        .await
        .unwrap()
        .version;
    service.remove(1, group.id, &admin, &second).await.unwrap();
    service.invite(1, group.id, &admin, &second).await.unwrap();
    service.accept(1, group.id, &second).await.unwrap();
    assert!(
        keycast_core::groups::require_admin(&pool, 1, group.id, &second)
            .await
            .unwrap()
            .version
            > version
    );
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_groups WHERE tenant_id=1 AND creator_pubkey=$1 AND request_id=$2").bind(&admin).bind(&request.request_id).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}

struct BrokenKeyManager;
#[async_trait::async_trait]
impl keycast_core::encryption::KeyManager for BrokenKeyManager {
    async fn encrypt(
        &self,
        _: &[u8],
    ) -> Result<Vec<u8>, keycast_core::encryption::KeyManagerError> {
        Err(keycast_core::encryption::KeyManagerError::Encrypt(
            "synthetic failure".into(),
        ))
    }
    async fn decrypt(
        &self,
        _: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, keycast_core::encryption::KeyManagerError> {
        Err(keycast_core::encryption::KeyManagerError::Decrypt(
            "synthetic failure".into(),
        ))
    }
}
#[tokio::test]
async fn encryption_failure_never_creates_a_partial_identity_and_retry_is_safe() {
    let url = std::env::var("DATABASE_URL").unwrap();
    assert!(url.contains("127.0.0.1") || url.contains("localhost"));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let admin = user(&pool).await;
    let request = CreateGroup {
        request_id: uuid::Uuid::new_v4().to_string(),
        name: "Encryption retry".into(),
        mode: GroupMode::Hosted,
        pubkey: None,
    };
    let broken = GroupService::new(pool.clone(), &BrokenKeyManager);
    assert!(broken.create(1, &admin, &request).await.is_err());
    assert!(broken.list(1, &admin).await.unwrap().is_empty());
    let kms = FileKeyManager::new().unwrap();
    let service = GroupService::new(pool.clone(), &kms);
    let first = service.create(1, &admin, &request).await.unwrap();
    assert_eq!(
        first.id,
        service.create(1, &admin, &request).await.unwrap().id
    );
}

#[tokio::test]
async fn deleted_accounts_do_not_rejoin_groups_and_ineligible_admins_do_not_count() {
    let url = std::env::var("DATABASE_URL").unwrap();
    assert!(url.contains("127.0.0.1") || url.contains("localhost"));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let kms = FileKeyManager::new().unwrap();
    let service = GroupService::new(pool.clone(), &kms);
    let admin = user(&pool).await;
    let second = user(&pool).await;
    let group = service
        .create(
            1,
            &admin,
            &CreateGroup {
                request_id: uuid::Uuid::new_v4().to_string(),
                name: "Account lifecycle".into(),
                mode: GroupMode::Hosted,
                pubkey: None,
            },
        )
        .await
        .unwrap();
    service.invite(1, group.id, &admin, &second).await.unwrap();
    service.accept(1, group.id, &second).await.unwrap();
    sqlx::query("UPDATE users SET status='suspended' WHERE tenant_id=1 AND pubkey=$1")
        .bind(&second)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        service.remove(1, group.id, &admin, &admin).await.is_err(),
        "an ineligible admin cannot protect the last active administrator"
    );
    sqlx::query("UPDATE users SET status='active' WHERE tenant_id=1 AND pubkey=$1")
        .bind(&second)
        .execute(&pool)
        .await
        .unwrap();
    std::env::set_var("BUNKER_RELAYS", "ws://127.0.0.1:8080");
    let grant = service
        .enroll(
            1,
            group.id,
            &second,
            &Keys::generate().public_key().to_hex(),
            keycast_core::secret_pool::SecretPair {
                secret: secrecy::SecretString::from("synthetic-connection-secret"),
                hash: bcrypt::hash("synthetic-connection-secret", 4).unwrap(),
            },
            false,
        )
        .await
        .unwrap();
    keycast_core::repositories::UserRepository::new(pool.clone())
        .delete_account(&second, 1)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (tenant_id,pubkey) VALUES (1,$1)")
        .bind(&second)
        .execute(&pool)
        .await
        .unwrap();
    let retired: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM group_grants WHERE authorization_id=$1",
    )
    .bind(grant.authorization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        retired,
        "account deletion retires an issued device grant permanently"
    );
    assert!(
        service.get(1, group.id, &second).await.is_err(),
        "recreating an account must not restore old group membership"
    );
    assert!(service.remove(1, group.id, &admin, &admin).await.is_err());
}
