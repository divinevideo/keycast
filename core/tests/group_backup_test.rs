#![cfg(feature = "integration-tests")]

use async_trait::async_trait;
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::groups::backup::{
    BackupBinding, BackupError, BackupMaterial, BackupService, RestoreBackup, UploadBackup,
};
use nostr::Keys;
use sqlx::{postgres::PgPoolOptions, PgPool};
use zeroize::Zeroizing;

struct TestKeyManager;
#[async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(bytes.iter().map(|b| b ^ 0xa5).collect())
    }
    async fn decrypt(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(bytes.iter().map(|b| b ^ 0xa5).collect()))
    }
}

async fn fixture(pool: &PgPool) -> (i32, String, Keys) {
    let admin = Keys::generate().public_key().to_hex();
    let keys = Keys::generate();
    sqlx::query("INSERT INTO users (pubkey,tenant_id) VALUES ($1,1)")
        .bind(&admin)
        .execute(pool)
        .await
        .unwrap();
    let team: i32 = sqlx::query_scalar(
        "INSERT INTO teams (name, tenant_id) VALUES ('Synthetic backup group',1) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let policy: i32 = sqlx::query_scalar(
        "INSERT INTO policies (name) VALUES ('Synthetic backup policy') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO identity_groups (id,tenant_id,name,pubkey,policy_id,mode,key_version,roster_version,creator_pubkey,request_id) VALUES ($1,1,'Synthetic backup group',$2,$3,'device',1,1,$4,$4)").bind(team).bind(keys.public_key().to_hex()).bind(policy).bind(&admin).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO group_memberships (tenant_id,group_id,admin_pubkey,status,version,installation_epoch) VALUES (1,$1,$2,'active',1,1)").bind(team).bind(&admin).execute(pool).await.unwrap();
    (team, admin, keys)
}
fn upload(group: i32, admin: &str, keys: &Keys, request: &str) -> UploadBackup {
    UploadBackup {
        request_id: request.into(),
        binding: BackupBinding {
            format_version: 1,
            tenant_id: 1,
            group_id: group,
            group_pubkey: keys.public_key().to_hex(),
            admin_pubkey: admin.into(),
            participant_id: None,
            membership_version: 1,
            key_version: 1,
            roster_version: 1,
            ciphersuite: "BIP-340".into(),
            tweak_version: "none".into(),
        },
        material: BackupMaterial::FullKey {
            secret_key: keys.secret_key().to_secret_hex(),
        },
    }
}

#[sqlx::test(migrations = "../database/migrations")]
async fn account_deletion_erases_only_its_recovery_ciphertext_and_receipts(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let (other_group, other_admin, other_keys) = fixture(&pool).await;
    sqlx::query("INSERT INTO group_memberships (tenant_id,group_id,admin_pubkey,status) VALUES (1,$1,$2,'active')")
        .bind(group).bind(&other_admin).execute(&pool).await.unwrap();
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let svc = BackupService::new(single.clone(), &TestKeyManager);
    for (id, principal, key) in [
        (group, &admin, &keys),
        (other_group, &other_admin, &other_keys),
    ] {
        svc.upload(1, id, principal, upload(id, principal, key, "backup"))
            .await
            .unwrap();
        svc.restore(
            1,
            id,
            principal,
            RestoreBackup {
                request_id: "restore".into(),
                backup_request_id: "backup".into(),
            },
        )
        .await
        .unwrap();
    }
    let repo = keycast_core::repositories::UserRepository::new(single.clone());
    assert!(repo.delete_account(&admin, 2).await.is_err());
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_backups WHERE tenant_id=1 AND admin_pubkey=$1",
    )
    .bind(&admin)
    .fetch_one(&single)
    .await
    .unwrap();
    assert_eq!(count, 1, "another tenant cannot erase recovery material");
    repo.delete_account(&admin, 1).await.unwrap();
    for table in ["group_backups", "group_backup_restores"] {
        let query = format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=1 AND admin_pubkey=$1");
        let deleted: i64 = sqlx::query_scalar(&query)
            .bind(&admin)
            .fetch_one(&single)
            .await
            .unwrap();
        let retained: i64 = sqlx::query_scalar(&query)
            .bind(&other_admin)
            .fetch_one(&single)
            .await
            .unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(retained, 1);
    }
}

#[sqlx::test(migrations = "../database/migrations")]
async fn durable_idempotent_recovery_and_current_membership(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let svc = BackupService::new(single.clone(), &TestKeyManager);
    assert!(
        matches!(svc.status(1,group,&admin).await, Ok(s) if !s.recoverable && s.backup_request_id.is_none())
    );
    svc.upload(1, group, &admin, upload(group, &admin, &keys, "first"))
        .await
        .unwrap();
    svc.upload(1, group, &admin, upload(group, &admin, &keys, "first"))
        .await
        .unwrap();
    drop(svc);
    let svc = BackupService::new(single, &TestKeyManager);
    let discovered = svc.status(1, group, &admin).await.unwrap();
    assert!(discovered.recoverable);
    let backup_request_id = discovered.backup_request_id.unwrap();
    let request = || RestoreBackup {
        request_id: "new-device".into(),
        backup_request_id: backup_request_id.clone(),
    };
    let restored = svc.restore(1, group, &admin, request()).await.unwrap();
    assert_eq!(restored.installation_epoch, 2);
    assert_eq!(
        svc.restore(1, group, &admin, request())
            .await
            .unwrap()
            .installation_epoch,
        2
    );
    if let BackupMaterial::FullKey { secret_key } = &restored.material {
        assert_eq!(secret_key, &keys.secret_key().to_secret_hex());
    } else {
        panic!("expected full key");
    }
    assert!(matches!(
        svc.restore(2, group, &admin, request()).await,
        Err(BackupError::Denied)
    ));
    assert!(matches!(
        svc.restore(1, group, &Keys::generate().public_key().to_hex(), request())
            .await,
        Err(BackupError::Denied)
    ));
    sqlx::query(
        "UPDATE group_memberships SET status='removed',version=version+1 WHERE group_id=$1",
    )
    .bind(group)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        svc.restore(1, group, &admin, request()).await,
        Err(BackupError::Denied)
    ));
}

#[sqlx::test(migrations = "../database/migrations")]
async fn failed_persistence_is_not_recoverable_and_retry_succeeds(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let svc = BackupService::new(pool.clone(), &TestKeyManager);
    sqlx::query("ALTER TABLE group_backups ADD CONSTRAINT synthetic_storage_failure CHECK (request_id <> 'fail')").execute(&pool).await.unwrap();
    assert!(matches!(
        svc.upload(1, group, &admin, upload(group, &admin, &keys, "fail"))
            .await,
        Err(BackupError::Unavailable)
    ));
    assert!(!svc.status(1, group, &admin).await.unwrap().recoverable);
    sqlx::query("ALTER TABLE group_backups DROP CONSTRAINT synthetic_storage_failure")
        .execute(&pool)
        .await
        .unwrap();
    svc.upload(1, group, &admin, upload(group, &admin, &keys, "fail"))
        .await
        .unwrap();
    assert!(svc.status(1, group, &admin).await.unwrap().recoverable);
    let mut conflicting = upload(group, &admin, &keys, "fail");
    if let BackupMaterial::FullKey { secret_key } = &mut conflicting.material {
        *secret_key = secret_key.to_uppercase();
    }
    assert!(matches!(
        svc.upload(1, group, &admin, conflicting).await,
        Err(BackupError::Conflict)
    ));
    sqlx::query("UPDATE identity_groups SET roster_version=2 WHERE id=$1")
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!svc.status(1, group, &admin).await.unwrap().recoverable);
    assert!(matches!(
        svc.restore(
            1,
            group,
            &admin,
            RestoreBackup {
                request_id: "restore".into(),
                backup_request_id: "fail".into()
            }
        )
        .await,
        Err(BackupError::Obsolete)
    ));
}

#[test]
fn packages_reject_nonce_seed_and_session_fields() {
    for field in ["nonces", "nonce_seed", "pending_session", "session_token"] {
        let payload = format!(
            "{{\"kind\":\"full_key\",\"secret_key\":\"{}\",\"{}\":\"forbidden\"}}",
            "01".repeat(32),
            field
        );
        assert!(serde_json::from_str::<BackupMaterial>(&payload).is_err());
    }
}

#[sqlx::test(migrations = "../database/migrations")]
async fn encrypted_binding_cannot_be_transplanted_to_another_group(pool: PgPool) {
    let (first, admin, keys) = fixture(&pool).await;
    let (second, other_admin, other_keys) = fixture(&pool).await;
    let svc = BackupService::new(pool.clone(), &TestKeyManager);
    svc.upload(1, first, &admin, upload(first, &admin, &keys, "first"))
        .await
        .unwrap();
    svc.upload(
        1,
        second,
        &other_admin,
        upload(second, &other_admin, &other_keys, "second"),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE group_backups b SET ciphertext=source.ciphertext,content_hash=source.content_hash FROM group_backups source WHERE b.group_id=$1 AND source.group_id=$2").bind(second).bind(first).execute(&pool).await.unwrap();
    assert!(matches!(
        svc.restore(
            1,
            second,
            &other_admin,
            RestoreBackup {
                request_id: "replacement".into(),
                backup_request_id: "second".into()
            }
        )
        .await,
        Err(BackupError::Invalid)
    ));
    let epoch: i64 =
        sqlx::query_scalar("SELECT installation_epoch FROM group_memberships WHERE group_id=$1")
            .bind(second)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(epoch, 1);
}

#[sqlx::test(migrations = "../database/migrations")]
async fn restore_persistence_failure_rolls_back_epoch(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let svc = BackupService::new(pool.clone(), &TestKeyManager);
    svc.upload(1, group, &admin, upload(group, &admin, &keys, "backup"))
        .await
        .unwrap();
    sqlx::query("ALTER TABLE group_backup_restores ADD CONSTRAINT synthetic_restore_failure CHECK (request_id <> 'fail')").execute(&pool).await.unwrap();
    let request = || RestoreBackup {
        request_id: "fail".into(),
        backup_request_id: "backup".into(),
    };
    assert!(matches!(
        svc.restore(1, group, &admin, request()).await,
        Err(BackupError::Unavailable)
    ));
    let epoch: i64 =
        sqlx::query_scalar("SELECT installation_epoch FROM group_memberships WHERE group_id=$1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(epoch, 1);
    sqlx::query("ALTER TABLE group_backup_restores DROP CONSTRAINT synthetic_restore_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        svc.restore(1, group, &admin, request())
            .await
            .unwrap()
            .installation_epoch,
        2
    );
}

#[path = "common/frost_fixture.rs"]
mod frost_fixture;

#[sqlx::test(migrations = "../database/migrations")]
async fn actual_frost_share_recovers_without_reviving_pending_sessions(pool: PgPool) {
    use keycast_core::groups::frost::{client::Participant, group_pubkey, FrostCoordinator};
    let f = frost_fixture::completed_dkg(&pool).await;
    frost_fixture::backup_all(&pool, &f).await;
    let admin = f.keys[0].public_key().to_hex();
    let member = f
        .dkg
        .roster
        .iter()
        .find(|m| m.admin_pubkey == admin)
        .unwrap();
    let key_bytes = f.participants[0].export_for_encrypted_backup().unwrap();
    let public = f.dkg.confirmed_public_package().unwrap();
    let make = || UploadBackup {
        request_id: "actual-frost".into(),
        binding: BackupBinding {
            format_version: 1,
            tenant_id: 1,
            group_id: f.group,
            group_pubkey: group_pubkey(public).unwrap().to_hex(),
            admin_pubkey: admin.clone(),
            participant_id: Some(i32::from(member.participant_id)),
            membership_version: 1,
            key_version: 1,
            roster_version: 1,
            ciphersuite: "FROST-secp256k1-SHA256-TR-v1".into(),
            tweak_version: "untweaked-v1".into(),
        },
        material: BackupMaterial::FrostShare {
            key_package: hex::encode(&*key_bytes),
            public_key_package: hex::encode(public.serialize().unwrap()),
        },
    };
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let svc = BackupService::new(single, &TestKeyManager);
    svc.upload(1, f.group, &admin, make()).await.unwrap();
    assert!(svc.status(1, f.group, &admin).await.unwrap().recoverable);
    // Pending operations are canceled, while the completed identity ceremony survives.
    let coordinator = FrostCoordinator::new(pool.clone());
    let pending = uuid::Uuid::new_v4().to_string();
    let proposal = || {
        nostr::UnsignedEvent::new(
            group_pubkey(public).unwrap(),
            nostr::Timestamp::from(1_800_000_000),
            nostr::Kind::TextNote,
            [],
            "Synthetic recovered group",
        )
    };
    let signer_ids = || {
        f.dkg
            .roster
            .iter()
            .take(2)
            .map(|m| m.participant_id)
            .collect::<Vec<_>>()
    };
    coordinator
        .create_signing(
            1,
            f.group,
            &admin,
            &pending,
            &f.dkg.binding.session_id,
            proposal(),
            signer_ids(),
        )
        .await
        .unwrap();
    let replacement = BackupService::new(pool.clone(), &TestKeyManager);
    let discovered = replacement.status(1, f.group, &admin).await.unwrap();
    let result = replacement
        .restore(
            1,
            f.group,
            &admin,
            RestoreBackup {
                request_id: "fresh-installation".into(),
                backup_request_id: discovered.backup_request_id.unwrap(),
            },
        )
        .await
        .unwrap();
    assert_eq!(result.installation_epoch, 2);
    let aborted: bool =
        sqlx::query_scalar("SELECT aborted FROM group_frost_sessions WHERE group_id=$1 AND id=$2")
            .bind(f.group)
            .bind(&pending)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(aborted);
    let dkg_aborted: bool =
        sqlx::query_scalar("SELECT aborted FROM group_frost_sessions WHERE group_id=$1 AND id=$2")
            .bind(f.group)
            .bind(&f.dkg.binding.session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!dkg_aborted);
    if let BackupMaterial::FrostShare { key_package, .. } = &result.material {
        let recovered = Zeroizing::new(hex::decode(key_package).unwrap());
        assert_eq!(&*recovered, &*key_bytes);
        Participant::restore(&recovered, &admin, &f.dkg).unwrap();
    } else {
        panic!("expected share")
    };
    // Restoring did not obsolete the immutable DKG package, so a replacement upload works.
    let mut fresh = make();
    fresh.request_id = "fresh-backup".into();
    svc.upload(1, f.group, &admin, fresh).await.unwrap();
    coordinator
        .get(1, f.group, &admin, &f.dkg.binding.session_id)
        .await
        .unwrap();
    coordinator
        .create_signing(
            1,
            f.group,
            &admin,
            &uuid::Uuid::new_v4().to_string(),
            &f.dkg.binding.session_id,
            proposal(),
            signer_ids(),
        )
        .await
        .unwrap();
    let mut invalid = make();
    invalid.request_id = "bad-participant".into();
    invalid.binding.participant_id = Some(65535);
    assert!(matches!(
        svc.upload(1, f.group, &admin, invalid).await,
        Err(BackupError::Invalid)
    ));
}

#[sqlx::test(migrations = "../database/migrations")]
async fn hosted_recovery_status_checks_real_custody_without_export(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let encrypted = TestKeyManager
        .encrypt(&keys.secret_key().secret_bytes())
        .await
        .unwrap();
    let stored:i32=sqlx::query_scalar("INSERT INTO stored_keys (name,team_id,pubkey,secret_key,tenant_id) VALUES ('Synthetic hosted group',$1,$2,$3,1) RETURNING id").bind(group).bind(keys.public_key().to_hex()).bind(encrypted).fetch_one(&pool).await.unwrap();
    sqlx::query("UPDATE identity_groups SET mode='hosted',signing_key_id=$2 WHERE id=$1")
        .bind(group)
        .bind(stored)
        .execute(&pool)
        .await
        .unwrap();
    let svc = BackupService::new(pool.clone(), &TestKeyManager);
    let hosted = svc.status(1, group, &admin).await.unwrap();
    assert!(hosted.recoverable);
    assert!(hosted.backup_request_id.is_none());
    assert!(matches!(
        svc.upload(
            1,
            group,
            &admin,
            upload(group, &admin, &keys, "no-hosted-export")
        )
        .await,
        Err(BackupError::Invalid)
    ));
    assert!(matches!(
        svc.restore(
            1,
            group,
            &admin,
            RestoreBackup {
                request_id: "no-hosted-export".into(),
                backup_request_id: "none".into()
            }
        )
        .await,
        Err(BackupError::Missing)
    ));
    sqlx::query("UPDATE stored_keys SET pubkey=$2 WHERE id=$1")
        .bind(stored)
        .bind(Keys::generate().public_key().to_hex())
        .execute(&pool)
        .await
        .unwrap();
    assert!(!svc.status(1, group, &admin).await.unwrap().recoverable);
    sqlx::query("UPDATE users SET status='suspended' WHERE tenant_id=1 AND pubkey=$1")
        .bind(&admin)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        svc.status(1, group, &admin).await,
        Err(BackupError::Denied)
    ));
}

#[sqlx::test(migrations = "../database/migrations")]
async fn audit_failure_prevents_upload_and_restore_acknowledgment(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let svc = BackupService::new(pool.clone(), &TestKeyManager);
    sqlx::query("ALTER TABLE group_audit ADD CONSTRAINT synthetic_audit_failure CHECK (action <> 'backup_uploaded')").execute(&pool).await.unwrap();
    assert!(matches!(
        svc.upload(1, group, &admin, upload(group, &admin, &keys, "audit"))
            .await,
        Err(BackupError::Unavailable)
    ));
    assert!(!svc.status(1, group, &admin).await.unwrap().recoverable);
    sqlx::query("ALTER TABLE group_audit DROP CONSTRAINT synthetic_audit_failure")
        .execute(&pool)
        .await
        .unwrap();
    svc.upload(1, group, &admin, upload(group, &admin, &keys, "audit"))
        .await
        .unwrap();
    svc.upload(1, group, &admin, upload(group, &admin, &keys, "audit"))
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_audit WHERE group_id=$1 AND action='backup_uploaded'",
    )
    .bind(group)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    sqlx::query("ALTER TABLE group_audit ADD CONSTRAINT synthetic_audit_failure CHECK (action <> 'backup_restored')").execute(&pool).await.unwrap();
    let request = || RestoreBackup {
        request_id: "audit-restore".into(),
        backup_request_id: "audit".into(),
    };
    assert!(matches!(
        svc.restore(1, group, &admin, request()).await,
        Err(BackupError::Unavailable)
    ));
    let epoch: i64 =
        sqlx::query_scalar("SELECT installation_epoch FROM group_memberships WHERE group_id=$1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(epoch, 1);
    sqlx::query("ALTER TABLE group_audit DROP CONSTRAINT synthetic_audit_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        svc.restore(1, group, &admin, request())
            .await
            .unwrap()
            .installation_epoch,
        2
    );
}

#[sqlx::test(migrations = "../database/migrations")]
async fn status_discovers_latest_current_id_and_rejects_substituted_ciphertext(pool: PgPool) {
    let (group, admin, keys) = fixture(&pool).await;
    let svc = BackupService::new(pool.clone(), &TestKeyManager);
    let first = svc
        .upload(1, group, &admin, upload(group, &admin, &keys, "first"))
        .await
        .unwrap();
    assert_eq!(first.backup_request_id.as_deref(), Some("first"));
    let latest = svc
        .upload(1, group, &admin, upload(group, &admin, &keys, "latest"))
        .await
        .unwrap();
    assert_eq!(latest.backup_request_id.as_deref(), Some("latest"));
    drop(svc);
    let replacement = BackupService::new(pool.clone(), &TestKeyManager);
    assert_eq!(
        replacement
            .status(1, group, &admin)
            .await
            .unwrap()
            .backup_request_id
            .as_deref(),
        Some("latest")
    );
    sqlx::query("UPDATE group_backups target SET ciphertext=source.ciphertext,content_hash=source.content_hash FROM group_backups source WHERE target.group_id=$1 AND target.request_id='latest' AND source.group_id=$1 AND source.request_id='first'").bind(group).execute(&pool).await.unwrap();
    assert!(matches!(
        replacement.status(1, group, &admin).await,
        Err(BackupError::Invalid)
    ));
    sqlx::query("UPDATE identity_groups SET key_version=key_version+1 WHERE id=$1")
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();
    let obsolete = replacement.status(1, group, &admin).await.unwrap();
    assert!(!obsolete.recoverable);
    assert!(obsolete.backup_request_id.is_none());
}
