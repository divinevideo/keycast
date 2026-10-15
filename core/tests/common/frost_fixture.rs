use keycast_core::groups::frost::{
    client::{DkgRound1, Participant},
    DkgState, FrostCoordinator,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    groups::{
        backup::{BackupBinding, BackupMaterial, BackupService, UploadBackup},
        frost::group_pubkey,
    },
};
use nostr::Keys;
use sqlx::PgPool;

struct FixtureKms;
#[async_trait::async_trait]
impl KeyManager for FixtureKms {
    async fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(bytes.iter().map(|b| b ^ 0xa5).collect())
    }
    async fn decrypt(&self, bytes: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(zeroize::Zeroizing::new(
            bytes.iter().map(|b| b ^ 0xa5).collect(),
        ))
    }
}

#[allow(dead_code)]
pub async fn backup_all(pool: &PgPool, f: &FrostFixture) {
    let service = BackupService::new(pool.clone(), &FixtureKms);
    let public = f.dkg.public_package.as_ref().unwrap();
    for (keys, participant) in f.keys.iter().zip(&f.participants) {
        let admin = keys.public_key().to_hex();
        let member = f
            .dkg
            .roster
            .iter()
            .find(|m| m.admin_pubkey == admin)
            .unwrap();
        service
            .upload(
                1,
                f.group,
                &admin,
                UploadBackup {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    binding: BackupBinding {
                        format_version: 1,
                        tenant_id: 1,
                        group_id: f.group,
                        group_pubkey: group_pubkey(public).unwrap().to_hex(),
                        admin_pubkey: admin.clone(),
                        participant_id: Some(i32::from(member.participant_id)),
                        membership_version: member.version,
                        key_version: f.dkg.binding.key_version,
                        roster_version: f.dkg.binding.roster_version,
                        ciphersuite: "FROST-secp256k1-SHA256-TR-v1".into(),
                        tweak_version: "untweaked-v1".into(),
                    },
                    material: BackupMaterial::FrostShare {
                        key_package: hex::encode(
                            participant.export_for_encrypted_backup().unwrap(),
                        ),
                        public_key_package: hex::encode(public.serialize().unwrap()),
                    },
                },
            )
            .await
            .unwrap();
    }
}

pub struct FrostFixture {
    pub group: i32,
    pub keys: Vec<Keys>,
    pub participants: Vec<Participant>,
    pub dkg: DkgState,
}

/// A real dealerless 2-of-3 ceremony through the persisted coordinator and the
/// native secret boundary. Every key and identity is synthetic and freshly random.
pub async fn completed_dkg(pool: &PgPool) -> FrostFixture {
    completed_dkg_with_invitee(pool, None).await
}

pub async fn completed_dkg_with_invitee(pool: &PgPool, invitee: Option<&str>) -> FrostFixture {
    let keys = (0..3).map(|_| Keys::generate()).collect::<Vec<_>>();
    let group: i32 = sqlx::query_scalar(
        "INSERT INTO teams (tenant_id,name) VALUES (1,'Synthetic threshold group') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let policy: i32 = sqlx::query_scalar(
        "INSERT INTO policies (team_id,name) VALUES ($1,'Synthetic threshold policy') RETURNING id",
    )
    .bind(group)
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO identity_groups (id,tenant_id,name,policy_id,mode,creator_pubkey,request_id) VALUES ($1,1,'Synthetic threshold group',$2,'frost',$3,$4)")
        .bind(group).bind(policy).bind(keys[0].public_key().to_hex()).bind(uuid::Uuid::new_v4().to_string()).execute(pool).await.unwrap();
    for key in &keys {
        let admin = key.public_key().to_hex();
        sqlx::query("INSERT INTO users (tenant_id,pubkey) VALUES (1,$1)")
            .bind(&admin)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO group_memberships (tenant_id,group_id,admin_pubkey,status) VALUES (1,$1,$2,'active')").bind(group).bind(admin).execute(pool).await.unwrap();
    }
    if let Some(invitee) = invitee {
        sqlx::query("INSERT INTO users (tenant_id,pubkey) VALUES (1,$1)")
            .bind(invitee)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO group_memberships (tenant_id,group_id,admin_pubkey,status) VALUES (1,$1,$2,'invited')").bind(group).bind(invitee).execute(pool).await.unwrap();
    }
    let coordinator = FrostCoordinator::new(pool.clone());
    let session = uuid::Uuid::new_v4().to_string();
    let mut state = coordinator
        .create_dkg(1, group, &keys[0].public_key().to_hex(), &session, 2)
        .await
        .unwrap();
    let mut first = Vec::new();
    for key in &keys {
        let (handle, event) = DkgRound1::start(key.clone(), &state).unwrap();
        state = coordinator
            .dkg_message(1, group, &key.public_key().to_hex(), &session, event)
            .await
            .unwrap();
        first.push(handle);
    }
    for (key, handle) in keys.iter().zip(&first) {
        let event = handle.agreement(&state).unwrap();
        state = coordinator
            .dkg_message(1, group, &key.public_key().to_hex(), &session, event)
            .await
            .unwrap();
    }
    let mut second = Vec::new();
    for (key, handle) in keys.iter().zip(first) {
        let (handle, events) = handle.round2(&state).unwrap();
        for event in events {
            state = coordinator
                .dkg_message(1, group, &key.public_key().to_hex(), &session, event)
                .await
                .unwrap();
        }
        second.push(handle);
    }
    let mut participants = Vec::new();
    for (key, handle) in keys.iter().zip(second) {
        let (participant, event) = handle.finish(&state).unwrap();
        state = coordinator
            .dkg_message(1, group, &key.public_key().to_hex(), &session, event)
            .await
            .unwrap();
        participants.push(participant);
    }
    state.confirmed_public_package().unwrap();
    FrostFixture {
        group,
        keys,
        participants,
        dkg: state,
    }
}
