//! Recoverable signing material. Secret-bearing types deliberately do not implement Debug.
use crate::encryption::KeyManager;
use nostr::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgConnection, PgPool};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("Current group administrator membership is required")]
    Denied,
    #[error("Invalid recovery package; check the format and group binding")]
    Invalid,
    #[error("This request ID already identifies different recovery material")]
    Conflict,
    #[error("Recovery package is obsolete; upload material for the current group versions")]
    Obsolete,
    #[error("No current recovery package; upload and confirm a backup first")]
    Missing,
    #[error("Recovery storage or encryption unavailable; retry with the same request ID")]
    Unavailable,
}
impl From<sqlx::Error> for BackupError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBinding {
    pub format_version: u16,
    pub tenant_id: i64,
    pub group_id: i32,
    pub group_pubkey: String,
    pub admin_pubkey: String,
    pub participant_id: Option<i32>,
    pub membership_version: i64,
    pub key_version: i32,
    pub roster_version: i32,
    pub ciphersuite: String,
    pub tweak_version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupMaterial {
    FullKey {
        secret_key: String,
    },
    FrostShare {
        key_package: String,
        public_key_package: String,
    },
}
impl Drop for BackupMaterial {
    fn drop(&mut self) {
        match self {
            Self::FullKey { secret_key } => secret_key.zeroize(),
            Self::FrostShare { key_package, .. } => key_package.zeroize(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadBackup {
    pub request_id: String,
    pub binding: BackupBinding,
    pub material: BackupMaterial,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBackup {
    pub request_id: String,
    pub backup_request_id: String,
}
#[derive(Serialize)]
pub struct RestoredBackup {
    pub binding: BackupBinding,
    pub material: BackupMaterial,
    pub installation_epoch: i64,
}
#[derive(Debug, Serialize)]
pub struct BackupStatus {
    pub recoverable: bool,
    pub backup_request_id: Option<String>,
    pub custody: String,
    pub key_version: i32,
    pub roster_version: i32,
    pub membership_version: i64,
}
#[derive(Clone, FromRow)]
struct Context {
    mode: String,
    pubkey: Option<String>,
    signing_key_id: Option<i32>,
    key_version: i32,
    roster_version: i32,
    version: i64,
    participant_id: Option<i32>,
    installation_epoch: i64,
}
#[derive(FromRow)]
struct StoredBackup {
    request_id: String,
    ciphertext: Vec<u8>,
    content_hash: Vec<u8>,
}

pub struct BackupService<'a> {
    pool: PgPool,
    key_manager: &'a dyn KeyManager,
}
impl<'a> BackupService<'a> {
    pub fn new(pool: PgPool, key_manager: &'a dyn KeyManager) -> Self {
        Self { pool, key_manager }
    }

    pub async fn upload(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        request: UploadBackup,
    ) -> Result<BackupStatus, BackupError> {
        valid_request_id(&request.request_id)?;
        let ctx = self.context(tenant, group, admin).await?;
        check_binding(&ctx, tenant, group, admin, &request.binding)?;
        validate_package(&ctx, &request).await?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&request).map_err(|_| BackupError::Invalid)?);
        let digest = Sha256::digest(&*plaintext).to_vec();
        // Encryption and all KMS work happen before taking any database locks.
        let ciphertext = self
            .key_manager
            .encrypt(&plaintext)
            .await
            .map_err(|_| BackupError::Unavailable)?;
        let mut tx = self.pool.begin().await?;
        let current = locked_context(&mut tx, tenant, group, admin).await?;
        check_binding(&current, tenant, group, admin, &request.binding)?;
        check_authoritative(&mut tx, tenant, group, &request.binding, &request.material).await?;
        let prior: Option<Vec<u8>> = sqlx::query_scalar("SELECT content_hash FROM group_backups WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND request_id=$4")
            .bind(tenant).bind(group).bind(admin).bind(&request.request_id).fetch_optional(&mut *tx).await?;
        if let Some(prior) = prior {
            if prior != digest {
                return Err(BackupError::Conflict);
            }
        } else {
            sqlx::query("INSERT INTO group_backups (tenant_id,group_id,admin_pubkey,request_id,membership_version,key_version,roster_version,content_hash,ciphertext) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(tenant).bind(group).bind(admin).bind(&request.request_id).bind(current.version).bind(current.key_version).bind(current.roster_version).bind(digest).bind(ciphertext).execute(&mut *tx).await?;
            audit(
                &mut tx,
                tenant,
                group,
                admin,
                "backup_uploaded",
                &request.request_id,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(status_for(&current, true, Some(request.request_id)))
    }

    pub async fn status(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
    ) -> Result<BackupStatus, BackupError> {
        let ctx = self.context(tenant, group, admin).await?;
        if ctx.mode == "hosted" {
            let encrypted: Option<Vec<u8>> = sqlx::query_scalar("SELECT secret_key FROM stored_keys WHERE tenant_id=$1 AND team_id=$2 AND id=$3 AND pubkey=$4")
                .bind(tenant).bind(group).bind(ctx.signing_key_id).bind(&ctx.pubkey).fetch_optional(&self.pool).await?;
            let recoverable = if let Some(encrypted) = encrypted {
                let bytes = self
                    .key_manager
                    .decrypt(&encrypted)
                    .await
                    .map_err(|_| BackupError::Unavailable)?;
                let secret = SecretKey::from_slice(&bytes).map_err(|_| BackupError::Invalid)?;
                Some(Keys::new(secret).public_key().to_hex()) == ctx.pubkey
            } else {
                false
            };
            // Recheck membership/version after asynchronous key-manager work.
            let current = self.context(tenant, group, admin).await?;
            return Ok(status_for(
                &current,
                recoverable
                    && ctx.version == current.version
                    && ctx.key_version == current.key_version
                    && ctx.roster_version == current.roster_version,
                None,
            ));
        }
        let row = sqlx::query_as::<_,StoredBackup>("SELECT request_id,ciphertext,content_hash FROM group_backups WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND membership_version=$4 AND key_version=$5 AND roster_version=$6 ORDER BY created_at DESC,request_id DESC LIMIT 1")
            .bind(tenant).bind(group).bind(admin).bind(ctx.version).bind(ctx.key_version).bind(ctx.roster_version).fetch_optional(&self.pool).await?;
        let backup_request_id = if let Some(row) = row {
            let package = self.decode(&row).await?;
            check_binding(&ctx, tenant, group, admin, &package.binding)?;
            validate_package(&ctx, &package).await?;
            let mut conn = self.pool.acquire().await?;
            check_authoritative(
                &mut conn,
                tenant,
                group,
                &package.binding,
                &package.material,
            )
            .await?;
            Some(package.request_id)
        } else {
            None
        };
        let current = self.context(tenant, group, admin).await?;
        Ok(status_for(
            &current,
            backup_request_id.is_some()
                && ctx.version == current.version
                && ctx.key_version == current.key_version
                && ctx.roster_version == current.roster_version,
            backup_request_id,
        ))
    }

    pub async fn restore(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        request: RestoreBackup,
    ) -> Result<RestoredBackup, BackupError> {
        valid_request_id(&request.request_id)?;
        valid_request_id(&request.backup_request_id)?;
        let ctx = self.context(tenant, group, admin).await?;
        let row = sqlx::query_as::<_,StoredBackup>("SELECT request_id,ciphertext,content_hash FROM group_backups WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND request_id=$4")
            .bind(tenant).bind(group).bind(admin).bind(&request.backup_request_id).fetch_optional(&self.pool).await?.ok_or(BackupError::Missing)?;
        let package = self.decode(&row).await?;
        if package.request_id != request.backup_request_id {
            return Err(BackupError::Invalid);
        }
        check_binding(&ctx, tenant, group, admin, &package.binding)?;
        validate_package(&ctx, &package).await?;
        let mut tx = self.pool.begin().await?;
        let current = locked_context(&mut tx, tenant, group, admin).await?;
        check_binding(&current, tenant, group, admin, &package.binding)?;
        check_authoritative(&mut tx, tenant, group, &package.binding, &package.material).await?;
        let prior: Option<(String,i64)> = sqlx::query_as("SELECT backup_request_id,installation_epoch FROM group_backup_restores WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND request_id=$4")
            .bind(tenant).bind(group).bind(admin).bind(&request.request_id).fetch_optional(&mut *tx).await?;
        let epoch = if let Some((backup, epoch)) = prior {
            if backup != request.backup_request_id {
                return Err(BackupError::Conflict);
            }
            if epoch != current.installation_epoch {
                return Err(BackupError::Obsolete);
            }
            epoch
        } else {
            let epoch:i64 = sqlx::query_scalar("UPDATE group_memberships SET installation_epoch=installation_epoch+1 WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 RETURNING installation_epoch")
                .bind(tenant).bind(group).bind(admin).fetch_one(&mut *tx).await?;
            sqlx::query("UPDATE group_grants SET revoked_at=NOW() WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND revoked_at IS NULL")
                .bind(tenant).bind(group).bind(admin).execute(&mut *tx).await?;
            sqlx::query("UPDATE group_frost_sessions SET aborted=TRUE WHERE tenant_id=$1 AND group_id=$2 AND aborted=FALSE AND ((session_kind='dkg' AND (state->'state'->'public_package' IS NULL OR state->'state'->'public_package' = 'null'::jsonb)) OR (session_kind='signing' AND (state->'state'->'result' IS NULL OR state->'state'->'result' = 'null'::jsonb)))")
                .bind(tenant).bind(group).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO group_backup_restores (tenant_id,group_id,admin_pubkey,request_id,backup_request_id,installation_epoch) VALUES ($1,$2,$3,$4,$5,$6)")
                .bind(tenant).bind(group).bind(admin).bind(&request.request_id).bind(&request.backup_request_id).bind(epoch).execute(&mut *tx).await?;
            audit(
                &mut tx,
                tenant,
                group,
                admin,
                "backup_restored",
                &request.request_id,
            )
            .await?;
            epoch
        };
        tx.commit().await?;
        Ok(RestoredBackup {
            binding: package.binding,
            material: package.material,
            installation_epoch: epoch,
        })
    }

    async fn context(&self, tenant: i64, group: i32, admin: &str) -> Result<Context, BackupError> {
        sqlx::query_as::<_, Context>(CONTEXT_QUERY)
            .bind(tenant)
            .bind(group)
            .bind(admin)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(BackupError::Denied)
    }
    async fn decode(&self, row: &StoredBackup) -> Result<UploadBackup, BackupError> {
        let plaintext = self
            .key_manager
            .decrypt(&row.ciphertext)
            .await
            .map_err(|_| BackupError::Unavailable)?;
        if Sha256::digest(&*plaintext).as_slice() != row.content_hash {
            return Err(BackupError::Invalid);
        }
        let package: UploadBackup =
            serde_json::from_slice(&plaintext).map_err(|_| BackupError::Invalid)?;
        if package.request_id != row.request_id {
            return Err(BackupError::Invalid);
        }
        Ok(package)
    }
}
const CONTEXT_QUERY:&str = "SELECT g.mode,g.pubkey,g.signing_key_id,g.key_version,g.roster_version,m.version,m.participant_id,m.installation_epoch FROM identity_groups g JOIN group_memberships m ON m.tenant_id=g.tenant_id AND m.group_id=g.id JOIN users u ON u.tenant_id=m.tenant_id AND u.pubkey=m.admin_pubkey WHERE g.tenant_id=$1 AND g.id=$2 AND m.admin_pubkey=$3 AND m.status='active' AND u.status='active'";
async fn locked_context(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    admin: &str,
) -> Result<Context, BackupError> {
    // Group lock order matches membership and signer mutations.
    sqlx::query_scalar::<_, i32>(
        "SELECT id FROM identity_groups WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(group)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(BackupError::Denied)?;
    sqlx::query_as::<_, Context>(&format!("{CONTEXT_QUERY} FOR UPDATE OF m,u"))
        .bind(tenant)
        .bind(group)
        .bind(admin)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(BackupError::Denied)
}
fn valid_request_id(value: &str) -> Result<(), BackupError> {
    if value.is_empty() || value.len() > 128 {
        Err(BackupError::Invalid)
    } else {
        Ok(())
    }
}
fn status_for(ctx: &Context, recoverable: bool, backup_request_id: Option<String>) -> BackupStatus {
    BackupStatus {
        recoverable,
        backup_request_id: backup_request_id.filter(|_| recoverable),
        custody: ctx.mode.clone(),
        key_version: ctx.key_version,
        roster_version: ctx.roster_version,
        membership_version: ctx.version,
    }
}
fn check_binding(
    ctx: &Context,
    tenant: i64,
    group: i32,
    admin: &str,
    b: &BackupBinding,
) -> Result<(), BackupError> {
    if b.format_version != 1
        || b.tenant_id != tenant
        || b.group_id != group
        || b.admin_pubkey != admin
        || Some(&b.group_pubkey) != ctx.pubkey.as_ref()
        || b.participant_id != ctx.participant_id
    {
        return Err(BackupError::Invalid);
    }
    if b.key_version != ctx.key_version
        || b.roster_version != ctx.roster_version
        || b.membership_version != ctx.version
    {
        return Err(BackupError::Obsolete);
    }
    Ok(())
}
fn validate_material(
    ctx: &Context,
    b: &BackupBinding,
    material: &BackupMaterial,
) -> Result<(), BackupError> {
    match material {
        BackupMaterial::FullKey { secret_key } => {
            if ctx.mode != "device"
                || b.participant_id.is_some()
                || b.ciphersuite != "BIP-340"
                || b.tweak_version != "none"
                || secret_key.len() != 64
            {
                return Err(BackupError::Invalid);
            }
            let bytes = Zeroizing::new(hex::decode(secret_key).map_err(|_| BackupError::Invalid)?);
            let secret = SecretKey::from_slice(&bytes).map_err(|_| BackupError::Invalid)?;
            if Keys::new(secret).public_key().to_hex() != b.group_pubkey {
                return Err(BackupError::Invalid);
            }
        }
        BackupMaterial::FrostShare {
            key_package,
            public_key_package,
        } => {
            if key_package.len() > 16_384 || public_key_package.len() > 65_536 {
                return Err(BackupError::Invalid);
            }
            use frost_secp256k1_tr as frost;
            if ctx.mode != "frost"
                || b.ciphersuite != "FROST-secp256k1-SHA256-TR-v1"
                || b.tweak_version != "untweaked-v1"
            {
                return Err(BackupError::Invalid);
            }
            let bytes = Zeroizing::new(hex::decode(key_package).map_err(|_| BackupError::Invalid)?);
            let key = Zeroizing::new(
                frost::keys::KeyPackage::deserialize(&bytes).map_err(|_| BackupError::Invalid)?,
            );
            let public = frost::keys::PublicKeyPackage::deserialize(
                &hex::decode(public_key_package).map_err(|_| BackupError::Invalid)?,
            )
            .map_err(|_| BackupError::Invalid)?;
            let participant: u16 = b
                .participant_id
                .and_then(|v| v.try_into().ok())
                .ok_or(BackupError::Invalid)?;
            let id = frost::Identifier::try_from(participant).map_err(|_| BackupError::Invalid)?;
            let verifying = key
                .verifying_key()
                .serialize()
                .map_err(|_| BackupError::Invalid)?;
            if key.serialize().map_err(|_| BackupError::Invalid)? != *bytes
                || key.identifier() != &id
                || key.verifying_key() != public.verifying_key()
                || public.verifying_shares().get(&id) != Some(key.verifying_share())
                || *key.min_signers() < 2
                || usize::from(*key.min_signers()) > public.verifying_shares().len()
                || verifying.len() != 33
                || hex::encode(&verifying[1..]) != b.group_pubkey
            {
                return Err(BackupError::Invalid);
            }
            // Verify that the secret scalar agrees with the package's public share.
            if frost::keys::VerifyingShare::from(*key.signing_share()) != *key.verifying_share() {
                return Err(BackupError::Invalid);
            }
        }
    }
    Ok(())
}

async fn check_authoritative(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    binding: &BackupBinding,
    material: &BackupMaterial,
) -> Result<(), BackupError> {
    if let BackupMaterial::FrostShare {
        key_package,
        public_key_package,
    } = material
    {
        let state: Option<serde_json::Value> = sqlx::query_scalar("SELECT state FROM group_frost_sessions WHERE tenant_id=$1 AND group_id=$2 AND session_kind='dkg' AND aborted=FALSE AND state->'state'->'binding'->>'key_version'=$3 AND state->'state'->'binding'->>'roster_version'=$4 AND state->'state'->'public_package' IS NOT NULL AND state->'state'->'public_package' <> 'null'::jsonb ORDER BY created_at DESC LIMIT 1")
            .bind(tenant).bind(group).bind(binding.key_version.to_string()).bind(binding.roster_version.to_string()).fetch_optional(conn).await?;
        let wrapper = state.ok_or(BackupError::Obsolete)?;
        let state = &wrapper["state"];
        let expected: frost_secp256k1_tr::keys::PublicKeyPackage =
            serde_json::from_value(state["public_package"].clone())
                .map_err(|_| BackupError::Invalid)?;
        let supplied = hex::decode(public_key_package).map_err(|_| BackupError::Invalid)?;
        if expected.serialize().map_err(|_| BackupError::Invalid)? != supplied {
            return Err(BackupError::Invalid);
        }
        let key_bytes = Zeroizing::new(hex::decode(key_package).map_err(|_| BackupError::Invalid)?);
        let key = Zeroizing::new(
            frost_secp256k1_tr::keys::KeyPackage::deserialize(&key_bytes)
                .map_err(|_| BackupError::Invalid)?,
        );
        if state["threshold"].as_u64() != Some(u64::from(*key.min_signers())) {
            return Err(BackupError::Invalid);
        }
    }
    Ok(())
}

async fn validate_package(ctx: &Context, package: &UploadBackup) -> Result<(), BackupError> {
    static VALIDATORS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
    let permit = VALIDATORS
        .try_acquire()
        .map_err(|_| BackupError::Unavailable)?;
    let bytes = Zeroizing::new(serde_json::to_vec(package).map_err(|_| BackupError::Invalid)?);
    if bytes.len() > 128 * 1024 {
        return Err(BackupError::Invalid);
    }
    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let package: UploadBackup =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::Invalid)?;
        validate_material(&ctx, &package.binding, &package.material)
    })
    .await
    .map_err(|_| BackupError::Unavailable)?
}

async fn audit(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    admin: &str,
    action: &str,
    request: &str,
) -> Result<(), BackupError> {
    sqlx::query("INSERT INTO group_audit (tenant_id,group_id,admin_pubkey,action,session_id) VALUES ($1,$2,$3,$4,$5)")
        .bind(tenant).bind(group).bind(admin).bind(action).bind(request).execute(conn).await?;
    Ok(())
}
