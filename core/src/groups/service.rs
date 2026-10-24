use crate::{encryption::KeyManager, secret_pool::SecretPair, types::authorization::Authorization};
use nostr_sdk::{Keys, PublicKey, SecretKey};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgPool};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("Group access denied")]
    Forbidden,
    #[error("Invalid group request: {0}")]
    Invalid(&'static str),
    #[error("Group request conflicts with current state")]
    Conflict,
    #[error("Group storage unavailable; retry the request")]
    Storage(#[from] sqlx::Error),
    #[error("Signing material temporarily unavailable; retry the request")]
    Encryption,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum GroupMode {
    #[default]
    Hosted,
    Device,
    Frost,
}
impl GroupMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::Device => "device",
            Self::Frost => "frost",
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroup {
    pub request_id: String,
    pub name: String,
    #[serde(default)]
    pub mode: GroupMode,
    pub pubkey: Option<String>,
}
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct Group {
    pub id: i32,
    pub tenant_id: i64,
    pub name: String,
    pub pubkey: Option<String>,
    pub signing_key_id: Option<i32>,
    pub policy_id: i32,
    pub mode: GroupMode,
    pub key_version: i32,
    pub roster_version: i32,
}
const GROUP_COLUMNS: &str = "g.id,g.tenant_id,g.name,g.pubkey,g.signing_key_id,g.policy_id,g.mode,g.key_version,g.roster_version";
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct GroupMembership {
    pub tenant_id: i64,
    pub group_id: i32,
    pub admin_pubkey: String,
    pub status: String,
    pub version: i64,
    pub participant_id: Option<i32>,
    pub installation_epoch: i64,
}
const MEMBER_COLUMNS: &str = "m.tenant_id,m.group_id,m.admin_pubkey,m.status,m.version,m.participant_id,m.installation_epoch";

pub async fn require_admin(
    pool: &PgPool,
    tenant: i64,
    group: i32,
    admin: &str,
) -> Result<GroupMembership, GroupError> {
    member(&mut *pool.acquire().await?, tenant, group, admin).await
}
async fn member(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    admin: &str,
) -> Result<GroupMembership, GroupError> {
    sqlx::query_as(&format!("SELECT {MEMBER_COLUMNS} FROM group_memberships m JOIN users u ON u.pubkey=m.admin_pubkey AND u.tenant_id=m.tenant_id WHERE m.tenant_id=$1 AND m.group_id=$2 AND m.admin_pubkey=$3 AND m.status='active' AND u.status='active'"))
        .bind(tenant).bind(group).bind(admin).fetch_optional(conn).await?.ok_or(GroupError::Forbidden)
}
async fn lock_group(conn: &mut PgConnection, tenant: i64, group: i32) -> Result<Group, GroupError> {
    sqlx::query_as(&format!(
        "SELECT {GROUP_COLUMNS} FROM identity_groups g WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
    ))
    .bind(tenant)
    .bind(group)
    .fetch_optional(conn)
    .await?
    .ok_or(GroupError::Forbidden)
}
/// Serialize new active relationships with account deletion before group/user locks.
pub(crate) async fn lock_group_account(
    conn: &mut PgConnection,
    tenant: i64,
    admin: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("group-account:{tenant}:{admin}"))
        .execute(conn)
        .await?;
    Ok(())
}

/// Serialize a tenant's OG Diviner grant loads with its account deletions.
///
/// Account deletion deletes a pubkey's grant and records itself in
/// `service_account_deletions` in one transaction; a grant load reads those
/// records and inserts grants in another. Under READ COMMITTED neither sees the
/// other's uncommitted rows, so interleaved they could each miss the other and
/// leave a grant nothing will ever remove: the coordinator does not call
/// Keycast again for a completed deletion. Deletions take this lock shared, so
/// they never wait on each other; a load takes it exclusive.
///
/// One key per tenant rather than one per pubkey: a load covers the whole
/// roster in one transaction, and a lock per pubkey would hold thousands of
/// entries in Postgres's server-wide lock table.
pub(crate) async fn lock_og_diviner_grants_shared(
    conn: &mut PgConnection,
    tenant: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind(og_diviner_grants_lock_key(tenant))
        .execute(conn)
        .await?;
    Ok(())
}

/// The exclusive side of [`lock_og_diviner_grants_shared`], for a grant load.
pub(crate) async fn lock_og_diviner_grants_exclusive(
    conn: &mut PgConnection,
    tenant: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(og_diviner_grants_lock_key(tenant))
        .execute(conn)
        .await?;
    Ok(())
}

fn og_diviner_grants_lock_key(tenant: i64) -> String {
    format!("og-diviner-grants:{tenant}")
}

async fn audit(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    admin: &str,
    action: &str,
    session: Option<&str>,
) -> Result<(), GroupError> {
    sqlx::query("INSERT INTO group_audit (tenant_id,group_id,admin_pubkey,action,session_id) VALUES ($1,$2,$3,$4,$5)")
        .bind(tenant).bind(group).bind(admin).bind(action).bind(session).execute(conn).await?;
    Ok(())
}
fn public_key(value: &str) -> Result<String, GroupError> {
    PublicKey::from_hex(value)
        .map(|p| p.to_hex())
        .map_err(|_| GroupError::Invalid("expected a full Nostr pubkey"))
}

pub struct GroupService<'a> {
    pool: PgPool,
    kms: &'a dyn KeyManager,
}
impl<'a> GroupService<'a> {
    pub fn new(pool: PgPool, kms: &'a dyn KeyManager) -> Self {
        Self { pool, kms }
    }
    pub async fn create(
        &self,
        tenant: i64,
        admin: &str,
        request: &CreateGroup,
    ) -> Result<Group, GroupError> {
        let admin = public_key(admin)?;
        if request.name.trim().is_empty()
            || request.name.len() > 128
            || request.request_id.is_empty()
            || request.request_id.len() > 128
        {
            return Err(GroupError::Invalid(
                "name and request_id are required (128 bytes maximum)",
            ));
        }
        if request.mode != GroupMode::Device && request.pubkey.is_some() {
            return Err(GroupError::Invalid("only device mode accepts a public key"));
        }
        let device_key = if request.mode == GroupMode::Device {
            Some(public_key(request.pubkey.as_deref().ok_or(
                GroupError::Invalid("device mode requires the group pubkey"),
            )?)?)
        } else {
            None
        };
        // KMS never runs while holding a transaction/connection.
        let hosted = if request.mode == GroupMode::Hosted {
            let k = Keys::generate();
            Some((
                k.public_key().to_hex(),
                self.kms
                    .encrypt(k.secret_key().as_secret_bytes())
                    .await
                    .map_err(|_| GroupError::Encryption)?,
            ))
        } else {
            None
        };
        let mut tx = self.pool.begin().await?;
        lock_group_account(&mut tx, tenant, &admin).await?;
        // Serializes identical creation retries without reserving an identity before encryption succeeds.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "group-create:{tenant}:{admin}:{}",
                request.request_id
            ))
            .execute(&mut *tx)
            .await?;
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=$1 AND pubkey=$2 AND status='active')").bind(tenant).bind(&admin).fetch_one(&mut *tx).await?;
        if !exists {
            return Err(GroupError::Forbidden);
        }
        let prior:Option<Group>=sqlx::query_as(&format!("SELECT {GROUP_COLUMNS} FROM identity_groups g WHERE tenant_id=$1 AND creator_pubkey=$2 AND request_id=$3"))
            .bind(tenant).bind(&admin).bind(&request.request_id).fetch_optional(&mut *tx).await?;
        if let Some(prior) = prior {
            member(&mut tx, tenant, prior.id, &admin).await?;
            if prior.name != request.name
                || prior.mode != request.mode
                || (request.mode == GroupMode::Device && prior.pubkey != device_key)
            {
                return Err(GroupError::Conflict);
            }
            tx.commit().await?;
            return Ok(prior);
        }
        let id: i32 =
            sqlx::query_scalar("INSERT INTO teams (tenant_id,name) VALUES ($1,$2) RETURNING id")
                .bind(tenant)
                .bind(&request.name)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query("INSERT INTO team_users (team_id,user_pubkey,role) VALUES ($1,$2,'admin')")
            .bind(id)
            .bind(&admin)
            .execute(&mut *tx)
            .await?;
        // An empty permission set intentionally permits all ordinary NIP-46 operations.
        let policy: i32 = sqlx::query_scalar(
            "INSERT INTO policies (team_id,name) VALUES ($1,'Group admin') RETURNING id",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let (pubkey, stored) = if let Some((pubkey, cipher)) = hosted {
            let stored:i32=sqlx::query_scalar("INSERT INTO stored_keys (tenant_id,team_id,name,pubkey,secret_key) VALUES ($1,$2,$3,$4,$5) RETURNING id").bind(tenant).bind(id).bind(&request.name).bind(&pubkey).bind(cipher).fetch_one(&mut *tx).await?;
            (Some(pubkey), Some(stored))
        } else {
            (device_key, None)
        };
        sqlx::query("INSERT INTO identity_groups (id,tenant_id,name,pubkey,signing_key_id,policy_id,mode,creator_pubkey,request_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(id).bind(tenant).bind(&request.name).bind(pubkey).bind(stored).bind(policy).bind(request.mode.as_str()).bind(&admin).bind(&request.request_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO group_memberships (tenant_id,group_id,admin_pubkey,status) VALUES ($1,$2,$3,'active')").bind(tenant).bind(id).bind(&admin).execute(&mut *tx).await?;
        audit(&mut tx, tenant, id, &admin, "group_created", None).await?;
        let result = lock_group(&mut tx, tenant, id).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn get(&self, tenant: i64, group: i32, admin: &str) -> Result<Group, GroupError> {
        require_admin(&self.pool, tenant, group, admin).await?;
        sqlx::query_as(&format!(
            "SELECT {GROUP_COLUMNS} FROM identity_groups g WHERE tenant_id=$1 AND id=$2"
        ))
        .bind(tenant)
        .bind(group)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(GroupError::Forbidden)
    }
    pub async fn list(&self, tenant: i64, admin: &str) -> Result<Vec<Group>, GroupError> {
        Ok(sqlx::query_as(&format!("SELECT {GROUP_COLUMNS} FROM identity_groups g JOIN group_memberships m ON m.group_id=g.id AND m.tenant_id=g.tenant_id JOIN users u ON u.pubkey=m.admin_pubkey AND u.tenant_id=m.tenant_id WHERE g.tenant_id=$1 AND m.admin_pubkey=$2 AND m.status='active' AND u.status='active' ORDER BY g.id"))
            .bind(tenant).bind(admin).fetch_all(&self.pool).await?)
    }
    pub async fn members(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
    ) -> Result<Vec<GroupMembership>, GroupError> {
        require_admin(&self.pool, tenant, group, admin).await?;
        Ok(sqlx::query_as(&format!("SELECT {MEMBER_COLUMNS} FROM group_memberships m WHERE tenant_id=$1 AND group_id=$2 ORDER BY admin_pubkey"))
            .bind(tenant).bind(group).fetch_all(&self.pool).await?)
    }
    pub async fn invitations(&self, tenant: i64, admin: &str) -> Result<Vec<Group>, GroupError> {
        Ok(sqlx::query_as(&format!("SELECT {GROUP_COLUMNS} FROM identity_groups g JOIN group_memberships m ON m.group_id=g.id AND m.tenant_id=g.tenant_id WHERE g.tenant_id=$1 AND m.admin_pubkey=$2 AND m.status='invited' ORDER BY g.id"))
            .bind(tenant).bind(admin).fetch_all(&self.pool).await?)
    }
    pub async fn invite(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        invitee: &str,
    ) -> Result<(), GroupError> {
        let invitee = public_key(invitee)?;
        let mut tx = self.pool.begin().await?;
        let g = lock_group(&mut tx, tenant, group).await?;
        member(&mut tx, tenant, group, admin).await?;
        if g.mode == GroupMode::Frost && g.pubkey.is_some() {
            return Err(GroupError::Invalid(
                "a new threshold roster requires a new group identity",
            ));
        }
        sqlx::query("INSERT INTO group_memberships (tenant_id,group_id,admin_pubkey,status) VALUES ($1,$2,$3,'invited') ON CONFLICT (tenant_id,group_id,admin_pubkey) DO UPDATE SET status='invited',version=group_memberships.version+1 WHERE group_memberships.status='removed'")
            .bind(tenant).bind(group).bind(&invitee).execute(&mut *tx).await?;
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            "admin_invited",
            Some(&invitee),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn accept(&self, tenant: i64, group: i32, admin: &str) -> Result<(), GroupError> {
        let mut tx = self.pool.begin().await?;
        lock_group_account(&mut tx, tenant, admin).await?;
        let current = lock_group(&mut tx, tenant, group).await?;
        if current.mode == GroupMode::Frost && current.pubkey.is_some() {
            let pinned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_memberships WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND status='active' AND participant_id IS NOT NULL)")
                .bind(tenant).bind(group).bind(admin).fetch_one(&mut *tx).await?;
            if !pinned {
                return Err(GroupError::Invalid(
                    "a new threshold participant requires a new group identity",
                ));
            }
        }
        let result=sqlx::query("UPDATE group_memberships m SET status='active' WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND status IN ('invited','active') AND EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=$1 AND u.pubkey=$3 AND u.status='active')")
            .bind(tenant).bind(group).bind(admin).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(GroupError::Forbidden);
        }
        sqlx::query("INSERT INTO team_users (team_id,user_pubkey,role) VALUES ($1,$2,'admin') ON CONFLICT (team_id,user_pubkey) DO NOTHING").bind(group).bind(admin).execute(&mut *tx).await?;
        audit(&mut tx, tenant, group, admin, "invitation_accepted", None).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn remove(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        removed: &str,
    ) -> Result<(), GroupError> {
        let mut tx = self.pool.begin().await?;
        lock_group(&mut tx, tenant, group).await?;
        member(&mut tx, tenant, group, admin).await?;
        let others:i64=sqlx::query_scalar("SELECT COUNT(*) FROM group_memberships m JOIN users u ON u.tenant_id=m.tenant_id AND u.pubkey=m.admin_pubkey WHERE m.tenant_id=$1 AND m.group_id=$2 AND m.status='active' AND u.status='active' AND m.admin_pubkey<>$3").bind(tenant).bind(group).bind(removed).fetch_one(&mut *tx).await?;
        if others == 0 {
            return Err(GroupError::Invalid("at least one active admin must remain"));
        }
        sqlx::query("UPDATE group_memberships SET status='removed',version=version+1,installation_epoch=installation_epoch+1 WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND status<>'removed'").bind(tenant).bind(group).bind(removed).execute(&mut *tx).await?;
        sqlx::query("UPDATE group_grants SET revoked_at=NOW() WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND revoked_at IS NULL").bind(tenant).bind(group).bind(removed).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM team_users WHERE team_id=$1 AND user_pubkey=$2")
            .bind(group)
            .bind(removed)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            "admin_removed",
            Some(removed),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    /// The caller obtains a bcrypt secret pair from bounded admission before this call.
    /// Every enrollment is fresh; recovery can revoke all prior installations first.
    pub async fn enroll(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        client: &str,
        pair: SecretPair,
        recovery: bool,
    ) -> Result<GroupAccess, GroupError> {
        let client = public_key(client)?;
        let g = self.get(tenant, group, admin).await?;
        if g.mode != GroupMode::Hosted {
            return Err(GroupError::Invalid(
                "hosted signing is unavailable for this custody mode",
            ));
        }
        let key_id = g.signing_key_id.ok_or(GroupError::Conflict)?;
        let cipher: Vec<u8> = sqlx::query_scalar(
            "SELECT secret_key FROM stored_keys WHERE tenant_id=$1 AND id=$2 AND team_id=$3",
        )
        .bind(tenant)
        .bind(key_id)
        .bind(group)
        .fetch_one(&self.pool)
        .await?;
        let secret = self
            .kms
            .decrypt(&cipher)
            .await
            .map_err(|_| GroupError::Encryption)?;
        let key = SecretKey::from_slice(&secret).map_err(|_| GroupError::Encryption)?;
        let bunker = crate::bunker_key::derive_bunker_keys(&key, &pair.hash);
        let relays = Authorization::get_bunker_relays();
        let mut tx = self.pool.begin().await?;
        let current = lock_group(&mut tx, tenant, group).await?;
        let m = member(&mut tx, tenant, group, admin).await?;
        if current.key_version != g.key_version
            || current.signing_key_id != g.signing_key_id
            || current.pubkey != g.pubkey
        {
            return Err(GroupError::Conflict);
        }
        let epoch = if recovery {
            sqlx::query("UPDATE group_memberships SET installation_epoch=installation_epoch+1 WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3").bind(tenant).bind(group).bind(admin).execute(&mut *tx).await?;
            sqlx::query("UPDATE group_grants SET revoked_at=NOW() WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND revoked_at IS NULL").bind(tenant).bind(group).bind(admin).execute(&mut *tx).await?;
            m.installation_epoch + 1
        } else {
            m.installation_epoch
        };
        let auth:i32=sqlx::query_scalar("INSERT INTO authorizations (tenant_id,stored_key_id,policy_id,secret_hash,bunker_public_key,relays,connected_client_pubkey,connected_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()) RETURNING id")
            .bind(tenant).bind(key_id).bind(g.policy_id).bind(&pair.hash).bind(bunker.public_key().to_hex()).bind(serde_json::to_string(&relays).map_err(|_|GroupError::Conflict)?).bind(&client).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO group_grants (authorization_id,tenant_id,group_id,admin_pubkey,membership_version,key_version,installation_epoch) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(auth).bind(tenant).bind(group).bind(admin).bind(m.version).bind(g.key_version).bind(epoch).execute(&mut *tx).await?;
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            if recovery {
                "device_recovered"
            } else {
                "device_enrolled"
            },
            Some(&auth.to_string()),
        )
        .await?;
        tx.commit().await?;
        Ok(GroupAccess {
            authorization_id: auth,
            group_pubkey: g.pubkey.ok_or(GroupError::Conflict)?,
            bunker_pubkey: bunker.public_key().to_hex(),
            bunker_url: Authorization::generate_bunker_url(
                &bunker.public_key().to_hex(),
                pair.secret.expose_secret(),
            ),
            client_pubkey: client,
            key_version: g.key_version,
            installation_epoch: epoch,
        })
    }
    pub async fn grants(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
    ) -> Result<Vec<GroupGrant>, GroupError> {
        require_admin(&self.pool, tenant, group, admin).await?;
        Ok(sqlx::query_as("SELECT gg.authorization_id,gg.admin_pubkey,gg.membership_version,gg.key_version,gg.installation_epoch,gg.revoked_at,a.connected_client_pubkey,a.policy_id,a.expires_at FROM group_grants gg JOIN authorizations a ON a.id=gg.authorization_id AND a.tenant_id=gg.tenant_id WHERE gg.tenant_id=$1 AND gg.group_id=$2 ORDER BY gg.authorization_id")
            .bind(tenant).bind(group).fetch_all(&self.pool).await?)
    }
    pub async fn revoke(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        authorization: i32,
    ) -> Result<(), GroupError> {
        let mut tx = self.pool.begin().await?;
        lock_group(&mut tx, tenant, group).await?;
        member(&mut tx, tenant, group, admin).await?;
        let rows=sqlx::query("UPDATE group_grants SET revoked_at=COALESCE(revoked_at,NOW()) WHERE tenant_id=$1 AND group_id=$2 AND authorization_id=$3").bind(tenant).bind(group).bind(authorization).execute(&mut *tx).await?;
        if rows.rows_affected() != 1 {
            return Err(GroupError::Forbidden);
        }
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            "grant_revoked",
            Some(&authorization.to_string()),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
#[derive(Serialize)]
pub struct GroupAccess {
    pub authorization_id: i32,
    pub group_pubkey: String,
    pub bunker_pubkey: String,
    pub bunker_url: String,
    pub client_pubkey: String,
    pub key_version: i32,
    pub installation_epoch: i64,
}

#[derive(Serialize, FromRow)]
pub struct GroupGrant {
    pub authorization_id: i32,
    pub admin_pubkey: String,
    pub membership_version: i64,
    pub key_version: i32,
    pub installation_epoch: i64,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub connected_client_pubkey: Option<String>,
    pub policy_id: i32,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
