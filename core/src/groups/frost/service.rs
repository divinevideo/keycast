use super::*;
use nostr::{Event, UnsignedEvent};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgPool};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

static WORK: once_cell::sync::Lazy<Arc<Semaphore>> =
    once_cell::sync::Lazy::new(|| Arc::new(Semaphore::new(4)));

#[derive(Clone)]
pub struct FrostCoordinator {
    pool: PgPool,
}

#[derive(FromRow)]
struct GroupRow {
    key_version: i32,
    roster_version: i32,
    pubkey: Option<String>,
    mode: String,
}
#[derive(FromRow)]
struct MemberRow {
    admin_pubkey: String,
    participant_id: Option<i32>,
    version: i64,
    installation_epoch: i64,
    status: String,
    human_active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "state", rename_all = "snake_case")]
// Only one public session is loaded per transaction; keep the wire/native API
// concrete rather than adding heap indirection for individual variants.
#[allow(clippy::large_enum_variant)]
pub enum Session {
    Dkg(DkgState),
    Signing(SigningState),
}
impl Session {
    fn members(&self) -> &[Member] {
        match self {
            Self::Dkg(s) => &s.roster,
            Self::Signing(s) => &s.signers,
        }
    }
    fn binding(&self) -> &Binding {
        match self {
            Self::Dkg(s) => &s.binding,
            Self::Signing(s) => &s.binding,
        }
    }
    fn abort(&mut self) {
        match self {
            Self::Dkg(s) => s.aborted = true,
            Self::Signing(s) => s.aborted = true,
        }
    }
    fn aborted(&self) -> bool {
        match self {
            Self::Dkg(s) => s.aborted,
            Self::Signing(s) => s.aborted,
        }
    }
}

async fn admission() -> Result<OwnedSemaphorePermit, FrostError> {
    WORK.clone()
        .try_acquire_owned()
        .map_err(|_| FrostError::Invalid("coordinator busy; retry"))
}

async fn context(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    admin: &str,
) -> Result<(GroupRow, Vec<MemberRow>), FrostError> {
    let row: GroupRow = sqlx::query_as("SELECT key_version,roster_version,pubkey,mode FROM identity_groups WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant).bind(group).fetch_optional(&mut *conn).await?.ok_or(FrostError::Forbidden)?;
    let members: Vec<MemberRow> = sqlx::query_as("SELECT m.admin_pubkey,m.participant_id,m.version,m.installation_epoch,m.status,(u.status='active') AS human_active FROM group_memberships m JOIN users u ON u.tenant_id=m.tenant_id AND u.pubkey=m.admin_pubkey WHERE m.tenant_id=$1 AND m.group_id=$2 ORDER BY m.admin_pubkey FOR UPDATE OF m FOR SHARE OF u")
        .bind(tenant).bind(group).fetch_all(&mut *conn).await?;
    if row.mode != "frost"
        || !members
            .iter()
            .any(|m| m.admin_pubkey == admin && m.status == "active" && m.human_active)
    {
        return Err(FrostError::Forbidden);
    }
    Ok((row, members))
}

fn active_snapshot(members: &[MemberRow]) -> Result<Vec<Member>, FrostError> {
    members
        .iter()
        .filter(|m| m.status == "active" && m.human_active)
        .map(|m| {
            Ok(Member {
                admin_pubkey: m.admin_pubkey.clone(),
                participant_id: m
                    .participant_id
                    .and_then(|id| id.try_into().ok())
                    .ok_or(FrostError::Invalid("missing participant identifier"))?,
                version: m.version,
                installation_epoch: m.installation_epoch,
            })
        })
        .collect()
}

async fn save(conn: &mut PgConnection, state: &Session) -> Result<(), FrostError> {
    let b = state.binding();
    sqlx::query("UPDATE group_frost_sessions SET state=$4,aborted=$5 WHERE tenant_id=$1 AND group_id=$2 AND id=$3")
        .bind(b.tenant_id).bind(b.group_id).bind(&b.session_id).bind(serde_json::to_value(state)?).bind(state.aborted()).execute(conn).await?;
    Ok(())
}

async fn load(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    id: &str,
) -> Result<(Session, bool), FrostError> {
    let (value,aborted,expired): (serde_json::Value,bool,bool) = sqlx::query_as("SELECT state,aborted,expires_at <= now() FROM group_frost_sessions WHERE tenant_id=$1 AND group_id=$2 AND id=$3 FOR UPDATE")
        .bind(tenant).bind(group).bind(id).fetch_optional(conn).await?.ok_or(FrostError::NotFound)?;
    let mut session: Session = serde_json::from_value(value)?;
    if aborted {
        session.abort();
    }
    Ok((session, aborted || expired))
}

fn current(session: &Session, group: &GroupRow, members: &[MemberRow]) -> bool {
    let b = session.binding();
    b.key_version == group.key_version
        && b.roster_version == group.roster_version
        && session.members().iter().all(|s| {
            members.iter().any(|m| {
                m.status == "active"
                    && m.human_active
                    && m.admin_pubkey == s.admin_pubkey
                    && m.participant_id == Some(i32::from(s.participant_id))
                    && m.version == s.version
                    && m.installation_epoch == s.installation_epoch
            })
        })
        && (!matches!(session, Session::Dkg(_))
            || members
                .iter()
                .filter(|m| m.status == "active" && m.human_active)
                .count()
                == session.members().len())
}

fn valid_id(id: &str) -> Result<(), FrostError> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| FrostError::Invalid("session id must be a fresh UUID"))?;
    Ok(())
}

async fn audit(
    conn: &mut PgConnection,
    tenant: i64,
    group: i32,
    admin: &str,
    id: &str,
    action: &str,
    event: Option<String>,
) -> Result<(), FrostError> {
    sqlx::query("INSERT INTO group_audit (tenant_id,group_id,admin_pubkey,action,session_id,event_id) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(tenant).bind(group).bind(admin).bind(action).bind(id).bind(event).execute(conn).await?;
    Ok(())
}

impl FrostCoordinator {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Discover immutable public identity data after device loss. No historical
    /// ceremony ID, device credential, nonce or installation snapshot is needed.
    pub async fn identity(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
    ) -> Result<DkgState, FrostError> {
        let permit = admission().await?;
        let mut tx = self.pool.begin().await?;
        let (row, _) = context(&mut tx, tenant, group, admin).await?;
        let expected = row.pubkey.ok_or(FrostError::NotFound)?;
        let value:serde_json::Value=sqlx::query_scalar("SELECT state FROM group_frost_sessions WHERE tenant_id=$1 AND group_id=$2 AND session_kind='dkg' AND NOT aborted AND state->>'type'='dkg' AND state->'state'->>'aborted'='false' AND jsonb_typeof(state->'state'->'public_package')='object' AND state->'state'->'binding'->>'key_version'=$3 AND state->'state'->'binding'->>'roster_version'=$4 ORDER BY created_at DESC,id LIMIT 1")
            .bind(tenant).bind(group).bind(row.key_version.to_string()).bind(row.roster_version.to_string()).fetch_optional(&mut *tx).await?.ok_or(FrostError::NotFound)?;
        let identity = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let Session::Dkg(state) = serde_json::from_value(value)? else {
                return Err(FrostError::Invalid("invalid confirmed identity"));
            };
            if state.binding.tenant_id != tenant
                || state.binding.group_id != group
                || group_pubkey(state.confirmed_public_package()?)?.to_hex() != expected
            {
                return Err(FrostError::Invalid("confirmed identity binding differs"));
            }
            Ok(state)
        })
        .await
        .map_err(|_| FrostError::Aborted)??;
        tx.commit().await?;
        Ok(identity)
    }

    pub async fn create_dkg(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        session_id: &str,
        threshold: u16,
    ) -> Result<DkgState, FrostError> {
        valid_id(session_id)?;
        let _permit = admission().await?;
        let mut tx = self.pool.begin().await?;
        let (row, mut members) = context(&mut tx, tenant, group, admin).await?;
        if let Ok((Session::Dkg(state), stale)) = load(&mut tx, tenant, group, session_id).await {
            if stale || state.aborted || state.threshold != threshold {
                return Err(FrostError::Invalid("session id already used or expired"));
            }
            if !current(&Session::Dkg(state.clone()), &row, &members) {
                return Err(FrostError::Aborted);
            }
            tx.commit().await?;
            return Ok(state);
        }
        if row.pubkey.is_some() {
            return Err(FrostError::Invalid(
                "group identity already generated; rotation requires a new group",
            ));
        }
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_frost_sessions WHERE tenant_id=$1 AND group_id=$2 AND session_kind='dkg' AND NOT aborted AND expires_at > now())")
            .bind(tenant).bind(group).fetch_one(&mut *tx).await?;
        if pending {
            return Err(FrostError::Invalid("another DKG ceremony is pending"));
        }
        let mut next = members
            .iter()
            .filter_map(|m| m.participant_id)
            .max()
            .unwrap_or(0);
        for member in members
            .iter_mut()
            .filter(|m| m.status == "active" && m.participant_id.is_none())
        {
            next += 1;
            if next > i32::from(u16::MAX) {
                return Err(FrostError::Invalid("participant identifiers exhausted"));
            }
            sqlx::query("UPDATE group_memberships SET participant_id=$4 WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND participant_id IS NULL")
                .bind(tenant).bind(group).bind(&member.admin_pubkey).bind(next).execute(&mut *tx).await?;
            member.participant_id = Some(next);
        }
        let binding = Binding {
            protocol: PROTOCOL.into(),
            tenant_id: tenant,
            group_id: group,
            session_id: session_id.into(),
            key_version: row.key_version,
            roster_version: row.roster_version,
            roster_hash: String::new(),
        };
        let state = DkgState::new(binding, threshold, active_snapshot(&members)?)?;
        Self::insert(&mut tx, &Session::Dkg(state.clone()), "dkg").await?;
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            session_id,
            "frost_dkg_create",
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(state)
    }

    async fn insert(
        conn: &mut PgConnection,
        state: &Session,
        kind: &str,
    ) -> Result<(), FrostError> {
        let b = state.binding();
        sqlx::query("INSERT INTO group_frost_sessions (tenant_id,group_id,id,session_kind,state,expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval '15 minutes')")
            .bind(b.tenant_id).bind(b.group_id).bind(&b.session_id).bind(kind).bind(serde_json::to_value(state)?).execute(conn).await?;
        Ok(())
    }

    pub async fn get(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        id: &str,
    ) -> Result<Session, FrostError> {
        let mut tx = self.pool.begin().await?;
        let (row, members) = context(&mut tx, tenant, group, admin).await?;
        let (mut session, expired) = load(&mut tx, tenant, group, id).await?;
        // Completed DKG remains available as public identity data after timeout or removal.
        let completed = matches!(&session, Session::Dkg(s) if s.public_package.is_some())
            || matches!(&session,Session::Signing(s) if s.result.is_some());
        if !completed && (expired || !current(&session, &row, &members)) {
            session.abort();
            save(&mut tx, &session).await?;
            audit(&mut tx, tenant, group, admin, id, "frost_stale_abort", None).await?;
        }
        tx.commit().await?;
        Ok(session)
    }

    pub async fn dkg_message(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        id: &str,
        event: Event,
    ) -> Result<DkgState, FrostError> {
        let permit = admission().await?;
        let mut tx = self.pool.begin().await?;
        let (row, members) = context(&mut tx, tenant, group, admin).await?;
        let (mut session, stale) = load(&mut tx, tenant, group, id).await?;
        // A completed ceremony is immutable identity data. Late traffic must
        // never turn an established identity into an aborted pending session.
        if let Session::Dkg(completed) = &session {
            if completed.public_package.is_some() {
                if event.pubkey.to_hex() != admin {
                    return Err(FrostError::Forbidden);
                }
                let original = completed.clone();
                let mut check = completed.clone();
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    check.receive(event)
                })
                .await
                .map_err(|_| FrostError::Aborted)??;
                tx.commit().await?;
                return Ok(original);
            }
        }
        if stale || !current(&session, &row, &members) {
            session.abort();
            save(&mut tx, &session).await?;
            audit(&mut tx, tenant, group, admin, id, "frost_stale_abort", None).await?;
            tx.commit().await?;
            return Err(FrostError::Aborted);
        }
        let Session::Dkg(mut state) = session else {
            return Err(FrostError::Invalid("not a DKG session"));
        };
        if event.pubkey.to_hex() != admin {
            return Err(FrostError::Forbidden);
        }
        let (state_after, result) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let r = state.receive(event);
            (state, r)
        })
        .await
        .map_err(|_| FrostError::Aborted)?;
        state = state_after;
        if let Some(package) = &state.public_package {
            let pubkey = group_pubkey(package)?.to_hex();
            if row.pubkey.as_ref().is_some_and(|p| p != &pubkey) {
                return Err(FrostError::Invalid("group public key changed"));
            }
            sqlx::query("UPDATE identity_groups SET pubkey=$3 WHERE tenant_id=$1 AND id=$2 AND pubkey IS NULL").bind(tenant).bind(group).bind(pubkey).execute(&mut *tx).await?;
        }
        save(&mut tx, &Session::Dkg(state.clone())).await?;
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            id,
            if result.is_ok() {
                "frost_dkg_message"
            } else {
                "frost_dkg_abort"
            },
            None,
        )
        .await?;
        tx.commit().await?;
        result?;
        Ok(state)
    }

    // Keep tenant/group/acting human explicit at the authorization boundary;
    // the remaining inputs form one immutable signing proposal.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_signing(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        id: &str,
        dkg_id: &str,
        event: UnsignedEvent,
        signer_ids: Vec<u16>,
    ) -> Result<SigningState, FrostError> {
        valid_id(id)?;
        let permit = admission().await?;
        let mut tx = self.pool.begin().await?;
        let (row, members) = context(&mut tx, tenant, group, admin).await?;
        if let Ok((Session::Signing(prior), _)) = load(&mut tx, tenant, group, id).await {
            if prior.result.is_some() {
                let mut requested = event.clone();
                let canonical = nostr::EventId::new(
                    &requested.pubkey,
                    &requested.created_at,
                    &requested.kind,
                    &requested.tags,
                    &requested.content,
                );
                if requested.id.is_some_and(|provided| provided != canonical) {
                    return Err(FrostError::Invalid("event id differs from event bytes"));
                }
                requested.id = Some(canonical);
                let mut expected = prior
                    .signers
                    .iter()
                    .map(|m| m.participant_id)
                    .collect::<Vec<_>>();
                expected.sort_unstable();
                let mut requested_ids = signer_ids.clone();
                requested_ids.sort_unstable();
                if prior.dkg_session_id != dkg_id
                    || prior.event != requested
                    || expected != requested_ids
                {
                    return Err(FrostError::Invalid("completed signing proposal differs"));
                }
                tx.commit().await?;
                return Ok(prior);
            }
        }
        let (dkg, aborted) = load(&mut tx, tenant, group, dkg_id).await?;
        let Session::Dkg(dkg) = dkg else {
            return Err(FrostError::Invalid("not a DKG session"));
        };
        // Expiry ends a ceremony, not the identity created by a completed ceremony.
        if (aborted && dkg.public_package.is_none()) || dkg.aborted || row.pubkey.is_none() {
            return Err(FrostError::Aborted);
        }
        let signers = active_snapshot(&members)?
            .into_iter()
            .filter(|m| signer_ids.contains(&m.participant_id))
            .collect::<Vec<_>>();
        if signers.len() != signer_ids.len() {
            return Err(FrostError::Invalid("unknown, duplicate or inactive signer"));
        }
        for signer in &signers {
            let backed_up:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_backups WHERE tenant_id=$1 AND group_id=$2 AND admin_pubkey=$3 AND membership_version=$4 AND key_version=$5 AND roster_version=$6)")
                .bind(tenant).bind(group).bind(&signer.admin_pubkey).bind(signer.version).bind(row.key_version).bind(row.roster_version).fetch_one(&mut *tx).await?;
            if !backed_up {
                return Err(FrostError::Invalid("participant backup required; upload and confirm current share recovery material"));
            }
        }
        let mut binding = dkg.binding.clone();
        binding.session_id = id.into();
        if binding.key_version != row.key_version || binding.roster_version != row.roster_version {
            return Err(FrostError::Invalid("obsolete identity version"));
        }
        let proposed = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            SigningState::new(binding, &dkg, event, signers)
        })
        .await
        .map_err(|_| FrostError::Aborted)??;
        if let Ok((Session::Signing(mut prior), stale)) = load(&mut tx, tenant, group, id).await {
            if stale || prior.aborted || prior.proposal_digest()? != proposed.proposal_digest()? {
                prior.aborted = true;
                save(&mut tx, &Session::Signing(prior)).await?;
                audit(
                    &mut tx,
                    tenant,
                    group,
                    admin,
                    id,
                    "frost_proposal_abort",
                    None,
                )
                .await?;
                tx.commit().await?;
                return Err(FrostError::Invalid(
                    "conflicting or expired signing session",
                ));
            }
            tx.commit().await?;
            return Ok(prior);
        }
        Self::insert(&mut tx, &Session::Signing(proposed.clone()), "signing").await?;
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            id,
            "frost_signing_create",
            Some(proposed.event_id.to_hex()),
        )
        .await?;
        tx.commit().await?;
        Ok(proposed)
    }

    pub async fn signing_message(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        id: &str,
        message: SigningMessage,
    ) -> Result<SigningState, FrostError> {
        let permit = admission().await?;
        let mut tx = self.pool.begin().await?;
        let (row, members) = context(&mut tx, tenant, group, admin).await?;
        let (mut session, expired) = load(&mut tx, tenant, group, id).await?;
        if let Session::Signing(completed) = &session {
            if completed.result.is_some() {
                let signer = completed
                    .signers
                    .iter()
                    .find(|m| m.admin_pubkey == admin)
                    .ok_or(FrostError::Forbidden)?
                    .participant_id;
                let exact = match &message {
                    SigningMessage::Commitment {
                        proposal_digest,
                        commitment,
                    } => {
                        proposal_digest == &completed.proposal_digest()?
                            && completed.commitments.get(&signer) == Some(commitment)
                    }
                    SigningMessage::Partial {
                        proposal_digest,
                        partial,
                    } => {
                        proposal_digest == &completed.proposal_digest()?
                            && completed.partials.get(&signer) == Some(partial)
                    }
                    SigningMessage::Abort => false,
                };
                if !exact {
                    return Err(FrostError::Invalid("completed signing message differs"));
                }
                let original = completed.clone();
                tx.commit().await?;
                return Ok(original);
            }
        }
        if expired || !current(&session, &row, &members) {
            session.abort();
            save(&mut tx, &session).await?;
            audit(&mut tx, tenant, group, admin, id, "frost_stale_abort", None).await?;
            tx.commit().await?;
            return Err(FrostError::Aborted);
        }
        let Session::Signing(mut state) = session else {
            return Err(FrostError::Invalid("not a signing session"));
        };
        if state.aborted {
            return Err(FrostError::Aborted);
        }
        let signer = state
            .signers
            .iter()
            .find(|m| m.admin_pubkey == admin)
            .ok_or(FrostError::Forbidden)?
            .participant_id;
        let was_completed = state.result.is_some();
        let result = match message {
            SigningMessage::Abort => {
                state.aborted = true;
                Ok(())
            }
            SigningMessage::Commitment {
                proposal_digest,
                commitment,
            } => {
                if proposal_digest != state.proposal_digest()? {
                    state.aborted = true;
                    Err(FrostError::Invalid("signing proposal differs"))
                } else if let Some(prior) = state.commitments.get(&signer) {
                    if prior == &commitment {
                        Ok(())
                    } else {
                        state.aborted = true;
                        Err(FrostError::Invalid("conflicting commitment"))
                    }
                } else {
                    // Reserve BOTH nonce points independently. Reusing either scalar
                    // is forbidden, even with a different companion commitment.
                    let hashes = [digest(commitment.hiding())?, digest(commitment.binding())?];
                    let mut reused = false;
                    for hash in hashes {
                        let inserted=sqlx::query("INSERT INTO group_frost_commitments (tenant_id,group_id,participant_id,commitment_hash,session_id) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
                            .bind(tenant).bind(group).bind(i32::from(signer)).bind(hash).bind(id).execute(&mut *tx).await?.rows_affected();
                        if inserted != 1 {
                            reused = true;
                        }
                    }
                    if reused {
                        state.aborted = true;
                        Err(FrostError::Invalid("nonce commitment already used"))
                    } else {
                        state.commitments.insert(signer, commitment);
                        Ok(())
                    }
                }
            }
            SigningMessage::Partial {
                proposal_digest,
                partial,
            } => {
                if proposal_digest != state.proposal_digest()? {
                    state.aborted = true;
                    Err(FrostError::Invalid("signing proposal differs"))
                } else {
                    let (s, r) = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let r = state.add_partial(signer, partial);
                        (state, r)
                    })
                    .await
                    .map_err(|_| FrostError::Aborted)?;
                    state = s;
                    r
                }
            }
        };
        save(&mut tx, &Session::Signing(state.clone())).await?;
        let action = if state.result.is_some() && !was_completed {
            "frost_sign_event"
        } else if state.aborted {
            "frost_signing_abort"
        } else {
            "frost_signing_message"
        };
        audit(
            &mut tx,
            tenant,
            group,
            admin,
            id,
            action,
            Some(state.event_id.to_hex()),
        )
        .await?;
        tx.commit().await?;
        result?;
        Ok(state)
    }

    pub async fn abort(
        &self,
        tenant: i64,
        group: i32,
        admin: &str,
        id: &str,
    ) -> Result<(), FrostError> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, tenant, group, admin).await?;
        let (mut state, _) = load(&mut tx, tenant, group, id).await?;
        if matches!(&state,Session::Dkg(d) if d.public_package.is_some())
            || matches!(&state,Session::Signing(s) if s.result.is_some())
        {
            return Err(FrostError::Invalid("completed result cannot be aborted"));
        }
        state.abort();
        save(&mut tx, &state).await?;
        audit(&mut tx, tenant, group, admin, id, "frost_abort", None).await?;
        tx.commit().await?;
        Ok(())
    }
}
