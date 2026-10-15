//! Mandatory client-side secret boundary. These handles deliberately have no
//! Clone, Debug, serde or nonce-export API. Dropping a handle aborts its operation.
//! A mobile/native binding must keep the handles native and never persist them.
use super::{
    crypto, identifier, Binding, DkgMessage, DkgPayload, DkgState, FrostError, PrivateRound2,
    SigningState, MESSAGE_KIND, PROTOCOL,
};
use frost_secp256k1_tr as frost;
use nostr::{nips::nip44, Event, EventBuilder, Keys, Kind};
use std::collections::BTreeMap;
use zeroize::Zeroize;

fn envelope(keys: &Keys, binding: &Binding, message: DkgMessage) -> Result<Event, FrostError> {
    EventBuilder::new(
        Kind::Custom(MESSAGE_KIND),
        serde_json::to_string(&DkgPayload {
            binding: binding.clone(),
            message,
        })?,
    )
    .sign_with_keys(keys)
    .map_err(|_| FrostError::Invalid("cannot authenticate DKG message"))
}

fn descriptor(state: &DkgState) -> Result<(), FrostError> {
    let check = DkgState::new(state.binding.clone(), state.threshold, state.roster.clone())?;
    if check.binding != state.binding || state.aborted {
        return Err(FrostError::Invalid("invalid ceremony descriptor"));
    }
    Ok(())
}

fn round1_packages(
    state: &DkgState,
    own: u16,
) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>, FrostError> {
    state.transcript()?;
    state
        .round1
        .iter()
        .filter(|(id, _)| **id != own)
        .map(|(id, event)| {
            let (_, payload) = state.parse(event)?;
            match payload.message {
                DkgMessage::Round1 { package } => Ok((identifier(*id)?, package)),
                _ => Err(FrostError::Invalid("invalid round-one package")),
            }
        })
        .collect()
}

pub struct DkgRound1 {
    keys: Keys,
    id: u16,
    binding: Binding,
    secret: frost::keys::dkg::round1::SecretPackage,
    own_round1: Event,
}
impl Drop for DkgRound1 {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl DkgRound1 {
    /// Explicit caller approval starts DKG; inbound envelopes never do so.
    pub fn start(keys: Keys, state: &DkgState) -> Result<(Self, Event), FrostError> {
        descriptor(state)?;
        if !state.round1.is_empty() || !state.agreements.is_empty() {
            // Other peers may have already posted. Only our own prior contribution
            // proves this installation has lost a secret and must abort.
            if state.round1.values().any(|e| e.pubkey == keys.public_key()) {
                return Err(FrostError::Invalid("lost DKG state; restart ceremony"));
            }
        }
        let id = state
            .roster
            .iter()
            .find(|m| m.admin_pubkey == keys.public_key().to_hex())
            .ok_or(FrostError::Forbidden)?
            .participant_id;
        let (secret, package) = crypto(frost::keys::dkg::part1(
            identifier(id)?,
            state.roster.len() as u16,
            state.threshold,
            rand::rngs::OsRng,
        ))?;
        let event = envelope(&keys, &state.binding, DkgMessage::Round1 { package })?;
        Ok((
            Self {
                keys,
                id,
                binding: state.binding.clone(),
                secret,
                own_round1: event.clone(),
            },
            event,
        ))
    }

    pub fn agreement(&self, state: &DkgState) -> Result<Event, FrostError> {
        descriptor(state)?;
        if state.binding != self.binding
            || state.round1.get(&self.id).map(|e| &e.content) != Some(&self.own_round1.content)
        {
            return Err(FrostError::Invalid("ceremony or own contribution changed"));
        }
        envelope(
            &self.keys,
            &self.binding,
            DkgMessage::Agreement {
                transcript: state.transcript()?,
            },
        )
    }

    /// Consumes round-one secrets only after every roster member signed the same transcript.
    pub fn round2(self, state: &DkgState) -> Result<(DkgRound2, Vec<Event>), FrostError> {
        self.agreement(state)?;
        let transcript = state.agreed_transcript()?;
        let round1 = round1_packages(state, self.id)?;
        let (secret, packages) = crypto(frost::keys::dkg::part2(self.secret.clone(), &round1))?;
        let mut events = Vec::new();
        for member in &state.roster {
            if member.participant_id == self.id {
                continue;
            }
            let recipient = nostr::PublicKey::from_hex(&member.admin_pubkey)
                .map_err(|_| FrostError::Invalid("invalid recipient"))?;
            let package = packages
                .get(&identifier(member.participant_id)?)
                .ok_or(FrostError::Invalid("missing private contribution"))?
                .clone();
            let plaintext = zeroize::Zeroizing::new(serde_json::to_string(&PrivateRound2 {
                binding: self.binding.clone(),
                sender: self.id,
                recipient: member.participant_id,
                transcript: transcript.clone(),
                package,
            })?);
            let ciphertext = nip44::encrypt(
                self.keys.secret_key(),
                &recipient,
                plaintext.as_bytes(),
                nip44::Version::V2,
            )
            .map_err(|_| FrostError::Invalid("cannot encrypt private contribution"))?;
            events.push(envelope(
                &self.keys,
                &self.binding,
                DkgMessage::Round2 {
                    recipient: member.participant_id,
                    ciphertext,
                },
            )?);
        }
        Ok((
            DkgRound2 {
                keys: self.keys.clone(),
                id: self.id,
                binding: self.binding.clone(),
                transcript,
                secret,
                round1,
            },
            events,
        ))
    }
}

pub struct DkgRound2 {
    keys: Keys,
    id: u16,
    binding: Binding,
    transcript: String,
    secret: frost::keys::dkg::round2::SecretPackage,
    round1: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
}
impl Drop for DkgRound2 {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl DkgRound2 {
    pub fn finish(self, state: &DkgState) -> Result<(Participant, Event), FrostError> {
        if state.binding != self.binding || state.agreed_transcript()? != self.transcript {
            return Err(FrostError::Invalid("ceremony changed"));
        }
        let mut received = BTreeMap::new();
        for member in &state.roster {
            if member.participant_id == self.id {
                continue;
            }
            let event = state
                .round2
                .get(&format!("{}:{}", member.participant_id, self.id))
                .ok_or(FrostError::Invalid("missing confidential contribution"))?;
            let (sender, payload) = state.parse(event)?;
            let ciphertext = match payload.message {
                DkgMessage::Round2 {
                    recipient,
                    ciphertext,
                } if recipient == self.id && sender == member.participant_id => ciphertext,
                _ => return Err(FrostError::Invalid("invalid confidential envelope")),
            };
            let plaintext = zeroize::Zeroizing::new(
                nip44::decrypt(self.keys.secret_key(), &event.pubkey, ciphertext).map_err(
                    |_| FrostError::Invalid("cannot authenticate confidential contribution"),
                )?,
            );
            let private: PrivateRound2 = serde_json::from_str(&plaintext)?;
            if private.binding != self.binding
                || private.sender != sender
                || private.recipient != self.id
                || private.transcript != self.transcript
            {
                return Err(FrostError::Invalid("private contribution binding differs"));
            }
            received.insert(identifier(sender)?, private.package);
        }
        let (key, public) = crypto(frost::keys::dkg::part3(
            &self.secret,
            &self.round1,
            &received,
        ))?;
        let confirmation = envelope(
            &self.keys,
            &self.binding,
            DkgMessage::Confirmation {
                transcript: self.transcript.clone(),
                public_package: public.clone(),
            },
        )?;
        Ok((
            Participant {
                key,
                public,
                binding: self.binding.clone(),
                admin_pubkey: self.keys.public_key().to_hex(),
                id: self.id,
            },
            confirmation,
        ))
    }
}

pub struct Participant {
    key: frost::keys::KeyPackage,
    public: frost::keys::PublicKeyPackage,
    binding: Binding,
    admin_pubkey: String,
    id: u16,
}
impl Drop for Participant {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Participant {
    /// Only the long-lived share is exportable for the authenticated encrypted
    /// backup path. This never contains an approval, nonce or DKG secret.
    pub fn export_for_encrypted_backup(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, FrostError> {
        Ok(zeroize::Zeroizing::new(crypto(self.key.serialize())?))
    }

    pub fn restore(
        key_bytes: &[u8],
        admin_pubkey: &str,
        dkg: &DkgState,
    ) -> Result<Self, FrostError> {
        let public = dkg.confirmed_public_package()?.clone();
        let key = crypto(frost::keys::KeyPackage::deserialize(key_bytes))?;
        let member = dkg
            .roster
            .iter()
            .find(|m| m.admin_pubkey == admin_pubkey)
            .ok_or(FrostError::Forbidden)?;
        let id = member.participant_id;
        if *key.identifier() != identifier(id)?
            || key.verifying_key() != public.verifying_key()
            || public.verifying_shares().get(key.identifier()) != Some(key.verifying_share())
            || *key.min_signers() != dkg.threshold
        {
            return Err(FrostError::Invalid("recovered share binding differs"));
        }
        Ok(Self {
            key,
            public,
            binding: dkg.binding.clone(),
            admin_pubkey: admin_pubkey.into(),
            id,
        })
    }

    /// Call only after displaying/approving the complete event and signer set.
    pub fn approve(
        &self,
        state: &SigningState,
        dkg: &DkgState,
    ) -> Result<(Approval, frost::round1::SigningCommitments), FrostError> {
        let binding = &state.binding;
        if binding.protocol != PROTOCOL
            || binding.tenant_id != self.binding.tenant_id
            || binding.group_id != self.binding.group_id
            || binding.key_version != self.binding.key_version
            || binding.roster_version != self.binding.roster_version
            || binding.roster_hash != self.binding.roster_hash
            || state.dkg_session_id != self.binding.session_id
            || state.public_package != self.public
            || dkg.confirmed_public_package()? != &self.public
            || state.aborted
        {
            return Err(FrostError::Invalid("signing identity binding differs"));
        }
        let validated = SigningState::new(
            binding.clone(),
            dkg,
            state.event.clone(),
            state.signers.clone(),
        )?;
        if validated.event_id != state.event_id
            || !state
                .signers
                .iter()
                .any(|m| m.participant_id == self.id && m.admin_pubkey == self.admin_pubkey)
        {
            return Err(FrostError::Invalid("event or signer set differs"));
        }
        if state.commitments.contains_key(&self.id) {
            return Err(FrostError::Invalid("lost approval; abort session"));
        }
        let (nonces, commitment) =
            frost::round1::commit(self.key.signing_share(), &mut rand::rngs::OsRng);
        Ok((
            Approval {
                nonces,
                commitment,
                id: self.id,
                proposal: state.proposal_digest()?,
            },
            commitment,
        ))
    }
}

pub struct Approval {
    nonces: frost::round1::SigningNonces,
    commitment: frost::round1::SigningCommitments,
    id: u16,
    proposal: String,
}

impl Drop for Approval {
    fn drop(&mut self) {
        self.nonces.zeroize();
    }
}

impl Approval {
    /// Consumed on every attempt, including errors. Never regenerate a partial
    /// on retry: resend the already-produced public partial or abort.
    pub fn sign(
        self,
        participant: &Participant,
        state: &SigningState,
    ) -> Result<frost::round2::SignatureShare, FrostError> {
        if self.id != participant.id
            || self.proposal != state.proposal_digest()?
            || state.commitments.get(&self.id) != Some(&self.commitment)
        {
            return Err(FrostError::Invalid("approval or commitment changed"));
        }
        crypto(frost::round2::sign(
            &state.signing_package()?,
            &self.nonces,
            &participant.key,
        ))
    }
}
