use super::{crypto, FrostError};
use base64::Engine;
use frost_secp256k1_tr as frost;
use nostr::{Event, EventId, PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PROTOCOL: &str = "keycast-frost-v1/secp256k1-tr-2.2.0/untweaked";
pub const MESSAGE_KIND: u16 = 21146;
pub const MAX_PARTICIPANTS: usize = 32;

// JSON object keys are strings, including when an enum's buffered serde content
// is decoded from SQLx JSONB. Parse participant identifiers explicitly.
mod participant_map {
    use super::*;
    pub fn serialize<T: Serialize, S: serde::Serializer>(
        map: &BTreeMap<u16, T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        map.iter()
            .map(|(id, value)| (id.to_string(), value))
            .collect::<BTreeMap<_, _>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<u16, T>, D::Error> {
        BTreeMap::<String, T>::deserialize(deserializer)?
            .into_iter()
            .map(|(id, value)| Ok((id.parse::<u16>().map_err(serde::de::Error::custom)?, value)))
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub admin_pubkey: String,
    pub participant_id: u16,
    pub version: i64,
    pub installation_epoch: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub protocol: String,
    pub tenant_id: i64,
    pub group_id: i32,
    pub session_id: String,
    pub key_version: i32,
    pub roster_version: i32,
    pub roster_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "round", rename_all = "snake_case", deny_unknown_fields)]
pub enum DkgMessage {
    Round1 {
        package: frost::keys::dkg::round1::Package,
    },
    Agreement {
        transcript: String,
    },
    Round2 {
        recipient: u16,
        ciphertext: String,
    },
    Confirmation {
        transcript: String,
        public_package: frost::keys::PublicKeyPackage,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgPayload {
    pub binding: Binding,
    pub message: DkgMessage,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRound2 {
    pub binding: Binding,
    pub sender: u16,
    pub recipient: u16,
    pub transcript: String,
    pub package: frost::keys::dkg::round2::Package,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgState {
    pub binding: Binding,
    pub threshold: u16,
    pub roster: Vec<Member>,
    #[serde(with = "participant_map")]
    pub round1: BTreeMap<u16, Event>,
    #[serde(with = "participant_map")]
    pub agreements: BTreeMap<u16, Event>,
    pub round2: BTreeMap<String, Event>,
    #[serde(with = "participant_map")]
    pub confirmations: BTreeMap<u16, Event>,
    pub public_package: Option<frost::keys::PublicKeyPackage>,
    pub aborted: bool,
}

pub fn digest<T: Serialize>(value: &T) -> Result<String, FrostError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

pub(crate) fn identifier(id: u16) -> Result<frost::Identifier, FrostError> {
    crypto(id.try_into())
}

impl DkgState {
    pub fn new(
        mut binding: Binding,
        threshold: u16,
        roster: Vec<Member>,
    ) -> Result<Self, FrostError> {
        if threshold < 2 || usize::from(threshold) > roster.len() || roster.len() > MAX_PARTICIPANTS
        {
            return Err(FrostError::Invalid(
                "threshold must be 2..=roster size, at most 32 participants",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        for member in &roster {
            identifier(member.participant_id)?;
            PublicKey::from_hex(&member.admin_pubkey)
                .map_err(|_| FrostError::Invalid("invalid admin identity"))?;
            if !ids.insert(member.participant_id) || !keys.insert(&member.admin_pubkey) {
                return Err(FrostError::Invalid("duplicate participant"));
            }
        }
        binding.protocol = PROTOCOL.into();
        binding.roster_hash = digest(&(threshold, &roster))?;
        Ok(Self {
            binding,
            threshold,
            roster,
            round1: BTreeMap::new(),
            agreements: BTreeMap::new(),
            round2: BTreeMap::new(),
            confirmations: BTreeMap::new(),
            public_package: None,
            aborted: false,
        })
    }

    pub fn member(&self, id: u16) -> Result<&Member, FrostError> {
        self.roster
            .iter()
            .find(|m| m.participant_id == id)
            .ok_or(FrostError::Forbidden)
    }

    pub fn parse(&self, event: &Event) -> Result<(u16, DkgPayload), FrostError> {
        if self.binding.roster_hash != digest(&(self.threshold, &self.roster))? {
            return Err(FrostError::Invalid("roster descriptor changed"));
        }
        event
            .verify()
            .map_err(|_| FrostError::Invalid("invalid authenticated envelope"))?;
        if event.kind.as_u16() != MESSAGE_KIND || event.content.len() > 262_144 {
            return Err(FrostError::Invalid("invalid envelope kind or length"));
        }
        let member = self
            .roster
            .iter()
            .find(|m| m.admin_pubkey == event.pubkey.to_hex())
            .ok_or(FrostError::Forbidden)?;
        let payload: DkgPayload = serde_json::from_str(&event.content)?;
        if payload.binding != self.binding || self.binding.protocol != PROTOCOL {
            return Err(FrostError::Invalid("envelope binding differs"));
        }
        Ok((member.participant_id, payload))
    }

    pub fn transcript(&self) -> Result<String, FrostError> {
        if self.round1.len() != self.roster.len() {
            return Err(FrostError::Invalid("missing round-one participant"));
        }
        let mut packages = BTreeMap::new();
        for (id, event) in &self.round1 {
            let (sender, payload) = self.parse(event)?;
            if sender != *id {
                return Err(FrostError::Invalid("sender mismatch"));
            }
            match payload.message {
                DkgMessage::Round1 { package } => {
                    packages.insert(*id, package);
                }
                _ => return Err(FrostError::Invalid("invalid round-one transcript")),
            }
        }
        digest(&(&self.binding, packages))
    }

    /// Clients verify every signed acknowledgement before revealing round two.
    pub fn agreed_transcript(&self) -> Result<String, FrostError> {
        if self.aborted {
            return Err(FrostError::Aborted);
        }
        let transcript = self.transcript()?;
        if self.agreements.len() != self.roster.len() {
            return Err(FrostError::Invalid("missing transcript agreement"));
        }
        for (id, event) in &self.agreements {
            let (sender, payload) = self.parse(event)?;
            if sender != *id
                || !matches!(payload.message, DkgMessage::Agreement { transcript: ref t } if t == &transcript)
            {
                return Err(FrostError::Invalid("transcript disagreement"));
            }
        }
        Ok(transcript)
    }

    pub fn receive(&mut self, event: Event) -> Result<(), FrostError> {
        if self.aborted {
            return Err(FrostError::Aborted);
        }
        let (sender, payload) = self.parse(&event)?;
        let result = self.receive_valid(sender, payload.message, event);
        if result.is_err() {
            self.aborted = true;
        }
        result
    }

    fn receive_valid(
        &mut self,
        sender: u16,
        message: DkgMessage,
        event: Event,
    ) -> Result<(), FrostError> {
        match message {
            DkgMessage::Round1 { .. } => insert_message(&mut self.round1, sender, event),
            DkgMessage::Agreement { transcript } => {
                if transcript != self.transcript()? {
                    return Err(FrostError::Invalid("transcript disagreement"));
                }
                insert_message(&mut self.agreements, sender, event)
            }
            DkgMessage::Round2 {
                recipient,
                ref ciphertext,
            } => {
                self.agreed_transcript()?;
                self.member(recipient)?;
                if recipient == sender || ciphertext.len() < 100 || ciphertext.len() > 131_072 {
                    return Err(FrostError::Invalid("invalid confidential delivery"));
                }
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(ciphertext)
                    .map_err(|_| FrostError::Invalid("round two requires NIP-44 v2 ciphertext"))?;
                if raw.len() < 99 || raw.first() != Some(&2) {
                    return Err(FrostError::Invalid(
                        "round two requires NIP-44 v2 ciphertext",
                    ));
                }
                insert_message(&mut self.round2, format!("{sender}:{recipient}"), event)
            }
            DkgMessage::Confirmation {
                transcript,
                public_package,
            } => {
                if transcript != self.agreed_transcript()?
                    || self.round2.len() != self.roster.len() * (self.roster.len() - 1)
                {
                    return Err(FrostError::Invalid("incomplete DKG delivery"));
                }
                let expected: std::collections::BTreeSet<_> = self
                    .roster
                    .iter()
                    .map(|m| identifier(m.participant_id))
                    .collect::<Result<_, _>>()?;
                if public_package
                    .verifying_shares()
                    .keys()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    != expected
                {
                    return Err(FrostError::Invalid("public package roster differs"));
                }
                if let Some(first) = self.confirmations.values().next() {
                    let (_, prior) = self.parse(first)?;
                    if !matches!(prior.message, DkgMessage::Confirmation { public_package: ref p, .. } if p == &public_package)
                    {
                        return Err(FrostError::Invalid("public-key disagreement"));
                    }
                }
                insert_message(&mut self.confirmations, sender, event)?;
                if self.confirmations.len() == self.roster.len() {
                    self.public_package = Some(public_package);
                }
                Ok(())
            }
        }
    }

    pub fn confirmed_public_package(&self) -> Result<&frost::keys::PublicKeyPackage, FrostError> {
        self.agreed_transcript()?;
        let package = self
            .public_package
            .as_ref()
            .ok_or(FrostError::Invalid("DKG not completed"))?;
        if self.confirmations.len() != self.roster.len() {
            return Err(FrostError::Invalid("missing final confirmation"));
        }
        for (id, event) in &self.confirmations {
            let (sender, payload) = self.parse(event)?;
            if sender != *id
                || !matches!(payload.message, DkgMessage::Confirmation { public_package: ref p, ref transcript } if p == package && transcript == &self.transcript()?)
            {
                return Err(FrostError::Invalid("invalid final confirmation"));
            }
        }
        Ok(package)
    }
}

fn insert_message<K: Ord>(
    map: &mut BTreeMap<K, Event>,
    key: K,
    event: Event,
) -> Result<(), FrostError> {
    if let Some(prior) = map.get(&key) {
        if prior.content != event.content {
            return Err(FrostError::Invalid("conflicting duplicate"));
        }
    } else {
        map.insert(key, event);
    }
    Ok(())
}

pub fn group_pubkey(package: &frost::keys::PublicKeyPackage) -> Result<PublicKey, FrostError> {
    let bytes = crypto(package.verifying_key().serialize())?;
    PublicKey::from_slice(&bytes[1..]).map_err(|_| FrostError::Invalid("invalid group public key"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningState {
    pub binding: Binding,
    pub dkg_session_id: String,
    pub event: UnsignedEvent,
    pub event_id: EventId,
    pub signers: Vec<Member>,
    pub public_package: frost::keys::PublicKeyPackage,
    #[serde(with = "participant_map")]
    pub commitments: BTreeMap<u16, frost::round1::SigningCommitments>,
    #[serde(with = "participant_map")]
    pub partials: BTreeMap<u16, frost::round2::SignatureShare>,
    pub result: Option<Event>,
    pub aborted: bool,
}

impl SigningState {
    pub fn new(
        binding: Binding,
        dkg: &DkgState,
        mut event: UnsignedEvent,
        signers: Vec<Member>,
    ) -> Result<Self, FrostError> {
        let package = dkg.confirmed_public_package()?.clone();
        if signers.len() < usize::from(dkg.threshold)
            || signers.len() > dkg.roster.len()
            || event.pubkey != group_pubkey(&package)?
        {
            return Err(FrostError::Invalid("invalid quorum or event author"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for signer in &signers {
            if dkg.member(signer.participant_id)?.admin_pubkey != signer.admin_pubkey
                || !seen.insert(signer.participant_id)
            {
                return Err(FrostError::Invalid("invalid signer set"));
            }
        }
        let event_id = EventId::new(
            &event.pubkey,
            &event.created_at,
            &event.kind,
            &event.tags,
            &event.content,
        );
        if event.id.is_some_and(|id| id != event_id) {
            return Err(FrostError::Invalid("event id differs from event bytes"));
        }
        event.id = Some(event_id);
        Ok(Self {
            binding,
            dkg_session_id: dkg.binding.session_id.clone(),
            event,
            event_id,
            signers,
            public_package: package,
            commitments: BTreeMap::new(),
            partials: BTreeMap::new(),
            result: None,
            aborted: false,
        })
    }

    pub fn proposal_digest(&self) -> Result<String, FrostError> {
        digest(&(
            &self.binding,
            &self.dkg_session_id,
            &self.event,
            &self.signers,
            &self.public_package,
        ))
    }

    pub fn signing_package(&self) -> Result<frost::SigningPackage, FrostError> {
        if self.aborted {
            return Err(FrostError::Aborted);
        }
        if self.binding.protocol != PROTOCOL
            || self.event.id != Some(self.event_id)
            || self.event_id
                != EventId::new(
                    &self.event.pubkey,
                    &self.event.created_at,
                    &self.event.kind,
                    &self.event.tags,
                    &self.event.content,
                )
        {
            return Err(FrostError::Invalid(
                "event bytes differ from approved event id",
            ));
        }
        if self.commitments.len() != self.signers.len() {
            return Err(FrostError::Invalid("missing signer commitment"));
        }
        if self
            .signers
            .iter()
            .map(|m| m.participant_id)
            .collect::<std::collections::BTreeSet<_>>()
            != self.commitments.keys().copied().collect()
        {
            return Err(FrostError::Invalid("commitment signer set differs"));
        }
        let commitments = self
            .commitments
            .iter()
            .map(|(id, c)| Ok((identifier(*id)?, *c)))
            .collect::<Result<_, FrostError>>()?;
        Ok(frost::SigningPackage::new(
            commitments,
            self.event_id.as_bytes(),
        ))
    }

    pub fn add_partial(
        &mut self,
        id: u16,
        partial: frost::round2::SignatureShare,
    ) -> Result<(), FrostError> {
        if !self.signers.iter().any(|s| s.participant_id == id) {
            return Err(FrostError::Forbidden);
        }
        self.signing_package()?;
        if let Some(prior) = self.partials.get(&id) {
            if prior != &partial {
                self.aborted = true;
                return Err(FrostError::Invalid("conflicting partial signature"));
            }
            return Ok(());
        }
        self.partials.insert(id, partial);
        if self.partials.len() == self.signers.len() {
            let package = self.signing_package()?;
            let shares = self
                .partials
                .iter()
                .map(|(id, s)| Ok((identifier(*id)?, *s)))
                .collect::<Result<_, FrostError>>()?;
            let signature = match crypto(frost::aggregate(&package, &shares, &self.public_package))
            {
                Ok(s) => s,
                Err(e) => {
                    self.aborted = true;
                    return Err(e);
                }
            };
            let bytes = crypto(signature.serialize())?;
            let signature = nostr::secp256k1::schnorr::Signature::from_slice(&bytes)
                .map_err(|_| FrostError::Invalid("invalid BIP-340 signature"))?;
            let event = self
                .event
                .clone()
                .add_signature(signature)
                .map_err(|_| FrostError::Invalid("Nostr signature verification failed"))?;
            event
                .verify()
                .map_err(|_| FrostError::Invalid("Nostr event verification failed"))?;
            self.result = Some(event);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
// This public protocol enum owns its cryptographic wire payloads. It is never
// stored in a large collection; boxing would complicate native bridge callers.
#[allow(clippy::large_enum_variant)]
pub enum SigningMessage {
    Commitment {
        proposal_digest: String,
        commitment: frost::round1::SigningCommitments,
    },
    Partial {
        proposal_digest: String,
        partial: frost::round2::SignatureShare,
    },
    Abort,
}
