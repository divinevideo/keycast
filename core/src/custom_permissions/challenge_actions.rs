//! Bounded signing-family validation for Divine challenge v1 and contest curation.
//! Signed consumers retain responsibility for organizer/entrant authority and lifecycle replay.

mod snapshot;
use super::PermissionDisplay;
use crate::{
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Checksum};
use nostr_sdk::{Event, PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use unicode_segmentation::UnicodeSegmentation;

const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const DAY: u64 = 86_400;
pub struct ChallengeActions;

#[async_trait]
impl CustomPermission for ChallengeActions {
    fn from_permission(p: &Permission) -> Result<Box<dyn CustomPermission>, PermissionError> {
        if !p.config.0.as_object().is_some_and(|o| o.is_empty()) {
            return Err(PermissionError::InvalidConfig(
                "challenge_actions requires an empty object".into(),
            ));
        }
        Ok(Box::new(Self))
    }
    fn identifier(&self) -> &'static str {
        "challenge_actions"
    }
    fn can_sign(&self, e: &UnsignedEvent) -> bool {
        // Account for the complete eventual signed record, independent of any caller ID.
        #[derive(Serialize)]
        struct SignedTemplate<'a> {
            id: &'a str,
            sig: &'a str,
            pubkey: &'a str,
            created_at: u64,
            kind: u16,
            tags: &'a nostr_sdk::Tags,
            content: &'a str,
        }
        let id = "0".repeat(64);
        let sig = "0".repeat(128);
        let pubkey = e.pubkey.to_hex();
        let template = SignedTemplate {
            id: &id,
            sig: &sig,
            pubkey: &pubkey,
            created_at: e.created_at.as_secs(),
            kind: e.kind.as_u16(),
            tags: &e.tags,
            content: &e.content,
        };
        if check_size(&template).is_none() {
            return false;
        }
        let wire = Wire {
            id: "0".repeat(64),
            sig: "0".repeat(128),
            pubkey: e.pubkey.to_hex(),
            kind: e.kind.as_u16(),
            created_at: e.created_at.as_secs(),
            tags: e.tags.iter().map(|t| t.as_slice().to_vec()).collect(),
            content: e.content.clone(),
        };
        check_size(&wire).is_some() && validate(&wire).is_some()
    }
    fn can_sign_creator_binding(&self, _: &[u8]) -> bool {
        false
    }
    fn can_encrypt(&self, _: &str, _: &PublicKey, _: &PublicKey) -> bool {
        false
    }
    fn can_decrypt(&self, _: &str, _: &PublicKey, _: &PublicKey) -> bool {
        false
    }
    fn display(&self) -> PermissionDisplay {
        PermissionDisplay { icon:"🏆", title:"Challenges and contest curation", description:"Create and manage challenges, enter and withdraw entries, announce results, and curate contests. No private-message access.".into() }
    }
}

#[derive(Serialize, Deserialize)]
struct Wire {
    id: String,
    pubkey: String,
    sig: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}
fn valid(condition: bool) -> Option<()> {
    condition.then_some(())
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn tags<'a>(e: &'a Wire, name: &'a str) -> impl Iterator<Item = &'a Vec<String>> {
    e.tags
        .iter()
        .filter(move |t| t.first().is_some_and(|n| n == name))
}
fn one<'a>(e: &'a Wire, name: &str) -> Option<&'a str> {
    let mut found = e
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|n| n == name));
    let value = found.next()?.get(1)?;
    valid(found.next().is_none())?;
    Some(value)
}
fn optional<'a>(e: &'a Wire, name: &str) -> Option<Option<&'a str>> {
    if e.tags.iter().any(|t| t.first().is_some_and(|n| n == name)) {
        one(e, name).map(Some)
    } else {
        Some(None)
    }
}
fn decimal(value: &str) -> Option<u64> {
    valid(
        value == "0"
            || (value.starts_with(|c: char| ('1'..='9').contains(&c))
                && value.bytes().all(|c| c.is_ascii_digit())),
    )?;
    value.parse::<u64>().ok().filter(|v| *v <= MAX_SAFE_INTEGER)
}
fn check_size(e: &impl Serialize) -> Option<()> {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if b.len() > MAX_EVENT_BYTES - self.0 {
                return Err(std::io::Error::other("size"));
            }
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(0), e).ok()
}
fn title(value: &str, max: usize) -> Option<()> {
    fn whitespace(c: char) -> bool {
        matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
    }
    valid(
        !value.trim_matches(whitespace).is_empty()
            && value.graphemes(true).take(max + 1).count() <= max,
    )
}
const ICU_COMPATIBILITY_NAMES: &[&str] = &[
    "ACT",
    "AET",
    "AGT",
    "ART",
    "AST",
    "BET",
    "BST",
    "CAT",
    "CNT",
    "CST",
    "CTT",
    "Canada/East-Saskatchewan",
    "EAT",
    "ECT",
    "IET",
    "IST",
    "JST",
    "MIT",
    "NET",
    "NST",
    "PLT",
    "PNT",
    "PRT",
    "PST",
    "SST",
    "SystemV/AST4",
    "SystemV/AST4ADT",
    "SystemV/CST6",
    "SystemV/CST6CDT",
    "SystemV/EST5",
    "SystemV/EST5EDT",
    "SystemV/HST10",
    "SystemV/MST7",
    "SystemV/MST7MDT",
    "SystemV/PST8",
    "SystemV/PST8PDT",
    "SystemV/YST9",
    "SystemV/YST9YDT",
    "US/Pacific-New",
    "VST",
];

fn check_timezone(value: &str) -> Option<()> {
    valid(
        !value.is_empty()
            && !value.starts_with(['+', '-'])
            && (chrono_tz::TZ_VARIANTS
                .iter()
                .any(|tz| tz.name().eq_ignore_ascii_case(value))
                || ICU_COMPATIBILITY_NAMES
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(value))),
    )
}
fn check_relay(value: &str) -> Option<()> {
    let u = nostr_sdk::Url::parse(value).ok()?;
    valid(
        matches!(u.scheme(), "ws" | "wss")
            && u.host_str().is_some_and(|s| !s.is_empty())
            && u.username().is_empty()
            && u.password().is_none_or(str::is_empty)
            && u.fragment().is_none_or(str::is_empty),
    )?;
    // URL/idna enforce nontransitional Bidi and joiner validation. UTS #46
    // criterion 4 additionally rejects an ACE-decoded label starting with xn--
    // when CheckHyphens=false, as required by the canonical Unicode 17 profile.
    for label in u.host_str()?.split('.') {
        if let Some(encoded) = label.strip_prefix("xn--") {
            let decoded = idna::punycode::decode_to_string(encoded)?;
            valid(!decoded.to_ascii_lowercase().starts_with("xn--"))?;
        }
    }
    Some(())
}

struct Definition {
    start: u64,
    end: u64,
    active: bool,
}
fn definition(e: &Wire) -> Option<Definition> {
    valid(e.kind == 31923 && action(e)? == "definition" && e.tags.iter().all(|t| !t.is_empty()))?;
    valid(!one(e, "d")?.is_empty() && e.content.len() <= 8192)?;
    title(one(e, "title")?, 120)?;
    let (start, end) = (decimal(one(e, "start")?)?, decimal(one(e, "end")?)?);
    valid(end > start && end - start <= 90 * DAY)?;
    let tz = one(e, "start_tzid")?;
    check_timezone(tz)?;
    check_timezone(optional(e, "end_tzid")?.unwrap_or(tz))?;
    let days: HashSet<_> = tags(e, "D").map(|t| t.get(1).map(String::as_str)).collect();
    for day in start / DAY..=(end - 1) / DAY {
        valid(days.contains(&Some(day.to_string().as_str())))?;
    }
    for day in days {
        let n = decimal(day?)?;
        valid(n >= start / DAY && n <= (end - 1) / DAY)?;
    }
    let relays: Vec<_> = tags(e, "challenge_relay").collect();
    valid((1..=4).contains(&relays.len()))?;
    for relay in relays {
        check_relay(relay.get(1)?)?;
    }
    let status = one(e, "challenge_status")?;
    valid(matches!(status, "active" | "cancelled"))?;
    Some(Definition {
        start,
        end,
        active: status == "active",
    })
}
fn action(e: &Wire) -> Option<&str> {
    let mut markers = tags(e, "challenge");
    let marker = markers.next()?;
    valid(
        markers.next().is_none()
            && marker.len() == 3
            && marker[1] == "1"
            && ["definition", "entry", "withdraw", "result"].contains(&marker[2].as_str())
            && tags(e, "t").any(|t| t.get(1).is_some_and(|v| v == "divine-challenge")),
    )?;
    Some(&marker[2])
}
fn coordinate(value: &str, kinds: &[&str]) -> Option<()> {
    let mut parts = value.splitn(3, ':');
    valid(kinds.contains(&parts.next()?) && hex(parts.next()?))?;
    valid(!parts.next()?.is_empty())
}
fn snapshot(e: &Wire, name: &str) -> Option<Wire> {
    let mut v = snapshot::signed_fields(one(e, name)?).ok()?;
    valid(
        hex(v["id"].as_str()?)
            && hex(v["pubkey"].as_str()?)
            && v["sig"].as_str()?.len() == 128
            && v["sig"]
                .as_str()?
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
    )?;
    for field in ["created_at", "kind"] {
        let n = v[field].as_f64()?;
        valid(n >= 0.0 && n <= MAX_SAFE_INTEGER as f64 && n.fract() == 0.0)?;
        v[field] = Value::from(n as u64);
    }
    let wire: Wire = serde_json::from_value(v.clone()).ok()?;
    check_size(&wire)?;
    // Fresh deserialization excludes unsigned verification caches; SDK verifies ID and signature.
    if let Ok(event) = serde_json::from_value::<Event>(v) {
        event.verify().ok()?;
    } else {
        // NIP-01 permits empty ordinary tags in video snapshots; the SDK's
        // higher-level Tag parser cannot represent them. Preserve the wire
        // preimage and verify with the SDK's Schnorr primitives in that case.
        valid(wire.tags.iter().any(Vec::is_empty))?;
        use nostr_sdk::secp256k1::{schnorr::Signature, Message};
        use sha2::{Digest, Sha256};
        use std::str::FromStr;
        let preimage = serde_json::to_vec(&(
            0,
            &wire.pubkey,
            wire.created_at,
            wire.kind,
            &wire.tags,
            &wire.content,
        ))
        .ok()?;
        let digest: [u8; 32] = Sha256::digest(preimage).into();
        valid(hex::encode(digest) == wire.id)?;
        let key = PublicKey::from_hex(&wire.pubkey).ok()?.xonly().ok()?;
        let signature = Signature::from_str(&wire.sig).ok()?;
        nostr_sdk::SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(digest), &key)
            .ok()?;
    }
    Some(wire)
}
fn definition_snapshot(e: &Wire, root: &str) -> Option<Definition> {
    let signed = snapshot(e, "challenge_snapshot")?;
    let def = definition(&signed)?;
    valid(
        root == format!("31923:{}:{}", signed.pubkey, one(&signed, "d")?)
            && one(e, "a")? == root
            && one(e, "k")? == "31923"
            && one(e, "p")? == signed.pubkey
            && one(e, "e")? == signed.id
            && tags(e, "i").next().is_none(),
    )?;
    Some(def)
}
struct Nip19Checksum;
impl Checksum for Nip19Checksum {
    type MidstateRepr = <Bech32 as Checksum>::MidstateRepr;
    const CODE_LENGTH: usize = 5000;
    const CHECKSUM_LENGTH: usize = Bech32::CHECKSUM_LENGTH;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = Bech32::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = Bech32::TARGET_RESIDUE;
}
fn cited_id(value: &str) -> Option<String> {
    // The TypeScript NIP-19 decoder's explicit length limit is 5000.
    if value.len() > 5000 {
        return None;
    }
    let decoded = CheckedHrpstring::new::<Nip19Checksum>(value).ok()?;
    decoded.validate_segwit_padding().ok()?;
    let data: Vec<u8> = decoded.byte_iter().collect();
    match decoded.hrp().as_str().to_ascii_lowercase().as_str() {
        "note" => Some(hex::encode(data)),
        "nevent" => {
            let mut first = [None; 4];
            let mut rest = data.as_slice();
            while !rest.is_empty() {
                if rest.len() < 2 {
                    return None;
                }
                let kind = usize::from(rest[0]);
                let len = usize::from(rest[1]);
                let value = rest.get(2..2 + len)?;
                if kind < 4 && first[kind].is_none() {
                    first[kind] = Some(value);
                }
                rest = &rest[2 + len..];
            }
            let id = first[0]?;
            if id.len() != 32
                || first[2].is_some_and(|v| v.len() != 32)
                || first[3].is_some_and(|v| v.len() != 4)
            {
                return None;
            }
            Some(hex::encode(id))
        }
        _ => None,
    }
}
fn citation(e: &Wire, id: &str) -> Option<()> {
    static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i-u)nostr:((?:note|nevent)1[023456789acdefghjklmnpqrstuvwxyz]+)")
            .expect("constant citation pattern")
    });
    valid(
        tags(e, "q").any(|t| t.get(1).is_some_and(|v| v == id))
            && PATTERN
                .captures_iter(&e.content)
                .any(|m| cited_id(&m[1]).is_some_and(|v| v == id)),
    )
}
fn validate(e: &Wire) -> Option<()> {
    valid(e.created_at <= MAX_SAFE_INTEGER && e.tags.iter().all(|t| !t.is_empty()))?;
    if e.kind == 1985 {
        return curation(e);
    }
    let action = action(e)?;
    if action == "definition" {
        definition(e)?;
        return Some(());
    }
    valid(e.kind == 1111)?;
    let root = one(e, "A")?;
    coordinate(root, &["31923"])?;
    let root_key = root.split(':').nth(1)?;
    valid(
        one(e, "K")? == "31923"
            && one(e, "P")? == root_key
            && tags(e, "E").next().is_none()
            && tags(e, "I").next().is_none(),
    )?;
    match action {
        "withdraw" => valid(
            hex(one(e, "e")?)
                && one(e, "k")? == "1111"
                && hex(one(e, "p")?)
                && tags(e, "a").next().is_none()
                && tags(e, "i").next().is_none(),
        ),
        "entry" => {
            let def = definition_snapshot(e, root)?;
            let video = snapshot(e, "video_snapshot")?;
            valid(
                matches!(video.kind, 21 | 22 | 34235 | 34236)
                    && def.active
                    && e.created_at >= def.start
                    && e.created_at < def.end,
            )?;
            if video.kind >= 30000 {
                valid(!one(&video, "d")?.is_empty())?;
            }
            citation(e, &video.id)
        }
        "result" => {
            let def = definition_snapshot(e, root)?;
            valid(def.active && e.created_at >= def.end)?;
            let winners: Vec<_> = tags(e, "winner").collect();
            valid((1..=20).contains(&winners.len()))?;
            let mut ids = HashSet::new();
            for w in winners {
                valid(w.len() == 3 && hex(&w[1]) && ids.insert(&w[1]))?;
                title(&w[2], 80)?;
                citation(e, &w[1])?;
            }
            Some(())
        }
        _ => None,
    }
}
fn curation(e: &Wire) -> Option<()> {
    valid(
        e.content.is_empty()
            && e.tags.iter().all(|t| {
                t.first()
                    .is_some_and(|n| ["L", "l", "e", "a"].contains(&n.as_str()))
            }),
    )?;
    let namespace = one(e, "L")?;
    valid(
        namespace
            .strip_prefix("video.divine.contest.")
            .is_some_and(|suffix| !suffix.is_empty()),
    )?;
    let l = tags(e, "L").next()?;
    let label = tags(e, "l").next()?;
    let target = tags(e, "e").next()?;
    valid(
        l.len() == 2
            && one(e, "l").is_some()
            && label.len() == 3
            && ["include", "exclude"].contains(&label[1].as_str())
            && label[2] == namespace
            && one(e, "e").is_some()
            && target.len() == 3
            && hex(&target[1]),
    )?;
    valid(target[2].encode_utf16().count() <= 2048)?;
    check_relay(&target[2])?;
    if let Some(address) = optional(e, "a")? {
        valid(tags(e, "a").next()?.len() == 2)?;
        // Addressable-video identifiers may be empty and use the consumer's UTF-16 budget.
        let mut parts = address.splitn(3, ':');
        valid(["34235", "34236"].contains(&parts.next()?) && hex(parts.next()?))?;
        valid(parts.next()?.encode_utf16().count() <= 1024)?;
    }
    Some(())
}
