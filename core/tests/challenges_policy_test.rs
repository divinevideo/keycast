use chrono::Utc;
use keycast_core::{
    traits::CustomPermission,
    types::permission::{JsonConfig, Permission},
};
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde_json::{json, Value};

fn permission(config: Value) -> Permission {
    Permission {
        id: 0,
        identifier: "challenge_actions".into(),
        config: JsonConfig(config),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}
fn policy() -> Box<dyn CustomPermission> {
    permission(json!({}))
        .to_custom_permission()
        .expect("registered challenge permission")
}
fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/challenges/v1/events.json")).unwrap()
}
fn unsigned(mut value: Value) -> UnsignedEvent {
    value.as_object_mut().unwrap().remove("sig");
    value.as_object_mut().unwrap().remove("id");
    serde_json::from_value(value).unwrap()
}
fn fixture(name: &str) -> Value {
    fixtures()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()["event"]
        .clone()
}
#[test]
fn canonical_templates_and_relevant_invalid_fixtures() {
    let p = policy();
    for case in fixtures()["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        // Outer signatures and author identity are consumer responsibilities.
        let expected = case["expected"]["ok"] == true
            || matches!(
                name,
                "changed-signature"
                    | "changed-id"
                    | "mismatched-video-author"
                    | "unofficial-result"
            );
        if name == "empty-tag-revision" {
            assert!(serde_json::from_value::<UnsignedEvent>(case["event"].clone()).is_err());
            continue;
        }
        assert_eq!(
            p.can_sign(&unsigned(case["event"].clone())),
            expected,
            "{name}"
        );
    }
}
#[test]
fn strict_config_and_denied_operations() {
    for cfg in [
        json!(null),
        json!([]),
        json!(false),
        json!(""),
        json!({"organizers": []}),
    ] {
        assert!(permission(cfg).to_custom_permission().is_err());
    }
    let p = policy();
    let k = PublicKey::from_hex(&"11".repeat(32)).unwrap();
    assert_eq!(p.identifier(), "challenge_actions");
    assert!(!p.can_encrypt("test", &k, &k));
    assert!(!p.can_decrypt("test", &k, &k));
    assert!(!p.can_sign_creator_binding(b"test"));
    for kind in [0, 1, 4, 21, 22, 44, 1059, 22242, 27235, 34235, 34236] {
        let mut e = fixture("definition");
        e["kind"] = json!(kind);
        assert!(!p.can_sign(&unsigned(e)));
    }
    for kind in [31923, 1111, 1985] {
        let mut e = fixture("definition");
        e["kind"] = json!(kind);
        e["tags"] = json!([]);
        assert!(!p.can_sign(&unsigned(e)));
    }
}
#[test]
fn contest_include_exclude_and_closed_label_shape() {
    let p = policy();
    for action in ["include", "exclude"] {
        let mut e = fixture("definition");
        e["kind"] = json!(1985);
        e["content"] = json!("");
        e["tags"] = json!([
            ["L", "video.divine.contest.synthetic"],
            ["l", action, "video.divine.contest.synthetic"],
            ["e", "11".repeat(32), "wss://relay.example"]
        ]);
        assert!(p.can_sign(&unsigned(e.clone())));
        e["tags"]
            .as_array_mut()
            .unwrap()
            .push(json!(["a", format!("34235:{}:synthetic", "22".repeat(32))]));
        assert!(p.can_sign(&unsigned(e.clone())));
        for tag in [
            json!(["p", "22".repeat(32)]),
            json!(["L", "video.divine.contest.other"]),
            json!(["e", "11".repeat(32), "wss://relay.example"]),
            json!(["a", format!("34236:{}:second", "22".repeat(32))]),
        ] {
            let mut bad = e.clone();
            bad["tags"].as_array_mut().unwrap().push(tag);
            assert!(!p.can_sign(&unsigned(bad)));
        }
        for suffix in ["MixedCase", "synthetic:é/★"] {
            let mut other = e.clone();
            let ns = format!("video.divine.contest.{suffix}");
            other["tags"][0][1] = json!(ns);
            other["tags"][1][2] = json!(ns);
            assert!(p.can_sign(&unsigned(other)));
        }
        for value in ["", "video.divine.contest.", "other.synthetic"] {
            let mut bad = e.clone();
            bad["tags"][0][1] = json!(value);
            bad["tags"][1][2] = json!(value);
            assert!(!p.can_sign(&unsigned(bad)));
        }
        let mut bad = e.clone();
        bad["tags"][1][2] = json!("video.divine.contest.other");
        assert!(!p.can_sign(&unsigned(bad)));
        let mut bad = e.clone();
        bad["tags"][2][2] = json!("https://relay.example");
        assert!(!p.can_sign(&unsigned(bad)));
        let mut bad = e.clone();
        bad["content"] = json!("extra");
        assert!(!p.can_sign(&unsigned(bad)));
    }
}
#[test]
fn unsigned_pubkey_is_not_signer_authority() {
    let p = policy();
    for name in ["definition", "entry", "withdraw", "result"] {
        let mut e = fixture(name);
        e["pubkey"] = json!("11".repeat(32));
        assert!(p.can_sign(&unsigned(e)), "{name}");
    }
}
#[test]
fn duplicate_semantics_and_alternate_parents_fail() {
    let p = policy();
    for name in ["definition", "entry", "withdraw", "result"] {
        let e = fixture(name);
        for tag in e["tags"].as_array().unwrap() {
            if ["t", "D", "challenge_relay", "q", "winner"].contains(&tag[0].as_str().unwrap()) {
                continue;
            }
            let mut bad = e.clone();
            bad["tags"].as_array_mut().unwrap().push(tag.clone());
            assert!(!p.can_sign(&unsigned(bad)), "{name}: {tag}");
        }
    }
    for name in ["entry", "withdraw", "result"] {
        for tag in [
            json!(["E", "11".repeat(32)]),
            json!(["I", "external"]),
            json!(["i", "external"]),
        ] {
            let mut e = fixture(name);
            e["tags"].as_array_mut().unwrap().push(tag);
            assert!(!p.can_sign(&unsigned(e)));
        }
    }
}

const AUDITED_ICU_NAMES: &[&str] = &[
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

#[test]
fn complete_audited_timezone_set_and_case_variants() {
    assert_eq!(chrono_tz::TZ_VARIANTS.len(), 597);
    assert_eq!(AUDITED_ICU_NAMES.len(), 40);
    let p = policy();
    for name in chrono_tz::TZ_VARIANTS
        .iter()
        .map(|v| v.name())
        .chain(AUDITED_ICU_NAMES.iter().copied())
    {
        for spelling in [
            name.to_string(),
            name.to_ascii_lowercase(),
            name.to_ascii_uppercase(),
        ] {
            let mut e = fixture("definition");
            for tag in e["tags"].as_array_mut().unwrap() {
                if tag[0] == "start_tzid" {
                    tag[1] = json!(spelling);
                }
            }
            e["tags"]
                .as_array_mut()
                .unwrap()
                .push(json!(["end_tzid", spelling]));
            assert!(p.can_sign(&unsigned(e)), "{spelling}");
        }
    }
    for spelling in [
        "ACT0",
        "PST8",
        "SystemV/PST9PDT",
        "Factory",
        "Etc/Unknown",
        "GMT+01:00",
        "+01:00",
        "-12:00",
        "",
    ] {
        let mut e = fixture("definition");
        for tag in e["tags"].as_array_mut().unwrap() {
            if tag[0] == "start_tzid" {
                tag[1] = json!(spelling);
            }
        }
        assert!(!p.can_sign(&unsigned(e)), "{spelling}");
    }
}
fn independent_definition() -> Value {
    json!({"kind":31923,"created_at":20,"pubkey":"11".repeat(32),"content":"Synthetic prompt", "tags":[["challenge","1","definition"],["t","divine-challenge"],["t","ordinary-topic"],["d","independent:definition"],["title","Independent synthetic challenge"],["start","100"],["end","200"],["start_tzid","UTC"],["D","0"],["challenge_status","active"],["challenge_relay","wss://relay.example"]]})
}
#[test]
fn independently_assembled_definition_fields_and_url_edges() {
    let p = policy();
    assert!(p.can_sign(&unsigned(independent_definition())));
    for (name, value) in [
        ("start", "-1"),
        ("start", "01"),
        ("end", "100"),
        ("end", "9007199254740992"),
        ("d", ""),
        ("title", "\u{feff}"),
        ("D", "1"),
        ("challenge_status", "unknown"),
        ("challenge_relay", "https://relay.example"),
        ("challenge_relay", "wss://user:pass@relay.example"),
        ("challenge_relay", "wss://relay.example/#fragment"),
    ] {
        let mut e = independent_definition();
        for tag in e["tags"].as_array_mut().unwrap() {
            if tag[0] == name {
                tag[1] = json!(value);
            }
        }
        assert!(!p.can_sign(&unsigned(e)), "{name} {value}");
    }
    let mut e = independent_definition();
    e["tags"].as_array_mut().unwrap().retain(|t| t[0] != "t");
    assert!(!p.can_sign(&unsigned(e)));
    for (name, field) in [
        ("entry", "challenge_snapshot"),
        ("entry", "video_snapshot"),
        ("result", "challenge_snapshot"),
    ] {
        for invalid in ["null", "{}", "[]", "not JSON"] {
            let mut e = fixture(name);
            for t in e["tags"].as_array_mut().unwrap() {
                if t[0] == field {
                    t[1] = json!(invalid);
                }
            }
            assert!(!p.can_sign(&unsigned(e)));
        }
        let mut e = fixture(name);
        for t in e["tags"].as_array_mut().unwrap() {
            if t[0] == field {
                let mut snapshot: Value = serde_json::from_str(t[1].as_str().unwrap()).unwrap();
                snapshot["content"] = json!("tampered");
                snapshot["verified"] = json!(true);
                t[1] = json!(snapshot.to_string());
            }
        }
        assert!(!p.can_sign(&unsigned(e)));
    }
    let mut e = independent_definition();
    e["content"] = json!("x".repeat(70_000));
    assert!(!p.can_sign(&unsigned(e)));
}

#[test]
fn uts46_decoded_ace_prefix_is_rejected_in_unsigned_and_signed_snapshots() {
    use nostr_sdk::Keys;
    let p = policy();
    for relay in ["wss://xn--xn--a--gua.pt", "wss://xn--xn---epa"] {
        let mut def = independent_definition();
        for tag in def["tags"].as_array_mut().unwrap() {
            if tag[0] == "challenge_relay" {
                tag[1] = json!(relay);
            }
        }
        assert!(!p.can_sign(&unsigned(def.clone())), "unsigned {relay}");
        let keys = Keys::generate();
        def["pubkey"] = json!(keys.public_key().to_hex());
        let signed = unsigned(def).sign_with_keys(&keys).unwrap();
        let coordinate = format!(
            "31923:{}:independent:definition",
            keys.public_key().to_hex()
        );
        let mut entry = fixture("entry");
        entry["created_at"] = json!(150);
        for tag in entry["tags"].as_array_mut().unwrap() {
            match tag[0].as_str().unwrap() {
                "A" | "a" => tag[1] = json!(coordinate),
                "P" | "p" => tag[1] = json!(keys.public_key().to_hex()),
                "e" => tag[1] = json!(signed.id.to_hex()),
                "challenge_snapshot" => tag[1] = json!(serde_json::to_string(&signed).unwrap()),
                _ => {}
            }
        }
        assert!(!p.can_sign(&unsigned(entry)), "signed snapshot {relay}");
    }
}

#[test]
fn canonical_nevent_citations_accept_unused_relay_hints_and_long_tokens() {
    use bech32::{Bech32, Checksum, Hrp};
    struct Nip19Checksum;
    impl Checksum for Nip19Checksum {
        type MidstateRepr = <Bech32 as Checksum>::MidstateRepr;
        const CODE_LENGTH: usize = 5000;
        const CHECKSUM_LENGTH: usize = Bech32::CHECKSUM_LENGTH;
        const GENERATOR_SH: [Self::MidstateRepr; 5] = Bech32::GENERATOR_SH;
        const TARGET_RESIDUE: Self::MidstateRepr = Bech32::TARGET_RESIDUE;
    }
    let p = policy();
    for relays in [
        vec!["not a relay URL".to_string()],
        vec!["wss://relay.example/".to_string() + &"x".repeat(200); 6],
    ] {
        let mut e = fixture("entry");
        let raw = e["tags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t[0] == "video_snapshot")
            .unwrap()[1]
            .as_str()
            .unwrap();
        let snapshot: Value = serde_json::from_str(raw).unwrap();
        let id = snapshot["id"].as_str().unwrap();
        let mut data = vec![0, 32];
        data.extend(hex::decode(id).unwrap());
        for relay in relays {
            data.push(1);
            data.push(relay.len() as u8);
            data.extend(relay.as_bytes());
        }
        e["content"] = json!(format!(
            "nostr:{}",
            bech32::encode::<Nip19Checksum>(Hrp::parse("nevent").unwrap(), &data).unwrap()
        ));
        assert!(
            p.can_sign(&unsigned(e)),
            "canonical citations do not require usable relay hints"
        );
    }
}

#[test]
fn signed_video_snapshot_preserves_canonical_empty_ordinary_tags() {
    use nostr_sdk::{prelude::ToBech32, secp256k1::Message, EventId, Keys};
    use sha2::{Digest, Sha256};
    let p = policy();
    let keys = Keys::generate();
    let mut e = fixture("entry");
    let source = e["tags"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t[0] == "video_snapshot")
        .unwrap()[1]
        .as_str()
        .unwrap();
    let mut video: Value = serde_json::from_str(source).unwrap();
    video["pubkey"] = json!(keys.public_key().to_hex());
    video["tags"].as_array_mut().unwrap().push(json!([]));
    let preimage = json!([
        0,
        video["pubkey"],
        video["created_at"],
        video["kind"],
        video["tags"],
        video["content"]
    ]);
    let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&preimage).unwrap()).into();
    let id = hex::encode(digest);
    video["id"] = json!(id);
    video["sig"] = json!(keys.sign_schnorr(&Message::from_digest(digest)).to_string());
    for tag in e["tags"].as_array_mut().unwrap() {
        match tag[0].as_str().unwrap() {
            "video_snapshot" => tag[1] = json!(video.to_string()),
            "q" => tag[1] = json!(id),
            _ => {}
        }
    }
    e["content"] = json!(format!(
        "nostr:{}",
        EventId::from_hex(&id).unwrap().to_bech32().unwrap()
    ));
    assert!(
        p.can_sign(&unsigned(e.clone())),
        "canonical signed video snapshots allow empty ordinary tags"
    );
    for field in ["content", "id", "sig"] {
        let mut bad_video = video.clone();
        bad_video[field] = match field {
            "content" => json!("tampered"),
            "id" => json!("00".repeat(32)),
            _ => json!("00".repeat(64)),
        };
        let mut bad = e.clone();
        for tag in bad["tags"].as_array_mut().unwrap() {
            if tag[0] == "video_snapshot" {
                tag[1] = json!(bad_video.to_string());
            }
        }
        assert!(
            !p.can_sign(&unsigned(bad)),
            "tampered empty-tag snapshot {field}"
        );
    }
}
