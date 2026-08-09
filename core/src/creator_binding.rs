// ABOUTME: Validates C2PA creator-binding payloads before canonical signing
// ABOUTME: Keeps non-event signing scoped to the expected Divine assertion shape

use nostr_sdk::PublicKey;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

pub const MAX_CREATOR_BINDING_PAYLOAD_BYTES: usize = 64 * 1024;

/// divine-mobile's `NostrCreatorBindingService` assertion, as a closed shape.
///
/// Every byte of the payload is signed with the user's key, so anything accepted
/// here becomes caller-chosen content inside a signed blob. `ContentFilter` only
/// scans the free-text values (`claims`, `created_at`, `referenced_assertions`),
/// so any field it cannot see must be structurally impossible rather than merely
/// unexpected.
///
/// `deny_unknown_fields` does the work at every depth, and it also makes serde
/// reject *duplicate* keys. That second property is load-bearing: `serde_json`
/// collapses duplicates last-wins, but the caller signs the original bytes, so a
/// shadowed duplicate would ride into the signature without ever being validated
/// or content-filtered — and a first-wins reader downstream would see a different
/// assertion than the one Keycast approved.
///
/// Adding a field means updating this struct and
/// `ContentFilter::can_sign_creator_binding` together, in lockstep with mobile.
// Most fields are never read: they exist so serde enforces the shape. The
// caller signs the original bytes, so this type is a validator, not a model.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatorBindingPayload {
    version: u64,
    pubkey: String,
    sig_alg: String,
    #[serde(default)]
    created_at: Option<String>,
    claims: Claims,
    referenced_assertions: Vec<String>,
    hard_binding: HardBinding,
}

/// Mirrors `CreatorBindingClaims.toJson()`; every field is conditional there, so
/// every field is optional here and `{}` is legitimate.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    #[serde(default)]
    nip05: Option<String>,
    #[serde(default)]
    website: Option<String>,
    #[serde(default)]
    social_handles: Option<Vec<SocialHandle>>,
}

/// Mirrors `CreatorSocialHandle.toJson()`.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocialHandle {
    platform: String,
    handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HardBinding {
    alg: String,
    value: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CreatorBindingError {
    #[error("creator-binding payload exceeds maximum size")]
    PayloadTooLarge,
    #[error("creator-binding payload must be UTF-8 JSON")]
    InvalidUtf8,
    #[error("creator-binding payload must not include a signature")]
    PreSignedPayload,
    #[error("creator-binding payload shape is invalid: {0}")]
    InvalidShape(String),
    #[error("creator-binding version must be 1")]
    InvalidVersion,
    #[error("creator-binding sig_alg must be nostr.secp256k1")]
    InvalidSignatureAlgorithm,
    #[error("creator-binding pubkey must match signer")]
    PubkeyMismatch,
    #[error("creator-binding hard_binding must be {{alg: \"sha256\", value: <64 lowercase hex>}}")]
    InvalidHardBinding,
}

/// Validate that a canonical-signing payload is a creator-binding assertion for
/// the signing key.
///
/// The caller signs the original bytes after this check, so this function must
/// not reserialize or normalize the JSON — which is exactly why the accepted
/// shape is closed rather than merely checked for required fields. Unknown
/// fields, duplicate keys, and unexpected types are all rejected, so the bytes
/// that get signed cannot carry anything the policy layer never saw.
pub fn validate_creator_binding_payload(
    payload: &[u8],
    signer_pubkey: PublicKey,
) -> Result<(), CreatorBindingError> {
    if payload.len() > MAX_CREATOR_BINDING_PAYLOAD_BYTES {
        return Err(CreatorBindingError::PayloadTooLarge);
    }

    let text = std::str::from_utf8(payload).map_err(|_| CreatorBindingError::InvalidUtf8)?;

    // Checked ahead of the struct so re-submitting an already-signed assertion
    // gets a specific answer instead of a generic unknown-field message.
    if let Ok(Value::Object(object)) = serde_json::from_str::<Value>(text) {
        if object.contains_key("signature") || object.contains_key("sig") {
            return Err(CreatorBindingError::PreSignedPayload);
        }
    }

    let parsed: CreatorBindingPayload =
        serde_json::from_str(text).map_err(|e| CreatorBindingError::InvalidShape(e.to_string()))?;

    if parsed.version != 1 {
        return Err(CreatorBindingError::InvalidVersion);
    }

    if parsed.sig_alg != "nostr.secp256k1" {
        return Err(CreatorBindingError::InvalidSignatureAlgorithm);
    }

    if parsed.pubkey != signer_pubkey.to_hex() {
        return Err(CreatorBindingError::PubkeyMismatch);
    }

    validate_hard_binding(&parsed.hard_binding)?;

    Ok(())
}

/// `hard_binding` is pinned to `{alg: "sha256", value: <64 lowercase hex>}`.
///
/// Pinning it leaves no free-text surface here, which is what lets the content
/// filter skip this field: a hex digest would otherwise trip blocklists on words
/// that are also valid hex ("bad", "dead", "cafe").
fn validate_hard_binding(hard_binding: &HardBinding) -> Result<(), CreatorBindingError> {
    if hard_binding.alg != "sha256" {
        return Err(CreatorBindingError::InvalidHardBinding);
    }

    if hard_binding.value.len() != 64
        || !hard_binding
            .value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(CreatorBindingError::InvalidHardBinding);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;
    use serde_json::json;

    fn valid_payload(pubkey: PublicKey) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 1,
            "pubkey": pubkey.to_hex(),
            "sig_alg": "nostr.secp256k1",
            "created_at": "2026-04-29T00:00:00Z",
            "claims": {
                "nip05": "creator@example.com",
                "website": "https://example.com"
            },
            // divine-mobile sends a sorted list of assertion label strings.
            "referenced_assertions": ["c2pa.actions.v2", "cawg.training-mining"],
            "hard_binding": {
                "alg": "sha256",
                "value": "39341a12a2f77007d6e72841f667523d39463a825d82c6c98981881283fb7ed0"
            }
        }))
        .expect("valid JSON")
    }

    #[test]
    fn accepts_mobile_creator_binding_shape() {
        let keys = Keys::generate();
        let payload = valid_payload(keys.public_key());

        validate_creator_binding_payload(&payload, keys.public_key())
            .expect("mobile creator-binding payload should validate");
    }

    #[test]
    fn rejects_non_object_payload() {
        let keys = Keys::generate();
        let err =
            validate_creator_binding_payload(b"\"divine-creator-binding-test\"", keys.public_key())
                .expect_err("bare test vector is not a creator-binding object");

        assert!(matches!(err, CreatorBindingError::InvalidShape(_)), "{err}");
    }

    #[test]
    fn rejects_wrong_version() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["version"] = json!(2);
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::InvalidVersion);
    }

    #[test]
    fn rejects_wrong_signature_algorithm() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["sig_alg"] = json!("ed25519");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::InvalidSignatureAlgorithm);
    }

    #[test]
    fn rejects_pubkey_mismatch() {
        let signer = Keys::generate();
        let other = Keys::generate();
        let payload = valid_payload(other.public_key());

        let err = validate_creator_binding_payload(&payload, signer.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::PubkeyMismatch);
    }

    #[test]
    fn rejects_missing_claims() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value.as_object_mut().unwrap().remove("claims");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(matches!(err, CreatorBindingError::InvalidShape(_)), "{err}");
    }

    #[test]
    fn rejects_missing_referenced_assertions() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("referenced_assertions");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(matches!(err, CreatorBindingError::InvalidShape(_)), "{err}");
    }

    #[test]
    fn rejects_missing_hard_binding() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value.as_object_mut().unwrap().remove("hard_binding");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(
            err.to_string().contains("missing field `hard_binding`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_oversize_payload() {
        let keys = Keys::generate();
        let payload = vec![b' '; MAX_CREATOR_BINDING_PAYLOAD_BYTES + 1];

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::PayloadTooLarge);
    }

    #[test]
    fn rejects_non_utf8_payload() {
        let keys = Keys::generate();
        let payload = [0xff, 0xfe, 0xfd];

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::InvalidUtf8);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        // An extra field would otherwise ride into the signed bytes untouched by
        // `content_filter`, which only inspects the known free-text fields.
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["note"] = json!("arbitrary caller-controlled text");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(err.to_string().contains("unknown field `note`"), "{err}");
    }

    /// `serde_json::Value` collapses duplicate keys last-wins, but the caller
    /// signs the original bytes. A shadowed duplicate would therefore be signed
    /// without ever being validated or content-filtered, and a first-wins reader
    /// downstream would see a different assertion than the one approved here.
    #[test]
    fn rejects_duplicate_top_level_key() {
        let keys = Keys::generate();
        let valid = String::from_utf8(valid_payload(keys.public_key())).unwrap();
        let smuggled = valid.replacen(
            r#""created_at":"#,
            r#""created_at":"scam: caller text in created_at","created_at":"#,
            1,
        );

        let err =
            validate_creator_binding_payload(smuggled.as_bytes(), keys.public_key()).unwrap_err();
        assert!(
            err.to_string().contains("duplicate field `created_at`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_duplicate_nested_claim_key() {
        let keys = Keys::generate();
        let payload = format!(
            r#"{{"version":1,"pubkey":"{}","sig_alg":"nostr.secp256k1",
                 "created_at":"2026-04-29T00:00:00Z",
                 "claims":{{"nip05":"scam: caller text","nip05":"creator@example.com"}},
                 "referenced_assertions":[],
                 "hard_binding":{{"alg":"sha256","value":"{}"}}}}"#,
            keys.public_key().to_hex(),
            "3".repeat(64)
        );

        let err =
            validate_creator_binding_payload(payload.as_bytes(), keys.public_key()).unwrap_err();
        assert!(err.to_string().contains("duplicate field `nip05`"), "{err}");
    }

    #[test]
    fn rejects_caller_controlled_claim_key() {
        // Claim keys are caller-supplied text that the content filter never sees,
        // because it only walks values.
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["claims"] = json!({"scam: arbitrary caller-controlled text": ""});
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown field `scam: arbitrary caller-controlled text`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_caller_controlled_social_handle_key() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["claims"] = json!({
            "social_handles": [{"platform": "x", "handle": "creator", "scam: text": ""}]
        });
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `scam: text`"),
            "{err}"
        );
    }

    #[test]
    fn accepts_full_mobile_claims_shape() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["claims"] = json!({
            "nip05": "creator@example.com",
            "website": "https://example.com",
            "social_handles": [{"platform": "x", "handle": "creator"}]
        });
        let payload = serde_json::to_vec(&value).unwrap();

        validate_creator_binding_payload(&payload, keys.public_key())
            .expect("full CreatorBindingClaims shape must validate");
    }

    #[test]
    fn accepts_empty_claims() {
        // Every claim field is conditional on the mobile side, so `{}` is legitimate.
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["claims"] = json!({});
        let payload = serde_json::to_vec(&value).unwrap();

        validate_creator_binding_payload(&payload, keys.public_key())
            .expect("claims with no fields must validate");
    }

    #[test]
    fn rejects_non_string_created_at() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["created_at"] = json!({"smuggled": "structured data"});
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(matches!(err, CreatorBindingError::InvalidShape(_)), "{err}");
    }

    #[test]
    fn rejects_non_string_referenced_assertion() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["referenced_assertions"] = json!([{"url": "self#jumbf=/c2pa"}]);
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert!(matches!(err, CreatorBindingError::InvalidShape(_)), "{err}");
    }

    #[test]
    fn rejects_hard_binding_with_extra_or_bad_fields() {
        let keys = Keys::generate();

        for bad in [
            json!({"alg": "sha256", "value": "a".repeat(64), "note": "extra"}),
            json!({"alg": "scam: free text", "value": "a".repeat(64)}),
            json!({"alg": "sha256", "value": "not-hex"}),
            json!({"alg": "sha256", "value": "A".repeat(64)}),
            json!({"alg": "sha256"}),
        ] {
            let mut value: Value =
                serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
            value["hard_binding"] = bad.clone();
            let payload = serde_json::to_vec(&value).unwrap();

            let err = validate_creator_binding_payload(&payload, keys.public_key())
                .expect_err(&format!("hard_binding {bad} must be rejected"));
            assert!(
                matches!(
                    err,
                    CreatorBindingError::InvalidHardBinding | CreatorBindingError::InvalidShape(_)
                ),
                "{err}"
            );
        }
    }

    #[test]
    fn accepts_payload_without_optional_created_at() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value.as_object_mut().unwrap().remove("created_at");
        let payload = serde_json::to_vec(&value).unwrap();

        validate_creator_binding_payload(&payload, keys.public_key())
            .expect("created_at is allowed but not required");
    }

    #[test]
    fn rejects_pre_signed_payload() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["signature"] = json!("already-signed");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::PreSignedPayload);
    }
}
