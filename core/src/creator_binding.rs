// ABOUTME: Validates C2PA creator-binding payloads before canonical signing
// ABOUTME: Keeps non-event signing scoped to the expected Divine assertion shape

use nostr_sdk::PublicKey;
use serde_json::Value;
use thiserror::Error;

pub const MAX_CREATOR_BINDING_PAYLOAD_BYTES: usize = 64 * 1024;

/// The exact top-level fields divine-mobile's `NostrCreatorBindingService` emits.
///
/// The allowlist is closed on purpose: every byte of the payload is signed with
/// the user's key, so anything accepted here becomes caller-chosen content
/// inside a signed blob. `content_filter` scans only the free-text fields
/// (`claims`, `created_at`, `referenced_assertions`), so an unknown field would
/// bypass policy entirely. Adding a field means updating this list, the
/// per-field shape checks below, and `ContentFilter::can_sign_creator_binding`
/// together, in lockstep with the mobile client.
const ALLOWED_TOP_LEVEL_FIELDS: [&str; 7] = [
    "version",
    "pubkey",
    "sig_alg",
    "created_at",
    "claims",
    "referenced_assertions",
    "hard_binding",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CreatorBindingError {
    #[error("creator-binding payload exceeds maximum size")]
    PayloadTooLarge,
    #[error("creator-binding payload must be UTF-8 JSON")]
    InvalidUtf8,
    #[error("creator-binding payload must be a JSON object")]
    NotObject,
    #[error("creator-binding version must be 1")]
    InvalidVersion,
    #[error("creator-binding sig_alg must be nostr.secp256k1")]
    InvalidSignatureAlgorithm,
    #[error("creator-binding pubkey must match signer")]
    PubkeyMismatch,
    #[error("creator-binding claims must be an object of known string fields")]
    InvalidClaims,
    #[error("creator-binding claims has unexpected field: {0}")]
    UnexpectedClaim(String),
    #[error("creator-binding referenced_assertions must be an array of strings")]
    InvalidReferencedAssertions,
    #[error("creator-binding hard_binding must be {{alg: \"sha256\", value: <64 hex>}}")]
    InvalidHardBinding,
    #[error("creator-binding created_at must be a string")]
    InvalidCreatedAt,
    #[error("creator-binding payload must not include a signature")]
    PreSignedPayload,
    #[error("creator-binding payload is invalid JSON")]
    InvalidJson,
    #[error("creator-binding payload has unexpected field: {0}")]
    UnexpectedField(String),
}

/// Validate that a canonical-signing payload is a creator-binding assertion for
/// the signing key. The caller signs the original bytes after this check, so this
/// function must not reserialize or normalize the JSON.
///
/// The accepted shape is closed, not just checked for required fields: unknown
/// top-level fields are rejected so the signed bytes cannot carry
/// caller-controlled content past the policy layer.
pub fn validate_creator_binding_payload(
    payload: &[u8],
    signer_pubkey: PublicKey,
) -> Result<(), CreatorBindingError> {
    if payload.len() > MAX_CREATOR_BINDING_PAYLOAD_BYTES {
        return Err(CreatorBindingError::PayloadTooLarge);
    }

    let text = std::str::from_utf8(payload).map_err(|_| CreatorBindingError::InvalidUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| CreatorBindingError::InvalidJson)?;
    let object = value.as_object().ok_or(CreatorBindingError::NotObject)?;

    if object.contains_key("signature") || object.contains_key("sig") {
        return Err(CreatorBindingError::PreSignedPayload);
    }

    if let Some(unexpected) = object
        .keys()
        .find(|key| !ALLOWED_TOP_LEVEL_FIELDS.contains(&key.as_str()))
    {
        return Err(CreatorBindingError::UnexpectedField(unexpected.clone()));
    }

    match object.get("version").and_then(Value::as_u64) {
        Some(1) => {}
        _ => return Err(CreatorBindingError::InvalidVersion),
    }

    match object.get("sig_alg").and_then(Value::as_str) {
        Some("nostr.secp256k1") => {}
        _ => return Err(CreatorBindingError::InvalidSignatureAlgorithm),
    }

    match object.get("pubkey").and_then(Value::as_str) {
        Some(pubkey) if pubkey == signer_pubkey.to_hex() => {}
        _ => return Err(CreatorBindingError::PubkeyMismatch),
    }

    validate_claims(object.get("claims"))?;

    // `created_at` is optional, but when present it must be a plain string so it
    // cannot smuggle structured caller data.
    if object
        .get("created_at")
        .is_some_and(|value| !value.is_string())
    {
        return Err(CreatorBindingError::InvalidCreatedAt);
    }

    // divine-mobile sends a sorted `List<String>` of assertion labels.
    match object
        .get("referenced_assertions")
        .and_then(Value::as_array)
    {
        Some(items) if items.iter().all(Value::is_string) => {}
        _ => return Err(CreatorBindingError::InvalidReferencedAssertions),
    }

    validate_hard_binding(object.get("hard_binding"))?;

    Ok(())
}

/// `claims` is pinned to divine-mobile's `CreatorBindingClaims.toJson()` shape:
/// every key optional, but no key outside the known set at any depth.
///
/// Keys are pinned rather than content-filtered on purpose. A caller-chosen key
/// would be free text that `ContentFilter` never sees, since
/// `contains_blocked_word` only walks values. Scanning keys instead would deny
/// on the fixed names themselves — a blocklist holding "and" or "for" matches
/// `social_handles` and `platform` — which is the false-denial trap this module
/// already avoids elsewhere.
fn validate_claims(claims: Option<&Value>) -> Result<(), CreatorBindingError> {
    const ALLOWED_CLAIMS: [&str; 3] = ["nip05", "website", "social_handles"];
    const ALLOWED_HANDLE_FIELDS: [&str; 2] = ["platform", "handle"];

    let object = claims
        .and_then(Value::as_object)
        .ok_or(CreatorBindingError::InvalidClaims)?;

    if let Some(unexpected) = object
        .keys()
        .find(|key| !ALLOWED_CLAIMS.contains(&key.as_str()))
    {
        return Err(CreatorBindingError::UnexpectedClaim(unexpected.clone()));
    }

    for key in ["nip05", "website"] {
        if object.get(key).is_some_and(|value| !value.is_string()) {
            return Err(CreatorBindingError::InvalidClaims);
        }
    }

    let Some(handles) = object.get("social_handles") else {
        return Ok(());
    };

    for handle in handles
        .as_array()
        .ok_or(CreatorBindingError::InvalidClaims)?
    {
        let handle = handle
            .as_object()
            .ok_or(CreatorBindingError::InvalidClaims)?;

        if let Some(unexpected) = handle
            .keys()
            .find(|key| !ALLOWED_HANDLE_FIELDS.contains(&key.as_str()))
        {
            return Err(CreatorBindingError::UnexpectedClaim(unexpected.clone()));
        }

        if !ALLOWED_HANDLE_FIELDS
            .iter()
            .all(|key| handle.get(*key).is_some_and(Value::is_string))
        {
            return Err(CreatorBindingError::InvalidClaims);
        }
    }

    Ok(())
}

/// `hard_binding` is pinned to exactly `{alg: "sha256", value: <64 lowercase hex>}`.
///
/// Pinning it leaves no free-text surface here, which is what lets the content
/// filter skip this field: a hex digest would otherwise trip blocklists on words
/// that are also valid hex ("bad", "dead", "cafe").
fn validate_hard_binding(hard_binding: Option<&Value>) -> Result<(), CreatorBindingError> {
    let object = hard_binding
        .and_then(Value::as_object)
        .ok_or(CreatorBindingError::InvalidHardBinding)?;

    if object.len() != 2 || !object.contains_key("alg") || !object.contains_key("value") {
        return Err(CreatorBindingError::InvalidHardBinding);
    }

    if object.get("alg").and_then(Value::as_str) != Some("sha256") {
        return Err(CreatorBindingError::InvalidHardBinding);
    }

    let value = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or(CreatorBindingError::InvalidHardBinding)?;

    if value.len() != 64
        || !value
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

        assert_eq!(err, CreatorBindingError::NotObject);
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
        assert_eq!(err, CreatorBindingError::InvalidClaims);
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
        assert_eq!(err, CreatorBindingError::InvalidReferencedAssertions);
    }

    #[test]
    fn rejects_missing_hard_binding() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value.as_object_mut().unwrap().remove("hard_binding");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::InvalidHardBinding);
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
        // `content_filter`, which only inspects `claims`.
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["note"] = json!("arbitrary caller-controlled text");
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(
            err,
            CreatorBindingError::UnexpectedField("note".to_string())
        );
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
        assert_eq!(
            err,
            CreatorBindingError::UnexpectedClaim(
                "scam: arbitrary caller-controlled text".to_string()
            )
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
        assert_eq!(
            err,
            CreatorBindingError::UnexpectedClaim("scam: text".to_string())
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
        assert_eq!(err, CreatorBindingError::InvalidCreatedAt);
    }

    #[test]
    fn rejects_non_string_referenced_assertion() {
        let keys = Keys::generate();
        let mut value: Value = serde_json::from_slice(&valid_payload(keys.public_key())).unwrap();
        value["referenced_assertions"] = json!([{"url": "self#jumbf=/c2pa"}]);
        let payload = serde_json::to_vec(&value).unwrap();

        let err = validate_creator_binding_payload(&payload, keys.public_key()).unwrap_err();
        assert_eq!(err, CreatorBindingError::InvalidReferencedAssertions);
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
            assert_eq!(err, CreatorBindingError::InvalidHardBinding);
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
