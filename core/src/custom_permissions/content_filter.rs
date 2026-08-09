use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Returns true if any string value reachable from `value` contains a blocked
/// word. Object keys are skipped so only creator-supplied content is matched.
fn contains_blocked_word(value: &Value, words: &[String]) -> bool {
    match value {
        Value::String(text) => words.iter().any(|word| text.contains(word)),
        Value::Array(items) => items.iter().any(|item| contains_blocked_word(item, words)),
        Value::Object(map) => map.values().any(|item| contains_blocked_word(item, words)),
        _ => false,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContentFilterConfig {
    pub blocked_words: Option<Vec<String>>,
}

pub struct ContentFilter {
    config: ContentFilterConfig,
}

impl ContentFilter {
    /// Returns the set of blocked words, or None if no filtering
    pub fn blocked_words(&self) -> Option<&Vec<String>> {
        self.config.blocked_words.as_ref()
    }
}

#[async_trait]
impl CustomPermission for ContentFilter {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let parsed_config: ContentFilterConfig =
            serde_json::from_value(permission.config.0.clone())
                .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;

        Ok(Box::new(Self {
            config: parsed_config,
        }))
    }

    fn identifier(&self) -> &'static str {
        "content_filter"
    }

    fn can_sign(&self, event: &UnsignedEvent) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| event.content.contains(word)),
        }
    }

    fn can_sign_creator_binding(&self, payload: &[u8]) -> bool {
        let Some(words) = &self.config.blocked_words else {
            return true;
        };

        // Scan every caller-controlled free-text surface, and only those.
        //
        // Matching the whole serialized payload instead would also match the
        // fixed structural key names and the pinned values: `sig_alg` contains
        // "sig", and `pubkey` plus `hard_binding.value` are hex, so a blocklist
        // holding "sig", "bad", "dead" or "cafe" would silently deny every
        // creator-binding request rather than filtering creator content.
        // `version`, `pubkey`, `sig_alg` and `hard_binding` are pinned by
        // `validate_creator_binding_payload`, so they carry no caller text.
        let Ok(text) = std::str::from_utf8(payload) else {
            return false;
        };
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return false;
        };
        let Some(claims) = value.get("claims") else {
            return false;
        };

        let free_text = [
            Some(claims),
            value.get("created_at"),
            value.get("referenced_assertions"),
        ];
        let blocked = free_text
            .into_iter()
            .flatten()
            .any(|field| contains_blocked_word(field, words));

        !blocked
    }

    fn can_encrypt(
        &self,
        plaintext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| plaintext.contains(word)),
        }
    }

    // We can't know what is in the content of the event, so we always allow decryption
    fn can_decrypt(
        &self,
        _ciphertext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }

    fn display(&self) -> PermissionDisplay {
        match &self.config.blocked_words {
            None => PermissionDisplay {
                icon: "✅",
                title: "No content restrictions",
                description: "No blocked words or phrases".to_string(),
            },
            Some(words) if words.is_empty() => PermissionDisplay {
                icon: "✅",
                title: "No content restrictions",
                description: "No blocked words or phrases".to_string(),
            },
            Some(words) => PermissionDisplay {
                icon: "🛡️",
                title: "Content restrictions",
                description: format!("Cannot post content containing: {}", words.join(", ")),
            },
        }
    }
}

#[test]
fn test_default() {
    let config = ContentFilterConfig::default();
    assert!(config.blocked_words.is_none());
}

#[cfg(test)]
mod creator_binding_tests {
    use super::*;
    use crate::types::permission::{JsonConfig, Permission};
    use chrono::Utc;

    fn filter(blocked_words: &[&str]) -> Box<dyn CustomPermission> {
        let now = Utc::now();
        Permission {
            id: 1,
            identifier: "content_filter".to_string(),
            config: JsonConfig(serde_json::json!({ "blocked_words": blocked_words })),
            created_at: now,
            updated_at: now,
        }
        .to_custom_permission()
        .expect("content_filter test permission")
    }

    /// Mirrors the payload divine-mobile builds in
    /// `NostrCreatorBindingService.createAssertion`.
    fn payload(nip05: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "pubkey": "0".repeat(64),
            "sig_alg": "nostr.secp256k1",
            "created_at": "2026-04-29T00:00:00Z",
            "claims": { "nip05": nip05 },
            "referenced_assertions": ["c2pa.actions.v2", "cawg.training-mining"],
            "hard_binding": {
                "alg": "sha256",
                "value": "badc0ffee0ddf00d39463a825d82c6c98981881283fb7ed039341a12a2f77007"
            }
        }))
        .expect("valid creator binding")
    }

    #[test]
    fn blocked_word_in_structural_key_does_not_deny() {
        // "ass" occurs in `referenced_assertions`; it is not creator content.
        assert!(filter(&["ass"]).can_sign_creator_binding(&payload("creator@example.com")));
    }

    #[test]
    fn blocked_word_in_hard_binding_digest_does_not_deny() {
        // "bad" and "c0ffee" are valid hex and appear in the digest above.
        assert!(filter(&["bad"]).can_sign_creator_binding(&payload("creator@example.com")));
    }

    /// The residual-bypass proof of concept: before this was fixed, blocked text
    /// parked in `created_at` or `referenced_assertions` passed the policy layer
    /// and got signed with the user's key.
    #[test]
    fn blocked_word_in_created_at_denies() {
        let value = serde_json::json!({
            "version": 1,
            "created_at": "scam: arbitrary caller-controlled text",
            "claims": {},
            "referenced_assertions": [],
        });
        let bytes = serde_json::to_vec(&value).expect("valid JSON");

        assert!(!filter(&["scam"]).can_sign_creator_binding(&bytes));
    }

    #[test]
    fn blocked_word_in_referenced_assertions_denies() {
        let value = serde_json::json!({
            "version": 1,
            "created_at": "2026-04-29T00:00:00Z",
            "claims": {},
            "referenced_assertions": ["scam: more caller-controlled text"],
        });
        let bytes = serde_json::to_vec(&value).expect("valid JSON");

        assert!(!filter(&["scam"]).can_sign_creator_binding(&bytes));
    }

    #[test]
    fn blocked_word_in_pinned_pubkey_hex_does_not_deny() {
        // `pubkey` is a 64-char hex string pinned to the signer, so hex-shaped
        // blocklist words must not deny. Regression guard against widening the
        // scan back to the whole document.
        let value = serde_json::json!({
            "version": 1,
            "pubkey": "deadbeef".repeat(8),
            "sig_alg": "nostr.secp256k1",
            "created_at": "2026-04-29T00:00:00Z",
            "claims": {},
            "referenced_assertions": [],
        });
        let bytes = serde_json::to_vec(&value).expect("valid JSON");

        assert!(filter(&["dead"]).can_sign_creator_binding(&bytes));
        assert!(filter(&["sig"]).can_sign_creator_binding(&bytes));
    }

    #[test]
    fn blocked_word_in_claim_value_denies() {
        assert!(!filter(&["blocked"]).can_sign_creator_binding(&payload("blocked@example.com")));
    }

    #[test]
    fn nested_claim_value_is_filtered() {
        let value = serde_json::json!({
            "version": 1,
            "claims": {
                "social_handles": [{"platform": "x", "handle": "blockedhandle"}]
            }
        });
        let bytes = serde_json::to_vec(&value).expect("valid JSON");

        assert!(!filter(&["blockedhandle"]).can_sign_creator_binding(&bytes));
    }

    #[test]
    fn no_blocked_words_allows() {
        let now = Utc::now();
        let permission = Permission {
            id: 1,
            identifier: "content_filter".to_string(),
            config: JsonConfig(serde_json::json!({})),
            created_at: now,
            updated_at: now,
        }
        .to_custom_permission()
        .expect("content_filter test permission");

        assert!(permission.can_sign_creator_binding(&payload("creator@example.com")));
    }

    #[test]
    fn non_utf8_payload_denies() {
        assert!(!filter(&["blocked"]).can_sign_creator_binding(&[0xff, 0xfe, 0xfd]));
    }
}
