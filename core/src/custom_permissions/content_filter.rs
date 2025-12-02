use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};

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
