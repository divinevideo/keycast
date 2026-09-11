use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const CONFIG_ENV: &str = "KEYCAST_RETENTION_DIGEST_KEYS";

#[derive(Debug, Clone, Copy)]
pub enum DigestPurpose {
    DeletionBinding,
    ProvisioningFingerprint,
    ProvisioningBinding,
}

impl DigestPurpose {
    fn key_domain(self) -> &'static [u8] {
        match self {
            Self::DeletionBinding => b"keycast-retention-key/deletion-binding/v1",
            Self::ProvisioningFingerprint => b"keycast-retention-key/provisioning-fingerprint/v1",
            Self::ProvisioningBinding => b"keycast-retention-key/provisioning-binding/v1",
        }
    }

    fn message_domain(self) -> &'static [u8] {
        match self {
            Self::DeletionBinding => b"keycast-retention-message/deletion-binding/v1",
            Self::ProvisioningFingerprint => {
                b"keycast-retention-message/provisioning-fingerprint/v1"
            }
            Self::ProvisioningBinding => b"keycast-retention-message/provisioning-binding/v1",
        }
    }
}

#[derive(Debug, Error)]
pub enum RetentionDigestKeyringError {
    #[error("retention digest keys are not configured")]
    Missing,
    #[error("invalid retention digest key configuration")]
    Invalid,
    #[error("retention digest key version {0} is unavailable")]
    UnknownVersion(i32),
}

/// Versioned root keys with purpose-specific derived HMAC keys.
///
/// Configuration format: `current=v2;v1=<64 hex chars>;v2=<64 hex chars>`.
/// Root keys never leave this type and are not printable through `Debug`.
#[derive(Clone)]
pub struct RetentionDigestKeyring {
    current: i32,
    roots: BTreeMap<i32, [u8; 32]>,
}

impl std::fmt::Debug for RetentionDigestKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetentionDigestKeyring")
            .field("current", &self.current)
            .field("versions", &self.roots.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RetentionDigestKeyring {
    pub fn from_env() -> Result<Self, RetentionDigestKeyringError> {
        let raw = std::env::var(CONFIG_ENV).map_err(|_| RetentionDigestKeyringError::Missing)?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, RetentionDigestKeyringError> {
        let mut current = None;
        let mut roots = BTreeMap::new();
        for entry in raw
            .split(';')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let (name, value) = entry
                .split_once('=')
                .ok_or(RetentionDigestKeyringError::Invalid)?;
            if name == "current" {
                current = Some(parse_version(value)?);
                continue;
            }
            let version = parse_version(name)?;
            let decoded = hex::decode(value).map_err(|_| RetentionDigestKeyringError::Invalid)?;
            let root: [u8; 32] = decoded
                .try_into()
                .map_err(|_| RetentionDigestKeyringError::Invalid)?;
            if roots.insert(version, root).is_some() {
                return Err(RetentionDigestKeyringError::Invalid);
            }
        }
        let current = current.ok_or(RetentionDigestKeyringError::Invalid)?;
        if !roots.contains_key(&current) {
            return Err(RetentionDigestKeyringError::Invalid);
        }
        Ok(Self { current, roots })
    }

    pub fn current_version(&self) -> i32 {
        self.current
    }

    pub fn versions(&self) -> Vec<i32> {
        self.roots.keys().copied().collect()
    }

    pub fn digest(&self, purpose: DigestPurpose, fields: &[&[u8]]) -> Vec<u8> {
        self.digest_at(self.current, purpose, fields)
            .expect("current retention key must exist")
    }

    pub fn digests_for_all_versions(
        &self,
        purpose: DigestPurpose,
        fields: &[&[u8]],
    ) -> Vec<Vec<u8>> {
        self.roots
            .keys()
            .map(|version| {
                self.digest_at(*version, purpose, fields)
                    .expect("enumerated retention key must exist")
            })
            .collect()
    }

    pub fn verify(
        &self,
        version: i32,
        purpose: DigestPurpose,
        fields: &[&[u8]],
        expected: &[u8],
    ) -> Result<bool, RetentionDigestKeyringError> {
        let mut verifier = HmacSha256::new_from_slice(&digest_key(
            self.roots
                .get(&version)
                .ok_or(RetentionDigestKeyringError::UnknownVersion(version))?,
            purpose,
        ))
        .expect("HMAC accepts any key length");
        update_message(&mut verifier, purpose, fields);
        Ok(verifier.verify_slice(expected).is_ok())
    }

    fn digest_at(
        &self,
        version: i32,
        purpose: DigestPurpose,
        fields: &[&[u8]],
    ) -> Result<Vec<u8>, RetentionDigestKeyringError> {
        let root = self
            .roots
            .get(&version)
            .ok_or(RetentionDigestKeyringError::UnknownVersion(version))?;
        let mut mac = HmacSha256::new_from_slice(&digest_key(root, purpose))
            .expect("HMAC accepts any key length");
        update_message(&mut mac, purpose, fields);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn parse_version(raw: &str) -> Result<i32, RetentionDigestKeyringError> {
    raw.strip_prefix('v')
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value > 0)
        .ok_or(RetentionDigestKeyringError::Invalid)
}

fn digest_key(root: &[u8; 32], purpose: DigestPurpose) -> [u8; 32] {
    let mut derivation = HmacSha256::new_from_slice(root).expect("HMAC accepts any key length");
    derivation.update(purpose.key_domain());
    derivation.finalize().into_bytes().into()
}

fn update_message(mac: &mut HmacSha256, purpose: DigestPurpose, fields: &[&[u8]]) {
    mac.update(purpose.message_domain());
    for field in fields {
        mac.update(&((*field).len() as u64).to_be_bytes());
        mac.update(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const V2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn rotated_keyring_verifies_old_digest() {
        let before = RetentionDigestKeyring::parse(&format!("current=v1;v1={V1}"))
            .expect("valid v1 keyring");
        let digest = before.digest(DigestPurpose::DeletionBinding, &[b"tenant", b"account"]);
        let after = RetentionDigestKeyring::parse(&format!("current=v2;v1={V1};v2={V2}"))
            .expect("valid rotated keyring");
        assert!(after
            .verify(
                1,
                DigestPurpose::DeletionBinding,
                &[b"tenant", b"account"],
                &digest,
            )
            .expect("v1 remains available"));
    }

    #[test]
    fn purpose_and_field_boundaries_are_separate() {
        let keys =
            RetentionDigestKeyring::parse(&format!("current=v1;v1={V1}")).expect("valid keyring");
        let digest = keys.digest(DigestPurpose::DeletionBinding, &[b"ab", b"c"]);
        assert!(!keys
            .verify(1, DigestPurpose::DeletionBinding, &[b"a", b"bc"], &digest,)
            .expect("known key"));
        assert!(!keys
            .verify(
                1,
                DigestPurpose::ProvisioningBinding,
                &[b"ab", b"c"],
                &digest,
            )
            .expect("known key"));
    }
}
