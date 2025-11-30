use crate::encryption::KeyManagerError;
use crate::types::user::UserError;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Nostr Key Error: {0}")]
    NostrKey(#[from] nostr_sdk::key::Error),

    #[error("NIP-49 Error: {0}")]
    Nip49(#[from] nostr_sdk::nips::nip49::Error),

    #[error("NIP-19 Error: {0}")]
    Nip19(#[from] nostr_sdk::nips::nip19::Error),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("User is not an admin of the team")]
    NotAdmin(#[from] UserError),

    #[error("Key manager error: {0}")]
    KeyManager(#[from] KeyManagerError),
}

/// A stored key is a key that has been stored in the database for a team
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct StoredKey {
    /// The id of the stored key
    pub id: i32,
    /// The id of the team the key belongs to
    pub team_id: i32,
    /// The name of the key
    pub name: String,
    /// The Nostr pubkey of the key in hex format
    pub pubkey: String,
    /// The secret key of the key, in bytes, encrypted
    pub secret_key: Vec<u8>,
    /// The date and time the key was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the key was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

/// A public representation of a stored key, without the secret key
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicStoredKey {
    pub id: i32,
    pub team_id: i32,
    pub name: String,
    pub pubkey: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl From<StoredKey> for PublicStoredKey {
    fn from(key: StoredKey) -> Self {
        Self {
            id: key.id,
            team_id: key.team_id,
            name: key.name,
            pubkey: key.pubkey,
            created_at: key.created_at,
            updated_at: key.updated_at,
        }
    }
}
