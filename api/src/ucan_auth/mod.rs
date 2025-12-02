// ABOUTME: UCAN-based authentication using user-signed capability tokens
// ABOUTME: Replaces server-signed JWT with user-signed UCAN for decentralized auth

mod did;
mod key_material;
mod validation;

pub use did::{did_to_nostr_pubkey, nostr_pubkey_to_did};
pub use key_material::NostrKeyMaterial;
pub use validation::{extract_user_from_ucan, validate_ucan_token};
