// ABOUTME: UCAN-based authentication using user-signed capability tokens
// ABOUTME: Replaces server-signed JWT with user-signed UCAN for decentralized auth

mod did;
pub mod dpop;
mod key_material;
mod validation;

pub use did::{did_to_nostr_pubkey, nostr_pubkey_to_did};
pub use dpop::{enforce_dpop_binding, extract_cnf_jkt_from_ucan, verify_dpop_proof};
pub use key_material::{NostrKeyMaterial, NostrVerifyKeyMaterial};
pub use validation::{extract_user_from_ucan, is_server_signed, validate_ucan_token};
