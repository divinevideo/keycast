// ABOUTME: Server-side DM containment gate for verified_minor accounts (support-trust-safety#183).
// ABOUTME: Refuses to sign/encrypt DM-shaped events destined outside the pinned official set.

//! Protected-minor (13-15) DM containment for custodial accounts.
//!
//! Keycast holds the signing key for custodial minors, and its signing API is
//! reachable with just the account's credentials — so client-side DM
//! restrictions (divine-mobile#5754 / divine-web#474) are friction, not
//! containment, for these accounts. This module is the server-side backstop:
//! for a `verified_minor` user, Keycast refuses to sign or encrypt DM-shaped
//! payloads whose recipients fall outside the pinned official set.
//!
//! # Trust model (pin-only, deliberately)
//!
//! The clients approve a recipient via "pinned pubkey AND live NIP-05
//! re-resolution" (divine-mobile#4948): the pin blocks attacker *addition*,
//! the NIP-05 leg is a *revocation* lever. Server-side we enforce the pin
//! only. A live NIP-05 lookup inside the signing hot path would add a network
//! dependency to every DM sign and force a fail-open-vs-fail-closed call on
//! every resolver hiccup; revocation server-side is handled by shipping an
//! updated pin (and, for compromise, by the account-status lifecycle). The
//! pinned values are mirrored by hand from the clients' shipped sets
//! (`officialAccounts.ts` / `official_accounts.dart`) and must stay identical.
//!
//! # What is gated (egress only)
//!
//! * `nip04_encrypt` / `nip44_encrypt`: recipient must be the user or pinned.
//! * `sign_event` kind 4 (NIP-04 DM), kinds 14/15 (NIP-17 rumors), kind 1059
//!   (gift wrap): every `p` tag must resolve to the user or a pinned account,
//!   and at least one `p` tag must be present.
//! * `sign_event` kind 13 (NIP-59 seal): the seal names no recipient — its
//!   content is NIP-44 ciphertext under the conversation key of the *unstated*
//!   receiver. The recipient is recovered by trial-decrypting against the
//!   user's conversation keys with each approved pubkey (NIP-44 v2 is
//!   authenticated, so this is deterministic); the inner rumor's `p` tags must
//!   also all be approved. Anything that does not decrypt is refused.
//!
//! Decrypt/unwrap (ingress) is intentionally untouched — #183 scopes
//! containment to egress.
//!
//! Fail closed: an unresolvable recipient, an unparseable `p` tag, or a seal
//! that decrypts to nothing is a refusal, never a pass-through.

use nostr_sdk::nips::nip44;
use nostr_sdk::{Keys, Kind, PublicKey, Tag, UnsignedEvent};
use once_cell::sync::Lazy;

/// The pinned official accounts a protected minor may exchange DMs with.
/// Mirrored by hand from the clients' shipped sets — keep the values identical
/// to divine-web `officialAccounts.ts` and divine-mobile
/// `official_accounts.dart` (verified 2026-07-09). Additions are
/// deploy-gated by design: this is a child-contact list, and requiring a
/// release to widen it is the accepted friction that makes the pin an
/// attacker-addition barrier (no env override on purpose).
pub const PINNED_MINOR_CONTACTABLE_PUBKEYS: [&str; 2] = [
    // Divine HQ (_@divinehq.divine.video)
    "c4a39f1291291d452405cd8ddd798c4a29a3858c52cd0d843f1f6852cf17682e",
    // Divine Moderation (moderation@divine.video)
    "8fd5eb6d8f362163bc00a5ab6b4a3167dbf32d00ec4efdbcf43b3c9514433b7e",
];

/// Why a verified_minor sign/encrypt request was refused. The variants exist
/// for server-side logging; callers surface one uniform, non-specific error to
/// the client (matching the policy-denial message) so account state is not
/// leaked through error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinorDmDenied {
    /// A recipient (encrypt target or `p` tag) is outside the approved set.
    RecipientNotApproved,
    /// The recipient cannot be determined (no `p` tags, or a `p` tag that is
    /// not a valid pubkey). Fail closed.
    RecipientUnresolvable,
    /// A kind-13 seal whose content does not decrypt under any approved
    /// conversation key — its recipient is unknowable to us. Fail closed.
    SealNotDecryptable,
    /// A kind-13 seal decrypted, but the inner rumor is not a well-formed
    /// event JSON we can extract recipients from. Fail closed.
    SealRumorInvalid,
}

impl std::fmt::Display for MinorDmDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            MinorDmDenied::RecipientNotApproved => "recipient not in approved set",
            MinorDmDenied::RecipientUnresolvable => "recipient unresolvable",
            MinorDmDenied::SealNotDecryptable => "seal not decryptable to an approved recipient",
            MinorDmDenied::SealRumorInvalid => "sealed rumor malformed",
        };
        write!(f, "verified_minor DM gate: {}", reason)
    }
}

/// Parsed pinned pubkeys. The constants are compile-time-fixed valid hex, so
/// the expects cannot fire at runtime (pinned by the unit tests).
static PINNED_KEYS: Lazy<[PublicKey; 2]> = Lazy::new(|| {
    [
        PublicKey::from_hex(PINNED_MINOR_CONTACTABLE_PUBKEYS[0])
            .expect("pinned official pubkey 0 must be valid hex"),
        PublicKey::from_hex(PINNED_MINOR_CONTACTABLE_PUBKEYS[1])
            .expect("pinned official pubkey 1 must be valid hex"),
    ]
});

/// A recipient is approved iff it is the user themselves (self-DMs cannot
/// exfiltrate: only the user can decrypt them, and NIP-17 requires a
/// self-addressed copy of every send) or one of the pinned officials.
fn is_approved(user_pubkey: &PublicKey, candidate: &PublicKey) -> bool {
    candidate == user_pubkey || PINNED_KEYS.contains(candidate)
}

/// Whether signing `kind` is subject to the verified_minor DM gate at all.
/// Kinds outside this set sign normally for minors (public posting is
/// relay-moderated and out of #183's scope).
pub fn is_minor_gated_kind(kind: Kind) -> bool {
    matches!(kind.as_u16(), 4 | 13 | 14 | 15 | 1059)
}

/// Gate for the encryption primitives (`nip04_encrypt` / `nip44_encrypt`):
/// a verified_minor may encrypt only to themselves or a pinned official.
pub fn validate_minor_encrypt(
    user_pubkey: &PublicKey,
    recipient: &PublicKey,
) -> Result<(), MinorDmDenied> {
    if is_approved(user_pubkey, recipient) {
        Ok(())
    } else {
        Err(MinorDmDenied::RecipientNotApproved)
    }
}

/// Gate for `sign_event`: refuse DM-shaped events whose recipients fall
/// outside the approved set. Non-DM kinds pass through untouched.
///
/// Takes the user's [`Keys`] (not just the pubkey) because a kind-13 seal
/// names no recipient — recovering it requires trial-decrypting the content
/// under the user's conversation keys with each approved pubkey.
pub fn validate_minor_sign(user_keys: &Keys, event: &UnsignedEvent) -> Result<(), MinorDmDenied> {
    match event.kind.as_u16() {
        4 | 14 | 15 | 1059 => {
            validate_p_tag_recipients(&user_keys.public_key(), event.tags.as_slice())
        }
        13 => validate_seal(user_keys, &event.content),
        _ => Ok(()),
    }
}

/// Every `p` tag must carry a parseable, approved pubkey, and at least one
/// `p` tag must be present — a DM shape with no recipient is unresolvable and
/// therefore refused.
fn validate_p_tag_recipients(
    user_pubkey: &PublicKey,
    tags: &[Tag],
) -> Result<(), MinorDmDenied> {
    let mut found_recipient = false;
    for tag in tags {
        let slice = tag.as_slice();
        if slice.first().map(String::as_str) != Some("p") {
            continue;
        }
        found_recipient = true;
        let recipient = slice
            .get(1)
            .and_then(|hex| PublicKey::from_hex(hex).ok())
            .ok_or(MinorDmDenied::RecipientUnresolvable)?;
        if !is_approved(user_pubkey, &recipient) {
            return Err(MinorDmDenied::RecipientNotApproved);
        }
    }
    if found_recipient {
        Ok(())
    } else {
        Err(MinorDmDenied::RecipientUnresolvable)
    }
}

/// A kind-13 seal's true recipient is whoever holds the other half of the
/// NIP-44 conversation key its content was encrypted under. NIP-44 v2 is
/// authenticated (HMAC), so trial decryption against the small approved set
/// deterministically recovers the recipient — or proves it is not approved.
fn validate_seal(user_keys: &Keys, content: &str) -> Result<(), MinorDmDenied> {
    let user_pubkey = user_keys.public_key();
    let candidates = [user_pubkey, PINNED_KEYS[0], PINNED_KEYS[1]];
    for candidate in &candidates {
        if let Ok(plaintext) = nip44::decrypt(user_keys.secret_key(), candidate, content) {
            return validate_sealed_rumor(&user_pubkey, &plaintext);
        }
    }
    Err(MinorDmDenied::SealNotDecryptable)
}

/// The decrypted seal payload must be an event-shaped JSON object whose `p`
/// tags (the rumor's stated recipients, possibly a group) are all approved.
/// No `p` tags is fine: the actual recipient is already proven by which
/// conversation key decrypted the seal.
fn validate_sealed_rumor(
    user_pubkey: &PublicKey,
    plaintext: &str,
) -> Result<(), MinorDmDenied> {
    let rumor: serde_json::Value =
        serde_json::from_str(plaintext).map_err(|_| MinorDmDenied::SealRumorInvalid)?;
    let tags = rumor
        .get("tags")
        .and_then(|tags| tags.as_array())
        .ok_or(MinorDmDenied::SealRumorInvalid)?;
    for tag in tags {
        let tag = tag.as_array().ok_or(MinorDmDenied::SealRumorInvalid)?;
        if tag.first().and_then(|name| name.as_str()) != Some("p") {
            continue;
        }
        let recipient = tag
            .get(1)
            .and_then(|hex| hex.as_str())
            .and_then(|hex| PublicKey::from_hex(hex).ok())
            .ok_or(MinorDmDenied::SealRumorInvalid)?;
        if !is_approved(user_pubkey, &recipient) {
            return Err(MinorDmDenied::RecipientNotApproved);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::nips::nip44;
    use nostr_sdk::{EventBuilder, Kind, Tag, TagKind};
    use serde_json::json;

    fn hq_pubkey() -> PublicKey {
        PublicKey::from_hex(PINNED_MINOR_CONTACTABLE_PUBKEYS[0]).unwrap()
    }

    fn moderation_pubkey() -> PublicKey {
        PublicKey::from_hex(PINNED_MINOR_CONTACTABLE_PUBKEYS[1]).unwrap()
    }

    /// Build an unsigned event of `kind` authored by `author` with one `p` tag
    /// per recipient.
    fn dm_shaped_event(kind: u16, author: &Keys, recipients: &[PublicKey]) -> UnsignedEvent {
        let tags: Vec<Tag> = recipients.iter().map(|pk| Tag::public_key(*pk)).collect();
        EventBuilder::new(Kind::from(kind), "test message")
            .tags(tags)
            .build(author.public_key())
    }

    /// Serialized kind-14 rumor JSON from `author` to `recipients`, the way a
    /// client serializes the unsigned rumor before sealing it.
    fn rumor_json(author: &Keys, recipients: &[PublicKey]) -> String {
        let tags: Vec<Vec<String>> = recipients
            .iter()
            .map(|pk| vec!["p".to_string(), pk.to_hex()])
            .collect();
        json!({
            "id": "0000000000000000000000000000000000000000000000000000000000000000",
            "pubkey": author.public_key().to_hex(),
            "created_at": 1_700_000_000,
            "kind": 14,
            "tags": tags,
            "content": "sealed message",
        })
        .to_string()
    }

    /// Build a kind-13 seal event for `user` whose content is `plaintext`
    /// NIP-44-encrypted under the conversation key (encrypt_secret, encrypt_to).
    fn seal_event(
        user: &Keys,
        encrypt_secret: &nostr_sdk::SecretKey,
        encrypt_to: &PublicKey,
        plaintext: &str,
    ) -> UnsignedEvent {
        let content =
            nip44::encrypt(encrypt_secret, encrypt_to, plaintext, nip44::Version::V2).unwrap();
        EventBuilder::new(Kind::from(13u16), content).build(user.public_key())
    }

    // -- gated-kind classification --------------------------------------------

    #[test]
    fn gated_kinds_are_dm_shapes_only() {
        for kind in [4u16, 13, 14, 15, 1059] {
            assert!(is_minor_gated_kind(Kind::from(kind)), "kind {kind}");
        }
        for kind in [0u16, 1, 3, 6, 7, 30023, 10050, 24133] {
            assert!(!is_minor_gated_kind(Kind::from(kind)), "kind {kind}");
        }
    }

    // -- encrypt gate ----------------------------------------------------------

    #[test]
    fn minor_may_encrypt_to_pinned_officials() {
        let user = Keys::generate();
        assert_eq!(
            validate_minor_encrypt(&user.public_key(), &hq_pubkey()),
            Ok(())
        );
        assert_eq!(
            validate_minor_encrypt(&user.public_key(), &moderation_pubkey()),
            Ok(())
        );
    }

    #[test]
    fn minor_may_encrypt_to_self() {
        let user = Keys::generate();
        assert_eq!(
            validate_minor_encrypt(&user.public_key(), &user.public_key()),
            Ok(())
        );
    }

    #[test]
    fn minor_may_not_encrypt_to_arbitrary_recipient() {
        let user = Keys::generate();
        let mallory = Keys::generate();
        assert_eq!(
            validate_minor_encrypt(&user.public_key(), &mallory.public_key()),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    // -- sign gate: non-DM kinds untouched --------------------------------------

    #[test]
    fn non_dm_kinds_sign_normally_even_with_arbitrary_p_tags() {
        let user = Keys::generate();
        let mallory = Keys::generate();
        // Kind 1 note mentioning an arbitrary pubkey: public posting, not a DM.
        let event = dm_shaped_event(1, &user, &[mallory.public_key()]);
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    // -- sign gate: p-tag kinds (4 / 14 / 15 / 1059) ----------------------------

    #[test]
    fn rumor_to_pinned_official_is_allowed() {
        let user = Keys::generate();
        let event = dm_shaped_event(14, &user, &[hq_pubkey()]);
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    #[test]
    fn rumor_to_arbitrary_recipient_is_refused() {
        let user = Keys::generate();
        let mallory = Keys::generate();
        let event = dm_shaped_event(14, &user, &[mallory.public_key()]);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    #[test]
    fn group_rumor_including_one_unapproved_recipient_is_refused() {
        // All-or-nothing, matching the clients' group send semantics.
        let user = Keys::generate();
        let mallory = Keys::generate();
        let event = dm_shaped_event(14, &user, &[hq_pubkey(), mallory.public_key()]);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    #[test]
    fn rumor_without_p_tags_is_refused_fail_closed() {
        let user = Keys::generate();
        let event = dm_shaped_event(14, &user, &[]);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientUnresolvable)
        );
    }

    #[test]
    fn file_message_rumor_kind_15_is_gated_like_kind_14() {
        let user = Keys::generate();
        let mallory = Keys::generate();
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(15, &user, &[hq_pubkey()])),
            Ok(())
        );
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(15, &user, &[mallory.public_key()])),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    #[test]
    fn nip04_dm_kind_4_is_gated_by_p_tags() {
        let user = Keys::generate();
        let mallory = Keys::generate();
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(4, &user, &[moderation_pubkey()])),
            Ok(())
        );
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(4, &user, &[mallory.public_key()])),
            Err(MinorDmDenied::RecipientNotApproved)
        );
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(4, &user, &[])),
            Err(MinorDmDenied::RecipientUnresolvable)
        );
    }

    #[test]
    fn gift_wrap_kind_1059_is_gated_by_p_tags() {
        let user = Keys::generate();
        let mallory = Keys::generate();
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(1059, &user, &[hq_pubkey()])),
            Ok(())
        );
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(1059, &user, &[mallory.public_key()])),
            Err(MinorDmDenied::RecipientNotApproved)
        );
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(1059, &user, &[])),
            Err(MinorDmDenied::RecipientUnresolvable)
        );
    }

    #[test]
    fn dm_with_malformed_p_tag_is_refused_fail_closed() {
        let user = Keys::generate();
        let tag = Tag::custom(TagKind::custom("p"), ["not-a-valid-pubkey"]);
        let event = EventBuilder::new(Kind::from(14u16), "hi")
            .tags([tag])
            .build(user.public_key());
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientUnresolvable)
        );
    }

    #[test]
    fn dm_p_tag_with_relay_hint_extra_elements_still_validates() {
        // ["p", "<hex>", "<relay-url>"] is a legal NIP-10-style tag form.
        let user = Keys::generate();
        let tag = Tag::parse([
            "p".to_string(),
            hq_pubkey().to_hex(),
            "wss://relay.example.com".to_string(),
        ])
        .unwrap();
        let event = EventBuilder::new(Kind::from(14u16), "hi")
            .tags([tag])
            .build(user.public_key());
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    // -- sign gate: kind-13 seal (trial decryption) ------------------------------

    #[test]
    fn seal_to_pinned_official_is_allowed() {
        // The legit custodial flow: rumor NIP-44-encrypted to HQ via the
        // (gated) encrypt primitive, then the seal is signed.
        let user = Keys::generate();
        let rumor = rumor_json(&user, &[hq_pubkey()]);
        let event = seal_event(&user, user.secret_key(), &hq_pubkey(), &rumor);
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    #[test]
    fn seal_to_self_is_allowed_for_own_history_copy() {
        // NIP-17 wraps every message to the sender as well (own history copy).
        let user = Keys::generate();
        let rumor = rumor_json(&user, &[hq_pubkey()]);
        let event = seal_event(&user, user.secret_key(), &user.public_key(), &rumor);
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    #[test]
    fn seal_encrypted_to_arbitrary_recipient_is_refused() {
        // Seal produced for a non-approved conversation key (e.g. the client
        // colluding with the counterparty who derived the conversation key
        // out-of-band): must not be signable.
        let user = Keys::generate();
        let mallory = Keys::generate();
        let rumor = rumor_json(&user, &[mallory.public_key()]);
        // K(mallory_sk, user_pk) == K(user_sk, mallory_pk): ciphertext readable
        // by mallory, produced without ever calling our encrypt primitive.
        let event = seal_event(&user, mallory.secret_key(), &user.public_key(), &rumor);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::SealNotDecryptable)
        );
    }

    #[test]
    fn seal_with_garbage_content_is_refused_fail_closed() {
        let user = Keys::generate();
        let event =
            EventBuilder::new(Kind::from(13u16), "not-nip44-ciphertext").build(user.public_key());
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::SealNotDecryptable)
        );
    }

    #[test]
    fn seal_to_official_whose_rumor_names_unapproved_recipient_is_refused() {
        // Group all-or-nothing at the seal layer: decrypts under the HQ
        // conversation key but the inner rumor also names mallory.
        let user = Keys::generate();
        let mallory = Keys::generate();
        let rumor = rumor_json(&user, &[hq_pubkey(), mallory.public_key()]);
        let event = seal_event(&user, user.secret_key(), &hq_pubkey(), &rumor);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    #[test]
    fn seal_whose_plaintext_is_not_event_json_is_refused() {
        let user = Keys::generate();
        let event = seal_event(&user, user.secret_key(), &hq_pubkey(), "not json at all");
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::SealRumorInvalid)
        );
    }

    #[test]
    fn seal_whose_rumor_has_no_p_tags_is_allowed() {
        // The recipient is already proven by which conversation key decrypted
        // the content; an inner rumor without p tags (e.g. a self-addressed
        // application-data rumor) adds no additional recipients.
        let user = Keys::generate();
        let rumor = rumor_json(&user, &[]);
        let event = seal_event(&user, user.secret_key(), &hq_pubkey(), &rumor);
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    #[test]
    fn seal_rumor_with_malformed_p_tag_is_refused_fail_closed() {
        let user = Keys::generate();
        let rumor = json!({
            "id": "0000000000000000000000000000000000000000000000000000000000000000",
            "pubkey": user.public_key().to_hex(),
            "created_at": 1_700_000_000,
            "kind": 14,
            "tags": [["p", "zzz-not-a-pubkey"]],
            "content": "sealed message",
        })
        .to_string();
        let event = seal_event(&user, user.secret_key(), &hq_pubkey(), &rumor);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::SealRumorInvalid)
        );
    }
}
