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
//! The recipient of a DM is bound by whoever can *decrypt* it, not by the
//! attacker-controlled `p` tag: the NIP-44 / NIP-04 conversation key is
//! *symmetric* ECDH, so a colluding non-approved party can compute the
//! minor↔them key from their own secret and the minor's public key and forge
//! minor-keyed ciphertext without ever calling Keycast. Binding on the `p` tag
//! alone is therefore spoofable. Each shape is gated at the point its true
//! recipient is actually determinable:
//!
//! * `nip04_encrypt` / `nip44_encrypt`: recipient must be the user or pinned.
//!   This is the primitive that produces DM ciphertext, so it blocks a
//!   non-colluding minor from encrypting to a stranger at all.
//! * `sign_event` kind 13 (NIP-59 seal): the seal names no recipient — its
//!   content is NIP-44 ciphertext under the conversation key of the *unstated*
//!   receiver. The recipient is recovered by trial-decrypting against the
//!   user's conversation keys with each approved pubkey (NIP-44 v2 is
//!   authenticated, so this is deterministic); the inner rumor's `p` tags and
//!   the seal's own `p` tags must also all be approved. This is the real NIP-17
//!   containment point.
//! * `sign_event` kind 4 (NIP-04 DM): a complete, normal-client-rendered DM
//!   whose recipient IS the `p` tag (NIP-04 content is unauthenticated, so the
//!   reader cannot be verified by decryption). Every `p` tag must be approved,
//!   which keeps a minor-signed kind-4 facially addressed to an approved party.
//! * `sign_event` kinds 14/15 (NIP-17 rumor) and 1059 (gift wrap): **refused
//!   outright.** A conformant client never asks a remote signer to sign these
//!   with the user's key (rumors are unsigned; wraps use a one-time ephemeral
//!   key), so a `p`-tag check there is pure false confidence. The legitimate
//!   NIP-17 DM to an approved official flows through `nip44_encrypt` (gated) +
//!   the kind-13 seal (gated).
//!
//! Decrypt/unwrap (ingress) is intentionally untouched — #183 scopes
//! containment to egress.
//!
//! Fail closed: an unresolvable recipient, an unparseable `p` tag, a seal that
//! decrypts to nothing, or an unverifiable DM-carrier kind is a refusal, never
//! a pass-through.
//!
//! # Accepted ceiling
//!
//! A minor can freely sign public posts (e.g. kind 1), whose content is
//! arbitrary — so a minor + a colluding recipient can always steganographically
//! encode a payload the recipient extracts out-of-band. No server-side gate can
//! close that (it is not a DM shape any normal client renders as a DM). This
//! gate's job is narrower and achievable: Keycast will not produce a DM-shaped,
//! normal-client-deliverable artifact addressed to a non-approved recipient.

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
    /// A DM-carrier kind (NIP-17 rumor 14/15, gift wrap 1059) whose recipient
    /// cannot be verified at signing time and which a conformant client never
    /// asks a remote signer to sign — refused outright. See [`validate_minor_sign`].
    UnverifiableDmKind,
}

impl std::fmt::Display for MinorDmDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            MinorDmDenied::RecipientNotApproved => "recipient not in approved set",
            MinorDmDenied::RecipientUnresolvable => "recipient unresolvable",
            MinorDmDenied::SealNotDecryptable => "seal not decryptable to an approved recipient",
            MinorDmDenied::SealRumorInvalid => "sealed rumor malformed",
            MinorDmDenied::UnverifiableDmKind => "DM-carrier kind not signable by a minor",
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
///
/// Recipient binding differs by shape, because binding the *spoofable `p` tag*
/// alone is not containment (the NIP-44 / NIP-04 conversation key is symmetric
/// ECDH, so a colluding non-approved party can forge minor-keyed ciphertext and
/// hide it behind a decoy approved `p` tag):
///
/// - **kind 4 (NIP-04 DM)** is a complete, normal-client-rendered DM whose
///   recipient IS the `p` tag; NIP-04 content is unauthenticated AES-CBC, so we
///   cannot verify the true reader by decryption. We require the `p` tag(s)
///   approved, which keeps a minor-signed kind-4 facially addressed to an
///   approved party; the gated `nip04_encrypt` primitive blocks producing the
///   ciphertext for a non-colluding stranger. Residual: a colluding recipient
///   can still read a decoy-`p`-tagged payload — the public-post steganography
///   ceiling, reachable via any signable kind (e.g. a plain kind-1 note) and
///   not closable server-side.
/// - **kind 13 (NIP-59 seal)** names no recipient; we recover it by
///   trial-decrypting the content against the approved conversation keys
///   (authenticated NIP-44 v2 makes this deterministic). This is the real
///   NIP-17 containment point.
/// - **kinds 14/15 (NIP-17 rumor) and 1059 (gift wrap)** are refused outright.
///   A conformant client NEVER asks a remote signer to sign these with the
///   user's key: rumors are unsigned (NIP-59), and gift wraps are signed by a
///   one-time ephemeral key, not the sender's. Signing one with the minor's key
///   only serves a covert channel, and a `p`-tag check there is pure false
///   confidence (see above). The legitimate NIP-17 DM to an approved official
///   flows entirely through `nip44_encrypt` (gated) + the kind-13 seal (gated).
pub fn validate_minor_sign(user_keys: &Keys, event: &UnsignedEvent) -> Result<(), MinorDmDenied> {
    match event.kind.as_u16() {
        4 => validate_p_tag_recipients(&user_keys.public_key(), event.tags.as_slice()),
        13 => validate_seal(user_keys, event),
        14 | 15 | 1059 => Err(MinorDmDenied::UnverifiableDmKind),
        _ => Ok(()),
    }
}

/// Every `p` tag must carry a parseable, approved pubkey, and at least one
/// `p` tag must be present — a DM shape with no recipient is unresolvable and
/// therefore refused.
fn validate_p_tag_recipients(user_pubkey: &PublicKey, tags: &[Tag]) -> Result<(), MinorDmDenied> {
    let has_p_tag = tags
        .iter()
        .any(|tag| tag.as_slice().first().map(String::as_str) == Some("p"));
    if !has_p_tag {
        return Err(MinorDmDenied::RecipientUnresolvable);
    }
    validate_p_tags_approved(user_pubkey, tags)
}

/// A kind-13 seal's true recipient is whoever holds the other half of the
/// NIP-44 conversation key its content was encrypted under. NIP-44 v2 is
/// authenticated (HMAC), so trial decryption against the small approved set
/// deterministically recovers the recipient — or proves it is not approved.
///
/// Per NIP-59 a seal carries no tags, but any `p` tags a client does attach
/// would become relay-routable metadata, so they must be approved too (a
/// near-free defense-in-depth check; content stays bound by decryption). The
/// crypto here (≤3 ECDH + HKDF + a bounded NIP-44 decrypt) runs inline: it is
/// sub-millisecond and bounded, unlike the unwrap-batch path that fans out.
fn validate_seal(user_keys: &Keys, event: &UnsignedEvent) -> Result<(), MinorDmDenied> {
    let user_pubkey = user_keys.public_key();
    validate_p_tags_approved(&user_pubkey, event.tags.as_slice())?;
    let candidates = [user_pubkey, PINNED_KEYS[0], PINNED_KEYS[1]];
    for candidate in &candidates {
        if let Ok(plaintext) = nip44::decrypt(user_keys.secret_key(), candidate, &event.content) {
            return validate_sealed_rumor(&user_pubkey, &plaintext);
        }
    }
    Err(MinorDmDenied::SealNotDecryptable)
}

/// Reject any `p` tag that is not a parseable, approved pubkey. Unlike
/// [`validate_p_tag_recipients`], zero `p` tags is fine here — used where the
/// recipient is established by other means (the seal's decryption target).
fn validate_p_tags_approved(user_pubkey: &PublicKey, tags: &[Tag]) -> Result<(), MinorDmDenied> {
    for tag in tags {
        let slice = tag.as_slice();
        if slice.first().map(String::as_str) != Some("p") {
            continue;
        }
        let recipient = slice
            .get(1)
            .and_then(|hex| PublicKey::from_hex(hex).ok())
            .ok_or(MinorDmDenied::RecipientUnresolvable)?;
        if !is_approved(user_pubkey, &recipient) {
            return Err(MinorDmDenied::RecipientNotApproved);
        }
    }
    Ok(())
}

/// The decrypted seal payload must be an event-shaped JSON object whose `p`
/// tags (the rumor's stated recipients, possibly a group) are all approved.
/// No `p` tags is fine: the actual recipient is already proven by which
/// conversation key decrypted the seal.
fn validate_sealed_rumor(user_pubkey: &PublicKey, plaintext: &str) -> Result<(), MinorDmDenied> {
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

    // -- sign gate: rumor/wrap kinds (14 / 15 / 1059) refused outright ----------
    //
    // A conformant client never asks a remote signer to sign these with the
    // user's key (rumors are unsigned; wraps use a one-time ephemeral key), and
    // a `p`-tag check on them is spoofable (symmetric ECDH). So they are refused
    // regardless of recipient — closing the decoy-`p`-tag covert channel.

    #[test]
    fn rumor_kind_14_refused_outright_even_to_pinned_official() {
        let user = Keys::generate();
        let event = dm_shaped_event(14, &user, &[hq_pubkey()]);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::UnverifiableDmKind)
        );
    }

    #[test]
    fn file_message_kind_15_refused_outright() {
        let user = Keys::generate();
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(15, &user, &[hq_pubkey()])),
            Err(MinorDmDenied::UnverifiableDmKind)
        );
    }

    #[test]
    fn gift_wrap_kind_1059_refused_outright() {
        let user = Keys::generate();
        assert_eq!(
            validate_minor_sign(&user, &dm_shaped_event(1059, &user, &[hq_pubkey()])),
            Err(MinorDmDenied::UnverifiableDmKind)
        );
    }

    #[test]
    fn gift_wrap_with_decoy_approved_p_tag_is_refused_bypass_closed() {
        // The bypass the adversarial review found: a 1059 whose content is
        // ciphertext readable by a colluding non-approved party, hidden behind a
        // decoy approved `p` tag. Refusing 1059 outright closes it — a p-tag
        // check would have PASSED this and signed a covert channel.
        let user = Keys::generate();
        let event = dm_shaped_event(1059, &user, &[hq_pubkey()]);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::UnverifiableDmKind)
        );
    }

    // -- sign gate: NIP-04 DM (kind 4) stays p-tag-gated ------------------------

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
    fn nip04_group_including_one_unapproved_recipient_is_refused() {
        // All-or-nothing across p tags.
        let user = Keys::generate();
        let mallory = Keys::generate();
        let event = dm_shaped_event(4, &user, &[hq_pubkey(), mallory.public_key()]);
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    #[test]
    fn nip04_with_malformed_p_tag_is_refused_fail_closed() {
        let user = Keys::generate();
        let tag = Tag::custom(TagKind::custom("p"), ["not-a-valid-pubkey"]);
        let event = EventBuilder::new(Kind::from(4u16), "hi")
            .tags([tag])
            .build(user.public_key());
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientUnresolvable)
        );
    }

    #[test]
    fn nip04_p_tag_with_relay_hint_extra_elements_still_validates() {
        // ["p", "<hex>", "<relay-url>"] is a legal NIP-10-style tag form.
        let user = Keys::generate();
        let tag = Tag::parse([
            "p".to_string(),
            hq_pubkey().to_hex(),
            "wss://relay.example.com".to_string(),
        ])
        .unwrap();
        let event = EventBuilder::new(Kind::from(4u16), "hi")
            .tags([tag])
            .build(user.public_key());
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    #[test]
    fn non_dm_kind_1_ignores_content_and_p_tags() {
        // Public posting is out of scope: a kind-1 note may carry any content
        // (including arbitrary ciphertext) and any p tags — the steganography
        // ceiling lives here and is not closable server-side.
        let user = Keys::generate();
        let mallory = Keys::generate();
        let event = dm_shaped_event(1, &user, &[mallory.public_key()]);
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }

    #[test]
    fn gated_kind_set_matches_validator_arms() {
        // Anti-drift (M2): every kind is_minor_gated_kind marks must be actively
        // handled by validate_minor_sign (never fall to the permissive `_` arm),
        // and every non-gated kind must pass even when DM-shaped. Uses a garbage
        // seal for 13 (fails closed) and an unapproved p tag for 4.
        let user = Keys::generate();
        let mallory = Keys::generate();
        for kind in 0u16..=1100 {
            let gated = is_minor_gated_kind(Kind::from(kind));
            let event = if kind == 13 {
                EventBuilder::new(Kind::from(13u16), "not-ciphertext").build(user.public_key())
            } else {
                dm_shaped_event(kind, &user, &[mallory.public_key()])
            };
            let result = validate_minor_sign(&user, &event);
            assert_eq!(
                result.is_err(),
                gated,
                "kind {kind}: gated={gated} but validator result={result:?}"
            );
        }
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

    #[test]
    fn seal_with_unapproved_outer_p_tag_is_refused() {
        // M1: a seal decrypting to an approved recipient but carrying an
        // unapproved `p` tag on the seal EVENT itself (relay-routable metadata)
        // is refused before any decryption.
        let user = Keys::generate();
        let mallory = Keys::generate();
        let rumor = rumor_json(&user, &[hq_pubkey()]);
        let content =
            nip44::encrypt(user.secret_key(), &hq_pubkey(), &rumor, nip44::Version::V2).unwrap();
        let event = EventBuilder::new(Kind::from(13u16), content)
            .tags([Tag::public_key(mallory.public_key())])
            .build(user.public_key());
        assert_eq!(
            validate_minor_sign(&user, &event),
            Err(MinorDmDenied::RecipientNotApproved)
        );
    }

    #[test]
    fn seal_with_approved_outer_p_tag_is_allowed() {
        // The benign case of the M1 check: an outer `p` tag naming the approved
        // recipient (as some clients do for routing) does not trip the gate.
        let user = Keys::generate();
        let rumor = rumor_json(&user, &[hq_pubkey()]);
        let content =
            nip44::encrypt(user.secret_key(), &hq_pubkey(), &rumor, nip44::Version::V2).unwrap();
        let event = EventBuilder::new(Kind::from(13u16), content)
            .tags([Tag::public_key(hq_pubkey())])
            .build(user.public_key());
        assert_eq!(validate_minor_sign(&user, &event), Ok(()));
    }
}
