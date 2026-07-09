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
