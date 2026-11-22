// ABOUTME: Server-side limits for accounts that signed in before confirming their email.
// ABOUTME: DM egress uses the protected-minor containment rules; refusals carry their own code.

//! Accounts created with instant access can sign in before their email is
//! confirmed. Until they confirm, Keycast refuses to produce direct messages
//! for them, so the lock holds for every client — older app builds, modified
//! clients and direct API calls — not only the app that shows the nudge.
//!
//! The rules are exactly the protected-minor containment gate's
//! ([`crate::verified_minor_dm`]): the same DM shapes are gated at the same
//! points, and the same recipients stay reachable — the account itself and the
//! pinned Divine HQ and Moderation accounts, so someone who has not confirmed
//! yet can still ask for help or appeal. Decryption is ingress and untouched,
//! so people can still read what they were sent. Only the refusal differs: it
//! carries [`EMAIL_NOT_CONFIRMED_CODE`] so the client can explain it, where the
//! minor refusal stays deliberately non-specific.
//!
//! The gate applies only to an account that *has* an email that is not
//! confirmed. An account with no email at all — preloaded, imported, or one
//! whose unconfirmed address was handed to the person who confirmed it — is
//! not gated: there is nothing left for it to confirm.

/// Machine-readable code returned when an unconfirmed account tries to DM.
pub const EMAIL_NOT_CONFIRMED_CODE: &str = "EMAIL_NOT_CONFIRMED";
/// Client-facing message for [`EMAIL_NOT_CONFIRMED_CODE`].
pub const EMAIL_NOT_CONFIRMED_MESSAGE: &str = "Confirm your email to send direct messages.";

/// The DM gates that apply to one account, read from its users row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DmGates {
    /// Approved protected minor (13-15): contained to the pinned officials.
    pub verified_minor: bool,
    /// Has an email that is not confirmed: contained to the pinned officials
    /// until it is.
    pub email_unconfirmed: bool,
}

impl DmGates {
    /// Whether any containment applies.
    #[must_use]
    pub fn contained(self) -> bool {
        self.verified_minor || self.email_unconfirmed
    }
}

/// SQL expression for [`DmGates::email_unconfirmed`] over a `users` row.
///
/// `email_verified` is nullable; only an explicit `false` beside a stored email
/// counts as unconfirmed, so a legacy row with no answer is never locked out.
pub const EMAIL_UNCONFIRMED_SQL: &str =
    "COALESCE(email IS NOT NULL AND email_verified = false, false)";
