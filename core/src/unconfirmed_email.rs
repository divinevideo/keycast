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

use nostr_sdk::Kind;
use std::sync::{Arc, RwLock};

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

// ============================================================================
// Hourly caps until confirmation
// ============================================================================

/// Machine-readable code returned when an unconfirmed account hits a cap.
pub const UNCONFIRMED_RATE_LIMITED_CODE: &str = "UNCONFIRMED_RATE_LIMITED";
/// Client-facing message for [`UNCONFIRMED_RATE_LIMITED_CODE`].
pub const UNCONFIRMED_RATE_LIMITED_MESSAGE: &str =
    "You've hit the limit for accounts that haven't confirmed their email. Confirm your email to lift it, or try again later.";

/// What an event counts against while its author's email is unconfirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapCategory {
    /// Video posts (NIP-71 kinds 21/22, Divine's addressable 34235/34236).
    Post,
    /// Comments and text notes (kinds 1111 and 1).
    Comment,
    /// Reports (NIP-56 kind 1984).
    Report,
}

impl CapCategory {
    /// Every category, in a stable order for metrics.
    pub const ALL: [CapCategory; 3] =
        [CapCategory::Post, CapCategory::Comment, CapCategory::Report];

    /// Stable label for keys, logs and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CapCategory::Post => "post",
            CapCategory::Comment => "comment",
            CapCategory::Report => "report",
        }
    }
}

/// The cap an event kind counts against, or `None` for uncapped kinds
/// (reactions, reposts, follows, profiles, lists, deletions, everything else).
#[must_use]
pub fn cap_category(kind: Kind) -> Option<CapCategory> {
    match kind.as_u16() {
        21 | 22 | 34235 | 34236 => Some(CapCategory::Post),
        1 | 1111 => Some(CapCategory::Comment),
        1984 => Some(CapCategory::Report),
        _ => None,
    }
}

/// Outcome of counting one signed event against its cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapAdmission {
    /// The event may be returned.
    Admitted,
    /// The window is full.
    Limited {
        /// Whole seconds until the oldest counted event leaves the window.
        retry_after: u32,
    },
}

/// Counts signed events for unconfirmed accounts. Implemented over Redis in
/// the API crate and installed once at startup with [`install_caps`], so every
/// signing path — HTTP RPC, `/api/user/sign` and the NIP-46 signer daemon —
/// shares one limiter.
#[async_trait::async_trait]
pub trait UnconfirmedCaps: Send + Sync {
    /// Count one event in `category` for `pubkey_hex`. Implementations fail
    /// open: an unavailable backend admits.
    async fn admit(&self, tenant_id: i64, pubkey_hex: &str, category: CapCategory) -> CapAdmission;
}

static CAPS: RwLock<Option<Arc<dyn UnconfirmedCaps>>> = RwLock::new(None);

/// Install the process-wide limiter, replacing any installed before. Production
/// installs once at startup; tests install their own per test.
pub fn install_caps(caps: Arc<dyn UnconfirmedCaps>) {
    *CAPS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(caps);
}

fn installed_caps() -> Option<Arc<dyn UnconfirmedCaps>> {
    CAPS.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Count a just-signed event for an account, if the cap applies to it.
///
/// Admits without counting when the account's email is confirmed (or absent),
/// when the kind is uncapped, or when no limiter is installed. Call it after the
/// event is signed and every other check has passed, so an event refused for any
/// other reason never spends the budget.
pub async fn admit_signed_event(
    tenant_id: i64,
    pubkey_hex: &str,
    kind: Kind,
    gates: DmGates,
) -> CapAdmission {
    if !gates.email_unconfirmed {
        return CapAdmission::Admitted;
    }
    let (Some(category), Some(caps)) = (cap_category(kind), installed_caps()) else {
        return CapAdmission::Admitted;
    };
    caps.admit(tenant_id, pubkey_hex, category).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_kinds_count_as_posts() {
        for kind in [21u16, 22, 34235, 34236] {
            assert_eq!(
                cap_category(Kind::from(kind)),
                Some(CapCategory::Post),
                "{kind}"
            );
        }
    }

    #[test]
    fn comments_and_reports_have_their_own_caps() {
        assert_eq!(cap_category(Kind::from(1u16)), Some(CapCategory::Comment));
        assert_eq!(
            cap_category(Kind::from(1111u16)),
            Some(CapCategory::Comment)
        );
        assert_eq!(cap_category(Kind::from(1984u16)), Some(CapCategory::Report));
    }

    #[test]
    fn everyday_actions_are_uncapped() {
        for kind in [0u16, 3, 5, 6, 7, 16, 10000, 30000, 22236] {
            assert_eq!(cap_category(Kind::from(kind)), None, "{kind}");
        }
    }

    #[tokio::test]
    async fn a_confirmed_account_is_never_counted() {
        let gates = DmGates::default();
        assert_eq!(
            admit_signed_event(1, "pubkey", Kind::from(34236u16), gates).await,
            CapAdmission::Admitted
        );
    }

    #[test]
    fn contained_when_either_gate_applies() {
        assert!(!DmGates::default().contained());
        assert!(DmGates {
            verified_minor: true,
            email_unconfirmed: false
        }
        .contained());
        assert!(DmGates {
            verified_minor: false,
            email_unconfirmed: true
        }
        .contained());
    }
}
