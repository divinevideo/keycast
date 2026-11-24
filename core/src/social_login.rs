// ABOUTME: Account resolution for "Continue with Google / Apple"
// ABOUTME: Signs in, links by verified email, or creates a custodial account for a verified provider identity

use crate::encryption::KeyManager;
use crate::repositories::{
    CreateSocialAccountOutcome, EmailMatch, LinkSocialIdentityOutcome, NewSocialAccount,
    RepositoryError, UserIdentityRepository,
};
use nostr_sdk::Keys;
use sqlx::PgPool;
use std::fmt;

/// Identity providers that can sign a person in to a Keycast account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocialProvider {
    Google,
    Apple,
}

impl SocialProvider {
    /// Value stored in `user_identities.provider` and sent by clients.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Apple => "apple",
        }
    }

    /// Name shown to people, e.g. in emails.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Apple => "Apple",
        }
    }

    /// Parse the request value. Matching is exact: clients send lowercase names.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "google" => Some(Self::Google),
            "apple" => Some(Self::Apple),
            _ => None,
        }
    }
}

impl fmt::Display for SocialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A provider identity whose ID token has already been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSocialIdentity {
    pub provider: SocialProvider,
    /// The provider's stable user id (`sub`).
    pub subject: String,
    /// Normalized (lowercase) email, when the token carried a usable one.
    pub email: Option<String>,
    /// The provider says it verified the address.
    pub email_verified: bool,
    /// The provider is authoritative for the address, so it can be trusted to belong to this
    /// person today and not only when it was verified. Required before linking to an existing
    /// account by email.
    pub email_authoritative: bool,
}

/// How a verified identity was mapped to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialAccountResolution {
    /// The subject was already linked to this account.
    SignedIn { pubkey: String },
    /// The subject was linked to an existing account with the same verified email.
    Linked { pubkey: String, email: String },
    /// A new account was created for the subject. `released_accounts` names the unconfirmed
    /// accounts the email was removed from; usually none.
    Created {
        pubkey: String,
        released_accounts: Vec<String>,
    },
}

impl SocialAccountResolution {
    #[must_use]
    pub fn pubkey(&self) -> &str {
        match self {
            Self::SignedIn { pubkey }
            | Self::Linked { pubkey, .. }
            | Self::Created { pubkey, .. } => pubkey,
        }
    }

    /// Stable label for logs and audit metadata.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SignedIn { .. } => "signed_in",
            Self::Linked { .. } => "linked",
            Self::Created { .. } => "created",
        }
    }
}

/// Why an existing account with the same email cannot be linked automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRefusalReason {
    /// The provider verified the address but is not authoritative for it.
    ProviderEmailNotAuthoritative,
    /// Several confirmed accounts use the address in different letter case.
    AmbiguousEmail,
}

impl LinkRefusalReason {
    /// Stable label for logs and audit metadata.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProviderEmailNotAuthoritative => "provider_email_not_authoritative",
            Self::AmbiguousEmail => "ambiguous_email",
        }
    }
}

/// Outcomes that are answered to the person rather than treated as failures of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocialLoginRefusal {
    /// The token carries no usable email, so no account can be created.
    EmailMissing,
    /// The provider did not verify the email.
    EmailNotVerified,
    /// An account with this email exists but must be linked by signing in to it first.
    AccountLinkRequired(LinkRefusalReason),
}

#[derive(Debug, thiserror::Error)]
pub enum SocialLoginError {
    #[error("social login refused: {0:?}")]
    Refused(SocialLoginRefusal),
    #[error("key encryption failed: {0}")]
    Encryption(String),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// What to do with the accounts that share the provider's email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailDecision {
    /// Create an account. Any unconfirmed accounts with the email give it up.
    Create,
    Link(String),
    Refuse(LinkRefusalReason),
}

/// Decide between creating, linking and refusing from the accounts that share the email.
///
/// Only confirmed accounts count. An account that never confirmed its email cannot sign in, so
/// it does not hold the address against the provider sign-in. Linking happens only when exactly
/// one confirmed account matches and the provider is authoritative for the address; with none,
/// an account is created.
#[must_use]
pub fn decide_for_email_matches(
    matches: &[EmailMatch],
    email_authoritative: bool,
) -> EmailDecision {
    let confirmed: Vec<&EmailMatch> = matches.iter().filter(|m| m.email_verified).collect();
    match confirmed.as_slice() {
        [] => EmailDecision::Create,
        [_] if !email_authoritative => {
            EmailDecision::Refuse(LinkRefusalReason::ProviderEmailNotAuthoritative)
        }
        [only] => EmailDecision::Link(only.pubkey.clone()),
        _ => EmailDecision::Refuse(LinkRefusalReason::AmbiguousEmail),
    }
}

/// Resolution runs at most this many times. A second pass only happens when a concurrent
/// request created or linked the same email or subject between the read and the write.
const MAX_RESOLUTION_ATTEMPTS: usize = 2;

/// Map a verified provider identity to a Keycast account.
///
/// 1. A linked subject signs in to its account.
/// 2. Otherwise the email must be present and verified by the provider.
/// 3. No confirmed account with the email: a new account is created with a fresh Nostr key, and
///    accounts that never confirmed the email give it up.
/// 4. Exactly one confirmed account and an authoritative provider: the subject is linked to it.
/// 5. Anything else is refused with [`SocialLoginRefusal::AccountLinkRequired`].
pub async fn resolve_social_account(
    pool: &PgPool,
    key_manager: &dyn KeyManager,
    tenant_id: i64,
    identity: &VerifiedSocialIdentity,
) -> Result<SocialAccountResolution, SocialLoginError> {
    let repo = UserIdentityRepository::new(pool.clone());
    // Generated and encrypted at most once, outside every transaction.
    let mut new_key: Option<(String, Vec<u8>)> = None;

    for _ in 0..MAX_RESOLUTION_ATTEMPTS {
        if let Some(linked) = repo
            .find_by_subject(tenant_id, identity.provider, &identity.subject)
            .await?
        {
            repo.record_login(
                tenant_id,
                identity.provider,
                &identity.subject,
                identity.email.as_deref(),
            )
            .await?;
            return Ok(SocialAccountResolution::SignedIn {
                pubkey: linked.user_pubkey,
            });
        }

        let Some(email) = identity.email.as_deref() else {
            return Err(SocialLoginError::Refused(SocialLoginRefusal::EmailMissing));
        };
        if !identity.email_verified {
            return Err(SocialLoginError::Refused(
                SocialLoginRefusal::EmailNotVerified,
            ));
        }

        let matches = repo.find_users_by_email(tenant_id, email).await?;
        match decide_for_email_matches(&matches, identity.email_authoritative) {
            EmailDecision::Refuse(reason) => {
                return Err(SocialLoginError::Refused(
                    SocialLoginRefusal::AccountLinkRequired(reason),
                ));
            }
            EmailDecision::Link(pubkey) => {
                match repo
                    .link(
                        tenant_id,
                        &pubkey,
                        email,
                        identity.provider,
                        &identity.subject,
                    )
                    .await?
                {
                    LinkSocialIdentityOutcome::Linked => {
                        return Ok(SocialAccountResolution::Linked {
                            pubkey,
                            email: email.to_string(),
                        });
                    }
                    LinkSocialIdentityOutcome::AccountChanged
                    | LinkSocialIdentityOutcome::SubjectTaken => continue,
                }
            }
            EmailDecision::Create => {
                if new_key.is_none() {
                    new_key = Some(generate_encrypted_key(key_manager).await?);
                }
                let (pubkey, encrypted_secret) = new_key.as_ref().expect("key generated above");
                match repo
                    .create_account(NewSocialAccount {
                        tenant_id,
                        pubkey,
                        email,
                        encrypted_secret,
                        provider: identity.provider,
                        subject: &identity.subject,
                    })
                    .await?
                {
                    CreateSocialAccountOutcome::Created { released } => {
                        return Ok(SocialAccountResolution::Created {
                            pubkey: pubkey.clone(),
                            released_accounts: released,
                        });
                    }
                    CreateSocialAccountOutcome::EmailTaken
                    | CreateSocialAccountOutcome::SubjectTaken => continue,
                }
            }
        }
    }

    Err(SocialLoginError::Repository(RepositoryError::Unavailable(
        "social login resolution kept racing with concurrent requests".to_string(),
    )))
}

async fn generate_encrypted_key(
    key_manager: &dyn KeyManager,
) -> Result<(String, Vec<u8>), SocialLoginError> {
    let keys = Keys::generate();
    let encrypted = key_manager
        .encrypt(&keys.secret_key().to_secret_bytes())
        .await
        .map_err(|error| SocialLoginError::Encryption(error.to_string()))?;
    Ok((keys.public_key().to_hex(), encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email_match(pubkey: &str, verified: bool) -> EmailMatch {
        EmailMatch {
            pubkey: pubkey.to_string(),
            email: format!("{pubkey}@example.com"),
            email_verified: verified,
        }
    }

    #[test]
    fn provider_names_round_trip_and_reject_unknown_values() {
        for provider in [SocialProvider::Google, SocialProvider::Apple] {
            assert_eq!(SocialProvider::parse(provider.as_str()), Some(provider));
        }
        assert_eq!(SocialProvider::parse("Google"), None);
        assert_eq!(SocialProvider::parse("facebook"), None);
    }

    #[test]
    fn no_matching_account_creates_one() {
        assert_eq!(decide_for_email_matches(&[], false), EmailDecision::Create);
    }

    #[test]
    fn one_verified_account_links_only_with_an_authoritative_provider() {
        let matches = [email_match("a", true)];
        assert_eq!(
            decide_for_email_matches(&matches, true),
            EmailDecision::Link("a".to_string())
        );
        assert_eq!(
            decide_for_email_matches(&matches, false),
            EmailDecision::Refuse(LinkRefusalReason::ProviderEmailNotAuthoritative)
        );
    }

    #[test]
    fn unconfirmed_accounts_never_link_and_give_up_the_email() {
        for authoritative in [true, false] {
            assert_eq!(
                decide_for_email_matches(&[email_match("a", false)], authoritative),
                EmailDecision::Create
            );
            assert_eq!(
                decide_for_email_matches(
                    &[email_match("a", false), email_match("b", false)],
                    authoritative
                ),
                EmailDecision::Create
            );
        }
    }

    #[test]
    fn a_confirmed_account_links_whatever_unconfirmed_variants_exist() {
        let matches = [
            email_match("a", false),
            email_match("b", true),
            email_match("c", false),
        ];
        assert_eq!(
            decide_for_email_matches(&matches, true),
            EmailDecision::Link("b".to_string())
        );
        assert_eq!(
            decide_for_email_matches(&matches, false),
            EmailDecision::Refuse(LinkRefusalReason::ProviderEmailNotAuthoritative)
        );
    }

    #[test]
    fn confirmed_case_variants_of_one_address_are_ambiguous() {
        assert_eq!(
            decide_for_email_matches(
                &[
                    email_match("a", true),
                    email_match("b", false),
                    email_match("c", true)
                ],
                true
            ),
            EmailDecision::Refuse(LinkRefusalReason::AmbiguousEmail)
        );
    }
}
