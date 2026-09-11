// ABOUTME: The tri-state email-marketing consent event recorded on a keycast account.
// ABOUTME: Distinguishes "never asked" from "asked and declined"; see the 2026-09-03 sync design.

/// What a person answered when asked about marketing email.
///
/// Tri-state on purpose. A boolean collapses "asked and declined" into "never asked", and that
/// distinction decides whether it is legitimate to ask again. It also maps cleanly onto the
/// `Option<bool>` that `POST /api/headless/register` already accepts, so no API change is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailMarketingConsent {
    NeverAsked,
    Declined,
    OptedIn,
}

impl EmailMarketingConsent {
    /// The stored representation. Must match the CHECK constraint in the migration exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailMarketingConsent::NeverAsked => "never_asked",
            EmailMarketingConsent::Declined => "declined",
            EmailMarketingConsent::OptedIn => "opted_in",
        }
    }

    /// Parse a value read from the database. Returns Err rather than defaulting, so a value the
    /// CHECK constraint should have rejected surfaces loudly instead of silently becoming
    /// "never asked" and re-asking someone who already declined.
    pub fn from_db(value: &str) -> Result<Self, String> {
        match value {
            "never_asked" => Ok(EmailMarketingConsent::NeverAsked),
            "declined" => Ok(EmailMarketingConsent::Declined),
            "opted_in" => Ok(EmailMarketingConsent::OptedIn),
            other => Err(format!("unknown email marketing consent state: {other}")),
        }
    }

    pub fn is_opted_in(&self) -> bool {
        matches!(self, EmailMarketingConsent::OptedIn)
    }
}

impl From<Option<bool>> for EmailMarketingConsent {
    /// The client omitting the field means nobody asked; sending `false` means they were shown the
    /// choice and declined.
    fn from(value: Option<bool>) -> Self {
        match value {
            None => EmailMarketingConsent::NeverAsked,
            Some(false) => EmailMarketingConsent::Declined,
            Some(true) => EmailMarketingConsent::OptedIn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_field_means_never_asked() {
        assert_eq!(
            EmailMarketingConsent::from(None),
            EmailMarketingConsent::NeverAsked
        );
    }

    #[test]
    fn explicit_false_means_declined() {
        assert_eq!(
            EmailMarketingConsent::from(Some(false)),
            EmailMarketingConsent::Declined
        );
    }

    #[test]
    fn explicit_true_means_opted_in() {
        assert_eq!(
            EmailMarketingConsent::from(Some(true)),
            EmailMarketingConsent::OptedIn
        );
    }

    #[test]
    fn round_trips_through_the_database_representation() {
        for state in [
            EmailMarketingConsent::NeverAsked,
            EmailMarketingConsent::Declined,
            EmailMarketingConsent::OptedIn,
        ] {
            assert_eq!(
                EmailMarketingConsent::from_db(state.as_str()).unwrap(),
                state
            );
        }
    }

    #[test]
    fn rejects_an_unknown_database_value() {
        assert!(EmailMarketingConsent::from_db("subscribed").is_err());
    }
}
