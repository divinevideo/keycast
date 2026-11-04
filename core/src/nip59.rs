// ABOUTME: NIP-59 gift wrap construction and opening on top of the bounded NIP-44 entry point
// ABOUTME: nostr 0.44 builds and opens wraps itself, which caps a wrap's outer layer at 65,408 bytes

use crate::nip44::{self, Nip44Error};
use nostr_sdk::nips::nip59::{UnwrappedGift, RANGE_RANDOM_TIMESTAMP_TWEAK};
use nostr_sdk::{Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, Timestamp};
use thiserror::Error;

/// Why a kind-1059 gift wrap could not be built.
#[derive(Debug, Error)]
pub enum GiftWrapError {
    #[error("seal must be kind 13, got kind {0}")]
    NotSeal(u16),
    #[error("encrypting the seal failed: {0}")]
    Encrypt(#[from] Nip44Error),
    #[error("signing the gift wrap failed: {0}")]
    Sign(String),
}

/// Why a kind-1059 gift wrap could not be opened.
#[derive(Debug, Error)]
pub enum GiftUnwrapError {
    #[error("not a gift wrap")]
    NotGiftWrap,
    #[error("decrypting a layer failed: {0}")]
    Decrypt(#[from] Nip44Error),
    #[error("a layer is not a valid event: {0}")]
    InvalidEvent(String),
    #[error("the rumor's author is not the seal's signer")]
    SenderMismatch,
}

/// Wraps `seal` for `receiver` in a kind-1059 event signed by a fresh ephemeral
/// key, the way [`EventBuilder::gift_wrap_from_seal`] does, but encrypting
/// through [`nip44::encrypt`] so a seal over 65,408 bytes still fits.
pub fn gift_wrap_from_seal(receiver: &PublicKey, seal: &Event) -> Result<Event, GiftWrapError> {
    if seal.kind != Kind::Seal {
        return Err(GiftWrapError::NotSeal(seal.kind.as_u16()));
    }

    let ephemeral = Keys::generate();
    let content = nip44::encrypt(ephemeral.secret_key(), receiver, &seal.as_json())?;

    EventBuilder::new(Kind::GiftWrap, content)
        .tags([Tag::public_key(*receiver)])
        .custom_created_at(Timestamp::tweaked(RANGE_RANDOM_TIMESTAMP_TWEAK))
        .sign_with_keys(&ephemeral)
        .map_err(|e| GiftWrapError::Sign(e.to_string()))
}

/// Opens a gift wrap addressed to `keys`, the way [`UnwrappedGift::from_gift_wrap`]
/// does, but decrypting through [`nip44::decrypt`] so its size bound applies and
/// a wrap over 65,408 bytes can be opened.
///
/// Verifies the seal's signature, which is the only anchor of the sender's
/// identity. It does not verify the outer wrap's own id and signature.
pub fn unwrap_gift(keys: &Keys, gift_wrap: &Event) -> Result<UnwrappedGift, GiftUnwrapError> {
    if gift_wrap.kind != Kind::GiftWrap {
        return Err(GiftUnwrapError::NotGiftWrap);
    }

    let seal_json = nip44::decrypt(keys.secret_key(), &gift_wrap.pubkey, &gift_wrap.content)?;
    let seal =
        Event::from_json(seal_json).map_err(|e| GiftUnwrapError::InvalidEvent(e.to_string()))?;
    seal.verify()
        .map_err(|e| GiftUnwrapError::InvalidEvent(e.to_string()))?;

    let rumor_json = nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content)?;
    let rumor = nostr_sdk::UnsignedEvent::from_json(rumor_json)
        .map_err(|e| GiftUnwrapError::InvalidEvent(e.to_string()))?;

    if rumor.pubkey != seal.pubkey {
        return Err(GiftUnwrapError::SenderMismatch);
    }

    Ok(UnwrappedGift {
        sender: seal.pubkey,
        rumor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, UnsignedEvent};

    fn rumor_from(author: &Keys, receiver: &PublicKey, text: &str) -> UnsignedEvent {
        let mut rumor = EventBuilder::private_msg_rumor(*receiver, text).build(author.public_key());
        rumor.ensure_id();
        rumor
    }

    /// A kind-13 seal signed by `signer` that carries `rumor` encrypted to `receiver`.
    fn seal_signed_by(signer: &Keys, receiver: &PublicKey, rumor: &UnsignedEvent) -> Event {
        let content = nip44::encrypt(signer.secret_key(), receiver, &rumor.as_json()).unwrap();
        EventBuilder::new(Kind::Seal, content)
            .sign_with_keys(signer)
            .unwrap()
    }

    /// A kind-13 seal whose content is a placeholder `len` bytes long.
    fn seal_of(len: usize) -> Event {
        let author = Keys::generate();
        EventBuilder::new(Kind::Seal, "a".repeat(len))
            .sign_with_keys(&author)
            .unwrap()
    }

    #[test]
    fn rejects_a_seal_that_is_not_kind_13() {
        let not_a_seal = EventBuilder::text_note("hi")
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let result = gift_wrap_from_seal(&Keys::generate().public_key(), &not_a_seal);
        assert!(
            matches!(result, Err(GiftWrapError::NotSeal(1))),
            "{result:?}"
        );
    }

    #[test]
    fn wraps_a_seal_the_previous_library_could_not() {
        // The wrap's outer plaintext is the seal's JSON: over 65,408 bytes,
        // the most nostr 0.44 will encrypt.
        let receiver = Keys::generate();
        let seal = seal_of(70_000);

        let wrap = gift_wrap_from_seal(&receiver.public_key(), &seal).unwrap();

        assert_eq!(wrap.kind, Kind::GiftWrap);
        wrap.verify().unwrap();
        let opened = nip44::decrypt(receiver.secret_key(), &wrap.pubkey, &wrap.content).unwrap();
        assert_eq!(Event::from_json(opened).unwrap(), seal);
    }

    #[test]
    fn opens_a_wrap_for_a_message_that_needs_the_extended_length_prefix() {
        let (sender, receiver) = (Keys::generate(), Keys::generate());
        let text = "a".repeat(41_000);
        let rumor = rumor_from(&sender, &receiver.public_key(), &text);
        let seal = seal_signed_by(&sender, &receiver.public_key(), &rumor);

        let wrap = gift_wrap_from_seal(&receiver.public_key(), &seal).unwrap();
        let opened = unwrap_gift(&receiver, &wrap).unwrap();

        assert_eq!(opened.sender, sender.public_key());
        assert_eq!(opened.rumor.content, text);
    }

    #[test]
    fn refuses_a_seal_whose_signature_is_not_valid() {
        // The seal is the only anchor of the sender's identity, and anyone can
        // build the wrap around it: a forged seal must not authenticate.
        let (victim, attacker, receiver) = (Keys::generate(), Keys::generate(), Keys::generate());
        let rumor = rumor_from(&victim, &receiver.public_key(), "forged");
        let seal = seal_signed_by(&victim, &receiver.public_key(), &rumor);
        let other_signature = EventBuilder::text_note("unrelated")
            .sign_with_keys(&attacker)
            .unwrap()
            .sig;
        let mut forged = serde_json::to_value(&seal).unwrap();
        forged["sig"] = serde_json::to_value(other_signature).unwrap();
        let forged: Event = serde_json::from_value(forged).unwrap();
        assert!(forged.verify().is_err(), "the test seal must be invalid");

        let wrap = gift_wrap_from_seal(&receiver.public_key(), &forged).unwrap();

        assert!(matches!(
            unwrap_gift(&receiver, &wrap),
            Err(GiftUnwrapError::InvalidEvent(_))
        ));
    }

    #[test]
    fn refuses_a_rumor_written_by_someone_other_than_the_seal_signer() {
        let (signer, claimed, receiver) = (Keys::generate(), Keys::generate(), Keys::generate());
        let rumor = rumor_from(&claimed, &receiver.public_key(), "not mine");
        let seal = seal_signed_by(&signer, &receiver.public_key(), &rumor);

        let wrap = gift_wrap_from_seal(&receiver.public_key(), &seal).unwrap();

        assert!(matches!(
            unwrap_gift(&receiver, &wrap),
            Err(GiftUnwrapError::SenderMismatch)
        ));
    }

    #[test]
    fn signs_each_wrap_with_a_fresh_key_that_belongs_to_neither_party() {
        // A reused or fixed signing key would link every wrap Keycast builds
        // to one public key. Ids alone differ anyway, so check the signer.
        let (sender, receiver) = (Keys::generate(), Keys::generate());
        let rumor = rumor_from(&sender, &receiver.public_key(), "hi");
        let seal = seal_signed_by(&sender, &receiver.public_key(), &rumor);

        let wraps: Vec<Event> = (0..3)
            .map(|_| gift_wrap_from_seal(&receiver.public_key(), &seal).unwrap())
            .collect();

        let signers: std::collections::HashSet<PublicKey> =
            wraps.iter().map(|wrap| wrap.pubkey).collect();
        assert_eq!(signers.len(), wraps.len());
        for wrap in &wraps {
            assert_ne!(wrap.pubkey, sender.public_key());
            assert_ne!(wrap.pubkey, receiver.public_key());
            wrap.verify().unwrap();
        }
    }

    #[test]
    fn addresses_the_wrap_to_the_receiver_and_no_one_else() {
        let (sender, receiver) = (Keys::generate(), Keys::generate());
        let rumor = rumor_from(&sender, &receiver.public_key(), "hi");
        let seal = seal_signed_by(&sender, &receiver.public_key(), &rumor);

        let wrap = gift_wrap_from_seal(&receiver.public_key(), &seal).unwrap();

        assert_eq!(wrap.tags.len(), 1);
        assert_eq!(
            wrap.tags.public_keys().collect::<Vec<_>>(),
            vec![&receiver.public_key()]
        );
    }

    #[test]
    fn dates_a_wrap_at_random_instead_of_when_it_was_sent() {
        // NIP-59 randomises the wrap's time, up to two days back, so it does not
        // reveal when the message was sent. Eight wraps all landing within an
        // hour of now by chance has odds of about 1 in 3 * 10^13.
        let receiver = Keys::generate();
        let seal = seal_of(10);
        let now = Timestamp::now().as_secs();

        let oldest_age = (0..8)
            .map(|_| gift_wrap_from_seal(&receiver.public_key(), &seal).unwrap())
            .map(|wrap| now.saturating_sub(wrap.created_at.as_secs()))
            .max()
            .unwrap();

        assert!(oldest_age > 3_600, "oldest wrap was only {oldest_age}s old");
    }

    #[test]
    fn refuses_to_open_an_event_that_is_not_a_gift_wrap() {
        let keys = Keys::generate();
        let event = EventBuilder::text_note("hi").sign_with_keys(&keys).unwrap();
        assert!(matches!(
            unwrap_gift(&keys, &event),
            Err(GiftUnwrapError::NotGiftWrap)
        ));
    }
}
