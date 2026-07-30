// ABOUTME: Regression tests for per-request authorization expiry in the NIP-46 signer
// ABOUTME: A handler cached while valid must stop working the moment its expires_at falls due

use chrono::{Duration, Utc};
use keycast_core::signing_handler::SigningHandler;
use keycast_signer::{HandlerStatus, Nip46Handler};
use nostr_sdk::prelude::*;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// The handler cache has no TTL, so these tests never touch the database — they
/// exercise the status logic on a handler that is already in memory, which is
/// exactly the state the bug lived in. `connect_lazy` builds a pool without
/// opening a connection.
fn lazy_pool() -> PgPool {
    PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool construction should not require a live database")
}

fn handler_cached_as_active() -> Nip46Handler {
    Nip46Handler::new_for_test(
        Keys::generate(),
        Keys::generate(),
        "test_hash".to_string(),
        1,
        1,
        false,
        lazy_pool(),
    )
}

/// Regression: a team bunker authorization loaded into the handler cache while it
/// was still valid kept a stale `Active` status forever, because expiry was only
/// computed on a cache miss and the cache has no TTL. An operator's expired bunker
/// URL kept signing, encrypting, and decrypting indefinitely.
#[tokio::test]
async fn expired_authorization_cached_as_active_is_a_tombstone() {
    let handler = handler_cached_as_active().with_expires_at(Some(Utc::now() - Duration::hours(1)));

    assert!(
        handler.is_tombstone(),
        "an authorization past its expires_at must be a tombstone even when cached as Active"
    );
    assert_eq!(
        handler.tombstone_error_message(),
        Some("Authorization has expired"),
        "the client must get an explicit expiry error, not a silent timeout"
    );
}

#[tokio::test]
async fn authorization_expiring_in_the_future_stays_active() {
    let handler = handler_cached_as_active().with_expires_at(Some(Utc::now() + Duration::hours(1)));

    assert!(!handler.is_tombstone());
    assert_eq!(handler.tombstone_error_message(), None);
}

#[tokio::test]
async fn authorization_without_expiry_stays_active() {
    let handler = handler_cached_as_active().with_expires_at(None);

    assert!(!handler.is_tombstone());
    assert_eq!(handler.tombstone_error_message(), None);
}

/// Revocation outranks expiry: a revoked authorization that is also past its
/// expires_at must still report as revoked, so the client sees the real reason.
#[tokio::test]
async fn revoked_authorization_reports_revoked_even_when_also_expired() {
    let handler = handler_cached_as_active()
        .with_status(HandlerStatus::Revoked)
        .with_expires_at(Some(Utc::now() - Duration::hours(1)));

    assert!(handler.is_tombstone());
    assert_eq!(
        handler.tombstone_error_message(),
        Some("Authorization has been revoked")
    );
}

/// An expiry that falls due while the handler sits in cache must take effect on
/// the very next request — the failure mode was that it never did.
#[tokio::test]
async fn expiry_takes_effect_without_reloading_the_handler() {
    let just_past = Utc::now() - Duration::seconds(1);
    let handler = handler_cached_as_active().with_expires_at(Some(just_past));

    assert!(
        handler.is_tombstone(),
        "expiry must be evaluated against the clock per request, not at load time"
    );
}

#[tokio::test]
async fn expired_authorization_cannot_sign_directly() {
    let handler =
        handler_cached_as_active().with_expires_at(Some(Utc::now() - Duration::seconds(1)));
    let pubkey =
        PublicKey::from_hex(&handler.user_pubkey()).expect("test handler has a valid pubkey");
    let unsigned = EventBuilder::text_note("must not be signed").build(pubkey);

    let error = handler
        .sign_event_direct(unsigned)
        .await
        .expect_err("an expired authorization must not reach the signing key");

    assert_eq!(
        error.to_string(),
        "Permission denied: Authorization has expired"
    );
}
