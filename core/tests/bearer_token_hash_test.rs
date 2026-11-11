#![cfg(feature = "integration-tests")]

use chrono::{Duration, Utc};
use keycast_core::repositories::{ClaimTokenRepository, PendingEmailSide, UserRepository};
use keycast_core::token_hash::hash_token;
use sqlx::PgPool;

const PUBKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

#[sqlx::test(migrations = "../database/migrations")]
async fn new_claim_and_resend_links_replace_old_credentials(pool: PgPool) {
    let users = UserRepository::new(pool.clone());
    users.ensure_exists(PUBKEY, 1).await.unwrap();
    let claims = ClaimTokenRepository::new(pool.clone());
    claims.create("first-claim", PUBKEY, None, 1).await.unwrap();
    claims
        .create("second-claim", PUBKEY, None, 1)
        .await
        .unwrap();
    assert!(claims.find_valid("first-claim").await.unwrap().is_none());
    assert!(claims.find_valid("second-claim").await.unwrap().is_some());
    let expiry = Utc::now() + Duration::hours(1);
    claims
        .stage_pending_claim(
            "second-claim",
            1,
            "claim@example.com",
            "hash",
            "first-confirmation",
            expiry,
        )
        .await
        .unwrap();
    let snapshot = claims
        .pending_claim_send_state("second-claim", 1)
        .await
        .unwrap()
        .unwrap();
    assert!(claims
        .touch_claim_confirmation(
            "second-claim",
            1,
            ("second-confirmation", expiry),
            &snapshot.confirmation_token_hash,
            -1
        )
        .await
        .unwrap());
    assert!(claims
        .confirmation_classification("first-confirmation", 1)
        .await
        .unwrap()
        .is_none());
    assert!(claims
        .confirmation_classification("second-confirmation", 1)
        .await
        .unwrap()
        .is_some());
    // A restaged claim can change recipient/password while a resend is awaiting admission.
    // The older snapshot must not authorize a token sent to that older recipient.
    assert!(!claims
        .touch_claim_confirmation(
            "second-claim",
            1,
            ("stale-confirmation", expiry),
            &snapshot.confirmation_token_hash,
            -1
        )
        .await
        .unwrap());
    assert!(claims
        .confirmation_classification("stale-confirmation", 1)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = "../database/migrations")]
async fn stored_digests_are_not_accepted_as_bearer_tokens(pool: PgPool) {
    let users = UserRepository::new(pool.clone());
    let expiry = Utc::now() + Duration::hours(1);
    users
        .create_with_credentials(
            PUBKEY,
            1,
            "hash-test@example.com",
            "password-hash",
            false,
            "verification-secret",
            expiry,
        )
        .await
        .unwrap();
    users
        .set_password_reset_token(PUBKEY, 1, "reset-secret", expiry)
        .await
        .unwrap();
    users
        .set_pending_email_change(
            PUBKEY,
            1,
            "new@example.com",
            "old-address-secret",
            "new-address-secret",
            expiry,
        )
        .await
        .unwrap();

    let stored: (String, String, String, String) = sqlx::query_as(
        "SELECT email_verification_token, password_reset_token, pending_email_old_token, pending_email_new_token FROM users WHERE pubkey = $1",
    ).bind(PUBKEY).fetch_one(&pool).await.unwrap();
    assert_eq!(
        stored,
        (
            hash_token("verification-secret"),
            hash_token("reset-secret"),
            hash_token("old-address-secret"),
            hash_token("new-address-secret")
        )
    );
    assert!(users
        .find_by_verification_token("verification-secret", 1)
        .await
        .unwrap()
        .is_some());
    assert!(users
        .find_by_verification_token(&stored.0, 1)
        .await
        .unwrap()
        .is_none());
    assert!(users
        .find_by_reset_token("reset-secret", 1)
        .await
        .unwrap()
        .is_some());
    assert!(users
        .find_by_reset_token(&stored.1, 1)
        .await
        .unwrap()
        .is_none());
    for (raw, side, digest) in [
        ("old-address-secret", PendingEmailSide::Old, &stored.2),
        ("new-address-secret", PendingEmailSide::New, &stored.3),
    ] {
        assert!(
            matches!(users.find_by_pending_email_token(raw, 1).await.unwrap(), Some((_, found)) if found == side)
        );
        assert!(users
            .find_by_pending_email_token(digest, 1)
            .await
            .unwrap()
            .is_none());
        assert!(!users
            .mark_pending_email_confirmed(PUBKEY, 1, side, digest)
            .await
            .unwrap());
        assert!(!users
            .clear_pending_email_change_by_token(PUBKEY, 1, digest)
            .await
            .unwrap());
        assert!(users
            .mark_pending_email_confirmed(PUBKEY, 1, side, raw)
            .await
            .unwrap());
    }

    let claims = ClaimTokenRepository::new(pool.clone());
    let row = claims
        .create("claim-secret", PUBKEY, None, 1)
        .await
        .unwrap();
    assert_eq!(row.token_hash, hash_token("claim-secret"));
    assert!(claims.find_valid("claim-secret").await.unwrap().is_some());
    assert!(claims.find_valid(&row.token_hash).await.unwrap().is_none());
    claims
        .stage_pending_claim(
            "claim-secret",
            1,
            "claimed@example.com",
            "hash",
            "confirmation-secret",
            expiry,
        )
        .await
        .unwrap();
    let digest: String =
        sqlx::query_scalar("SELECT confirmation_token FROM account_claim_tokens WHERE id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(digest, hash_token("confirmation-secret"));
    assert!(claims
        .confirmation_classification("confirmation-secret", 1)
        .await
        .unwrap()
        .is_some());
    assert!(claims
        .confirmation_classification(&digest, 1)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = false)]
async fn migration_preserves_links_nulls_and_expiry(pool: PgPool) {
    let mut before_hashing = sqlx::migrate!("../database/migrations");
    before_hashing
        .migrations
        .to_mut()
        .retain(|migration| migration.version < 20261110230000);
    before_hashing.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (pubkey, tenant_id, email_verification_token, password_reset_token, pending_email_old_token, pending_email_new_token) VALUES ($1, 1, 'old-verification', 'old-reset', 'old-side', NULL)")
        .bind(PUBKEY).execute(&pool).await.unwrap();
    let expiry = Utc::now() + Duration::hours(1);
    sqlx::query("INSERT INTO account_claim_tokens (token, user_pubkey, tenant_id, expires_at, confirmation_token, confirmation_expires_at) VALUES ('old-claim', $1, 1, $2, 'old-confirmation', $2)")
        .bind(PUBKEY).bind(expiry).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO oauth_codes (code, user_pubkey, tenant_id, client_id, redirect_uri, scope, expires_at, device_code, pending_email_verification_token) VALUES ('old-oauth-code', $1, 1, 'synthetic-client', 'https://example.com/callback', 'sign_event', $2, 'old-device', 'old-verification')")
        .bind(PUBKEY).bind(expiry).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO atproto_oauth_sessions (tenant_id, client_id, redirect_uri, scope, request_uri, par_expires_at, authorization_code, authorization_code_expires_at) VALUES (1, 'synthetic-client', 'https://example.com/callback', 'atproto', 'synthetic-request', $1, 'old-atproto-code', $1)")
        .bind(expiry).execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../database/migrations/20261110230000_hash_bearer_tokens.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let row: (String, String, String, Option<String>) = sqlx::query_as("SELECT email_verification_token, password_reset_token, pending_email_old_token, pending_email_new_token FROM users WHERE pubkey = $1")
        .bind(PUBKEY).fetch_one(&pool).await.unwrap();
    assert_eq!(
        row,
        (
            hash_token("old-verification"),
            hash_token("old-reset"),
            hash_token("old-side"),
            None
        )
    );
    let row: (String, String, chrono::DateTime<Utc>) = sqlx::query_as("SELECT token, confirmation_token, expires_at FROM account_claim_tokens WHERE user_pubkey = $1")
        .bind(PUBKEY).fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, hash_token("old-claim"));
    assert_eq!(row.1, hash_token("old-confirmation"));
    assert_eq!(row.2.timestamp_micros(), expiry.timestamp_micros());
    let row: (String, String, String) = sqlx::query_as("SELECT code, device_code, pending_email_verification_token FROM oauth_codes WHERE user_pubkey = $1")
        .bind(PUBKEY).fetch_one(&pool).await.unwrap();
    assert_eq!(
        row,
        (
            hash_token("old-oauth-code"),
            hash_token("old-device"),
            hash_token("old-verification")
        )
    );
    let oauth = keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
    assert!(oauth
        .find_valid(1, "old-oauth-code")
        .await
        .unwrap()
        .is_some());
    assert!(oauth.find_valid(1, &row.0).await.unwrap().is_none());
    let atproto = keycast_core::repositories::AtprotoOAuthSessionRepository::new(pool.clone());
    let session = atproto
        .find_by_authorization_code("old-atproto-code")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        session.authorization_code_hash,
        Some(hash_token("old-atproto-code"))
    );
    assert!(atproto
        .find_by_authorization_code(&hash_token("old-atproto-code"))
        .await
        .unwrap()
        .is_none());
    let claims = ClaimTokenRepository::new(pool.clone());
    assert!(claims.find_valid("old-claim").await.unwrap().is_some());
    assert!(claims
        .confirmation_classification("old-confirmation", 1)
        .await
        .unwrap()
        .is_some());
}
