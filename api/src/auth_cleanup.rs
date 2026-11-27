//! Periodic cleanup for abandoned authentication state and bounded-retention service queues.

use keycast_core::{metrics::METRICS, repositories::AdminAuditEventRepository};
use sqlx::PgPool;
use std::sync::Arc;

use crate::social_identity::{AppleTokenClient, SocialLoginSettings};

async fn revoke_apple_grants(
    pool: &PgPool,
    key_manager: &dyn keycast_core::encryption::KeyManager,
    client: Option<&AppleTokenClient>,
) -> Result<(), sqlx::Error> {
    let expired = sqlx::query("DELETE FROM apple_grant_revocations WHERE expires_at <= NOW()")
        .execute(pool)
        .await?
        .rows_affected();
    if expired != 0 {
        tracing::warn!(
            expired,
            "Apple grant revocations expired without confirmation"
        );
    }
    let Some(client) = client else {
        return Ok(());
    };
    for _ in 0..16 {
        // Claim just one at a time. The retry lease is longer than the outbound deadline.
        // No transaction or connection is held while decrypting or calling Apple.
        let job: Option<(i64, String, Vec<u8>)> = sqlx::query_as(
            "WITH next_job AS (
                 SELECT id FROM apple_grant_revocations
                 WHERE next_attempt_at <= NOW() AND expires_at > NOW()
                 ORDER BY next_attempt_at, id LIMIT 1 FOR UPDATE SKIP LOCKED
             )
             UPDATE apple_grant_revocations job SET next_attempt_at = NOW() + INTERVAL '15 minutes'
             FROM next_job WHERE job.id = next_job.id
             RETURNING job.id, job.client_id, job.encrypted_token",
        )
        .fetch_optional(pool)
        .await?;
        let Some((id, client_id, encrypted)) = job else {
            break;
        };
        let revoked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let plaintext = key_manager
                .decrypt(&encrypted)
                .await
                .map_err(|_| "decrypt")?;
            let token = std::str::from_utf8(&plaintext).map_err(|_| "decode")?;
            client
                .revoke(&client_id, token)
                .await
                .map_err(|_| "request")
        })
        .await;
        if matches!(revoked, Ok(Ok(()))) {
            sqlx::query("DELETE FROM apple_grant_revocations WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await?;
        } else {
            let stage = revoked.ok().and_then(Result::err).unwrap_or("timeout");
            tracing::warn!(stage, "Apple grant revocation did not complete; will retry");
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use jwt_simple::prelude::{ECDSAP256KeyPairLike, ES256KeyPair};
    use keycast_core::encryption::{KeyManager, KeyManagerError};
    use secrecy::SecretString;
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    struct FixtureKeyManager;

    #[async_trait::async_trait]
    impl KeyManager for FixtureKeyManager {
        async fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
            Ok(bytes.to_vec())
        }

        async fn decrypt(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
            Ok(Zeroizing::new(bytes.to_vec()))
        }
    }

    #[sqlx::test(migrations = "../database/migrations")]
    async fn apple_revocation_removes_successes_and_leases_failures(pool: PgPool) {
        use axum::{http::StatusCode, routing::post, Form, Router};
        let endpoint = Router::new().route(
            "/revoke",
            post(|Form(form): Form<HashMap<String, String>>| async move {
                assert_eq!(form["token"], "fixture");
                assert_eq!(form["token_type_hint"], "refresh_token");
                assert!(!form["client_secret"].is_empty());
                match form["client_id"].as_str() {
                    "success" => StatusCode::OK,
                    "retry" => StatusCode::SERVICE_UNAVAILABLE,
                    other => panic!("unexpected client: {other}"),
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, endpoint).await.unwrap() });
        let settings = SocialLoginSettings {
            apple_signing_key: Some(crate::social_identity::AppleSigningKey {
                team_id: "fixture-team".into(),
                key_id: "fixture-key".into(),
                private_key_pem: SecretString::from(ES256KeyPair::generate().to_pem().unwrap()),
            }),
            ..Default::default()
        };
        let client = AppleTokenClient::from_settings(&settings)
            .unwrap()
            .with_revoke_url(format!("http://{address}/revoke"));
        sqlx::query(
            "INSERT INTO apple_grant_revocations (client_id, encrypted_token, expires_at)
                     VALUES ('success', $1, NOW() + INTERVAL '1 day'),
                            ('retry', $1, NOW() + INTERVAL '1 day'),
                            ('expired', $1, NOW() - INTERVAL '1 day')",
        )
        .bind(b"fixture".as_slice())
        .execute(&pool)
        .await
        .unwrap();
        revoke_apple_grants(&pool, &FixtureKeyManager, Some(&client))
            .await
            .unwrap();
        let queued: Vec<(String, bool)> = sqlx::query_as(
            "SELECT client_id, next_attempt_at > NOW() FROM apple_grant_revocations",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(queued, vec![("retry".into(), true)]);
        server.abort();
    }
}

/// Remove expired email-marketing queue rows independently of the sync consumer.
///
/// Both tables contain email addresses that are useful only for a bounded delivery window. This
/// runs from keycast's existing periodic cleanup task, so retention does not depend on the worker
/// calling a list endpoint.
pub async fn delete_expired_email_marketing_queue_rows(
    pool: &PgPool,
) -> Result<(u64, u64), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deletions = sqlx::query("DELETE FROM email_marketing_deletions WHERE expires_at <= NOW()")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let email_changes =
        sqlx::query("DELETE FROM email_marketing_email_changes WHERE expires_at <= NOW()")
            .execute(&mut *tx)
            .await?
            .rows_affected();
    tx.commit().await?;
    Ok((deletions, email_changes))
}

/// Queue rows close enough to expiry that the sync worker is about to lose them.
///
/// Draining is acknowledge-based and reads from the head, so a row that keeps failing is retried
/// forever while everything behind it is never served. Expiry then removes it. Both outcomes are
/// silent: an operator sees a healthy-looking run every five minutes while a deleted account's
/// address is quietly dropped and that person keeps receiving marketing.
///
/// Counted, never listed. These rows exist to hold email addresses.
pub async fn count_email_marketing_queue_near_expiry(
    pool: &PgPool,
    within: std::time::Duration,
) -> Result<(i64, i64), sqlx::Error> {
    let horizon = chrono::Utc::now() + chrono::Duration::from_std(within).unwrap_or_default();
    let deletions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_marketing_deletions WHERE expires_at <= $1")
            .bind(horizon)
            .fetch_one(pool)
            .await?;
    let email_changes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_email_changes WHERE expires_at <= $1",
    )
    .bind(horizon)
    .fetch_one(pool)
    .await?;
    Ok((deletions, email_changes))
}

/// Delete legacy asynchronous-signup rows that never received a password hash.
///
/// Accounts that sign in through Google or Apple also have no password, on purpose. They are
/// recognised by their linked provider and kept.
pub async fn delete_legacy_stale_signup_rows(
    pool: &PgPool,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "DELETE FROM users WHERE password_hash IS NULL
         AND vine_id IS NULL
         AND email IS NOT NULL
         AND created_at < NOW() - INTERVAL '10 minutes'
         AND NOT EXISTS (
             SELECT 1 FROM user_identities identity
             WHERE identity.user_pubkey = users.pubkey
               AND identity.tenant_id = users.tenant_id
         )",
    )
    .execute(pool)
    .await
}

/// Remove legacy pre-#366 asynchronous-signup rows, expired OAuth rows, and expired service queues.
pub fn spawn_cleanup_task(
    pool: PgPool,
    key_manager: Arc<Box<dyn keycast_core::encryption::KeyManager>>,
) -> tokio::task::JoinHandle<()> {
    let apple = AppleTokenClient::from_settings(&SocialLoginSettings::from_env());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

        loop {
            interval.tick().await;
            if let Err(error) =
                revoke_apple_grants(&pool, key_manager.as_ref().as_ref(), apple.as_ref()).await
            {
                tracing::error!(%error, "Apple grant revocation queue processing failed");
            }

            // TODO(#377): Remove this DELETE after the bounded-bcrypt rollout no longer has
            // pre-migration first-party registration rows with password_hash IS NULL.
            let result = delete_legacy_stale_signup_rows(&pool).await;

            match result {
                Ok(result) if result.rows_affected() > 0 => {
                    tracing::info!(
                        "Cleanup task: deleted {} legacy stale signup rows",
                        result.rows_affected()
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::error!("Cleanup task: failed to delete rows: {}", error),
            }

            let oauth_code_repo =
                keycast_core::repositories::OAuthCodeRepository::new(pool.clone());
            match oauth_code_repo.delete_expired_and_consumed().await {
                Ok(deleted) if deleted > 0 => tracing::info!(
                    "Cleanup task: deleted {} expired/consumed oauth_codes rows",
                    deleted
                ),
                Ok(_) => {}
                Err(error) => {
                    tracing::error!("Cleanup task: failed to delete oauth_codes rows: {}", error);
                }
            }

            // Warn before the window closes, so a stuck drain is visible while it can still be
            // fixed rather than only after the rows are gone.
            match count_email_marketing_queue_near_expiry(
                &pool,
                std::time::Duration::from_secs(48 * 60 * 60),
            )
            .await
            {
                Ok((deletions, email_changes)) if deletions + email_changes > 0 => {
                    tracing::warn!(
                        deletions,
                        email_changes,
                        "Cleanup task: email-marketing queue rows expire within 48h and are still \
                         undrained. Past expiry a deleted account's contact is never removed."
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::error!(
                    "Cleanup task: failed to count email-marketing queue backlog: {}",
                    error
                ),
            }

            match delete_expired_email_marketing_queue_rows(&pool).await {
                Ok((deletions, email_changes)) if deletions + email_changes > 0 => {
                    // Warn, not info: each dropped deletion row means somebody who deleted their
                    // account keeps receiving marketing, with nothing left that knows to stop it.
                    tracing::warn!(
                        deletions,
                        email_changes,
                        "Cleanup task: dropped expired email-marketing queue rows before the sync \
                         worker drained them"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::error!(
                    "Cleanup task: failed to delete expired email-marketing queue rows: {}",
                    error
                ),
            }

            let retention_repo = AdminAuditEventRepository::new(pool.clone());
            let now = chrono::Utc::now();
            match retention_repo.count_overdue_retention_rows(now).await {
                Ok((deletions, provisioning)) => METRICS.set_retention_overdue(
                    deletions.try_into().unwrap_or_default(),
                    provisioning.try_into().unwrap_or_default(),
                ),
                Err(error) => {
                    tracing::error!(error = %error, "Retention task: failed to scan overdue rows")
                }
            }
            match retention_repo
                .delete_expired_deletion_events(now, 1_000)
                .await
            {
                Ok(deleted) if deleted > 0 => tracing::info!(
                    deleted,
                    "Retention task: deleted expired service-deletion audit events"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "Retention task: failed to delete expired service-deletion audit events"
                ),
            }
        }
    })
}
