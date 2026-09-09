//! Periodic cleanup for abandoned authentication state and bounded-retention service queues.

use sqlx::PgPool;

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

/// Remove legacy pre-#366 asynchronous-signup rows, expired OAuth rows, and expired service queues.
pub fn spawn_cleanup_task(pool: PgPool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

        loop {
            interval.tick().await;

            // TODO(#377): Remove this DELETE after the bounded-bcrypt rollout no longer has
            // pre-migration first-party registration rows with password_hash IS NULL.
            let result = sqlx::query(
                "DELETE FROM users WHERE password_hash IS NULL
                 AND vine_id IS NULL
                 AND email IS NOT NULL
                 AND created_at < NOW() - INTERVAL '10 minutes'",
            )
            .execute(&pool)
            .await;

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
        }
    })
}
