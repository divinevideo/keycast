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

            match delete_expired_email_marketing_queue_rows(&pool).await {
                Ok((deletions, email_changes)) if deletions + email_changes > 0 => {
                    tracing::info!(
                        deletions,
                        email_changes,
                        "Cleanup task: deleted expired email-marketing queue rows"
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
