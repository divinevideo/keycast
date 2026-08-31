//! Periodic cleanup for abandoned and legacy authentication state.

use sqlx::PgPool;

/// Remove legacy pre-#366 asynchronous-signup rows and expired OAuth rows.
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
        }
    })
}
