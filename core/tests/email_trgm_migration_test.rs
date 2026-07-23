use sqlx::PgPool;

fn assert_test_database_url() -> String {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    assert!(
        database_url.contains("localhost") || database_url.contains("127.0.0.1"),
        "Tests must run against localhost database"
    );

    database_url
}

#[tokio::test]
async fn migrations_enable_trigram_email_search_index() {
    let pool = PgPool::connect(&assert_test_database_url())
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let extension_installed: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')")
            .fetch_one(&pool)
            .await
            .expect("Failed to inspect installed extensions");
    assert!(extension_installed, "pg_trgm extension must be installed");

    let index_definition: Option<String> = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes
         WHERE schemaname = 'public' AND indexname = 'idx_users_email_trgm'",
    )
    .fetch_optional(&pool)
    .await
    .expect("Failed to inspect users indexes");
    let index_definition = index_definition.expect("idx_users_email_trgm index must exist");

    assert!(
        index_definition.contains("USING gin (email gin_trgm_ops)"),
        "email search index must use the trigram GIN operator class: {index_definition}"
    );
    assert!(
        index_definition.contains("WHERE (email IS NOT NULL)"),
        "email search index must exclude null emails: {index_definition}"
    );
}
