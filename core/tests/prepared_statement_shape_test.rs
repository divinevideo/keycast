#![cfg(feature = "integration-tests")]
// ABOUTME: Regression coverage for prepared query result shapes across additive migrations.
// ABOUTME: Uses an isolated schema so the DDL cannot interfere with parallel database tests.

use keycast_core::types::oauth_authorization::OAuthAuthorization;
use sqlx::postgres::PgPoolOptions;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string())
}

#[tokio::test]
async fn signer_lookups_keep_a_stable_result_shape_when_a_column_is_added() {
    let database_url = database_url();
    assert!(
        database_url.contains("localhost") || database_url.contains("127.0.0.1"),
        "integration test must run against localhost PostgreSQL"
    );

    let test_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to test database");
    sqlx::query(
        "CREATE TEMP TABLE oauth_authorizations \
         (LIKE public.oauth_authorizations INCLUDING ALL)",
    )
    .execute(&test_pool)
    .await
    .expect("copy authorization table shape into a connection-local table");

    let missing_bunker = "missing-bunker";

    OAuthAuthorization::find_active_by_bunker_pubkey_for_tenant(&test_pool, missing_bunker, 1)
        .await
        .expect("prepare the active signer lookup");
    OAuthAuthorization::find_by_bunker_pubkey_for_signer(&test_pool, missing_bunker)
        .await
        .expect("prepare the on-demand signer lookup");

    let wildcard_query = "SELECT * FROM oauth_authorizations WHERE bunker_public_key = $1";
    sqlx::query_as::<_, OAuthAuthorization>(wildcard_query)
        .bind(missing_bunker)
        .fetch_optional(&test_pool)
        .await
        .expect("prepare the wildcard control query");

    sqlx::query("ALTER TABLE oauth_authorizations ADD COLUMN future_column TEXT")
        .execute(&test_pool)
        .await
        .expect("simulate an additive migration");

    let stable_active_lookup =
        OAuthAuthorization::find_active_by_bunker_pubkey_for_tenant(&test_pool, missing_bunker, 1)
            .await;
    let stable_on_demand_lookup =
        OAuthAuthorization::find_by_bunker_pubkey_for_signer(&test_pool, missing_bunker).await;
    let wildcard_lookup = sqlx::query_as::<_, OAuthAuthorization>(wildcard_query)
        .bind(missing_bunker)
        .fetch_optional(&test_pool)
        .await;

    test_pool.close().await;

    stable_active_lookup
        .expect("explicit active signer projection must survive an added table column");
    stable_on_demand_lookup
        .expect("explicit on-demand signer projection must survive an added table column");
    let wildcard_error = wildcard_lookup
        .expect_err("PostgreSQL behavior probe: wildcard control must change result shape");
    let sqlstate = match &wildcard_error {
        sqlx::Error::Database(database_error) => database_error.code(),
        _ => None,
    };
    assert_eq!(
        sqlstate.as_deref(),
        Some("0A000"),
        "PostgreSQL behavior probe returned an unexpected error: {wildcard_error}"
    );
}
