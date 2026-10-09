#![cfg(feature = "integration-tests")]
// ABOUTME: Checks the migration that adds the verified NIP-46 client to OAuth
// ABOUTME: authorizations and keeps it NULL unless it equals the bound client.

mod common;

use sqlx::PgPool;

const MIGRATION_VERSION: i64 = 20261008210000;
const MIGRATION_SQL: &str =
    include_str!("../../database/migrations/20261008210000_add_oauth_verified_client_pubkey.sql");

/// Insert an OAuth authorization with the given binding and return its id.
async fn insert_authorization(pool: &PgPool, connected: Option<&str>) -> i32 {
    let user_pubkey = common::unique_pubkey();
    common::insert_bare_user(pool, &user_pubkey).await;
    sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (tenant_id, user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash,
          relays, connected_client_pubkey, connected_at, handle_expires_at)
         VALUES ($1, $2, 'https://verified-client.example.com', 'Verified Client', $3,
                 'unused-secret-hash', '[]', $4, NOW(), NOW() + INTERVAL '30 days')
         RETURNING id",
    )
    .bind(common::TENANT_ID)
    .bind(&user_pubkey)
    .bind(common::unique_pubkey())
    .bind(connected)
    .fetch_one(pool)
    .await
    .expect("insert oauth authorization")
}

async fn update(pool: &PgPool, id: i32, set: &str, value: Option<&str>) {
    sqlx::query(&format!(
        "UPDATE oauth_authorizations SET {set} WHERE id = $2"
    ))
    .bind(value)
    .bind(id)
    .execute(pool)
    .await
    .expect("update oauth authorization");
}

async fn verified(pool: &PgPool, id: i32) -> Option<String> {
    sqlx::query_scalar("SELECT verified_client_pubkey FROM oauth_authorizations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read verified client")
}

#[sqlx::test(migrations = "../database/migrations")]
async fn verified_client_stays_null_unless_it_equals_the_binding(pool: PgPool) {
    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)",
    )
    .bind(MIGRATION_VERSION)
    .fetch_one(&pool)
    .await
    .expect("read applied migrations");
    assert!(applied, "the verified client migration must be applied");

    let column: (String, String, Option<String>) = sqlx::query_as(
        "SELECT data_type, is_nullable, column_default
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'oauth_authorizations'
           AND column_name = 'verified_client_pubkey'",
    )
    .fetch_one(&pool)
    .await
    .expect("verified_client_pubkey column must exist");
    assert_eq!(column, ("text".to_string(), "YES".to_string(), None));

    let client = common::unique_pubkey();
    let other_client = common::unique_pubkey();

    // Written the way bindings were written before the column: no verified client.
    let id = insert_authorization(&pool, Some(&client)).await;
    assert_eq!(verified(&pool, id).await, None);

    // A connect with the secret writes both columns.
    update(
        &pool,
        id,
        "connected_client_pubkey = $1, verified_client_pubkey = $1",
        Some(&client),
    )
    .await;
    assert_eq!(verified(&pool, id).await, Some(client.clone()));

    // Updates that leave the binding alone keep it.
    update(
        &pool,
        id,
        "last_activity = NOW(), client_id = $1",
        Some("renamed"),
    )
    .await;
    assert_eq!(verified(&pool, id).await, Some(client.clone()));

    // Clearing only the binding, as code that predates the column disconnects,
    // clears the verified client too, so binding the same client again the old
    // way is not trusted.
    update(&pool, id, "connected_client_pubkey = $1", None).await;
    assert_eq!(verified(&pool, id).await, None);
    update(&pool, id, "connected_client_pubkey = $1", Some(&client)).await;
    assert_eq!(verified(&pool, id).await, None);

    // Binding another client the old way drops the verified client as well.
    update(
        &pool,
        id,
        "connected_client_pubkey = $1, verified_client_pubkey = $1",
        Some(&client),
    )
    .await;
    update(
        &pool,
        id,
        "connected_client_pubkey = $1",
        Some(&other_client),
    )
    .await;
    assert_eq!(verified(&pool, id).await, None);

    // A verified client that does not match the binding is never stored.
    update(&pool, id, "verified_client_pubkey = $1", Some(&client)).await;
    assert_eq!(verified(&pool, id).await, None);
}

#[sqlx::test(migrations = "../database/migrations")]
async fn existing_bindings_have_no_verified_client_after_migration(pool: PgPool) {
    // Return the table to its shape before this migration, with a bound row.
    sqlx::raw_sql(
        "DROP TRIGGER oauth_authorizations_verified_client_trigger ON oauth_authorizations;
         DROP FUNCTION keep_verified_client_with_binding();
         ALTER TABLE oauth_authorizations DROP COLUMN verified_client_pubkey;",
    )
    .execute(&pool)
    .await
    .expect("undo the migration");
    let client = common::unique_pubkey();
    let id = insert_authorization(&pool, Some(&client)).await;

    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&pool)
        .await
        .expect("run the migration");

    assert_eq!(
        verified(&pool, id).await,
        None,
        "a binding that existed before the migration has no verified client"
    );
    update(
        &pool,
        id,
        "connected_client_pubkey = $1, verified_client_pubkey = $1",
        Some(&client),
    )
    .await;
    assert_eq!(verified(&pool, id).await, Some(client.clone()));
    update(&pool, id, "connected_client_pubkey = $1", None).await;
    assert_eq!(
        verified(&pool, id).await,
        None,
        "the migration also installs the trigger"
    );
}
