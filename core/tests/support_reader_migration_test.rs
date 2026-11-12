#![cfg(feature = "integration-tests")]
//! Verifies the support reader's effective privileges after all migrations.

use sqlx::PgPool;

const MIGRATION: &str =
    include_str!("../../database/migrations/20261110180000_support_reader_column_grants.sql");

const HIDDEN_COLUMNS: [(&str, &str); 26] = [
    ("users", "password_reset_token"),
    ("users", "email_verification_token"),
    ("users", "pending_email_old_token"),
    ("users", "pending_email_new_token"),
    ("account_claim_tokens", "token"),
    ("account_claim_tokens", "confirmation_token"),
    ("oauth_codes", "code"),
    ("oauth_codes", "device_code"),
    ("oauth_codes", "pending_email_verification_token"),
    ("atproto_oauth_sessions", "authorization_code"),
    ("oauth_authorizations", "authorization_handle"),
    ("users", "password_hash"),
    ("oauth_codes", "pin_hash"),
    ("oauth_codes", "pending_password_hash"),
    ("account_claim_tokens", "pending_password_hash"),
    ("email_verification_tokens", "token_hash"),
    ("oauth_refresh_tokens", "token_hash"),
    ("password_reset_tokens", "token_hash"),
    ("authorizations", "secret_hash"),
    ("oauth_authorizations", "secret_hash"),
    ("atproto_oauth_sessions", "refresh_token_hash"),
    ("personal_keys", "encrypted_secret_key"),
    ("stored_keys", "secret_key"),
    ("ap_actor_keys", "encrypted_private_key"),
    ("oauth_codes", "pending_encrypted_secret"),
    ("group_backups", "ciphertext"),
];

#[sqlx::test(migrations = "../database/migrations")]
async fn support_reader_has_only_classified_column_reads(pool: PgPool) {
    let role: (i32, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT oid::int, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb,
                rolreplication, rolbypassrls
         FROM pg_roles WHERE rolname = 'support_reader'",
    )
    .fetch_one(&pool)
    .await
    .expect("support reader exists");
    assert!(!role.1, "support reader cannot log in");
    assert_eq!(
        (role.2, role.3, role.4, role.5, role.6),
        (false, false, false, false, false)
    );

    let memberships: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_auth_members WHERE member = $1::int::oid")
            .bind(role.0)
            .fetch_one(&pool)
            .await
            .expect("read role memberships");
    assert_eq!(memberships, 0, "support reader must inherit no other role");

    let schema: (bool, bool) = sqlx::query_as(
        "SELECT has_schema_privilege('support_reader', 'public', 'USAGE'),
                has_schema_privilege('support_reader', 'public', 'CREATE')",
    )
    .fetch_one(&pool)
    .await
    .expect("read schema privileges");
    assert_eq!(schema, (true, false));

    let unexpected_table_privileges: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, p.privilege
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                                'REFERENCES', 'TRIGGER']) AS p(privilege)
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
           AND has_table_privilege('support_reader', c.oid, p.privilege)",
    )
    .fetch_all(&pool)
    .await
    .expect("read effective table privileges");
    assert!(
        unexpected_table_privileges.is_empty(),
        "unexpected table privileges: {unexpected_table_privileges:?}"
    );

    let columns: Vec<(String, String, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text,
                has_column_privilege('support_reader', c.oid, a.attnum, 'SELECT'),
                has_column_privilege('support_reader', c.oid, a.attnum, 'INSERT'),
                has_column_privilege('support_reader', c.oid, a.attnum, 'UPDATE'),
                has_column_privilege('support_reader', c.oid, a.attnum, 'REFERENCES')
         FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
           AND a.attnum > 0 AND NOT a.attisdropped
         ORDER BY c.relname, a.attnum",
    )
    .fetch_all(&pool)
    .await
    .expect("inventory every public table column");
    assert!(!columns.is_empty(), "column inventory must not be vacuous");
    for (table, column, select, insert, update, references) in &columns {
        let hidden = HIDDEN_COLUMNS.contains(&(table.as_str(), column.as_str()));
        assert_eq!(
            *select, !hidden,
            "classify public.{table}.{column}: grant it explicitly or mark it hidden"
        );
        assert!(
            !insert && !update && !references,
            "unexpected write privileges on public.{table}.{column}"
        );
    }
    for (table, column) in HIDDEN_COLUMNS {
        assert!(
            columns.iter().any(|c| c.0 == table && c.1 == column),
            "hidden column public.{table}.{column} must exist"
        );

        // Exercise authorization as the reader, not only the catalog predicates.
        let mut tx = pool.begin().await.expect("begin reader transaction");
        sqlx::query("SET LOCAL ROLE support_reader")
            .execute(&mut *tx)
            .await
            .expect("assume support reader locally");
        let error = sqlx::query(&format!(
            "SELECT \"{column}\" FROM public.\"{table}\" LIMIT 0"
        ))
        .execute(&mut *tx)
        .await
        .expect_err("hidden column read must fail");
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        );
        tx.rollback().await.expect("rollback denied read");
    }

    let mut tx = pool
        .begin()
        .await
        .expect("begin permitted reader transaction");
    sqlx::query("SET LOCAL ROLE support_reader")
        .execute(&mut *tx)
        .await
        .expect("assume support reader locally");
    sqlx::query("SELECT email, email_verified, pending_email FROM public.users LIMIT 0")
        .execute(&mut *tx)
        .await
        .expect("support can read classified account fields");
    tx.rollback().await.expect("rollback permitted read");

    // Replaying against an existing role must keep its identity and grants.
    sqlx::raw_sql(MIGRATION)
        .execute(&pool)
        .await
        .expect("replay migration with an existing role");
    let oid: i32 =
        sqlx::query_scalar("SELECT oid::int FROM pg_roles WHERE rolname = 'support_reader'")
            .fetch_one(&pool)
            .await
            .expect("read preserved role");
    assert_eq!(oid, role.0);

    let mut tx = pool.begin().await.expect("begin future schema probe");
    sqlx::query("ALTER TABLE public.users ADD COLUMN support_reader_unclassified_test text")
        .execute(&mut *tx)
        .await
        .expect("add unclassified probe column");
    let readable: bool = sqlx::query_scalar(
        "SELECT has_column_privilege('support_reader', 'public.users',
                                     'support_reader_unclassified_test', 'SELECT')",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read probe privilege");
    assert!(
        !readable,
        "new columns are unreadable until explicitly classified"
    );
    tx.rollback().await.expect("rollback future schema probe");
}

#[sqlx::test(migrations = "../database/migrations")]
async fn migration_refuses_schema_create_it_cannot_revoke(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin schema privilege probe");
    let migrator = format!("support_migrator_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE ROLE {migrator} NOLOGIN"))
        .execute(&mut *tx)
        .await
        .expect("create an unprivileged test migrator");
    sqlx::query("GRANT CREATE ON SCHEMA public TO PUBLIC")
        .execute(&mut *tx)
        .await
        .expect("restore legacy schema creation privilege for this probe");
    sqlx::query(&format!("SET LOCAL ROLE {migrator}"))
        .execute(&mut *tx)
        .await
        .expect("assume a non-owner migrator");

    let error = sqlx::raw_sql(MIGRATION)
        .execute(&mut *tx)
        .await
        .expect_err("migration must refuse an effective schema creation privilege");
    let database_error = error
        .as_database_error()
        .expect("Postgres rejects migration");
    assert_eq!(database_error.code().as_deref(), Some("42501"));
    assert!(
        database_error
            .message()
            .starts_with("support_reader must not create objects in schema public"),
        "the explicit privilege assertion must reject the migration, not a later grant"
    );
    // Also removes the test-only cluster role and restores the schema ACL.
    tx.rollback()
        .await
        .expect("rollback schema privilege probe");
}
