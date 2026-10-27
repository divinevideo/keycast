//! Explicit, aggregate-only audit of linked permission conversion. See
//! docs/challenge-signing-policy.md for invocation and operational limits.
use keycast_core::types::permission::{JsonConfig, Permission, PermissionError};
use serde::Serialize;

#[derive(Debug, Default, PartialEq, Serialize)]
struct Failures {
    malformed_json: u64,
    unknown_permission: u64,
    invalid_config: u64,
    conversion_database: u64,
}

#[derive(Debug, Default, Serialize)]
struct Conversions {
    succeeded: u64,
    failed: u64,
    display_succeeded: u64,
    failures: Failures,
}

impl Conversions {
    fn record(&mut self, identifier: String, config: String) {
        let config = match JsonConfig::try_from(config) {
            Ok(config) => config,
            Err(_) => {
                self.failed += 1;
                self.failures.malformed_json += 1;
                return;
            }
        };
        // Neither the factory nor display uses database metadata. Do not fetch it.
        let permission = Permission {
            id: 0,
            identifier,
            config,
            created_at: chrono::DateTime::UNIX_EPOCH,
            updated_at: chrono::DateTime::UNIX_EPOCH,
        };
        match permission.to_custom_permission() {
            Ok(custom) => {
                // Same conversion as Policy::permission_displays; discard all text.
                let _ = custom.display();
                self.succeeded += 1;
                self.display_succeeded += 1;
            }
            Err(error) => {
                self.failed += 1;
                match error {
                    PermissionError::UnknownPermission(_) => self.failures.unknown_permission += 1,
                    PermissionError::InvalidConfig(_) => self.failures.invalid_config += 1,
                    PermissionError::Database(_) => self.failures.conversion_database += 1,
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Limits {
    rows: i64,
    bytes: i64,
    row_bytes: i64,
}
const LIMITS: Limits = Limits {
    rows: 10_000,
    bytes: 8 * 1024 * 1024,
    row_bytes: 256 * 1024,
};

#[derive(Debug, PartialEq)]
enum AuditError {
    Usage,
    ConnectionRequired,
    Database,
    ReadOnly,
    Budget,
    Incomplete,
    Timeout,
    Output,
}
impl AuditError {
    fn message(&self) -> &'static str {
        match self {
            Self::Usage => "audit: require --audit-linked-permissions-read-only",
            Self::ConnectionRequired => "audit: require KEYCAST_PERMISSION_AUDIT_DATABASE_URL",
            Self::Database => "audit: database operation failed",
            Self::ReadOnly => "audit: server transaction settings not verified",
            Self::Budget => "audit: row or byte budget exceeded; audit incomplete",
            Self::Incomplete => "audit: linked permission set incomplete",
            Self::Timeout => "audit: time budget exceeded; audit incomplete",
            Self::Output => "audit: aggregate output failed",
        }
    }
}

#[derive(Debug, Default, Serialize, sqlx::FromRow)]
struct Totals {
    linked_policies: i64,
    links: i64,
    distinct_permissions: i64,
    available_permissions: i64,
    invalid_links: i64,
    config_and_identifier_bytes: i64,
    largest_row_bytes: i64,
}
impl Totals {
    fn check(&self, limits: Limits) -> Result<(), AuditError> {
        if self.invalid_links != 0 || self.distinct_permissions != self.available_permissions {
            return Err(AuditError::Incomplete);
        }
        if self.links > limits.rows
            || self.distinct_permissions > limits.rows
            || self.config_and_identifier_bytes > limits.bytes
            || self.largest_row_bytes > limits.row_bytes
        {
            return Err(AuditError::Budget);
        }
        Ok(())
    }
}
#[derive(Debug, Default, Serialize)]
struct Report {
    totals: Totals,
    conversions: Conversions,
}
impl Report {
    fn passed(&self) -> bool {
        self.conversions.failed == 0
    }
}
async fn begin_audit(
    pool: &sqlx::PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, AuditError> {
    let mut tx = pool
        .begin_with("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await
        .map_err(|_| AuditError::Database)?;
    for statement in [
        "SET LOCAL statement_timeout = '15s'",
        "SET LOCAL lock_timeout = '2s'",
        "SET LOCAL idle_in_transaction_session_timeout = '30s'",
    ] {
        sqlx::query(statement)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuditError::Database)?;
    }
    let read_only: String = sqlx::query_scalar("SHOW transaction_read_only")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuditError::Database)?;
    let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuditError::Database)?;
    if read_only != "on" || isolation != "repeatable read" {
        return Err(AuditError::ReadOnly);
    }
    Ok(tx)
}
// Only aggregate sizes leave the server until every budget has passed. EXISTS
// deduplicates shared permissions without comparing or grouping config text.
const TOTALS_SQL: &str = "
    WITH linked AS (
        SELECT p.id, octet_length(p.identifier)::bigint + octet_length(p.config)::bigint AS bytes
        FROM public.permissions p
        WHERE EXISTS (SELECT 1 FROM public.policy_permissions pp WHERE pp.permission_id = p.id)
    )
    SELECT
        count(DISTINCT pp.policy_id)::bigint AS linked_policies,
        count(*)::bigint AS links,
        count(DISTINCT pp.permission_id)::bigint AS distinct_permissions,
        (SELECT count(*) FROM linked)::bigint AS available_permissions,
        count(*) FILTER (WHERE pp.policy_id IS NULL OR p.id IS NULL)::bigint AS invalid_links,
        (SELECT coalesce(sum(bytes), 0)::bigint FROM linked) AS config_and_identifier_bytes,
        (SELECT coalesce(max(bytes), 0)::bigint FROM linked) AS largest_row_bytes
    FROM public.policy_permissions pp
    LEFT JOIN public.permissions p ON p.id = pp.permission_id";

async fn audit_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    limits: Limits,
) -> Result<Report, AuditError> {
    let totals = sqlx::query_as::<_, Totals>(TOTALS_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| AuditError::Database)?;
    totals.check(limits)?;
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT p.identifier, p.config FROM public.permissions p
         WHERE EXISTS (SELECT 1 FROM public.policy_permissions pp WHERE pp.permission_id = p.id)
         ORDER BY p.id LIMIT $1",
    )
    .bind(limits.rows + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| AuditError::Database)?;
    if rows.len() as i64 != totals.distinct_permissions {
        return Err(AuditError::Incomplete);
    }
    let mut conversions = Conversions::default();
    for (identifier, config) in rows {
        conversions.record(identifier, config);
    }
    if conversions.succeeded + conversions.failed != totals.distinct_permissions as u64 {
        return Err(AuditError::Incomplete);
    }
    Ok(Report {
        totals,
        conversions,
    })
}
async fn run() -> Result<Report, AuditError> {
    use sqlx::{
        postgres::{PgConnectOptions, PgPoolOptions},
        ConnectOptions,
    };
    use std::time::Duration;
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--audit-linked-permissions-read-only"))
        || args.next().is_some()
    {
        return Err(AuditError::Usage);
    }
    // Deliberately no dotenv, app configuration, logging, migrations or key manager.
    let url = std::env::var("KEYCAST_PERMISSION_AUDIT_DATABASE_URL")
        .map_err(|_| AuditError::ConnectionRequired)?;
    let options = url
        .parse::<PgConnectOptions>()
        .map_err(|_| AuditError::Database)?
        .application_name("keycast_permission_audit")
        .disable_statement_logging();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .map_err(|_| AuditError::Database)?;
    let result = async {
        let mut tx = begin_audit(&pool).await?;
        let report = audit_snapshot(&mut tx, LIMITS).await?;
        // No commit, including on a successful audit.
        tx.rollback().await.map_err(|_| AuditError::Database)?;
        Ok(report)
    }
    .await;
    pool.close().await;
    result
}

fn write_report(report: &Report) -> Result<(), AuditError> {
    use std::io::Write;
    let output = serde_json::json!({
        "complete": true, "passed": report.passed(),
        "totals": report.totals, "conversions": report.conversions,
    });
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output).map_err(|_| AuditError::Output)?;
    writeln!(stdout).map_err(|_| AuditError::Output)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), run())
        .await
        .unwrap_or(Err(AuditError::Timeout));
    let error = match result {
        Ok(report) => match write_report(&report) {
            Ok(()) if report.passed() => return std::process::ExitCode::SUCCESS,
            Ok(()) => {
                eprintln!("audit: linked permission conversion failed");
                return std::process::ExitCode::FAILURE;
            }
            Err(error) => error,
        },
        Err(error) => error,
    };
    eprintln!("{}", error.message());
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_factory_and_consent_display_accept_known_permissions() {
        let mut result = Conversions::default();
        for (identifier, config) in [
            ("allowed_kinds", r#"{"allowed_kinds":[1,1111]}"#),
            ("allowed_kinds_legacy", r#"{"allowed_kinds":[]}"#),
            ("content_filter", r#"{"blocked_words":["synthetic"]}"#),
            ("decrypt_only", "{}"),
            ("encrypt_to_self", "{}"),
            ("full_access", "{}"),
            ("challenge_actions", "{}"),
        ] {
            result.record(identifier.into(), config.into());
        }
        assert_eq!(result.succeeded, 7);
        assert_eq!(result.display_succeeded, 7);
        assert_eq!(result.failed, 0);
        assert_eq!(result.failures, Failures::default());
    }

    #[test]
    fn mixed_rows_report_safe_failures_without_losing_valid_conversions() {
        let mut result = Conversions::default();
        for (identifier, config) in [
            ("full_access", "{}"),
            ("synthetic_unknown_identifier", "{}"),
            ("challenge_actions", r#"{"synthetic_private_option":true}"#),
            (
                "allowed_kinds",
                r#"{"allowed_kinds":"synthetic_private_value"}"#,
            ),
            ("content_filter", "synthetic malformed json"),
        ] {
            result.record(identifier.into(), config.into());
        }
        assert_eq!(result.succeeded, 1);
        assert_eq!(result.display_succeeded, 1);
        assert_eq!(result.failed, 4);
        assert_eq!(
            result.failures,
            Failures {
                malformed_json: 1,
                unknown_permission: 1,
                invalid_config: 2,
                conversion_database: 0,
            }
        );
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains("synthetic"));
        assert!(!output.contains("challenge_actions"));
        assert!(!output.contains("allowed_kinds"));
    }
    #[test]
    fn budgets_and_missing_rows_fail_closed() {
        let valid = || Totals {
            links: 2,
            distinct_permissions: 1,
            available_permissions: 1,
            config_and_identifier_bytes: 20,
            largest_row_bytes: 20,
            ..Default::default()
        };
        let limits = Limits {
            rows: 2,
            bytes: 20,
            row_bytes: 20,
        };
        assert_eq!(valid().check(limits), Ok(()));
        assert_eq!(
            valid().check(Limits { rows: 1, ..limits }),
            Err(AuditError::Budget)
        );
        assert_eq!(
            valid().check(Limits {
                bytes: 19,
                ..limits
            }),
            Err(AuditError::Budget)
        );
        assert_eq!(
            valid().check(Limits {
                row_bytes: 19,
                ..limits
            }),
            Err(AuditError::Budget)
        );
        assert_eq!(
            Totals {
                available_permissions: 0,
                ..valid()
            }
            .check(limits),
            Err(AuditError::Incomplete)
        );
        assert_eq!(
            Totals {
                invalid_links: 1,
                ..valid()
            }
            .check(limits),
            Err(AuditError::Incomplete)
        );
    }

    // Explicit feature and dedicated fixture URL: never use DATABASE_URL or shared services.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn owned_database_snapshot_budgets_and_readonly() {
        use sqlx::{postgres::PgConnectOptions, ConnectOptions};
        let url = std::env::var("KEYCAST_PERMISSION_AUDIT_TEST_DATABASE_URL")
            .expect("Set the dedicated owned audit test database URL");
        let options: PgConnectOptions = url.parse().expect("Invalid test database options");
        assert_eq!(options.get_host(), "127.0.0.1");
        assert_eq!(options.get_port(), 55448);
        assert_eq!(
            options.get_database(),
            Some("keycast_permission_audit_test")
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options.disable_statement_logging())
            .await
            .unwrap();
        // Fixture matches initial migration's relevant TEXT/nullable-link columns.
        sqlx::raw_sql("DROP TABLE IF EXISTS policy_permissions; DROP TABLE IF EXISTS permissions;
            CREATE TABLE permissions (id integer PRIMARY KEY, identifier text NOT NULL, config text NOT NULL);
            CREATE TABLE policy_permissions (id integer PRIMARY KEY, policy_id integer, permission_id integer);
            INSERT INTO permissions VALUES (1,'full_access','{}'), (2,'unknown_synthetic','{}'),
                (3,'challenge_actions','{bad'), (4,'challenge_actions','{\"extra\":true}'),
                (5,'content_filter','unlinked malformed');
            INSERT INTO policy_permissions VALUES (1,10,1),(2,11,1),(3,10,2),(4,10,3),(5,10,4);")
            .execute(&pool).await.unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        let report = audit_snapshot(&mut tx, LIMITS).await.unwrap();
        assert_eq!(report.totals.linked_policies, 2);
        assert_eq!(report.totals.links, 5);
        assert_eq!(report.totals.distinct_permissions, 4);
        assert_eq!(report.totals.available_permissions, 4);
        assert_eq!(report.totals.invalid_links, 0);
        assert_eq!(report.totals.config_and_identifier_bytes, 84);
        assert_eq!(report.totals.largest_row_bytes, 31);
        assert_eq!(report.conversions.succeeded, 1);
        assert_eq!(report.conversions.failed, 3);
        assert_eq!(report.conversions.failures.malformed_json, 1);
        assert_eq!(report.conversions.failures.unknown_permission, 1);
        assert_eq!(report.conversions.failures.invalid_config, 1);
        assert!(!report.passed());
        tx.rollback().await.unwrap();

        let mut tx = begin_audit(&pool).await.unwrap();
        for (setting, expected) in [
            ("SHOW statement_timeout", "15s"),
            ("SHOW lock_timeout", "2s"),
            ("SHOW idle_in_transaction_session_timeout", "30s"),
        ] {
            let actual: String = sqlx::query_scalar(setting)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(actual, expected);
        }
        let error = sqlx::query("INSERT INTO permissions VALUES (99,'full_access','{}')")
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("25006")
        );
        tx.rollback().await.unwrap();

        // Establish the snapshot, then commit a concurrent writer on a different connection.
        let writer = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        let _: i64 = sqlx::query_scalar("SELECT count(*) FROM policy_permissions")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sqlx::raw_sql(
            "INSERT INTO permissions VALUES (6,'full_access','{}');
            INSERT INTO policy_permissions VALUES (6,12,6)",
        )
        .execute(&writer)
        .await
        .unwrap();
        let report = audit_snapshot(&mut tx, LIMITS).await.unwrap();
        assert_eq!(report.totals.links, 5);
        assert_eq!(report.totals.distinct_permissions, 4);
        assert_eq!(report.conversions.succeeded, 1);
        tx.rollback().await.unwrap();
        writer.close().await;

        for limits in [
            Limits { rows: 5, ..LIMITS },
            Limits { bytes: 1, ..LIMITS },
            Limits {
                row_bytes: 1,
                ..LIMITS
            },
        ] {
            let mut tx = begin_audit(&pool).await.unwrap();
            assert!(matches!(
                audit_snapshot(&mut tx, limits).await,
                Err(AuditError::Budget)
            ));
            tx.rollback().await.unwrap();
        }
        // Oversized TEXT is rejected by SQL size preflight, before JSON decoding.
        sqlx::query("UPDATE permissions SET config = repeat('x', 262145) WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        assert!(matches!(
            audit_snapshot(&mut tx, LIMITS).await,
            Err(AuditError::Budget)
        ));
        tx.rollback().await.unwrap();

        sqlx::query("DELETE FROM policy_permissions")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        let report = audit_snapshot(&mut tx, LIMITS).await.unwrap();
        assert!(report.passed());
        assert_eq!(report.totals.links, 0);
        assert_eq!(report.conversions.succeeded, 0);
        tx.rollback().await.unwrap();

        sqlx::query("INSERT INTO policy_permissions VALUES (1,10,NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        assert!(matches!(
            audit_snapshot(&mut tx, LIMITS).await,
            Err(AuditError::Incomplete)
        ));
        tx.rollback().await.unwrap();
        sqlx::query("UPDATE policy_permissions SET permission_id = 999 WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        assert!(matches!(
            audit_snapshot(&mut tx, LIMITS).await,
            Err(AuditError::Incomplete)
        ));
        tx.rollback().await.unwrap();
        sqlx::raw_sql("DROP TABLE policy_permissions; DROP TABLE permissions;")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = begin_audit(&pool).await.unwrap();
        assert!(matches!(
            audit_snapshot(&mut tx, LIMITS).await,
            Err(AuditError::Database)
        ));
        tx.rollback().await.unwrap();
        pool.close().await;
    }
}
