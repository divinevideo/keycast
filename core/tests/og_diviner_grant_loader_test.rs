#![cfg(feature = "integration-tests")]

// ABOUTME: Verifies the OG Diviner grant loader writes a roster idempotently.
// ABOUTME: Pins dry-run, re-run, unknown-tenant, and schema-guard behavior.

use keycast_core::repositories::{
    parse_grant_roster, OgDivinerGrantEvidence, OgDivinerGrantRepository, RepositoryError,
};
use serial_test::serial;
use sqlx::postgres::PgPool;

const TENANT_ID: i64 = 1;
const EVIDENCE: OgDivinerGrantEvidence = OgDivinerGrantEvidence::PreCutoffAppPost;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    assert!(url.contains("localhost") || url.contains("127.0.0.1"));
    PgPool::connect(&url)
        .await
        .expect("connect to test database")
}

/// A prefix unique to this test, so its rows never collide with another's.
fn key(seed: char) -> String {
    format!("06d3{}", std::iter::repeat_n(seed, 60).collect::<String>())
}

async fn purge(pool: &PgPool, keys: &[String]) {
    sqlx::query("DELETE FROM og_diviner_grants WHERE pubkey = ANY($1)")
        .bind(keys)
        .execute(pool)
        .await
        .unwrap();
}

async fn granted(pool: &PgPool, keys: &[String]) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT pubkey, evidence FROM og_diviner_grants
         WHERE tenant_id = $1 AND pubkey = ANY($2)
         ORDER BY pubkey",
    )
    .bind(TENANT_ID)
    .bind(keys)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[serial]
async fn applying_the_same_roster_twice_grants_each_pubkey_once() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let keys = vec![key('a'), key('b'), key('c')];
    purge(&pool, &keys).await;
    let roster = parse_grant_roster(&format!(
        "{}\n{}\n{}\n{}\n",
        keys[0], keys[1], keys[2], keys[0]
    ))
    .unwrap();

    let first = repository.load(TENANT_ID, EVIDENCE, &roster, true).await;
    let second = repository.load(TENANT_ID, EVIDENCE, &roster, true).await;
    let rows = granted(&pool, &keys).await;
    purge(&pool, &keys).await;

    let first = first.unwrap();
    assert!(first.applied);
    assert_eq!(first.unique, 3);
    assert_eq!(first.newly_granted, 3);
    assert_eq!(first.already_granted, 0);

    let second = second.unwrap();
    assert_eq!(second.newly_granted, 0, "a re-run grants nothing new");
    assert_eq!(second.already_granted, 3);

    assert_eq!(
        rows,
        keys.iter()
            .map(|k| (k.clone(), "pre_cutoff_app_post".to_string()))
            .collect::<Vec<_>>(),
        "one row per unique pubkey, labelled with the evidence"
    );
}

#[tokio::test]
#[serial]
async fn a_dry_run_counts_without_writing() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let keys = vec![key('d'), key('e')];
    purge(&pool, &keys).await;
    let already = parse_grant_roster(&keys[0]).unwrap();
    repository
        .load(TENANT_ID, EVIDENCE, &already, true)
        .await
        .unwrap();
    let roster = parse_grant_roster(&keys.join("\n")).unwrap();

    let report = repository.load(TENANT_ID, EVIDENCE, &roster, false).await;
    let rows = granted(&pool, &keys).await;
    purge(&pool, &keys).await;

    let report = report.unwrap();
    assert!(!report.applied);
    assert_eq!(report.unique, 2);
    assert_eq!(
        report.newly_granted, 1,
        "the dry run reports what would be new"
    );
    assert_eq!(report.already_granted, 1);
    assert_eq!(
        rows.len(),
        1,
        "the dry run wrote nothing beyond the pre-existing grant"
    );
}

#[tokio::test]
#[serial]
async fn an_unknown_tenant_is_rejected_before_anything_is_written() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let keys = vec![key('f')];
    purge(&pool, &keys).await;
    let roster = parse_grant_roster(&keys[0]).unwrap();
    let missing_tenant = i64::MAX;

    let dry_run = repository
        .load(missing_tenant, EVIDENCE, &roster, false)
        .await;
    let applied = repository
        .load(missing_tenant, EVIDENCE, &roster, true)
        .await;
    let written: i64 =
        sqlx::query_scalar("SELECT count(*) FROM og_diviner_grants WHERE pubkey = $1")
            .bind(&keys[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    purge(&pool, &keys).await;

    assert!(
        matches!(dry_run, Err(RepositoryError::NotFound(_))),
        "a dry run against a missing tenant must fail, not report success: {dry_run:?}"
    );
    assert!(
        matches!(applied, Err(RepositoryError::NotFound(_))),
        "got {applied:?}"
    );
    assert_eq!(written, 0);
}

#[tokio::test]
#[serial]
async fn the_table_rejects_malformed_pubkeys_and_unknown_evidence() {
    let pool = pool().await;
    // Its own seed: purging another test's key would race it under a
    // process-per-test runner, where #[serial] does not reach.
    let keys = vec![key('0'), key('0').to_uppercase()];
    purge(&pool, &keys).await;

    let uppercase = sqlx::query(
        "INSERT INTO og_diviner_grants (tenant_id, pubkey, evidence)
         VALUES (1, $1, 'pre_cutoff_app_post')",
    )
    .bind(&keys[1])
    .execute(&pool)
    .await;
    let unknown_evidence = sqlx::query(
        "INSERT INTO og_diviner_grants (tenant_id, pubkey, evidence)
         VALUES (1, $1, 'vibes')",
    )
    .bind(&keys[0])
    .execute(&pool)
    .await;
    purge(&pool, &keys).await;

    // 23514 is check_violation: the rejection must come from the table's own
    // constraints, not from some unrelated failure such as a missing tenant.
    assert_eq!(
        sqlstate(&uppercase).as_deref(),
        Some("23514"),
        "uppercase hex must not be stored"
    );
    assert_eq!(
        sqlstate(&unknown_evidence).as_deref(),
        Some("23514"),
        "evidence labels outside the vocabulary must not be stored"
    );
}

fn sqlstate<T>(result: &Result<T, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => error.code().map(|code| code.into_owned()),
        _ => None,
    }
}

#[tokio::test]
#[serial]
async fn a_dry_run_counts_only_grants_in_its_own_tenant() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let other_tenant: i64 = sqlx::query_scalar(
        "INSERT INTO tenants (domain, name) VALUES ('og-diviner-loader.example.invalid', 'OG loader test')
         ON CONFLICT (domain) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let keys = vec![key('7'), key('8')];
    purge(&pool, &keys).await;
    let roster = parse_grant_roster(&keys.join("\n")).unwrap();
    // The same pubkeys already granted elsewhere must not count as granted here.
    repository
        .load(other_tenant, EVIDENCE, &roster, true)
        .await
        .unwrap();

    let dry_run = repository.load(TENANT_ID, EVIDENCE, &roster, false).await;
    let applied = repository.load(TENANT_ID, EVIDENCE, &roster, true).await;
    purge(&pool, &keys).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(other_tenant)
        .execute(&pool)
        .await
        .unwrap();

    let (dry_run, applied) = (dry_run.unwrap(), applied.unwrap());
    assert_eq!(applied.newly_granted, 2);
    assert_eq!(
        (dry_run.newly_granted, dry_run.already_granted),
        (applied.newly_granted, applied.already_granted),
        "a dry run predicts exactly what applying in the same tenant does"
    );
}

#[tokio::test]
#[serial]
async fn the_report_names_the_tenant_it_loaded_into() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let tenant: i64 = sqlx::query_scalar(
        "INSERT INTO tenants (domain, name) VALUES ('og-diviner-report.example.invalid', 'OG report test')
         ON CONFLICT (domain) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let roster = parse_grant_roster(&key('9')).unwrap();

    let report = repository.load(tenant, EVIDENCE, &roster, false).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();

    let report = report.unwrap();
    assert_eq!(report.tenant_domain, "og-diviner-report.example.invalid");
    assert_eq!(report.tenant_name, "OG report test");
}

/// The loader prints load errors, and Postgres reports the failing row --
/// pubkey included -- in a constraint violation's detail. The only thing
/// keeping that row out of the output is RepositoryError's conversion keeping
/// the message and dropping the detail. Pin it.
#[tokio::test]
#[serial]
async fn repository_errors_do_not_carry_the_failing_row() {
    let pool = pool().await;
    let row_pubkey = key('b').to_uppercase();
    purge(&pool, std::slice::from_ref(&row_pubkey)).await;

    let raw = sqlx::query(
        "INSERT INTO og_diviner_grants (tenant_id, pubkey, evidence)
         VALUES (1, $1, 'pre_cutoff_app_post')",
    )
    .bind(&row_pubkey)
    .execute(&pool)
    .await
    .expect_err("an uppercase pubkey violates the CHECK constraint");
    purge(&pool, std::slice::from_ref(&row_pubkey)).await;

    assert!(
        format!("{raw:?}").contains(&row_pubkey),
        "positive control: the raw sqlx error carries the failing row"
    );
    let converted = RepositoryError::from(raw);
    assert!(
        matches!(converted, RepositoryError::Integrity(_)),
        "got {converted:?}"
    );
    assert!(
        !converted.to_string().contains(&row_pubkey),
        "Display must not carry the failing row"
    );
    assert!(
        !format!("{converted:?}").contains(&row_pubkey),
        "Debug must not carry the failing row"
    );
}

/// Records a completed service deletion of `pubkey` in `tenant_id`, as the
/// deletion coordinator's call would. The request id is derived from the
/// pubkey so `forget_deletions` can find it again.
async fn record_deletion(pool: &PgPool, tenant_id: i64, pubkey: &str) {
    sqlx::query(
        "INSERT INTO service_account_deletions
             (deletion_request_id, tenant_id, user_pubkey, outcome)
         VALUES ($1, $2, $3, 'already_absent')",
    )
    .bind(format!("og-loader-test-{tenant_id}-{pubkey}"))
    .bind(tenant_id)
    .bind(pubkey)
    .execute(pool)
    .await
    .unwrap();
}

async fn forget_deletions(pool: &PgPool, keys: &[String]) {
    sqlx::query("DELETE FROM service_account_deletions WHERE user_pubkey = ANY($1)")
        .bind(keys)
        .execute(pool)
        .await
        .unwrap();
}

async fn grant_directly(pool: &PgPool, pubkey: &str) {
    sqlx::query(
        "INSERT INTO og_diviner_grants (tenant_id, pubkey, evidence)
         VALUES ($1, $2, 'pre_cutoff_app_post')",
    )
    .bind(TENANT_ID)
    .bind(pubkey)
    .execute(pool)
    .await
    .unwrap();
}

/// Someone who already deleted their account must not be granted: the
/// coordinator will never call Keycast for them again, so nothing would ever
/// remove the grant.
#[tokio::test]
#[serial]
async fn a_recorded_deletion_excludes_the_pubkey_from_dry_run_and_apply() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let keys = vec![key('1'), key('2')];
    purge(&pool, &keys).await;
    forget_deletions(&pool, &keys).await;
    record_deletion(&pool, TENANT_ID, &keys[0]).await;
    let roster = parse_grant_roster(&keys.join("\n")).unwrap();

    let dry_run = repository.load(TENANT_ID, EVIDENCE, &roster, false).await;
    let applied = repository.load(TENANT_ID, EVIDENCE, &roster, true).await;
    let rows = granted(&pool, &keys).await;
    purge(&pool, &keys).await;
    forget_deletions(&pool, &keys).await;

    let (dry_run, applied) = (dry_run.unwrap(), applied.unwrap());
    assert_eq!(
        (
            applied.unique,
            applied.newly_granted,
            applied.already_granted,
            applied.excluded_deleted,
            applied.revoked_deleted,
        ),
        (2, 1, 0, 1, 0),
        "the deleted pubkey is excluded, the other granted"
    );
    assert_eq!(
        (
            dry_run.newly_granted,
            dry_run.already_granted,
            dry_run.excluded_deleted,
            dry_run.revoked_deleted,
        ),
        (
            applied.newly_granted,
            applied.already_granted,
            applied.excluded_deleted,
            applied.revoked_deleted,
        ),
        "a dry run predicts exactly what applying does"
    );
    assert_eq!(
        rows,
        vec![(keys[1].clone(), "pre_cutoff_app_post".to_string())],
        "no grant was written for the deleted pubkey"
    );
}

/// Positive control for the exclusion's tenant filter: a deletion recorded in
/// another tenant says nothing about this one.
#[tokio::test]
#[serial]
async fn a_deletion_in_another_tenant_does_not_exclude_the_pubkey() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let other_tenant: i64 = sqlx::query_scalar(
        "INSERT INTO tenants (domain, name) VALUES ('og-diviner-deleted.example.invalid', 'OG deleted test')
         ON CONFLICT (domain) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let keys = vec![key('3')];
    purge(&pool, &keys).await;
    forget_deletions(&pool, &keys).await;
    record_deletion(&pool, other_tenant, &keys[0]).await;
    let roster = parse_grant_roster(&keys[0]).unwrap();

    let dry_run = repository.load(TENANT_ID, EVIDENCE, &roster, false).await;
    let applied = repository.load(TENANT_ID, EVIDENCE, &roster, true).await;
    let rows = granted(&pool, &keys).await;
    purge(&pool, &keys).await;
    forget_deletions(&pool, &keys).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(other_tenant)
        .execute(&pool)
        .await
        .unwrap();

    let (dry_run, applied) = (dry_run.unwrap(), applied.unwrap());
    assert_eq!((dry_run.newly_granted, dry_run.excluded_deleted), (1, 0));
    assert_eq!((applied.newly_granted, applied.excluded_deleted), (1, 0));
    assert_eq!(rows.len(), 1, "the grant lands in this tenant");
}

/// A grant whose pubkey has a recorded deletion is revoked by the load and
/// counted as excluded, not as already granted. The deletion path normally
/// removes the grant itself, so this covers a grant the deletion could not
/// see: one a load inserted while that deletion ran. A dry run after the load
/// reports it under "would revoke", and applying again removes it (see the
/// `revoked` step in `OgDivinerGrantRepository::load`).
#[tokio::test]
#[serial]
async fn a_load_revokes_a_grant_whose_pubkey_has_a_recorded_deletion() {
    let pool = pool().await;
    let repository = OgDivinerGrantRepository::new(pool.clone());
    let keys = vec![key('4'), key('5')];
    purge(&pool, &keys).await;
    forget_deletions(&pool, &keys).await;
    grant_directly(&pool, &keys[0]).await;
    grant_directly(&pool, &keys[1]).await;
    record_deletion(&pool, TENANT_ID, &keys[0]).await;
    let roster = parse_grant_roster(&keys.join("\n")).unwrap();

    let dry_run = repository.load(TENANT_ID, EVIDENCE, &roster, false).await;
    let after_dry_run = granted(&pool, &keys).await;
    let applied = repository.load(TENANT_ID, EVIDENCE, &roster, true).await;
    let rows = granted(&pool, &keys).await;
    purge(&pool, &keys).await;
    forget_deletions(&pool, &keys).await;

    let (dry_run, applied) = (dry_run.unwrap(), applied.unwrap());
    assert_eq!(
        (
            applied.newly_granted,
            applied.already_granted,
            applied.excluded_deleted,
            applied.revoked_deleted,
        ),
        (0, 1, 1, 1)
    );
    assert_eq!(
        (
            dry_run.newly_granted,
            dry_run.already_granted,
            dry_run.excluded_deleted,
            dry_run.revoked_deleted,
        ),
        (0, 1, 1, 1),
        "a dry run predicts exactly what applying does"
    );
    assert_eq!(after_dry_run.len(), 2, "the dry run revoked nothing");
    assert_eq!(
        rows,
        vec![(keys[1].clone(), "pre_cutoff_app_post".to_string())],
        "only the deleted pubkey's grant was removed"
    );
}
