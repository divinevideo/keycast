#![cfg(feature = "integration-tests")]

// ABOUTME: Verifies the OG Diviner grant loader writes a roster idempotently.
// ABOUTME: Pins dry-run, re-run, unknown-tenant, and schema-guard behavior.

use keycast_core::repositories::{
    parse_grant_roster, OgDivinerGrantEvidence, OgDivinerGrantRepository, RepositoryError,
};
use serial_test::serial;
use sqlx::PgPool;

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
    let keys = vec![key('a'), key('a').to_uppercase()];
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

    assert!(uppercase.is_err(), "uppercase hex must not be stored");
    assert!(
        unknown_evidence.is_err(),
        "evidence labels outside the vocabulary must not be stored"
    );
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
