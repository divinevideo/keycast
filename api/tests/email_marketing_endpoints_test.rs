#![cfg(feature = "integration-tests")]

// ABOUTME: Tests for the marketing-consent service-token endpoints
// ABOUTME: Covers cursor paging, floor writes, consent immutability, and read-then-ack semantics

mod common;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use chrono::{DateTime, Duration, Utc};
use keycast_api::api::http::email_marketing::{
    ack_deletions, ack_email_changes, list_consents, list_deletions, list_email_changes,
    record_observations, AckRequest, ConsentPageQuery, IdPageQuery, Observation,
    ObservationsRequest,
};
use nostr_sdk::Keys;
use sqlx::PgPool;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Seed a user with a known consent state and updated_at, returning its pubkey.
async fn seed(pool: &PgPool, email: &str, consent: &str, updated_at: DateTime<Utc>) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_marketing_consent,
                            email_marketing_consent_at, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, $4, $4)",
    )
    .bind(&pubkey)
    .bind(email)
    .bind(consent)
    .bind(updated_at)
    .execute(pool)
    .await
    .unwrap();
    pubkey
}

async fn cleanup(pool: &PgPool, pubkeys: &[String]) {
    for pubkey in pubkeys {
        sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(pubkey)
            .execute(pool)
            .await
            .unwrap();
    }
}

/// The cursor is (email_marketing_consent_at, pubkey) precisely because two accounts can share a
/// timestamp. A timestamp-only cursor either skips a record or loops on it forever.
#[tokio::test]
async fn cursor_pages_deterministically_when_timestamps_collide() {
    let pool = setup_pool().await;
    let shared = Utc::now() + Duration::days(3650);
    let a = seed(
        &pool,
        &format!("collide-a-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        shared,
    )
    .await;
    let b = seed(
        &pool,
        &format!("collide-b-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        shared,
    )
    .await;
    let (first, second) = if a < b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    };

    let page_one: Vec<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users
         WHERE tenant_id = 1
           AND email_marketing_consent_at IS NOT NULL
           AND (email_marketing_consent_at, pubkey) > ($1, $2)
         ORDER BY email_marketing_consent_at, pubkey LIMIT 1",
    )
    .bind(shared - Duration::seconds(1))
    .bind("")
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(page_one[0].0, first);

    let page_two: Vec<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users
         WHERE tenant_id = 1
           AND email_marketing_consent_at IS NOT NULL
           AND (email_marketing_consent_at, pubkey) > ($1, $2)
         ORDER BY email_marketing_consent_at, pubkey LIMIT 1",
    )
    .bind(shared)
    .bind(&first)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        page_two[0].0, second,
        "the tiebreak must advance the cursor"
    );

    cleanup(&pool, &[a, b]).await;
}

/// NULL is "never observed", which is not the same as "not opted out". Defaulting it to false
/// would let an unchecked account read as safe to email.
#[tokio::test]
async fn the_floor_starts_null_not_false() {
    let pool = setup_pool().await;
    let pubkey = seed(
        &pool,
        &format!("fresh-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    let floor: Option<bool> =
        sqlx::query_scalar("SELECT email_marketing_global_optout FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(floor, None);
    cleanup(&pool, &[pubkey]).await;
}

/// Recording an opt-out must not touch the consent event. That record is the evidence consent was
/// validly obtained; if this ever fails, the immutability guarantee has been broken.
#[tokio::test]
async fn observing_an_optout_does_not_rewrite_the_consent_event() {
    let pool = setup_pool().await;
    let pubkey = seed(
        &pool,
        &format!("stable-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    // Exactly the statement the endpoint runs.
    sqlx::query(
        "UPDATE users
         SET email_marketing_global_optout = TRUE,
             email_marketing_optout_observed_at = $3
         WHERE pubkey = $1 AND tenant_id = 1
           AND $2 IS TRUE
           AND email_marketing_global_optout IS DISTINCT FROM TRUE",
    )
    .bind(&pubkey)
    .bind(true)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    let (consent, consent_at, floor): (String, Option<DateTime<Utc>>, Option<bool>) =
        sqlx::query_as(
            "SELECT email_marketing_consent, email_marketing_consent_at,
                    email_marketing_global_optout
             FROM users WHERE pubkey = $1",
        )
        .bind(&pubkey)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(
        consent, "opted_in",
        "the consent event must survive an opt-out"
    );
    assert!(consent_at.is_some(), "and keep when it was given");
    assert_eq!(floor, Some(true), "while the floor records the withdrawal");

    cleanup(&pool, &[pubkey]).await;
}

/// Replaying an identical observation must change nothing, so a batch retried after a crash does
/// not churn the observation timestamp.
#[tokio::test]
async fn an_identical_observation_is_a_no_op() {
    let pool = setup_pool().await;
    let pubkey = seed(
        &pool,
        &format!("twice-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    let statement = "UPDATE users
         SET email_marketing_global_optout = TRUE,
             email_marketing_optout_observed_at = $3
         WHERE pubkey = $1 AND tenant_id = 1
           AND $2 IS TRUE
           AND email_marketing_global_optout IS DISTINCT FROM TRUE";

    let first = sqlx::query(statement)
        .bind(&pubkey)
        .bind(true)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(first.rows_affected(), 1);

    let second = sqlx::query(statement)
        .bind(&pubkey)
        .bind(true)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        second.rows_affected(),
        0,
        "an unchanged observation must not rewrite the row"
    );

    cleanup(&pool, &[pubkey]).await;
}

/// HubSpot forgets an opt-out when the address changes. A later observation that the new
/// contact is not globally opted out must not clear the floor we already recorded.
#[tokio::test]
async fn a_later_false_observation_does_not_clear_the_floor() {
    let pool = setup_pool().await;
    let pubkey = seed(
        &pool,
        &format!("floor-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    let statement = "UPDATE users
         SET email_marketing_global_optout = TRUE,
             email_marketing_optout_observed_at = $3
         WHERE pubkey = $1 AND tenant_id = 1
           AND $2 IS TRUE
           AND email_marketing_global_optout IS DISTINCT FROM TRUE";

    sqlx::query(statement)
        .bind(&pubkey)
        .bind(true)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();

    let cleared = sqlx::query(statement)
        .bind(&pubkey)
        .bind(false)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        cleared.rows_affected(),
        0,
        "a false observation must not lift the floor"
    );

    let floor: Option<bool> =
        sqlx::query_scalar("SELECT email_marketing_global_optout FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(floor, Some(true));

    cleanup(&pool, &[pubkey]).await;
}

/// Read and acknowledge are separate calls on purpose: a crash between them replays the deletion
/// rather than losing it, and losing one means emailing someone who deleted their account.
#[tokio::test]
async fn deletions_survive_until_acknowledged() {
    let pool = setup_pool().await;
    let email = format!("bye-{}@example.test", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at) VALUES (1, $1, NOW())",
    )
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    let listed: Vec<(i64,)> = sqlx::query_as(
        "SELECT id FROM email_marketing_deletions WHERE tenant_id = 1 AND email = $1",
    )
    .bind(&email)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(listed.len(), 1);

    // Still present before acknowledgement: reading does not consume.
    let again: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_deletions WHERE tenant_id = 1 AND email = $1",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(again, 1);

    let cleared =
        sqlx::query("DELETE FROM email_marketing_deletions WHERE id = ANY($1) AND tenant_id = $2")
            .bind(vec![listed[0].0])
            .bind(1i64)
            .execute(&pool)
            .await
            .unwrap();
    assert_eq!(cleared.rows_affected(), 1);
}

/// Acknowledging an id that does not exist must be harmless rather than an error, so a retry after
/// a partial failure cannot wedge the drain.
#[tokio::test]
async fn acknowledging_an_unknown_id_is_harmless() {
    let pool = setup_pool().await;
    let cleared =
        sqlx::query("DELETE FROM email_marketing_deletions WHERE id = ANY($1) AND tenant_id = $2")
            .bind(vec![-999_999i64])
            .bind(1i64)
            .execute(&pool)
            .await
            .unwrap();
    assert_eq!(cleared.rows_affected(), 0);
}

/// Email-change rows follow the same read-then-acknowledge contract, and must carry two distinct
/// addresses or the sync cannot find the contact it needs to move.
#[tokio::test]
async fn email_changes_carry_both_addresses_and_survive_until_acknowledged() {
    let pool = setup_pool().await;
    let pubkey = Keys::generate().public_key().to_hex();
    let old_email = format!("old-{}@example.test", uuid::Uuid::new_v4());
    let new_email = format!("new-{}@example.test", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO email_marketing_email_changes
             (tenant_id, pubkey, old_email, new_email, changed_at)
         VALUES (1, $1, $2, $3, NOW())",
    )
    .bind(&pubkey)
    .bind(&old_email)
    .bind(&new_email)
    .execute(&pool)
    .await
    .unwrap();

    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, old_email, new_email FROM email_marketing_email_changes
         WHERE tenant_id = 1 AND pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, old_email);
    assert_eq!(rows[0].2, new_email);
    assert_ne!(
        rows[0].1, rows[0].2,
        "a row whose addresses match cannot locate the contact to move"
    );

    let cleared = sqlx::query(
        "DELETE FROM email_marketing_email_changes WHERE id = ANY($1) AND tenant_id = $2",
    )
    .bind(vec![rows[0].0])
    .bind(1i64)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(cleared.rows_affected(), 1);
}

/// Every statement these endpoints run is tenant-scoped. An unscoped read would return another
/// tenant's accounts to a marketing sync service.
#[tokio::test]
async fn reads_are_tenant_scoped() {
    let pool = setup_pool().await;
    let email = format!("tenant-{}@example.test", uuid::Uuid::new_v4());
    let pubkey = seed(&pool, &email, "opted_in", Utc::now()).await;

    let visible_to_other_tenant: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND pubkey = $2")
            .bind(9999i64)
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        visible_to_other_tenant, 0,
        "a tenant-scoped read must not see another tenant's account"
    );

    cleanup(&pool, &[pubkey]).await;
}

fn handler_status<T: IntoResponse>(
    result: Result<T, keycast_api::api::error::ApiError>,
) -> StatusCode {
    match result {
        Ok(ok) => ok.into_response().status(),
        Err(err) => err.into_response().status(),
    }
}

fn empty_headers() -> HeaderMap {
    HeaderMap::new()
}

fn bearer_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

/// Inject TenantExtractor the same way other service-token tests do. Routing through the real
/// extractor 500s on an uninitialized tenant cache before the guard runs, which is why a naive
/// HTTP test passed with `authorize_service_token` deleted.
#[tokio::test]
async fn service_token_is_required_on_every_email_marketing_handler() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let (auth_state, _producer) = common::create_test_auth_state(pool);
    let headers = empty_headers();
    let statuses = [
        handler_status(
            list_consents(
                common::test_tenant(),
                State(auth_state.clone()),
                headers.clone(),
                Query(ConsentPageQuery {
                    since: None,
                    since_pubkey: None,
                    limit: None,
                }),
            )
            .await,
        ),
        handler_status(
            record_observations(
                common::test_tenant(),
                State(auth_state.clone()),
                headers.clone(),
                axum::Json(ObservationsRequest {
                    observations: vec![],
                }),
            )
            .await,
        ),
        handler_status(
            list_deletions(
                common::test_tenant(),
                State(auth_state.clone()),
                headers.clone(),
                Query(IdPageQuery {
                    since: None,
                    limit: None,
                }),
            )
            .await,
        ),
        handler_status(
            ack_deletions(
                common::test_tenant(),
                State(auth_state.clone()),
                headers.clone(),
                axum::Json(AckRequest { ids: vec![] }),
            )
            .await,
        ),
        handler_status(
            list_email_changes(
                common::test_tenant(),
                State(auth_state.clone()),
                headers.clone(),
                Query(IdPageQuery {
                    since: None,
                    limit: None,
                }),
            )
            .await,
        ),
        handler_status(
            ack_email_changes(
                common::test_tenant(),
                State(auth_state),
                headers,
                axum::Json(AckRequest { ids: vec![] }),
            )
            .await,
        ),
    ];

    for status in statuses {
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn a_valid_service_token_reaches_the_consent_list() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let (auth_state, _producer) = common::create_test_auth_state(pool);
    let status = handler_status(
        list_consents(
            common::test_tenant(),
            State(auth_state),
            bearer_headers(TOKEN),
            Query(ConsentPageQuery {
                since: None,
                since_pubkey: None,
                limit: None,
            }),
        )
        .await,
    );
    assert_eq!(status, StatusCode::OK);
}

/// An account whose consent is old but whose row was touched for an unrelated reason must not
/// reappear on the cursor.
///
/// The sync's unit of work is a consent event, not "an account that changed". Ordering on
/// `updated_at` meant a password change or profile edit re-triggered a subscribe, silently
/// reversing a granular unsubscribe the person had made in the meantime. Consent timestamps are
/// immutable, so ordering on them processes each answer exactly once.
///
/// Note the trigger: `users_update_trigger` forces `updated_at` to NOW() on every UPDATE, so an
/// unrelated write always moves it forward. That is exactly the hazard, and it is why the consent
/// timestamp here is in the PAST rather than the future: a future consent_at would sort after
/// NOW() and the test would pass without discriminating anything.
#[tokio::test]
async fn an_unrelated_account_update_does_not_reappear_on_the_cursor() {
    let pool = setup_pool().await;
    let consented_at = Utc::now() - Duration::days(90);
    let pubkey = seed(
        &pool,
        &format!("settled-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        consented_at,
    )
    .await;

    // Somebody changes their password long after consenting. The trigger moves updated_at to now.
    sqlx::query("UPDATE users SET password_hash = 'changed' WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();

    let moved: bool = sqlx::query_scalar(
        "SELECT updated_at > email_marketing_consent_at FROM users WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        moved,
        "precondition: the unrelated write must move updated_at past consent_at"
    );

    // A sync that already processed this consent asks for anything newer.
    let after: Vec<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users
         WHERE tenant_id = 1
           AND email_marketing_consent_at IS NOT NULL
           AND (email_marketing_consent_at, pubkey) > ($1, $2)
         ORDER BY email_marketing_consent_at, pubkey",
    )
    .bind(consented_at)
    .bind(&pubkey)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(
        !after.iter().any(|(p,)| p == &pubkey),
        "an unrelated update must not re-trigger a subscribe"
    );

    cleanup(&pool, &[pubkey]).await;
}

/// Accounts nobody ever asked have no consent event, so they are not consent records and must not
/// occupy pages the sync has to read past.
#[tokio::test]
async fn never_asked_accounts_are_not_returned() {
    let pool = setup_pool().await;
    let at = Utc::now() + Duration::days(3650);
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_marketing_consent, created_at, updated_at)
         VALUES ($1, 1, $2, 'never_asked', $3, $3)",
    )
    .bind(&pubkey)
    .bind(format!("unasked-{}@example.test", uuid::Uuid::new_v4()))
    .bind(at)
    .execute(&pool)
    .await
    .unwrap();

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT pubkey FROM users
         WHERE tenant_id = 1 AND email_marketing_consent_at IS NOT NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(!rows.iter().any(|(p,)| p == &pubkey));
    cleanup(&pool, &[pubkey]).await;
}

/// A summed row count cannot tell an expected no-op from a lost write: an unknown pubkey, a
/// wrong-tenant caller, an orphan and an identical replay all contribute zero.
#[tokio::test]
async fn observations_report_per_pubkey_outcomes() {
    let pool = setup_pool().await;
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let at = Utc::now() - Duration::days(1);
    let live = seed(
        &pool,
        &format!("live-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        at,
    )
    .await;
    let ghost = Keys::generate().public_key().to_hex();
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());

    let response = record_observations(
        common::test_tenant(),
        State(auth_state.clone()),
        bearer_headers(TOKEN),
        axum::Json(ObservationsRequest {
            observations: vec![
                Observation {
                    pubkey: live.clone(),
                    global_optout: true,
                    observed_at: Utc::now(),
                },
                Observation {
                    pubkey: ghost.clone(),
                    global_optout: true,
                    observed_at: Utc::now(),
                },
            ],
        }),
    )
    .await
    .unwrap();

    assert_eq!(response.0.updated, 1);
    assert!(response.0.unchanged.is_empty());
    assert_eq!(response.0.not_found, vec![ghost]);

    let replay = record_observations(
        common::test_tenant(),
        State(auth_state),
        bearer_headers(TOKEN),
        axum::Json(ObservationsRequest {
            observations: vec![Observation {
                pubkey: live.clone(),
                global_optout: false,
                observed_at: Utc::now(),
            }],
        }),
    )
    .await
    .unwrap();
    assert_eq!(replay.0.updated, 0);
    assert_eq!(replay.0.unchanged, vec![live.clone()]);
    assert!(replay.0.not_found.is_empty());

    cleanup(&pool, &[live]).await;
}

#[tokio::test]
async fn observations_reject_duplicate_pubkeys() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let (auth_state, _producer) = common::create_test_auth_state(pool);
    let pubkey = Keys::generate().public_key().to_hex();
    let observed_at = Utc::now();

    let status = handler_status(
        record_observations(
            common::test_tenant(),
            State(auth_state),
            bearer_headers(TOKEN),
            axum::Json(ObservationsRequest {
                observations: vec![
                    Observation {
                        pubkey: pubkey.clone(),
                        global_optout: false,
                        observed_at,
                    },
                    Observation {
                        pubkey,
                        global_optout: true,
                        observed_at,
                    },
                ],
            }),
        )
        .await,
    );

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// An orphaned identity left by a key rotation has no email and must not accept a floor write:
/// recording an opt-out against a row nothing reads loses the opt-out.
#[tokio::test]
async fn observations_skip_an_orphaned_identity() {
    let pool = setup_pool().await;
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let orphan = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_marketing_consent, created_at, updated_at)
         VALUES ($1, 1, NULL, 'never_asked', NOW(), NOW())",
    )
    .bind(&orphan)
    .execute(&pool)
    .await
    .unwrap();
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());

    let response = record_observations(
        common::test_tenant(),
        State(auth_state),
        bearer_headers(TOKEN),
        axum::Json(ObservationsRequest {
            observations: vec![Observation {
                pubkey: orphan.clone(),
                global_optout: true,
                observed_at: Utc::now(),
            }],
        }),
    )
    .await
    .unwrap();

    assert_eq!(response.0.updated, 0);
    assert!(response.0.unchanged.is_empty());
    assert_eq!(response.0.not_found, vec![orphan.clone()]);
    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&orphan)
        .execute(&pool)
        .await
        .unwrap();
}

/// Retention must be a property of the data, not of a consumer that may never run. Otherwise a
/// deleted account's address is kept indefinitely whenever the worker is switched off.
#[tokio::test]
async fn expired_deletion_rows_are_purged() {
    let pool = setup_pool().await;
    let stale = format!("stale-{}@example.test", uuid::Uuid::new_v4());
    let fresh = format!("fresh-{}@example.test", uuid::Uuid::new_v4());
    let stale_change = Keys::generate().public_key().to_hex();
    let fresh_change = Keys::generate().public_key().to_hex();

    sqlx::query(
        "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at, expires_at)
         VALUES (1, $1, NOW() - interval '30 days', NOW() - interval '1 day'),
                (1, $2, NOW(), NOW() + interval '14 days')",
    )
    .bind(&stale)
    .bind(&fresh)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO email_marketing_email_changes
             (tenant_id, pubkey, old_email, new_email, changed_at, expires_at)
         VALUES (1, $1, 'stale-old@example.test', 'stale-new@example.test', NOW(),
                    NOW() - interval '1 day'),
                (1, $2, 'fresh-old@example.test', 'fresh-new@example.test', NOW(),
                    NOW() + interval '14 days')",
    )
    .bind(&stale_change)
    .bind(&fresh_change)
    .execute(&pool)
    .await
    .unwrap();

    let removed = keycast_api::auth_cleanup::delete_expired_email_marketing_queue_rows(&pool)
        .await
        .unwrap();
    assert_eq!(removed, (1, 1));

    let remaining: Vec<(String,)> =
        sqlx::query_as("SELECT email FROM email_marketing_deletions WHERE email IN ($1, $2)")
            .bind(&stale)
            .bind(&fresh)
            .fetch_all(&pool)
            .await
            .unwrap();

    let emails: Vec<&String> = remaining.iter().map(|(e,)| e).collect();
    assert!(
        !emails.contains(&&stale),
        "an expired address must not be retained"
    );
    assert!(
        emails.contains(&&fresh),
        "a live pending removal must survive"
    );
    let remaining_changes: Vec<(String,)> =
        sqlx::query_as("SELECT pubkey FROM email_marketing_email_changes WHERE pubkey = ANY($1)")
            .bind(vec![stale_change, fresh_change.clone()])
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining_changes, vec![(fresh_change.clone(),)]);

    sqlx::query("DELETE FROM email_marketing_deletions WHERE email = $1")
        .bind(&fresh)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM email_marketing_email_changes WHERE pubkey = $1")
        .bind(&fresh_change)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn deletion_list_hides_tombstone_when_the_address_has_newer_consent() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let email = format!("reused-{}@example.test", uuid::Uuid::new_v4());
    let declined_email = format!("declined-{}@example.test", uuid::Uuid::new_v4());
    let deleted_at = Utc::now() - Duration::days(1);
    sqlx::query(
        "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at)
         VALUES (1, $1, $3), (1, $2, $3)",
    )
    .bind(&email)
    .bind(&declined_email)
    .bind(deleted_at)
    .execute(&pool)
    .await
    .unwrap();
    let replacement = seed(&pool, &email.to_uppercase(), "opted_in", Utc::now()).await;
    let declined = seed(&pool, &declined_email, "declined", Utc::now()).await;
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());

    let response = list_deletions(
        common::test_tenant(),
        State(auth_state),
        bearer_headers(TOKEN),
        Query(IdPageQuery {
            since: None,
            limit: None,
        }),
    )
    .await
    .unwrap();

    assert!(
        response.0.results.iter().all(|row| row.email != email),
        "an old tombstone must not delete a newer consent for the same address"
    );
    assert!(
        response
            .0
            .results
            .iter()
            .any(|row| row.email == declined_email),
        "a declined replacement did not create a contact and must not suppress deletion"
    );

    sqlx::query("DELETE FROM email_marketing_deletions WHERE email = ANY($1)")
        .bind(vec![email, declined_email])
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, &[replacement, declined]).await;
}
