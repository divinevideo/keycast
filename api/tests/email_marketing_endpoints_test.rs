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

const TEST_TOKEN: &str = "test-service-token-secret";

/// Build the auth state the handlers take, with the service token set.
async fn handler_ctx(pool: PgPool) -> keycast_api::api::http::AuthState {
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TEST_TOKEN) };
    let (auth_state, _producer) = common::create_test_auth_state(pool);
    auth_state
}

/// Post one observation through the real endpoint.
async fn observe(
    auth_state: &keycast_api::api::http::AuthState,
    pubkey: &str,
    global_optout: bool,
) -> keycast_api::api::http::email_marketing::ObservationsResponse {
    record_observations(
        common::test_tenant(),
        State(auth_state.clone()),
        bearer_headers(TEST_TOKEN),
        axum::Json(ObservationsRequest {
            observations: vec![Observation {
                pubkey: pubkey.to_string(),
                global_optout,
                observed_at: Utc::now(),
            }],
        }),
    )
    .await
    .unwrap()
    .0
}

/// Read one page of consents through the real endpoint.
async fn consents_since(
    auth_state: &keycast_api::api::http::AuthState,
    since: Option<DateTime<Utc>>,
    since_pubkey: Option<String>,
) -> Vec<String> {
    list_consents(
        common::test_tenant(),
        State(auth_state.clone()),
        bearer_headers(TEST_TOKEN),
        Query(ConsentPageQuery {
            since,
            since_pubkey,
            limit: Some(200),
        }),
    )
    .await
    .unwrap()
    .0
    .results
    .into_iter()
    .map(|r| r.pubkey)
    .collect()
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
    let auth_state = handler_ctx(pool.clone()).await;
    let pubkey = seed(
        &pool,
        &format!("stable-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    let response = observe(&auth_state, &pubkey, true).await;
    assert_eq!(response.updated, 1);

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
    let auth_state = handler_ctx(pool.clone()).await;
    let pubkey = seed(
        &pool,
        &format!("twice-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    assert_eq!(observe(&auth_state, &pubkey, true).await.updated, 1);

    let stamped: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT email_marketing_optout_observed_at FROM users WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();

    let replay = observe(&auth_state, &pubkey, true).await;
    assert_eq!(
        replay.updated, 0,
        "an unchanged observation must not rewrite the row"
    );
    assert!(
        replay.unchanged.contains(&pubkey),
        "and must be reported as a no-op, not lost"
    );

    let after: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT email_marketing_optout_observed_at FROM users WHERE pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        after, stamped,
        "the observation timestamp must not churn on replay"
    );

    cleanup(&pool, &[pubkey]).await;
}

/// HubSpot forgets an opt-out when the address changes. A later observation that the new
/// contact is not globally opted out must not clear the floor we already recorded.
#[tokio::test]
async fn a_later_false_observation_does_not_clear_the_floor() {
    let pool = setup_pool().await;
    let auth_state = handler_ctx(pool.clone()).await;
    let pubkey = seed(
        &pool,
        &format!("floor-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;

    assert_eq!(observe(&auth_state, &pubkey, true).await.updated, 1);

    let response = observe(&auth_state, &pubkey, false).await;
    assert_eq!(response.updated, 0);
    assert!(response.unchanged.contains(&pubkey));

    let floor: Option<bool> =
        sqlx::query_scalar("SELECT email_marketing_global_optout FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        floor,
        Some(true),
        "a false observation must never clear a recorded opt-out"
    );

    // A never-observed account is the direction that can actually distinguish the two guards: an
    // already-TRUE floor is protected by the write-once check regardless, so that case alone would
    // stay green even if the endpoint started writing whatever it was told.
    let fresh = seed(
        &pool,
        &format!("nullfloor-{}@example.test", uuid::Uuid::new_v4()),
        "opted_in",
        Utc::now(),
    )
    .await;
    assert_eq!(observe(&auth_state, &fresh, false).await.updated, 0);
    let fresh_floor: Option<bool> =
        sqlx::query_scalar("SELECT email_marketing_global_optout FROM users WHERE pubkey = $1")
            .bind(&fresh)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        fresh_floor, None,
        "a false observation must stay 'never observed', not record 'not opted out'",
    );

    cleanup(&pool, &[pubkey, fresh]).await;
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

/// Tenant scoping has to be proved through the endpoint. Counting rows with the test's own WHERE
/// clause proves only that the test wrote a WHERE clause.
#[tokio::test]
async fn reads_are_tenant_scoped() {
    let pool = setup_pool().await;
    let auth_state = handler_ctx(pool.clone()).await;
    let at = Utc::now() + Duration::days(3650);
    let email = format!("tenant-{}@example.test", uuid::Uuid::new_v4());
    let pubkey = seed(&pool, &email, "opted_in", at).await;

    // common::test_tenant() is tenant 1; move the seeded row to a real second tenant. users.tenant_id
    // carries an FK, so this has to be an actual row rather than an arbitrary id.
    let other_tenant: i64 =
        sqlx::query_scalar("INSERT INTO tenants (domain, name) VALUES ($1, $1) RETURNING id")
            .bind(format!("other-{}.example.test", uuid::Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query("UPDATE users SET tenant_id = $2 WHERE pubkey = $1")
        .bind(&pubkey)
        .bind(other_tenant)
        .execute(&pool)
        .await
        .unwrap();

    let visible = consents_since(
        &auth_state,
        Some(at - Duration::seconds(1)),
        Some(String::new()),
    )
    .await;
    assert!(
        !visible.contains(&pubkey),
        "the consent endpoint must not return another tenant's account",
    );

    sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(other_tenant)
        .execute(&pool)
        .await
        .unwrap();
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

/// The cursor is the consent timestamp, not updated_at, so an unrelated account change must not
/// put somebody back in front of the sync and re-trigger a subscribe.
#[tokio::test]
async fn an_unrelated_account_update_does_not_reappear_on_the_cursor() {
    let pool = setup_pool().await;
    let auth_state = handler_ctx(pool.clone()).await;
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

    // A sync that already processed this consent asks the endpoint for anything newer.
    let after = consents_since(&auth_state, Some(consented_at), Some(pubkey.clone())).await;

    assert!(
        !after.contains(&pubkey),
        "an unrelated update must not re-trigger a subscribe",
    );

    cleanup(&pool, &[pubkey]).await;
}

/// An account nobody asked has no consent event, so the endpoint must not hand it to the sync at
/// all. Filtering it out in the test's own query would prove nothing about the endpoint.
#[tokio::test]
async fn never_asked_accounts_are_not_returned() {
    let pool = setup_pool().await;
    let auth_state = handler_ctx(pool.clone()).await;
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

    // No cursor: with one set, the (consent_at, pubkey) comparison already excludes a NULL
    // consent_at, so the test would pass without the endpoint filtering anything at all. The
    // first page is where the filter is the only thing standing between this row and the sync.
    let returned = consents_since(&auth_state, None, None).await;
    assert!(
        !returned.contains(&pubkey),
        "an account with no consent event must not appear in the consent feed",
    );

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

/// A queued email move must not act on an address that now belongs to another opted-in account.
/// This is independent of ordering: the worker finds contacts by address at drain time, so both a
/// reclaim before the queued change and one after it would rename the new holder's contact.
#[tokio::test]
async fn email_change_list_withholds_reclaimed_addresses_in_both_orders() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());

    let reclaimed_before = format!("reclaimed-before-{}@example.test", uuid::Uuid::new_v4());
    let reclaimed_after = format!("reclaimed-after-{}@example.test", uuid::Uuid::new_v4());
    let declined_address = format!("declined-holder-{}@example.test", uuid::Uuid::new_v4());
    let now = Utc::now();

    let before_holder = seed(
        &pool,
        &reclaimed_before,
        "opted_in",
        now - Duration::hours(2),
    )
    .await;
    let declined_holder = seed(&pool, &declined_address, "declined", now).await;
    let source_pubkeys: Vec<String> = (0..3)
        .map(|_| Keys::generate().public_key().to_hex())
        .collect();

    for (pubkey, old_email) in source_pubkeys.iter().zip([
        reclaimed_before.as_str(),
        reclaimed_after.as_str(),
        declined_address.as_str(),
    ]) {
        sqlx::query(
            "INSERT INTO email_marketing_email_changes
                 (tenant_id, pubkey, old_email, new_email, changed_at)
             VALUES (1, $1, $2, $3, $4)",
        )
        .bind(pubkey)
        .bind(old_email)
        .bind(format!("destination-{}@example.test", uuid::Uuid::new_v4()))
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    }

    // This holder claims the address after the change row was queued. Uppercasing also pins the
    // case-insensitive comparison used everywhere else for email identity.
    let after_holder = seed(
        &pool,
        &reclaimed_after.to_uppercase(),
        "opted_in",
        now + Duration::hours(2),
    )
    .await;

    let page = list_email_changes(
        common::test_tenant(),
        State(auth_state),
        bearer_headers(TOKEN),
        Query(IdPageQuery {
            since: None,
            limit: None,
        }),
    )
    .await
    .unwrap()
    .0;

    assert!(
        page.results
            .iter()
            .all(|row| row.old_email != reclaimed_before && row.old_email != reclaimed_after),
        "neither reclaim order may expose a stale move"
    );
    assert!(
        page.results
            .iter()
            .any(|row| row.old_email == declined_address),
        "a declined holder has no Keycast-created contact and must not suppress the move"
    );

    sqlx::query("DELETE FROM email_marketing_email_changes WHERE pubkey = ANY($1)")
        .bind(&source_pubkeys)
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, &[before_holder, after_holder, declined_holder]).await;
}

/// Race A, and the reason it cannot be left to drain ordering. An unacknowledged email-change row
/// means the platform still holds a contact at the OLD address; the account's current address has
/// not been created there yet. Tombstoning only the current address removes nothing and leaves the
/// old one subscribed for a deleted account. Folding the pending change into the deletion means the
/// queue names every address that needs removing, whatever order a consumer drains in.
#[tokio::test]
async fn deleting_an_account_tombstones_its_unprocessed_old_addresses() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    let first = format!("first-{}@example.test", uuid::Uuid::new_v4());
    let second = format!("second-{}@example.test", uuid::Uuid::new_v4());
    let current = format!("current-{}@example.test", uuid::Uuid::new_v4());
    let pubkey = seed(&pool, &current, "opted_in", Utc::now()).await;

    // Two changes the sync worker has not drained yet: first -> second -> current.
    for (old, new) in [(&first, &second), (&second, &current)] {
        sqlx::query(
            "INSERT INTO email_marketing_email_changes
                 (tenant_id, pubkey, old_email, new_email, changed_at)
             VALUES (1, $1, $2, $3, NOW())",
        )
        .bind(&pubkey)
        .bind(old)
        .bind(new)
        .execute(&pool)
        .await
        .unwrap();
    }

    keycast_core::repositories::UserRepository::new(pool.clone())
        .delete_account(&pubkey, 1)
        .await
        .unwrap();

    let tombstoned: Vec<(String,)> = sqlx::query_as(
        "SELECT email FROM email_marketing_deletions
         WHERE tenant_id = 1 AND email = ANY($1) ORDER BY email",
    )
    .bind(vec![first.clone(), second.clone(), current.clone()])
    .fetch_all(&pool)
    .await
    .unwrap();
    let got: Vec<&str> = tombstoned.iter().map(|r| r.0.as_str()).collect();

    for addr in [&first, &second, &current] {
        assert!(
            got.contains(&addr.as_str()),
            "every address the platform may hold must be tombstoned; {addr} missing from {got:?}",
        );
    }

    // The change rows must not survive the account. Left behind, a consumer would replay them and
    // re-create a contact for an account that no longer exists.
    let leftover: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_email_changes WHERE tenant_id = 1 AND pubkey = $1",
    )
    .bind(&pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        leftover, 0,
        "pending email-change rows outlived the account"
    );
}

/// The tie-break has to be exercised through the handler, not restated in the test.
///
/// This replaces `cursor_pages_deterministically_when_timestamps_collide`, which wrote its own
/// row-value comparison inline and asserted on that, so it only ever proved PostgreSQL supports
/// the syntax rather than that `list_consents` uses it.
///
/// That gap was demonstrated the hard way. The tuple comparison was briefly deleted from the
/// handler by an editing accident on this branch, and the whole suite stayed green: the one test
/// named after this behaviour did not notice its own subject being removed. A test that restates
/// production SQL cannot fail when production SQL changes, which is the only time it matters.
#[tokio::test]
async fn the_consent_cursor_does_not_drop_rows_sharing_a_timestamp() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());

    // Three accounts answering in the same transaction share a consent_at exactly.
    let shared = Utc::now() + Duration::days(3650);
    let mut seeded = Vec::new();
    for _ in 0..3 {
        seeded.push(
            seed(
                &pool,
                &format!("tie-{}@example.test", uuid::Uuid::new_v4()),
                "opted_in",
                shared,
            )
            .await,
        );
    }
    seeded.sort();

    // Page one at a time, exactly as the worker does, and collect everything the cursor yields.
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = Some(ConsentPageQuery {
        since: Some(shared - Duration::seconds(1)),
        since_pubkey: Some(String::new()),
        limit: Some(1),
    });

    for _ in 0..6 {
        let Some(query) = cursor.take() else { break };
        let page = list_consents(
            common::test_tenant(),
            State(auth_state.clone()),
            bearer_headers(TOKEN),
            Query(query),
        )
        .await
        .unwrap()
        .0;

        for r in &page.results {
            if seeded.contains(&r.pubkey) {
                seen.push(r.pubkey.clone());
            }
        }

        cursor = page.next.map(|n| ConsentPageQuery {
            since: Some(n.since),
            since_pubkey: Some(n.since_pubkey),
            limit: Some(1),
        });
    }

    seen.sort();
    seen.dedup();
    assert_eq!(
        seen, seeded,
        "every account sharing a consent_at must be reachable through the cursor; a timestamp-only \
         comparison skips the rest of a tied group and those people are never synced",
    );
}

/// The reclaim guard has to fire on the address, not on the timing.
///
/// The original predicate also required the live account's consent to be NEWER than deleted_at,
/// which only catches somebody registering after the deletion. It misses the reverse order, which
/// is just as reachable: A frees an address by changing their own, B claims it and opts in, and only
/// then does A delete. B consented first, so the guard stayed silent and B's contact was removed.
///
/// The timing comparison was never needed. 4b and 4c run inside the deletion transaction and the
/// users row goes at step 5 of that same transaction, so once a tombstone is visible no live row can
/// be the account it came from. Any live opted-in holder of that address is therefore someone else.
#[tokio::test]
async fn a_tombstone_is_withheld_even_when_the_new_holder_consented_first() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let (auth_state, _producer) = common::create_test_auth_state(pool.clone());

    let reclaimed = format!("early-{}@example.test", uuid::Uuid::new_v4());
    let orphaned = format!("nobody-{}@example.test", uuid::Uuid::new_v4());

    // The new holder opted in BEFORE the previous holder's account was deleted.
    let holder = seed(
        &pool,
        &reclaimed,
        "opted_in",
        Utc::now() - Duration::hours(2),
    )
    .await;

    for email in [&reclaimed, &orphaned] {
        sqlx::query(
            "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at)
             VALUES (1, $1, $2)",
        )
        .bind(email)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    }

    let page = list_deletions(
        common::test_tenant(),
        State(auth_state),
        bearer_headers(TOKEN),
        Query(IdPageQuery {
            since: None,
            limit: None,
        }),
    )
    .await
    .unwrap()
    .0;

    let served: Vec<&str> = page.results.iter().map(|r| r.email.as_str()).collect();
    assert!(
        !served.contains(&reclaimed.as_str()),
        "serving this deletes a live opted-in account's contact, and nothing re-subscribes them",
    );
    assert!(
        served.contains(&orphaned.as_str()),
        "an address with no live holder must still be served",
    );

    cleanup(&pool, &[holder]).await;
}

/// Rotation has to carry undrained email changes to the new pubkey.
///
/// The deletion fold matches change rows on pubkey. Rotation moved the consent columns to the
/// replacement identity but left the change rows pointing at the old one, so the fold missed them:
/// the old address was never tombstoned, and the change row outlived the account it belonged to.
#[tokio::test]
async fn rotation_carries_undrained_email_changes_to_the_new_identity() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    let old_address = format!("before-{}@example.test", uuid::Uuid::new_v4());
    let current = format!("after-{}@example.test", uuid::Uuid::new_v4());
    let old_pubkey = seed(&pool, &current, "opted_in", Utc::now()).await;

    sqlx::query(
        "INSERT INTO email_marketing_email_changes
             (tenant_id, pubkey, old_email, new_email, changed_at)
         VALUES (1, $1, $2, $3, NOW())",
    )
    .bind(&old_pubkey)
    .bind(&old_address)
    .bind(&current)
    .execute(&pool)
    .await
    .unwrap();

    let new_pubkey = Keys::generate().public_key().to_hex();
    let _: i64 = keycast_core::repositories::UserRepository::new(pool.clone())
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            1,
            &current,
            "$2b$12$abcdefghijklmnopqrstuv",
            b"rotated-secret",
        )
        .await
        .unwrap();

    let moved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_email_changes WHERE tenant_id = 1 AND pubkey = $1",
    )
    .bind(&new_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        moved, 1,
        "the change row must follow the account to its new pubkey"
    );

    // And the deletion fold, which matches on pubkey, must now find it.
    keycast_core::repositories::UserRepository::new(pool.clone())
        .delete_account(&new_pubkey, 1)
        .await
        .unwrap();

    let tombstoned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_marketing_deletions WHERE tenant_id = 1 AND email = $1",
    )
    .bind(&old_address)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tombstoned, 1,
        "the old address was left subscribed for a deleted account"
    );
}

/// A queue row that is about to expire has to be visible before it is gone, not after.
///
/// Draining reads from the head and acknowledges on success, so a row that keeps failing is retried
/// forever while everything behind it is never served. Expiry then removes it and the deleted
/// account's contact is never taken out of the email platform. Both steps are silent otherwise.
#[tokio::test]
async fn queue_rows_near_expiry_are_counted_before_they_are_dropped() {
    common::assert_test_database_url();
    let pool = common::setup_test_db().await;

    let soon = format!("soon-{}@example.test", uuid::Uuid::new_v4());
    let later = format!("later-{}@example.test", uuid::Uuid::new_v4());

    let (base_d, base_c) = keycast_api::auth_cleanup::count_email_marketing_queue_near_expiry(
        &pool,
        std::time::Duration::from_secs(48 * 60 * 60),
    )
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO email_marketing_deletions (tenant_id, email, deleted_at, expires_at)
         VALUES (1, $1, NOW(), NOW() + INTERVAL '1 hour'),
                (1, $2, NOW(), NOW() + INTERVAL '13 days')",
    )
    .bind(&soon)
    .bind(&later)
    .execute(&pool)
    .await
    .unwrap();

    let (deletions, changes) = keycast_api::auth_cleanup::count_email_marketing_queue_near_expiry(
        &pool,
        std::time::Duration::from_secs(48 * 60 * 60),
    )
    .await
    .unwrap();

    assert_eq!(
        deletions - base_d,
        1,
        "only the row inside the window counts; a fresh row must not raise the alarm",
    );
    assert_eq!(changes - base_c, 0);

    sqlx::query("DELETE FROM email_marketing_deletions WHERE email = ANY($1)")
        .bind(vec![soon, later])
        .execute(&pool)
        .await
        .unwrap();
}

/// The row's snapshot is frozen at insert time, so a floor recorded afterwards has to win.
///
/// A withdrawal discovered while draining is written to users, but the queue row still carries the
/// NULL it was created with. If that row is replayed, the consumer's own lookup no longer finds the
/// opt-out either, because the rename moved the contact and the platform does not carry
/// subscription state across an address change. Serving the stale snapshot would then subscribe
/// somebody whose withdrawal this database already records.
#[tokio::test]
async fn an_email_change_row_reflects_a_floor_recorded_after_it_was_written() {
    common::assert_test_database_url();
    const TOKEN: &str = "test-service-token-secret";
    unsafe { std::env::set_var("KEYCAST_SERVICE_TOKEN", TOKEN) };
    let pool = common::setup_test_db().await;
    let auth_state = handler_ctx(pool.clone()).await;

    let current = format!("now-{}@example.test", uuid::Uuid::new_v4());
    let old = format!("was-{}@example.test", uuid::Uuid::new_v4());
    let pubkey = seed(&pool, &current, "opted_in", Utc::now()).await;

    // Written with no floor known at the time.
    sqlx::query(
        "INSERT INTO email_marketing_email_changes
             (tenant_id, pubkey, old_email, new_email, changed_at, global_optout)
         VALUES (1, $1, $2, $3, NOW(), NULL)",
    )
    .bind(&pubkey)
    .bind(&old)
    .bind(&current)
    .execute(&pool)
    .await
    .unwrap();

    // The withdrawal is discovered and recorded afterwards.
    assert_eq!(observe(&auth_state, &pubkey, true).await.updated, 1);

    let page = list_email_changes(
        common::test_tenant(),
        State(auth_state.clone()),
        bearer_headers(TOKEN),
        Query(IdPageQuery {
            since: None,
            limit: None,
        }),
    )
    .await
    .unwrap()
    .0;

    let row = page
        .results
        .iter()
        .find(|r| r.pubkey == pubkey)
        .expect("the change row must still be served");
    assert_eq!(
        row.global_optout,
        Some(true),
        "a floor recorded after the row was written must win over the row's stale snapshot",
    );

    cleanup(&pool, &[pubkey]).await;
}
