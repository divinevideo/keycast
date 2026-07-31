#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the raw-key egress hardening (#325) over
// ABOUTME: POST /user/export-key and POST /user/change-key: audit rows, the
// ABOUTME: shared wrong-password lockout, and the machine-readable refusal codes.

mod common;

use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use keycast_api::api::{
    http::{
        auth::{change_key, export_key, AuthError, ChangeKeyRequest},
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_api::PrefixedRedis;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use serde_json::json;
use serial_test::serial;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::Duration as StdDuration};
use ucan::builder::UcanBuilder;
use uuid::Uuid;

const TENANT_ID: i64 = 1;
const PASSWORD: &str = "correct-horse-battery-staple";

/// Mirrors `KEY_EGRESS_MAX_ATTEMPTS` in `api/src/key_egress_limiter.rs`.
const MAX_ATTEMPTS: usize = 5;

// ---------------------------------------------------------------- harness

async fn setup_pool() -> PgPool {
    setup_pool_with_options(10, StdDuration::from_secs(30)).await
}

async fn setup_pool_with_options(max_connections: u32, acquire_timeout: StdDuration) -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(acquire_timeout)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    pool
}

fn create_test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "login.divine.video".to_string(),
        name: "Key Egress Hardening Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn create_test_auth_state(pool: PgPool, key_manager: Arc<Box<dyn KeyManager>>) -> AuthState {
    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must name dedicated Redis");
    let client = redis::Client::open(redis_url).expect("valid Redis URL");
    let connection = redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect to dedicated Redis");
    let prefix = format!("keycast-pr326-independent-review:{}", Uuid::new_v4());
    create_test_auth_state_with_redis(
        pool,
        key_manager,
        Some(PrefixedRedis::new(connection, Some(prefix))),
    )
}

fn create_test_auth_state_with_redis(
    pool: PgPool,
    key_manager: Arc<Box<dyn KeyManager>>,
    redis: Option<PrefixedRedis>,
) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt_sender: bcrypt_queue.sender(),
            redis,
            secret_pool: secret_pool.receiver(),
        }),
        auth_tx: None,
    }
}

async fn insert_user(
    pool: &PgPool,
    pubkey: &str,
    email: &str,
    password: &str,
    email_verified: bool,
    verified_minor: bool,
) {
    let password_hash = bcrypt::hash(password, 4).expect("hash password");
    sqlx::query(
        "INSERT INTO users
            (pubkey, tenant_id, email, password_hash, email_verified, verified_minor, verified_minor_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $6 THEN NOW() ELSE NULL END, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .bind(&password_hash)
    .bind(email_verified)
    .bind(verified_minor)
    .execute(pool)
    .await
    .expect("insert user");
}

async fn create_personal_key(
    pool: &PgPool,
    user_pubkey: &str,
    user_keys: &Keys,
    km: &dyn KeyManager,
) {
    let encrypted = km
        .encrypt(&user_keys.secret_key().secret_bytes())
        .await
        .expect("encrypt user secret");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(user_pubkey)
    .bind(&encrypted)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("create personal key");
}

async fn bearer_for(keys: &Keys) -> String {
    let key_material = NostrKeyMaterial::from_keys(keys.clone());
    let user_did = nostr_pubkey_to_did(&keys.public_key());
    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(json!({
            "tenant_id": TENANT_ID,
            "email": "key-egress-hardening@example.com",
            "redirect_origin": "https://login.divine.video",
        }))
        .build()
        .expect("build UCAN")
        .sign()
        .await
        .expect("sign UCAN");
    format!("Bearer {}", ucan.encode().expect("encode UCAN"))
}

fn auth_headers(bearer: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", bearer.parse().expect("valid header"));
    headers.insert("host", "login.divine.video".parse().expect("valid host"));
    headers.insert("x-forwarded-proto", "https".parse().expect("valid proto"));
    headers.insert(
        "origin",
        "https://login.divine.video".parse().expect("valid origin"),
    );
    headers
}

fn unique_email() -> String {
    format!("keh-{}@example.com", Uuid::new_v4())
}

fn km_arc(km: FileKeyManager) -> Arc<Box<dyn KeyManager>> {
    Arc::new(Box::new(km) as Box<dyn KeyManager>)
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&body).expect("response body should be JSON")
}

// ------------------------------------------------------------ audit probes

#[derive(Debug, sqlx::FromRow)]
struct EgressEvent {
    endpoint: String,
    event_type: String,
    outcome: String,
    reason_code: Option<String>,
    http_status: Option<i32>,
    pubkey: Option<String>,
    metadata_json: serde_json::Value,
    #[allow(dead_code)]
    occurred_at: DateTime<Utc>,
}

async fn egress_events(pool: &PgPool, pubkey: &str) -> Vec<EgressEvent> {
    sqlx::query_as::<_, EgressEvent>(
        "SELECT endpoint, event_type, outcome, reason_code, http_status, pubkey,
                metadata_json, occurred_at
         FROM auth_events
         WHERE tenant_id = $1 AND pubkey = $2
         ORDER BY occurred_at ASC, id ASC",
    )
    .bind(TENANT_ID)
    .bind(pubkey)
    .fetch_all(pool)
    .await
    .expect("read auth events")
}

/// Every row this account produced, serialized. Used to prove key material never
/// reaches the audit trail.
async fn raw_event_text(pool: &PgPool, pubkey: &str) -> String {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT to_jsonb(auth_events)::text FROM auth_events
         WHERE tenant_id = $1 AND pubkey = $2",
    )
    .bind(TENANT_ID)
    .bind(pubkey)
    .fetch_all(pool)
    .await
    .expect("read raw auth events");
    rows.into_iter()
        .map(|row| row.0)
        .collect::<Vec<_>>()
        .join("\n")
}

struct AuditFailureTrigger {
    trigger_name: String,
    function_name: String,
}

impl AuditFailureTrigger {
    async fn install(pool: &PgPool, pubkey: &str, endpoint: &str) -> Self {
        Self::install_for_outcome(pool, pubkey, endpoint, "success").await
    }

    async fn install_for_outcome(
        pool: &PgPool,
        pubkey: &str,
        endpoint: &str,
        outcome: &'static str,
    ) -> Self {
        let suffix = Uuid::new_v4().simple().to_string();
        let trigger_name = format!("fail_key_egress_audit_{suffix}");
        let function_name = format!("fail_key_egress_audit_fn_{suffix}");

        // Both interpolated values are controlled test fixtures: a 64-character
        // lowercase hex pubkey, a static endpoint, and a static outcome.
        let function_sql = format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger AS $$
             BEGIN
                 IF NEW.pubkey = '{pubkey}'
                    AND NEW.endpoint = '{endpoint}'
                    AND NEW.outcome = '{outcome}'
                 THEN
                     RAISE EXCEPTION 'injected scoped key-egress audit failure';
                 END IF;
                 RETURN NEW;
             END;
             $$ LANGUAGE plpgsql"
        );
        sqlx::query(&function_sql)
            .execute(pool)
            .await
            .expect("install scoped audit failure function");

        let trigger_sql = format!(
            "CREATE TRIGGER {trigger_name}
             BEFORE INSERT ON auth_events
             FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        );
        sqlx::query(&trigger_sql)
            .execute(pool)
            .await
            .expect("install scoped audit failure trigger");

        Self {
            trigger_name,
            function_name,
        }
    }

    async fn remove(self, pool: &PgPool) {
        let drop_trigger = format!(
            "DROP TRIGGER IF EXISTS {} ON auth_events",
            self.trigger_name
        );
        sqlx::query(&drop_trigger)
            .execute(pool)
            .await
            .expect("remove scoped audit failure trigger");

        let drop_function = format!("DROP FUNCTION IF EXISTS {}()", self.function_name);
        sqlx::query(&drop_function)
            .execute(pool)
            .await
            .expect("remove scoped audit failure function");
    }
}

async fn create_oauth_authorization(pool: &PgPool, user_pubkey: &str) -> i32 {
    let bunker_pubkey = Keys::generate().public_key().to_hex();
    sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
            (user_pubkey, bunker_public_key, secret_hash, relays, redirect_origin,
             tenant_id, handle_expires_at)
         VALUES ($1, $2, 'test_hash', 'wss://relay.example.com',
                 'https://app.example.com', $3, NOW() + INTERVAL '1 day')
         RETURNING id",
    )
    .bind(user_pubkey)
    .bind(bunker_pubkey)
    .bind(TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("create OAuth authorization")
}

async fn assert_original_custody_unchanged(
    pool: &PgPool,
    old_pubkey: &str,
    new_pubkey: &str,
    expected_email: &str,
    expected_oauth_id: i32,
) {
    let old_identity: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT email, password_hash FROM users WHERE pubkey = $1 AND tenant_id = $2",
    )
    .bind(old_pubkey)
    .bind(TENANT_ID)
    .fetch_optional(pool)
    .await
    .expect("read old identity");
    let (email, password_hash) = old_identity.expect("old identity must remain");
    assert_eq!(email.as_deref(), Some(expected_email));
    assert!(
        password_hash.is_some(),
        "old identity must retain its password hash"
    );

    let old_key_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM personal_keys WHERE user_pubkey = $1 AND tenant_id = $2
         )",
    )
    .bind(old_pubkey)
    .bind(TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("read old personal key");
    assert!(old_key_exists, "old custody key must remain");

    let oauth_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM oauth_authorizations
             WHERE id = $1 AND user_pubkey = $2 AND tenant_id = $3
         )",
    )
    .bind(expected_oauth_id)
    .bind(old_pubkey)
    .bind(TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("read OAuth authorization");
    assert!(oauth_exists, "OAuth authorization must remain");

    let new_identity_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM users WHERE pubkey = $1 AND tenant_id = $2
         )",
    )
    .bind(new_pubkey)
    .bind(TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("read replacement identity");
    assert!(
        !new_identity_exists,
        "failed change-key must not create the replacement identity"
    );
}

/// Spend `count` wrong-password attempts against export-key.
async fn burn_attempts(auth_state: &AuthState, keys: &Keys, bearer: &str, count: usize) {
    for attempt in 0..count {
        let err = export_key(
            create_test_tenant(),
            State(auth_state.clone()),
            auth_headers(bearer),
            Json(json!({ "password": "wrong-password", "format": "nsec" })),
        )
        .await
        .expect_err("wrong password must be refused");
        assert!(
            matches!(err, AuthError::InvalidCredentials),
            "attempt {attempt} for {} should be InvalidCredentials, got: {err:?}",
            keys.public_key().to_hex()
        );
    }
}

// ------------------------------------------------------------------- tests

#[tokio::test]
#[serial]
async fn successful_export_is_recorded_without_the_key() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;

    let Json(resp) = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect("export must succeed");
    assert!(resp.key.starts_with("nsec1"));

    let events = egress_events(&pool, &pubkey).await;
    assert_eq!(
        events.len(),
        1,
        "expected exactly one audit row: {events:?}"
    );
    let event = &events[0];
    assert_eq!(event.endpoint, "/api/user/export-key");
    assert_eq!(event.event_type, "key_egress");
    assert_eq!(event.outcome, "success");
    assert_eq!(event.reason_code, None);
    assert_eq!(event.http_status, Some(200));
    // Full pubkey, never truncated.
    assert_eq!(event.pubkey.as_deref(), Some(pubkey.as_str()));

    // The 200 body IS the private key, so the record of it must not be.
    let raw = raw_event_text(&pool, &pubkey).await;
    assert!(
        !raw.contains("nsec1"),
        "audit trail must never carry key material: {raw}"
    );
    assert!(
        !raw.contains(&resp.key),
        "audit trail must never carry the exported key"
    );
}

#[tokio::test]
#[serial]
async fn successful_export_needs_only_one_database_connection() {
    let pool = setup_pool_with_options(1, StdDuration::from_millis(250)).await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool, km_arc(km)).await;

    let Json(response) = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect("one request must not need two simultaneous pool connections");

    assert!(response.key.starts_with("nsec1"));
}

#[tokio::test]
#[serial]
async fn successful_change_key_needs_only_one_database_connection() {
    let pool = setup_pool_with_options(1, StdDuration::from_millis(250)).await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();

    let response = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("encode nsec")),
        }),
    )
    .await
    .expect("one change-key request must not need two simultaneous connections");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let new_identity_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM users WHERE pubkey = $1 AND tenant_id = $2
         )",
    )
    .bind(new_pubkey)
    .bind(TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read replacement identity");
    assert!(new_identity_exists);
}

#[tokio::test]
#[serial]
async fn export_fails_closed_when_redis_is_not_configured() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state_with_redis(pool, km_arc(km), None);

    let error = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect_err("admission cannot be enforced without Redis");

    assert!(
        matches!(error, AuthError::ServiceUnavailable { .. }),
        "missing Redis must load-shed with 503, got: {error:?}"
    );
}

#[tokio::test]
#[serial]
async fn export_returns_no_key_when_its_success_audit_cannot_commit() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let failure = AuditFailureTrigger::install(&pool, &pubkey, "/api/user/export-key").await;

    let result = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await;
    failure.remove(&pool).await;

    let error = result.expect_err("audit failure must prevent key delivery");
    let response = axum::response::IntoResponse::into_response(error);
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read failure response");
    let body = String::from_utf8(body.to_vec()).expect("UTF-8 failure response");
    assert!(
        !body.contains("nsec1"),
        "failure response must not contain key material"
    );

    let events = egress_events(&pool, &pubkey).await;
    assert!(
        events.iter().all(|event| event.outcome != "success"),
        "a rejected success audit must not appear committed: {events:?}"
    );
}

#[tokio::test]
#[serial]
async fn wrong_password_is_recorded_as_a_countable_failure() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    burn_attempts(&auth_state, &keys, &bearer, 1).await;

    let events = egress_events(&pool, &pubkey).await;
    assert_eq!(events.len(), 1, "expected one audit row: {events:?}");
    assert_eq!(events[0].outcome, "failure");
    // This exact reason_code is what the lockout counts.
    assert_eq!(events[0].reason_code.as_deref(), Some("invalid_password"));
    assert_eq!(events[0].http_status, Some(401));
}

#[tokio::test]
#[serial]
async fn failed_wrong_password_audit_does_not_refund_the_redis_budget() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;
    let failure =
        AuditFailureTrigger::install_for_outcome(&pool, &pubkey, "/api/user/export-key", "failure")
            .await;

    let result = export_key(
        create_test_tenant(),
        State(auth_state.clone()),
        auth_headers(&bearer),
        Json(json!({ "password": "wrong-password", "format": "nsec" })),
    )
    .await;
    failure.remove(&pool).await;
    let error = result.expect_err("failed forensic audit must prevent a 401 response");
    let response = axum::response::IntoResponse::into_response(error);
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "audit unavailability must surface as 503 after Redis spends the attempt"
    );

    burn_attempts(&auth_state, &keys, &bearer, MAX_ATTEMPTS - 1).await;
    let locked = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect_err("the failed audit must not have refunded its Redis attempt");
    assert!(
        matches!(locked, AuthError::TooManyRequests { .. }),
        "one failed audit plus four recorded failures must exhaust the budget: {locked:?}"
    );

    let events = egress_events(&pool, &pubkey).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.reason_code.as_deref() == Some("invalid_password"))
            .count(),
        MAX_ATTEMPTS - 1,
        "the missing forensic row is expected, but Redis must retain the fifth budget entry"
    );
}

#[tokio::test]
#[serial]
async fn export_locks_out_after_the_attempt_budget_is_spent() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    burn_attempts(&auth_state, &keys, &bearer, MAX_ATTEMPTS).await;

    let err = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(json!({ "password": "wrong-password", "format": "nsec" })),
    )
    .await
    .expect_err("attempt past the budget must be locked out");

    match err {
        AuthError::TooManyRequests { retry_after, .. } => {
            assert!(retry_after > 0, "Retry-After must be actionable");
            assert!(
                retry_after <= 15 * 60,
                "Retry-After must not exceed the window, got {retry_after}"
            );
        }
        other => panic!("expected TooManyRequests, got: {other:?}"),
    }

    let events = egress_events(&pool, &pubkey).await;
    assert!(
        events
            .iter()
            .all(|event| event.reason_code.as_deref() != Some("rate_limited")),
        "repeated locked requests must not amplify database writes: {events:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn concurrent_wrong_password_burst_spends_only_the_attempt_budget() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..(MAX_ATTEMPTS + 5) {
        let auth_state = auth_state.clone();
        let bearer = bearer.clone();
        attempts.spawn(async move {
            export_key(
                create_test_tenant(),
                State(auth_state),
                auth_headers(&bearer),
                Json(json!({ "password": "wrong-password", "format": "nsec" })),
            )
            .await
        });
    }

    let mut results = Vec::new();
    while let Some(result) = attempts.join_next().await {
        results.push(result.expect("attempt task should finish"));
    }

    let invalid_credentials = results
        .iter()
        .filter(|result| matches!(result, Err(AuthError::InvalidCredentials)))
        .count();
    let rate_limited = results
        .iter()
        .filter(|result| matches!(result, Err(AuthError::TooManyRequests { .. })))
        .count();
    assert_eq!(
        invalid_credentials, MAX_ATTEMPTS,
        "only the configured budget should reach password verification: {results:?}"
    );
    assert_eq!(
        rate_limited,
        results.len() - MAX_ATTEMPTS,
        "the rest of the burst should be locked out: {results:?}"
    );

    let events = egress_events(&pool, &pubkey).await;
    let counted_failures = events
        .iter()
        .filter(|event| event.reason_code.as_deref() == Some("invalid_password"))
        .count();
    assert_eq!(
        counted_failures, MAX_ATTEMPTS,
        "the audit-backed counter must not overspend under concurrency: {events:?}"
    );
}

#[tokio::test]
#[serial]
async fn lockout_refuses_the_correct_password_too() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    burn_attempts(&auth_state, &keys, &bearer, MAX_ATTEMPTS).await;

    // The point of a lockout: once spent, being right no longer helps, so the
    // endpoint stops being an oracle regardless of what the caller guesses.
    let err = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect_err("a locked-out account must not export even with the right password");

    assert!(
        matches!(err, AuthError::TooManyRequests { .. }),
        "expected TooManyRequests, got: {err:?}"
    );
}

#[tokio::test]
#[serial]
async fn export_bad_requests_after_authorization_are_audited() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    let missing_password = export_key(
        create_test_tenant(),
        State(auth_state.clone()),
        auth_headers(&bearer),
        Json(json!({ "format": "nsec" })),
    )
    .await
    .expect_err("missing password must be refused");
    assert!(matches!(missing_password, AuthError::BadRequest(_)));

    let invalid_format = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(json!({ "password": PASSWORD, "format": "hex" })),
    )
    .await
    .expect_err("invalid format must be refused");
    assert!(matches!(invalid_format, AuthError::BadRequest(_)));

    let events = egress_events(&pool, &pubkey).await;
    let reasons = events
        .iter()
        .map(|event| event.reason_code.as_deref())
        .collect::<Vec<_>>();
    assert!(
        reasons.contains(&Some("missing_password")),
        "missing password must be audited: {events:?}"
    );
    assert!(
        reasons.contains(&Some("invalid_format")),
        "invalid format after a correct password must be audited: {events:?}"
    );
}

#[tokio::test]
#[serial]
async fn change_key_duplicate_after_correct_password_is_audited() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;

    let duplicate_keys = Keys::generate();
    let duplicate_pubkey = duplicate_keys.public_key().to_hex();
    insert_user(
        &pool,
        &duplicate_pubkey,
        &unique_email(),
        PASSWORD,
        true,
        false,
    )
    .await;

    let duplicate_nsec = duplicate_keys
        .secret_key()
        .to_bech32()
        .expect("encode duplicate key");
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;

    let err = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: Some(duplicate_nsec),
        }),
    )
    .await
    .expect_err("duplicate BYOK pubkey must be refused");
    assert!(matches!(err, AuthError::DuplicateKey));

    let events = egress_events(&pool, &pubkey).await;
    let duplicate_event = events
        .iter()
        .find(|event| event.reason_code.as_deref() == Some("duplicate_key"))
        .expect("duplicate-key refusal must be audited");
    assert_eq!(duplicate_event.endpoint, "/api/user/change-key");
    assert_eq!(
        duplicate_event.metadata_json["new_pubkey"],
        serde_json::json!(duplicate_pubkey)
    );
}

#[tokio::test]
#[serial]
async fn export_and_change_key_share_one_attempt_budget() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    // Spend the whole budget on export-key…
    burn_attempts(&auth_state, &keys, &bearer, MAX_ATTEMPTS).await;

    // …and change-key must already be locked. Otherwise an attacker just moves
    // the guessing to the other endpoint that takes the same password.
    let err = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(ChangeKeyRequest {
            password: "wrong-password".to_string(),
            nsec: None,
        }),
    )
    .await
    .expect_err("change-key must share the export-key budget");

    assert!(
        matches!(err, AuthError::TooManyRequests { .. }),
        "expected TooManyRequests, got: {err:?}"
    );
}

#[tokio::test]
#[serial]
async fn successful_rotation_starts_a_budget_for_the_new_pubkey() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let old_keys = Keys::generate();
    let old_pubkey = old_keys.public_key().to_hex();
    insert_user(&pool, &old_pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &old_pubkey, &old_keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let old_bearer = bearer_for(&old_keys).await;

    for _ in 0..(MAX_ATTEMPTS - 1) {
        let error = export_key(
            create_test_tenant(),
            State(auth_state.clone()),
            auth_headers(&old_bearer),
            Json(json!({ "password": "wrong", "format": "nsec" })),
        )
        .await
        .expect_err("wrong password");
        assert!(matches!(error, AuthError::InvalidCredentials));
    }

    let new_keys = Keys::generate();
    change_key(
        create_test_tenant(),
        State(auth_state.clone()),
        auth_headers(&old_bearer),
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("nsec")),
        }),
    )
    .await
    .expect("correct password may use the fifth in-flight slot");

    let new_bearer = bearer_for(&new_keys).await;
    let error = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&new_bearer),
        Json(json!({ "password": "wrong", "format": "nsec" })),
    )
    .await
    .expect_err("wrong password on new identity");
    assert!(
        matches!(error, AuthError::InvalidCredentials),
        "rotation intentionally starts a fresh budget for the new pubkey: {error:?}"
    );
}

#[tokio::test]
#[serial]
async fn policy_denial_outranks_the_lockout() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;
    burn_attempts(&auth_state, &keys, &bearer, MAX_ATTEMPTS).await;
    sqlx::query(
        "UPDATE users
         SET verified_minor = true, verified_minor_at = NOW()
         WHERE tenant_id = $1 AND pubkey = $2",
    )
    .bind(TENANT_ID)
    .bind(&pubkey)
    .execute(&pool)
    .await
    .expect("apply policy state after spending the Redis budget");

    let err = export_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect_err("a protected minor must be refused");

    // The policy answer must not vary with lockout state, which an attacker can drive.
    assert!(
        matches!(err, AuthError::KeyEgressDenied),
        "policy denial must outrank the lockout, got: {err:?}"
    );

    // …and the refusal is recorded as the denial it was, not as a lockout.
    let events = egress_events(&pool, &pubkey).await;
    let recorded = events
        .last()
        .expect("the refusal must be audited")
        .reason_code
        .clone();
    assert_eq!(recorded.as_deref(), Some("policy_denied"));
}

#[tokio::test]
#[serial]
async fn gates_before_the_password_do_not_spend_the_budget() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    // Unverified email: refused before bcrypt, so it never guesses at anything.
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, false, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    for _ in 0..(MAX_ATTEMPTS + 2) {
        let err = export_key(
            create_test_tenant(),
            State(auth_state.clone()),
            auth_headers(&bearer),
            Json(json!({ "password": PASSWORD, "format": "nsec" })),
        )
        .await
        .expect_err("unverified email must be refused");
        assert!(
            matches!(err, AuthError::EmailNotVerified),
            "must stay EmailNotVerified rather than locking out, got: {err:?}"
        );
    }

    let events = egress_events(&pool, &pubkey).await;
    assert!(
        events
            .iter()
            .all(|event| event.reason_code.as_deref() == Some("email_not_verified")),
        "no attempt should have been counted as a wrong password: {events:?}"
    );
}

#[tokio::test]
#[serial]
async fn email_verification_gate_is_intentionally_not_symmetric() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, false, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let bearer = bearer_for(&keys).await;

    let export_error = export_key(
        create_test_tenant(),
        State(auth_state.clone()),
        auth_headers(&bearer),
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    .expect_err("export must require a verified email");
    assert!(matches!(export_error, AuthError::EmailNotVerified));

    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer),
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("nsec")),
        }),
    )
    .await
    .expect("the pre-existing change-key contract does not check email_verified");
    let migrated: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND pubkey = $2)",
    )
    .bind(TENANT_ID)
    .bind(&new_pubkey)
    .fetch_one(&pool)
    .await
    .expect("check migrated identity");
    assert!(migrated);
}

#[tokio::test]
#[serial]
async fn change_key_success_records_the_new_identity_in_full() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_user(&pool, &pubkey, &unique_email(), PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;

    let response = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: None,
        }),
    )
    .await
    .expect("change-key must succeed");

    let events = egress_events(&pool, &pubkey).await;
    let success = events
        .iter()
        .find(|event| event.outcome == "success")
        .expect("change-key success must be audited");
    assert_eq!(success.endpoint, "/api/user/change-key");
    assert_eq!(success.event_type, "key_egress");

    let new_pubkey = success.metadata_json["new_pubkey"]
        .as_str()
        .expect("new_pubkey must be recorded");
    assert_eq!(
        new_pubkey.len(),
        64,
        "the new identity must be recorded in full, got: {new_pubkey}"
    );
    assert_ne!(new_pubkey, pubkey);
    assert_eq!(success.metadata_json["byok"], serde_json::json!(false));

    let status: String =
        sqlx::query_scalar("SELECT status FROM users WHERE tenant_id = $1 AND pubkey = $2")
            .bind(TENANT_ID)
            .bind(new_pubkey)
            .fetch_one(&pool)
            .await
            .expect("load post-change account status");
    assert_eq!(
        status, "active",
        "the new row must match the active status used to build the UCAN before mutation"
    );

    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .expect("change-key session cookie")
        .to_str()
        .expect("ASCII cookie");
    let token = cookie
        .strip_prefix("keycast_session=")
        .and_then(|value| value.split(';').next())
        .expect("session token in cookie");
    let encoded_payload = token.split('.').nth(1).expect("UCAN payload segment");
    let payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .expect("base64url UCAN payload"),
    )
    .expect("JSON UCAN payload");
    assert!(
        !payload.to_string().contains("account_status"),
        "an active post-change account must not emit an account_status fact: {payload}"
    );
}

#[tokio::test]
#[serial]
async fn change_key_rolls_back_custody_when_its_success_audit_fails() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = unique_email();
    insert_user(&pool, &pubkey, &email, PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let oauth_id = create_oauth_authorization(&pool, &pubkey).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    let failure = AuditFailureTrigger::install(&pool, &pubkey, "/api/user/change-key").await;

    let result = change_key(
        create_test_tenant(),
        State(auth_state),
        auth_headers(&bearer_for(&keys).await),
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("encode nsec")),
        }),
    )
    .await;
    failure.remove(&pool).await;

    assert!(
        result.is_err(),
        "injected audit failure must fail the request"
    );
    assert_original_custody_unchanged(&pool, &pubkey, &new_pubkey, &email, oauth_id).await;
    assert!(
        egress_events(&pool, &pubkey)
            .await
            .iter()
            .all(|event| event.outcome != "success"),
        "failed transaction must not retain a success audit"
    );
}

#[tokio::test]
#[serial]
async fn change_key_missing_origin_fails_before_custody_changes() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("key manager");
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = unique_email();
    insert_user(&pool, &pubkey, &email, PASSWORD, true, false).await;
    create_personal_key(&pool, &pubkey, &keys, &km).await;
    let oauth_id = create_oauth_authorization(&pool, &pubkey).await;
    let auth_state = create_test_auth_state(pool.clone(), km_arc(km)).await;
    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    let bearer = bearer_for(&keys).await;
    let mut headers = auth_headers(&bearer);
    headers.remove("origin");

    let error = change_key(
        create_test_tenant(),
        State(auth_state),
        headers,
        Json(ChangeKeyRequest {
            password: PASSWORD.to_string(),
            nsec: Some(new_keys.secret_key().to_bech32().expect("encode nsec")),
        }),
    )
    .await
    .expect_err("Origin is required");

    assert!(matches!(error, AuthError::BadRequest(_)));
    assert_original_custody_unchanged(&pool, &pubkey, &new_pubkey, &email, oauth_id).await;
    assert!(
        egress_events(&pool, &pubkey)
            .await
            .iter()
            .all(|event| event.outcome != "success"),
        "request that never completed must not retain a success audit"
    );
}

// ------------------------------------------------------- wire-shape contract

#[tokio::test]
async fn rate_limited_response_is_429_with_retry_after_and_a_code() {
    let response = axum::response::IntoResponse::into_response(AuthError::TooManyRequests {
        message: "Too many incorrect passwords. Please wait before trying again.".to_string(),
        retry_after: 42,
    });

    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("Retry-After")
            .expect("Retry-After must be set")
            .to_str()
            .expect("ASCII"),
        "42"
    );

    let body = response_json(response).await;
    assert_eq!(body["code"], "TOO_MANY_ATTEMPTS");
    assert_eq!(
        body["error"],
        "Too many incorrect passwords. Please wait before trying again."
    );
}

#[tokio::test]
async fn email_not_verified_response_carries_a_stable_code() {
    let response = axum::response::IntoResponse::into_response(AuthError::EmailNotVerified);

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_eq!(body["code"], "EMAIL_NOT_VERIFIED");
    // The message is unchanged from before the code existed — clients that still
    // read prose keep working.
    assert_eq!(
        body["error"],
        "Please verify your email address before continuing. Check your inbox for the verification link."
    );
}

#[tokio::test]
async fn the_two_403s_are_distinguishable_without_reading_prose() {
    let denied = axum::response::IntoResponse::into_response(AuthError::KeyEgressDenied);
    let unverified = axum::response::IntoResponse::into_response(AuthError::EmailNotVerified);

    assert_eq!(denied.status(), unverified.status());

    let denied_body = response_json(denied).await;
    let unverified_body = response_json(unverified).await;
    assert_ne!(
        denied_body["code"], unverified_body["code"],
        "a client must be able to tell a recoverable 403 from a policy 403"
    );
    assert_eq!(denied_body["code"], "KEY_EGRESS_DENIED");
    assert_eq!(unverified_body["code"], "EMAIL_NOT_VERIFIED");
}
