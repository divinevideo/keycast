#![cfg(feature = "integration-tests")]
// ABOUTME: Runtime probe for nested SQLx pool acquisition -- every transaction-bearing
// ABOUTME: repository method must complete a call on a pool with exactly one connection.

//! # The one-connection probe
//!
//! This exists because repositories hold their own `PgPool` and so can acquire
//! a connection on their own. The stronger fix is for every repository method
//! to take `&mut PgConnection`, which makes nested acquisition unrepresentable
//! rather than merely detectable; if that ever lands, delete this file, because
//! it would be testing something that cannot happen.
//!
//! Production runs `max_connections = 10` per instance with
//! `ACQUIRE_TIMEOUT_SECS = 60` (`core/src/database.rs`). A code path that holds
//! an open transaction while independently acquiring a second connection from
//! the same pool needs TWO connections to serve ONE request. That does not fail
//! in a quiet test suite -- it fails under concurrency, by stalling every
//! stalled request for the full 60s while it keeps holding its first
//! connection. One exposed handler can starve login, OAuth and the signer.
//!
//! Concurrency tests cannot pin this down: whether they trip depends on burst
//! size versus pool size, which makes them knife edges that pass for the wrong
//! reason. The deterministic probe is a pool of size one. A path that needs a
//! second connection can never get it, so it blocks until the acquire timeout
//! expires; a path that needs only one returns in milliseconds. The two
//! outcomes differ by three orders of magnitude, so [`PROBE_ACQUIRE_TIMEOUT`]
//! is not a tuning knob.
//!
//! `nesting_probe_detects_a_deliberate_violation` is the control: it performs a
//! real nested acquisition and asserts the probe catches it. Without that, a
//! harness that silently stopped working would look exactly like a clean run.
//!
//! # This probe is a sample, not a sweep
//!
//! Each case here costs a hand-written fixture, so the probe covers
//! [`COVERED_SITES`] of the [`TOTAL_HOLD_SITES`] functions in the workspace that
//! hold a pool connection. **A green run here does not mean the codebase is
//! clean.** It means the paths real traffic reaches were exercised and none of
//! them needed a second connection. When you add a repository method that opens
//! a transaction, add a case here for it.

use std::future::Future;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use keycast_core::repositories::UserRepository;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// Short on purpose: a nesting path burns all of it, a correct path uses none.
const PROBE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(4);

/// A correct single-connection call takes milliseconds; a nesting one takes the
/// full [`PROBE_ACQUIRE_TIMEOUT`]. This sits between the two with wide margin on
/// both sides, so a loaded CI box cannot turn a pass into a failure and a real
/// nesting bug cannot squeeze under it.
const MAX_HEALTHY: Duration = Duration::from_secs(2);

/// The default tenant seeded by `database/migrations`.
const TENANT_ID: i64 = 1;

/// Every function in the workspace that holds a pool connection.
///
/// Re-derive with: `rg -n 'self\.pool\.begin\(\)' core/src signer/src api/src`
/// plus any function taking `&mut Transaction`. Update this when it changes.
const TOTAL_HOLD_SITES: usize = 17;

/// The subset this probe exercises, highest reachability first. Each entry
/// corresponds to one `#[tokio::test]` below.
const COVERED_SITES: &[&str] = &[
    "UserRepository::register_with_personal_key",
    "UserRepository::finalize_oauth_registration",
    "UserRepository::complete_pending_oauth_registration",
    "UserRepository::claim_account_consuming_token",
    "UserRepository::delete_account",
    "UserRepository::change_key_transaction",
    "UserRepository::create_preloaded_user",
    "UserRepository::suggest_users_for_admin",
];

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string())
}

/// Pool for fixtures. Kept separate from the probe pool so seeding never
/// competes for the single connection under test.
async fn seed_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url())
        .await
        .expect("connect seed pool")
}

/// A pool with exactly one connection. Surviving one request on this pool is
/// proof that the path never holds two at once.
async fn one_connection_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(PROBE_ACQUIRE_TIMEOUT)
        .connect(&database_url())
        .await
        .expect("connect probe pool")
}

/// Runs `exercise` on a one-connection pool and fails if it stalls.
///
/// The call's own success or failure is irrelevant -- a method may legitimately
/// return `NotFound` or a constraint error. What is asserted is that it
/// *returned* rather than blocking on the pool.
async fn assert_no_nested_acquisition<F, Fut, T>(label: &str, exercise: F)
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = T>,
{
    let pool = one_connection_pool().await;
    let started = Instant::now();
    let _ = exercise(pool).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < MAX_HEALTHY,
        "{label} needed more than one pool connection: it ran for {elapsed:?} on a \
         max_connections(1) pool (acquire timeout {PROBE_ACQUIRE_TIMEOUT:?}).\n\n\
         This is nested pool acquisition: the path holds a transaction (or another \
         connection) while calling something that acquires its own connection from \
         the same pool. In production that path needs two of the ten connections per \
         request and stalls for {stall}s under load, holding its first connection the \
         whole time and starving every other endpoint on the instance.\n\n\
         Fix: thread the open transaction into the inner call (`&mut *tx`) instead of \
         letting it reach for the pool.",
        stall = 60,
    );
}

async fn insert_user(pool: &PgPool, pubkey: &str, email: &str) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, 'x', true, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert user");
}

fn unique_pubkey() -> String {
    Uuid::new_v4().simple().to_string().repeat(2)
}

fn unique_email() -> String {
    format!("np-{}@example.com", Uuid::new_v4())
}

// ===========================================================================
// Coverage disclosure.
// ===========================================================================

/// States the probe's coverage in the test name, so a reader skimming a green
/// run cannot mistake it for a clean bill of health on the whole codebase.
///
/// The name is the point: `println!` is swallowed on a passing test, but the
/// harness always prints the test name.
#[test]
fn probe_samples_8_of_17_hold_sites_a_green_run_is_not_a_clean_sweep() {
    assert_eq!(
        COVERED_SITES.len(),
        8,
        "COVERED_SITES changed but the test name still says 8; rename the test so \
         the printed coverage stays truthful"
    );
    assert!(
        COVERED_SITES.len() <= TOTAL_HOLD_SITES,
        "COVERED_SITES lists more sites than exist"
    );

    // Visible with --nocapture, and on any failure above.
    println!(
        "one-connection probe covers {}/{} hold sites:\n{}\n\
         The remaining {} are not exercised here, so a green run is not a \
         clean bill of health for the whole workspace.",
        COVERED_SITES.len(),
        TOTAL_HOLD_SITES,
        COVERED_SITES
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
        TOTAL_HOLD_SITES - COVERED_SITES.len(),
    );
}

// ===========================================================================
// Control: the probe must actually catch a violation.
// ===========================================================================

/// Deliberately nests: holds a transaction, then calls a repository method that
/// acquires its own connection. This is the exact shape the audit looks for.
async fn deliberately_nested(pool: PgPool) {
    let repo = UserRepository::new(pool.clone());
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT 1")
        .execute(&mut *tx)
        .await
        .expect("query on tx");
    // Second connection demanded while the first is still held.
    let _ = repo.exists("deadbeef", TENANT_ID).await;
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn nesting_probe_detects_a_deliberate_violation() {
    let pool = one_connection_pool().await;
    let started = Instant::now();
    deliberately_nested(pool).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed >= PROBE_ACQUIRE_TIMEOUT,
        "the one-connection probe failed to detect a deliberate nested acquisition \
         (returned in {elapsed:?}). The probe is broken, so every other test in this \
         file is now meaningless."
    );
}

// ===========================================================================
// Transaction-bearing repository methods, highest reachability first.
// ===========================================================================

/// Signup: POST /auth/register -> api/src/api/http/auth.rs.
#[tokio::test]
async fn register_with_personal_key_uses_one_connection() {
    assert_no_nested_acquisition(
        "UserRepository::register_with_personal_key",
        |pool| async move {
            UserRepository::new(pool)
                .register_with_personal_key(
                    &unique_pubkey(),
                    TENANT_ID,
                    &unique_email(),
                    Some("hash"),
                    &Uuid::new_v4().to_string(),
                    Utc::now() + ChronoDuration::hours(1),
                    b"encrypted",
                )
                .await
        },
    )
    .await;
}

/// OAuth registration finalisation -> api/src/api/http/oauth.rs.
#[tokio::test]
async fn finalize_oauth_registration_uses_one_connection() {
    assert_no_nested_acquisition(
        "UserRepository::finalize_oauth_registration",
        |pool| async move {
            UserRepository::new(pool)
                .finalize_oauth_registration(
                    &unique_pubkey(),
                    TENANT_ID,
                    &unique_email(),
                    "hash",
                    &Uuid::new_v4().to_string(),
                    Utc::now() + ChronoDuration::hours(1),
                    b"encrypted",
                    &Uuid::new_v4().to_string(),
                )
                .await
        },
    )
    .await;
}

/// Email verification completing a deferred OAuth signup -> auth.rs.
#[tokio::test]
async fn complete_pending_oauth_registration_uses_one_connection() {
    let seed = seed_pool().await;
    let pubkey = unique_pubkey();
    insert_user(&seed, &pubkey, &unique_email()).await;

    assert_no_nested_acquisition(
        "UserRepository::complete_pending_oauth_registration",
        |pool| async move {
            UserRepository::new(pool)
                .complete_pending_oauth_registration(
                    &pubkey,
                    TENANT_ID,
                    &unique_email(),
                    "hash",
                    &Uuid::new_v4().to_string(),
                    Some(b"encrypted"),
                )
                .await
        },
    )
    .await;
}

/// Account claim -> api/src/api/http/claim.rs.
#[tokio::test]
async fn claim_account_consuming_token_uses_one_connection() {
    assert_no_nested_acquisition(
        "UserRepository::claim_account_consuming_token",
        |pool| async move {
            UserRepository::new(pool)
                .claim_account_consuming_token(
                    &Uuid::new_v4().to_string(),
                    TENANT_ID,
                    &unique_email(),
                    "hash",
                )
                .await
        },
    )
    .await;
}

/// Account deletion -> auth.rs. Fans out across teams, authorizations and keys.
#[tokio::test]
async fn delete_account_uses_one_connection() {
    let seed = seed_pool().await;
    let pubkey = unique_pubkey();
    insert_user(&seed, &pubkey, &unique_email()).await;

    assert_no_nested_acquisition("UserRepository::delete_account", |pool| async move {
        UserRepository::new(pool)
            .delete_account(&pubkey, TENANT_ID)
            .await
    })
    .await;
}

/// Key rotation -> auth.rs. Deletes authorizations and re-parents the identity.
#[tokio::test]
async fn change_key_transaction_uses_one_connection() {
    let seed = seed_pool().await;
    let old = unique_pubkey();
    insert_user(&seed, &old, &unique_email()).await;

    assert_no_nested_acquisition(
        "UserRepository::change_key_transaction",
        |pool| async move {
            UserRepository::new(pool)
                .change_key_transaction(
                    &old,
                    &unique_pubkey(),
                    TENANT_ID,
                    &unique_email(),
                    "hash",
                    b"encrypted",
                )
                .await
        },
    )
    .await;
}

/// Admin preload -> api/src/api/http/admin.rs.
#[tokio::test]
async fn create_preloaded_user_uses_one_connection() {
    assert_no_nested_acquisition("UserRepository::create_preloaded_user", |pool| async move {
        UserRepository::new(pool)
            .create_preloaded_user(
                &unique_pubkey(),
                TENANT_ID,
                &Uuid::new_v4().to_string(),
                &format!("u{}", Uuid::new_v4().simple()),
                Some("Display"),
                b"encrypted",
            )
            .await
    })
    .await;
}

/// Admin user search -> admin.rs. Sets a local GUC inside the transaction, so
/// it is the method most likely to reach for a second connection by accident.
#[tokio::test]
async fn suggest_users_for_admin_uses_one_connection() {
    assert_no_nested_acquisition(
        "UserRepository::suggest_users_for_admin",
        |pool| async move {
            UserRepository::new(pool)
                .suggest_users_for_admin("test", TENANT_ID)
                .await
        },
    )
    .await;
}
