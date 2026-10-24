#![cfg(feature = "integration-tests")]

// ABOUTME: Verifies OG Diviner eligibility uses the frozen signup policy.
// ABOUTME: Guards the cutoff, preload exclusions, and tenant-scoped roster grants.

use keycast_core::repositories::{og_diviner_cutoff, AccountDeletionOutcome, UserRepository};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

const TENANT_ID: i64 = 1;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    assert!(url.contains("localhost") || url.contains("127.0.0.1"));
    PgPool::connect(&url)
        .await
        .expect("connect to test database")
}

/// Fixture pubkeys carry a prefix unique to this test.
///
/// Generic fillers are shared across the suite -- `api/tests/`
/// `divine_name_promotion_timeout_test.rs` binds `"1".repeat(64)` against this
/// same database in the same run -- so a row leaked from here would collide on
/// the users primary key and fail an unrelated crate's test.
fn pubkey(seed: char) -> String {
    format!("06d1{}", std::iter::repeat_n(seed, 60).collect::<String>())
}

/// Removes every fixture row, scoped to this test's tenant.
async fn purge(pool: &PgPool, keys: &[&str]) {
    for key in keys {
        sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1 AND tenant_id = $2")
            .bind(key)
            .bind(TENANT_ID)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1 AND tenant_id = $2")
            .bind(key)
            .bind(TENANT_ID)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(key)
            .bind(TENANT_ID)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[serial]
async fn eligibility_uses_signup_claim_and_mobile_authorization_timestamps() {
    let pool = pool().await;
    let repository = UserRepository::new(pool.clone());
    // The real policy value, not a restatement of it: if the cutoff moves, this
    // test moves with it instead of silently testing a date nothing ships.
    let cutoff = og_diviner_cutoff();
    let ordinary = pubkey('1');
    let unclaimed = pubkey('2');
    let claimed_late = pubkey('3');
    let claimed_early = pubkey('a');
    let mobile_authorized = pubkey('4');
    let ordinary_completed_late = pubkey('6');
    let ordinary_at_cutoff = pubkey('7');
    let mobile_at_cutoff = pubkey('8');
    let preloaded_mobile_authorized = pubkey('f');
    let preloaded_mobile_at_cutoff = pubkey('0');
    let preloaded_other_client = pubkey('9');
    let preloaded_without_token = pubkey('b');
    let claimed_after_cutoff_token_deleted = pubkey('c');
    let suspended_ordinary = pubkey('d');
    let banned_claimed_early = pubkey('e');
    let keys = [
        ordinary.as_str(),
        unclaimed.as_str(),
        claimed_late.as_str(),
        claimed_early.as_str(),
        mobile_authorized.as_str(),
        ordinary_completed_late.as_str(),
        ordinary_at_cutoff.as_str(),
        mobile_at_cutoff.as_str(),
        preloaded_mobile_authorized.as_str(),
        preloaded_mobile_at_cutoff.as_str(),
        preloaded_other_client.as_str(),
        preloaded_without_token.as_str(),
        claimed_after_cutoff_token_deleted.as_str(),
        suspended_ordinary.as_str(),
        banned_claimed_early.as_str(),
    ];

    purge(&pool, &keys).await;

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at)
         VALUES ($1, 1, 'ordinary@example.invalid', TRUE, 'hash', $2, $2)",
    )
    .bind(&ordinary)
    .bind(cutoff - chrono::Duration::seconds(1))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, status, created_at, updated_at)
         VALUES ($1, 1, 'suspended@example.invalid', TRUE, 'hash', 'suspended', $2, $2)",
    )
    .bind(&suspended_ordinary)
    .bind(cutoff - chrono::Duration::seconds(1))
    .execute(&pool)
    .await
    .unwrap();

    // vine_id is the durable preload marker. These rows deliberately have no
    // token: one models create_preloaded_user before token issuance; the other
    // models a post-cutoff claim whose consumed token was later cleaned up.
    for (key, vine_id) in [
        (&preloaded_without_token, "vine-without-token"),
        (
            &claimed_after_cutoff_token_deleted,
            "vine-deleted-consumed-token",
        ),
    ] {
        sqlx::query(
            "INSERT INTO users
             (pubkey, tenant_id, vine_id, email, email_verified, password_hash,
              created_at, updated_at)
             VALUES ($1, 1, $2, $3, TRUE, 'hash', $4, $4)",
        )
        .bind(key)
        .bind(vine_id)
        .bind(format!("{vine_id}@example.invalid"))
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at)
         VALUES
         ($1, 1, 'completed-late@example.invalid', FALSE, 'hash', $3, $2),
         ($4, 1, 'at-cutoff@example.invalid', TRUE, 'hash', $2, $2)",
    )
    .bind(&ordinary_completed_late)
    .bind(cutoff)
    .bind(cutoff - chrono::Duration::seconds(1))
    .bind(&ordinary_at_cutoff)
    .execute(&pool)
    .await
    .unwrap();

    // Observed while the row is still unverified; asserted after teardown so a
    // failure here cannot leak fixtures into the shared test database.
    let completed_late_while_unverified = repository
        .is_og_diviner(&ordinary_completed_late, TENANT_ID, cutoff)
        .await
        .unwrap();

    sqlx::query(
        "UPDATE users
         SET email_verified = TRUE, updated_at = $1
         WHERE pubkey = $2 AND tenant_id = 1",
    )
    .bind(cutoff + chrono::Duration::seconds(1))
    .bind(&ordinary_completed_late)
    .execute(&pool)
    .await
    .unwrap();

    for key in [
        &unclaimed,
        &claimed_late,
        &claimed_early,
        &banned_claimed_early,
    ] {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, vine_id, created_at, updated_at)
             VALUES ($1, 1, $2, $3, $3)",
        )
        .bind(key)
        .bind(format!("vine-{key}"))
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    for (key, used_at) in [
        (&unclaimed, None),
        (&claimed_late, Some(cutoff)),
        (&claimed_early, Some(cutoff - chrono::Duration::seconds(1))),
        (
            &banned_claimed_early,
            Some(cutoff - chrono::Duration::seconds(1)),
        ),
    ] {
        sqlx::query(
            "INSERT INTO account_claim_tokens
             (token, user_pubkey, tenant_id, expires_at, used_at, created_at)
             VALUES ($1, $2, 1, $3, $4, $5)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(key)
        .bind(cutoff + chrono::Duration::days(1))
        .bind(used_at)
        .bind(cutoff - chrono::Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::query("UPDATE users SET status = 'banned' WHERE pubkey = $1 AND tenant_id = 1")
        .bind(&banned_claimed_early)
        .execute(&pool)
        .await
        .unwrap();

    for (key, bunker, created_at, vine_id) in [
        (
            &mobile_authorized,
            pubkey('5'),
            cutoff - chrono::Duration::seconds(1),
            None,
        ),
        (&mobile_at_cutoff, pubkey('9'), cutoff, None),
        (
            &preloaded_mobile_authorized,
            pubkey('b'),
            cutoff - chrono::Duration::seconds(1),
            Some("vine-mobile-before-cutoff"),
        ),
        (
            &preloaded_mobile_at_cutoff,
            pubkey('c'),
            cutoff,
            Some("vine-mobile-at-cutoff"),
        ),
    ] {
        // This matches completed headless materialization: the user and first
        // mobile authorization are created together at verification time.
        // Preloaded fixtures have no claim token and cannot use the ordinary
        // signup branch, isolating authorization evidence and its cutoff.
        sqlx::query(
            "INSERT INTO users
             (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at, vine_id)
             VALUES ($1, 1, $2, TRUE, 'hash', $3, $3, $4)",
        )
        .bind(key)
        .bind(format!("mobile-{key}@example.invalid"))
        .bind(created_at)
        .bind(vine_id)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO oauth_authorizations
             (user_pubkey, redirect_origin, client_id, bunker_public_key,
              secret_hash, relays, created_at, updated_at, tenant_id,
              handle_expires_at)
             VALUES ($1, 'https://divine.video', 'divine-mobile', $2,
                     'hash', '[]', $3, $3, 1, $4)",
        )
        .bind(key)
        .bind(bunker)
        .bind(created_at)
        .bind(cutoff + chrono::Duration::days(1))
        .execute(&pool)
        .await
        .unwrap();
    }

    // Pins the client_id filter itself. Every other authorization fixture is a
    // divine-mobile row, so dropping `AND oa.client_id = 'divine-mobile'` from
    // the disjunct leaves them all unchanged and the suite green -- while any
    // third-party OAuth client's pre-cutoff authorization would start granting
    // the chit. This account is preloaded and has no claim token, so the
    // authorization is its only candidate evidence, and it is the wrong client.
    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at,
          updated_at, vine_id)
         VALUES ($1, 1, $2, TRUE, 'hash', $3, $3, 'vine-other-client')",
    )
    .bind(&preloaded_other_client)
    .bind(format!(
        "other-client-{preloaded_other_client}@example.invalid"
    ))
    .bind(cutoff - chrono::Duration::days(30))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key,
          secret_hash, relays, created_at, updated_at, tenant_id,
          handle_expires_at)
         VALUES ($1, 'https://divine.video', 'divine-crossposter', $2,
                 'hash', '[]', $3, $3, 1, $4)",
    )
    .bind(&preloaded_other_client)
    .bind(pubkey('e'))
    .bind(cutoff - chrono::Duration::seconds(1))
    .bind(cutoff + chrono::Duration::days(1))
    .execute(&pool)
    .await
    .unwrap();

    let mut observed = Vec::new();
    for key in keys {
        observed.push(
            repository
                .is_og_diviner(key, TENANT_ID, cutoff)
                .await
                .unwrap(),
        );
    }

    // Teardown before the assertions, so the shared database is left clean even
    // when one of them fails.
    purge(&pool, &keys).await;

    let [ordinary_eligible, unclaimed_eligible, claimed_late_eligible, claimed_early_eligible, mobile_authorized_eligible, completed_late_eligible, at_cutoff_eligible, mobile_at_cutoff_eligible, preloaded_mobile_authorized_eligible, preloaded_mobile_at_cutoff_eligible, preloaded_other_client_eligible, preloaded_without_token_eligible, deleted_claim_token_eligible, suspended_ordinary_eligible, banned_claimed_early_eligible] =
        observed[..]
    else {
        panic!("expected one observation per fixture");
    };

    assert!(
        !completed_late_while_unverified,
        "an unverified account is not yet complete, so it does not qualify"
    );
    assert!(ordinary_eligible, "pre-cutoff completed signup qualifies");
    assert!(
        preloaded_mobile_authorized_eligible,
        "a preloaded account without claim tokens qualifies through pre-cutoff mobile authorization"
    );
    assert!(
        !preloaded_mobile_at_cutoff_eligible,
        "mobile authorization at the cutoff does not qualify a preloaded account"
    );
    assert!(
        !unclaimed_eligible,
        "a preloaded account nobody claimed does not qualify"
    );
    assert!(
        !claimed_late_eligible,
        "a preloaded account claimed at or after the cutoff does not qualify"
    );
    assert!(
        claimed_early_eligible,
        "a preloaded account claimed before the cutoff qualifies on the claim timestamp"
    );
    assert!(
        mobile_authorized_eligible,
        "a pre-cutoff first-party mobile authorization qualifies"
    );
    assert!(
        completed_late_eligible,
        "completing verification after the cutoff does not forfeit a pre-cutoff signup"
    );
    assert!(
        !at_cutoff_eligible,
        "the cutoff is exclusive: a signup exactly at it does not qualify"
    );
    assert!(
        !mobile_at_cutoff_eligible,
        "the cutoff is exclusive for mobile authorizations too"
    );
    assert!(
        !preloaded_without_token_eligible,
        "a preloaded row without a claim token cannot fall through to ordinary eligibility"
    );
    assert!(
        !deleted_claim_token_eligible,
        "deleting a post-cutoff consumed token cannot make a preloaded account ordinary"
    );
    assert!(
        suspended_ordinary_eligible,
        "suspension does not rewrite historical cohort membership"
    );
    assert!(
        !preloaded_other_client_eligible,
        "a pre-cutoff authorization from a client other than divine-mobile is \
         not signup evidence, so it does not qualify"
    );
    assert!(
        banned_claimed_early_eligible,
        "a ban does not rewrite historical cohort membership"
    );
}

/// Grant fixtures use their own prefix so they never share a key with the
/// signup fixtures above.
fn granted_pubkey(seed: char) -> String {
    format!("06d2{}", std::iter::repeat_n(seed, 60).collect::<String>())
}

/// A second tenant, so a grant can be shown not to cross tenants. Created on
/// demand because the test database seeds only tenant 1.
async fn second_tenant(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO tenants (domain, name) VALUES ('og-diviner-grants.example.invalid', 'OG grants test')
         ON CONFLICT (domain) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn grant(pool: &PgPool, tenant_id: i64, key: &str) {
    sqlx::query(
        "INSERT INTO og_diviner_grants (tenant_id, pubkey, evidence)
         VALUES ($1, $2, 'pre_cutoff_app_post')",
    )
    .bind(tenant_id)
    .bind(key)
    .execute(pool)
    .await
    .unwrap();
}

async fn purge_grants(pool: &PgPool, tenant_ids: &[i64], keys: &[&str]) {
    for tenant_id in tenant_ids {
        for key in keys {
            sqlx::query("DELETE FROM og_diviner_grants WHERE pubkey = $1 AND tenant_id = $2")
                .bind(key)
                .bind(tenant_id)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
#[serial]
async fn granted_app_posters_qualify_without_a_signup_record_and_only_in_their_tenant() {
    let pool = pool().await;
    let repository = UserRepository::new(pool.clone());
    let cutoff = og_diviner_cutoff();
    let other_tenant = second_tenant(&pool).await;

    // Most of this cohort brought their own key and has no Keycast account.
    let granted_no_account = granted_pubkey('1');
    // Someone who posted before the cutoff and imported the key afterwards:
    // their users row fails the signup rule, so only the grant qualifies them.
    let granted_late_account = granted_pubkey('2');
    let ungranted_no_account = granted_pubkey('3');
    let granted_in_other_tenant_only = granted_pubkey('4');
    let keys = [
        granted_no_account.as_str(),
        granted_late_account.as_str(),
        ungranted_no_account.as_str(),
        granted_in_other_tenant_only.as_str(),
    ];

    purge_grants(&pool, &[TENANT_ID, other_tenant], &keys).await;
    purge(&pool, &keys).await;

    sqlx::query(
        "INSERT INTO users
         (pubkey, tenant_id, email, email_verified, password_hash, created_at, updated_at)
         VALUES ($1, 1, 'granted-late@example.invalid', TRUE, 'hash', $2, $2)",
    )
    .bind(&granted_late_account)
    .bind(cutoff)
    .execute(&pool)
    .await
    .unwrap();

    let late_account_before_grant = repository
        .is_og_diviner(&granted_late_account, TENANT_ID, cutoff)
        .await
        .unwrap();

    grant(&pool, TENANT_ID, &granted_no_account).await;
    grant(&pool, TENANT_ID, &granted_late_account).await;
    grant(&pool, other_tenant, &granted_in_other_tenant_only).await;

    let mut observed = Vec::new();
    for key in keys {
        observed.push(
            repository
                .is_og_diviner(key, TENANT_ID, cutoff)
                .await
                .unwrap(),
        );
    }
    let tenant_one_grant_seen_from_other_tenant = repository
        .is_og_diviner(&granted_no_account, other_tenant, cutoff)
        .await
        .unwrap();
    let other_tenant_grant_seen_from_its_own_tenant = repository
        .is_og_diviner(&granted_in_other_tenant_only, other_tenant, cutoff)
        .await
        .unwrap();

    // Teardown before the assertions, as above.
    purge_grants(&pool, &[TENANT_ID, other_tenant], &keys).await;
    purge(&pool, &keys).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(other_tenant)
        .execute(&pool)
        .await
        .unwrap();

    let [granted_no_account_eligible, granted_late_account_eligible, ungranted_no_account_eligible, granted_in_other_tenant_only_eligible] =
        observed[..]
    else {
        panic!("expected one observation per fixture");
    };

    assert!(
        !late_account_before_grant,
        "precondition: a signup exactly at the cutoff does not qualify on its own"
    );
    assert!(
        granted_no_account_eligible,
        "a granted pubkey with no Keycast account qualifies"
    );
    assert!(
        granted_late_account_eligible,
        "a grant qualifies an account the signup rule rejects"
    );
    assert!(
        !ungranted_no_account_eligible,
        "a pubkey with neither a grant nor a signup record does not qualify"
    );
    assert!(
        !granted_in_other_tenant_only_eligible,
        "a grant in another tenant does not qualify the pubkey here"
    );
    assert!(
        !tenant_one_grant_seen_from_other_tenant,
        "a grant in tenant 1 does not qualify the pubkey in another tenant"
    );
    assert!(
        other_tenant_grant_seen_from_its_own_tenant,
        "positive control: the other tenant's grant does qualify in that tenant"
    );
}

async fn grant_count(pool: &PgPool, tenant_id: i64, key: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM og_diviner_grants WHERE tenant_id = $1 AND pubkey = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[serial]
async fn account_deletion_removes_the_grant_in_its_tenant_only() {
    let pool = pool().await;
    let repository = UserRepository::new(pool.clone());
    let cutoff = og_diviner_cutoff();
    let other_tenant = second_tenant(&pool).await;

    let with_account = granted_pubkey('5');
    // The common case: a grantee Keycast never held an account for, deleted on
    // the coordinator's request after a vanish elsewhere.
    let without_account = granted_pubkey('6');
    let keys = [with_account.as_str(), without_account.as_str()];

    purge_grants(&pool, &[TENANT_ID, other_tenant], &keys).await;
    purge(&pool, &keys).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, 1, $2, $2)",
    )
    .bind(&with_account)
    .bind(cutoff)
    .execute(&pool)
    .await
    .unwrap();
    for key in keys {
        grant(&pool, TENANT_ID, key).await;
        grant(&pool, other_tenant, key).await;
    }

    let deleted = repository.delete_account(&with_account, TENANT_ID).await;

    let mut tx = pool.begin().await.unwrap();
    let absent = UserRepository::delete_account_in_tx(&mut tx, &without_account, TENANT_ID).await;
    tx.commit().await.unwrap();

    let with_account_eligible = repository
        .is_og_diviner(&with_account, TENANT_ID, cutoff)
        .await
        .unwrap();
    let without_account_eligible = repository
        .is_og_diviner(&without_account, TENANT_ID, cutoff)
        .await
        .unwrap();
    let with_account_grants = grant_count(&pool, TENANT_ID, &with_account).await;
    let without_account_grants = grant_count(&pool, TENANT_ID, &without_account).await;
    let other_tenant_grants = [
        grant_count(&pool, other_tenant, &with_account).await,
        grant_count(&pool, other_tenant, &without_account).await,
    ];

    purge_grants(&pool, &[TENANT_ID, other_tenant], &keys).await;
    purge(&pool, &keys).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(other_tenant)
        .execute(&pool)
        .await
        .unwrap();

    deleted.expect("the account existed, so deletion succeeds");
    assert!(
        matches!(absent, Ok(AccountDeletionOutcome::AlreadyAbsent)),
        "a grantee with no account is reported absent: {:?}",
        absent.as_ref().err()
    );
    assert_eq!(
        with_account_grants, 0,
        "deleting the account removes its grant"
    );
    assert!(
        !with_account_eligible,
        "a deleted account is no longer eligible"
    );
    assert_eq!(
        without_account_grants, 0,
        "the grant goes even when there was no account to delete"
    );
    assert!(!without_account_eligible);
    assert_eq!(
        other_tenant_grants,
        [1, 1],
        "the same pubkey's grant in another tenant survives"
    );
}
