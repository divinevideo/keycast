use chrono::{Duration, Utc};
use keycast_core::repositories::{AuthEventRecord, AuthEventRepository};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn assert_test_database_url() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    assert!(
        url.contains("localhost") || url.contains("127.0.0.1"),
        "Tests must run against localhost database"
    );
}

async fn setup_pool() -> PgPool {
    assert_test_database_url();
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

#[tokio::test]
async fn records_and_queries_auth_events() {
    let pool = setup_pool().await;
    let repo = AuthEventRepository::new(pool.clone());
    let suffix = Uuid::new_v4().to_string();
    let email = format!("auth-event-{}@example.com", suffix);
    let pubkey = format!("{:0>64}", suffix.replace('-', ""));
    let request_id = format!("req-{}", &suffix[..8]);

    repo.record(AuthEventRecord {
        tenant_id: 1,
        request_id: request_id.clone(),
        endpoint: "/api/headless/login".to_string(),
        event_type: "request_completed".to_string(),
        outcome: "failure".to_string(),
        reason_code: Some("user_not_found".to_string()),
        http_status: Some(401),
        email: Some(email.clone()),
        email_hash: "hash".to_string(),
        pubkey: Some(pubkey.clone()),
        pubkey_prefix: Some(pubkey[..8].to_string()),
        client_id: Some("test-client".to_string()),
        redirect_origin: Some("https://example.com".to_string()),
        user_agent: Some("integration-test".to_string()),
        metadata_json: json!({"flow": "headless"}),
    })
    .await
    .unwrap();

    let by_email = repo.list_recent_by_email(1, &email, 10).await.unwrap();
    assert_eq!(by_email.len(), 1);
    assert_eq!(by_email[0].request_id, request_id);

    let by_request = repo
        .list_recent_by_request_id(1, &request_id, 10)
        .await
        .unwrap();
    assert_eq!(by_request.len(), 1);
    assert_eq!(by_request[0].reason_code.as_deref(), Some("user_not_found"));
}

/// `count_recent_failures` is the read side of the raw-key egress lockout, so it
/// has to count only the matching failures and report the oldest one in the
/// active budget — that timestamp is what tells a locked-out caller when the
/// window reopens.
#[tokio::test]
async fn counts_only_matching_failures_and_reports_the_oldest() {
    let pool = setup_pool().await;
    let repo = AuthEventRepository::new(pool.clone());
    let suffix = Uuid::new_v4().to_string();
    let pubkey = format!("{:0>64}", suffix.replace('-', ""));
    let other_pubkey = format!("{:0>64}", Uuid::new_v4().to_string().replace('-', ""));

    let write = |pubkey: String, event_type: &str, outcome: &str, reason: &str| {
        let repo = repo.clone();
        let event_type = event_type.to_string();
        let outcome = outcome.to_string();
        let reason = reason.to_string();
        async move {
            repo.record(AuthEventRecord {
                tenant_id: 1,
                request_id: Uuid::new_v4().to_string(),
                endpoint: "/api/user/export-key".to_string(),
                event_type,
                outcome,
                reason_code: Some(reason),
                http_status: Some(401),
                email: None,
                email_hash: "none".to_string(),
                pubkey: Some(pubkey),
                pubkey_prefix: None,
                client_id: None,
                redirect_origin: None,
                user_agent: None,
                metadata_json: json!({}),
            })
            .await
            .unwrap()
        }
    };

    // Two that count.
    let mut counted =
        vec![write(pubkey.clone(), "key_egress", "failure", "invalid_password").await];
    counted.push(write(pubkey.clone(), "key_egress", "failure", "invalid_password").await);
    // Three that must not: wrong outcome, wrong reason, wrong event_type.
    write(pubkey.clone(), "key_egress", "success", "invalid_password").await;
    write(pubkey.clone(), "key_egress", "failure", "rate_limited").await;
    write(pubkey.clone(), "login", "failure", "invalid_password").await;
    // And another account's failure must not spend this account's budget.
    write(other_pubkey, "key_egress", "failure", "invalid_password").await;

    let window_start = Utc::now() - Duration::minutes(15);
    let (count, oldest) = repo
        .count_recent_failures(
            1,
            &pubkey,
            "key_egress",
            "invalid_password",
            window_start,
            5,
        )
        .await
        .unwrap();

    assert_eq!(count, 2, "only matching failures count");
    assert_eq!(
        oldest.expect("oldest must be reported when the count is non-zero"),
        counted[0].occurred_at,
        "oldest must be the first failure, since that is the next one to age out"
    );

    for _ in 0..4 {
        counted.push(write(pubkey.clone(), "key_egress", "failure", "invalid_password").await);
    }

    let (over_budget_count, active_budget_oldest) = repo
        .count_recent_failures(
            1,
            &pubkey,
            "key_egress",
            "invalid_password",
            window_start,
            5,
        )
        .await
        .unwrap();

    assert_eq!(over_budget_count, 6);
    assert_eq!(
        active_budget_oldest.expect("oldest active-budget failure must be reported"),
        counted[1].occurred_at,
        "when over budget, Retry-After is based on the 5th newest failure aging out"
    );

    // A window that has already moved past every failure counts nothing.
    let (aged_out, none) = repo
        .count_recent_failures(
            1,
            &pubkey,
            "key_egress",
            "invalid_password",
            Utc::now() + Duration::seconds(1),
            5,
        )
        .await
        .unwrap();
    assert_eq!(aged_out, 0);
    assert!(none.is_none());
}
