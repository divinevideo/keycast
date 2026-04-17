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
