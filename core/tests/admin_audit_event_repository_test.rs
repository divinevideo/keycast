use keycast_core::repositories::{AdminAuditEventRecord, AdminAuditEventRepository};
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
async fn records_and_lists_admin_audit_event() {
    let pool = setup_pool().await;
    let repo = AdminAuditEventRepository::new(pool.clone());

    // Use a synthetic tenant id so this test does not collide with other
    // suites running in parallel against the shared test DB.
    let tenant_id: i64 = 9_000_000 + (Uuid::new_v4().as_u128() as i64).rem_euclid(1_000_000);
    let actor_pubkey = format!("{:0>64}", Uuid::new_v4().simple());
    let target_client_id = format!("audit-test-client-{}", &Uuid::new_v4().to_string()[..8]);

    let inserted = repo
        .record(AdminAuditEventRecord {
            tenant_id,
            actor_pubkey: actor_pubkey.clone(),
            action: "registered_client.create".to_string(),
            target_resource_type: "registered_client".to_string(),
            target_resource_id: Some("123".to_string()),
            target_client_id: Some(target_client_id.clone()),
            metadata_json: json!({
                "name": "Audit Test",
                "allowed_redirect_uris": ["https://example.com/cb"]
            }),
        })
        .await
        .expect("audit insert should succeed");

    assert!(inserted.id > 0, "id should be set");
    assert_eq!(inserted.tenant_id, tenant_id);
    assert_eq!(inserted.actor_pubkey, actor_pubkey);
    assert_eq!(inserted.action, "registered_client.create");
    assert_eq!(inserted.target_resource_type, "registered_client");
    assert_eq!(inserted.target_resource_id.as_deref(), Some("123"));
    assert_eq!(
        inserted.target_client_id.as_deref(),
        Some(target_client_id.as_str())
    );
    assert_eq!(inserted.metadata_json["name"], "Audit Test");

    let listed = repo
        .list_recent(tenant_id, 10)
        .await
        .expect("list_recent should succeed");

    assert_eq!(listed.len(), 1, "exactly one event for this tenant");
    assert_eq!(listed[0].id, inserted.id);
    assert_eq!(listed[0].action, "registered_client.create");
    assert_eq!(
        listed[0].target_client_id.as_deref(),
        Some(target_client_id.as_str())
    );
}

#[tokio::test]
async fn list_recent_returns_newest_first_and_respects_tenant_scope() {
    let pool = setup_pool().await;
    let repo = AdminAuditEventRepository::new(pool.clone());

    let tenant_a: i64 = 9_100_000 + (Uuid::new_v4().as_u128() as i64).rem_euclid(1_000_000);
    let tenant_b: i64 = 9_200_000 + (Uuid::new_v4().as_u128() as i64).rem_euclid(1_000_000);
    let actor = format!("{:0>64}", Uuid::new_v4().simple());

    // Insert two events for tenant_a, one for tenant_b.
    for action in ["registered_client.create", "registered_client.update"] {
        repo.record(AdminAuditEventRecord {
            tenant_id: tenant_a,
            actor_pubkey: actor.clone(),
            action: action.to_string(),
            target_resource_type: "registered_client".to_string(),
            target_resource_id: Some("1".to_string()),
            target_client_id: Some("client-a".to_string()),
            metadata_json: json!({}),
        })
        .await
        .unwrap();
    }
    repo.record(AdminAuditEventRecord {
        tenant_id: tenant_b,
        actor_pubkey: actor.clone(),
        action: "registered_client.delete".to_string(),
        target_resource_type: "registered_client".to_string(),
        target_resource_id: Some("9".to_string()),
        target_client_id: Some("client-b".to_string()),
        metadata_json: json!({}),
    })
    .await
    .unwrap();

    let a_list = repo.list_recent(tenant_a, 10).await.unwrap();
    assert_eq!(a_list.len(), 2, "tenant_a should see only its own rows");
    assert!(
        a_list[0].id > a_list[1].id,
        "list_recent should be newest first (descending id)"
    );
    assert!(a_list.iter().all(|row| row.tenant_id == tenant_a));

    let b_list = repo.list_recent(tenant_b, 10).await.unwrap();
    assert_eq!(b_list.len(), 1);
    assert_eq!(b_list[0].target_client_id.as_deref(), Some("client-b"));
}
