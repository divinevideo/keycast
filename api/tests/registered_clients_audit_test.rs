#![cfg(feature = "integration-tests")]

// ABOUTME: HTTP-handler tests verifying registered_client admin actions write
// ABOUTME: durable audit rows to admin_audit_events.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::{
            admin::{
                create_registered_client, delete_registered_client, update_registered_client,
                CreateRegisteredClientRequest, UpdateRegisteredClientRequest,
            },
            routes::AuthState,
        },
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    pool
}

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

fn make_auth_state(pool: PgPool) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
            tenant_cache,
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
        }),
        auth_tx: None,
    }
}

fn make_tenant(id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id,
        domain: "localhost".to_string(),
        name: "Audit Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn make_admin_auth(pubkey: &str) -> UcanAuth {
    UcanAuth {
        pubkey: pubkey.to_string(),
        admin_role: Some("full".to_string()),
    }
}

async fn cleanup(pool: &PgPool, tenant_id: i64, client_id: &str, actor_pubkey: &str) {
    let _ = sqlx::query("DELETE FROM registered_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind(tenant_id)
        .bind(client_id)
        .execute(pool)
        .await;
    let _ =
        sqlx::query("DELETE FROM admin_audit_events WHERE tenant_id = $1 AND actor_pubkey = $2")
            .bind(tenant_id)
            .bind(actor_pubkey)
            .execute(pool)
            .await;
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    actor_pubkey: String,
    action: String,
    target_resource_type: String,
    target_resource_id: Option<String>,
    target_client_id: Option<String>,
    metadata_json: serde_json::Value,
}

async fn read_audit_rows(pool: &PgPool, tenant_id: i64, actor_pubkey: &str) -> Vec<AuditRow> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT actor_pubkey, action, target_resource_type, target_resource_id,
                target_client_id, metadata_json
         FROM admin_audit_events
         WHERE tenant_id = $1 AND actor_pubkey = $2
         ORDER BY occurred_at ASC, id ASC",
    )
    .bind(tenant_id)
    .bind(actor_pubkey)
    .fetch_all(pool)
    .await
    .expect("audit rows fetch")
}

#[tokio::test]
async fn create_update_delete_each_writes_admin_audit_event() {
    let pool = setup_pool().await;

    // Synthetic tenant id well outside the seeded range to avoid colliding with
    // other tests running in parallel against the shared DB.
    let tenant_id: i64 = 9_300_000 + (Uuid::new_v4().as_u128() as i64).rem_euclid(1_000_000);
    let actor_pubkey = format!("{:0>64}", Uuid::new_v4().simple());
    let client_id = format!("audit-http-{}", &Uuid::new_v4().to_string()[..8]);

    cleanup(&pool, tenant_id, &client_id, &actor_pubkey).await;

    let state = make_auth_state(pool.clone());

    // CREATE
    let created = create_registered_client(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Json(CreateRegisteredClientRequest {
            client_id: client_id.clone(),
            name: "Audit HTTP".to_string(),
            allowed_redirect_uris: vec!["https://example.com/cb".to_string()],
        }),
    )
    .await
    .expect("create handler ok")
    .0;

    // UPDATE
    let _ = update_registered_client(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Path(created.id),
        Json(UpdateRegisteredClientRequest {
            name: Some("Audit HTTP renamed".to_string()),
            allowed_redirect_uris: Some(vec!["https://example.com/cb2".to_string()]),
        }),
    )
    .await
    .expect("update handler ok");

    // DELETE
    let _ = delete_registered_client(
        make_tenant(tenant_id),
        State(state),
        make_admin_auth(&actor_pubkey),
        Path(created.id),
    )
    .await
    .expect("delete handler ok");

    let rows = read_audit_rows(&pool, tenant_id, &actor_pubkey).await;
    assert_eq!(rows.len(), 3, "create+update+delete each emit one row");

    let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(
        actions,
        vec![
            "registered_client.create",
            "registered_client.update",
            "registered_client.delete",
        ]
    );

    for row in &rows {
        assert_eq!(row.actor_pubkey, actor_pubkey);
        assert_eq!(row.target_resource_type, "registered_client");
        assert_eq!(
            row.target_resource_id.as_deref(),
            Some(created.id.to_string()).as_deref()
        );
        assert_eq!(row.target_client_id.as_deref(), Some(client_id.as_str()));
    }

    // Spot-check metadata payloads carry the state we expect.
    // create: flat snapshot of the just-created row.
    assert_eq!(rows[0].metadata_json["name"], "Audit HTTP");
    assert_eq!(
        rows[0].metadata_json["allowed_redirect_uris"][0],
        "https://example.com/cb"
    );

    // update: {before, after} captured atomically by the CTE in
    // RegisteredClientRepository::update. before holds the pre-update
    // snapshot; after holds the post-update snapshot.
    assert_eq!(rows[1].metadata_json["before"]["name"], "Audit HTTP");
    assert_eq!(
        rows[1].metadata_json["before"]["allowed_redirect_uris"][0],
        "https://example.com/cb"
    );
    assert_eq!(rows[1].metadata_json["after"]["name"], "Audit HTTP renamed");
    assert_eq!(
        rows[1].metadata_json["after"]["allowed_redirect_uris"][0],
        "https://example.com/cb2"
    );

    // delete: flat snapshot of the row at the moment of deletion.
    assert_eq!(rows[2].metadata_json["name"], "Audit HTTP renamed");
    assert_eq!(
        rows[2].metadata_json["allowed_redirect_uris"][0],
        "https://example.com/cb2"
    );

    cleanup(&pool, tenant_id, &client_id, &actor_pubkey).await;
}
