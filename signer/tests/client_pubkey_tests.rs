#![cfg(feature = "integration-tests")]

// NIP-46 Client Pubkey Tracking Tests
// Tests that the signer properly tracks client pubkeys after connect and validates subsequent requests
//
// TDD: These tests are written BEFORE the implementation. They should fail initially.

use keycast_core::bcrypt_admission::BcryptAdmission;
use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use keycast_core::repositories::OAuthAuthorizationRepository;
use keycast_core::signing_handler::SigningHandler;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use keycast_signer::Nip46Handler;
use nostr_sdk::nips::{nip04, nip44};
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// Helper to create test database with schema
async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database. Make sure PostgreSQL is running.");

    pool
}

/// Helper to create OAuth authorization for testing client pubkey tracking
async fn create_oauth_authorization_for_client_test(
    pool: &PgPool,
    tenant_id: i64,
    key_manager: &dyn KeyManager,
) -> (OAuthAuthorization, Keys, String) {
    // Generate user keys (used for both bunker and signing in OAuth)
    let user_keys = Keys::generate();

    // Generate unique secret for this test
    let unique_secret = format!("client_test_secret_{}", Uuid::new_v4());

    // Create user first
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(user_keys.public_key().to_hex())
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create user");

    // Encrypt user secret for personal_keys
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");

    // Create OAuth authorization
    // Hash the secret with bcrypt for storage (like production code does)
    let secret_hash = bcrypt::hash(&unique_secret, 4).expect("Failed to hash secret"); // Cost 4 for fast tests

    let redirect_origin = format!("https://test-{}.example.com", Uuid::new_v4());
    let oauth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, client_id, bunker_public_key, secret_hash, relays, tenant_id, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'Client Test App', $3, $4, $5, $6, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id"
    )
    .bind(user_keys.public_key().to_hex())
    .bind(&redirect_origin)
    .bind(user_keys.public_key().to_hex())
    .bind(&secret_hash)
    .bind(json!(["wss://relay.damus.io"]))
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create OAuth authorization");

    // Load OAuth authorization
    let oauth_auth = OAuthAuthorization::find(pool, tenant_id, oauth_id)
        .await
        .expect("Failed to load OAuth authorization");

    (oauth_auth, user_keys, unique_secret)
}

// ============================================================================
// TEST 1: Successful connect stores client pubkey in database
// ============================================================================
#[tokio::test]
async fn test_connect_stores_client_pubkey() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    // Create OAuth authorization
    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    // Create handler - use the hash from the authorization, keep plaintext secret for process_connect
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Simulate client connecting - client generates ephemeral keypair
    let client_keys = Keys::generate();
    let client_pubkey = client_keys.public_key().to_hex();

    // Process connect request (this method needs to be implemented)
    let result = handler.process_connect(&client_pubkey, &secret).await;
    assert!(result.is_ok(), "Connect should succeed with valid secret");
    assert_eq!(result.unwrap(), "ack", "Connect should return 'ack'");

    // Verify client pubkey was stored in database
    let stored_client: Option<String> = sqlx::query_scalar(
        "SELECT connected_client_pubkey FROM oauth_authorizations WHERE id = $1",
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");

    assert!(
        stored_client.is_some(),
        "connected_client_pubkey should be stored"
    );
    assert_eq!(
        stored_client.unwrap(),
        client_pubkey,
        "Stored client pubkey should match"
    );
}

// ============================================================================
// TEST 2: Second connect with same secret from different client is rejected
// ============================================================================
#[tokio::test]
async fn test_connect_rejects_reused_secret() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    // Create OAuth authorization
    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // First client connects successfully
    let client_a = Keys::generate();
    let result = handler
        .process_connect(&client_a.public_key().to_hex(), &secret)
        .await;
    assert!(result.is_ok(), "First connect should succeed");

    // Second client tries to use same secret
    let client_b = Keys::generate();
    let result = handler
        .process_connect(&client_b.public_key().to_hex(), &secret)
        .await;

    // Should be rejected - secret already used by client_a
    assert!(
        result.is_err(),
        "Second connect with same secret should fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("already used") || err_msg.contains("Secret"),
        "Error should indicate secret was already used, got: {}",
        err_msg
    );
}

// ============================================================================
// TEST 3: Same client reconnecting with same secret succeeds
// ============================================================================
#[tokio::test]
async fn test_same_client_can_reconnect() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();

    let result = handler.process_connect(&client_pubkey, &secret).await;
    assert!(result.is_ok(), "First connect should succeed");

    // Same client reconnects (e.g., after app restart)
    let result = handler.process_connect(&client_pubkey, &secret).await;
    assert!(result.is_ok(), "Reconnect from same client should succeed");
}

// ============================================================================
// TEST 4: Request from connected client succeeds
// ============================================================================
#[tokio::test]
async fn test_request_from_connected_client_succeeds() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects first
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();
    handler
        .process_connect(&client_pubkey, &secret)
        .await
        .expect("Connect should succeed");

    // Now client makes a sign request
    let unsigned = EventBuilder::text_note("Hello world").build(user_keys.public_key());

    // validate_client should pass for this client
    let validation = handler.validate_client(&client_pubkey).await;
    assert!(
        validation.is_ok(),
        "Request from connected client should be validated"
    );

    // Actually sign the event
    let result = handler.sign_event_direct(unsigned).await;
    assert!(result.is_ok(), "Sign should succeed from connected client");
}

// ============================================================================
// TEST 5: Request from unknown client is rejected
// ============================================================================
#[tokio::test]
async fn test_request_from_unknown_client_rejected() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client A connects
    let client_a = Keys::generate();
    handler
        .process_connect(&client_a.public_key().to_hex(), &secret)
        .await
        .expect("Connect should succeed");

    // Client B (never connected) tries to make a request
    let client_b = Keys::generate();
    let validation = handler
        .validate_client(&client_b.public_key().to_hex())
        .await;

    assert!(
        validation.is_err(),
        "Request from unknown client should be rejected"
    );
    let err_msg = validation.unwrap_err().to_string();
    assert!(
        err_msg.contains("Unknown client") || err_msg.contains("not connected"),
        "Error should indicate unknown client, got: {}",
        err_msg
    );
}

// ============================================================================
// Helpers for the relay reply path
// ============================================================================

/// Create a team authorization and return (id, bunker keys, team key, secret, secret hash).
async fn create_team_authorization_for_client_test(
    pool: &PgPool,
    tenant_id: i64,
    key_manager: &dyn KeyManager,
) -> (i32, Keys, Keys, String, String) {
    let team_id: i32 = sqlx::query_scalar(
        "INSERT INTO teams (name, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind("Client Test Team")
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create team");

    let bunker_keys = Keys::generate();
    let team_keys = Keys::generate();
    let encrypted_secret = key_manager
        .encrypt(&team_keys.secret_key().secret_bytes())
        .await
        .expect("Failed to encrypt team secret");

    let stored_key_id: i32 = sqlx::query_scalar(
        "INSERT INTO stored_keys (name, pubkey, secret_key, team_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("Client Test Key {}", Uuid::new_v4()))
    .bind(team_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(team_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create stored key");

    // A policy with no permissions allows every request.
    let policy_id: i32 = sqlx::query_scalar(
        "INSERT INTO policies (name, team_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("Client Test Policy {}", Uuid::new_v4()))
    .bind(team_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create policy");

    let secret = format!("team_client_test_secret_{}", Uuid::new_v4());
    let secret_hash = bcrypt::hash(&secret, 4).expect("Failed to hash secret");
    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO authorizations
         (stored_key_id, secret_hash, bunker_public_key, relays, policy_id, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
         RETURNING id",
    )
    .bind(stored_key_id)
    .bind(&secret_hash)
    .bind(bunker_keys.public_key().to_hex())
    .bind(json!(["wss://relay.damus.io"]).to_string())
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create team authorization");

    (auth_id, bunker_keys, team_keys, secret, secret_hash)
}

/// Read the client bound to an authorization row in `table`.
async fn stored_client(pool: &PgPool, table: &str, id: i32) -> Option<String> {
    sqlx::query_scalar(&format!(
        "SELECT connected_client_pubkey FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("Failed to query database")
}

/// Read the verified client of an OAuth authorization.
async fn verified_client(pool: &PgPool, id: i32) -> Option<String> {
    sqlx::query_scalar("SELECT verified_client_pubkey FROM oauth_authorizations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("Failed to query database")
}

/// One valid request for every NIP-46 request a client can send without the
/// secret, signed and encrypted with `key`, as (label, method, params). Each
/// succeeds once the client is bound.
fn requests_for_every_method(
    handler: &Nip46Handler,
    key: &Keys,
) -> Vec<(&'static str, &'static str, Value)> {
    let peer = Keys::generate();
    let peer_hex = peer.public_key().to_hex();
    let bunker_hex = handler.bunker_public_key().to_hex();
    let unsigned = EventBuilder::text_note("client binding test").build(key.public_key());
    let nip44_ciphertext = nip44::encrypt(
        peer.secret_key(),
        &key.public_key(),
        "to the key",
        nip44::Version::V2,
    )
    .expect("Failed to encrypt nip44 fixture");
    let nip04_ciphertext = nip04::encrypt(peer.secret_key(), &key.public_key(), "to the key")
        .expect("Failed to encrypt nip04 fixture");

    vec![
        ("get_public_key", "get_public_key", json!([])),
        (
            "sign_event",
            "sign_event",
            json!([serde_json::to_string(&unsigned).unwrap()]),
        ),
        (
            "nip44_encrypt",
            "nip44_encrypt",
            json!([peer_hex, "from the key"]),
        ),
        (
            "nip44_decrypt",
            "nip44_decrypt",
            json!([peer_hex, nip44_ciphertext]),
        ),
        (
            "nip04_encrypt",
            "nip04_encrypt",
            json!([peer_hex, "from the key"]),
        ),
        (
            "nip04_decrypt",
            "nip04_decrypt",
            json!([peer_hex, nip04_ciphertext]),
        ),
        ("connect without a secret", "connect", json!([bunker_hex])),
        (
            "connect with an empty secret",
            "connect",
            json!([bunker_hex, ""]),
        ),
    ]
}

/// Send one request from `client` through the relay reply path and return
/// the decrypted JSON-RPC response body.
async fn relay_request(
    handler: &Nip46Handler,
    client: &Keys,
    method: &str,
    params: Value,
) -> Value {
    let request_id = json!(format!("req-{method}"));
    let request = json!({ "id": request_id, "method": method, "params": params });
    let response = handler
        .build_nip46_response_event(
            method,
            &request,
            &request_id,
            &client.public_key().to_hex(),
            client.public_key(),
            EventId::all_zeros(),
            true,
        )
        .await
        .expect("every request must produce a response event");
    let content = nip44::decrypt(
        client.secret_key(),
        &handler.bunker_public_key(),
        &response.content,
    )
    .expect("client must be able to decrypt the response");
    serde_json::from_str(&content).expect("response must be valid JSON-RPC")
}

/// Send `connect` with `secret` from `client` through the relay reply path.
async fn relay_connect(handler: &Nip46Handler, client: &Keys, secret: Value) -> Value {
    let params = json!([handler.bunker_public_key().to_hex(), secret]);
    relay_request(handler, client, "connect", params).await
}

/// Assert that a response is an error containing `expected` and no result.
fn assert_refused(body: &Value, label: &str, expected: &str) {
    assert!(
        body.get("result").is_none(),
        "{label} must not return a result, got: {body}"
    );
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(expected),
        "{label} must be refused with {expected:?}, got: {body}"
    );
}

/// Check every request: refused for `refused` clients, answered for `bound`.
async fn assert_only_bound_client_is_served(
    handler: &Nip46Handler,
    key: &Keys,
    bound: Option<&Keys>,
    refused: &[&Keys],
) {
    for client in refused {
        for (label, method, params) in requests_for_every_method(handler, key) {
            let body = relay_request(handler, client, method, params).await;
            assert_refused(&body, label, "must connect first");
        }
    }

    if let Some(client) = bound {
        for (label, method, params) in requests_for_every_method(handler, key) {
            let body = relay_request(handler, client, method, params).await;
            assert!(
                body.get("error").is_none() && body.get("result").is_some(),
                "{label} from the bound client must succeed, got: {body}"
            );
            if method == "get_public_key" {
                assert_eq!(body["result"], key.public_key().to_hex());
            }
        }
    }
}

/// Walk an unbound authorization through binding: nothing is served before
/// `connect` with the secret, then only the bound client is served.
async fn assert_requests_require_connect(
    pool: &PgPool,
    handler: &Nip46Handler,
    key: &Keys,
    table: &str,
    id: i32,
    secret: &str,
) {
    let client = Keys::generate();
    let other_client = Keys::generate();

    assert_only_bound_client_is_served(handler, key, None, &[&client]).await;
    assert_eq!(
        stored_client(pool, table, id).await,
        None,
        "refused requests must not bind a client"
    );

    let body = relay_connect(handler, &client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "connect with the secret must bind, got: {body}"
    );
    assert_eq!(
        stored_client(pool, table, id).await,
        Some(client.public_key().to_hex())
    );
    if table == "oauth_authorizations" {
        assert_eq!(
            verified_client(pool, id).await,
            Some(client.public_key().to_hex()),
            "a connect with the secret records the verified client"
        );
    }

    assert_only_bound_client_is_served(handler, key, Some(&client), &[&other_client]).await;

    let body = relay_connect(handler, &other_client, json!(secret)).await;
    assert_refused(
        &body,
        "connect with the secret from another client",
        "Secret already used by another client",
    );
    let body = relay_connect(handler, &client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "the bound client may connect again, got: {body}"
    );
    assert_eq!(
        stored_client(pool, table, id).await,
        Some(client.public_key().to_hex())
    );
}

/// Run two connects with the secret while the authorization row is locked,
/// so both find it unbound before either can bind. Returns both results.
async fn race_two_connects(
    pool: &PgPool,
    handler: &Nip46Handler,
    table: &str,
    id: i32,
    secret: &str,
    clients: [&str; 2],
) -> [Result<String, String>; 2] {
    let mut lock = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query(&format!("SELECT id FROM {table} WHERE id = $1 FOR UPDATE"))
        .bind(id)
        .fetch_one(&mut *lock)
        .await
        .expect("Failed to lock the authorization row");

    let connects = clients.map(|client| {
        let handler = handler.clone();
        let client = client.to_string();
        let secret = secret.to_string();
        tokio::spawn(async move {
            handler
                .process_connect(&client, &secret)
                .await
                .map_err(|e| e.to_string())
        })
    });

    // Release the lock only once both binding UPDATEs are waiting on it.
    let binding_update = format!("UPDATE {table}%SET connected_client_pubkey%");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'
               AND query LIKE $1",
        )
        .bind(&binding_update)
        .fetch_one(pool)
        .await
        .expect("Failed to read pg_stat_activity");
        if waiting >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "both connects must reach the binding UPDATE"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    lock.commit().await.expect("Failed to release the row lock");

    let [first, second] = connects;
    [
        first.await.expect("connect task panicked"),
        second.await.expect("connect task panicked"),
    ]
}

/// Race two clients' connects and check exactly one is bound.
async fn assert_concurrent_connects_bind_one_client(
    pool: &PgPool,
    handler: &Nip46Handler,
    table: &str,
    id: i32,
    secret: &str,
) {
    let clients = [
        Keys::generate().public_key().to_hex(),
        Keys::generate().public_key().to_hex(),
    ];
    let [first, second] =
        race_two_connects(pool, handler, table, id, secret, [&clients[0], &clients[1]]).await;

    let (winner, loser_error) = match (&first, &second) {
        (Ok(_), Err(error)) => (&clients[0], error),
        (Err(error), Ok(_)) => (&clients[1], error),
        _ => panic!("exactly one concurrent connect may bind, got {first:?} and {second:?}"),
    };
    assert!(
        loser_error.contains("Secret already used by another client"),
        "the other connect must be refused as already used, got: {loser_error}"
    );
    assert_eq!(stored_client(pool, table, id).await, Some(winner.clone()));
}

/// Check that a bound client gets nothing once its authorization is inactive.
async fn assert_inactive_authorization_refuses_bound_client(
    handler: &Nip46Handler,
    key: &Keys,
    client: &Keys,
    secret: &str,
) {
    let unsigned = EventBuilder::text_note("inactive authorization").build(key.public_key());
    let body = relay_request(handler, client, "get_public_key", json!([])).await;
    assert_refused(&body, "get_public_key", "Authorization is no longer active");
    let body = relay_request(
        handler,
        client,
        "sign_event",
        json!([serde_json::to_string(&unsigned).unwrap()]),
    )
    .await;
    assert_refused(&body, "sign_event", "Authorization is no longer active");
    let body = relay_connect(handler, client, json!(secret)).await;
    assert_refused(
        &body,
        "connect with the secret",
        "Authorization is no longer active",
    );
}

// ============================================================================
// TEST 6: An unbound OAuth authorization serves no client until connect
// ============================================================================
#[tokio::test]
async fn test_oauth_requests_require_connect_with_secret() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    assert_requests_require_connect(
        &pool,
        &handler,
        &user_keys,
        "oauth_authorizations",
        oauth_auth.id,
        &secret,
    )
    .await;
}

// ============================================================================
// TEST 6b: An unbound team authorization serves no client until connect
// ============================================================================
#[tokio::test]
async fn test_team_requests_require_connect_with_secret() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (auth_id, bunker_keys, team_keys, secret, secret_hash) =
        create_team_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        bunker_keys,
        team_keys.clone(),
        secret_hash,
        auth_id,
        tenant_id,
        false,
        pool.clone(),
    );

    assert_requests_require_connect(
        &pool,
        &handler,
        &team_keys,
        "authorizations",
        auth_id,
        &secret,
    )
    .await;
}

// ============================================================================
// TEST 6c: A connect with a wrong or malformed secret binds nothing
// ============================================================================
#[tokio::test]
async fn test_connect_with_invalid_secret_binds_nothing() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );
    let client = Keys::generate();

    let body = relay_connect(&handler, &client, json!("not-the-secret")).await;
    assert_refused(&body, "connect with a wrong secret", "Invalid secret");
    for (label, secret_param) in [
        ("a null secret", json!(null)),
        ("a numeric secret", json!(7)),
    ] {
        let body = relay_connect(&handler, &client, secret_param).await;
        assert_refused(&body, label, "must connect first");
    }
    assert_eq!(
        stored_client(&pool, "oauth_authorizations", oauth_auth.id).await,
        None,
        "refused connects must not bind a client"
    );

    let body = relay_connect(&handler, &client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "the real secret must still bind, got: {body}"
    );
}

// ============================================================================
// TEST 6d: Concurrent connects with the secret bind exactly one client
// ============================================================================
#[tokio::test]
async fn test_concurrent_connects_bind_one_client() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;
    let bcrypt = || BcryptAdmission::new(2, Duration::from_secs(30));

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys,
        oauth_auth.secret_hash.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    )
    .with_bcrypt(bcrypt());
    assert_concurrent_connects_bind_one_client(
        &pool,
        &handler,
        "oauth_authorizations",
        oauth_auth.id,
        &secret,
    )
    .await;

    let (auth_id, bunker_keys, team_keys, secret, secret_hash) =
        create_team_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        bunker_keys,
        team_keys,
        secret_hash,
        auth_id,
        tenant_id,
        false,
        pool.clone(),
    )
    .with_bcrypt(bcrypt());
    assert_concurrent_connects_bind_one_client(&pool, &handler, "authorizations", auth_id, &secret)
        .await;

    // A binding that is not the verified client counts as none, so the race
    // is the same when the row starts with one.
    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    sqlx::query(
        "UPDATE oauth_authorizations SET connected_client_pubkey = $1, connected_at = NOW()
         WHERE id = $2",
    )
    .bind(Keys::generate().public_key().to_hex())
    .bind(oauth_auth.id)
    .execute(&pool)
    .await
    .expect("Failed to bind an unverified client");
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys,
        oauth_auth.secret_hash.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    )
    .with_bcrypt(bcrypt());
    assert_concurrent_connects_bind_one_client(
        &pool,
        &handler,
        "oauth_authorizations",
        oauth_auth.id,
        &secret,
    )
    .await;
}

// ============================================================================
// TEST 6e: A bound client is refused once its authorization is inactive
// ============================================================================
#[tokio::test]
async fn test_inactive_authorization_refuses_bound_client() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    // The handlers stay cached as active, as on an instance that has not seen
    // the change yet; only the database row says the authorization is over.
    for deactivate in [
        "UPDATE oauth_authorizations SET revoked_at = NOW() WHERE id = $1",
        "UPDATE oauth_authorizations SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    ] {
        let (oauth_auth, user_keys, secret) =
            create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
        let handler = Nip46Handler::new_for_test(
            user_keys.clone(),
            user_keys.clone(),
            oauth_auth.secret_hash.clone(),
            oauth_auth.id,
            tenant_id,
            true,
            pool.clone(),
        );
        let client = Keys::generate();
        let body = relay_connect(&handler, &client, json!(secret)).await;
        assert_eq!(
            body["result"], "ack",
            "connect with the secret must bind, got: {body}"
        );

        sqlx::query(deactivate)
            .bind(oauth_auth.id)
            .execute(&pool)
            .await
            .expect("Failed to deactivate authorization");
        assert_inactive_authorization_refuses_bound_client(&handler, &user_keys, &client, &secret)
            .await;
    }

    let (auth_id, bunker_keys, team_keys, secret, secret_hash) =
        create_team_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        bunker_keys,
        team_keys.clone(),
        secret_hash,
        auth_id,
        tenant_id,
        false,
        pool.clone(),
    );
    let client = Keys::generate();
    let body = relay_connect(&handler, &client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "connect with the secret must bind, got: {body}"
    );

    sqlx::query("UPDATE authorizations SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1")
        .bind(auth_id)
        .execute(&pool)
        .await
        .expect("Failed to expire team authorization");
    assert_inactive_authorization_refuses_bound_client(&handler, &team_keys, &client, &secret)
        .await;
}

// ============================================================================
// TEST 6f: After a disconnect, a client must connect with the secret again
// ============================================================================
#[tokio::test]
async fn test_disconnect_requires_connect_with_secret_again() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );
    let first_client = Keys::generate();
    let second_client = Keys::generate();

    let body = relay_connect(&handler, &first_client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "connect with the secret must bind, got: {body}"
    );

    let disconnected = OAuthAuthorizationRepository::new(pool.clone())
        .disconnect_client(
            &oauth_auth.bunker_public_key,
            &oauth_auth.user_pubkey,
            tenant_id,
        )
        .await
        .expect("Failed to disconnect client");
    assert_eq!(disconnected, 1);
    assert_eq!(verified_client(&pool, oauth_auth.id).await, None);

    assert_only_bound_client_is_served(&handler, &user_keys, None, &[&first_client]).await;

    let body = relay_connect(&handler, &second_client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "connect with the secret must bind, got: {body}"
    );
    assert_only_bound_client_is_served(
        &handler,
        &user_keys,
        Some(&second_client),
        &[&first_client],
    )
    .await;
}

// ============================================================================
// TEST 6g: Only the approved client can bind a nostr-login authorization
// ============================================================================
#[tokio::test]
async fn test_only_approved_client_can_bind() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(),
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );
    let approved_client = Keys::generate();
    let other_client = Keys::generate();

    // Bound at creation to the approved client. Rows stored before the key
    // was normalized can hold it in uppercase.
    sqlx::query(
        "UPDATE oauth_authorizations
         SET client_pubkey = $1, connected_client_pubkey = $2, verified_client_pubkey = $2
         WHERE id = $3",
    )
    .bind(approved_client.public_key().to_hex().to_uppercase())
    .bind(approved_client.public_key().to_hex())
    .bind(oauth_auth.id)
    .execute(&pool)
    .await
    .expect("Failed to set the approved client");
    assert_only_bound_client_is_served(
        &handler,
        &user_keys,
        Some(&approved_client),
        &[&other_client],
    )
    .await;

    OAuthAuthorizationRepository::new(pool.clone())
        .disconnect_client(
            &oauth_auth.bunker_public_key,
            &oauth_auth.user_pubkey,
            tenant_id,
        )
        .await
        .expect("Failed to disconnect client");

    let body = relay_connect(&handler, &other_client, json!(secret)).await;
    assert_refused(
        &body,
        "connect with the secret from another client",
        "Client not approved for this authorization",
    );
    assert_eq!(
        stored_client(&pool, "oauth_authorizations", oauth_auth.id).await,
        None
    );

    let body = relay_connect(&handler, &approved_client, json!(secret)).await;
    assert_eq!(
        body["result"], "ack",
        "the approved client may bind, got: {body}"
    );
    assert_only_bound_client_is_served(
        &handler,
        &user_keys,
        Some(&approved_client),
        &[&other_client],
    )
    .await;
}

// ============================================================================
// TEST 6h: A binding that is not the verified client is not served
// ============================================================================
#[tokio::test]
async fn test_unverified_binding_is_not_served() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    // A binding with no verified client, and one that replaced the verified
    // client without going through a connect with the secret.
    for verified in [None, Some(Keys::generate().public_key().to_hex())] {
        let (oauth_auth, user_keys, secret) =
            create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;
        let handler = Nip46Handler::new_for_test(
            user_keys.clone(),
            user_keys.clone(),
            oauth_auth.secret_hash.clone(),
            oauth_auth.id,
            tenant_id,
            true,
            pool.clone(),
        );
        let stored_client_keys = Keys::generate();
        let app = Keys::generate();

        sqlx::query(
            "UPDATE oauth_authorizations
             SET connected_client_pubkey = $1, verified_client_pubkey = $2, connected_at = NOW()
             WHERE id = $3",
        )
        .bind(stored_client_keys.public_key().to_hex())
        .bind(verified.as_deref())
        .bind(oauth_auth.id)
        .execute(&pool)
        .await
        .expect("Failed to store an unverified binding");

        assert_only_bound_client_is_served(&handler, &user_keys, None, &[&stored_client_keys])
            .await;

        let body = relay_connect(&handler, &app, json!(secret)).await;
        assert_eq!(
            body["result"], "ack",
            "connect with the secret must bind, got: {body}"
        );
        assert_eq!(
            verified_client(&pool, oauth_auth.id).await,
            Some(app.public_key().to_hex())
        );
        assert_only_bound_client_is_served(
            &handler,
            &user_keys,
            Some(&app),
            &[&stored_client_keys],
        )
        .await;
    }
}

// ============================================================================
// TEST 7: Revocation clears client pubkey
// ============================================================================
#[tokio::test]
async fn test_revocation_clears_client_pubkey() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects
    let client = Keys::generate();
    let client_pubkey = client.public_key().to_hex();
    handler
        .process_connect(&client_pubkey, &secret)
        .await
        .expect("Connect should succeed");

    // Verify client is stored
    let stored_client: Option<String> = sqlx::query_scalar(
        "SELECT connected_client_pubkey FROM oauth_authorizations WHERE id = $1",
    )
    .bind(oauth_auth.id)
    .fetch_one(&pool)
    .await
    .expect("Failed to query database");
    assert!(stored_client.is_some(), "Client should be stored");

    // Simulate revocation (directly update DB - API would call this)
    sqlx::query(
        "UPDATE oauth_authorizations SET connected_client_pubkey = NULL, connected_at = NULL WHERE id = $1"
    )
    .bind(oauth_auth.id)
    .execute(&pool)
    .await
    .expect("Failed to revoke");

    // Request from previously-connected client should now fail
    let validation = handler.validate_client(&client_pubkey).await;

    // After revocation, client must reconnect
    let err_msg = validation
        .expect_err("Request after revocation should require reconnect")
        .to_string();
    assert!(
        err_msg.contains("must connect first"),
        "Error should ask the client to connect, got: {}",
        err_msg
    );

    // Binding the same client again without the secret, as code that predates
    // verified_client_pubkey binds, is not trusted either.
    sqlx::query("UPDATE oauth_authorizations SET connected_client_pubkey = $1 WHERE id = $2")
        .bind(&client_pubkey)
        .bind(oauth_auth.id)
        .execute(&pool)
        .await
        .expect("Failed to rebind");
    let err_msg = handler
        .validate_client(&client_pubkey)
        .await
        .expect_err("A binding made without the secret must not be trusted")
        .to_string();
    assert!(
        err_msg.contains("must connect first"),
        "Error should ask the client to connect, got: {}",
        err_msg
    );
}

// ============================================================================
// TEST 8: connected_at timestamp is set on connect
// ============================================================================
#[tokio::test]
async fn test_connected_at_timestamp_set() {
    let pool = setup_test_db().await;
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");
    let tenant_id = 1;

    let (oauth_auth, user_keys, secret) =
        create_oauth_authorization_for_client_test(&pool, tenant_id, &key_manager).await;

    let handler = Nip46Handler::new_for_test(
        user_keys.clone(),
        user_keys.clone(),
        oauth_auth.secret_hash.clone(), // Handler needs the hash for verification
        oauth_auth.id,
        tenant_id,
        true,
        pool.clone(),
    );

    // Client connects
    let client = Keys::generate();
    handler
        .process_connect(&client.public_key().to_hex(), &secret)
        .await
        .expect("Connect should succeed");

    // Verify connected_at is set
    let connected_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT connected_at FROM oauth_authorizations WHERE id = $1")
            .bind(oauth_auth.id)
            .fetch_one(&pool)
            .await
            .expect("Failed to query database");

    assert!(
        connected_at.is_some(),
        "connected_at should be set after connect"
    );
}
