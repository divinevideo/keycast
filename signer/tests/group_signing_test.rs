#![cfg(feature = "integration-tests")]

use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use keycast_core::signing_handler::SigningHandler;
use keycast_signer::Nip46Handler;
use nostr_relay_builder::prelude::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

struct GroupFixture {
    pool: PgPool,
    group_id: i32,
    stored_key_id: i32,
    policy_id: i32,
    keys: Keys,
}

struct Device {
    handler: Nip46Handler,
    client: Keys,
    admin: String,
    authorization_id: i32,
}

impl GroupFixture {
    async fn new() -> Self {
        // A single connection also catches nested acquisition in post-sign auditing.
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL is required"))
            .await
            .unwrap();
        let group_id: i32 = sqlx::query_scalar("INSERT INTO teams (name, tenant_id) VALUES ('Synthetic signing group', 1) RETURNING id")
            .fetch_one(&pool).await.unwrap();
        let keys = Keys::generate();
        let encrypted_key = FileKeyManager::new()
            .unwrap()
            .encrypt(keys.secret_key().as_secret_bytes())
            .await
            .unwrap();
        let stored_key_id: i32 = sqlx::query_scalar("INSERT INTO stored_keys (name, pubkey, secret_key, team_id, tenant_id) VALUES ('Synthetic group key', $1, $2, $3, 1) RETURNING id")
            .bind(keys.public_key().to_hex()).bind(encrypted_key).bind(group_id)
            .fetch_one(&pool).await.unwrap();
        let policy_id: i32 = sqlx::query_scalar("INSERT INTO policies (name, team_id) VALUES ('Synthetic signing policy', $1) RETURNING id")
            .bind(group_id).fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO identity_groups (id, tenant_id, name, pubkey, signing_key_id, policy_id, mode, creator_pubkey, request_id) VALUES ($1, 1, 'Synthetic signing group', $2, $3, $4, 'hosted', $5, $6)")
            .bind(group_id).bind(keys.public_key().to_hex()).bind(stored_key_id).bind(policy_id)
            .bind(Keys::generate().public_key().to_hex()).bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();
        Self {
            pool,
            group_id,
            stored_key_id,
            policy_id,
            keys,
        }
    }

    async fn device(&self, existing_admin: Option<&str>) -> Device {
        let admin = existing_admin
            .map(str::to_owned)
            .unwrap_or_else(|| Keys::generate().public_key().to_hex());
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id) VALUES ($1, 1) ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(&admin)
        .execute(&self.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO group_memberships (tenant_id, group_id, admin_pubkey, status) VALUES (1, $1, $2, 'active') ON CONFLICT DO NOTHING")
            .bind(self.group_id).bind(&admin).execute(&self.pool).await.unwrap();
        let client = Keys::generate();
        let bunker = Keys::generate();
        let secret_hash = bcrypt::hash("synthetic-group-secret", 4).unwrap();
        let authorization_id: i32 = sqlx::query_scalar("INSERT INTO authorizations (stored_key_id, secret_hash, bunker_public_key, relays, policy_id, tenant_id, connected_client_pubkey) VALUES ($1, $2, $3, '[]', $4, 1, $5) RETURNING id")
            .bind(self.stored_key_id).bind(&secret_hash).bind(bunker.public_key().to_hex()).bind(self.policy_id).bind(client.public_key().to_hex())
            .fetch_one(&self.pool).await.unwrap();
        sqlx::query("INSERT INTO group_grants (authorization_id, tenant_id, group_id, admin_pubkey, membership_version, key_version, installation_epoch) SELECT $1, 1, $2, $3, version, 1, installation_epoch FROM group_memberships WHERE tenant_id = 1 AND group_id = $2 AND admin_pubkey = $3")
            .bind(authorization_id).bind(self.group_id).bind(&admin).execute(&self.pool).await.unwrap();
        let handler = Nip46Handler::new_for_test(
            bunker,
            self.keys.clone(),
            secret_hash,
            authorization_id,
            1,
            false,
            self.pool.clone(),
        );
        Device {
            handler,
            client,
            admin,
            authorization_id,
        }
    }

    fn unsigned(&self) -> UnsignedEvent {
        UnsignedEvent::new(
            self.keys.public_key(),
            Timestamp::now(),
            Kind::TextNote,
            [],
            format!("Synthetic group content {}", uuid::Uuid::new_v4()),
        )
    }
}

async fn request(device: &Device, method: &str, params: Value) -> Value {
    let id = json!(uuid::Uuid::new_v4().to_string());
    let request = json!({"id":id, "method": method, "params":params});
    let response = device
        .handler
        .build_nip46_response_event(
            method,
            &request,
            &id,
            &device.client.public_key().to_hex(),
            device.client.public_key(),
            EventId::all_zeros(),
            true,
        )
        .await
        .unwrap();
    let plaintext = nip44::decrypt(
        device.client.secret_key(),
        &device.handler.bunker_public_key(),
        response.content,
    )
    .unwrap();
    serde_json::from_str(&plaintext).unwrap()
}

fn verify_bip340(event: &Event) {
    // Verify the actual BIP-340 signature over the NIP-01 event digest independently
    // of the handler and SDK Event::verify convenience method.
    let digest = EventId::new(
        &event.pubkey,
        &event.created_at,
        &event.kind,
        &event.tags,
        &event.content,
    );
    assert_eq!(digest, event.id);
    let message = nostr::secp256k1::Message::from_digest(event.id.to_bytes());
    nostr::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&event.sig, &message, &event.pubkey.xonly().unwrap())
        .unwrap();
}

#[tokio::test]
async fn three_admins_sign_independently_and_relay_round_trip() {
    let group = GroupFixture::new().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let publisher = Client::new(Keys::generate());
    publisher.add_relay(relay.url().await).await.unwrap();
    let connected = publisher.try_connect(Duration::from_secs(5)).await;
    assert_eq!(
        connected.success.len(),
        1,
        "publisher must connect to the local relay"
    );
    let reader = Client::new(Keys::generate());
    reader.add_relay(relay.url().await).await.unwrap();
    let connected = reader.try_connect(Duration::from_secs(5)).await;
    assert_eq!(
        connected.success.len(),
        1,
        "reader must connect to the local relay"
    );
    for _ in 0..3 {
        let device = group.device(None).await;
        let connected = request(
            &device,
            "connect",
            json!([
                device.handler.bunker_public_key().to_hex(),
                "synthetic-group-secret"
            ]),
        )
        .await;
        assert_eq!(connected["result"], "ack");
        assert_eq!(
            request(&device, "get_public_key", json!([])).await["result"],
            group.keys.public_key().to_hex()
        );
        let response = request(
            &device,
            "sign_event",
            json!([serde_json::to_string(&group.unsigned()).unwrap()]),
        )
        .await;
        let event = Event::from_json(response["result"].as_str().unwrap()).unwrap();
        assert_eq!(event.pubkey, group.keys.public_key());
        assert!(
            event.tags.is_empty(),
            "admins must never become content members"
        );
        verify_bip340(&event);
        let published = publisher.send_event(&event).await.unwrap();
        assert_eq!(
            published.success.len(),
            1,
            "relay must acknowledge the event"
        );
        let readback = reader
            .fetch_events(Filter::new().id(event.id), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(readback.iter().any(|stored| stored == &event));
        let audit: (String, String, String) = sqlx::query_as("SELECT admin_pubkey, event_id, session_id FROM group_audit WHERE tenant_id = 1 AND group_id = $1 AND action = 'sign_event' AND session_id = $2")
            .bind(group.group_id).bind(device.authorization_id.to_string()).fetch_one(&group.pool).await.unwrap();
        assert_eq!(
            audit,
            (
                device.admin,
                event.id.to_hex(),
                device.authorization_id.to_string()
            )
        );
    }
    publisher.disconnect().await;
    reader.disconnect().await;
    relay.shutdown();
}

#[tokio::test]
async fn group_grants_preserve_each_acting_accounts_communication_policy() {
    let group = GroupFixture::new().await;
    let protected = group.device(None).await;
    let other = group.device(None).await;
    sqlx::query("UPDATE users SET verified_minor = TRUE WHERE tenant_id = 1 AND pubkey = $1")
        .bind(&protected.admin)
        .execute(&group.pool)
        .await
        .unwrap();
    let recipient = Keys::generate().public_key();
    let dm = UnsignedEvent::new(
        group.keys.public_key(),
        Timestamp::now(),
        Kind::from(4),
        [Tag::public_key(recipient)],
        "Synthetic communication policy fixture",
    );
    assert!(protected
        .handler
        .sign_event_direct(dm.clone())
        .await
        .is_err());
    let response = request(
        &protected,
        "sign_event",
        json!([serde_json::to_string(&dm).unwrap()]),
    )
    .await;
    assert!(response["error"].is_string());
    assert!(protected
        .handler
        .validate_permissions_for_encrypt("Synthetic fixture", &recipient)
        .await
        .is_err());
    protected
        .handler
        .validate_permissions_for_encrypt("Synthetic fixture", &group.keys.public_key())
        .await
        .unwrap();
    protected
        .handler
        .sign_event_direct(group.unsigned())
        .await
        .unwrap();
    other.handler.sign_event_direct(dm.clone()).await.unwrap();
    other
        .handler
        .validate_permissions_for_encrypt("Synthetic fixture", &recipient)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET verified_minor = FALSE WHERE tenant_id = 1 AND pubkey = $1")
        .bind(&protected.admin)
        .execute(&group.pool)
        .await
        .unwrap();
    protected.handler.sign_event_direct(dm).await.unwrap();
}

#[tokio::test]
async fn cached_handlers_refuse_removed_admin_and_obsolete_devices() {
    let group = GroupFixture::new().await;
    let old = group.device(None).await;
    let other_instance = old.handler.clone();
    old.handler
        .sign_event_direct(group.unsigned())
        .await
        .unwrap();
    sqlx::query("UPDATE group_memberships SET status = 'removed', version = version + 1 WHERE tenant_id = 1 AND group_id = $1 AND admin_pubkey = $2")
        .bind(group.group_id).bind(&old.admin).execute(&group.pool).await.unwrap();
    assert!(other_instance
        .sign_event_direct(group.unsigned())
        .await
        .is_err());
    assert!(old
        .handler
        .process_connect(&old.client.public_key().to_hex(), "synthetic-group-secret")
        .await
        .is_err());
    for method in ["get_public_key", "connect"] {
        assert!(request(&old, method, json!([])).await["error"].is_string());
    }
    let signing = request(
        &old,
        "sign_event",
        json!([serde_json::to_string(&group.unsigned()).unwrap()]),
    )
    .await;
    assert!(signing["error"].is_string());
    sqlx::query("UPDATE group_memberships SET status = 'active', version = version + 1, installation_epoch = installation_epoch + 1 WHERE tenant_id = 1 AND group_id = $1 AND admin_pubkey = $2")
        .bind(group.group_id).bind(&old.admin).execute(&group.pool).await.unwrap();
    assert!(old
        .handler
        .sign_event_direct(group.unsigned())
        .await
        .is_err());
    let replacement = group.device(Some(&old.admin)).await;
    let event = replacement
        .handler
        .sign_event_direct(group.unsigned())
        .await
        .unwrap();
    assert_eq!(event.pubkey, group.keys.public_key());
    verify_bip340(&event);
    assert!(old
        .handler
        .sign_event_direct(group.unsigned())
        .await
        .is_err());
}

#[tokio::test]
async fn missing_revoked_or_stale_grants_never_fall_back_to_team_signing() {
    let group = GroupFixture::new().await;
    for alteration in [
        "DELETE FROM group_grants WHERE authorization_id = $1",
        "UPDATE group_grants SET revoked_at = NOW() WHERE authorization_id = $1",
        "UPDATE group_grants SET key_version = key_version + 1 WHERE authorization_id = $1",
        "UPDATE group_grants SET membership_version = membership_version + 1 WHERE authorization_id = $1",
        "UPDATE group_grants SET installation_epoch = installation_epoch + 1 WHERE authorization_id = $1",
    ] {
        let device = group.device(None).await;
        sqlx::query(alteration).bind(device.authorization_id).execute(&group.pool).await.unwrap();
        assert!(device.handler.sign_event_direct(group.unsigned()).await.is_err(), "{alteration}");
        assert!(device.handler.validate_client(&device.client.public_key().to_hex()).await.is_err(), "{alteration}");
    }
    let device = group.device(None).await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE pubkey = $1")
        .bind(&device.admin)
        .execute(&group.pool)
        .await
        .unwrap();
    assert!(device
        .handler
        .sign_event_direct(group.unsigned())
        .await
        .is_err());
    let device = group.device(None).await;
    sqlx::query(
        "UPDATE identity_groups SET pubkey = $1, key_version = key_version + 1 WHERE id = $2",
    )
    .bind(Keys::generate().public_key().to_hex())
    .bind(group.group_id)
    .execute(&group.pool)
    .await
    .unwrap();
    assert!(device
        .handler
        .sign_event_direct(group.unsigned())
        .await
        .is_err());
}

#[tokio::test]
async fn removal_committed_while_signing_refuses_result_before_audit() {
    let group = GroupFixture::new().await;
    let device = group.device(None).await;
    let signer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&group.pool)
        .await
        .unwrap();
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut removal = control.begin().await.unwrap();
    sqlx::query("SELECT id FROM identity_groups WHERE id = $1 FOR UPDATE")
        .bind(group.group_id)
        .fetch_one(&mut *removal)
        .await
        .unwrap();
    let handler = device.handler.clone();
    let unsigned = group.unsigned();
    let signing = tokio::spawn(async move { handler.sign_event_direct(unsigned).await });
    // The post-sign audit waits on our group lock. No sleep-based guess about
    // whether the cryptography has completed or the final check has run.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted)",
            )
            .bind(signer_pid)
            .fetch_one(&mut *removal)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("signing must reach its final durable validation");
    sqlx::query("UPDATE group_memberships SET status = 'removed', version = version + 1 WHERE tenant_id = 1 AND group_id = $1 AND admin_pubkey = $2")
        .bind(group.group_id)
        .bind(&device.admin)
        .execute(&mut *removal)
        .await
        .unwrap();
    removal.commit().await.unwrap();
    assert!(signing.await.unwrap().is_err());
    let released: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_audit WHERE group_id = $1 AND action = 'sign_event'",
    )
    .bind(group.group_id)
    .fetch_one(&group.pool)
    .await
    .unwrap();
    assert_eq!(released, 0);
}

#[tokio::test]
async fn audit_storage_failure_refuses_both_signing_paths() {
    let group = GroupFixture::new().await;
    let device = group.device(None).await;
    let function = format!("synthetic_group_audit_failure_{}", group.group_id);
    let trigger = format!("synthetic_group_audit_failure_{}", group.group_id);
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $function$
         BEGIN
           IF NEW.group_id = {} AND NEW.action = 'sign_event' THEN
             RAISE EXCEPTION 'Synthetic audit storage failure';
           END IF;
           RETURN NEW;
         END;
         $function$;
         CREATE TRIGGER {trigger} BEFORE INSERT ON group_audit FOR EACH ROW EXECUTE FUNCTION {function}();",
        group.group_id
    ))
    .execute(&group.pool)
    .await
    .unwrap();
    let direct = device.handler.sign_event_direct(group.unsigned()).await;
    let request_id = json!("synthetic-audit-failure");
    let request = json!({"id":request_id,"method":"sign_event","params":[serde_json::to_string(&group.unsigned()).unwrap()]});
    let nip46 = device
        .handler
        .build_nip46_response_event(
            "sign_event",
            &request,
            &request_id,
            &device.client.public_key().to_hex(),
            device.client.public_key(),
            EventId::all_zeros(),
            true,
        )
        .await;
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {trigger} ON group_audit; DROP FUNCTION {function}();"
    ))
    .execute(&group.pool)
    .await
    .unwrap();
    assert!(
        direct.is_err(),
        "an unaudited signature must never be returned"
    );
    assert!(
        nip46.is_err(),
        "an unaudited signature must never be encrypted into a response"
    );
    let released: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_audit WHERE group_id = $1 AND action = 'sign_event'",
    )
    .bind(group.group_id)
    .fetch_one(&group.pool)
    .await
    .unwrap();
    assert_eq!(released, 0);
}
