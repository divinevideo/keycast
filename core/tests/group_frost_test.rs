#![cfg(feature = "integration-tests")]
#[path = "common/frost_fixture.rs"]
mod frost_fixture;
use frost_fixture::{backup_all, completed_dkg, FrostFixture};
use keycast_core::groups::frost::{
    client::DkgRound1, group_pubkey, DkgMessage, DkgPayload, FrostCoordinator, Session,
    SigningMessage, SigningState, MESSAGE_KIND,
};
use nostr::{EventBuilder, Kind, Timestamp, UnsignedEvent};
use nostr_relay_builder::prelude::{LocalRelay, RelayBuilder};
use nostr_sdk::{Client, Filter};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

fn event(f: &FrostFixture) -> UnsignedEvent {
    UnsignedEvent::new(
        group_pubkey(f.dkg.public_package.as_ref().unwrap()).unwrap(),
        Timestamp::from(1_800_000_000),
        Kind::TextNote,
        [],
        "Synthetic threshold content",
    )
}
async fn proposal(pool: &PgPool, f: &FrostFixture, indices: &[usize]) -> SigningState {
    let ids = indices
        .iter()
        .map(|i| {
            f.dkg
                .roster
                .iter()
                .find(|m| m.admin_pubkey == f.keys[*i].public_key().to_hex())
                .unwrap()
                .participant_id
        })
        .collect();
    let mut unsigned = event(f);
    // Each subset publishes a distinct event; relays deduplicate by event ID,
    // while different valid threshold signatures over identical bytes share it.
    unsigned.content.push_str(&uuid::Uuid::new_v4().to_string());
    FrostCoordinator::new(pool.clone())
        .create_signing(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &uuid::Uuid::new_v4().to_string(),
            &f.dkg.binding.session_id,
            unsigned,
            ids,
        )
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../database/migrations")]
#[serial_test::serial(frost_coordinator)]
async fn real_dkg_all_two_of_three_subsets_and_nostr_verification(pool: PgPool) {
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let f = completed_dkg(&single).await;
    backup_all(&single, &f).await;
    let coordinator = FrostCoordinator::new(single.clone());
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let publisher = Client::new(nostr::Keys::generate());
    publisher.add_relay(relay.url().await).await.unwrap();
    assert_eq!(
        publisher
            .try_connect(Duration::from_secs(5))
            .await
            .success
            .len(),
        1
    );
    let reader = Client::new(nostr::Keys::generate());
    reader.add_relay(relay.url().await).await.unwrap();
    assert_eq!(
        reader
            .try_connect(Duration::from_secs(5))
            .await
            .success
            .len(),
        1
    );
    for (iteration, subset) in [[0, 1], [0, 2], [1, 2], [0, 1]].into_iter().enumerate() {
        if iteration == 3 {
            sqlx::query("UPDATE group_memberships SET status='removed',version=version+1 WHERE tenant_id=1 AND group_id=$1 AND admin_pubkey=$2")
                .bind(f.group).bind(f.keys[2].public_key().to_hex()).execute(&single).await.unwrap();
            assert!(coordinator
                .get(
                    1,
                    f.group,
                    &f.keys[2].public_key().to_hex(),
                    &f.dkg.binding.session_id
                )
                .await
                .is_err());
            sqlx::query("UPDATE group_frost_sessions SET expires_at=now()-interval '1 hour' WHERE tenant_id=1 AND group_id=$1 AND id=$2")
                .bind(f.group).bind(&f.dkg.binding.session_id).execute(&single).await.unwrap();
            let duplicate = f
                .dkg
                .round1
                .values()
                .find(|e| e.pubkey == f.keys[0].public_key())
                .unwrap()
                .clone();
            let complete = coordinator
                .dkg_message(
                    1,
                    f.group,
                    &f.keys[0].public_key().to_hex(),
                    &f.dkg.binding.session_id,
                    duplicate,
                )
                .await
                .unwrap();
            assert!(!complete.aborted);
            assert!(complete.public_package.is_some());
            let conflict = DkgPayload {
                binding: f.dkg.binding.clone(),
                message: DkgMessage::Agreement {
                    transcript: "0".repeat(64),
                },
            };
            let late = EventBuilder::new(
                Kind::Custom(MESSAGE_KIND),
                serde_json::to_string(&conflict).unwrap(),
            )
            .sign_with_keys(&f.keys[0])
            .unwrap();
            assert!(coordinator
                .dkg_message(
                    1,
                    f.group,
                    &f.keys[0].public_key().to_hex(),
                    &f.dkg.binding.session_id,
                    late
                )
                .await
                .is_err());
        }
        let mut state = proposal(&single, &f, &subset).await;
        let mut approvals = Vec::new();
        for i in subset {
            let (approval, commitment) = f.participants[i].approve(&state, &f.dkg).unwrap();
            let message = SigningMessage::Commitment {
                proposal_digest: state.proposal_digest().unwrap(),
                commitment,
            };
            let admin = f.keys[i].public_key().to_hex();
            state = coordinator
                .signing_message(
                    1,
                    f.group,
                    &admin,
                    &state.binding.session_id,
                    message.clone(),
                )
                .await
                .unwrap();
            // Lost HTTP responses may safely resend the public commitment.
            state = coordinator
                .signing_message(1, f.group, &admin, &state.binding.session_id, message)
                .await
                .unwrap();
            approvals.push((i, approval));
        }
        for (i, approval) in approvals {
            let partial = approval.sign(&f.participants[i], &state).unwrap();
            let message = SigningMessage::Partial {
                proposal_digest: state.proposal_digest().unwrap(),
                partial,
            };
            state = coordinator
                .signing_message(
                    1,
                    f.group,
                    &f.keys[i].public_key().to_hex(),
                    &state.binding.session_id,
                    message.clone(),
                )
                .await
                .unwrap();
            state = coordinator
                .signing_message(
                    1,
                    f.group,
                    &f.keys[i].public_key().to_hex(),
                    &state.binding.session_id,
                    message,
                )
                .await
                .unwrap();
        }
        let signed = state.result.clone().unwrap();
        signed.verify().unwrap();
        let published = publisher.send_event(&signed).await.unwrap();
        assert_eq!(published.success.len(), 1);
        let received = reader
            .fetch_events(Filter::new().id(signed.id), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(received.iter().any(|event| event == &signed));
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM group_audit WHERE group_id=$1 AND session_id=$2 AND action='frost_sign_event' AND event_id=$3")
            .bind(f.group).bind(&state.binding.session_id).bind(signed.id.to_hex()).fetch_one(&single).await.unwrap();
        assert_eq!(audits, 1);
        // Final public results remain immutable and idempotent after timeout.
        sqlx::query("UPDATE group_frost_sessions SET expires_at=now()-interval '1 hour' WHERE tenant_id=1 AND group_id=$1 AND id=$2")
            .bind(f.group).bind(&state.binding.session_id).execute(&single).await.unwrap();
        let actor = &f.keys[subset[0]].public_key().to_hex();
        let participant = state
            .signers
            .iter()
            .find(|m| &m.admin_pubkey == actor)
            .unwrap()
            .participant_id;
        let partial = state.partials[&participant];
        let replay = SigningMessage::Partial {
            proposal_digest: state.proposal_digest().unwrap(),
            partial,
        };
        let completed = coordinator
            .signing_message(1, f.group, actor, &state.binding.session_id, replay)
            .await
            .unwrap();
        assert_eq!(completed.result.as_ref(), Some(&signed));
        assert!(!completed.aborted);
        assert!(coordinator
            .signing_message(
                1,
                f.group,
                actor,
                &state.binding.session_id,
                SigningMessage::Partial {
                    proposal_digest: "0".repeat(64),
                    partial
                }
            )
            .await
            .is_err());
        assert!(coordinator
            .abort(1, f.group, actor, &state.binding.session_id)
            .await
            .is_err());
        let restored = coordinator
            .create_signing(
                1,
                f.group,
                actor,
                &state.binding.session_id,
                &state.dkg_session_id,
                state.event.clone(),
                state.signers.iter().map(|m| m.participant_id).collect(),
            )
            .await
            .unwrap();
        assert_eq!(restored.result.as_ref(), Some(&signed));
        let Session::Signing(unchanged) = coordinator
            .get(1, f.group, actor, &state.binding.session_id)
            .await
            .unwrap()
        else {
            panic!("signing result");
        };
        assert_eq!(unchanged.result.as_ref(), Some(&signed));
        assert!(!unchanged.aborted);
        assert_eq!(signed.pubkey, event(&f).pubkey);
        assert_eq!(signed.id, state.event_id);
        let mut damaged = signed.clone();
        damaged.content.push('!');
        assert!(damaged.verify().is_err());
    }
    publisher.disconnect().await;
    reader.disconnect().await;
    relay.shutdown();
}

#[sqlx::test(migrations = "../database/migrations")]
#[serial_test::serial(frost_coordinator)]
async fn commitment_reuse_changed_approval_and_recovery_abort(pool: PgPool) {
    let f = completed_dkg(&pool).await;
    backup_all(&pool, &f).await;
    let coordinator = FrostCoordinator::new(pool.clone());
    let mut first = proposal(&pool, &f, &[0, 1]).await;
    let (approval, commitment) = f.participants[0].approve(&first, &f.dkg).unwrap();
    first = coordinator
        .signing_message(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &first.binding.session_id,
            SigningMessage::Commitment {
                proposal_digest: first.proposal_digest().unwrap(),
                commitment,
            },
        )
        .await
        .unwrap();
    let second = proposal(&pool, &f, &[0, 1]).await;
    let message = SigningMessage::Commitment {
        proposal_digest: second.proposal_digest().unwrap(),
        commitment,
    };
    // A different worker cannot reuse the reservation after an aborted session.
    coordinator
        .abort(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &first.binding.session_id,
        )
        .await
        .unwrap();
    assert!(FrostCoordinator::new(pool.clone())
        .signing_message(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &second.binding.session_id,
            message
        )
        .await
        .is_err());
    let mut altered = first.clone();
    altered.event.content.push('!');
    assert!(approval.sign(&f.participants[0], &altered).is_err());
    let third = proposal(&pool, &f, &[0, 1]).await;
    let (_, commitment) = f.participants[0].approve(&third, &f.dkg).unwrap();
    sqlx::query("UPDATE group_memberships SET installation_epoch=installation_epoch+1 WHERE tenant_id=1 AND group_id=$1 AND admin_pubkey=$2").bind(f.group).bind(f.keys[0].public_key().to_hex()).execute(&pool).await.unwrap();
    assert!(coordinator
        .signing_message(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &third.binding.session_id,
            SigningMessage::Commitment {
                proposal_digest: third.proposal_digest().unwrap(),
                commitment
            }
        )
        .await
        .is_err());
    let Session::Signing(aborted) = coordinator
        .get(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &third.binding.session_id,
        )
        .await
        .unwrap()
    else {
        panic!("signing state");
    };
    assert!(aborted.aborted);
    // Recovery keeps participant identity while using the current installation epoch.
    let next = proposal(&pool, &f, &[0, 1]).await;
    assert_eq!(
        next.signers
            .iter()
            .find(|m| m.admin_pubkey == f.keys[0].public_key().to_hex())
            .unwrap()
            .installation_epoch,
        2
    );
    let restored = keycast_core::groups::frost::client::Participant::restore(
        &f.participants[0].export_for_encrypted_backup().unwrap(),
        &f.keys[0].public_key().to_hex(),
        &f.dkg,
    )
    .unwrap();
    restored.approve(&next, &f.dkg).unwrap();
    assert!(coordinator
        .get(
            2,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &next.binding.session_id
        )
        .await
        .is_err());
}

#[sqlx::test(migrations = "../database/migrations")]
#[serial_test::serial(frost_coordinator)]
async fn disagreement_confidential_delivery_and_immutable_roster(pool: PgPool) {
    let f = completed_dkg(&pool).await;
    let mut state = f.dkg.clone();
    state.public_package = None;
    state.confirmations.clear();
    state.round2.clear();
    state.agreements.clear();
    let sender = &f.keys[0];
    // An authenticated peer still cannot reveal round two before every agreement.
    let payload = DkgPayload {
        binding: state.binding.clone(),
        message: DkgMessage::Round2 {
            recipient: state
                .roster
                .iter()
                .find(|m| m.admin_pubkey != sender.public_key().to_hex())
                .unwrap()
                .participant_id,
            ciphertext: "A".repeat(200),
        },
    };
    let message = EventBuilder::new(
        Kind::Custom(MESSAGE_KIND),
        serde_json::to_string(&payload).unwrap(),
    )
    .sign_with_keys(sender)
    .unwrap();
    assert!(state.receive(message).is_err());
    assert!(state.aborted);
    let mut state = f.dkg.clone();
    state.public_package = None;
    state.confirmations.clear();
    state.agreements.clear();
    let payload = DkgPayload {
        binding: state.binding.clone(),
        message: DkgMessage::Agreement {
            transcript: "0".repeat(64),
        },
    };
    let message = EventBuilder::new(
        Kind::Custom(MESSAGE_KIND),
        serde_json::to_string(&payload).unwrap(),
    )
    .sign_with_keys(sender)
    .unwrap();
    assert!(state.receive(message).is_err());
    assert!(state.aborted);
    let mut changed = f.dkg.clone();
    changed.roster.swap(0, 1);
    assert!(DkgRound1::start(sender.clone(), &changed).is_err());
    // Round-two payloads cannot be decrypted by a nonrecipient.
    let delivery = f.dkg.round2.values().next().unwrap();
    let payload: DkgPayload = serde_json::from_str(&delivery.content).unwrap();
    let DkgMessage::Round2 {
        recipient,
        ciphertext,
    } = payload.message
    else {
        panic!("round two");
    };
    let outsider = f
        .keys
        .iter()
        .find(|key| {
            key.public_key() != delivery.pubkey
                && f.dkg
                    .roster
                    .iter()
                    .find(|m| m.admin_pubkey == key.public_key().to_hex())
                    .unwrap()
                    .participant_id
                    != recipient
        })
        .unwrap();
    assert!(
        nostr::nips::nip44::decrypt(outsider.secret_key(), &delivery.pubkey, ciphertext).is_err()
    );
    let mut incomplete = f.dkg.clone();
    incomplete.round1.pop_first();
    assert!(incomplete.transcript().is_err());
    assert!(keycast_core::groups::frost::DkgState::new(
        f.dkg.binding.clone(),
        1,
        f.dkg.roster.clone()
    )
    .is_err());
    let mut confirmation = f.dkg.clone();
    confirmation.public_package = None;
    confirmation.confirmations.clear();
    let first = f.dkg.confirmations.values().next().unwrap().clone();
    let first_sender = first.pubkey;
    confirmation.receive(first).unwrap();
    let second = f
        .keys
        .iter()
        .find(|k| k.public_key() != first_sender)
        .unwrap();
    let (_, other_public) = frost_secp256k1_tr::keys::generate_with_dealer(
        3,
        2,
        frost_secp256k1_tr::keys::IdentifierList::Default,
        rand::rngs::OsRng,
    )
    .unwrap();
    let conflicting = DkgPayload {
        binding: confirmation.binding.clone(),
        message: DkgMessage::Confirmation {
            transcript: confirmation.transcript().unwrap(),
            public_package: other_public,
        },
    };
    let event = EventBuilder::new(
        Kind::Custom(MESSAGE_KIND),
        serde_json::to_string(&conflicting).unwrap(),
    )
    .sign_with_keys(second)
    .unwrap();
    assert!(confirmation.receive(event).is_err());
    assert!(confirmation.aborted);
}

#[sqlx::test(migrations = "../database/migrations")]
#[serial_test::serial(frost_coordinator)]
async fn two_workers_cannot_reserve_the_same_nonce_and_backup_is_required(pool: PgPool) {
    let f = completed_dkg(&pool).await;
    let coordinator = FrostCoordinator::new(pool.clone());
    let ids = f
        .dkg
        .roster
        .iter()
        .take(2)
        .map(|m| m.participant_id)
        .collect();
    assert!(coordinator
        .create_signing(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &uuid::Uuid::new_v4().to_string(),
            &f.dkg.binding.session_id,
            event(&f),
            ids
        )
        .await
        .is_err());
    backup_all(&pool, &f).await;
    let first = proposal(&pool, &f, &[0, 1]).await;
    let second = proposal(&pool, &f, &[0, 1]).await;
    let (_, commitment) = f.participants[0].approve(&first, &f.dkg).unwrap();
    let admin = f.keys[0].public_key().to_hex();
    let worker = FrostCoordinator::new(pool.clone());
    let (a, b) = tokio::join!(
        coordinator.signing_message(
            1,
            f.group,
            &admin,
            &first.binding.session_id,
            SigningMessage::Commitment {
                proposal_digest: first.proposal_digest().unwrap(),
                commitment
            }
        ),
        worker.signing_message(
            1,
            f.group,
            &admin,
            &second.binding.session_id,
            SigningMessage::Commitment {
                proposal_digest: second.proposal_digest().unwrap(),
                commitment
            }
        ),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let burned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_frost_commitments WHERE tenant_id=1 AND group_id=$1",
    )
    .bind(f.group)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(burned, 2);
    sqlx::query("UPDATE users SET status='suspended' WHERE tenant_id=1 AND pubkey=$1")
        .bind(&admin)
        .execute(&pool)
        .await
        .unwrap();
    assert!(coordinator
        .get(1, f.group, &admin, &first.binding.session_id)
        .await
        .is_err());
}

#[sqlx::test(migrations = "../database/migrations")]
#[serial_test::serial(frost_coordinator)]
async fn complete_approval_rejects_replaced_event_id_and_signer_set(pool: PgPool) {
    let f = completed_dkg(&pool).await;
    backup_all(&pool, &f).await;
    let coordinator = FrostCoordinator::new(pool.clone());
    let mut state = proposal(&pool, &f, &[0, 1]).await;
    let (approval, commitment) = f.participants[0].approve(&state, &f.dkg).unwrap();
    state = coordinator
        .signing_message(
            1,
            f.group,
            &f.keys[0].public_key().to_hex(),
            &state.binding.session_id,
            SigningMessage::Commitment {
                proposal_digest: state.proposal_digest().unwrap(),
                commitment,
            },
        )
        .await
        .unwrap();
    let (other_approval, other) = f.participants[1].approve(&state, &f.dkg).unwrap();
    state = coordinator
        .signing_message(
            1,
            f.group,
            &f.keys[1].public_key().to_hex(),
            &state.binding.session_id,
            SigningMessage::Commitment {
                proposal_digest: state.proposal_digest().unwrap(),
                commitment: other,
            },
        )
        .await
        .unwrap();
    state.signing_package().unwrap();
    let mut changed_id = state.clone();
    changed_id.event_id = nostr::EventId::all_zeros();
    assert!(approval.sign(&f.participants[0], &changed_id).is_err());
    let mut changed_signers = state.clone();
    changed_signers.signers[0].participant_id = 60000;
    assert!(other_approval
        .sign(&f.participants[1], &changed_signers)
        .is_err());
    let id = state.signers[0].participant_id;
    state.commitments.remove(&id);
    state.commitments.insert(60000, commitment);
    assert!(state.signing_package().is_err());
}
