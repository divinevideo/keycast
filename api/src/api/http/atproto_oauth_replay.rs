// ABOUTME: Shared atomic replay-reservation store for ATProto OAuth
// ABOUTME: Replaces per-instance DPoP and private_key_jwt replay maps (keycast#367)

use chrono::Utc;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use keycast_core::metrics::METRICS;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::redis::PrefixedRedis;

/// DPoP proof `iat` acceptance window: a proof is acceptable while
/// `iat` is within `now ± DPOP_MAX_IAT_SKEW_SECONDS`. Shared with the
/// proof validator so retention and acceptance can never drift apart.
pub const DPOP_MAX_IAT_SKEW_SECONDS: i64 = 300;

/// Client assertion `exp` acceptance bound: an assertion is acceptable while
/// `now < exp <= now + CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS` and its `iat`
/// is within `CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS` of `now`. Shared with
/// the assertion validator so retention and acceptance can never drift apart.
pub const CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS: i64 = 300;

/// Extra retention beyond the exact acceptance-window end, so a reservation
/// made on one instance cannot expire a second before a validator on another
/// instance (with slightly skewed clock) stops accepting the proof.
const REPLAY_RESERVATION_SKEW_MARGIN_SECONDS: i64 = 1;

/// Explicit override for development-only degraded mode. Default is
/// fail-closed: when shared replay storage is unavailable or inconclusive,
/// protected requests are rejected with a retryable response.
const ATPROTO_OAUTH_REPLAY_FAIL_OPEN_ENV: &str = "ATPROTO_OAUTH_REPLAY_FAIL_OPEN";

/// How often to clean expired local-fallback entries.
const FALLBACK_CLEANUP_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Error)]
pub enum ReplayReservationError {
    #[error("replay identity has already been used")]
    Replay,
    #[error("replay protection storage is unavailable or inconclusive")]
    StorageUnavailable,
}

/// Which reservation store granted the reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationOutcome {
    /// Reserved atomically in the shared store visible to every instance.
    Reserved,
    /// Reserved in the per-instance fallback, only reachable in explicit
    /// fail-open degraded mode.
    FallbackReserved,
}

/// Replay-reservation namespaces. DPoP proofs and client assertions reserve
/// under separate key prefixes so the same identifier text in one namespace
/// can never block or admit the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayNamespace {
    DpopProof,
    ClientAssertion,
}

impl ReplayNamespace {
    fn key_prefix(self) -> &'static str {
        match self {
            ReplayNamespace::DpopProof => "atproto:oauth:replay:dpop-proof",
            ReplayNamespace::ClientAssertion => "atproto:oauth:replay:client-assertion",
        }
    }

    fn metric_label(self) -> &'static str {
        match self {
            ReplayNamespace::DpopProof => "dpop_proof",
            ReplayNamespace::ClientAssertion => "client_assertion",
        }
    }
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Replay key for a validated DPoP proof.
///
/// The key is type-separated by namespace prefix, scoped to the proof key's
/// JWK thumbprint (so the same `jti` under different client keys is
/// legitimate and does not collide), and digest-derived: `jkt` is a
/// server-computed fixed-length (43-char) base64url SHA-256 digest, and the
/// attacker-controlled `jti` of arbitrary length is reduced to a fixed
/// 64-char SHA-256 hex digest. Key length is therefore constant regardless
/// of input.
///
/// Cardinality: bounded by the number of distinct validated `(jkt, jti)`
/// pairs inside the retention window (at most
/// `2 * DPOP_MAX_IAT_SKEW_SECONDS + margin` seconds). Every reservation
/// expires, so the live-key count is bounded by request rate over that
/// window.
pub fn dpop_replay_key(jkt: &str, jti: &str) -> String {
    format!(
        "{}:{}:{}",
        ReplayNamespace::DpopProof.key_prefix(),
        jkt,
        sha256_hex(jti)
    )
}

/// Replay key for a validated private_key_jwt client assertion.
///
/// Type-separated by namespace prefix, scoped to the client_id, and
/// digest-derived: both the client_id (an arbitrary-length URL controlled by
/// the client) and the `jti` are reduced to fixed 64-char SHA-256 hex
/// digests, so attacker-controlled input can neither grow the key nor inject
/// separators. Cardinality is bounded exactly like the DPoP namespace, over
/// the client-assertion retention window.
pub fn client_assertion_replay_key(client_id: &str, jti: &str) -> String {
    format!(
        "{}:{}:{}",
        ReplayNamespace::ClientAssertion.key_prefix(),
        sha256_hex(client_id),
        sha256_hex(jti)
    )
}

/// DPoP reservation retention: must cover the complete period in which any
/// validator can still accept the proof. A proof with `iat` is accepted while
/// `iat >= now - DPOP_MAX_IAT_SKEW_SECONDS`, so the last acceptance instant
/// is `iat + DPOP_MAX_IAT_SKEW_SECONDS`. The TTL is measured from the
/// reservation time (`now`), clamped for defense in depth, plus a small
/// cross-instance clock-skew margin. Maximum: 601 seconds.
#[must_use]
pub fn dpop_reservation_ttl_seconds(iat: i64, now: i64) -> u64 {
    let acceptance_end = iat + DPOP_MAX_IAT_SKEW_SECONDS;
    let ttl = acceptance_end
        .saturating_sub(now)
        .clamp(1, 2 * DPOP_MAX_IAT_SKEW_SECONDS);
    (ttl + REPLAY_RESERVATION_SKEW_MARGIN_SECONDS) as u64
}

/// Client-assertion reservation retention: must cover the complete period in
/// which any validator can still accept the assertion, which ends at its
/// `exp`. The TTL is measured from the reservation time (`now`), clamped for
/// defense in depth, plus a small cross-instance clock-skew margin. Maximum:
/// 301 seconds.
#[must_use]
pub fn client_assertion_reservation_ttl_seconds(exp: i64, now: i64) -> u64 {
    let ttl = exp
        .saturating_sub(now)
        .clamp(1, CLIENT_ASSERTION_MAX_EXP_SKEW_SECONDS);
    (ttl + REPLAY_RESERVATION_SKEW_MARGIN_SECONDS) as u64
}

/// Per-instance fallback, used only in explicit fail-open degraded mode when
/// shared storage is unavailable. Provides atomic same-instance protection;
/// cross-instance replay is possible in that mode by definition.
static LOCAL_REPLAY_FALLBACK: Lazy<DashMap<String, Instant>> = Lazy::new(DashMap::new);

/// Track when fallback cleanup last ran to avoid doing it on every request.
static LAST_FALLBACK_CLEANUP: Lazy<std::sync::Mutex<Instant>> =
    Lazy::new(|| std::sync::Mutex::new(Instant::now()));

fn maybe_cleanup_fallback() {
    let should_cleanup = LAST_FALLBACK_CLEANUP
        .lock()
        .ok()
        .map(|last| last.elapsed() > Duration::from_secs(FALLBACK_CLEANUP_INTERVAL_SECS))
        .unwrap_or(false);

    if should_cleanup {
        let now = Instant::now();
        LOCAL_REPLAY_FALLBACK.retain(|_, expiry| *expiry > now);
        if let Ok(mut last) = LAST_FALLBACK_CLEANUP.lock() {
            *last = now;
        }
    }
}

fn fallback_reserve(
    namespace: ReplayNamespace,
    replay_key: &str,
    ttl_seconds: u64,
) -> Result<ReservationOutcome, ReplayReservationError> {
    maybe_cleanup_fallback();
    let now = Instant::now();
    let expiry = now + Duration::from_secs(ttl_seconds);
    match LOCAL_REPLAY_FALLBACK.entry(replay_key.to_string()) {
        Entry::Occupied(mut existing) => {
            if *existing.get() > now {
                METRICS.inc_atproto_oauth_replay_reservation(
                    namespace.metric_label(),
                    "fallback_rejected",
                );
                return Err(ReplayReservationError::Replay);
            }
            existing.insert(expiry);
        }
        Entry::Vacant(vacant) => {
            vacant.insert(expiry);
        }
    }
    METRICS.inc_atproto_oauth_replay_reservation(namespace.metric_label(), "fallback_reserved");
    Ok(ReservationOutcome::FallbackReserved)
}

fn parse_truthy_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn replay_fail_open_from_env_value(value: Option<&str>) -> bool {
    value.map(parse_truthy_env).unwrap_or(false)
}

fn replay_fail_open_enabled() -> bool {
    let value = std::env::var(ATPROTO_OAUTH_REPLAY_FAIL_OPEN_ENV).ok();
    replay_fail_open_from_env_value(value.as_deref())
}

/// Atomically reserve a validated replay identity.
///
/// The shared store is one atomic Redis `SET key value EX ttl NX`: `Ok(true)`
/// is the single winner, `Ok(false)` is a confirmed replay. When Redis is
/// unavailable or the answer is inconclusive (error), the default is
/// fail-closed ([`ReplayReservationError::StorageUnavailable`]); explicit
/// fail-open mode degrades to the per-instance fallback instead.
///
/// Callers must have validated syntax, claims, signature, audience/request
/// binding, and key binding before reserving, so an unauthenticated proof can
/// never poison the reservation store.
pub async fn reserve_replay_identity(
    redis: Option<&PrefixedRedis>,
    namespace: ReplayNamespace,
    replay_key: &str,
    ttl_seconds: u64,
    fail_open: bool,
) -> Result<ReservationOutcome, ReplayReservationError> {
    if let Some(redis) = redis {
        match redis
            .set_nx_ex(replay_key, ttl_seconds, &Utc::now().timestamp().to_string())
            .await
        {
            Ok(true) => {
                METRICS.inc_atproto_oauth_replay_reservation(namespace.metric_label(), "reserved");
                return Ok(ReservationOutcome::Reserved);
            }
            Ok(false) => {
                METRICS.inc_atproto_oauth_replay_reservation(
                    namespace.metric_label(),
                    "replay_rejected",
                );
                return Err(ReplayReservationError::Replay);
            }
            Err(error) => {
                METRICS.inc_atproto_oauth_replay_reservation(
                    namespace.metric_label(),
                    "storage_unavailable",
                );
                if fail_open {
                    tracing::error!(
                        error = %error,
                        namespace = namespace.metric_label(),
                        fail_open = true,
                        "ATProto OAuth replay reservation degraded: shared store unavailable, using per-instance fallback"
                    );
                } else {
                    tracing::error!(
                        error = %error,
                        namespace = namespace.metric_label(),
                        fail_open = false,
                        "ATProto OAuth replay reservation unavailable: rejecting request to avoid cross-instance replay risk"
                    );
                    return Err(ReplayReservationError::StorageUnavailable);
                }
            }
        }
    } else {
        METRICS
            .inc_atproto_oauth_replay_reservation(namespace.metric_label(), "storage_unavailable");
        if fail_open {
            tracing::error!(
                namespace = namespace.metric_label(),
                fail_open = true,
                "ATProto OAuth replay reservation degraded: shared store not configured, using per-instance fallback"
            );
        } else {
            tracing::error!(
                namespace = namespace.metric_label(),
                fail_open = false,
                "ATProto OAuth replay reservation unavailable: shared store not configured, rejecting request to avoid cross-instance replay risk"
            );
            return Err(ReplayReservationError::StorageUnavailable);
        }
    }

    fallback_reserve(namespace, replay_key, ttl_seconds)
}

fn shared_replay_store() -> Option<PrefixedRedis> {
    crate::state::get_keycast_state()
        .ok()
        .and_then(|state| state.redis.clone())
}

/// Reserve a validated DPoP proof's `(jkt, jti)` replay identity using the
/// application's shared replay store. Retention covers the proof's complete
/// acceptance window (see [`dpop_reservation_ttl_seconds`]).
pub async fn reserve_dpop_proof_jti(
    jkt: &str,
    jti: &str,
    iat: i64,
    now: i64,
) -> Result<ReservationOutcome, ReplayReservationError> {
    let redis = shared_replay_store();
    let ttl = dpop_reservation_ttl_seconds(iat, now);
    reserve_replay_identity(
        redis.as_ref(),
        ReplayNamespace::DpopProof,
        &dpop_replay_key(jkt, jti),
        ttl,
        replay_fail_open_enabled(),
    )
    .await
}

/// Reserve a validated client assertion's `(client_id, jti)` replay identity
/// using the application's shared replay store. Retention covers the
/// assertion's complete acceptance window (see
/// [`client_assertion_reservation_ttl_seconds`]).
pub async fn reserve_client_assertion_jti(
    client_id: &str,
    jti: &str,
    exp: i64,
    now: i64,
) -> Result<ReservationOutcome, ReplayReservationError> {
    let redis = shared_replay_store();
    let ttl = client_assertion_reservation_ttl_seconds(exp, now);
    reserve_replay_identity(
        redis.as_ref(),
        ReplayNamespace::ClientAssertion,
        &client_assertion_replay_key(client_id, jti),
        ttl,
        replay_fail_open_enabled(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpop_keys_are_namespaced_and_binding_scoped() {
        let jkt_a = "a".repeat(43);
        let jkt_b = "b".repeat(43);

        let base = dpop_replay_key(&jkt_a, "shared-jti");
        let other_jkt = dpop_replay_key(&jkt_b, "shared-jti");
        let other_jti = dpop_replay_key(&jkt_a, "other-jti");
        let other_namespace = client_assertion_replay_key(&jkt_a, "shared-jti");

        assert_ne!(
            base, other_jkt,
            "same jti under a different key must not collide"
        );
        assert_ne!(base, other_jti);
        assert_ne!(
            base, other_namespace,
            "namespaces must be isolated even for identical identifier text"
        );
    }

    #[test]
    fn client_assertion_keys_digest_unbounded_attacker_input() {
        let long_client_id = "https://".to_string() + &"a".repeat(10_000);
        let key = client_assertion_replay_key(&long_client_id, "jti");
        let short = client_assertion_replay_key("https://x.example", "jti");

        assert_eq!(key.len(), short.len());
        assert!(key.starts_with("atproto:oauth:replay:client-assertion:"));
        assert_ne!(key, short);

        let long_jti = "j".repeat(10_000);
        let dpop_key = dpop_replay_key(&"k".repeat(43), &long_jti);
        assert_eq!(dpop_key.len(), dpop_replay_key(&"k".repeat(43), "j").len());
    }

    #[test]
    fn dpop_ttl_covers_the_complete_acceptance_period() {
        let now = 10_000_i64;

        // Fresh proof: acceptable until iat + 300.
        assert_eq!(dpop_reservation_ttl_seconds(now, now), 301);
        // Future-dated proof at the window edge: acceptable until now + 600.
        assert_eq!(dpop_reservation_ttl_seconds(now + 300, now), 601);
        // Proof at the old edge of the window: acceptance ends now; keep the
        // minimum bounded reservation.
        assert_eq!(dpop_reservation_ttl_seconds(now - 300, now), 2);
        // Out-of-window inputs are clamped rather than panicking or exploding.
        assert_eq!(dpop_reservation_ttl_seconds(now - 5_000, now), 2);
        assert_eq!(dpop_reservation_ttl_seconds(now + 5_000, now), 601);
    }

    #[test]
    fn client_assertion_ttl_covers_the_complete_acceptance_period() {
        let now = 10_000_i64;

        assert_eq!(
            client_assertion_reservation_ttl_seconds(now + 300, now),
            301
        );
        assert_eq!(client_assertion_reservation_ttl_seconds(now + 1, now), 2);
        assert_eq!(client_assertion_reservation_ttl_seconds(now - 50, now), 2);
        assert_eq!(
            client_assertion_reservation_ttl_seconds(now + 5_000, now),
            301
        );
    }

    #[test]
    fn fail_open_env_defaults_closed_and_parses_truthy() {
        assert!(!replay_fail_open_from_env_value(None));
        assert!(replay_fail_open_from_env_value(Some("true")));
        assert!(replay_fail_open_from_env_value(Some(" ON ")));
        assert!(!replay_fail_open_from_env_value(Some("false")));
        assert!(!replay_fail_open_from_env_value(Some("")));
    }

    #[tokio::test]
    async fn without_shared_store_fails_closed_by_default() {
        let result = reserve_replay_identity(
            None,
            ReplayNamespace::DpopProof,
            &dpop_replay_key(&"a".repeat(43), "closed-jti"),
            300,
            false,
        )
        .await;
        assert!(matches!(
            result,
            Err(ReplayReservationError::StorageUnavailable)
        ));
    }

    #[tokio::test]
    async fn local_fallback_rejects_replay_atomically() {
        let replay_key = dpop_replay_key(&"a".repeat(43), "fallback-jti");

        let first =
            reserve_replay_identity(None, ReplayNamespace::DpopProof, &replay_key, 300, true)
                .await
                .expect("fail-open first insert succeeds");
        assert_eq!(first, ReservationOutcome::FallbackReserved);

        let replay =
            reserve_replay_identity(None, ReplayNamespace::DpopProof, &replay_key, 300, true).await;
        assert!(matches!(replay, Err(ReplayReservationError::Replay)));
    }

    #[tokio::test]
    async fn local_fallback_concurrent_reservation_has_exactly_one_winner() {
        let replay_key = client_assertion_replay_key("https://concurrent.example", "jti");
        let (result_a, result_b) = tokio::join!(
            reserve_replay_identity(
                None,
                ReplayNamespace::ClientAssertion,
                &replay_key,
                300,
                true
            ),
            reserve_replay_identity(
                None,
                ReplayNamespace::ClientAssertion,
                &replay_key,
                300,
                true
            ),
        );

        let winners = [result_a.is_ok(), result_b.is_ok()]
            .into_iter()
            .filter(|ok| *ok)
            .count();
        assert_eq!(winners, 1, "exactly one concurrent reservation must win");
    }

    #[tokio::test]
    async fn namespaces_do_not_collide_in_local_fallback() {
        let binding = &"a".repeat(43);
        let jti = "cross-namespace-jti";

        let dpop = reserve_replay_identity(
            None,
            ReplayNamespace::DpopProof,
            &dpop_replay_key(binding, jti),
            300,
            true,
        )
        .await;
        let assertion = reserve_replay_identity(
            None,
            ReplayNamespace::ClientAssertion,
            &client_assertion_replay_key(binding, jti),
            300,
            true,
        )
        .await;

        assert!(dpop.is_ok());
        assert!(assertion.is_ok());
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod shared_store_tests {
    use super::*;
    use redis::aio::ConnectionManager;

    fn test_redis_url() -> String {
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".into())
    }

    /// Two independently constructed handles to the same shared store, standing
    /// in for two serving instances. Returns the key prefix both share.
    async fn two_instances() -> (PrefixedRedis, PrefixedRedis, redis::Client, String) {
        let client = redis::Client::open(test_redis_url().as_str()).unwrap();
        let prefix = format!("test-atproto-replay:{}", uuid::Uuid::new_v4());
        let instance_a = PrefixedRedis::new(
            ConnectionManager::new(client.clone()).await.unwrap(),
            Some(prefix.clone()),
        );
        let instance_b = PrefixedRedis::new(
            ConnectionManager::new(client.clone()).await.unwrap(),
            Some(prefix.clone()),
        );
        (instance_a, instance_b, client, prefix)
    }

    #[tokio::test]
    async fn dpop_replay_is_rejected_across_independent_instances() {
        let (instance_a, instance_b, _client, _prefix) = two_instances().await;
        let jkt = "a".repeat(43);
        let jti = format!("cross-instance-{}", uuid::Uuid::new_v4());
        let key = dpop_replay_key(&jkt, &jti);
        let now = Utc::now().timestamp();

        let first = reserve_replay_identity(
            Some(&instance_a),
            ReplayNamespace::DpopProof,
            &key,
            dpop_reservation_ttl_seconds(now, now),
            false,
        )
        .await
        .expect("first instance reserves");
        assert_eq!(first, ReservationOutcome::Reserved);

        let replay = reserve_replay_identity(
            Some(&instance_b),
            ReplayNamespace::DpopProof,
            &key,
            dpop_reservation_ttl_seconds(now, now),
            false,
        )
        .await;
        assert!(matches!(replay, Err(ReplayReservationError::Replay)));
    }

    #[tokio::test]
    async fn client_assertion_replay_is_rejected_across_independent_instances() {
        let (instance_a, instance_b, _client, _prefix) = two_instances().await;
        let client_id = format!("https://{}.example", uuid::Uuid::new_v4());
        let jti = format!("cross-instance-{}", uuid::Uuid::new_v4());
        let key = client_assertion_replay_key(&client_id, &jti);
        let now = Utc::now().timestamp();

        let first = reserve_replay_identity(
            Some(&instance_a),
            ReplayNamespace::ClientAssertion,
            &key,
            client_assertion_reservation_ttl_seconds(now + 240, now),
            false,
        )
        .await
        .expect("first instance reserves");
        assert_eq!(first, ReservationOutcome::Reserved);

        let replay = reserve_replay_identity(
            Some(&instance_b),
            ReplayNamespace::ClientAssertion,
            &key,
            client_assertion_reservation_ttl_seconds(now + 240, now),
            false,
        )
        .await;
        assert!(matches!(replay, Err(ReplayReservationError::Replay)));
    }

    #[tokio::test]
    async fn concurrent_reservations_have_exactly_one_winner() {
        let (instance, _other, _client, _prefix) = two_instances().await;
        let key = dpop_replay_key(&"b".repeat(43), &format!("race-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let ttl = dpop_reservation_ttl_seconds(now, now);

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let redis = instance.clone();
            let key = key.clone();
            tasks.spawn(async move {
                reserve_replay_identity(Some(&redis), ReplayNamespace::DpopProof, &key, ttl, false)
                    .await
            });
        }

        let mut reserved = 0;
        let mut rejected = 0;
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(_) => reserved += 1,
                Err(ReplayReservationError::Replay) => rejected += 1,
                Err(ReplayReservationError::StorageUnavailable) => panic!("shared store failed"),
            }
        }
        assert_eq!(reserved, 1, "exactly one concurrent reservation must win");
        assert_eq!(rejected, 7);
    }

    #[tokio::test]
    async fn shared_store_namespaces_and_bindings_stay_isolated() {
        let (instance, _other, _client, _prefix) = two_instances().await;
        let shared_identifier = format!("shared-{}", uuid::Uuid::new_v4());
        let jkt_a = "a".repeat(43);
        let jkt_b = "c".repeat(43);
        let client_ids = [format!("https://a-{}.example", uuid::Uuid::new_v4())];

        let dpop_a = reserve_replay_identity(
            Some(&instance),
            ReplayNamespace::DpopProof,
            &dpop_replay_key(&jkt_a, &shared_identifier),
            300,
            false,
        )
        .await;
        let dpop_b = reserve_replay_identity(
            Some(&instance),
            ReplayNamespace::DpopProof,
            &dpop_replay_key(&jkt_b, &shared_identifier),
            300,
            false,
        )
        .await;
        let assertion = reserve_replay_identity(
            Some(&instance),
            ReplayNamespace::ClientAssertion,
            &client_assertion_replay_key(client_ids[0].as_str(), &shared_identifier),
            300,
            false,
        )
        .await;

        assert_eq!(dpop_a.unwrap(), ReservationOutcome::Reserved);
        assert_eq!(
            dpop_b.expect("same jti under a different DPoP key is legitimate"),
            ReservationOutcome::Reserved
        );
        assert_eq!(
            assertion.expect("identical identifier text in another namespace is legitimate"),
            ReservationOutcome::Reserved
        );
    }

    #[tokio::test]
    async fn reservations_outlive_the_complete_acceptance_period() {
        let (instance, _other, client, prefix) = two_instances().await;
        let now = Utc::now().timestamp();
        let suffix = uuid::Uuid::new_v4().to_string();

        // DPoP: proof minted now stays acceptable until now + 300.
        let dpop_key = dpop_replay_key(&"d".repeat(43), &format!("ttl-dpop-{suffix}"));
        reserve_replay_identity(
            Some(&instance),
            ReplayNamespace::DpopProof,
            &dpop_key,
            dpop_reservation_ttl_seconds(now, now),
            false,
        )
        .await
        .unwrap();

        // Client assertion: acceptable until exp = now + 300.
        let assertion_key =
            client_assertion_replay_key(&format!("https://ttl-{suffix}.example"), "jti");
        reserve_replay_identity(
            Some(&instance),
            ReplayNamespace::ClientAssertion,
            &assertion_key,
            client_assertion_reservation_ttl_seconds(now + 300, now),
            false,
        )
        .await
        .unwrap();

        // The stored keys carry the wrapper's deployment prefix; their live
        // TTLs must still cover the complete remaining acceptance period.
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        for unprefixed in [&dpop_key, &assertion_key] {
            let stored = format!("{prefix}:{unprefixed}");
            let ttl = redis::cmd("TTL")
                .arg(&stored)
                .query_async::<i64>(&mut conn)
                .await
                .unwrap();
            assert!(
                ttl >= 300,
                "reservation must not expire before the acceptance window ends (ttl={ttl})"
            );
        }
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn failing_shared_store_fails_closed_without_fail_open() {
        let client = redis::Client::open(test_redis_url().as_str()).unwrap();
        let failing = PrefixedRedis::new_failing(
            ConnectionManager::new(client).await.unwrap(),
            Some(format!("test-atproto-replay-fail:{}", uuid::Uuid::new_v4())),
        );
        let key = dpop_replay_key(&"e".repeat(43), "failing-store-jti");

        let closed =
            reserve_replay_identity(Some(&failing), ReplayNamespace::DpopProof, &key, 300, false)
                .await;
        assert!(matches!(
            closed,
            Err(ReplayReservationError::StorageUnavailable)
        ));

        let opened =
            reserve_replay_identity(Some(&failing), ReplayNamespace::DpopProof, &key, 300, true)
                .await;
        assert_eq!(
            opened.expect("fail-open degrades to the per-instance fallback"),
            ReservationOutcome::FallbackReserved
        );
    }
}
