// ABOUTME: Shared primitives for atomic Redis-backed replay reservations
// ABOUTME: Keeps replay fallback and retention behavior consistent across authentication paths

use dashmap::{mapref::entry::Entry, DashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::redis::PrefixedRedis;

pub enum SharedReservationOutcome {
    Reserved,
    Replay,
    Unavailable(Option<redis::RedisError>),
}

pub struct LocalReplayCache {
    entries: DashMap<String, Instant>,
    last_cleanup: Mutex<Instant>,
    cleanup_interval: Duration,
}

impl LocalReplayCache {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            last_cleanup: Mutex::new(Instant::now()),
            cleanup_interval,
        }
    }

    pub fn reserve(&self, replay_key: &str, ttl_seconds: u64) -> bool {
        self.maybe_cleanup();
        let now = Instant::now();
        let expiry = now + Duration::from_secs(ttl_seconds);
        match self.entries.entry(replay_key.to_string()) {
            Entry::Occupied(mut existing) => {
                if *existing.get() > now {
                    return false;
                }
                existing.insert(expiry);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(expiry);
            }
        }
        true
    }

    fn maybe_cleanup(&self) {
        let should_cleanup = self
            .last_cleanup
            .lock()
            .ok()
            .map(|last| last.elapsed() > self.cleanup_interval)
            .unwrap_or(false);
        if should_cleanup {
            let now = Instant::now();
            self.entries.retain(|_, expiry| *expiry > now);
            if let Ok(mut last) = self.last_cleanup.lock() {
                *last = now;
            }
        }
    }
}

pub fn truthy_env_value(value: Option<&str>) -> bool {
    value
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub fn reservation_ttl_seconds(
    acceptance_end: i64,
    now: i64,
    max_remaining_seconds: i64,
    clock_margin_seconds: i64,
) -> u64 {
    let remaining = acceptance_end
        .saturating_sub(now)
        .clamp(1, max_remaining_seconds);
    (remaining + clock_margin_seconds) as u64
}

pub async fn reserve_shared(
    redis: Option<&PrefixedRedis>,
    replay_key: &str,
    ttl_seconds: u64,
    value: &str,
) -> SharedReservationOutcome {
    let Some(redis) = redis else {
        return SharedReservationOutcome::Unavailable(None);
    };
    match redis.set_nx_ex(replay_key, ttl_seconds, value).await {
        Ok(true) => SharedReservationOutcome::Reserved,
        Ok(false) => SharedReservationOutcome::Replay,
        Err(error) => SharedReservationOutcome::Unavailable(Some(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_truthy_parser_and_ttl_are_bounded() {
        assert!(truthy_env_value(Some(" ON ")));
        assert!(!truthy_env_value(Some("false")));
        assert_eq!(reservation_ttl_seconds(10_300, 10_000, 600, 30), 330);
        assert_eq!(reservation_ttl_seconds(9_000, 10_000, 600, 30), 31);
    }

    #[test]
    fn local_cache_has_exactly_one_live_winner() {
        let cache = LocalReplayCache::new(Duration::from_secs(60));
        assert!(cache.reserve("key", 300));
        assert!(!cache.reserve("key", 300));
    }
}
