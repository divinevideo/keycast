use anchorhash::{AnchorHash, Builder};
use std::collections::HashSet;
use std::hash::{BuildHasherDefault, DefaultHasher};

// Use a deterministic hasher so all instances agree on key->node mapping
type DeterministicHasher = BuildHasherDefault<DefaultHasher>;

/// Wrapper around anchorhash for consistent hashing of bunker pubkeys to signer instances.
///
/// Uses AnchorHash algorithm which provides:
/// - Guaranteed optimal disruption (minimal key remapping on node changes)
/// - Extremely fast lookups (10s-100s of millions per second)
/// - Low memory footprint
/// - Uniform load distribution
pub struct SignerHashRing {
    anchor: Option<AnchorHash<u64, String, DeterministicHasher>>,
    my_instance_id: String,
    current_instances: HashSet<String>,
}

impl SignerHashRing {
    pub fn new(my_instance_id: String) -> Self {
        Self {
            anchor: None,
            my_instance_id,
            current_instances: HashSet::new(),
        }
    }

    /// Rebuild the ring with a new set of instance IDs.
    ///
    /// Since we get a fresh sorted list from PostgreSQL every 5 seconds,
    /// we rebuild the AnchorHash from scratch for simplicity and correctness.
    pub fn rebuild(&mut self, instance_ids: Vec<String>) {
        let new_instances: HashSet<String> = instance_ids.iter().cloned().collect();

        // Only rebuild if the instance set actually changed
        if new_instances == self.current_instances {
            return;
        }

        self.current_instances = new_instances;

        if instance_ids.is_empty() {
            self.anchor = None;
            return;
        }

        // Build AnchorHash with capacity for the current number of instances
        // The capacity parameter is the maximum number of resources the anchor can hold (u16)
        // Use deterministic hasher so all signer instances agree on key->node mapping
        let capacity = instance_ids.len().max(16).min(u16::MAX as usize) as u16;
        self.anchor = Some(
            Builder::with_hasher(DeterministicHasher::default())
                .with_resources(instance_ids)
                .build(capacity),
        );
    }

    /// Check if this instance should handle the given key (bunker pubkey).
    ///
    /// Uses the key's hash to consistently map to an instance.
    pub fn should_handle(&self, key: &str) -> bool {
        if self.current_instances.is_empty() {
            // No instances registered - handle everything (solo mode)
            return true;
        }

        match &self.anchor {
            Some(anchor) => {
                // Hash the key to u64 for anchorhash lookup
                let key_hash = Self::hash_key(key);
                match anchor.get_resource(key_hash) {
                    Some(owner) => owner == &self.my_instance_id,
                    None => true, // No owner found - handle it
                }
            }
            None => true, // No anchor configured - handle everything
        }
    }

    pub fn instance_id(&self) -> &str {
        &self.my_instance_id
    }

    /// Hash a string key to u64 using FNV-1a for speed and good distribution.
    #[inline]
    fn hash_key(key: &str) -> u64 {
        // FNV-1a hash - fast and good distribution for strings
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET;
        for byte in key.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solo_instance_handles_all() {
        let ring = SignerHashRing::new("instance-1".to_string());
        assert!(ring.should_handle("any-pubkey"));
        assert!(ring.should_handle("another-pubkey"));
    }

    #[test]
    fn test_two_instances_split_work() {
        let mut ring1 = SignerHashRing::new("instance-1".to_string());
        let mut ring2 = SignerHashRing::new("instance-2".to_string());

        let instances = vec!["instance-1".to_string(), "instance-2".to_string()];
        ring1.rebuild(instances.clone());
        ring2.rebuild(instances);

        let mut handled_by_1 = 0;
        let mut handled_by_2 = 0;

        for i in 0..100 {
            let pubkey = format!("pubkey-{}", i);
            if ring1.should_handle(&pubkey) {
                handled_by_1 += 1;
            }
            if ring2.should_handle(&pubkey) {
                handled_by_2 += 1;
            }
        }

        assert_eq!(handled_by_1 + handled_by_2, 100);
        assert!(handled_by_1 > 45 && handled_by_1 < 55);
        assert!(handled_by_2 > 45 && handled_by_2 < 55);
    }

    #[test]
    fn test_consistent_assignment() {
        let mut ring = SignerHashRing::new("instance-1".to_string());
        ring.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ]);

        let pubkey = "test-pubkey-abc";
        let first_result = ring.should_handle(pubkey);

        for _ in 0..10 {
            assert_eq!(ring.should_handle(pubkey), first_result);
        }
    }

    #[test]
    fn test_exactly_one_owner_per_key() {
        let instances = vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ];

        let mut ring1 = SignerHashRing::new("instance-1".to_string());
        let mut ring2 = SignerHashRing::new("instance-2".to_string());
        let mut ring3 = SignerHashRing::new("instance-3".to_string());

        ring1.rebuild(instances.clone());
        ring2.rebuild(instances.clone());
        ring3.rebuild(instances);

        for i in 0..1000 {
            let pubkey = format!("npub1{:064x}", i);
            let owners: Vec<bool> = vec![
                ring1.should_handle(&pubkey),
                ring2.should_handle(&pubkey),
                ring3.should_handle(&pubkey),
            ];
            let owner_count = owners.iter().filter(|&&x| x).count();
            assert_eq!(
                owner_count, 1,
                "Key {} should have exactly 1 owner, got {}",
                pubkey, owner_count
            );
        }
    }

    #[test]
    fn test_scale_up_minimal_remapping() {
        let mut ring_before = SignerHashRing::new("instance-1".to_string());
        ring_before.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ]);

        let mut ring_after = SignerHashRing::new("instance-1".to_string());
        ring_after.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
            "instance-4".to_string(),
        ]);

        let mut unchanged = 0;
        let total = 1000;

        for i in 0..total {
            let pubkey = format!("npub1{:064x}", i);
            if ring_before.should_handle(&pubkey) == ring_after.should_handle(&pubkey) {
                unchanged += 1;
            }
        }

        // AnchorHash guarantees optimal disruption: ~75% should remain unchanged
        let unchanged_pct = (unchanged as f64 / total as f64) * 100.0;
        assert!(
            unchanged_pct > 60.0,
            "Expected >60% keys unchanged after scale-up, got {:.1}%",
            unchanged_pct
        );
    }

    #[test]
    fn test_scale_down_minimal_remapping() {
        let mut ring_before = SignerHashRing::new("instance-1".to_string());
        ring_before.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
            "instance-4".to_string(),
        ]);

        let mut ring_after = SignerHashRing::new("instance-1".to_string());
        ring_after.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ]);

        let mut unchanged = 0;
        let total = 1000;

        for i in 0..total {
            let pubkey = format!("npub1{:064x}", i);
            if ring_before.should_handle(&pubkey) == ring_after.should_handle(&pubkey) {
                unchanged += 1;
            }
        }

        // AnchorHash guarantees optimal disruption: ~75% should remain unchanged
        let unchanged_pct = (unchanged as f64 / total as f64) * 100.0;
        assert!(
            unchanged_pct > 60.0,
            "Expected >60% keys unchanged after scale-down, got {:.1}%",
            unchanged_pct
        );
    }

    #[test]
    fn test_ten_instances_even_distribution() {
        let instances: Vec<String> = (1..=10).map(|i| format!("instance-{}", i)).collect();

        let rings: Vec<SignerHashRing> = instances
            .iter()
            .map(|id| {
                let mut ring = SignerHashRing::new(id.clone());
                ring.rebuild(instances.clone());
                ring
            })
            .collect();

        let mut counts = [0; 10];
        let total = 10000;

        for i in 0..total {
            let pubkey = format!("npub1{:064x}", i);
            for (idx, ring) in rings.iter().enumerate() {
                if ring.should_handle(&pubkey) {
                    counts[idx] += 1;
                }
            }
        }

        // Each instance should handle ~10% (1000 keys), allow 7-13% range
        for (idx, &count) in counts.iter().enumerate() {
            let pct = (count as f64 / total as f64) * 100.0;
            assert!(
                pct > 7.0 && pct < 13.0,
                "Instance {} has {:.1}% of keys (expected ~10%)",
                idx + 1,
                pct
            );
        }

        // Total should equal total keys
        let total_handled: i32 = counts.iter().sum();
        assert_eq!(total_handled, total);
    }

    #[test]
    fn test_rebuild_with_different_instances() {
        // Test that rebuilding with a different instance set works correctly
        let mut ring1 = SignerHashRing::new("instance-1".to_string());
        let mut ring2 = SignerHashRing::new("instance-2".to_string());
        let mut ringx = SignerHashRing::new("instance-X".to_string());

        // First configuration: instance-1 and instance-2
        ring1.rebuild(vec!["instance-1".to_string(), "instance-2".to_string()]);
        ring2.rebuild(vec!["instance-1".to_string(), "instance-2".to_string()]);

        // Second configuration: instance-1 and instance-X
        let mut ring1_after = SignerHashRing::new("instance-1".to_string());
        ringx.rebuild(vec!["instance-1".to_string(), "instance-X".to_string()]);
        ring1_after.rebuild(vec!["instance-1".to_string(), "instance-X".to_string()]);

        // Verify each key has exactly one owner in both configurations
        for i in 0..100 {
            let pubkey = format!("pubkey-{}", i);

            // Config 1: exactly one of instance-1 or instance-2
            let owners_before = [ring1.should_handle(&pubkey), ring2.should_handle(&pubkey)];
            assert_eq!(
                owners_before.iter().filter(|&&x| x).count(),
                1,
                "Key {} should have exactly 1 owner in config 1",
                pubkey
            );

            // Config 2: exactly one of instance-1 or instance-X
            let owners_after = [
                ring1_after.should_handle(&pubkey),
                ringx.should_handle(&pubkey),
            ];
            assert_eq!(
                owners_after.iter().filter(|&&x| x).count(),
                1,
                "Key {} should have exactly 1 owner in config 2",
                pubkey
            );
        }
    }

    #[test]
    fn test_empty_ring_handles_all() {
        let mut ring = SignerHashRing::new("instance-1".to_string());
        // Don't call rebuild - ring is empty
        assert!(ring.should_handle("any-key"));
        assert!(ring.should_handle("another-key"));

        // After rebuild with instances, should filter
        ring.rebuild(vec!["instance-1".to_string(), "instance-2".to_string()]);
        // Now not all keys should be handled
        let handled = (0..100)
            .map(|i| format!("pubkey-{}", i))
            .filter(|k| ring.should_handle(k))
            .count();
        assert!(
            handled < 100,
            "With 2 instances, should handle ~50% not 100%"
        );
    }

    #[test]
    fn test_real_nostr_pubkeys() {
        let instances = vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ];

        let mut ring1 = SignerHashRing::new("instance-1".to_string());
        let mut ring2 = SignerHashRing::new("instance-2".to_string());
        let mut ring3 = SignerHashRing::new("instance-3".to_string());

        ring1.rebuild(instances.clone());
        ring2.rebuild(instances.clone());
        ring3.rebuild(instances);

        // Real-looking nostr pubkeys (hex format)
        let pubkeys = vec![
            "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2",
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            "e88a691e98d9987c964521dff60025f60700378a4879180dcbbb4a5027850411",
            "32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245",
        ];

        for pubkey in pubkeys {
            let owners: Vec<bool> = vec![
                ring1.should_handle(pubkey),
                ring2.should_handle(pubkey),
                ring3.should_handle(pubkey),
            ];
            let owner_count = owners.iter().filter(|&&x| x).count();
            assert_eq!(
                owner_count, 1,
                "Pubkey {} should have exactly 1 owner",
                pubkey
            );
        }
    }

    #[test]
    fn test_rebuild_skips_unchanged() {
        let mut ring = SignerHashRing::new("instance-1".to_string());

        let instances = vec!["instance-1".to_string(), "instance-2".to_string()];
        ring.rebuild(instances.clone());

        // Get a reference to verify it's the same anchor after no-op rebuild
        let handled_before: Vec<bool> = (0..10)
            .map(|i| ring.should_handle(&format!("key-{}", i)))
            .collect();

        // Rebuild with same instances (should be a no-op)
        ring.rebuild(instances);

        let handled_after: Vec<bool> = (0..10)
            .map(|i| ring.should_handle(&format!("key-{}", i)))
            .collect();

        assert_eq!(
            handled_before, handled_after,
            "No-op rebuild should preserve assignments"
        );
    }
}
