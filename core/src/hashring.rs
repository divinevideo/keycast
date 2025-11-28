use siphasher::sip::SipHasher24;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

const VIRTUAL_NODES: usize = 150;

pub struct HashRing {
    ring: BTreeMap<u64, String>,
    my_instance_id: String,
}

impl HashRing {
    pub fn new(my_instance_id: String) -> Self {
        Self {
            ring: BTreeMap::new(),
            my_instance_id,
        }
    }

    pub fn rebuild(&mut self, instance_ids: Vec<String>) {
        self.ring.clear();
        for id in instance_ids {
            for i in 0..VIRTUAL_NODES {
                let key = format!("{}:{}", id, i);
                let hash = self.hash_key(&key);
                self.ring.insert(hash, id.clone());
            }
        }
    }

    pub fn should_handle(&self, key: &str) -> bool {
        if self.ring.is_empty() {
            return true;
        }
        let hash = self.hash_key(key);
        let owner = self
            .ring
            .range(hash..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, id)| id.as_str());
        owner == Some(&self.my_instance_id)
    }

    pub fn instance_id(&self) -> &str {
        &self.my_instance_id
    }

    fn hash_key(&self, key: &str) -> u64 {
        let mut hasher = SipHasher24::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_solo_instance_handles_all() {
        let ring = HashRing::new("instance-1".to_string());
        assert!(ring.should_handle("any-pubkey"));
        assert!(ring.should_handle("another-pubkey"));
    }

    #[test]
    fn test_two_instances_split_work() {
        let mut ring1 = HashRing::new("instance-1".to_string());
        let mut ring2 = HashRing::new("instance-2".to_string());

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
        assert!(handled_by_1 > 30 && handled_by_1 < 70);
        assert!(handled_by_2 > 30 && handled_by_2 < 70);
    }

    #[test]
    fn test_consistent_assignment() {
        let mut ring = HashRing::new("instance-1".to_string());
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

        let mut ring1 = HashRing::new("instance-1".to_string());
        let mut ring2 = HashRing::new("instance-2".to_string());
        let mut ring3 = HashRing::new("instance-3".to_string());

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
            assert_eq!(owner_count, 1, "Key {} should have exactly 1 owner, got {}", pubkey, owner_count);
        }
    }

    #[test]
    fn test_scale_up_minimal_remapping() {
        let mut ring_before = HashRing::new("instance-1".to_string());
        ring_before.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ]);

        let mut ring_after = HashRing::new("instance-1".to_string());
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

        // With consistent hashing, ~75% should remain unchanged (only ~25% remap to new instance)
        let unchanged_pct = (unchanged as f64 / total as f64) * 100.0;
        assert!(
            unchanged_pct > 60.0,
            "Expected >60% keys unchanged after scale-up, got {:.1}%",
            unchanged_pct
        );
    }

    #[test]
    fn test_scale_down_minimal_remapping() {
        let mut ring_before = HashRing::new("instance-1".to_string());
        ring_before.rebuild(vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
            "instance-4".to_string(),
        ]);

        let mut ring_after = HashRing::new("instance-1".to_string());
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

        // With consistent hashing, ~75% should remain unchanged
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

        let rings: Vec<HashRing> = instances
            .iter()
            .map(|id| {
                let mut ring = HashRing::new(id.clone());
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
    fn test_rebuild_clears_old_state() {
        let mut ring = HashRing::new("instance-1".to_string());

        ring.rebuild(vec!["instance-1".to_string(), "instance-2".to_string()]);
        let handled_before: HashSet<String> = (0..100)
            .map(|i| format!("pubkey-{}", i))
            .filter(|k| ring.should_handle(k))
            .collect();

        // Rebuild with completely different instances
        ring.rebuild(vec!["instance-1".to_string(), "instance-X".to_string()]);
        let handled_after: HashSet<String> = (0..100)
            .map(|i| format!("pubkey-{}", i))
            .filter(|k| ring.should_handle(k))
            .collect();

        // Distribution should change significantly
        let overlap = handled_before.intersection(&handled_after).count();
        assert!(
            overlap < handled_before.len(),
            "Rebuild should change key distribution"
        );
    }

    #[test]
    fn test_empty_ring_handles_all() {
        let mut ring = HashRing::new("instance-1".to_string());
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
        assert!(handled < 100, "With 2 instances, should handle ~50% not 100%");
    }

    #[test]
    fn test_real_nostr_pubkeys() {
        let instances = vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ];

        let mut ring1 = HashRing::new("instance-1".to_string());
        let mut ring2 = HashRing::new("instance-2".to_string());
        let mut ring3 = HashRing::new("instance-3".to_string());

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
            assert_eq!(owner_count, 1, "Pubkey {} should have exactly 1 owner", pubkey);
        }
    }
}
