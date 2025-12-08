use anchorhash::{AnchorHash, Builder};
use std::collections::HashSet;
use std::hash::{BuildHasherDefault, DefaultHasher};

type DeterministicHasher = BuildHasherDefault<DefaultHasher>;

/// Consistent hash ring using AnchorHash algorithm.
///
/// Provides:
/// - Guaranteed optimal disruption (minimal key remapping on node changes)
/// - Extremely fast lookups
/// - Uniform load distribution
#[derive(Clone)]
pub struct HashRing {
    anchor: Option<AnchorHash<u64, String, DeterministicHasher>>,
    my_instance_id: String,
    current_instances: HashSet<String>,
}

impl HashRing {
    pub fn new(my_instance_id: &str) -> Self {
        Self {
            anchor: None,
            my_instance_id: my_instance_id.to_string(),
            current_instances: HashSet::new(),
        }
    }

    /// Rebuild the ring with a new set of instance IDs.
    pub fn rebuild(&mut self, instance_ids: Vec<String>) {
        let new_instances: HashSet<String> = instance_ids.iter().cloned().collect();

        if new_instances == self.current_instances {
            return;
        }

        self.current_instances = new_instances;
        self.rebuild_anchor();
    }

    /// Add a single instance incrementally.
    pub fn add_instance(&mut self, instance_id: String) {
        if self.current_instances.contains(&instance_id) {
            return;
        }
        self.current_instances.insert(instance_id);
        self.rebuild_anchor();
    }

    /// Remove a single instance incrementally.
    pub fn remove_instance(&mut self, instance_id: &str) {
        if !self.current_instances.remove(instance_id) {
            return;
        }
        self.rebuild_anchor();
    }

    /// Get the number of instances in the ring.
    pub fn instance_count(&self) -> usize {
        self.current_instances.len()
    }

    fn rebuild_anchor(&mut self) {
        if self.current_instances.is_empty() {
            self.anchor = None;
            return;
        }

        let mut instance_ids: Vec<String> = self.current_instances.iter().cloned().collect();
        instance_ids.sort();

        let capacity = instance_ids.len().max(16).min(u16::MAX as usize) as u16;
        self.anchor = Some(
            Builder::with_hasher(DeterministicHasher::default())
                .with_resources(instance_ids)
                .build(capacity),
        );
    }

    /// Check if this instance should handle the given key.
    pub fn should_handle(&self, key: &str) -> bool {
        if self.current_instances.is_empty() {
            return true;
        }

        match &self.anchor {
            Some(anchor) => {
                let key_hash = Self::hash_key(key);
                match anchor.get_resource(key_hash) {
                    Some(owner) => owner == &self.my_instance_id,
                    None => true,
                }
            }
            None => true,
        }
    }

    pub fn instance_id(&self) -> &str {
        &self.my_instance_id
    }

    /// Get the current set of instances in the ring.
    pub fn instances(&self) -> &HashSet<String> {
        &self.current_instances
    }

    #[inline]
    fn hash_key(key: &str) -> u64 {
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
    fn test_hashring_solo_instance_handles_all() {
        let ring = HashRing::new("instance-1");
        assert!(ring.should_handle("any-pubkey"));
        assert!(ring.should_handle("another-pubkey"));
    }

    #[test]
    fn test_hashring_add_instance_increases_count() {
        let mut ring = HashRing::new("instance-1");
        ring.rebuild(vec!["instance-1".into(), "instance-2".into()]);

        ring.add_instance("instance-3".into());

        assert_eq!(ring.instance_count(), 3);
    }

    #[test]
    fn test_hashring_remove_instance_decreases_count() {
        let mut ring = HashRing::new("instance-1");
        ring.rebuild(vec![
            "instance-1".into(),
            "instance-2".into(),
            "instance-3".into(),
        ]);

        ring.remove_instance("instance-2");

        assert_eq!(ring.instance_count(), 2);
    }

    #[test]
    fn test_hashring_instance_count_after_rebuild() {
        let mut ring = HashRing::new("instance-1");
        ring.rebuild(vec!["instance-1".into(), "instance-2".into()]);

        assert_eq!(ring.instance_count(), 2);
    }

    #[test]
    fn test_hashring_incremental_equals_full_rebuild() {
        let mut ring1 = HashRing::new("instance-1");
        ring1.rebuild(vec!["instance-1".into(), "instance-2".into()]);
        ring1.add_instance("instance-3".into());
        ring1.remove_instance("instance-2");

        let mut ring2 = HashRing::new("instance-1");
        ring2.rebuild(vec!["instance-1".into(), "instance-3".into()]);

        for i in 0..1000 {
            let key = format!("key-{}", i);
            assert_eq!(
                ring1.should_handle(&key),
                ring2.should_handle(&key),
                "Key {} should have same owner in both rings",
                key
            );
        }
    }

    #[test]
    fn test_hashring_two_instances_split_work() {
        let mut ring1 = HashRing::new("instance-1");
        let mut ring2 = HashRing::new("instance-2");

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
        assert!(handled_by_1 > 40 && handled_by_1 < 60);
        assert!(handled_by_2 > 40 && handled_by_2 < 60);
    }

    #[test]
    fn test_hashring_exactly_one_owner_per_key() {
        let instances = vec![
            "instance-1".to_string(),
            "instance-2".to_string(),
            "instance-3".to_string(),
        ];

        let mut ring1 = HashRing::new("instance-1");
        let mut ring2 = HashRing::new("instance-2");
        let mut ring3 = HashRing::new("instance-3");

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
    fn test_hashring_consistent_assignment() {
        let mut ring = HashRing::new("instance-1");
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
    fn test_hashring_empty_ring_handles_all() {
        let ring = HashRing::new("instance-1");
        assert!(ring.should_handle("any-key"));
        assert!(ring.should_handle("another-key"));
    }
}
