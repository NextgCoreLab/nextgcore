//! Bounded, TTL'd cache for SCP proxy state (scpd-#102, TS 33.522 §4.2.3.3).
//!
//! The SCP's forwarding path accumulates per-peer state — pooled HTTP/2
//! clients, learnt `3gpp-Sbi-Binding` stickiness, per-endpoint circuit
//! breakers. Binding values and the discovery discriminator are
//! peer/header-influenced, so an unbounded map is a slow-memory-growth /
//! resource-exhaustion concern under sustained or adversarial traffic.
//!
//! [`BoundedCache`] caps the entry count and expires entries by age:
//!
//! - `get` returns a clone of a live (un-expired) value, or `None`.
//! - `insert` first purges expired entries; if still at capacity it evicts
//!   the oldest entry by insertion time, so the ceiling is a hard bound.
//! - `purge_expired` sweeps expired entries; the SCP main loop calls it
//!   periodically so idle entries are reclaimed without waiting for the next
//!   `insert` on that key.
//!
//! Eviction is approximate-LRU (oldest insertion first). A full LRU is not
//! worth the per-`get` recency bookkeeping for connection pools and
//! stickiness maps.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A cached value with the instant it was inserted (used for TTL and for
/// oldest-first eviction).
struct Entry<V> {
    value: V,
    inserted_at: Instant,
}

/// A size-capped, TTL'd map behind an `RwLock`.
pub struct BoundedCache<K, V> {
    inner: RwLock<HashMap<K, Entry<V>>>,
    /// Hard ceiling on live entries.
    max_entries: usize,
    /// Maximum age before an entry is considered expired.
    ttl: Duration,
}

impl<K, V> BoundedCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Create an empty cache bounded to `max_entries` live entries, each
    /// expiring `ttl` after insertion. `max_entries` is clamped to at least 1
    /// so a mis-configured `0` cannot make every `insert` a no-op.
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    /// Return a clone of the live value for `key`, or `None` if absent or
    /// expired. Expired entries are not removed here (a read lock suffices);
    /// [`purge_expired`](Self::purge_expired) or a later `insert` reclaims them.
    pub fn get(&self, key: &K) -> Option<V> {
        let map = self.inner.read().ok()?;
        map.get(key).and_then(|e| {
            if e.inserted_at.elapsed() < self.ttl {
                Some(e.value.clone())
            } else {
                None
            }
        })
    }

    /// Insert (or replace) `key`'s value, enforcing the size bound. When the
    /// key is new and the cache is full, expired entries are purged first and,
    /// if that does not free a slot, the oldest entry by insertion time is
    /// evicted. Replacing an existing key never evicts.
    pub fn insert(&self, key: K, value: V) {
        if let Ok(mut map) = self.inner.write() {
            if !map.contains_key(&key) && map.len() >= self.max_entries {
                map.retain(|_, e| e.inserted_at.elapsed() < self.ttl);
                if map.len() >= self.max_entries {
                    if let Some(oldest) = map
                        .iter()
                        .min_by_key(|(_, e)| e.inserted_at)
                        .map(|(k, _)| k.clone())
                    {
                        map.remove(&oldest);
                    }
                }
            }
            map.insert(
                key,
                Entry {
                    value,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    /// Remove all expired entries. Called periodically from the SCP main loop.
    pub fn purge_expired(&self) {
        if let Ok(mut map) = self.inner.write() {
            map.retain(|_, e| e.inserted_at.elapsed() < self.ttl);
        }
    }

    /// Number of entries currently held (including any not-yet-purged expired
    /// ones). Primarily for tests and observability.
    pub fn len(&self) -> usize {
        self.inner.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_inserted_value() {
        let cache: BoundedCache<String, u32> = BoundedCache::new(8, Duration::from_secs(60));
        cache.insert("a".into(), 1);
        assert_eq!(cache.get(&"a".to_string()), Some(1));
        assert_eq!(cache.get(&"missing".to_string()), None);
    }

    #[test]
    fn insert_beyond_bound_evicts_oldest() {
        let cache: BoundedCache<u32, u32> = BoundedCache::new(3, Duration::from_secs(60));
        // Insert in order 0,1,2 (0 is oldest), then 3 -> 0 evicted.
        for i in 0..3 {
            cache.insert(i, i);
        }
        assert_eq!(cache.len(), 3);
        cache.insert(3, 3);
        assert_eq!(cache.len(), 3, "the bound is a hard ceiling");
        assert_eq!(cache.get(&0), None, "the oldest entry was evicted");
        assert_eq!(cache.get(&3), Some(3), "the newest entry is present");
    }

    #[test]
    fn replacing_existing_key_never_evicts() {
        let cache: BoundedCache<u32, u32> = BoundedCache::new(2, Duration::from_secs(60));
        cache.insert(1, 10);
        cache.insert(2, 20);
        // Re-insert an existing key at capacity: no eviction, value updated.
        cache.insert(1, 11);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&1), Some(11));
        assert_eq!(cache.get(&2), Some(20));
    }

    #[test]
    fn expired_entries_are_not_returned_and_are_purged() {
        // TTL of zero => every entry is immediately expired (elapsed >= 0),
        // which lets the test assert expiry deterministically without sleeping.
        let cache: BoundedCache<String, u32> = BoundedCache::new(8, Duration::ZERO);
        cache.insert("a".into(), 1);
        assert_eq!(cache.get(&"a".to_string()), None, "expired: get misses");
        assert_eq!(cache.len(), 1, "still occupies a slot until purged");
        cache.purge_expired();
        assert!(cache.is_empty(), "purge_expired reclaims expired entries");
    }

    #[test]
    fn insert_purges_expired_before_evicting_at_capacity() {
        // With a zero TTL and capacity 1, a second insert finds the first entry
        // expired, purges it, and does not need to evict a live entry.
        let cache: BoundedCache<u32, u32> = BoundedCache::new(1, Duration::ZERO);
        cache.insert(1, 1);
        cache.insert(2, 2);
        assert_eq!(cache.len(), 1);
    }
}
