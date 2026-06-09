//! Client-side DNS answer cache.
//!
//! The client can run a local DNS listener that the operating system points at.
//! Repeated lookups (which browsers issue constantly) are answered instantly
//! from this cache instead of crossing the tunnel, which both speeds up browsing
//! and reduces how often a hijacking resolver ever sees the query.
//!
//! Entries expire by TTL and the cache is bounded by capacity with simple
//! least-recently-used eviction. It is safe to share across tasks.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Key identifying a cached answer: lowercase name + query type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
}

impl CacheKey {
    pub fn new(name: &str, qtype: u16) -> Self {
        CacheKey {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            qtype,
        }
    }
}

struct Entry {
    /// The full DNS response payload to return (already wire-encoded answer
    /// section bytes, as produced by the resolver), or raw record bytes — the
    /// caller decides the representation; the cache is agnostic.
    value: Vec<u8>,
    expires_at: Instant,
    last_used: Instant,
}

/// A bounded, TTL-aware DNS cache.
pub struct DnsCache {
    inner: Mutex<HashMap<CacheKey, Entry>>,
    capacity: usize,
}

impl DnsCache {
    /// Create a cache holding up to `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        DnsCache {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Look up a fresh entry, returning its value and refreshing its LRU stamp.
    pub fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let now = Instant::now();
        let mut map = self.inner.lock();
        if let Some(entry) = map.get_mut(key) {
            if entry.expires_at > now {
                entry.last_used = now;
                return Some(entry.value.clone());
            }
            // Expired: remove it.
            map.remove(key);
        }
        None
    }

    /// Insert or replace an entry with the given TTL. A zero TTL is not cached.
    pub fn put(&self, key: CacheKey, value: Vec<u8>, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut map = self.inner.lock();
        if map.len() >= self.capacity && !map.contains_key(&key) {
            Self::evict_one(&mut map, now);
        }
        map.insert(
            key,
            Entry {
                value,
                expires_at: now + ttl,
                last_used: now,
            },
        );
    }

    /// Number of entries currently stored (including not-yet-purged expired ones).
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all expired entries; returns how many were purged.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut map = self.inner.lock();
        let before = map.len();
        map.retain(|_, e| e.expires_at > now);
        before - map.len()
    }

    /// Evict the least-recently-used entry, preferring expired ones.
    fn evict_one(map: &mut HashMap<CacheKey, Entry>, now: Instant) {
        // First try to drop an expired entry.
        if let Some(key) = map
            .iter()
            .find(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
        {
            map.remove(&key);
            return;
        }
        // Otherwise drop the least-recently-used.
        if let Some(key) = map
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone())
        {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_round_trip() {
        let cache = DnsCache::new(10);
        let key = CacheKey::new("Example.COM", 1);
        cache.put(key.clone(), vec![1, 2, 3], Duration::from_secs(60));
        assert_eq!(cache.get(&key), Some(vec![1, 2, 3]));
        // Case-insensitive key normalisation.
        assert_eq!(cache.get(&CacheKey::new("example.com.", 1)), Some(vec![1, 2, 3]));
    }

    #[test]
    fn miss_on_wrong_type() {
        let cache = DnsCache::new(10);
        cache.put(CacheKey::new("a.com", 1), vec![1], Duration::from_secs(60));
        assert_eq!(cache.get(&CacheKey::new("a.com", 28)), None);
    }

    #[test]
    fn expiry() {
        let cache = DnsCache::new(10);
        let key = CacheKey::new("a.com", 1);
        cache.put(key.clone(), vec![1], Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn zero_ttl_not_cached() {
        let cache = DnsCache::new(10);
        let key = CacheKey::new("a.com", 1);
        cache.put(key.clone(), vec![1], Duration::ZERO);
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn capacity_eviction() {
        let cache = DnsCache::new(2);
        cache.put(CacheKey::new("a.com", 1), vec![1], Duration::from_secs(60));
        cache.put(CacheKey::new("b.com", 1), vec![2], Duration::from_secs(60));
        cache.put(CacheKey::new("c.com", 1), vec![3], Duration::from_secs(60));
        assert!(cache.len() <= 2);
    }

    #[test]
    fn purge_expired_counts() {
        let cache = DnsCache::new(10);
        cache.put(CacheKey::new("a.com", 1), vec![1], Duration::from_millis(5));
        cache.put(CacheKey::new("b.com", 1), vec![2], Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(cache.purge_expired(), 1);
        assert_eq!(cache.len(), 1);
    }
}
