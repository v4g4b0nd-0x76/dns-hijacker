use std::{
    num::NonZeroUsize,
    sync::Mutex,
    time::{Duration, Instant},
};

use lru::LruCache;

use crate::{
    constants::{CACHE_CAPACITY, CACHE_TTL_FALLBACK, CACHE_TTL_MAX, CACHE_TTL_MIN},
    dns::{min_answer_ttl, parse_domain},
};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
}

pub struct CacheEntry {
    pub packet: Vec<u8>,
    pub expires_at: Instant,
}

pub type ResponseCache = Mutex<LruCache<CacheKey, CacheEntry>>;

pub fn new_cache() -> ResponseCache {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(CACHE_CAPACITY).expect("cache capacity > 0"),
    ))
}

pub fn cache_key_from_query(payload: &[u8]) -> Option<CacheKey> {
    let (name, qname_end) = parse_domain(payload, 12)?;
    if qname_end + 2 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[qname_end], payload[qname_end + 1]]);
    Some(CacheKey { name, qtype })
}

pub fn clamp_cache_ttl(ttl_secs: u32) -> Duration {
    let ttl = Duration::from_secs(u64::from(ttl_secs));
    if ttl < CACHE_TTL_MIN {
        CACHE_TTL_MIN
    } else if ttl > CACHE_TTL_MAX {
        CACHE_TTL_MAX
    } else {
        ttl
    }
}

pub fn cache_lookup(cache: &ResponseCache, key: &CacheKey) -> Option<Vec<u8>> {
    let mut guard = cache.lock().ok()?;
    let entry = guard.get(key)?;
    if Instant::now() >= entry.expires_at {
        guard.pop(key);
        return None;
    }
    Some(entry.packet.clone())
}

pub fn cache_store(cache: &ResponseCache, key: CacheKey, packet: &[u8]) {
    let ttl = min_answer_ttl(packet)
        .map(clamp_cache_ttl)
        .unwrap_or(CACHE_TTL_FALLBACK);
    let mut stored = packet.to_vec();
    if stored.len() >= 2 {
        stored[0] = 0;
        stored[1] = 0;
    }
    if let Ok(mut guard) = cache.lock() {
        guard.put(
            key,
            CacheEntry {
                packet: stored,
                expires_at: Instant::now() + ttl,
            },
        );
    }
}
