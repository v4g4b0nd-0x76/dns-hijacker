use std::{num::NonZeroUsize, sync::Mutex, time::Duration};

use lru::LruCache;
use tokio::net::UdpSocket;

use crate::cache::{
    CacheKey, ResponseCache, cache_key_from_query, cache_lookup, cache_store, clamp_cache_ttl,
};
use crate::constants::{CACHE_TTL_MAX, CACHE_TTL_MIN, DNS_PROBE_PACKET};
use crate::dns::{craft_redirect_response, parse_domain, with_txid};
use crate::domain_trie::{DomainTrie, DomainTriePolicy};
use crate::{empty_cache, mock_query_google};

#[test]
fn clamp_cache_ttl_bounds() {
    assert_eq!(clamp_cache_ttl(1), CACHE_TTL_MIN);
    assert_eq!(clamp_cache_ttl(60), Duration::from_secs(60));
    assert_eq!(clamp_cache_ttl(10_000), CACHE_TTL_MAX);
}

#[test]
fn cache_store_and_lookup_rewrites_txid_on_serve() {
    let cache = empty_cache();
    let query = mock_query_google();
    let key = cache_key_from_query(query).unwrap();
    let (_, qname_end) = parse_domain(query, 12).unwrap();
    let mut answer = craft_redirect_response(query, qname_end, vec!["9.9.9.9"]).unwrap();
    answer[0] = 0x11;
    answer[1] = 0x22;

    cache_store(&cache, key.clone(), &answer);
    let cached = cache_lookup(&cache, &key).expect("cached");
    assert_eq!(&cached[..2], &[0, 0]);
    let served = with_txid(cached, [0xAB, 0xCD]);
    assert_eq!(&served[..2], &[0xAB, 0xCD]);
    assert_eq!(&served[served.len() - 4..], &[9, 9, 9, 9]);
    let _: CacheKey = key;
}

#[test]
fn drop_and_redirect_coexist() {
    let drop_list = vec!["ads.example.com".to_string()];
    let redirect_list = vec![("internal.corp".to_string(), "10.0.0.5,10.0.0.6".to_string())];
    let trie = DomainTrie::build(&drop_list, &redirect_list);

    assert_eq!(trie.lookup("ads.example.com"), &DomainTriePolicy::Drop);
    assert_eq!(
        trie.lookup("tracker.ads.example.com"),
        &DomainTriePolicy::Drop
    );
    assert_eq!(
        trie.lookup("app.internal.corp"),
        &DomainTriePolicy::Redirect(vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()])
    );
    assert_eq!(trie.lookup("unrelated.com"), &DomainTriePolicy::None);
}
