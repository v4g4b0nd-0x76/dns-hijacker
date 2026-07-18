use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aes_gcm::{Aes256Gcm, KeyInit, aead::OsRng};
use lru::LruCache;
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    cache::{
        CacheKey, ResponseCache, cache_key_from_query, cache_lookup, cache_store, clamp_cache_ttl,
    },
    conf::Conf,
    constants::{CACHE_TTL_MAX, CACHE_TTL_MIN, DNS_PROBE_PACKET, RESOLVE_TIMEOUT},
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response, min_answer_ttl, parse_domain, set_ecs_option, with_txid
    },
    handler::{DomainTrie, DomainTriePolicy, HandleQueryParams, handle_query},
    relay::{RelayInstance, RelayPicker},
    resolver::{ResolverPicker, create_resolver},
};

fn empty_cache() -> ResponseCache {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(16).expect("cache capacity"),
    ))
}

fn mock_query_google() -> &'static [u8] {
    DNS_PROBE_PACKET
}

fn mock_query_foo_test_com() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'f', b'o',
        b'o', 0x04, b't', b'e', b's', b't', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

fn mock_query_blocked_example() -> Vec<u8> {
    vec![
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'b', b'l',
        b'o', b'c', b'k', b'e', b'd', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
        b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

/// Small wrapper around `handle_query` that builds the `HandleQueryParams`
/// struct for tests that don't exercise the relay path (relay_picker: None),
/// so call sites below don't repeat the struct literal every time.
async fn call_handle_query(
    payload: &[u8],
    src_addr: SocketAddr,
    rule_trie: &Arc<DomainTrie>,
    resolver_picker: &ResolverPicker,
    server_socket: &UdpSocket,
    http: &reqwest::Client,
    cache: &ResponseCache,
) {
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("failed to bind udp socket"),
    );
    let params = HandleQueryParams {
        payload,
        src_addr,
        rule_trie,
        resolver_picker,
        server_socket,
        http,
        cache,
        relay_picker: None,
        socket: &socket,
    };
    handle_query(&params).await;
}

/// Builds a `DomainTrie` directly from a `Conf`'s drop_list/redirect_list,
/// matching what `main.rs`/`watch_conf_and_reload` do on load/reload.
fn trie_from_conf(conf: &Conf) -> Arc<DomainTrie> {
    Arc::new(DomainTrie::build(&conf.drop_list, &conf.redirect_list))
}

#[test]
fn parse_domain_from_mock_probe() {
    let (domain, qname_end) = parse_domain(mock_query_google(), 12).expect("parse");
    assert_eq!(domain, "google.com");
    assert_eq!(qname_end, 12 + 1 + 6 + 1 + 3 + 1);
}

#[test]
fn parse_domain_rejects_truncated() {
    assert!(parse_domain(&[0u8; 8], 12).is_none());
    let truncated = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05, b'a', b'b'];
    assert!(parse_domain(&truncated, 12).is_none());
}

#[test]
fn trie_matches_exact_and_wildcard_patterns() {
    // Replaces the old matches_domain_pattern-based test now that pattern
    // matching lives inside DomainTrie::lookup rather than a standalone fn.
    let drop_list = vec!["*.example.com".to_string()];
    let trie = DomainTrie::build(&drop_list, &[]);

    assert_eq!(trie.lookup("example.com"), &DomainTriePolicy::Drop);
    assert_eq!(trie.lookup("a.example.com"), &DomainTriePolicy::Drop);
    assert_eq!(trie.lookup("deep.sub.example.com"), &DomainTriePolicy::Drop);
    assert_eq!(trie.lookup("notexample.com"), &DomainTriePolicy::None);
    assert_eq!(trie.lookup("google.com"), &DomainTriePolicy::None);
}

#[test]
fn trie_redirect_carries_ip_list() {
    let redirect_list = vec![(
        "*.test.com".to_string(),
        "192.168.1.1,192.168.1.2".to_string(),
    )];
    let trie = DomainTrie::build(&[], &redirect_list);

    assert_eq!(
        trie.lookup("foo.test.com"),
        &DomainTriePolicy::Redirect(vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()])
    );
    assert_eq!(trie.lookup("other.com"), &DomainTriePolicy::None);
}

#[test]
fn craft_nxdomain_sets_rcode() {
    let resp = craft_nxdomain_response(mock_query_google()).expect("nxdomain");
    assert_eq!(resp[2], 0x81);
    assert_eq!(resp[3], 0x83);
    assert_eq!(&resp[12..], &mock_query_google()[12..]);
}

#[test]
fn craft_servfail_sets_rcode() {
    let resp = craft_servfail_response(mock_query_google()).expect("servfail");
    assert_eq!(resp[2], 0x81);
    assert_eq!(resp[3], 0x82);
}

#[test]
fn craft_redirect_appends_a_record() {
    let query = mock_query_foo_test_com();
    let (_, qname_end) = parse_domain(&query, 12).expect("parse");
    let resp = craft_redirect_response(&query, qname_end, vec!["192.168.1.1", "192.168.1.2"])
        .expect("redirect");

    assert_eq!(resp[6], 0x00);
    assert_eq!(resp[7], 2);

    assert_eq!(&resp[resp.len() - 4..], &[192, 168, 1, 2]);
    assert_eq!(&resp[resp.len() - 6..resp.len() - 4], &[0x00, 0x04]);

    let record_len = 16;
    let first_record_start = resp.len() - (record_len * 2);
    let first_rdata = &resp[first_record_start + 12..first_record_start + 16];
    assert_eq!(first_rdata, &[192, 168, 1, 1]);
}

#[test]
fn set_ecs_option_skips_loopback_by_default() {
    // With `None`, loopback/test clients get no ECS added at all - this is
    // the new safer default, replacing the old hardcoded 127.x -> 8.8.8.8 remap.
    let query = mock_query_google().to_vec();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53000);
    let result = set_ecs_option(&query, client, None).expect("should return Some(unchanged)");
    assert_eq!(result, query);
}

#[test]
fn set_ecs_option_fabricates_loopback_ip_when_opted_in() {
    // Passing Some(fake_ip) is the explicit opt-in path for testing ECS
    // behavior against loopback clients, replacing the old silent 8.8.8.8 hardcode.
    let query = mock_query_google().to_vec();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53000);
    let modified = set_ecs_option(&query, client, Some([203, 0, 113, 0])).expect("ecs");

    let old_ar = ((query[10] as u16) << 8) | query[11] as u16;
    let new_ar = ((modified[10] as u16) << 8) | modified[11] as u16;
    assert_eq!(new_ar, old_ar + 1);
    assert!(modified.len() > query.len());
    // ECS data ends with the truncated /24 octets (first 3 of the 4 given).
    assert!(modified.ends_with(&[203, 0, 113]));
}

#[test]
fn set_ecs_option_rewrites_real_client_ip() {
    // A non-loopback client should always get its actual subnet, regardless
    // of the fabricate_public_ip_for_loopback setting.
    let query = mock_query_google().to_vec();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 53000);
    let modified = set_ecs_option(&query, client, None).expect("ecs");

    let old_ar = ((query[10] as u16) << 8) | query[11] as u16;
    let new_ar = ((modified[10] as u16) << 8) | modified[11] as u16;
    assert_eq!(new_ar, old_ar + 1);
    assert!(modified.ends_with(&[198, 51, 100]));
}

#[test]
fn set_ecs_option_skips_ipv6_clients() {
    let query = mock_query_google().to_vec();
    let client: SocketAddr = "[::1]:53000".parse().unwrap();
    assert!(set_ecs_option(&query, client, None).is_none());
}

#[test]
fn with_txid_rewrites_header_id() {
    let packet = mock_query_google().to_vec();
    let rewritten = with_txid(packet, [0xBE, 0xEF]);
    assert_eq!(&rewritten[..2], &[0xBE, 0xEF]);
}

#[test]
fn clamp_cache_ttl_bounds() {
    assert_eq!(clamp_cache_ttl(1), CACHE_TTL_MIN);
    assert_eq!(clamp_cache_ttl(60), Duration::from_secs(60));
    assert_eq!(clamp_cache_ttl(10_000), CACHE_TTL_MAX);
}

#[test]
fn min_answer_ttl_from_redirect_packet() {
    let query = mock_query_google().to_vec();
    let (_, qname_end) = parse_domain(&query, 12).unwrap();
    let resp = craft_redirect_response(&query, qname_end, vec!["1.2.3.4"]).unwrap();
    assert_eq!(min_answer_ttl(&resp), Some(60));
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

#[tokio::test]
async fn integration_redirect_and_drop_over_udp() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let cache = empty_cache();

    let conf = Conf {
        drop_list: vec!["*.example.com".into()],
        redirect_list: vec![("*.test.com".into(), "192.168.1.1".into())],
        resolvers: vec!["127.0.0.1:9".into()],
        ..Default::default()
    };
    let rule_trie = trie_from_conf(&conf);

    let picker = ResolverPicker::from_healthy(vec![create_resolver("127.0.0.1:9")]);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let redirect_query = mock_query_foo_test_com();
    client.send_to(&redirect_query, server_addr).await.unwrap();
    let mut buf = [0u8; 512];
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    call_handle_query(
        &buf[..len],
        src,
        &rule_trie,
        &picker,
        &server,
        &http,
        &cache,
    )
    .await;

    let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
    assert!(resp_len > redirect_query.len());
    assert_eq!(buf[7], 1);
    assert_eq!(&buf[resp_len - 4..resp_len], &[192, 168, 1, 1]);

    let drop_query = mock_query_blocked_example();
    client.send_to(&drop_query, server_addr).await.unwrap();
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    call_handle_query(
        &buf[..len],
        src,
        &rule_trie,
        &picker,
        &server,
        &http,
        &cache,
    )
    .await;

    let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
    assert_eq!(resp_len, drop_query.len());
    assert_eq!(buf[3], 0x83);
}

#[tokio::test]
async fn integration_udp_upstream_echo() {
    let upstream_mock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_mock.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, src) = upstream_mock.recv_from(&mut buf).await.unwrap();
        let (_, qname_end) = parse_domain(&buf[..len], 12).unwrap();
        let answer = craft_redirect_response(&buf[..len], qname_end, vec!["8.8.4.4"]).unwrap();
        let _ = upstream_mock.send_to(&answer, src).await;
    });

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let cache = empty_cache();

    let conf = Conf {
        drop_list: vec![],
        redirect_list: vec![],
        resolvers: vec![upstream_addr.to_string()],
        ..Default::default()
    };
    let rule_trie = trie_from_conf(&conf);

    let picker = ResolverPicker::from_healthy(vec![create_resolver(&upstream_addr.to_string())]);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let query = mock_query_google().to_vec();
    client.send_to(&query, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    call_handle_query(
        &buf[..len],
        src,
        &rule_trie,
        &picker,
        &server,
        &http,
        &cache,
    )
    .await;

    let (resp_len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("client response timeout")
        .unwrap();
    assert_eq!(&buf[resp_len - 4..resp_len], &[8, 8, 4, 4]);
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn integration_cache_hit_skips_upstream() {
    let upstream_mock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_mock.local_addr().unwrap();
    let hit_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits = Arc::clone(&hit_count);
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, src) = upstream_mock.recv_from(&mut buf).await.unwrap();
        hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (_, qname_end) = parse_domain(&buf[..len], 12).unwrap();
        let answer = craft_redirect_response(&buf[..len], qname_end, vec!["1.1.1.1"]).unwrap();
        let _ = upstream_mock.send_to(&answer, src).await;
        let _ = timeout(
            Duration::from_millis(200),
            upstream_mock.recv_from(&mut buf),
        )
        .await;
    });

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let cache = empty_cache();
    let conf = Conf {
        drop_list: vec![],
        redirect_list: vec![],
        resolvers: vec![upstream_addr.to_string()],
        ..Default::default()
    };
    let rule_trie = trie_from_conf(&conf);

    let picker = ResolverPicker::from_healthy(vec![create_resolver(&upstream_addr.to_string())]);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let mut buf = [0u8; 512];

    let mut q1 = mock_query_google().to_vec();
    q1[0] = 0x01;
    q1[1] = 0x01;
    client.send_to(&q1, server_addr).await.unwrap();
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    call_handle_query(
        &buf[..len],
        src,
        &rule_trie,
        &picker,
        &server,
        &http,
        &cache,
    )
    .await;
    let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..2], &[0x01, 0x01]);
    assert_eq!(&buf[resp_len - 4..resp_len], &[1, 1, 1, 1]);

    let mut q2 = mock_query_google().to_vec();
    q2[0] = 0x02;
    q2[1] = 0x02;
    client.send_to(&q2, server_addr).await.unwrap();
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    call_handle_query(
        &buf[..len],
        src,
        &rule_trie,
        &picker,
        &server,
        &http,
        &cache,
    )
    .await;
    let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..2], &[0x02, 0x02]);
    assert_eq!(&buf[resp_len - 4..resp_len], &[1, 1, 1, 1]);

    upstream_task.await.unwrap();
    assert_eq!(hit_count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn integration_resolve_timeout_returns_servfail() {
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let cache = empty_cache();

    let conf = Conf {
        drop_list: vec![],
        redirect_list: vec![],
        resolvers: vec![blackhole_addr.to_string()],
        ..Default::default()
    };
    let rule_trie = trie_from_conf(&conf);

    let picker = ResolverPicker::from_healthy(vec![create_resolver(&blackhole_addr.to_string())]);
    let http = reqwest::Client::builder()
        .timeout(RESOLVE_TIMEOUT)
        .build()
        .unwrap();

    let query = mock_query_google().to_vec();
    client.send_to(&query, server_addr).await.unwrap();
    let mut buf = [0u8; 512];
    let (len, src) = server.recv_from(&mut buf).await.unwrap();

    let started = Instant::now();
    call_handle_query(
        &buf[..len],
        src,
        &rule_trie,
        &picker,
        &server,
        &http,
        &cache,
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= RESOLVE_TIMEOUT && elapsed < RESOLVE_TIMEOUT + Duration::from_secs(1),
        "elapsed={elapsed:?}"
    );

    let (resp_len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .expect("servfail response")
        .unwrap();
    assert_eq!(resp_len, query.len());
    assert_eq!(buf[3], 0x82);
}

// --- RelayPicker tests ---
//
// These use `RelayInstance::for_test` / `RelayPicker::from_instances`
// (test-only constructors) rather than `RelayPicker::new`, since the real
// constructor performs network resolution per instance and isn't suitable
// for unit tests. This lets us test the round-robin selection logic and
// the empty-instances guard in isolation.

fn test_key() -> aes_gcm::Key<Aes256Gcm> {
    Aes256Gcm::generate_key(OsRng)
}

#[test]
fn relay_picker_round_robins_across_instances() {
    let instances = vec![
        RelayInstance::for_test("https://relay-a.example.workers.dev", test_key()),
        RelayInstance::for_test("https://relay-b.example.workers.dev", test_key()),
        RelayInstance::for_test("https://relay-c.example.workers.dev", test_key()),
    ];
    let picker = RelayPicker::from_instances(instances);

    let urls: Vec<&str> = (0..6).map(|_| picker.pick().url()).collect();

    // Expect a clean repeating cycle over the 3 instances, in order.
    assert_eq!(
        urls,
        vec![
            "https://relay-a.example.workers.dev",
            "https://relay-b.example.workers.dev",
            "https://relay-c.example.workers.dev",
            "https://relay-a.example.workers.dev",
            "https://relay-b.example.workers.dev",
            "https://relay-c.example.workers.dev",
        ]
    );
}

#[test]
fn relay_picker_single_instance_always_returns_it() {
    let instances = vec![RelayInstance::for_test(
        "https://only.example.workers.dev",
        test_key(),
    )];
    let picker = RelayPicker::from_instances(instances);

    for _ in 0..5 {
        assert_eq!(picker.pick().url(), "https://only.example.workers.dev");
    }
}

#[tokio::test]
async fn relay_picker_new_rejects_empty_instances() {
    // RelayPicker::new checks for an empty instance list before attempting
    // any network resolution, so this should fail fast without needing a
    // reachable resolver or relay host.
    let conf = crate::conf::RelayConf {
        enable: true,
        relay_instances: vec![],
        ..Default::default()
    };
    let picker = ResolverPicker::from_healthy(vec![create_resolver("127.0.0.1:9")]);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("failed to bind socket"),
    );

    let result = RelayPicker::new(&conf, &picker, &http, &socket).await;
    assert!(result.is_err());
}
