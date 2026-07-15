use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use lru::LruCache;
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    cache::{
        CacheKey, ResponseCache, cache_key_from_query, cache_lookup, cache_store, clamp_cache_ttl,
    },
    conf::{Conf, RelayConf},
    constants::{CACHE_TTL_MAX, CACHE_TTL_MIN, DNS_PROBE_PACKET, RESOLVE_TIMEOUT},
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response,
        inject_ecs_option, matches_domain_pattern, min_answer_ttl, parse_domain, with_txid,
    },
    handler::handle_query,
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
fn matches_exact_and_wildcard_patterns() {
    assert!(matches_domain_pattern("google.com", "google.com"));
    assert!(matches_domain_pattern("a.example.com", "*.example.com"));
    assert!(matches_domain_pattern("example.com", "*.example.com"));
    assert!(!matches_domain_pattern("notexample.com", "*.example.com"));
    assert!(!matches_domain_pattern("google.com", "example.com"));
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
    assert_eq!(&resp[resp.len() - 6..resp.len() - 4], &[0x00, 0x04]); // RDLENGTH = 4

    let record_len = 16;
    let first_record_start = resp.len() - (record_len * 2);
    let first_rdata = &resp[first_record_start + 12..first_record_start + 16];
    assert_eq!(first_rdata, &[192, 168, 1, 1]);
}

#[test]
fn inject_ecs_rewrites_loopback_and_bumps_arcount() {
    let query = mock_query_google().to_vec();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53000);
    let modified = inject_ecs_option(&query, client).expect("ecs");

    let old_ar = ((query[10] as u16) << 8) | query[11] as u16;
    let new_ar = ((modified[10] as u16) << 8) | modified[11] as u16;
    assert_eq!(new_ar, old_ar + 1);
    assert!(modified.len() > query.len());
    assert!(modified.ends_with(&[8, 8, 8]));
}

#[test]
fn inject_ecs_skips_ipv6_clients() {
    let query = mock_query_google().to_vec();
    let client: SocketAddr = "[::1]:53000".parse().unwrap();
    assert!(inject_ecs_option(&query, client).is_none());
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
    let redirect_list = Arc::new(conf.redirect_list.clone());
    let drop_list = Arc::new(conf.drop_list.clone());

    let picker = ResolverPicker::from_healthy(vec![create_resolver("127.0.0.1:9")]);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let redirect_query = mock_query_foo_test_com();
    client.send_to(&redirect_query, server_addr).await.unwrap();
    let mut buf = [0u8; 512];
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    handle_query(
        &buf[..len],
        src,
        &Arc::new(conf.redirect_list),
        &Arc::new(conf.drop_list),
        &picker,
        &server,
        &http,
        &cache,
        &RelayConf::default(),
    )
    .await;

    let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
    assert!(resp_len > redirect_query.len());
    assert_eq!(buf[7], 1);
    assert_eq!(&buf[resp_len - 4..resp_len], &[192, 168, 1, 1]);

    let drop_query = mock_query_blocked_example();
    client.send_to(&drop_query, server_addr).await.unwrap();
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    handle_query(
        &buf[..len],
        src,
        &redirect_list,
        &drop_list,
        &picker,
        &server,
        &http,
        &cache,
        &RelayConf::default(),
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
    let redirect_list = Arc::new(conf.redirect_list.clone());
    let drop_list = Arc::new(conf.drop_list.clone());

    let picker = ResolverPicker::from_healthy(vec![create_resolver(&upstream_addr.to_string())]);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let query = mock_query_google().to_vec();
    client.send_to(&query, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, src) = server.recv_from(&mut buf).await.unwrap();
    handle_query(
        &buf[..len],
        src,
        &redirect_list,
        &drop_list,
        &picker,
        &server,
        &http,
        &cache,
        &RelayConf::default(),
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
    let redirect_list = Arc::new(conf.redirect_list.clone());
    let drop_list = Arc::new(conf.drop_list.clone());

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
    handle_query(
        &buf[..len],
        src,
        &redirect_list,
        &drop_list,
        &picker,
        &server,
        &http,
        &cache,
        &RelayConf::default(),
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
    handle_query(
        &buf[..len],
        src,
        &redirect_list,
        &drop_list,
        &picker,
        &server,
        &http,
        &cache,
        &RelayConf::default(),
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
    let redirect_list = Arc::new(conf.redirect_list.clone());
    let drop_list = Arc::new(conf.drop_list.clone());

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
    handle_query(
        &buf[..len],
        src,
        &redirect_list,
        &drop_list,
        &picker,
        &server,
        &http,
        &cache,
        &RelayConf::default(),
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
