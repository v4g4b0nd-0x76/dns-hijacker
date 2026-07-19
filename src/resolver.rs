use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, LazyLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval, timeout},
};

use crate::{
    conf::ResolverSearchingConf,
    constants::{
        DNS_PROBE_PACKET, DOH_CONNECT_TIMEOUT, RESOLVE_TIMEOUT, SEARCH_RESOLVER_INTERVAL,
        UDP_PROBE_TIMEOUT,
    },
    dns::{build_lookup_query, parse_a_records, set_ecs_option},
    errors::{DohError, Error},
    helpers::get_public_ip
};
use tracing::{debug, error, info, warn};

const HEALTH_CHECK_CONCURRENCY: usize = 100;
const SOURCE_FETCH_CONCURRENCY: usize = 8;
const MAX_HEALTHY_RESOLVERS: usize = 256;
const FAILED_RESOLVER_CAP: usize = 4096;
const FAILED_RESOLVER_FLUSH_INTERVAL: Duration = Duration::from_secs(3600);

/// Run `f` over `items` with at most `limit` tasks in flight (no futures-rs needed).
async fn collect_concurrent<I, T, F, Fut, R>(items: I, limit: usize, f: F) -> Vec<R>
where
    I: IntoIterator<Item = T>,
    F: Fn(T) -> Fut,
    Fut: Future<Output = R> + Send + 'static,
    T: Send + 'static,
    R: Send + 'static,
{
    let sem = Arc::new(Semaphore::new(limit.max(1)));
    let mut set = JoinSet::new();

    for item in items {
        let sem = Arc::clone(&sem);
        let fut = f(item);
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return None;
            };
            Some(fut.await)
        });
    }

    let mut out = Vec::with_capacity(set.len());
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(value)) = joined {
            out.push(value);
        }
    }
    out
}

struct FailedResolverSet {
    set: HashSet<String>,
    flushed_at: Instant,
}

static FAILED_RESOLVERS: LazyLock<RwLock<FailedResolverSet>> = LazyLock::new(|| {
    RwLock::new(FailedResolverSet {
        set: HashSet::with_capacity(256),
        flushed_at: Instant::now(),
    })
});

fn is_failed_resolver(resolver: &str) -> bool {
    FAILED_RESOLVERS
        .read()
        .map(|g| g.set.contains(resolver))
        .unwrap_or(false)
}

fn record_failed_resolver(resolver: String) {
    let Ok(mut guard) = FAILED_RESOLVERS.write() else {
        return;
    };

    if guard.flushed_at.elapsed() >= FAILED_RESOLVER_FLUSH_INTERVAL {
        info!(
            "[PICKER] flushing {} failed resolvers after 1h window",
            guard.set.len()
        );
        guard.set.clear();
        guard.flushed_at = Instant::now();
    }

    if guard.set.len() >= FAILED_RESOLVER_CAP {
        return;
    }
    guard.set.insert(resolver);
}

pub type Resolver = (String, Duration); // address - delay
#[derive(Clone)]
pub struct ResolverPicker {
    healthy_resolvers: Arc<RwLock<Vec<Resolver>>>,
}

impl ResolverPicker {
    pub async fn new(
        resolvers: Vec<String>,
        http: reqwest::Client,
        socket: &Arc<UdpSocket>,
    ) -> Result<Self, Error> {
        let sorted_resolvers = test_resolvers(resolvers, http, socket).await?;

        Ok(Self {
            healthy_resolvers: Arc::new(RwLock::new(sorted_resolvers)),
        })
    }

    /// Construct a picker that skips health checks (used by tests).
    pub fn from_healthy(resolvers: Vec<Resolver>) -> Self {
        Self {
            healthy_resolvers: Arc::new(RwLock::new(resolvers)),
        }
    }
    pub fn healthy_resolvers(&self) -> Arc<RwLock<Vec<Resolver>>> {
        self.healthy_resolvers.clone()
    }
    #[cfg(test)]
    fn select_resolver(&self, resolver: Option<String>) -> String {
        resolver
            .map(|r| normalize_resolver(&r))
            .unwrap_or_else(|| self.pick())
    }

    pub fn pick(&self) -> String {
        let healthy_resolvers = self.healthy_resolvers.read().unwrap();
        healthy_resolvers[0].clone().0
    }
    pub async fn resolve(
        &self,
        domain: &str,
        resolver: Option<String>,
        http: &reqwest::Client,
        socket: &UdpSocket,
    ) -> Result<Vec<Ipv4Addr>, Error> {
        let resolver = resolver
            .map(|r| normalize_resolver(&r))
            .unwrap_or_else(|| self.pick());
        let public_ip = get_public_ip(http)
            .await
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(185, 143, 233, 5))); // this ip is for iran so its a
        // close fallback
        let src_addr = SocketAddr::new(public_ip, 0);
        let query = build_lookup_query(domain);
        let (reply, _len) =
            resolve_from_upstream(&query, &resolver, src_addr, http, socket).await?;
        let ips = parse_a_records(&reply);
        Ok(ips)
    }
}

pub fn build_http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(RESOLVE_TIMEOUT)
        .connect_timeout(DOH_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| Error::Config(format!("failed to build HTTP client: {err}")))
}

#[inline(always)]
pub async fn resolve_from_upstream(
    payload: &[u8],
    upstream_resolver: &str,
    src_addr: SocketAddr,
    http: &reqwest::Client,
    upstream_socket: &UdpSocket,
) -> Result<(Vec<u8>, usize), Error> {
    let final_payload = set_ecs_option(payload, src_addr, None).unwrap_or_else(|| payload.to_vec());

    if upstream_resolver.starts_with("https://") {
        return resolve_via_doh(http, upstream_resolver, &final_payload).await;
    }

    let upstream_addr: SocketAddr = upstream_resolver
        .parse()
        .map_err(|_| Error::InvalidResolver(upstream_resolver.to_owned()))?;

    upstream_socket
        .send_to(&final_payload, upstream_addr)
        .await?;

    let mut reply_buf = [0u8; 4096];
    let (reply_len, _) = timeout(RESOLVE_TIMEOUT, upstream_socket.recv_from(&mut reply_buf))
        .await
        .map_err(|_| Error::ResolveTimeout)?
        .map_err(Error::from)?;

    Ok((reply_buf[..reply_len].to_vec(), reply_len))
}

pub async fn resolve_via_doh(
    http: &reqwest::Client,
    url: &str,
    payload: &[u8],
) -> Result<(Vec<u8>, usize), Error> {
    let response = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(payload.to_vec())
        .send()
        .await
        .map_err(DohError::Request)?;

    if !response.status().is_success() {
        return Err(DohError::Status(response.status()).into());
    }

    let body_bytes = response.bytes().await.map_err(DohError::Body)?;
    let reply_len = body_bytes.len();
    Ok((body_bytes.to_vec(), reply_len))
}

async fn test_resolvers(
    resolvers: Vec<String>,
    http: reqwest::Client,
    socket: &Arc<UdpSocket>,
) -> Result<Vec<Resolver>, Error> {
    let mut results: Vec<(String, Duration)> =
        collect_concurrent(resolvers, HEALTH_CHECK_CONCURRENCY, move |resolver| {
            let http = http.clone();
            let socket = socket.clone();
            async move {
                let socket = socket.clone();
                match measure_latency(&resolver, &http, &socket).await {
                    Ok(latency) => {
                        debug!("[PICKER LOG] {} responded in {:?}", resolver, latency);
                        Some((resolver, latency))
                    }
                    Err(e) => {
                        debug!("[PICKER WARN] {} failed health check: {}", resolver, e);
                        None
                    }
                }
            }
        })
        .await
        .into_iter()
        .flatten()
        .collect();

    if results.is_empty() {
        return Err(Error::NoHealthyResolvers);
    }

    results.sort_unstable_by_key(|&(_, latency)| latency);
    let sorted_resolvers: Vec<Resolver> = results.into_iter().collect();

    info!(
        "[PICKER] Healthy upstreams discovered and sorted: {:?}",
        sorted_resolvers
    );
    Ok(sorted_resolvers)
}

async fn measure_latency(
    resolver: &str,
    http: &reqwest::Client,
    socket: &Arc<UdpSocket>,
) -> Result<Duration, Error> {
    let start = Instant::now();

    if resolver.starts_with("https://") {
        let req_future = http
            .post(resolver)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(DNS_PROBE_PACKET)
            .send();

        let response = match timeout(RESOLVE_TIMEOUT, req_future).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => return Err(DohError::Request(err).into()),
            Err(_) => return Err(DohError::Timeout.into()),
        };

        if !response.status().is_success() {
            return Err(DohError::Status(response.status()).into());
        }

        let _ = response.bytes().await.map_err(DohError::Body)?;
        return Ok(start.elapsed());
    }

    let addr: SocketAddr = resolver
        .parse()
        .map_err(|_| Error::InvalidResolver(resolver.to_owned()))?;

    socket.send_to(DNS_PROBE_PACKET, addr).await?;

    let mut buf = [0u8; 512];
    match timeout(UDP_PROBE_TIMEOUT, socket.recv_from(&mut buf)).await {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err(Error::UdpTimeout),
    }
}

pub async fn run_resolver_finder(
    resolver_searching: ResolverSearchingConf,
    healthy_resolvers: Arc<RwLock<Vec<Resolver>>>,
    is_searching: Arc<AtomicBool>,
) -> Result<(), Error> {
    let mut tick = interval(Duration::from_secs(
        resolver_searching
            .resfresh_interval
            .unwrap_or(SEARCH_RESOLVER_INTERVAL),
    ));
    // Missed ticks delay instead of bursting catch-up work onto the runtime.
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let sources = resolver_searching.resolver_source;
    let keep_ipv4 = resolver_searching.ipv4;
    let keep_doh = resolver_searching.doh;
    // Client is Arc-backed internally; no extra Arc wrapper needed.
    let http = build_http_client()?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // RAII guard: flips the flag back to false on ANY exit from the loop body
    // (early `continue`, early `return`, or panic), not just the "happy path".
    struct SearchGuard(Arc<AtomicBool>);
    impl Drop for SearchGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    loop {
        // Wait for the tick BEFORE checking the flag, so a busy cycle doesn't
        // turn the "already searching" branch into a hot spin loop.
        tick.tick().await;

        if is_searching
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            warn!("there is already a search in progress, skipping this tick");
            continue;
        }
        let _guard = SearchGuard(is_searching.clone());

        info!("searching for new resolvers from provided sources");
        let discovery_start = Instant::now();

        let fetched: Vec<Vec<String>> = collect_concurrent(
            sources.iter().cloned(),
            SOURCE_FETCH_CONCURRENCY.min(sources.len().max(1)),
            |addr| {
                let http = http.clone();
                async move {
                    match fetch_resolvers_from_addr(&addr, &http, keep_ipv4, keep_doh).await {
                        Ok(list) => list,
                        Err(err) => {
                            error!("failed to fetch resolvers from {}: {}", addr, err);
                            Vec::new()
                        }
                    }
                }
            },
        )
        .await;

        let mut candidates: HashSet<String> = HashSet::new();
        for batch in fetched {
            for resolver in batch {
                if !is_failed_resolver(&resolver) {
                    candidates.insert(resolver);
                }
            }
        }
        if let Ok(guard) = healthy_resolvers.read() {
            for known in guard.iter() {
                candidates.remove(&known.0.to_string());
            }
        }

        if candidates.is_empty() {
            info!("[PICKER] no new resolver candidates this cycle");
            continue;
        }

        let mut results: Vec<(String, Duration)> =
            collect_concurrent(candidates, HEALTH_CHECK_CONCURRENCY, |resolver| {
                let socket = socket.clone();
                let http = http.clone();
                async move {
                    match measure_latency(&resolver, &http, &socket).await {
                        Ok(latency) => {
                            debug!("[PICKER LOG] {} responded in {:?}", resolver, latency);
                            Some((resolver, latency))
                        }
                        Err(e) => {
                            debug!("[PICKER WARN] {} failed health check: {}", resolver, e);
                            record_failed_resolver(resolver);
                            None
                        }
                    }
                }
            })
            .await
            .into_iter()
            .flatten()
            .collect();

        if results.is_empty() {
            info!("[PICKER] no healthy resolvers discovered this cycle");
            continue;
        }

        results.sort_unstable_by_key(|&(_, latency)| latency);
        let discovered: Vec<Resolver> = results.into_iter().collect();
        info!(
            "[PICKER] discovered {} new healthy resolvers in {}/ms",
            discovered.len(),
            discovery_start.elapsed().as_millis()
        );

        if let Ok(mut guard) = healthy_resolvers.write() {
            merge_discovered_into_healthy(&mut guard, discovered, MAX_HEALTHY_RESOLVERS);
        }
    }
}

fn merge_discovered_into_healthy(
    healthy: &mut Vec<Resolver>,
    discovered: Vec<Resolver>,
    max_len: usize,
) {
    let existing: HashSet<&str> = healthy.iter().map(|(addr, _)| addr.as_str()).collect();
    let mut prepend = Vec::with_capacity(discovered.len());
    for resolver in discovered {
        if !existing.contains(resolver.0.as_str()) {
            prepend.push(resolver);
        }
    }
    if prepend.is_empty() {
        return;
    }
    prepend.append(healthy);
    if prepend.len() > max_len {
        prepend.truncate(max_len);
    }
    *healthy = prepend;
}

async fn fetch_resolvers_from_addr(
    addr: &str,
    http: &reqwest::Client,
    keep_ipv4: bool,
    keep_doh: bool,
) -> Result<Vec<String>, Error> {
    let resp = http
        .get(addr)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map_err(|err| Error::Config(format!("failed to fetch from {addr}: {err}")))?;

    if !resp.status().is_success() {
        return Err(Error::Config(String::from(
            "None successfull http response",
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|err| Error::Config(format!("failed to read response body: {err}")))?;

    Ok(parse_resolver_list(&body, keep_ipv4, keep_doh))
}

fn parse_resolver_list(body: &str, keep_ipv4: bool, keep_doh: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(256);
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(entry) = classify_line(line, keep_ipv4, keep_doh) {
            out.push(entry);
        }
    }
    out
}

#[inline(always)]
fn classify_line(line: &str, keep_ipv4: bool, keep_doh: bool) -> Option<String> {
    if line.starts_with("https://") {
        return keep_doh.then(|| line.to_string());
    }

    // Plain IP lines: may be "ip" or "ip:port"
    let ip_part = line.split(':').next().unwrap_or(line);

    match IpAddr::from_str(ip_part) {
        Ok(IpAddr::V4(_)) => {
            if !keep_ipv4 {
                return None;
            }
            // Normalize to ip:port so downstream SocketAddr::parse always succeeds.
            if line.contains(':') {
                Some(line.to_string())
            } else {
                Some(format!("{line}:53"))
            }
        }
        Ok(IpAddr::V6(_)) => None, // explicitly excluded regardless of flags
        Err(_) => None,            // not a parseable IP or URL, skip
    }
}
fn normalize_resolver(resolver: &str) -> String {
    if resolver.starts_with("https://") || resolver.starts_with("http://") {
        return resolver.to_string();
    }

    if resolver.contains(':') {
        resolver.to_string()
    } else {
        format!("{resolver}:53")
    }
}
pub fn create_resolver(addr: &str) -> Resolver {
    (addr.to_string(), Duration::from_secs(0))
}
pub fn resolvers_to_addrs(resolvers: &[Resolver]) -> Vec<&str> {
    resolvers.iter().map(|(addr, _)| addr.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    #[test]
    fn classify_line_respects_ipv4_and_doh_flags() {
        assert_eq!(
            classify_line("1.1.1.1:53", true, false).as_deref(),
            Some("1.1.1.1:53")
        );
        assert_eq!(classify_line("1.1.1.1:53", false, true), None);
        assert_eq!(
            classify_line("https://dns.example/dns-query", false, true).as_deref(),
            Some("https://dns.example/dns-query")
        );
        assert_eq!(
            classify_line("https://dns.example/dns-query", true, false),
            None
        );
    }

    #[test]
    fn classify_line_skips_comments_ipv6_and_garbage() {
        assert_eq!(classify_line("# comment", true, true), None);
        assert_eq!(classify_line("2001:db8::1", true, true), None);
        assert_eq!(classify_line("not-an-ip", true, true), None);
        assert_eq!(classify_line("", true, true), None);
    }

    #[test]
    fn parse_resolver_list_filters_body() {
        let body = r#"
# public resolvers
1.1.1.1:53
8.8.8.8

https://cloudflare-dns.com/dns-query
2001:db8::1
garbage
"#;
        let ipv4_only = parse_resolver_list(body, true, false);
        assert_eq!(
            ipv4_only,
            vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
        );

        let doh_only = parse_resolver_list(body, false, true);
        assert_eq!(
            doh_only,
            vec!["https://cloudflare-dns.com/dns-query".to_string()]
        );

        let both = parse_resolver_list(body, true, true);
        assert_eq!(both.len(), 3);
    }

    #[test]
    fn merge_discovered_prepends_dedups_and_caps() {
        let mut healthy = vec![create_resolver("old-a"), create_resolver("old-b")];
        merge_discovered_into_healthy(
            &mut healthy,
            vec![
                create_resolver("fast"),
                create_resolver("old-a"),
                create_resolver("mid"),
            ],
            3,
        );
        assert_eq!(
            resolvers_to_addrs(&healthy),
            vec!["fast".to_string(), "mid".to_string(), "old-a".to_string()]
        );
    }

    #[test]
    fn merge_discovered_noop_when_all_known() {
        let mut healthy = vec![create_resolver("a"), create_resolver("b")];
        merge_discovered_into_healthy(
            &mut healthy,
            vec![create_resolver("a"), create_resolver("b")],
            256,
        );
        assert_eq!(resolvers_to_addrs(&healthy), vec!["a", "b"]);
    }

    #[test]
    fn failed_resolver_set_records_and_skips_duplicates() {
        let unique = format!("failed-test-{}", Instant::now().elapsed().as_nanos());
        assert!(!is_failed_resolver(&unique));
        record_failed_resolver(unique.clone());
        record_failed_resolver(unique.clone());
        assert!(is_failed_resolver(&unique));

        let Ok(guard) = FAILED_RESOLVERS.read() else {
            panic!("failed to lock FAILED_RESOLVERS");
        };
        assert_eq!(guard.set.iter().filter(|s| *s == &unique).count(), 1);
    }

    #[tokio::test]
    async fn collect_concurrent_respects_limit() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let limit = 4usize;
        let items: Vec<u32> = (0..40).collect();

        let values = collect_concurrent(items, limit, {
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            move |n| {
                let in_flight = Arc::clone(&in_flight);
                let peak = Arc::clone(&peak);
                async move {
                    let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(cur, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    n * 2
                }
            }
        })
        .await;

        assert_eq!(values.len(), 40);
        let mut sorted = values;
        sorted.sort_unstable();
        assert_eq!(sorted, (0..40).map(|n| n * 2).collect::<Vec<_>>());
        assert!(
            peak.load(Ordering::SeqCst) <= limit,
            "peak concurrency {} exceeded limit {}",
            peak.load(Ordering::SeqCst),
            limit
        );
        assert!(peak.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn collect_concurrent_empty_input() {
        let out: Vec<u32> = collect_concurrent(Vec::<u32>::new(), 8, |_| async { 1 }).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn run_resolver_finder_skips_when_already_searching() {
        let healthy = Arc::new(RwLock::new(vec![create_resolver("seed")]));
        let is_searching = Arc::new(AtomicBool::new(true));
        let conf = ResolverSearchingConf {
            enable: true,
            // Would fail if the finder actually tried to fetch; skip path must not touch it.
            resolver_source: vec!["http://127.0.0.1:1/must-not-fetch".into()],
            // Long interval so only the immediate first tick runs during this test.
            resfresh_interval: Some(3600),
            ipv4: true,
            doh: true,
        };

        let handle = tokio::spawn(run_resolver_finder(
            conf,
            Arc::clone(&healthy),
            Arc::clone(&is_searching),
        ));

        // First `interval` tick fires immediately; with is_searching==true the loop
        // should warn+continue without clearing the flag or touching healthy_resolvers.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            is_searching.load(Ordering::Acquire),
            "skip path must leave is_searching true (SearchGuard must not run)"
        );
        assert_eq!(
            *healthy.read().unwrap(),
            vec![create_resolver("seed")],
            "skip path must not mutate healthy_resolvers"
        );

        handle.abort();
        let _ = handle.await;
    }

    #[test]
    fn picker_pick_returns_first_healthy() {
        let picker = ResolverPicker::from_healthy(vec![create_resolver("a"), create_resolver("b")]);
        assert_eq!(picker.pick(), "a");
    }

    #[test]
    fn healthy_resolvers_shared_arc_sees_updates() {
        let picker = ResolverPicker::from_healthy(vec![create_resolver("seed")]);
        let shared = picker.healthy_resolvers();
        shared.write().unwrap().insert(0, create_resolver("new"));
        assert_eq!(picker.pick(), "new");
        assert_eq!(shared.read().unwrap()[0], create_resolver("new"));
    }

    #[test]
    fn healthy_resolvers_concurrent_picks_and_updates() {
        let picker = ResolverPicker::from_healthy(vec![create_resolver("seed")]);
        let shared = picker.healthy_resolvers();
        let barrier = Arc::new(Barrier::new(9));
        let mut handles = Vec::with_capacity(9);

        for _ in 0..8 {
            let picker = picker.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..2_000 {
                    let chosen = picker.pick();
                    assert!(!chosen.is_empty(), "pick returned empty resolver");
                }
            }));
        }

        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..2_000 {
                let mut guard = shared.write().unwrap();
                // Keep at least one entry so pick() never indexes empty.
                *guard = vec![create_resolver(&format!("r{i}")), create_resolver("seed")];
                if guard.len() > MAX_HEALTHY_RESOLVERS {
                    guard.truncate(MAX_HEALTHY_RESOLVERS);
                }
            }
        }));

        for handle in handles {
            handle.join().expect("worker panicked");
        }
        assert!(!picker.pick().is_empty());
    }

    #[test]
    fn healthy_resolvers_concurrent_merges_stay_capped() {
        let picker = ResolverPicker::from_healthy(vec![create_resolver("seed")]);
        let shared = picker.healthy_resolvers();
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::with_capacity(5);

        for t in 0..4 {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..300 {
                    let discovered = vec![
                        create_resolver(&format!("t{t}-fast-{i}")),
                        create_resolver(&format!("t{t}-mid-{i}")),
                        create_resolver("seed"),
                    ];
                    let mut guard = shared.write().unwrap();
                    merge_discovered_into_healthy(&mut guard, discovered, MAX_HEALTHY_RESOLVERS);
                    assert!(!guard.is_empty());
                    assert!(guard.len() <= MAX_HEALTHY_RESOLVERS);
                }
            }));
        }

        let picker = picker.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1_200 {
                let _ = picker.pick();
            }
        }));

        for handle in handles {
            handle.join().expect("worker panicked");
        }

        let guard = shared.read().unwrap();
        assert!(!guard.is_empty());
        assert!(guard.len() <= MAX_HEALTHY_RESOLVERS);
    }
    #[test]
    fn select_resolver_uses_explicit_override_and_normalizes_port() {
        let picker = ResolverPicker::from_healthy(vec![create_resolver("1.1.1.1:53")]);

        // bare IP with no port should get `:53` appended
        assert_eq!(
            picker.select_resolver(Some("8.8.8.8".to_string())),
            "8.8.8.8:53"
        );

        // already has a port, left untouched
        assert_eq!(
            picker.select_resolver(Some("9.9.9.9:53".to_string())),
            "9.9.9.9:53"
        );

        // DoH URL passed through unchanged
        assert_eq!(
            picker.select_resolver(Some("https://dns.example/dns-query".to_string())),
            "https://dns.example/dns-query"
        );
    }

    #[test]
    fn select_resolver_falls_back_to_pick_when_none() {
        let picker = ResolverPicker::from_healthy(vec![
            create_resolver("1.1.1.1:53"),
            create_resolver("8.8.8.8:53"),
        ]);

        // no explicit resolver given -> falls back to the picker's first (best) entry
        assert_eq!(picker.select_resolver(None), "1.1.1.1:53");
    }
}
