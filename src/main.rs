use lru::LruCache;
use serde::Deserialize;
use std::{
    fmt, io,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Semaphore, time::timeout};

const LOCAL_DNS: &str = "127.0.0.1:53";
const PAYLOAD_BUF_SIZE: usize = 1024;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
const DOH_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const UDP_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const RESOLVE_SEMAPHORE: usize = 100;
const RECV_BATCH_MAX: usize = 32;
const SOCKET_BUF_SIZE: usize = 4 * 1024 * 1024;
const CACHE_CAPACITY: usize = 4096;
const CACHE_TTL_MIN: Duration = Duration::from_secs(5);
const CACHE_TTL_MAX: Duration = Duration::from_secs(300);
const CACHE_TTL_FALLBACK: Duration = Duration::from_secs(60);

/// Minimal DNS query for `google.com` A record, used as a health-check probe.
const DNS_PROBE_PACKET: &[u8] = &[
    0xAA, 0xBB, // Transaction ID
    0x01, 0x00, // Flags: Standard Query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', // Label: google
    0x03, b'c', b'o', b'm', // Label: com
    0x00, // Null terminator
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
];

#[derive(Debug)]
enum Error {
    Io(io::Error),
    Config(String),
    InvalidResolver(String),
    Doh(DohError),
    UdpTimeout,
    UpstreamUnreachable,
    NoHealthyResolvers,
    ResolveTimeout,
}

#[derive(Debug)]
enum DohError {
    Timeout,
    Request(reqwest::Error),
    Status(reqwest::StatusCode),
    Body(reqwest::Error),
}

impl fmt::Display for DohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "DoH request timed out"),
            Self::Request(err) => write!(f, "DoH request failed: {err}"),
            Self::Status(status) => write!(f, "DoH upstream returned status {status}"),
            Self::Body(err) => write!(f, "failed to read DoH response body: {err}"),
        }
    }
}

impl std::error::Error for DohError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(err) | Self::Body(err) => Some(err),
            Self::Timeout | Self::Status(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Config(msg) => write!(f, "config error: {msg}"),
            Self::InvalidResolver(resolver) => write!(f, "invalid resolver address: {resolver}"),
            Self::Doh(err) => write!(f, "{err}"),
            Self::UdpTimeout => write!(f, "UDP request timed out"),
            Self::UpstreamUnreachable => write!(f, "could not resolve domain upstream"),
            Self::NoHealthyResolvers => {
                write!(
                    f,
                    "all provided DNS upstream resolvers are unhealthy or unreachable"
                )
            }
            Self::ResolveTimeout => write!(f, "resolve timed out after {RESOLVE_TIMEOUT:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Doh(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<DohError> for Error {
    fn from(err: DohError) -> Self {
        Self::Doh(err)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct CacheKey {
    name: String,
    qtype: u16,
}

struct CacheEntry {
    packet: Vec<u8>,
    expires_at: Instant,
}

type ResponseCache = Mutex<LruCache<CacheKey, CacheEntry>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let conf = Arc::new(load_conf()?);
    let http = build_http_client()?;
    let resolver_picker = ResolverPicker::new(conf.resolvers.clone(), http.clone()).await?;
    let server_socket = Arc::new(bind_udp_socket(LOCAL_DNS)?);
    let resolve_sem = Arc::new(Semaphore::new(RESOLVE_SEMAPHORE));
    let cache = Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(CACHE_CAPACITY).expect("cache capacity > 0"),
    )));

    println!("dns server listening at {}", LOCAL_DNS);
    let mut buf = [0u8; PAYLOAD_BUF_SIZE];
    loop {
        let (len, src_addr) = match server_socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(err) => {
                eprintln!("failed to receive payload: {}", err);
                continue;
            }
        };

        // Drain ready datagrams in one wakeup to cut recv syscalls under burst load.
        let mut batch = Vec::with_capacity(RECV_BATCH_MAX);
        batch.push((buf[..len].to_vec(), src_addr));
        while batch.len() < RECV_BATCH_MAX {
            match server_socket.try_recv_from(&mut buf) {
                Ok((n, addr)) => batch.push((buf[..n].to_vec(), addr)),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    eprintln!("failed to drain payload: {}", err);
                    break;
                }
            }
        }

        for (payload, src_addr) in batch {
            let Ok(permit) = resolve_sem.clone().try_acquire_owned() else {
                eprintln!("reached semaphore maximum");
                continue;
            };

            let conf = Arc::clone(&conf);
            let http = http.clone();
            let resolver_picker = resolver_picker.clone();
            let server_socket = Arc::clone(&server_socket);
            let cache = Arc::clone(&cache);

            tokio::spawn(async move {
                let _permit = permit;
                handle_query(
                    &payload,
                    src_addr,
                    &conf,
                    &resolver_picker,
                    &server_socket,
                    &http,
                    &cache,
                )
                .await;
            });
        }
    }
}

fn bind_udp_socket(addr: &str) -> Result<UdpSocket, Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr: SocketAddr = addr
        .parse()
        .map_err(|err| Error::Config(format!("invalid listen address {addr}: {err}")))?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = socket.set_send_buffer_size(SOCKET_BUF_SIZE);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

async fn handle_query(
    payload: &[u8],
    src_addr: SocketAddr,
    conf: &Conf,
    resolver_picker: &ResolverPicker,
    server_socket: &UdpSocket,
    http: &reqwest::Client,
    cache: &ResponseCache,
) {
    if payload.len() < 12 {
        eprintln!("invalid payload len");
        return;
    }

    let (domain, qname_end) = match parse_domain(payload, 12) {
        Some(res) => res,
        None => return,
    };
    println!("Resolving {}", domain);

    let should_drop = conf
        .drop_list
        .iter()
        .any(|pattern| matches_domain_pattern(&domain, pattern));

    if should_drop {
        println!("[Dropped] {}", domain);
        if let Some(resp) = craft_nxdomain_response(payload) {
            let _ = server_socket.send_to(&resp, src_addr).await;
        }
        return;
    }

    let redirect_target = conf
        .redirect_list
        .iter()
        .find(|(pattern, _)| matches_domain_pattern(&domain, pattern));

    if let Some((_, ip_with_port)) = redirect_target {
        let ip = ip_with_port.split(':').next().unwrap_or(ip_with_port);

        println!("[REDIRECT] {} -> {}", domain, ip);
        if let Some(resp) = craft_redirect_response(payload, qname_end, ip) {
            let _ = server_socket.send_to(&resp, src_addr).await;
        }
        return;
    }

    let cache_key = match cache_key_from_query(payload) {
        Some(key) => key,
        None => return,
    };
    let req_txid = [payload[0], payload[1]];

    if let Some(cached) = cache_lookup(cache, &cache_key) {
        println!("[CACHE HIT] {}", domain);
        let resp = with_txid(cached, req_txid);
        let _ = server_socket.send_to(&resp, src_addr).await;
        return;
    }

    let resolver = resolver_picker.pick();
    match timeout(
        RESOLVE_TIMEOUT,
        resolve_from_upstream(payload, resolver, src_addr, http),
    )
    .await
    {
        Ok(Ok((reply_buf, _reply_len))) => {
            cache_store(cache, cache_key, &reply_buf);
            let resp = with_txid(reply_buf, req_txid);
            let _ = server_socket.send_to(&resp, src_addr).await;
        }
        Ok(Err(Error::ResolveTimeout)) | Err(_) => {
            eprintln!(
                "resolve timed out for {} from {} after {:?}",
                domain, resolver, RESOLVE_TIMEOUT
            );
            if let Some(resp) = craft_servfail_response(payload) {
                let _ = server_socket.send_to(&resp, src_addr).await;
            }
        }
        Ok(Err(err)) => {
            eprintln!("failed to resolve {} from {}: {}", domain, resolver, err);
        }
    }
}

fn build_http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(RESOLVE_TIMEOUT)
        .connect_timeout(DOH_CONNECT_TIMEOUT)
        // DoH endpoints must be hit directly; following HTML redirects hides bad URLs.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| Error::Config(format!("failed to build HTTP client: {err}")))
}

async fn resolve_from_upstream(
    payload: &[u8],
    upstream_resolver: &str,
    src_addr: SocketAddr,
    http: &reqwest::Client,
) -> Result<(Vec<u8>, usize), Error> {
    // If inject_ecs_option returns None (IPv6), fall back to the original payload.
    let final_payload = inject_ecs_option(payload, src_addr).unwrap_or_else(|| payload.to_vec());

    // DoH URLs are not socket addresses — check this before parsing.
    if upstream_resolver.starts_with("https://") {
        return resolve_via_doh(http, upstream_resolver, &final_payload).await;
    }

    let upstream_addr: SocketAddr = upstream_resolver
        .parse()
        .map_err(|_| Error::InvalidResolver(upstream_resolver.to_owned()))?;

    // Per-query socket avoids races when many UDP resolves share one listen port.
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
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

async fn resolve_via_doh(
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

fn cache_key_from_query(payload: &[u8]) -> Option<CacheKey> {
    let (name, qname_end) = parse_domain(payload, 12)?;
    if qname_end + 2 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[qname_end], payload[qname_end + 1]]);
    Some(CacheKey { name, qtype })
}

#[inline(always)]
fn with_txid(mut packet: Vec<u8>, txid: [u8; 2]) -> Vec<u8> {
    if packet.len() >= 2 {
        packet[0] = txid[0];
        packet[1] = txid[1];
    }
    packet
}

fn clamp_cache_ttl(ttl_secs: u32) -> Duration {
    let ttl = Duration::from_secs(u64::from(ttl_secs));
    if ttl < CACHE_TTL_MIN {
        CACHE_TTL_MIN
    } else if ttl > CACHE_TTL_MAX {
        CACHE_TTL_MAX
    } else {
        ttl
    }
}

fn min_answer_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    if ancount == 0 {
        return None;
    }

    let (_, mut offset) = parse_domain(packet, 12)?;
    offset += 4; // qtype + qclass

    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        let (_, name_end) = parse_domain(packet, offset)?;
        offset = name_end;
        if offset + 10 > packet.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen =
            u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10 + rdlen;
        if offset > packet.len() {
            return None;
        }
        if ttl > 0 {
            min_ttl = min_ttl.min(ttl);
        }
    }

    if min_ttl == u32::MAX {
        None
    } else {
        Some(min_ttl)
    }
}

fn cache_lookup(cache: &ResponseCache, key: &CacheKey) -> Option<Vec<u8>> {
    let mut guard = cache.lock().ok()?;
    let entry = guard.get(key)?;
    if Instant::now() >= entry.expires_at {
        guard.pop(key);
        return None;
    }
    Some(entry.packet.clone())
}

fn cache_store(cache: &ResponseCache, key: CacheKey, packet: &[u8]) {
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

#[inline(always)]
fn parse_domain(payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut domain = String::new();
    loop {
        if offset >= payload.len() {
            return None;
        }
        let len = payload[offset] as usize;
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= payload.len() {
                return None;
            }
            let pointer_offset = ((len & 0x3F) << 8) | (payload[offset + 1] as usize);
            if let Some((sub_domain, _)) = parse_domain(payload, pointer_offset) {
                domain.push_str(&sub_domain);
            }
            offset += 2;
            break;
        }
        offset += 1;
        if len == 0 {
            break;
        } // End of name

        if offset + len > payload.len() {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }

        let label = std::str::from_utf8(&payload[offset..offset + len]).ok()?;
        domain.push_str(&label.to_lowercase());
        offset += len;
    }
    Some((domain, offset))
}

#[inline(always)]
/// Crafts a manual DNS answer appending a hardcoded A record to the request.
fn craft_redirect_response(payload: &[u8], qname_end: usize, ip_str: &str) -> Option<Vec<u8>> {
    let mut resp = payload.to_vec();
    if resp.len() < 12 {
        return None;
    }

    // 1. Modify Header
    resp[2] = 0x81; // Flags: Response, Opcode 0, Standard query
    resp[3] = 0x80; // Flags: Recursion available, No error
    resp[7] = 1; // Answer Count = 1 (Big Endian high byte always 0 for 1 answer)

    // 2. Extract Query Type and Class by copying them to break the borrow chain
    if qname_end + 4 > resp.len() {
        return None;
    }

    let mut qtype = [0u8; 2];
    qtype.copy_from_slice(&resp[qname_end..qname_end + 2]);

    let mut qclass = [0u8; 2];
    qclass.copy_from_slice(&resp[qname_end + 2..qname_end + 4]);

    // 3. Append Answer Record (Now safely allowed to mutate `resp`)
    // Name pointer referencing the question domain at offset 12 (0xC00C)
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&qtype); // Type (matches query, usually A)
    resp.extend_from_slice(&qclass); // Class (matches query, usually IN)
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL: 60 seconds

    // Parse target IP bytes
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    resp.extend_from_slice(&[0x00, 0x04]); // Data Length = 4 bytes
    resp.extend_from_slice(&ip.octets()); // IPv4 bytes

    Some(resp)
}

#[inline(always)]
/// Crafts an NXDOMAIN (domain not found) response.
fn craft_nxdomain_response(payload: &[u8]) -> Option<Vec<u8>> {
    let mut resp = payload.to_vec();
    if resp.len() < 12 {
        return None;
    }
    resp[2] = 0x81;
    resp[3] = 0x83; // Reply code 3: NXDomain
    Some(resp)
}

#[inline(always)]
/// Crafts a SERVFAIL response (RCODE 2) used when resolve budget is exceeded.
fn craft_servfail_response(payload: &[u8]) -> Option<Vec<u8>> {
    let mut resp = payload.to_vec();
    if resp.len() < 12 {
        return None;
    }
    resp[2] = 0x81;
    resp[3] = 0x82; // Reply code 2: ServFail
    Some(resp)
}

#[inline(always)]
fn inject_ecs_option(payload: &[u8], client_addr: std::net::SocketAddr) -> Option<Vec<u8>> {
    let ip_bytes = match client_addr.ip() {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == 127 {
                [8, 8, 8, 8]
            } else {
                octets
            }
        }
        std::net::IpAddr::V6(_) => return None,
    };

    let mut modified = payload.to_vec();
    if modified.len() < 12 {
        return Some(modified);
    }

    let arcount = ((modified[10] as u16) << 8) | (modified[11] as u16);
    let new_arcount = arcount + 1;
    modified[10] = (new_arcount >> 8) as u8;
    modified[11] = (new_arcount & 0xFF) as u8;

    let mut opt_rr = Vec::new();

    opt_rr.push(0x00);
    opt_rr.extend_from_slice(&[0x00, 0x29]);
    opt_rr.extend_from_slice(&[0x10, 0x00]);
    opt_rr.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let rd_length: u16 = 2 + 2 + 2 + 1 + 1 + 3;
    opt_rr.extend_from_slice(&rd_length.to_be_bytes());

    opt_rr.extend_from_slice(&[0x00, 0x08]);

    let option_data_len: u16 = 2 + 1 + 1 + 3;
    opt_rr.extend_from_slice(&option_data_len.to_be_bytes());

    opt_rr.extend_from_slice(&[0x00, 0x01]);
    opt_rr.push(24);
    opt_rr.push(0);

    opt_rr.extend_from_slice(&ip_bytes[0..3]);

    modified.extend_from_slice(&opt_rr);
    Some(modified)
}

#[derive(Default, Deserialize)]
struct Conf {
    drop_list: Vec<String>,
    #[serde(deserialize_with = "deserialize_redirect_list")]
    redirect_list: Vec<(String, String)>,
    resolvers: Vec<String>,
}

fn deserialize_redirect_list<'de, D>(deserializer: D) -> Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    use serde::de::Error;

    let entries = Vec::<String>::deserialize(deserializer)?;

    entries
        .into_iter()
        .map(|entry| {
            let (domain, target) = entry
                .split_once(':')
                .ok_or_else(|| D::Error::custom(format!("invalid redirect entry: {entry}")))?;

            Ok((domain.to_owned(), target.to_owned()))
        })
        .collect()
}

fn load_conf() -> Result<Conf, Error> {
    let content = std::fs::read_to_string("conf.toml")?;
    toml::from_str(&content).map_err(|err| Error::Config(err.to_string()))
}

#[derive(Clone)]
struct ResolverPicker {
    healthy_resolvers: Arc<Vec<String>>,
}

impl ResolverPicker {
    async fn new(resolvers: Vec<String>, http: reqwest::Client) -> Result<Self, Error> {
        let mut tasks = Vec::new();

        for resolver in resolvers {
            let http = http.clone();
            tasks.push(tokio::spawn(async move {
                match Self::measure_latency(&resolver, &http).await {
                    Ok(latency) => {
                        println!("[PICKER LOG] {} responded in {:?}", resolver, latency);
                        Some((resolver, latency))
                    }
                    Err(e) => {
                        eprintln!("[PICKER WARN] {} failed health check: {}", resolver, e);
                        None
                    }
                }
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some((resolver, latency))) = task.await {
                results.push((resolver, latency));
            }
        }

        if results.is_empty() {
            return Err(Error::NoHealthyResolvers);
        }

        // Sort by latency (lowest duration first)
        results.sort_by_key(|&(_, latency)| latency);

        let sorted_resolvers: Vec<String> = results.into_iter().map(|(res, _)| res).collect();

        println!(
            "[PICKER] Healthy upstreams discovered and sorted: {:?}",
            sorted_resolvers
        );

        Ok(Self {
            healthy_resolvers: Arc::new(sorted_resolvers),
        })
    }

    fn pick(&self) -> &str {
        &self.healthy_resolvers[0]
    }

    async fn measure_latency(resolver: &str, http: &reqwest::Client) -> Result<Duration, Error> {
        let start = Instant::now();

        if resolver.starts_with("https://") {
            let req_future = http
                .post(resolver)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(DNS_PROBE_PACKET.to_vec())
                .send();

            let response = match timeout(RESOLVE_TIMEOUT, req_future).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => return Err(DohError::Request(err).into()),
                Err(_) => return Err(DohError::Timeout.into()),
            };

            if !response.status().is_success() {
                return Err(DohError::Status(response.status()).into());
            }

            // Drain the body so the full round-trip is measured.
            let _ = response.bytes().await.map_err(DohError::Body)?;
            return Ok(start.elapsed());
        }

        let addr: SocketAddr = resolver
            .parse()
            .map_err(|_| Error::InvalidResolver(resolver.to_owned()))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(DNS_PROBE_PACKET, addr).await?;

        let mut buf = [0u8; 512];
        match timeout(UDP_PROBE_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(Ok(_)) => Ok(start.elapsed()),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Err(Error::UdpTimeout),
        }
    }
}

/// # Helpers
#[inline(always)]
fn matches_domain_pattern(domain: &str, pattern: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_lowercase();
    let pattern = pattern.trim_end_matches('.').to_lowercase();

    if domain == pattern {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return domain == suffix || domain.ends_with(&format!(".{}", suffix));
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn empty_cache() -> ResponseCache {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(16).expect("cache capacity"),
        ))
    }

    /// Mock DNS query for `google.com` A (same layout as DNS_PROBE_PACKET).
    fn mock_query_google() -> &'static [u8] {
        DNS_PROBE_PACKET
    }

    /// Mock DNS query for `foo.test.com` A.
    fn mock_query_foo_test_com() -> Vec<u8> {
        vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x03, b'f', b'o', b'o', // foo
            0x04, b't', b'e', b's', b't', // test
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ]
    }

    /// Mock DNS query for `blocked.example.com` A.
    fn mock_query_blocked_example() -> Vec<u8> {
        vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'b',
            b'l', b'o', b'c', b'k', b'e', b'd', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
    }

    #[test]
    fn parse_domain_from_mock_probe() {
        let (domain, qname_end) = parse_domain(mock_query_google(), 12).expect("parse");
        assert_eq!(domain, "google.com");
        assert_eq!(qname_end, 12 + 1 + 6 + 1 + 3 + 1); // labels + root
    }

    #[test]
    fn parse_domain_rejects_truncated() {
        assert!(parse_domain(&[0u8; 8], 12).is_none());
        // Declares a 5-byte label but packet ends before the label bytes.
        let truncated = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // header
            0x05, b'a', b'b', // incomplete label
        ];
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
        assert_eq!(resp[3], 0x83); // NXDOMAIN
        assert_eq!(&resp[12..], &mock_query_google()[12..]);
    }

    #[test]
    fn craft_servfail_sets_rcode() {
        let resp = craft_servfail_response(mock_query_google()).expect("servfail");
        assert_eq!(resp[2], 0x81);
        assert_eq!(resp[3], 0x82); // SERVFAIL
    }

    #[test]
    fn craft_redirect_appends_a_record() {
        let query = mock_query_foo_test_com();
        let (_, qname_end) = parse_domain(&query, 12).expect("parse");
        let resp = craft_redirect_response(&query, qname_end, "192.168.1.1").expect("redirect");

        assert_eq!(resp[7], 1); // ANCOUNT low byte
        assert_eq!(&resp[resp.len() - 4..], &[192, 168, 1, 1]);
        assert_eq!(&resp[resp.len() - 6..resp.len() - 4], &[0x00, 0x04]); // RDLENGTH
    }

    #[test]
    fn inject_ecs_rewrites_loopback_and_bumps_arcount() {
        let query = mock_query_google().to_vec();
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53000);
        let modified = inject_ecs_option(&query, client).expect("ecs");

        let old_ar = ((query[10] as u16) << 8) | query[11] as u16;
        let new_ar = ((modified[10] as u16) << 8) | modified[11] as u16;
        assert_eq!(new_ar, old_ar + 1);
        // loopback client is remapped to 8.8.8.x prefix bytes in ECS option
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
        let resp = craft_redirect_response(&query, qname_end, "1.2.3.4").unwrap();
        assert_eq!(min_answer_ttl(&resp), Some(60));
    }

    #[test]
    fn cache_store_and_lookup_rewrites_txid_on_serve() {
        let cache = empty_cache();
        let query = mock_query_google();
        let key = cache_key_from_query(query).unwrap();
        let (_, qname_end) = parse_domain(query, 12).unwrap();
        let mut answer = craft_redirect_response(query, qname_end, "9.9.9.9").unwrap();
        answer[0] = 0x11;
        answer[1] = 0x22;

        cache_store(&cache, key.clone(), &answer);
        let cached = cache_lookup(&cache, &key).expect("cached");
        assert_eq!(&cached[..2], &[0, 0]); // normalized in store
        let served = with_txid(cached, [0xAB, 0xCD]);
        assert_eq!(&served[..2], &[0xAB, 0xCD]);
        assert_eq!(&served[served.len() - 4..], &[9, 9, 9, 9]);
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
            resolvers: vec!["127.0.0.1:9".into()], // unused for drop/redirect paths
        };
        let picker = ResolverPicker {
            healthy_resolvers: Arc::new(vec!["127.0.0.1:9".into()]),
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        // --- redirect path ---
        let redirect_query = mock_query_foo_test_com();
        client.send_to(&redirect_query, server_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, src) = server.recv_from(&mut buf).await.unwrap();
        handle_query(
            &buf[..len],
            src,
            &conf,
            &picker,
            &server,
            &http,
            &cache,
        )
        .await;

        let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
        assert!(resp_len > redirect_query.len());
        assert_eq!(buf[7], 1); // one answer
        assert_eq!(&buf[resp_len - 4..resp_len], &[192, 168, 1, 1]);

        // --- drop / NXDOMAIN path ---
        let drop_query = mock_query_blocked_example();
        client.send_to(&drop_query, server_addr).await.unwrap();
        let (len, src) = server.recv_from(&mut buf).await.unwrap();
        handle_query(
            &buf[..len],
            src,
            &conf,
            &picker,
            &server,
            &http,
            &cache,
        )
        .await;

        let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(resp_len, drop_query.len());
        assert_eq!(buf[3], 0x83); // NXDOMAIN
    }

    #[tokio::test]
    async fn integration_udp_upstream_echo() {
        // Upstream mock resolver: echo a crafted A answer for google.com.
        let upstream_mock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_mock.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, src) = upstream_mock.recv_from(&mut buf).await.unwrap();
            let (_, qname_end) = parse_domain(&buf[..len], 12).unwrap();
            let answer = craft_redirect_response(&buf[..len], qname_end, "8.8.4.4").unwrap();
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
        };
        let picker = ResolverPicker {
            healthy_resolvers: Arc::new(vec![upstream_addr.to_string()]),
        };
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
            &conf,
            &picker,
            &server,
            &http,
            &cache,
        )
        .await;

        let (resp_len, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
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
            // Only the first query should reach upstream.
            let (len, src) = upstream_mock.recv_from(&mut buf).await.unwrap();
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (_, qname_end) = parse_domain(&buf[..len], 12).unwrap();
            let answer = craft_redirect_response(&buf[..len], qname_end, "1.1.1.1").unwrap();
            let _ = upstream_mock.send_to(&answer, src).await;

            // A second packet would mean a cache miss; ensure we do not hang forever.
            let _ = timeout(Duration::from_millis(200), upstream_mock.recv_from(&mut buf)).await;
        });

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let cache = empty_cache();

        let conf = Conf {
            drop_list: vec![],
            redirect_list: vec![],
            resolvers: vec![upstream_addr.to_string()],
        };
        let picker = ResolverPicker {
            healthy_resolvers: Arc::new(vec![upstream_addr.to_string()]),
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        let mut buf = [0u8; 512];

        // First request: miss → upstream
        let mut q1 = mock_query_google().to_vec();
        q1[0] = 0x01;
        q1[1] = 0x01;
        client.send_to(&q1, server_addr).await.unwrap();
        let (len, src) = server.recv_from(&mut buf).await.unwrap();
        handle_query(&buf[..len], src, &conf, &picker, &server, &http, &cache).await;
        let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..2], &[0x01, 0x01]);
        assert_eq!(&buf[resp_len - 4..resp_len], &[1, 1, 1, 1]);

        // Second request: hit → no second upstream call, new TXID preserved
        let mut q2 = mock_query_google().to_vec();
        q2[0] = 0x02;
        q2[1] = 0x02;
        client.send_to(&q2, server_addr).await.unwrap();
        let (len, src) = server.recv_from(&mut buf).await.unwrap();
        handle_query(&buf[..len], src, &conf, &picker, &server, &http, &cache).await;
        let (resp_len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..2], &[0x02, 0x02]);
        assert_eq!(&buf[resp_len - 4..resp_len], &[1, 1, 1, 1]);

        upstream_task.await.unwrap();
        assert_eq!(hit_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn integration_resolve_timeout_returns_servfail() {
        // Bind a UDP port that never replies.
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
        };
        let picker = ResolverPicker {
            healthy_resolvers: Arc::new(vec![blackhole_addr.to_string()]),
        };
        let http = reqwest::Client::builder()
            .timeout(RESOLVE_TIMEOUT)
            .build()
            .unwrap();

        let query = mock_query_google().to_vec();
        client.send_to(&query, server_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, src) = server.recv_from(&mut buf).await.unwrap();

        let started = Instant::now();
        handle_query(&buf[..len], src, &conf, &picker, &server, &http, &cache).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= RESOLVE_TIMEOUT && elapsed < RESOLVE_TIMEOUT + Duration::from_secs(1),
            "elapsed={elapsed:?}"
        );

        let (resp_len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
                .await
                .expect("servfail response")
                .unwrap();
        assert_eq!(resp_len, query.len());
        assert_eq!(buf[3], 0x82); // SERVFAIL
    }
}
