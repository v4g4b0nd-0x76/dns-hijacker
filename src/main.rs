use serde::Deserialize;
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

const LOCAL_DNS: &str = "0.0.0.0:553";
const PAYLOAD_BUF_SIZE: usize = 1024;

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let conf = load_conf()?;
    let resolver_picker = ResolverPicker::new(conf.resolvers).await?;
    let server_socket = UdpSocket::bind(LOCAL_DNS).await?;
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?; // todo: recheck the connection each x second

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
        let payload = &buf[..len];
        if len < 12 {
            eprintln!("invalid payload len");
            continue;
        }
        // extract domain at offset of 12
        let (domain, qname_end) = match parse_domain(payload, 12) {
            Some(res) => res,
            None => continue,
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
            continue;
        }

        let redirect_target = conf
            .redirect_list
            .iter()
            .find(|(pattern, _)| matches_domain_pattern(&domain, pattern));

        if let Some((_, ip_with_port)) = redirect_target {
            // Safe port stripping handled before calling packet crafter
            let ip = ip_with_port.split(':').next().unwrap_or(ip_with_port);

            println!(
                "[REDIRECT] {} -> {}",
                domain, ip
            );
            if let Some(resp) = craft_redirect_response(payload, qname_end, ip) {
                let _ = server_socket.send_to(&resp, src_addr).await;
            }
            continue;
        }

        let resolver = resolver_picker.pick();
        match resolve_from_upstream(payload, &upstream_socket, resolver).await {
            Ok((reply_buf, reply_len)) => {
                let _ = server_socket
                    .send_to(&reply_buf[..reply_len], src_addr)
                    .await;
            }
            Err(err) => {
                eprintln!("failed to resolve {} from {}: {}", domain, resolver, err);
                continue;
            }
        }
    }
}

async fn resolve_from_upstream(
    payload: &[u8],
    upstream_socket: &UdpSocket,
    upstream_resolver: &str,
) -> io::Result<(Vec<u8>, usize)> {
    let upstream_addr: SocketAddr = upstream_resolver
        .parse()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    // Forward the exact binary payload to DNS server
    if upstream_socket
        .send_to(payload, upstream_addr)
        .await
        .is_ok()
    {
        let mut reply_buf = [0u8; 1024];
        if let Ok((reply_len, _)) = upstream_socket.recv_from(&mut reply_buf).await {
            return Ok((reply_buf[..reply_len].to_vec(), reply_len));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not resolve domain",
    ))
}

#[inline]
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

#[inline]
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

#[inline]
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

fn load_conf() -> io::Result<Conf> {
    let content = std::fs::read_to_string("conf.toml")?;

    toml::from_str(&content).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[derive(Clone)]
pub struct ResolverPicker {
    // Stores the healthy resolvers sorted by lowest latency first
    healthy_resolvers: Arc<Vec<String>>,
}

impl ResolverPicker {
    pub async fn new(resolvers: Vec<String>) -> io::Result<Self> {
        let mut tasks = Vec::new();

        // 1. Benchmark all resolvers concurrently
        for resolver in resolvers {
            tasks.push(tokio::spawn(async move {
                match Self::measure_latency(&resolver).await {
                    Ok(latency) => Some((resolver, latency)),
                    Err(_) => None,
                }
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some((resolver, latency))) = task.await {
                results.push((resolver, latency));
            }
        }

        // 2. Fallback error check
        if results.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "All provided DNS upstream resolvers are unhealthy or unreachable",
            ));
        }

        // 3. Sort by latency (lowest duration first)
        results.sort_by_key(|&(_, latency)| latency);

        // 4. Extract sorted resolver strings
        let sorted_resolvers: Vec<String> = results.into_iter().map(|(res, _)| res).collect();

        println!(
            "[PICKER] Healthy upstreams discovered: {:?}",
            sorted_resolvers
        );

        Ok(Self {
            healthy_resolvers: Arc::new(sorted_resolvers),
        })
    }

    /// Returns the fastest available resolver string reference.
    pub fn pick(&self) -> &str {
        // Since they are sorted, index 0 is always the fastest
        &self.healthy_resolvers[0]
    }

    /// Sends a lightweight standard DNS query payload for 'google.com'
    /// to determine if a server is online and track its round-trip time.
    async fn measure_latency(resolver: &str) -> io::Result<Duration> {
        let addr: SocketAddr = resolver
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // A minimal, hardcoded raw binary DNS query packet for 'google.com' (A record)
        let dns_probe_packet: &[u8] = &[
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

        let start = Instant::now();
        socket.send_to(dns_probe_packet, addr).await?;

        let mut buf = [0u8; 512];
        // Enforce a strict 1.5-second timeout so slow/dead resolvers drop quickly
        let _ = timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await??;

        let latency = start.elapsed();
        Ok(latency)
    }
}

/// # Helpers
fn matches_domain_pattern(domain: &str, pattern: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_lowercase();
    let pattern = pattern.trim_end_matches('.').to_lowercase();

    if domain == pattern {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Matches "example.com" directly or any subdomain like "://example.com"
        return domain == suffix || domain.ends_with(&format!(".{}", suffix));
    }

    false
}
