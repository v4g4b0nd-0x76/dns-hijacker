use serde::Deserialize;
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

const LOCAL_DNS: &str = "0.0.0.0:553";
const UPSTREAM_RESOLVER: &str = "8.8.8.8:53";
const PAYLOAD_BUF_SIZE: usize = 1024;

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let domain_list = load_domain_list()?;
    let server_socket = UdpSocket::bind(LOCAL_DNS).await?;
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
        if domain_list.drop_list.contains(&domain) {
            // drop dns request
            println!("[Dropped] {}", domain);
            if let Some(resp) = craft_nxdomain_response(payload) {
                let _ = server_socket.send_to(&resp, src_addr).await;
            }
            continue;
        }

        if let Some((_, ip)) = domain_list.redirect_list.iter().find(|(d, _)| d == &domain) {
            println!("[REDIRECT] {} -> {}", domain, ip);
            if let Some(resp) = craft_redirect_response(payload, qname_end, ip) {
                let _ = server_socket.send_to(&resp, src_addr).await;
            }
            continue;
        }

        match resolve_from_upstream(payload, UPSTREAM_RESOLVER).await {
            Ok((reply_buf, reply_len)) => {
                let _ = server_socket.send_to(&reply_buf[..reply_len], src_addr).await;
            }
            Err(err) => {
                eprintln!(
                    "failed to resolve {} from {}: {}",
                    domain, UPSTREAM_RESOLVER, err
                );
                continue;
            }
        }
    }
}

async fn resolve_from_upstream(
    payload: &[u8],
    upstream_resolver: &str,
) -> io::Result<(Vec<u8>, usize)> {
    // TODO: optimization - pass a shared UdpSocket or connection pool as an argument instead of binding here
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;

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
            // FIX: Slice the buffer using reply_len so you don't return trailing zeros
            return Ok((reply_buf[..reply_len].to_vec(), reply_len));
        }
    }

    // FIX: Wrap the error in the Err variant
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
struct DomainList {
    drop_list: Vec<String>,
    #[serde(deserialize_with = "deserialize_redirect_list")]
    redirect_list: Vec<(String, String)>,
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

fn load_domain_list() -> io::Result<DomainList> {
    let content = std::fs::read_to_string("list.toml")?;

    toml::from_str(&content).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}
