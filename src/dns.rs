use rand::RngExt;
use std::net::SocketAddr;

#[inline(always)]
pub fn parse_domain(payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
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
        }

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
pub fn craft_redirect_response(
    payload: &[u8],
    qname_end: usize,
    ips_str: Vec<&str>,
) -> Option<Vec<u8>> {
    let mut resp = payload.to_vec();
    if resp.len() < 12 {
        return None;
    }
    resp[2] = 0x81;
    resp[3] = 0x80;

    if qname_end + 4 > resp.len() {
        return None;
    }
    let mut qtype = [0u8; 2];
    qtype.copy_from_slice(&resp[qname_end..qname_end + 2]);
    let mut qclass = [0u8; 2];
    qclass.copy_from_slice(&resp[qname_end + 2..qname_end + 4]);

    let ips: Vec<std::net::Ipv4Addr> = ips_str
        .iter()
        .filter_map(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
        .collect();

    if ips.is_empty() {
        return None; // nothing valid to redirect to
    }

    let ancount = ips.len() as u16;
    resp[6] = (ancount >> 8) as u8;
    resp[7] = (ancount & 0xFF) as u8;

    for ip in &ips {
        resp.extend_from_slice(&[0xC0, 0x0C]); // name = pointer to offset 12 (query name)
        resp.extend_from_slice(&qtype);
        resp.extend_from_slice(&qclass);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60s
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        resp.extend_from_slice(&ip.octets());
    }

    Some(resp)
}

#[inline(always)]
/// Crafts an NXDOMAIN (domain not found) response.
pub fn craft_nxdomain_response(payload: &[u8]) -> Option<Vec<u8>> {
    let mut resp = payload.to_vec();
    if resp.len() < 12 {
        return None;
    }
    resp[2] = 0x81;
    resp[3] = 0x83;
    Some(resp)
}

#[inline(always)]
/// Crafts a SERVFAIL response (RCODE 2) used when resolve budget is exceeded.
pub fn craft_servfail_response(payload: &[u8]) -> Option<Vec<u8>> {
    let mut resp = payload.to_vec();
    if resp.len() < 12 {
        return None;
    }
    resp[2] = 0x81;
    resp[3] = 0x82;
    Some(resp)
}


#[inline(always)]
pub fn matches_domain_pattern(domain: &str, pattern: &str) -> bool {
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

pub fn build_lookup_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    let txid: u16 = rand::rng().random();
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);

    for label in domain.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);

    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

use std::net::Ipv4Addr;

/// Skips a DNS name at `offset`, handling both plain labels and compression pointers.
/// Returns the offset just past the name.
fn skip_name(buf: &[u8], offset: usize) -> Option<usize> {
    let mut pos = offset;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos];
        if len == 0 {
            pos += 1;
            break;
        } else if len & 0xC0 == 0xC0 {
            pos += 2; // compression pointer is always exactly 2 bytes
            break;
        } else {
            pos += 1 + len as usize;
        }
    }
    Some(pos)
}

/// Extracts all A-record IPs from a raw DNS response
pub fn parse_a_records(buf: &[u8]) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if buf.len() < 12 {
        return ips;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = match skip_name(buf, pos) {
            Some(p) => p,
            None => return ips,
        };
        pos += 4; // qtype + qclass
    }

    for _ in 0..ancount {
        pos = match skip_name(buf, pos) {
            Some(p) => p,
            None => return ips,
        };
        if pos + 10 > buf.len() {
            return ips;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        if rdata_start + rdlength > buf.len() {
            return ips;
        }
        if rtype == 1 && rdlength == 4 {
            ips.push(Ipv4Addr::new(
                buf[rdata_start],
                buf[rdata_start + 1],
                buf[rdata_start + 2],
                buf[rdata_start + 3],
            ));
        }
        pos = rdata_start + rdlength;
    }
    ips
}

#[inline(always)]
pub fn with_txid(mut packet: Vec<u8>, txid: [u8; 2]) -> Vec<u8> {
    if packet.len() >= 2 {
        packet[0] = txid[0];
        packet[1] = txid[1];
    }
    packet
}

pub fn min_answer_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    if ancount == 0 {
        return None;
    }

    let (_, mut offset) = parse_domain(packet, 12)?;
    offset += 4;

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
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
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

/// Parsed representation of an EDNS0 OPT pseudo-RR (RFC 6891).
#[derive(Debug, Clone)]
pub struct EdnsOpt {
    /// Offset in the original packet where this OPT RR begins (the root name byte, 0x00).
    pub rr_start: usize,
    /// Offset just past the end of this OPT RR.
    pub rr_end: usize,
    /// UDP payload size advertised by the client (from CLASS field).
    pub udp_payload_size: u16,
    /// Extended RCODE high 8 bits (from TTL field byte 0).
    pub extended_rcode: u8,
    /// EDNS version (from TTL field byte 1).
    pub version: u8,
    /// DO bit (DNSSEC OK) and other flags (from TTL field bytes 2-3).
    pub flags: u16,
    /// Raw option data (RDATA) - may contain ECS, cookies, padding, etc.
    pub options: Vec<u8>,
}

/// Scans the Additional section for an existing OPT RR (type 41).
/// Returns None if there is no OPT record present.
pub fn find_opt_record(buf: &[u8]) -> Option<EdnsOpt> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12;

    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos += 4; // qtype + qclass
    }

    // Answer + authority sections both use the standard RR format; skip over them.
    for _ in 0..(ancount + nscount) {
        pos = skip_rr(buf, pos)?;
    }

    // Additional section: look for the OPT RR (type 41 / 0x0029).
    for _ in 0..arcount {
        let rr_start = pos;
        let name_end = skip_name(buf, pos)?;
        if name_end + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[name_end], buf[name_end + 1]]);
        let class = u16::from_be_bytes([buf[name_end + 2], buf[name_end + 3]]);
        let ttl_bytes = &buf[name_end + 4..name_end + 8];
        let rdlength = u16::from_be_bytes([buf[name_end + 8], buf[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        if rdata_start + rdlength > buf.len() {
            return None;
        }

        if rtype == 41 {
            return Some(EdnsOpt {
                rr_start,
                rr_end: rdata_start + rdlength,
                udp_payload_size: class,
                extended_rcode: ttl_bytes[0],
                version: ttl_bytes[1],
                flags: u16::from_be_bytes([ttl_bytes[2], ttl_bytes[3]]),
                options: buf[rdata_start..rdata_start + rdlength].to_vec(),
            });
        }

        pos = rdata_start + rdlength;
    }

    None
}

/// Skips a full resource record (name + type + class + ttl + rdlength + rdata).
fn skip_rr(buf: &[u8], offset: usize) -> Option<usize> {
    let name_end = skip_name(buf, offset)?;
    if name_end + 10 > buf.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([buf[name_end + 8], buf[name_end + 9]]) as usize;
    let end = name_end + 10 + rdlength;
    if end > buf.len() {
        return None;
    }
    Some(end)
}


/// One EDNS0 option (RFC 6891 section 6.1.2): OPTION-CODE, OPTION-LENGTH, OPTION-DATA.
struct EdnsOption<'a> {
    code: u16,
    data: &'a [u8],
}

/// Parses the raw options blob of an OPT RR into individual (code, data) pairs.
#[inline(always)]
fn parse_options(options: &[u8]) -> Vec<EdnsOption<'_>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= options.len() {
        let code = u16::from_be_bytes([options[pos], options[pos + 1]]);
        let len = u16::from_be_bytes([options[pos + 2], options[pos + 3]]) as usize;
        if pos + 4 + len > options.len() {
            break; // malformed, stop parsing rather than panic
        }
        out.push(EdnsOption {
            code,
            data: &options[pos + 4..pos + 4 + len],
        });
        pos += 4 + len;
    }
    out
}

/// Client Subnet option code (RFC 7871).
const OPT_CODE_ECS: u16 = 8;

#[inline(always)]
pub fn set_ecs_option(
    payload: &[u8],
    client_addr: SocketAddr,
    fabricate_public_ip_for_loopback: Option<[u8; 4]>,
) -> Option<Vec<u8>> {
    let ip_bytes = match client_addr.ip() {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == 127 {
                match fabricate_public_ip_for_loopback {
                    Some(fake) => fake,
                    None => return Some(payload.to_vec()), // leave ECS out for loopback/test clients
                }
            } else {
                octets
            }
        }
        std::net::IpAddr::V6(_) => return None, // TODO: add AAAA/IPv6 ECS (family 2) support
    };

    let mut ecs_data = Vec::with_capacity(8);
    ecs_data.extend_from_slice(&[0x00, 0x01]); // FAMILY = 1 (IPv4)
    ecs_data.push(24); // SOURCE PREFIX-LENGTH - /24 is the common privacy-preserving default
    ecs_data.push(0); // SCOPE PREFIX-LENGTH - 0 in queries, filled in by upstream in responses
    ecs_data.extend_from_slice(&ip_bytes[0..3]); // truncated address per RFC 7871 section 6

    match find_opt_record(payload) {
        Some(existing) => {
            let mut options = parse_options(&existing.options);
            // Drop any existing ECS option - we're replacing it, not appending.
            options.retain(|opt| opt.code != OPT_CODE_ECS);

            let mut new_options = Vec::new();
            for opt in &options {
                new_options.extend_from_slice(&opt.code.to_be_bytes());
                new_options.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
                new_options.extend_from_slice(opt.data);
            }
            new_options.extend_from_slice(&OPT_CODE_ECS.to_be_bytes());
            new_options.extend_from_slice(&(ecs_data.len() as u16).to_be_bytes());
            new_options.extend_from_slice(&ecs_data);

            rebuild_with_new_opt(payload, &existing, &new_options)
        }
        None => {
            // No existing OPT RR - build one from scratch, matching the old behavior
            // but through the same rebuild path so there's only one code path total.
            let synthetic = EdnsOpt {
                rr_start: payload.len(),
                rr_end: payload.len(),
                udp_payload_size: 4096, // common modern default (was implicit before)
                extended_rcode: 0,
                version: 0,
                flags: 0,
                options: Vec::new(),
            };
            rebuild_with_new_opt(payload, &synthetic, &{
                let mut v = Vec::new();
                v.extend_from_slice(&OPT_CODE_ECS.to_be_bytes());
                v.extend_from_slice(&(ecs_data.len() as u16).to_be_bytes());
                v.extend_from_slice(&ecs_data);
                v
            })
        }
    }
}


#[inline(always)]
fn rebuild_with_new_opt(payload: &[u8], existing: &EdnsOpt, new_options: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + new_options.len() + 16);
    out.extend_from_slice(&payload[..existing.rr_start]);

    out.push(0x00); // root name
    out.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    out.extend_from_slice(&existing.udp_payload_size.to_be_bytes()); // CLASS = UDP payload size
    out.push(existing.extended_rcode);
    out.push(existing.version);
    out.extend_from_slice(&existing.flags.to_be_bytes());
    out.extend_from_slice(&(new_options.len() as u16).to_be_bytes());
    out.extend_from_slice(new_options);

    out.extend_from_slice(&payload[existing.rr_end..]);

    // Fix up ARCOUNT only if we just added a brand new OPT RR (rr_start == rr_end == old len
    // means "synthetic, wasn't in the original packet").
    if existing.rr_start == existing.rr_end && existing.rr_start == payload.len() {
        if out.len() < 12 {
            return None;
        }
        let arcount = u16::from_be_bytes([out[10], out[11]]);
        let new_arcount = arcount + 1;
        out[10] = (new_arcount >> 8) as u8;
        out[11] = (new_arcount & 0xFF) as u8;
    }

    Some(out)
}
