use rand::{RngExt};
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
pub fn inject_ecs_option(payload: &[u8], client_addr: SocketAddr) -> Option<Vec<u8>> {
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
                buf[rdata_start], buf[rdata_start + 1],
                buf[rdata_start + 2], buf[rdata_start + 3],
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
