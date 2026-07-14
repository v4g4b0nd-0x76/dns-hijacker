use std::net::SocketAddr;

use tokio::{net::UdpSocket, time::timeout};

use crate::{
    cache::{cache_key_from_query, cache_lookup, cache_store, ResponseCache},
    conf::Conf,
    constants::{RESOLVE_TIMEOUT, SOCKET_BUF_SIZE},
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response,
        matches_domain_pattern, parse_domain, with_txid,
    },
    errors::Error,
    resolver::{resolve_from_upstream, ResolverPicker},
};

pub fn bind_udp_socket(addr: &str) -> Result<UdpSocket, Error> {
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

pub async fn handle_query(
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
