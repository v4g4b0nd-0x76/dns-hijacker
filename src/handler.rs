use std::{net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, time::timeout};

use crate::{
    cache::{ResponseCache, cache_key_from_query, cache_lookup, cache_store}, conf::RelayConf, constants::{RESOLVE_TIMEOUT, SOCKET_BUF_SIZE}, dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response,
        matches_domain_pattern, parse_domain, with_txid,
    }, errors::Error, relay::resolve_via_relay, resolver::{ResolverPicker, resolve_from_upstream}
};
use tracing::{debug, error, info, warn};

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
    redirect_list: &Arc<Vec<(String, String)>>,
    drop_list: &Arc<Vec<String>>,
    resolver_picker: &ResolverPicker,
    server_socket: &UdpSocket,
    http: &reqwest::Client,
    cache: &ResponseCache,
    relay_conf: &RelayConf,
) {
    if payload.len() < 12 {
        error!("invalid payload len");
        return;
    }
    let (domain, qname_end) = match parse_domain(payload, 12) {
        Some(res) => res,
        None => return,
    };
    debug!("Resolving {}", domain);

    let should_drop = drop_list
        .iter()
        .any(|pattern| matches_domain_pattern(&domain, pattern));
    if should_drop {
        warn!("[Dropped] {}", domain);
        if let Some(resp) = craft_nxdomain_response(payload) {
            let _ = server_socket.send_to(&resp, src_addr).await;
        }
        return;
    }

    let redirect_target = redirect_list
        .iter()
        .find(|(pattern, _)| matches_domain_pattern(&domain, pattern));
    if let Some((_, ip_with_port)) = redirect_target {
        let ips: Vec<&str> = ip_with_port
            .split(',')
            .map(|entry| entry.split(':').next().unwrap_or(entry))
            .collect();
        warn!("[REDIRECT] {} -> {:?}", domain, ips);
        if let Some(resp) = craft_redirect_response(payload, qname_end, ips) {
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
        debug!("[CACHE HIT] {}", domain);
        let resp = with_txid(cached, req_txid);
        let _ = server_socket.send_to(&resp, src_addr).await;
        return;
    }

    if relay_conf.enable {
        // --- Relay path ---
        info!("Using relay");
        match timeout(
            RESOLVE_TIMEOUT,
            resolve_via_relay(http, &relay_conf.relay_url, &relay_conf.key, payload),
        )
        .await
        {
            Ok(Ok(reply_buf)) => {
                cache_store(cache, cache_key, &reply_buf);
                let resp = with_txid(reply_buf.to_vec(), req_txid);
                let _ = server_socket.send_to(&resp, src_addr).await;
            }
            Ok(Err(err)) => {
                error!("relay resolve failed for {}: {}", domain, err);
                if let Some(resp) = craft_servfail_response(payload) {
                    let _ = server_socket.send_to(&resp, src_addr).await;
                }
            }
            Err(_) => {
                error!(
                    "relay resolve timed out for {} after {:?}",
                    domain, RESOLVE_TIMEOUT
                );
                if let Some(resp) = craft_servfail_response(payload) {
                    let _ = server_socket.send_to(&resp, src_addr).await;
                }
            }
        }
        return;
    }

    // --- Direct upstream path (existing behavior) ---
    let resolver = resolver_picker.pick();
    match timeout(
        RESOLVE_TIMEOUT,
        resolve_from_upstream(payload, &resolver, src_addr, http),
    )
    .await
    {
        Ok(Ok((reply_buf, _reply_len))) => {
            cache_store(cache, cache_key, &reply_buf);
            let resp = with_txid(reply_buf, req_txid);
            let _ = server_socket.send_to(&resp, src_addr).await;
        }
        Ok(Err(Error::ResolveTimeout)) | Err(_) => {
            error!(
                "resolve timed out for {} from {} after {:?}",
                domain, resolver, RESOLVE_TIMEOUT
            );
            if let Some(resp) = craft_servfail_response(payload) {
                let _ = server_socket.send_to(&resp, src_addr).await;
            }
        }
        Ok(Err(err)) => {
            error!("failed to resolve {} from {}: {}", domain, resolver, err);
        }
    }
}
