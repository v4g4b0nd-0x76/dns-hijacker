use std::{net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, time::timeout};

use crate::{
    cache::{ResponseCache, cache_key_from_query, cache_lookup, cache_store},
    constants::{RESOLVE_TIMEOUT, SOCKET_BUF_SIZE},
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response,
        matches_domain_pattern, parse_domain, with_txid,
    },
    errors::Error,
    relay::{RelayPicker},
    resolver::{ResolverPicker, resolve_from_upstream},
};
use tracing::{debug, error, warn};

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
enum RuleMatch<'a> {
    Drop,
    Redirect(&'a str),
    None,
}

fn check_rules<'a>(
    domain: &str,
    drop_list: &'a [String],
    redirect_list: &'a [(String, String)],
) -> RuleMatch<'a> {
    if drop_list
        .iter()
        .any(|pattern| matches_domain_pattern(domain, pattern))
    {
        return RuleMatch::Drop;
    }
    if let Some((_, ip_with_port)) = redirect_list
        .iter()
        .find(|(pattern, _)| matches_domain_pattern(domain, pattern))
    {
        return RuleMatch::Redirect(ip_with_port);
    }
    RuleMatch::None
}

async fn send(server_socket: &UdpSocket, src_addr: SocketAddr, resp: Vec<u8>) {
    let _ = server_socket.send_to(&resp, src_addr).await;
}

async fn send_servfail(server_socket: &UdpSocket, src_addr: SocketAddr, payload: &[u8]) {
    if let Some(resp) = craft_servfail_response(payload) {
        send(server_socket, src_addr, resp).await;
    }
}

pub struct HandleQueryParams<'a> {
    pub payload: &'a [u8],
    pub src_addr: SocketAddr,
    pub redirect_list: &'a Arc<Vec<(String, String)>>,
    pub drop_list: &'a Arc<Vec<String>>,
    pub resolver_picker: &'a ResolverPicker,
    pub server_socket: &'a UdpSocket,
    pub http: &'a reqwest::Client,
    pub cache: &'a ResponseCache,
    pub relay_picker: Option<&'a RelayPicker>,
    pub socket: &'a Arc<UdpSocket>
}

pub async fn handle_query<'a>(params: &HandleQueryParams<'a>) {
    let HandleQueryParams {
        payload,
        src_addr,
        redirect_list,
        drop_list,
        resolver_picker,
        server_socket,
        http,
        cache,
        relay_picker,
        socket
    } = *params;

    if payload.len() < 12 {
        error!("invalid payload len");
        return;
    }
    let Some((domain, qname_end)) = parse_domain(payload, 12) else {
        return;
    };
    debug!("Resolving {}", domain);

    match check_rules(&domain, drop_list, redirect_list) {
        RuleMatch::Drop => {
            warn!("[Dropped] {}", domain);
            if let Some(resp) = craft_nxdomain_response(payload) {
                send(server_socket, src_addr, resp).await;
            }
            return;
        }
        RuleMatch::Redirect(ip_with_port) => {
            let ips: Vec<&str> = ip_with_port
                .split(',')
                .map(|entry| entry.split(':').next().unwrap_or(entry))
                .collect();
            warn!("[REDIRECT] {} -> {:?}", domain, ips);
            if let Some(resp) = craft_redirect_response(payload, qname_end, ips) {
                send(server_socket, src_addr, resp).await;
            }
            return;
        }
        RuleMatch::None => {}
    }

    let Some(cache_key) = cache_key_from_query(payload) else {
        return;
    };
    let req_txid = [payload[0], payload[1]];

    if let Some(cached) = cache_lookup(cache, &cache_key) {
        debug!("[CACHE HIT] {}", domain);
        send(server_socket, src_addr, with_txid(cached, req_txid)).await;
        return;
    }
    let resolve_result: Result<Vec<u8>, Error> = if let Some(relay_picker) = relay_picker {
        let instance = relay_picker.pick();
        timeout(relay_picker.timeout_duration(), instance.resolve(&domain, payload))
            .await
            .unwrap_or(Err(Error::ResolveTimeout))
    } else {
        let resolver = resolver_picker.pick();
        timeout(
            RESOLVE_TIMEOUT,
            resolve_from_upstream(payload, &resolver, src_addr, http,socket),
        )
        .await
        .unwrap_or(Err(Error::ResolveTimeout))
        .map(|(buf, _len)| buf)
    };

    match resolve_result {
        Ok(reply_buf) => {
            cache_store(cache, cache_key, &reply_buf);
            send(server_socket, src_addr, with_txid(reply_buf, req_txid)).await;
        }
        Err(Error::ResolveTimeout) => {
            error!(
                "resolve timed out for {} after {:?}",
                domain, RESOLVE_TIMEOUT
            );
            send_servfail(server_socket, src_addr, payload).await;
        }
        Err(err) => {
            error!("failed to resolve {}: {}", domain, err);
            send_servfail(server_socket, src_addr, payload).await;
        }
    }
}
