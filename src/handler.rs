use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, LazyLock},
};

use reqwest::Client;
use std::collections::HashMap;
use std::sync::RwLock;
use tokio::{net::UdpSocket, time::timeout};
use url::Url;

use crate::{
    cache::{
        DomainCache, ResponseCache, cache_key_from_query, cache_lookup, cache_store, cache_url_ip,
        get_cached_domain,
    },
    conf::RelayConf,
    constants::{RESOLVE_TIMEOUT, SOCKET_BUF_SIZE},
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response,
        matches_domain_pattern, parse_domain, with_txid,
    },
    errors::Error,
    relay::resolve_via_relay,
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

static RELAY_CLIENTS: LazyLock<RwLock<HashMap<String, Client>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn host_from_url(url_str: &str) -> Result<String, Error> {
    let url = Url::parse(url_str).map_err(|e| Error::Config(format!("invalid relay url: {e}")))?;
    url.host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| Error::Config("relay url has no host".into()))
}

pub fn client_for_relay(worker_url: &str, ipv4: &[Ipv4Addr]) -> Result<Client, Error> {
    let host = host_from_url(worker_url)?;
    let ip = *ipv4
        .first()
        .ok_or_else(|| Error::Config("no resolved IPs for relay".into()))?;
    let key = format!("{host}|{ip}");

    if let Some(client) = RELAY_CLIENTS.read().unwrap().get(&key) {
        return Ok(client.clone());
    }

    let addr = SocketAddr::new(IpAddr::V4(ip), 443);
    let client = Client::builder()
        .resolve(&host, addr) // pins this hostname -> IP, bypassing OS DNS entirely
        .build()
        .map_err(|e| Error::Config(e.to_string()))?;

    RELAY_CLIENTS.write().unwrap().insert(key, client.clone());
    Ok(client)
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
    domain_cache: &DomainCache,
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
        let relay_host = match host_from_url(&relay_conf.relay_url) {
            Ok(host) => host,
            Err(err) => {
                error!("invalid relay_url {}: {}", relay_conf.relay_url, err);
                if let Some(resp) = craft_servfail_response(payload) {
                    let _ = server_socket.send_to(&resp, src_addr).await;
                }
                return;
            }
        };
        let ipv4 = match get_cached_domain(domain_cache, &relay_host) {
            Some(ipv4) => {
                ipv4
            }
            None => match resolver_picker.resolve(&relay_host.clone(), None, http).await {
                Ok(ipv4) => {

                    if ipv4.is_empty() {
                        error!("failed to resolve relay host {}", relay_host);
                        if let Some(resp) = craft_servfail_response(payload) {
                            let _ = server_socket.send_to(&resp, src_addr).await;
                        }
                    }
                    cache_url_ip(domain_cache, &relay_host, ipv4.clone());
                    ipv4
                }
                Err(err) => {
                    error!(
                        "failed to resolve relay host {}: {}",
                        relay_host, err
                    );
                    if let Some(resp) = craft_servfail_response(payload) {
                        let _ = server_socket.send_to(&resp, src_addr).await;
                    }
                    return;
                }
            },
        };

        let relay_client = match client_for_relay(&relay_conf.relay_url, &ipv4) {
            Ok(client) => client,
            Err(err) => {
                error!("failed to build relay client: {}", err);
                if let Some(resp) = craft_servfail_response(payload) {
                    let _ = server_socket.send_to(&resp, src_addr).await;
                }
                return;
            }
        };
        match timeout(
            RESOLVE_TIMEOUT,
            resolve_via_relay(
                &relay_client,
                &relay_conf.relay_url,
                &relay_conf.key,
                payload,
            ),
        )
        .await
        {
            Ok(Ok(reply_buf)) => {
                cache_store(cache, cache_key, &reply_buf);
                let resp = with_txid(reply_buf, req_txid);
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
