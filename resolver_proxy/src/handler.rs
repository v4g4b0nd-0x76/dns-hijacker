use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{
            AtomicUsize,
            Ordering::{self, Relaxed},
        },
    },
    time::Duration,
};
use tracing::{debug, error, warn};

use shared::{
    Error,
    cache::{ResponseCache, cache_key_from_query, cache_lookup, cache_store},
    constants::RESOLVE_TIMEOUT,
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response, parse_domain,
        send, with_txid,
    },
    domain_trie::{DomainTrie, RuleMatch, check_rules},
    metric_wrapper::MetricWrapper,
    obfs::ObfsKey,
};
use tokio::{net::UdpSocket, time::timeout};

use crate::conf::{ProxyConf, ProxyStrategy, TransportMode};

const PROXY_PAYLOAD_BUF_SIZE: usize = 4096;
pub struct HandleQueryParams<'a> {
    pub payload: &'a [u8],
    pub src_addr: SocketAddr,
    pub rule_trie: &'a Arc<DomainTrie>,
    pub server_socket: &'a UdpSocket,
    pub cache: &'a ResponseCache,
    pub metric_wrapper: Option<&'a Arc<MetricWrapper>>,
    pub target_picker: &'a Arc<TargetPicker>,
}
macro_rules! incr_metric {
    ($metric:expr, $field:ident) => {
        if let Some(m) = $metric {
            m.$field.fetch_add(1, Relaxed);
        }
    };
}
pub async fn handle_query<'a>(params: &HandleQueryParams<'a>) {
    let HandleQueryParams {
        payload,
        src_addr,
        rule_trie,
        server_socket,
        cache,
        metric_wrapper,
        target_picker,
    } = *params;
    if payload.len() < 12 {
        error!("invalid payload len");
        return;
    }

    let Some((domain, qname_end)) = parse_domain(payload, 12) else {
        return;
    };
    debug!("Resolving {}", domain);

    match check_rules(&domain, rule_trie) {
        RuleMatch::Drop => {
            warn!("[Dropped] {}", domain);
            if let Some(resp) = craft_nxdomain_response(payload) {
                incr_metric!(metric_wrapper, drop_count);
                send(server_socket, src_addr, resp).await;
            }
            return;
        }
        RuleMatch::Redirect(ips) => {
            let ip_refs: Vec<&str> = ips.iter().map(String::as_str).collect();
            warn!("[REDIRECT] {} -> {:?}", domain, ip_refs);
            if let Some(resp) = craft_redirect_response(payload, qname_end, ip_refs) {
                incr_metric!(metric_wrapper, redirect_count);
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

        incr_metric!(metric_wrapper, cached_count);
        send(server_socket, src_addr, with_txid(cached, req_txid)).await;
        return;
    }
    match forward_query(target_picker, payload, RESOLVE_TIMEOUT).await {
        Ok(reply_buf) => {
            cache_store(cache, cache_key, &reply_buf);
            incr_metric!(metric_wrapper, resolved_count);
            send(server_socket, src_addr, with_txid(reply_buf, req_txid)).await;
        }
        Err(err) => {
            error!("failed to resolve {}: {}", domain, err);
            incr_metric!(metric_wrapper, failed_count);
            craft_servfail_response(payload);
        }
    };
}

pub struct ResolvedTarget {
    pub name: String,
    pub mode: TransportMode,
    pub addr: SocketAddr,
    pub key: Option<ObfsKey>,
}

pub fn resolve_targets(conf: &ProxyConf) -> Result<Vec<ResolvedTarget>, Error> {
    conf.targets
        .iter()
        .map(|t| {
            let addr = t
                .address
                .to_socket_addrs()
                .map_err(|e| Error::Config(format!("bad target address {}: {e}", t.address)))?
                .next()
                .ok_or_else(|| Error::Config(format!("could not resolve {}", t.address)))?;

            let key = match &t.mode {
                TransportMode::UdpObfs => {
                    let k = t.shared_key.as_ref().ok_or_else(|| {
                        Error::Config(format!("target {} needs shared_key for udp_obfs", t.name))
                    })?;
                    Some(ObfsKey::from_base64(k).map_err(|_| {
                        Error::Config(format!("invalid shared_key for target {}", t.name))
                    })?)
                }
                TransportMode::Plain => None,
            };

            Ok(ResolvedTarget {
                name: t.name.clone(),
                mode: t.mode.clone(),
                addr,
                key,
            })
        })
        .collect()
}

pub struct TargetPicker {
    targets: Vec<ResolvedTarget>,
    strategy: ProxyStrategy,
    cursor: AtomicUsize,
}

impl TargetPicker {
    pub fn new(targets: Vec<ResolvedTarget>, strategy: ProxyStrategy) -> Result<Self, Error> {
        if targets.is_empty() {
            return Err(Error::Config("no proxy targets configured".into()));
        }
        Ok(Self {
            targets,
            strategy,
            cursor: AtomicUsize::new(0),
        })
    }

    /// Returns targets in the order to try them: for `ordered`, always the
    /// configured order (first = primary, rest = fallback). For
    /// `round_robin`, rotates the starting point each call but still
    /// returns every target as a fallback chain.
    pub fn try_order(&self) -> Vec<&ResolvedTarget> {
        match self.strategy {
            ProxyStrategy::Ordered => self.targets.iter().collect(),
            ProxyStrategy::RoundRobin => {
                let start = self.cursor.fetch_add(1, Ordering::Relaxed) % self.targets.len();
                self.targets[start..]
                    .iter()
                    .chain(self.targets[..start].iter())
                    .collect()
            }
        }
    }
}

/// Tries each target in the picker's order until one responds, returning the
/// first successful reply. The original DNS query bytes (including the
/// OS-assigned transaction ID) are sent as-is — dns_relay preserves the
/// transaction ID on its reply, so no rewriting is needed on the way back.
async fn forward_query(
    picker: &TargetPicker,
    query: &[u8],
    upstream_timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let mut last_err = Error::NoHealthyResolvers;

    for target in picker.try_order() {
        let result = match target.mode {
            TransportMode::Plain => send_plain(target.addr, query, upstream_timeout).await,
            TransportMode::UdpObfs => {
                let key = target
                    .key
                    .as_ref()
                    .expect("udp_obfs target validated to have a key at startup");
                send_obfs(target.addr, key, query, upstream_timeout).await
            }
        };

        match result {
            Ok(reply) => return Ok(reply),
            Err(err) => {
                debug!("[proxy] target {} failed: {}", target.name, err);
                last_err = err;
            }
        }
    }

    Err(last_err)
}

async fn send_plain(
    addr: SocketAddr,
    query: &[u8],
    upstream_timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await.map_err(Error::from)?;
    sock.connect(addr).await.map_err(Error::from)?;
    sock.send(query).await.map_err(Error::from)?;

    let mut buf = [0u8; PROXY_PAYLOAD_BUF_SIZE];
    let n = timeout(upstream_timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| Error::ResolveTimeout)?
        .map_err(Error::from)?;
    Ok(buf[..n].to_vec())
}

async fn send_obfs(
    addr: SocketAddr,
    key: &ObfsKey,
    query: &[u8],
    upstream_timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await.map_err(Error::from)?;
    sock.connect(addr).await.map_err(Error::from)?;

    let encoded = key.encode(query);
    sock.send(&encoded).await.map_err(Error::from)?;

    let mut buf = [0u8; PROXY_PAYLOAD_BUF_SIZE];
    let n = timeout(upstream_timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| Error::ResolveTimeout)?
        .map_err(Error::from)?;

    key.decode(&buf[..n]).ok_or(Error::InvalidResolver(format!(
        "undecodable obfs reply from {addr}"
    )))
}
