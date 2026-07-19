use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
};

use tokio::{net::UdpSocket, time::timeout};

use crate::{
    cache::{ResponseCache, cache_key_from_query, cache_lookup, cache_store},
    constants::{RESOLVE_TIMEOUT, SOCKET_BUF_SIZE},
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response, parse_domain,
        with_txid,
    },
    errors::Error,
    metric_wrapper::MetricWrapper,
    relay::RelayPicker,
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
enum RuleMatch {
    Drop,
    Redirect(Vec<String>),
    None,
}

fn check_rules(domain: &str, trie: &DomainTrie) -> RuleMatch {
    match trie.lookup(domain) {
        DomainTriePolicy::Drop => RuleMatch::Drop,
        DomainTriePolicy::Redirect(ips) => RuleMatch::Redirect(ips.clone()),
        DomainTriePolicy::None => RuleMatch::None,
    }
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
    pub rule_trie: &'a Arc<DomainTrie>,
    pub resolver_picker: &'a ResolverPicker,
    pub server_socket: &'a UdpSocket,
    pub http: &'a reqwest::Client,
    pub cache: &'a ResponseCache,
    pub relay_picker: Option<&'a RelayPicker>,
    pub socket: &'a Arc<UdpSocket>,
    pub metric_wrapper: Option<&'a Arc<MetricWrapper>>,
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
        resolver_picker,
        server_socket,
        http,
        cache,
        relay_picker,
        socket,
        metric_wrapper,
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
    let resolve_result: Result<Vec<u8>, Error> = if let Some(relay_picker) = relay_picker {
        let instance = relay_picker.pick();
        timeout(
            relay_picker.timeout_duration(),
            instance.resolve(&domain, payload),
        )
        .await
        .unwrap_or(Err(Error::ResolveTimeout))
    } else {
        let resolver = resolver_picker.pick();
        timeout(
            RESOLVE_TIMEOUT,
            resolve_from_upstream(payload, &resolver, src_addr, http, socket),
        )
        .await
        .unwrap_or(Err(Error::ResolveTimeout))
        .map(|(buf, _len)| buf)
    };

    match resolve_result {
        Ok(reply_buf) => {
            cache_store(cache, cache_key, &reply_buf);
            incr_metric!(metric_wrapper, resolved_count);
            send(server_socket, src_addr, with_txid(reply_buf, req_txid)).await;
        }
        Err(Error::ResolveTimeout) => {
            error!(
                "resolve timed out for {} after {:?}",
                domain, RESOLVE_TIMEOUT
            );
            incr_metric!(metric_wrapper, timeout_count);
            send_servfail(server_socket, src_addr, payload).await;
        }
        Err(err) => {
            error!("failed to resolve {}: {}", domain, err);
            incr_metric!(metric_wrapper, failed_count);
            send_servfail(server_socket, src_addr, payload).await;
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum DomainTriePolicy {
    #[default]
    None,
    Drop,
    Redirect(Vec<String>),
}

#[derive(Default)]
pub struct DomainTrie {
    children: HashMap<String, DomainTrie>,
    policy: DomainTriePolicy,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Walks/creates the path for `pattern` and sets the policy on the
    /// resulting leaf node - NOT on `self`. This is the fix for the bug
    /// in the draft: `node` (the leaf found by the loop) must be the
    /// thing mutated, since `self` is still the trie root at this point.
    fn insert_with_policy(&mut self, pattern: &str, policy: DomainTriePolicy) {
        let pattern = pattern.trim_end_matches('.').to_lowercase();
        let pattern = pattern.strip_prefix("*.").unwrap_or(&pattern);

        let mut node = self;
        for label in pattern.rsplit('.') {
            node = node.children.entry(label.to_string()).or_default();
        }
        node.policy = policy;
    }

    pub fn insert_drop(&mut self, pattern: &str) {
        self.insert_with_policy(pattern, DomainTriePolicy::Drop);
    }

    /// `ip_with_port` matches your existing redirect_list's second tuple
    /// element, e.g. "10.0.0.5,10.0.0.6" or "10.0.0.5:53" - split on both
    /// separators the same way your old craft_redirect_response call site did.
    pub fn insert_redirect(&mut self, pattern: &str, ip_with_port: &str) {
        let ips: Vec<String> = ip_with_port
            .split(',')
            .map(|entry| entry.split(':').next().unwrap_or(entry).to_string())
            .collect();
        self.insert_with_policy(pattern, DomainTriePolicy::Redirect(ips));
    }

    /// Builds a single trie containing both drop and redirect rules -
    /// matches your apparent intent of one DomainTrieType-driven structure
    /// rather than two separate generic tries.
    pub fn build(drop_list: &[String], redirect_list: &[(String, String)]) -> Self {
        let mut trie = Self::new();
        for pattern in drop_list {
            let pattern = pattern.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            trie.insert_drop(pattern);
        }
        for (pattern, ip_with_port) in redirect_list {
            let pattern = pattern.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            trie.insert_redirect(pattern, ip_with_port);
        }
        trie
    }

    /// Returns the policy at the closest matching boundary, walking TLD-down.
    /// A non-`None` policy on an ancestor short-circuits the walk, matching
    /// "*.example.com blocks all subdomains" semantics.
    pub fn lookup(&self, domain: &str) -> &DomainTriePolicy {
        let domain = domain.trim_end_matches('.').to_lowercase();
        let mut node = self;
        for label in domain.rsplit('.') {
            match node.children.get(label) {
                Some(next) => {
                    if next.policy != DomainTriePolicy::None {
                        return &next.policy;
                    }
                    node = next;
                }
                None => return &DomainTriePolicy::None,
            }
        }
        &DomainTriePolicy::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_and_redirect_coexist() {
        let drop_list = vec!["ads.example.com".to_string()];
        let redirect_list = vec![("internal.corp".to_string(), "10.0.0.5,10.0.0.6".to_string())];
        let trie = DomainTrie::build(&drop_list, &redirect_list);

        assert_eq!(trie.lookup("ads.example.com"), &DomainTriePolicy::Drop);
        assert_eq!(
            trie.lookup("tracker.ads.example.com"),
            &DomainTriePolicy::Drop
        );
        assert_eq!(
            trie.lookup("app.internal.corp"),
            &DomainTriePolicy::Redirect(vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()])
        );
        assert_eq!(trie.lookup("unrelated.com"), &DomainTriePolicy::None);
    }
}
