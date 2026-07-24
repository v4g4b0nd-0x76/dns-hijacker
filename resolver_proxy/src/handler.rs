use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
};
use tracing::{debug, error, warn};

use shared::{
    cache::{ResponseCache, cache_key_from_query, cache_lookup},
    dns::{craft_nxdomain_response, craft_redirect_response, parse_domain, send, with_txid},
    domain_trie::{DomainTrie, RuleMatch, check_rules},
    metric_wrapper::MetricWrapper,
};
use tokio::net::UdpSocket;

pub struct HandleQueryParams<'a> {
    pub payload: &'a [u8],
    pub src_addr: SocketAddr,
    pub rule_trie: &'a Arc<DomainTrie>,
    pub server_socket: &'a UdpSocket,
    pub http: &'a reqwest::Client,
    pub cache: &'a ResponseCache,
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
        server_socket,
        http,
        cache,
        metric_wrapper,
    } = *params;
    if payload.len() < 12 {
        error!("invalid payload len");
        return;

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
    }
}
