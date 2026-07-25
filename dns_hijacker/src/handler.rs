use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering::{AcqRel, Acquire, Relaxed, Release},
        },
    },
};

use crate::{
    cache::{ResponseCache, cache_key_from_query, cache_lookup, cache_store},
    dns::{
        craft_nxdomain_response, craft_redirect_response, parse_a_records, parse_domain, with_txid,
    },
    errors::Error,
    metric_wrapper::MetricWrapper,
    relay::RelayPicker,
    resolver::{DoqPool, ResolverPicker, resolve_from_upstream},
};
use crossbeam_queue::ArrayQueue;
use shared::{
    constants::RESOLVE_TIMEOUT,
    dns::{craft_servfail_response, send},
    domain_trie::{DomainTrie, RuleMatch, check_rules},
};
use tokio::{io::AsyncWriteExt, net::UdpSocket, time::timeout};
use tracing::{debug, error, warn};

pub struct HandleQueryParams<'a> {
    pub payload: &'a [u8],
    pub src_addr: SocketAddr,
    pub rule_trie: &'a Arc<DomainTrie>,
    pub resolver_picker: &'a ResolverPicker,
    pub server_socket: &'a UdpSocket,
    pub http: &'a reqwest::Client,
    pub cache: &'a ResponseCache,
    pub relay_picker: Option<&'a RelayPicker>,
    pub metric_wrapper: Option<&'a Arc<MetricWrapper>>,
    pub is_vpn_active: &'a Arc<AtomicBool>,
    pub doq_pool: &'a DoqPool,
    pub history_buffer: Option<&'a Arc<HistoryBuffer>>,
}
macro_rules! incr_metric {
    ($metric:expr, $field:ident) => {
        if let Some(m) = $metric {
            m.$field.fetch_add(1, Relaxed);
        }
    };
}

/// Runs the full drop/redirect/cache/resolve pipeline and returns the reply
/// bytes (with the original transaction ID restored) if one should be sent.
/// Does not send anything itself — callers decide how to deliver the bytes
/// (plain UDP, obfs-encoded UDP, etc).
pub async fn resolve_query<'a>(params: &HandleQueryParams<'a>) -> Option<Vec<u8>> {
    let HandleQueryParams {
        payload,
        src_addr,
        rule_trie,
        resolver_picker,
        http,
        cache,
        relay_picker,
        metric_wrapper,
        is_vpn_active,
        doq_pool,
        history_buffer,
        ..
    } = *params;

    if payload.len() < 12 {
        error!("invalid payload len");
        return None;
    }
    let (domain, qname_end) = parse_domain(payload, 12)?;
    debug!("Resolving {}", domain);

    match check_rules(&domain, rule_trie) {
        RuleMatch::Drop => {
            warn!("[Dropped] {}", domain);
            let resp = craft_nxdomain_response(payload)?;
            incr_metric!(metric_wrapper, drop_count);
            return Some(resp);
        }
        RuleMatch::Redirect(ips) => {
            let ip_refs: Vec<&str> = ips.iter().map(String::as_str).collect();
            warn!("[REDIRECT] {} -> {:?}", domain, ip_refs);
            let resp = craft_redirect_response(payload, qname_end, ip_refs)?;
            incr_metric!(metric_wrapper, redirect_count);
            return Some(resp);
        }
        RuleMatch::None => {}
    }

    let cache_key = cache_key_from_query(payload)?;
    let req_txid = [payload[0], payload[1]];

    if let Some(cached) = cache_lookup(cache, &cache_key) {
        debug!("[CACHE HIT] {}", domain);
        incr_metric!(metric_wrapper, cached_count);
        return Some(with_txid(cached, req_txid));
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
        let resolver = resolver_picker
            .pick_doh_first(is_vpn_active.load(std::sync::atomic::Ordering::Relaxed));
        timeout(
            RESOLVE_TIMEOUT,
            resolve_from_upstream(payload, &resolver, src_addr, http, doq_pool),
        )
        .await
        .unwrap_or(Err(Error::ResolveTimeout))
        .map(|(buf, _len)| buf)
    };

    match resolve_result {
        Ok(reply_buf) => {
            cache_store(cache, cache_key, &reply_buf);
            incr_metric!(metric_wrapper, resolved_count);
            if let Some(history_buffer) = history_buffer {
                let a_records = parse_a_records(&reply_buf);
                let ips: Vec<String> = a_records.iter().map(|ip| ip.to_string()).collect();
                history_buffer.push_many(domain, ips);
            }
            Some(with_txid(reply_buf, req_txid))
        }
        Err(Error::ResolveTimeout) => {
            error!(
                "resolve timed out for {} after {:?}",
                domain, RESOLVE_TIMEOUT
            );
            incr_metric!(metric_wrapper, timeout_count);
            craft_servfail_response(payload)
        }
        Err(err) => {
            error!("failed to resolve {}: {}", domain, err);
            incr_metric!(metric_wrapper, failed_count);
            craft_servfail_response(payload)
        }
    }
}

/// Plain-UDP wrapper: resolves and sends the reply straight back over the
/// socket the query arrived on. This is what the existing main loop calls.
pub async fn handle_query<'a>(params: &HandleQueryParams<'a>) {
    if let Some(resp) = resolve_query(params).await {
        send(params.server_socket, params.src_addr, resp).await;
    }
}

pub type HistoryBufferEntry = (String, Vec<String>); // domain to ipv4
const CAP: usize = 100;
pub struct HistoryBuffer {
    path: PathBuf,
    queue: ArrayQueue<HistoryBufferEntry>,
    flushing: AtomicBool,
}
impl HistoryBuffer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            queue: ArrayQueue::new(CAP),
            flushing: AtomicBool::new(false),
        }
    }

    pub fn push(self: &Arc<Self>, domain: String, ip: String) {
        self.push_many(domain, vec![ip]);
    }

    pub fn push_many(self: &Arc<Self>, domain: String, ips: Vec<String>) {
        if ips.is_empty() {
            return;
        }
        let mut entry = (domain, ips);
        while let Err(rejected) = self.queue.push(entry) {
            entry = rejected;
            self.try_spawn_flush();
            std::hint::spin_loop();
        }
        if self.queue.len() >= CAP {
            self.try_spawn_flush();
        }
    }
    fn try_spawn_flush(self: &Arc<Self>) {
        if self
            .flushing
            .compare_exchange(false, true, AcqRel, Acquire)
            .is_ok()
        {
            let this = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(e) = this.flush().await {
                    tracing::error!("history flush failed: {e:?}");
                }
                this.flushing.store(false, Release);
            });
        }
    }

    async fn flush(&self) -> Result<(), Error> {
        let mut batch = Vec::with_capacity(CAP);
        while let Some(entry) = self.queue.pop() {
            batch.push(entry);
        }
        if batch.is_empty() {
            return Ok(());
        }

        let mut history: HashMap<String, Vec<String>> = HashMap::new();
        let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&self.path).await {
            for line in content.lines() {
                let mut parts = line.split_whitespace();
                if let Some(domain) = parts.next() {
                    let ips: Vec<String> = parts.map(String::from).collect();
                    seen.insert(domain.to_string(), ips.iter().cloned().collect());
                    order.push(domain.to_string());
                    history.insert(domain.to_string(), ips);
                }
            }
        }

        for (domain, ips) in batch {
            let existing = history.entry(domain.clone()).or_insert_with(|| {
                order.push(domain.clone());
                Vec::new()
            });
            let seen_set = seen.entry(domain.clone()).or_default();

            for ip in ips {
                // skip if this ip has ever been recorded for this domain before
                if seen_set.insert(ip.clone()) {
                    existing.push(ip);
                }
            }
        }

        let mut out = String::new();
        for domain in &order {
            out.push_str(domain);
            for ip in &history[domain] {
                out.push(' ');
                out.push_str(ip);
            }
            out.push('\n');
        }

        let mut file = tokio::fs::File::create(&self.path).await?;
        file.write_all(out.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
    pub async fn close(self: &Arc<Self>) -> Result<(), Error> {
        while self.flushing.load(Acquire) {
            tokio::task::yield_now().await;
        }
        self.flush().await
    }
}
