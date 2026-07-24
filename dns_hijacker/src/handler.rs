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
    constants::RESOLVE_TIMEOUT,
    dns::{
        craft_nxdomain_response, craft_redirect_response, craft_servfail_response, parse_a_records,
        parse_domain, with_txid,
    },
    errors::Error,
    metric_wrapper::MetricWrapper,
    relay::RelayPicker,
    resolver::{DoqPool, ResolverPicker, resolve_from_upstream},
};
use crossbeam_queue::ArrayQueue;
use shared::domain_trie::{DomainTrie, RuleMatch, check_rules};
use tokio::{io::AsyncWriteExt, net::UdpSocket, time::timeout};
use tracing::{debug, error, warn};

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
        metric_wrapper,
        is_vpn_active,
        doq_pool,
        history_buffer,
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
