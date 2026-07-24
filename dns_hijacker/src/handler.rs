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
    constants::{RESOLVE_TIMEOUT, SOCKET_RCVBUF_BYTES},
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
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::AsyncWriteExt, net::UdpSocket, time::timeout};
use tracing::{debug, error, warn};

pub fn bind_udp_socket(addr: &str) -> Result<UdpSocket, Error> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| Error::Other(format!("bad addr: {e}")))?;
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| Error::Other(format!("failed to create socket: {e}")))?;

    // Critical for macOS: default kernel recv buffer is too small for a resolver-switch burst.
    // Without this, packets are dropped by the kernel before recv_from ever sees them.
    if let Err(e) = socket.set_recv_buffer_size(SOCKET_RCVBUF_BYTES) {
        warn!("failed to set SO_RCVBUF to {SOCKET_RCVBUF_BYTES}: {e}");
    }
    socket.set_reuse_address(true).ok();

    socket
        .bind(&sock_addr.into())
        .map_err(|e| Error::Other(format!("failed to bind: {e}")))?;

    // Must be non-blocking BEFORE handing to tokio, or UdpSocket::from_std will reject it.
    socket
        .set_nonblocking(true)
        .map_err(|e| Error::Other(format!("failed to set nonblocking: {e}")))?;

    let std_socket: std::net::UdpSocket = socket.into();

    // Requires an active Tokio runtime context (fine here — always called from within #[tokio::main]).
    tokio::net::UdpSocket::from_std(std_socket)
        .map_err(|e| Error::Other(format!("failed to convert to tokio socket: {e}")))
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

    pub fn build(drop_list: &[String], redirect_list: &[(String, String)]) -> Self {
        let mut trie = Self::new();

        let is_file_reference = |pattern: &str| {
            pattern.starts_with('/') || pattern.starts_with("./") || pattern.starts_with("../")
        };

        let read_list_file = |path: &str| -> Vec<String> {
            match std::fs::read_to_string(path) {
                Ok(content) => content
                    .lines()
                    .filter_map(|raw_line| {
                        let line = raw_line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            return None;
                        }
                        line.split_whitespace().next().map(str::to_string)
                    })
                    .collect(),
                Err(err) => {
                    tracing::error!("failed to read list file {}: {}", path, err);
                    Vec::new()
                }
            }
        };

        for entry in drop_list {
            let pattern = entry.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            if is_file_reference(pattern) {
                let lines = read_list_file(pattern);
                tracing::info!("loaded {} drop entries from {}", lines.len(), pattern);
                for domain in &lines {
                    trie.insert_drop(domain);
                }
            } else {
                trie.insert_drop(pattern);
            }
        }

        for (pattern, target) in redirect_list {
            let pattern = pattern.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            if is_file_reference(pattern) {
                let lines = read_list_file(pattern);
                tracing::info!("loaded {} redirect entries from {}", lines.len(), pattern);
                for line in &lines {
                    match line.split_once(':') {
                        Some((from, to)) if !from.trim().is_empty() && !to.trim().is_empty() => {
                            trie.insert_redirect(from.trim(), to.trim());
                        }
                        _ => tracing::warn!(
                            "skipping malformed redirect line in {}: {:?} (expected domain:ip1,ip2)",
                            pattern,
                            line
                        ),
                    }
                }
            } else {
                trie.insert_redirect(pattern, target);
            }
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
