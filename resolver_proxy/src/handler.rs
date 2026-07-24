use std::sync::{Arc, atomic::AtomicBool};

use shared::{cache::ResponseCache, domain_trie::DomainTrie, metric_wrapper::MetricWrapper};
use tokio::net::{UdpSocket, unix::SocketAddr};

pub struct HandleQueryParams<'a> {
    pub payload: &'a [u8],
    pub src_addr: SocketAddr,
    pub rule_trie: &'a Arc<DomainTrie>,
    pub server_socket: &'a UdpSocket,
    pub http: &'a reqwest::Client,
    pub cache: &'a ResponseCache,
    pub metric_wrapper: Option<&'a Arc<MetricWrapper>>,
    pub is_vpn_active: &'a Arc<AtomicBool>,
}
