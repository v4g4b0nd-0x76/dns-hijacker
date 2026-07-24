pub mod cache;
pub mod constants;
pub mod dns;
pub mod domain_trie;
pub mod errors;
pub mod logger;
pub mod metric_wrapper;
pub mod netguard;
#[cfg(test)]
mod tests;
use socket2::{Domain, Protocol, Socket, Type};

pub use crate::errors::*;
use crate::{
    cache::ResponseCache,
    constants::{DNS_PROBE_PACKET, DOH_CONNECT_TIMEOUT, RESOLVE_TIMEOUT, SOCKET_RCVBUF_BYTES},
};
use aes_gcm::{
    Aes256Gcm,
    aead::{KeyInit, OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use lru::LruCache;
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, sync::Mutex};
use tokio::net::UdpSocket;

pub fn gen_relay_key(_conf_path: &PathBuf) -> Result<(), Error> {
    let key = Aes256Gcm::generate_key(OsRng);
    println!("{}", STANDARD.encode(key));
    Ok(())
}

pub fn empty_cache() -> ResponseCache {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(16).expect("cache capacity"),
    ))
}
pub fn mock_query_google() -> &'static [u8] {
    DNS_PROBE_PACKET
}
pub fn deserialize_redirect_list<'de, D>(deserializer: D) -> Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    use serde::de::Error;

    let entries = Vec::<String>::deserialize(deserializer)?;

    entries
        .into_iter()
        .map(|entry| {
            let (domain, target) = entry
                .split_once(':')
                .ok_or_else(|| D::Error::custom(format!("invalid redirect entry: {entry}")))?;

            Ok((domain.to_owned(), target.to_owned()))
        })
        .collect()
}

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
        tracing::warn!("failed to set SO_RCVBUF to {SOCKET_RCVBUF_BYTES}: {e}");
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

    tokio::net::UdpSocket::from_std(std_socket)
        .map_err(|e| Error::Other(format!("failed to convert to tokio socket: {e}")))
}

pub fn build_http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(RESOLVE_TIMEOUT)
        .connect_timeout(DOH_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| Error::Config(format!("failed to build HTTP client: {err}")))
}
