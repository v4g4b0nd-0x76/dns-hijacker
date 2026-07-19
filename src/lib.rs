//! DNS hijacker library: config, resolver picker, packet helpers, and query handling.

pub mod cache;
pub mod conf;
pub mod dns;
pub mod errors;
pub mod handler;
pub mod logger;
pub mod metric_wrapper;
pub mod relay;
pub mod resolver;
pub use cache::{ResponseCache, new_cache};
pub use conf::{Conf, load_conf};
pub use errors::{DohError, Error};
pub use handler::{bind_udp_socket, handle_query};
pub use logger::init_logger;
pub use relay::gen_relay_key;
pub use resolver::{ResolverPicker, build_http_client, run_resolver_finder};

pub mod constants {
    use std::time::Duration;

    pub const LOCAL_DNS: &str = "127.0.0.1:53";
    pub const PAYLOAD_BUF_SIZE: usize = 1024;
    pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
    pub const DOH_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
    pub const UDP_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
    pub const SOCKET_BUF_SIZE: usize = 4 * 1024 * 1024;
    pub const CACHE_CAPACITY: usize = 4096;
    pub const CACHE_TTL_MIN: Duration = Duration::from_secs(5);
    pub const CACHE_TTL_MAX: Duration = Duration::from_secs(300);
    pub const CACHE_TTL_FALLBACK: Duration = Duration::from_secs(60);
    pub const SEARCH_RESOLVER_INTERVAL: u64 = 15;

    pub const RESOLVE_SEMAPHORE: usize = 512; // was likely 64/128 — raise it
    pub const RECV_BATCH_MAX: usize = 256; // drain more per wakeup during bursts

    pub const BACKLOG_CAPACITY: usize = 1024; // bounded, ~2x semaphore size
    pub const MAX_BACKLOG_AGE_MS: u64 = 800; // drop entries older than this (client will have retried)

    pub const SOCKET_RCVBUF_BYTES: usize = 4 * 1024 * 1024; // 4MB

    /// Minimal DNS query for `google.com` A record, used as a health-check probe.
    pub const DNS_PROBE_PACKET: &[u8] = &[
        0xAA, 0xBB, // Transaction ID
        0x01, 0x00, // Flags: Standard Query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', // Label: google
        0x03, b'c', b'o', b'm', // Label: com
        0x00, // Null terminator
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ];
}
pub mod helpers {
    use crate::Error;
    use std::net::IpAddr;

    pub fn clear_screen() {
        print!("\x1B[2J\x1B[1;1H"); // clear screen, move cursor to top-left
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }

    pub async fn get_public_ip(http: &reqwest::Client) -> Result<IpAddr, Error> {
        let resp = http
            .get("https://api.ipify.org")
            .send()
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
        let text = resp.text().await.map_err(|e| Error::Other(e.to_string()))?;
        text.trim()
            .parse::<IpAddr>()
            .map_err(|_| Error::Other("invalid public IP response".into()))
    }
}

#[cfg(test)]
mod tests;
