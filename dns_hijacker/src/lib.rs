//! DNS hijacker library: config, resolver picker, packet helpers, and query handling.
use shared::*;
pub mod conf;
pub mod handler;
pub mod relay;
pub mod resolver;
pub use cache::{ResponseCache, new_cache};
pub use conf::{Conf, load_conf};
pub use errors::{DohError, Error};
pub use handler::handle_query;
pub use logger::init_logger;
pub use relay::gen_relay_key;
pub use resolver::{ResolverPicker, run_resolver_finder};

pub mod constants {
    use std::time::Duration;

    pub const UDP_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
    pub const SOCKET_BUF_SIZE: usize = 4 * 1024 * 1024;
    pub const SEARCH_RESOLVER_INTERVAL: u64 = 15;

    pub const BACKLOG_CAPACITY: usize = 1024; // bounded, ~2x semaphore size

    pub const NETGUARD_POLL_INTERVAL_MS: u64 = 1500;
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
