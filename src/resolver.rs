use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{net::UdpSocket, time::timeout};

use crate::{
    constants::{DNS_PROBE_PACKET, DOH_CONNECT_TIMEOUT, RESOLVE_TIMEOUT, UDP_PROBE_TIMEOUT},
    dns::inject_ecs_option,
    errors::{DohError, Error},
};
use tracing::{error, info};

#[derive(Clone)]
pub struct ResolverPicker {
    healthy_resolvers: Arc<Vec<String>>,
}

impl ResolverPicker {
    pub async fn new(resolvers: Vec<String>, http: reqwest::Client) -> Result<Self, Error> {
        let mut tasks = Vec::new();

        for resolver in resolvers {
            let http = http.clone();
            tasks.push(tokio::spawn(async move {
                match Self::measure_latency(&resolver, &http).await {
                    Ok(latency) => {
                        info!("[PICKER LOG] {} responded in {:?}", resolver, latency);
                        Some((resolver, latency))
                    }
                    Err(e) => {
                        error!("[PICKER WARN] {} failed health check: {}", resolver, e);
                        None
                    }
                }
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some((resolver, latency))) = task.await {
                results.push((resolver, latency));
            }
        }

        if results.is_empty() {
            return Err(Error::NoHealthyResolvers);
        }

        results.sort_by_key(|&(_, latency)| latency);

        let sorted_resolvers: Vec<String> = results.into_iter().map(|(res, _)| res).collect();

        info!(
            "[PICKER] Healthy upstreams discovered and sorted: {:?}",
            sorted_resolvers
        );

        Ok(Self {
            healthy_resolvers: Arc::new(sorted_resolvers),
        })
    }

    /// Construct a picker that skips health checks (used by tests).
    pub fn from_healthy(resolvers: Vec<String>) -> Self {
        Self {
            healthy_resolvers: Arc::new(resolvers),
        }
    }

    pub fn pick(&self) -> &str {
        &self.healthy_resolvers[0]
    }

    async fn measure_latency(resolver: &str, http: &reqwest::Client) -> Result<Duration, Error> {
        let start = Instant::now();

        if resolver.starts_with("https://") {
            let req_future = http
                .post(resolver)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(DNS_PROBE_PACKET.to_vec())
                .send();

            let response = match timeout(RESOLVE_TIMEOUT, req_future).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => return Err(DohError::Request(err).into()),
                Err(_) => return Err(DohError::Timeout.into()),
            };

            if !response.status().is_success() {
                return Err(DohError::Status(response.status()).into());
            }

            let _ = response.bytes().await.map_err(DohError::Body)?;
            return Ok(start.elapsed());
        }

        let addr: SocketAddr = resolver
            .parse()
            .map_err(|_| Error::InvalidResolver(resolver.to_owned()))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(DNS_PROBE_PACKET, addr).await?;

        let mut buf = [0u8; 512];
        match timeout(UDP_PROBE_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(Ok(_)) => Ok(start.elapsed()),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Err(Error::UdpTimeout),
        }
    }
}

pub fn build_http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(RESOLVE_TIMEOUT)
        .connect_timeout(DOH_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| Error::Config(format!("failed to build HTTP client: {err}")))
}

pub async fn resolve_from_upstream(
    payload: &[u8],
    upstream_resolver: &str,
    src_addr: SocketAddr,
    http: &reqwest::Client,
) -> Result<(Vec<u8>, usize), Error> {
    let final_payload = inject_ecs_option(payload, src_addr).unwrap_or_else(|| payload.to_vec());

    if upstream_resolver.starts_with("https://") {
        return resolve_via_doh(http, upstream_resolver, &final_payload).await;
    }

    let upstream_addr: SocketAddr = upstream_resolver
        .parse()
        .map_err(|_| Error::InvalidResolver(upstream_resolver.to_owned()))?;

    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
    upstream_socket
        .send_to(&final_payload, upstream_addr)
        .await?;

    let mut reply_buf = [0u8; 4096];
    let (reply_len, _) = timeout(RESOLVE_TIMEOUT, upstream_socket.recv_from(&mut reply_buf))
        .await
        .map_err(|_| Error::ResolveTimeout)?
        .map_err(Error::from)?;

    Ok((reply_buf[..reply_len].to_vec(), reply_len))
}

pub async fn resolve_via_doh(
    http: &reqwest::Client,
    url: &str,
    payload: &[u8],
) -> Result<(Vec<u8>, usize), Error> {
    let response = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(payload.to_vec())
        .send()
        .await
        .map_err(DohError::Request)?;

    if !response.status().is_success() {
        return Err(DohError::Status(response.status()).into());
    }

    let body_bytes = response.bytes().await.map_err(DohError::Body)?;
    let reply_len = body_bytes.len();
    Ok((body_bytes.to_vec(), reply_len))
}
