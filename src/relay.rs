use crate::{
    Error, ResolverPicker,
    conf::{Relay, RelayConf},
    dns::{build_lookup_query, parse_a_records},
};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::Client;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tracing::error;
use url::Url;

pub fn gen_relay_key(_conf_path: &PathBuf) -> Result<(), Error> {
    let key = Aes256Gcm::generate_key(OsRng);
    println!("{}", STANDARD.encode(key));
    Ok(())
}

pub fn encode_for_relay(key: &Key<Aes256Gcm>, dns_message: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, dns_message)
        .expect("encryption failure");
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decode_from_relay(key: &Key<Aes256Gcm>, packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let (nonce_bytes, ciphertext) = packet.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    Aes256Gcm::new(key).decrypt(nonce, ciphertext).ok()
}

pub fn load_key_from_str(key_b64: &str) -> Result<Key<Aes256Gcm>, Error> {
    let bytes = STANDARD
        .decode(key_b64)
        .map_err(|e| Error::Config(format!("invalid RELAY_KEY base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Config(format!(
            "RELAY_KEY must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&bytes))
}

pub async fn resolve_via_relay(
    http: &reqwest::Client,
    worker_url: &str,
    key: &Key<Aes256Gcm>,
    dns_query: &[u8],
) -> Result<Vec<u8>, Error> {
    let encrypted = encode_for_relay(key, dns_query);
    let response = http
        .post(worker_url)
        .body(encrypted)
        .send()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;
    decode_from_relay(key, &body).ok_or_else(|| Error::Config("decrypt failed".into()))
}

pub async fn resolve_domain_via_relay(
    http: &reqwest::Client,
    worker_url: &str,
    key: &Key<Aes256Gcm>,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, Error> {
    let query = build_lookup_query(domain);
    let encrypted = encode_for_relay(key, &query);
    let response = http
        .post(worker_url)
        .body(encrypted)
        .send()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;

    if !status.is_success() {
        let text = String::from_utf8_lossy(&body);
        return Err(Error::Config(format!(
            "relay returned {status} for {domain}: {text}"
        )));
    }

    let reply =
        decode_from_relay(key, &body).ok_or_else(|| Error::Config("decrypt failed".into()))?;
    let ips = parse_a_records(&reply);
    if ips.is_empty() {
        return Err(Error::Config(format!("no A records for {domain}")));
    }
    Ok(ips)
}

pub fn host_from_url(url_str: &str) -> Result<String, Error> {
    let url = Url::parse(url_str).map_err(|e| Error::Config(format!("invalid relay url: {e}")))?;
    url.host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| Error::Config("relay url has no host".into()))
}

pub fn client_for_relay(
    worker_url: &str,
    ipv4: Option<&[Ipv4Addr]>,
) -> Result<reqwest::Client, Error> {
    let host = host_from_url(worker_url)?;

    let mut builder = Client::builder();
    if let Some(ipv4) = ipv4 {
        let ip = *ipv4
            .first()
            .ok_or_else(|| Error::Config("no resolved IPs for relay".into()))?;
        let addr = SocketAddr::new(IpAddr::V4(ip), 443);
        builder = builder.resolve(&host, addr);
    }

    builder.build().map_err(|e| Error::Config(e.to_string()))
}

pub struct RelayInstance {
    relay_client: Arc<reqwest::Client>,
    key: Key<Aes256Gcm>,
    url: String,
}

impl RelayInstance {
    async fn new(
        conf: &Relay,
        resolver_picker: &ResolverPicker,
        http: &reqwest::Client,
        resolve_ipv4: bool,
    ) -> Result<Self, Error> {
        let relay_host = host_from_url(&conf.relay_url).map_err(|err| {
            let msg = format!("invalid relay_url {}: {}", conf.relay_url, err);
            error!("{}", msg);
            Error::RelayErr(msg)
        })?;

        let ipv4: Option<Vec<Ipv4Addr>> = if resolve_ipv4 {
            let resolved = resolver_picker
                .resolve(&relay_host, None, http)
                .await
                .map_err(|err| {
                    let msg = format!("failed to resolve relay host {}: {}", relay_host, err);
                    error!("{}", msg);
                    Error::RelayErr(msg)
                })?;

            if resolved.is_empty() {
                let msg = format!("failed to resolve relay host {}", relay_host);
                error!("{}", msg);
                return Err(Error::RelayErr(msg));
            }
            Some(resolved)
        } else {
            None
        };

        let relay_client = client_for_relay(&conf.relay_url, ipv4.as_deref()).map_err(|err| {
            let msg = format!("failed to build relay client: {}", err);
            error!("{}", msg);
            Error::RelayErr(msg)
        })?;

        let key = load_key_from_str(&conf.relay_key)
            .map_err(|err| Error::RelayErr(format!("invalid relay instance key: {}", err)))?;

        Ok(Self {
            relay_client: Arc::new(relay_client),
            key,
            url: conf.relay_url.clone(),
        })
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.relay_client
    }

    pub fn key(&self) -> &Key<Aes256Gcm> {
        &self.key
    }

    pub fn url(&self) -> &str {
        &self.url
    }
    #[cfg(test)]
    pub fn for_test(url: &str, key: Key<Aes256Gcm>) -> Self {
        Self {
            relay_client: Arc::new(reqwest::Client::new()),
            key,
            url: url.to_string(),
        }
    }
}

pub struct RelayPicker {
    instances: Vec<RelayInstance>,
    last_idx: AtomicUsize,
}

impl RelayPicker {
    pub async fn new(
        conf: &RelayConf,
        resolver_picker: &ResolverPicker,
        http: &reqwest::Client,
    ) -> Result<Self, Error> {
        if conf.relay_instances.is_empty() {
            return Err(Error::RelayErr("no relay instances configured".into()));
        }

        let mut instances = Vec::with_capacity(conf.relay_instances.len());
        for instance_conf in &conf.relay_instances {
            instances.push(RelayInstance::new(instance_conf, resolver_picker, http, conf.resolve_manual).await?);
        }

        Ok(Self {
            instances,
            last_idx: AtomicUsize::new(0),
        })
    }

    pub fn pick(&self) -> &RelayInstance {
        let idx = self.last_idx.fetch_add(1, Ordering::Relaxed) % self.instances.len();
        &self.instances[idx]
    }
    #[cfg(test)]
    pub fn from_instances(instances: Vec<RelayInstance>) -> Self {
        Self {
            instances,
            last_idx: AtomicUsize::new(0),
        }
    }
}
