use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::SystemTime;

use serde::Deserialize;
use shared::Error;
use shared::deserialize_redirect_list;
#[derive(Deserialize)]
pub struct Conf {
    #[serde(default = "default_empty_vec")]
    pub drop_list: Vec<String>,
    #[serde(
        deserialize_with = "deserialize_redirect_list",
        default = "default_empty_vec"
    )]
    pub redirect_list: Vec<(String, String)>,
    #[serde(default)]
    pub hotreload_conf: HotreloadConf,
    #[serde(default)]
    pub metric_conf: MetricConf,
    #[serde(default = "default_false")]
    pub vpn_reassertion: bool,
    pub targets: ProxyConf,
    #[serde(default = "default_dns_target")]
    pub dns_target: String,
}
fn default_empty_vec<T>() -> Vec<T> {
    Vec::new()
}
fn default_dns_target() -> String {
    String::from("127.0.0.1:53")
}
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyTarget {
    pub name: String,
    pub mode: TransportMode, // "plain" | "udp_obfs" | "tls" (tls not covered here yet)
    pub address: String,     // ip:port, or domain:port for tls
    #[serde(default)]
    pub shared_key: Option<String>, // required for udp_obfs / tls
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Plain,
    UdpObfs,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConf {
    pub listen_addr: String, // e.g. "127.0.0.1:53"
    pub targets: Vec<ProxyTarget>,
    #[serde(default = "default_strategy")]
    pub strategy: ProxyStrategy, // "ordered" | "round_robin"
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyStrategy {
    Ordered,
    RoundRobin,
}

fn default_strategy() -> ProxyStrategy {
    ProxyStrategy::Ordered
}
fn default_upstream_timeout_ms() -> u64 {
    2_000
}
fn default_false() -> bool {
    false
}

#[derive(Default, Clone, Deserialize)]
pub struct HotreloadConf {
    pub enable: bool,
    pub poll_interval_ms: u64,
}

use arc_swap::ArcSwap;
use shared::domain_trie::DomainTrie;
use shared::metric_wrapper::MetricConf;
use tokio::time::interval;
use tracing::{error, info};

pub async fn watch_conf_and_reload(
    path: PathBuf,
    poll_interval: Duration,
    conf: Arc<RwLock<Conf>>,
    rule_trie: Arc<ArcSwap<DomainTrie>>,
) {
    let mut tick = interval(poll_interval);
    let mut last_mtime: Option<SystemTime> =
        std::fs::metadata(&path).and_then(|m| m.modified()).ok();

    loop {
        tick.tick().await;

        let mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(err) => {
                error!("failed to stat {}: {}", path.display(), err);
                continue;
            }
        };
        if Some(mtime) == last_mtime {
            continue;
        }
        last_mtime = Some(mtime);

        match load_conf(&path) {
            Ok(new_conf) => {
                let new_trie = DomainTrie::build(&new_conf.drop_list, &new_conf.redirect_list);
                rule_trie.store(Arc::new(new_trie));
                *conf.write().unwrap() = new_conf;

                info!("config reloaded successfully");
            }
            Err(err) => error!("failed to reload conf.toml, keeping old config: {}", err),
        }
    }
}

pub fn load_conf(conf_path: &PathBuf) -> Result<Conf, Error> {
    let conf_str = std::fs::read_to_string(conf_path)
        .map_err(|err| Error::Config(format!("could not read conf: {}", err)))?;
    let conf: Conf = toml::from_str(&conf_str)
        .map_err(|err| Error::Config(format!("failed to parse toml :{}", err)))?;
    Ok(conf)
}
