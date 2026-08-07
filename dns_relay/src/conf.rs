use crate::ResponseCache;
use crate::cache::remove_domains_from_cache;
use crate::errors::Error;
use serde::Deserialize;
use shared::domain_trie::DomainTrie;
use shared::metric_wrapper::MetricConf;
use std::sync::Arc;
use std::time::SystemTime;
use std::{path::PathBuf, sync::RwLock};
use tokio::time::{Duration, interval};

#[derive(Default, Deserialize)]
pub struct Conf {
    #[serde(default = "default_dns_target")]
    pub dns_target: String,
    pub drop_list: Vec<String>,
    #[serde(deserialize_with = "shared::deserialize_redirect_list")]
    pub redirect_list: Vec<(String, String)>,
    pub resolvers: Vec<String>,
    #[serde(default)]
    pub resolver_searching: ResolverSearchingConf,
    #[serde(default)]
    pub hotreload_conf: HotreloadConf,
    #[serde(default)]
    pub relay_conf: RelayConf,
    #[serde(default)]
    pub metric_conf: MetricConf,
    #[serde(default = "default_false")]
    pub vpn_reassertion: bool,
    #[serde(default = "default_false")]
    pub init_tls: bool,
    #[serde(default = "default_false")]
    pub record_history: bool,
    #[serde(default)]
    pub record_history_conf: Option<RecordHisotryConf>,
    #[serde(default)]
    pub obfs_conf: ObfsConf,
}

#[derive(Default, Deserialize, Clone)]
pub struct RecordHisotryConf {
    pub matched_list: Vec<String>, // vector of patters to cover like *.google.com or ads.google.com
    pub lines: usize,
}

fn default_dns_target() -> String {
    String::from("127.0.0.1:53")
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ObfsConf {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_obfs_bind")]
    pub bind_addr: String,
    /// One or more base64 keys. Multiple keys let you run several
    /// resolver_proxy deployments/clients against one dns_relay instance,
    /// each with its own key — the AEAD tag itself tells you which key (if
    /// any) a given packet was encrypted under.
    #[serde(default)]
    pub keys: Vec<String>,
}

fn default_obfs_bind() -> String {
    "0.0.0.0:8853".to_string()
}

fn default_false() -> bool {
    false
}

#[derive(Default, Clone, Deserialize)]
pub struct RelayConf {
    pub enable: bool,
    pub resolve_manual: bool,
    #[serde(default = "default_relay_timeout_sec")]
    pub relay_timeout_sec: u64,
    pub relay_instances: Vec<Relay>,
}
fn default_relay_timeout_sec() -> u64 {
    5
}

#[derive(Default, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayTransport {
    #[default]
    Direct,
    GoogleChained,
}

#[derive(Default, Clone, Deserialize)]
pub struct Relay {
    pub relay_key: String,
    pub relay_url: String,
    pub transport: RelayTransport,
}

#[derive(Clone, Deserialize)]
pub struct HotreloadConf {
    pub enable: bool,
    pub poll_interval_ms: u64,
}
impl Default for HotreloadConf {
    fn default() -> Self {
        Self {
            enable: true,
            poll_interval_ms: 100,
        }
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct ResolverSearchingConf {
    pub enable: bool,
    pub resolver_source: Vec<String>,
    #[serde(default)]
    pub resfresh_interval: Option<u64>,
    pub ipv4: bool,
    pub doh: bool,
}

pub fn load_conf(path: &PathBuf) -> Result<Conf, Error> {
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|err| Error::Config(err.to_string()))
}

use arc_swap::ArcSwap;
use tracing::{error, info};

pub async fn watch_conf_and_reload(
    path: PathBuf,
    poll_interval: Duration,
    conf: Arc<RwLock<Conf>>,
    rule_trie: Arc<ArcSwap<DomainTrie>>,
    cache: Arc<ResponseCache>,
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
                let drop_list_clone = new_conf.drop_list.clone();
                let new_trie = DomainTrie::build(&new_conf.drop_list, &new_conf.redirect_list);
                rule_trie.store(Arc::new(new_trie));
                remove_domains_from_cache(&cache, &drop_list_clone);
                *conf.write().unwrap() = new_conf;

                info!("config reloaded successfully");
            }
            Err(err) => error!("failed to reload conf.toml, keeping old config: {}", err),
        }
    }
}
