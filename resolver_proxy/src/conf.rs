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
    pub drop_list: Vec<String>,
    #[serde(deserialize_with = "deserialize_redirect_list")]
    pub redirect_list: Vec<(String, String)>,
    #[serde(default)]
    pub hotreload_conf: HotreloadConf,
    #[serde(default)]
    pub metric_conf: MetricConf,
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
