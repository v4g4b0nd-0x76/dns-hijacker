use serde::Deserialize;
use std::{path::PathBuf, sync::RwLock};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::time::{interval, Duration};
use crate::errors::Error;

#[derive(Default, Deserialize)]
pub struct Conf {
    pub drop_list: Vec<String>,
    #[serde(deserialize_with = "deserialize_redirect_list")]
    pub redirect_list: Vec<(String, String)>,
    pub resolvers: Vec<String>,
    #[serde(default)]
    pub resolver_searching: ResolverSearchingConf,
    #[serde(default)]
    pub hotreload_conf: HotreloadConf,
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
fn deserialize_redirect_list<'de, D>(deserializer: D) -> Result<Vec<(String, String)>, D::Error>
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

pub fn load_conf(path: &PathBuf) -> Result<Conf, Error> {
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|err| Error::Config(err.to_string()))
}

use tracing::{error, info};
use arc_swap::ArcSwap;

pub async fn watch_conf_and_reload(
    path: PathBuf,
    poll_interval: Duration,
    conf: Arc<RwLock<Conf>>,
    redirect_list: Arc<ArcSwap<Vec<(String, String)>>>,
    drop_list: Arc<ArcSwap<Vec<String>>>,
) {
    let mut tick = interval(poll_interval);
    let mut last_mtime: Option<SystemTime> = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok();

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
                redirect_list.store(Arc::new(new_conf.redirect_list.clone()));
                drop_list.store(Arc::new(new_conf.drop_list.clone()));
                *conf.write().unwrap() = new_conf;
                info!("config reloaded successfully");
            }
            Err(err) => error!("failed to reload conf.toml, keeping old config: {}", err),
        }
    }
}
