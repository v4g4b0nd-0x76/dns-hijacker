use serde::Deserialize;

use crate::errors::Error;

#[derive(Default, Deserialize)]
pub struct Conf {
    pub drop_list: Vec<String>,
    #[serde(deserialize_with = "deserialize_redirect_list")]
    pub redirect_list: Vec<(String, String)>,
    pub resolvers: Vec<String>,
    #[serde(default)]
    pub resolver_searching: ResolverSearchingConf,
}

#[derive(Clone,Default, Deserialize)]
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

pub fn load_conf() -> Result<Conf, Error> {
    let content = std::fs::read_to_string("conf.toml")?;
    toml::from_str(&content).map_err(|err| Error::Config(err.to_string()))
}
