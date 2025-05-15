use agama_network::model;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Tun {
    pub owner: Option<u32>,
    pub group: Option<u32>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Tap {
    pub owner: Option<u32>,
    pub group: Option<u32>,
}

impl From<&Tun> for model::ConnectionConfig {
    fn from(tuntap: &Tun) -> model::ConnectionConfig {
        model::ConnectionConfig::Tun(model::TunConfig {
            mode: model::TunMode::Tun,
            group: tuntap.group.map(|v| v.to_string()),
            owner: tuntap.owner.map(|v| v.to_string()),
        })
    }
}

impl From<&Tap> for model::ConnectionConfig {
    fn from(tuntap: &Tap) -> model::ConnectionConfig {
        model::ConnectionConfig::Tun(model::TunConfig {
            mode: model::TunMode::Tap,
            group: tuntap.group.map(|v| v.to_string()),
            owner: tuntap.owner.map(|v| v.to_string()),
        })
    }
}
