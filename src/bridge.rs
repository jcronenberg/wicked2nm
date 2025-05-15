use agama_network::model;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Bridge {
    #[serde(default)]
    pub stp: bool,
    pub priority: Option<u16>,
    pub forward_delay: Option<f32>,
    pub hello_time: Option<f32>,
    pub max_age: Option<f32>,
    pub aging_time: Option<f32>, // wicked uses US english, but kernel and nm UK (ageing)
    pub address: Option<String>,
}

impl From<&Bridge> for model::ConnectionConfig {
    fn from(bridge: &Bridge) -> model::ConnectionConfig {
        model::ConnectionConfig::Bridge(model::BridgeConfig {
            stp: bridge.stp,
            priority: bridge.priority.map(|v| v as u32),
            forward_delay: bridge.forward_delay.map(|v| v.round() as u32),
            hello_time: bridge.hello_time.map(|v| v.round() as u32),
            max_age: bridge.max_age.map(|v| v.round() as u32),
            ageing_time: bridge.aging_time.map(|v| v.round() as u32),
        })
    }
}
