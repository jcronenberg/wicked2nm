use agama_network::model::{self, InfinibandConfig, InfinibandTransportMode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use std::str::FromStr;

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Infiniband {
    pub mode: Option<String>,
    pub multicast: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct InfinibandChild {
    pub device: String,
    #[serde(deserialize_with = "deserialize_pkey")]
    pub pkey: u16,
    pub mode: Option<String>,
    pub multicast: Option<String>,
}

fn deserialize_pkey<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let pkey_string: String = String::deserialize(deserializer)?;
    let pkey_string: &str = pkey_string.trim_start_matches("0x");
    Ok(u16::from_str_radix(pkey_string, 16).unwrap())
}

impl From<&Infiniband> for model::ConnectionConfig {
    fn from(value: &Infiniband) -> Self {
        model::ConnectionConfig::Infiniband(InfinibandConfig {
            transport_mode: InfinibandTransportMode::from_str(
                value
                    .mode
                    .as_ref()
                    .unwrap_or(&"datagram".to_string())
                    .as_str(),
            )
            .unwrap(),
            ..Default::default()
        })
    }
}

impl From<&InfinibandChild> for model::ConnectionConfig {
    fn from(value: &InfinibandChild) -> Self {
        model::ConnectionConfig::Infiniband(InfinibandConfig {
            p_key: Some(value.pkey as i32),
            parent: Some(value.device.clone()),
            transport_mode: InfinibandTransportMode::from_str(
                value
                    .mode
                    .as_ref()
                    .unwrap_or(&"datagram".to_string())
                    .as_str(),
            )
            .unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::*;
    use crate::MIGRATION_SETTINGS;

    #[allow(dead_code)]
    fn setup_default_migration_settings() {
        let _ = MIGRATION_SETTINGS.set(crate::MigrationSettings::default());
    }

    #[test]
    fn test_infiniband_migration() {
        setup_default_migration_settings();
        let infiniband_interface = Interface {
            infiniband: Some(Infiniband {
                mode: Some("datagram".to_string()),
                multicast: Some("allowed".to_string()),
            }),
            ..Default::default()
        };

        let connections = infiniband_interface.to_connection(&None);
        assert!(connections.is_ok());
        let connection = &connections.unwrap().connections[0];
        let model::ConnectionConfig::Infiniband(infiniband) = &connection.config else {
            panic!()
        };
        assert_eq!(
            infiniband.transport_mode,
            InfinibandTransportMode::from_str("datagram").unwrap()
        );
    }

    #[test]
    fn test_infiniband_child_migration() {
        setup_default_migration_settings();
        let infiniband_child_interface = Interface {
            infiniband_child: Some(InfinibandChild {
                mode: Some("datagram".to_string()),
                multicast: Some("allowed".to_string()),
                pkey: 0x8001,
                device: "ib0".to_string(),
            }),
            ..Default::default()
        };

        let connections = infiniband_child_interface.to_connection(&None);
        assert!(connections.is_ok());

        // Check multicast warning is generated
        assert_eq!(connections.as_ref().unwrap().warnings.len(), 1);
        assert_eq!(
            connections.as_ref().unwrap().warnings[0].to_string(),
            "Infiniband multicast isn't supported by NetworkManager"
        );

        let connection = &connections.unwrap().connections[0];
        let model::ConnectionConfig::Infiniband(infiniband_child) = &connection.config else {
            panic!()
        };
        assert_eq!(
            infiniband_child.transport_mode,
            InfinibandTransportMode::from_str("datagram").unwrap()
        );
        assert_eq!(infiniband_child.p_key, Some(0x8001));
        assert_eq!(infiniband_child.parent, Some("ib0".to_string()));
    }

    #[test]
    fn test_deserialize_pkey() {
        let xml = r##"
                  <interface-child>
                    <pkey>0x8001</pkey>
                    <device>ib0</device>
                  </interface-child>
                  "##;
        let infiniband_child = quick_xml::de::from_str::<InfinibandChild>(xml).unwrap();
        assert_eq!(infiniband_child.pkey, 0x8001);
    }
}
