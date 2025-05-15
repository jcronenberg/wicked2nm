use agama_network::model;
use serde::{Deserialize, Serialize};
use serde_with::{skip_serializing_none, DeserializeFromStr, SerializeDisplay};
use strum_macros::{Display, EnumString};

#[derive(
    Debug, Clone, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display, Default,
)]
#[strum(serialize_all = "kebab_case")]
pub enum WickedVlanProtocol {
    #[default]
    #[strum(serialize = "ieee802-1Q")]
    Ieee802_1Q,
    Ieee802Ad,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Vlan {
    pub device: String,
    pub address: Option<String>,
    #[serde(default)]
    pub protocol: WickedVlanProtocol,
    pub tag: u16,
}

impl From<&Vlan> for model::ConnectionConfig {
    fn from(vlan: &Vlan) -> model::ConnectionConfig {
        model::ConnectionConfig::Vlan(model::VlanConfig {
            parent: vlan.device.clone(),
            id: (vlan.tag as u32),
            protocol: (&vlan.protocol).into(),
        })
    }
}

impl From<&WickedVlanProtocol> for model::VlanProtocol {
    fn from(v: &WickedVlanProtocol) -> model::VlanProtocol {
        match v {
            WickedVlanProtocol::Ieee802_1Q => model::VlanProtocol::IEEE802_1Q,
            WickedVlanProtocol::Ieee802Ad => model::VlanProtocol::IEEE802_1ad,
        }
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
    fn test_vlan_protocol() {
        setup_default_migration_settings();
        let v: WickedVlanProtocol = Default::default();
        assert_eq!(v, WickedVlanProtocol::Ieee802_1Q);
        assert_eq!(v.to_string(), String::from("ieee802-1Q"));
        let v = WickedVlanProtocol::Ieee802Ad;
        assert_eq!(v.to_string(), String::from("ieee802-ad"));
    }

    #[test]
    fn test_vlan_interface() {
        setup_default_migration_settings();
        let vlan_interface = Interface {
            vlan: Some(Vlan {
                device: String::from("en0"),
                tag: 10,
                protocol: WickedVlanProtocol::Ieee802Ad,
                address: Some(String::from("02:11:22:33:44:55")),
            }),
            ..Default::default()
        };

        let ifc = vlan_interface.to_connection(&None);

        assert!(ifc.is_ok());
        let ifc = &ifc.unwrap().connections[0];
        assert!(matches!(ifc.config, model::ConnectionConfig::Vlan(_)));
        if let model::ConnectionConfig::Vlan(v) = &ifc.config {
            assert_eq!(v.id, 10);
            assert_eq!(v.protocol, model::VlanProtocol::IEEE802_1ad);
            assert_eq!(v.parent, "en0");
        }

        assert_eq!(ifc.mac_address.to_string(), "02:11:22:33:44:55");
    }
}
