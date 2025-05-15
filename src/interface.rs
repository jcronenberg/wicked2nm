use crate::bond::Bond;
use crate::bridge::Bridge;
use crate::infiniband::{Infiniband, InfinibandChild};
use crate::netconfig_dhcp::{HostnameOption, NetconfigDhcp};
use crate::tuntap::Tap;
use crate::tuntap::Tun;
use crate::vlan::Vlan;
use crate::wireless::Wireless;
use crate::MIGRATION_SETTINGS;
use agama_network::model::{
    self, Dhcp4Settings, Dhcp6Settings, IpConfig, IpRoute, Ipv4Method, Ipv6Method, MacAddress,
};
use agama_network::types::Status;
use anyhow::anyhow;
use cidr::IpInet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DeserializeFromStr, SerializeDisplay};
use std::{net::IpAddr, str::FromStr};
use strum_macros::{Display, EnumString};

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Interface {
    pub name: String,
    pub firewall: Firewall,
    pub link: Link,
    pub ipv4: Ipv4,
    #[serde(rename = "ipv4-static")]
    pub ipv4_static: Option<Ipv4Static>,
    #[serde(rename = "ipv4-dhcp")]
    pub ipv4_dhcp: Option<Ipv4Dhcp>,
    pub ipv6: Ipv6,
    #[serde(rename = "ipv6-static")]
    pub ipv6_static: Option<Ipv6Static>,
    #[serde(rename = "ipv6-dhcp")]
    pub ipv6_dhcp: Option<Ipv6Dhcp>,
    #[serde(rename = "ipv6-auto")]
    pub ipv6_auto: Option<Ipv6Auto>,
    pub dummy: Option<Dummy>,
    pub ethernet: Option<Ethernet>,
    pub bond: Option<Bond>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireless: Option<Wireless>,
    #[serde(rename = "@origin")]
    pub origin: String,
    pub vlan: Option<Vlan>,
    pub bridge: Option<Bridge>,
    pub infiniband: Option<Infiniband>,
    #[serde(rename = "infiniband-child")]
    pub infiniband_child: Option<InfinibandChild>,
    pub tun: Option<Tun>,
    pub tap: Option<Tap>,
    pub control: Control,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Firewall {
    pub zone: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Link {
    pub master: Option<String>,
    pub mtu: Option<u32>,
    pub port: Option<LinkPort>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LinkPort {
    #[serde(rename = "@type")]
    pub port_type: LinkPortType,
    pub priority: Option<u32>,
    pub path_cost: Option<u32>,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum LinkPortType {
    Bridge,
    Bond,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Ipv4 {
    #[serde(default = "default_true")]
    pub enabled: bool,
    // ignored
    #[serde(rename = "arp-verify", default = "default_true")]
    pub arp_verify: bool,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            enabled: true,
            arp_verify: true,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Ipv6 {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub privacy: Option<Ip6Privacy>,
    // ignored
    #[serde(rename = "accept-redirects", default)]
    pub accept_redirects: bool,
}

#[derive(
    Debug, PartialEq, Default, SerializeDisplay, DeserializeFromStr, EnumString, Clone, Display,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Ip6Privacy {
    Disable = 0,
    #[default]
    PreferPublic = 1,
    PreferTemporary = 2,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            enabled: true,
            privacy: None,
            accept_redirects: false,
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Ipv4Static {
    #[serde(rename = "address")]
    pub addresses: Option<Vec<Address>>,
    #[serde(rename = "route")]
    pub routes: Option<Vec<Route>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Ipv4Dhcp {
    pub enabled: bool,
    // ignored
    #[serde(default = "default_flags")]
    pub flags: String,
    // ignored
    #[serde(default = "default_v4_update")]
    pub update: String,
    pub hostname: Option<String>,
    // ignored
    #[serde(rename = "defer-timeout", default = "default_defer_timeout")]
    pub defer_timeout: u32,
    // ignored
    #[serde(rename = "recover-lease", default = "default_true")]
    pub recover_lease: bool,
    #[serde(rename = "release-lease", default)]
    pub release_lease: bool,
}

fn default_flags() -> String {
    "group".to_string()
}

fn default_v4_update() -> String {
    "default-route,dns,nis,ntp,nds,mtu,tz,boot".to_string()
}

fn default_defer_timeout() -> u32 {
    15_u32
}

impl Default for Ipv4Dhcp {
    fn default() -> Self {
        Self {
            enabled: true,
            flags: default_flags(),
            update: default_v4_update(),
            hostname: None,
            defer_timeout: default_defer_timeout(),
            recover_lease: true,
            release_lease: false,
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Ipv6Static {
    #[serde(rename = "address")]
    pub addresses: Option<Vec<Address>>,
    #[serde(rename = "route")]
    pub routes: Option<Vec<Route>>,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Address {
    pub local: String,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ipv6Dhcp {
    pub enabled: bool,
    pub mode: String,
    // ignored
    #[serde(default = "default_flags")]
    pub flags: String,
    // ignored
    #[serde(default = "default_v6_dhcp_update")]
    pub update: String,
    // ignored
    #[serde(rename = "rapid-commit", default = "default_true")]
    pub rapid_commit: bool,
    pub hostname: Option<String>,
    // ignored
    #[serde(rename = "defer-timeout", default = "default_defer_timeout")]
    pub defer_timeout: u32,
    // ignored
    #[serde(rename = "recover-lease", default = "default_true")]
    pub recover_lease: bool,
    // ignored
    #[serde(rename = "refresh-lease", default)]
    pub refresh_lease: bool,
    #[serde(rename = "release-lease", default)]
    pub release_lease: bool,
}

fn default_v6_dhcp_update() -> String {
    "dns,nis,ntp,tz,boot".to_string()
}

impl Default for Ipv6Dhcp {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: String::from("auto"),
            flags: default_flags(),
            update: default_v6_dhcp_update(),
            rapid_commit: true,
            hostname: None,
            defer_timeout: default_defer_timeout(),
            recover_lease: true,
            refresh_lease: false,
            release_lease: false,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ipv6Auto {
    pub enabled: bool,
    // ignored
    #[serde(default = "default_v6_dhcp_update")]
    pub update: String,
}

fn default_v6_auto_update() -> String {
    "dns".to_string()
}

impl Default for Ipv6Auto {
    fn default() -> Self {
        Self {
            enabled: true,
            update: default_v6_auto_update(),
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Dummy {
    pub address: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Route {
    pub destination: Option<String>,
    #[serde(rename = "nexthop")]
    pub nexthops: Option<Vec<Nexthop>>,
    pub priority: Option<u32>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Ethernet {
    pub address: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Nexthop {
    pub gateway: String,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Control {
    #[serde(default)]
    pub mode: ControlMode,
    // ignored
    #[serde(rename = "boot-stage")]
    pub boot_stage: Option<String>,
    // ignored
    pub persistent: Option<String>,
}

#[derive(
    Debug, PartialEq, Default, SerializeDisplay, DeserializeFromStr, EnumString, Clone, Display,
)]
#[strum(serialize_all = "snake_case")]
pub enum ControlMode {
    #[default]
    Manual,
    Off,
    Boot,
    Hotplug,
}

impl From<ControlMode> for bool {
    fn from(value: ControlMode) -> Self {
        match value {
            ControlMode::Manual => false,
            ControlMode::Off => false,
            ControlMode::Boot => true,
            ControlMode::Hotplug => true,
        }
    }
}

pub struct ConnectionResult {
    pub connections: Vec<model::Connection>,
    pub warnings: Vec<anyhow::Error>,
}

pub struct IpConfigResult {
    ip_config: IpConfig,
    warnings: Vec<anyhow::Error>,
}

impl From<&LinkPort> for model::PortConfig {
    fn from(port: &LinkPort) -> Self {
        match port.port_type {
            LinkPortType::Bridge => model::PortConfig::Bridge(model::BridgePortConfig {
                priority: port.priority,
                path_cost: port.path_cost,
            }),
            LinkPortType::Bond => model::PortConfig::None,
        }
    }
}

impl Interface {
    pub fn to_connection(
        &self,
        netconfig_dhcp: &Option<NetconfigDhcp>,
    ) -> Result<ConnectionResult, anyhow::Error> {
        let settings = MIGRATION_SETTINGS.get().unwrap();
        let ip_config = self.to_ip_config(netconfig_dhcp)?;
        let mut warnings = ip_config.warnings;
        warnings.append(&mut check_ignored(self));
        let mut connection = model::Connection {
            id: self.name.clone(),
            firewall_zone: self.firewall.zone.clone(),
            interface: Some(self.name.clone()),
            ip_config: ip_config.ip_config,
            status: Status::Down,
            mtu: self.link.mtu.unwrap_or_default(),
            autoconnect: self.control.mode.clone().into(),
            ..Default::default()
        };

        if let Some(port) = &self.link.port {
            connection.port_config = port.into();
        }

        let mut connections: Vec<model::Connection> = vec![];

        if settings.activate_connections {
            connection.status = if connection.autoconnect {
                Status::Up
            } else {
                Status::Down
            };
        }

        if let Some(ethernet) = &self.ethernet {
            connection.mac_address = MacAddress::try_from(&ethernet.address)?;
            connection.config = model::ConnectionConfig::Ethernet;
            connections.push(connection);
        } else if let Some(dummy) = &self.dummy {
            connection.mac_address = MacAddress::try_from(&dummy.address)?;
            connection.config = model::ConnectionConfig::Dummy;
            connections.push(connection);
        } else if let Some(bond) = &self.bond {
            connection.mac_address = MacAddress::try_from(&bond.address)?;
            connection.config = bond.into();
            connections.push(connection);
        } else if let Some(vlan) = &self.vlan {
            connection.mac_address = MacAddress::try_from(&vlan.address)?;
            connection.config = vlan.into();
            connections.push(connection);
        } else if let Some(bridge) = &self.bridge {
            connection.mac_address = MacAddress::try_from(&bridge.address)?;
            connection.config = bridge.into();
            connections.push(connection);
        } else if let Some(wireless) = &self.wireless {
            if let Some(networks) = &wireless.networks {
                if networks.len() > 1 {
                    log::info!("{} has multiple networks defined, these will be split into different connections in NM", connection.id);
                }
                for (i, network) in networks.iter().enumerate() {
                    let mut wireless_connection = connection.clone();
                    if networks.len() > 1 {
                        wireless_connection.id.push_str(&format!("-{}", i));
                    }
                    wireless_connection.config = network.try_into()?;
                    if let Some(wpa_eap) = &network.wpa_eap {
                        wireless_connection.ieee_8021x_config = Some(wpa_eap.try_into()?);
                    }
                    connections.push(wireless_connection);
                }
            }
        } else if let Some(infiniband) = &self.infiniband {
            if infiniband.multicast.is_some() {
                warnings.push(anyhow::anyhow!(
                    "Infiniband multicast isn't supported by NetworkManager"
                ));
            }
            connection.config = infiniband.into();
            connections.push(connection)
        } else if let Some(infiniband_child) = &self.infiniband_child {
            if infiniband_child.multicast.is_some() {
                warnings.push(anyhow::anyhow!(
                    "Infiniband multicast isn't supported by NetworkManager"
                ));
            }
            connection.config = infiniband_child.into();
            connections.push(connection)
        } else if let Some(tun) = &self.tun {
            connection.config = tun.into();
            connections.push(connection)
        } else if let Some(tap) = &self.tap {
            connection.config = tap.into();
            connections.push(connection)
        } else {
            connections.push(connection);
        }

        Ok(ConnectionResult {
            connections,
            warnings,
        })
    }

    pub fn to_ip_config(
        &self,
        netconfig_dhcp: &Option<NetconfigDhcp>,
    ) -> Result<IpConfigResult, anyhow::Error> {
        let mut connection_result = IpConfigResult {
            ip_config: IpConfig {
                ..Default::default()
            },
            warnings: vec![],
        };
        let method4 = if self.ipv4_static.is_some() {
            Ipv4Method::Manual
        } else if !self.ipv4.enabled {
            Ipv4Method::Disabled
        } else if self.ipv4_dhcp.is_some() {
            Ipv4Method::Auto
        } else {
            Ipv4Method::Disabled
        };
        let method6 = if self.ipv6_static.is_some() {
            Ipv6Method::Manual
        } else if self.ipv6_dhcp.is_some() && self.ipv6_dhcp.as_ref().unwrap().mode == "managed" {
            Ipv6Method::Dhcp
        } else if !self.ipv6.enabled {
            Ipv6Method::Disabled
        } else {
            Ipv6Method::Auto
        };

        let mut addresses: Vec<IpInet> = vec![];
        let mut routes4: Vec<IpRoute> = vec![];
        let mut routes6: Vec<IpRoute> = vec![];
        if let Some(ipv4_static) = &self.ipv4_static {
            if let Some(addresses_in) = &ipv4_static.addresses {
                for addr in addresses_in {
                    addresses.push(match IpInet::from_str(addr.local.as_str()) {
                        Ok(address) => address,
                        Err(e) => {
                            anyhow::bail!("Failed to parse address \"{}\": {}", addr.local, e)
                        }
                    });
                }
            }
            if let Some(routes) = &ipv4_static.routes {
                for route in routes {
                    routes4.push(match route.try_into() {
                        Ok(route) => route,
                        Err(e) => {
                            connection_result.warnings.push(e);
                            continue;
                        }
                    });
                }
            }
        }
        if let Some(ipv6_static) = &self.ipv6_static {
            if let Some(addresses_in) = &ipv6_static.addresses {
                for addr in addresses_in {
                    addresses.push(match IpInet::from_str(addr.local.as_str()) {
                        Ok(address) => address,
                        Err(e) => {
                            anyhow::bail!("Failed to parse address \"{}\": {}", addr.local, e)
                        }
                    });
                }
            }
            if let Some(routes) = &ipv6_static.routes {
                for route in routes {
                    routes6.push(match route.try_into() {
                        Ok(route) => route,
                        Err(e) => {
                            connection_result.warnings.push(e);
                            continue;
                        }
                    });
                }
            }
        }

        let mut dhcp4_settings: Option<Dhcp4Settings> = None;
        if let Some(ipv4_dhcp) = &self.ipv4_dhcp {
            let mut dhcp_settings = Dhcp4Settings::default();
            if let Some(hostname) = &ipv4_dhcp.hostname {
                dhcp_settings.send_hostname = Some(true);
                if let Some(netconfig_dhcp) = netconfig_dhcp {
                    if netconfig_dhcp.dhclient_hostname_option != HostnameOption::Auto {
                        dhcp_settings.hostname = Some(hostname.clone());
                    }
                } else {
                    dhcp_settings.hostname = Some(hostname.clone());
                }
            } else {
                dhcp_settings.send_hostname = Some(false);
            }
            dhcp_settings.send_release = Some(ipv4_dhcp.release_lease);
            dhcp4_settings = Some(dhcp_settings);
        }

        let mut dhcp6_settings: Option<Dhcp6Settings> = None;
        if let Some(ipv6_dhcp) = &self.ipv6_dhcp {
            let mut dhcp_settings = Dhcp6Settings::default();
            if let Some(hostname) = &ipv6_dhcp.hostname {
                dhcp_settings.send_hostname = Some(true);
                if let Some(netconfig_dhcp) = netconfig_dhcp {
                    if netconfig_dhcp.dhclient6_hostname_option != HostnameOption::Auto {
                        dhcp_settings.hostname = Some(hostname.clone());
                    }
                } else {
                    dhcp_settings.hostname = Some(hostname.clone());
                }
            } else {
                dhcp_settings.send_hostname = Some(false);
            }
            dhcp_settings.send_release = Some(ipv6_dhcp.release_lease);
            dhcp6_settings = Some(dhcp_settings);
        }

        let mut ip6_privacy: Option<i32> = None;
        if let Some(privacy) = &self.ipv6.privacy {
            ip6_privacy = Some(privacy.clone() as i32);
        }

        connection_result.ip_config = IpConfig {
            addresses,
            method4,
            method6,
            routes4,
            routes6,
            dhcp4_settings,
            dhcp6_settings,
            ip6_privacy,
            ..Default::default()
        };
        Ok(connection_result)
    }
}

impl TryFrom<&Route> for IpRoute {
    type Error = anyhow::Error;
    fn try_from(route: &Route) -> Result<Self, Self::Error> {
        let mut next_hop: Option<IpAddr> = None;
        if let Some(nexthops) = &route.nexthops {
            if nexthops.len() > 1 {
                return Err(anyhow::anyhow!(
                    "Multipath routing isn't natively supported by NetworkManager"
                ));
            } else {
                next_hop = Some(IpAddr::from_str(&nexthops[0].gateway).unwrap());
            }
        }
        let destination = if route.destination.is_some() {
            IpInet::from_str(route.destination.clone().unwrap().as_str())?
        } else if next_hop.is_some() {
            // default route
            let default_ip = if next_hop.unwrap().is_ipv4() {
                IpAddr::from_str("0.0.0.0")?
            } else {
                IpAddr::from_str("::")?
            };
            IpInet::new(default_ip, 0)?
        } else {
            return Err(anyhow::anyhow!("Error occurred when parsing a route"));
        };
        let metric = route.priority;
        Ok(IpRoute {
            destination,
            next_hop,
            metric,
        })
    }
}

fn check_ignored(interface: &Interface) -> Vec<anyhow::Error> {
    let mut warnings: Vec<anyhow::Error> = vec![];

    let ipv4 = &interface.ipv4;
    let ipv4_default = Ipv4::default();
    if ipv4.arp_verify != ipv4_default.arp_verify {
        warnings.push(anyhow!(
            "Unhandled field in interface {}: {}",
            interface.name,
            stringify!(ipv4.arp_verify)
        ));
    }

    let ipv6 = &interface.ipv6;
    let ipv6_default = Ipv6::default();
    if ipv6.accept_redirects != ipv6_default.accept_redirects {
        warnings.push(anyhow!(
            "Unhandled field in interface {}: {}",
            interface.name,
            stringify!(ipv6.accept_redirects)
        ));
    }

    if let Some(ipv4_dhcp) = &interface.ipv4_dhcp {
        let ipv4_dhcp_default = Ipv4Dhcp::default();
        if ipv4_dhcp.flags != ipv4_dhcp_default.flags {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv4_dhcp.flags)
            ));
        }
        if ipv4_dhcp.update != ipv4_dhcp_default.update {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv4_dhcp.update)
            ));
        }
        if ipv4_dhcp.defer_timeout != ipv4_dhcp_default.defer_timeout {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv4_dhcp.defer_timeout)
            ));
        }
        if ipv4_dhcp.recover_lease != ipv4_dhcp_default.recover_lease {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv4_dhcp.recover_lease)
            ));
        }
    }

    if let Some(ipv6_dhcp) = &interface.ipv6_dhcp {
        let ipv6_dhcp_default = Ipv6Dhcp::default();
        if ipv6_dhcp.flags != ipv6_dhcp_default.flags {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_dhcp.flags)
            ));
        }

        if ipv6_dhcp.update != ipv6_dhcp_default.update {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_dhcp.update)
            ));
        }
        if ipv6_dhcp.rapid_commit != ipv6_dhcp_default.rapid_commit {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_dhcp.rapid_commit)
            ));
        }
        if ipv6_dhcp.defer_timeout != ipv6_dhcp_default.defer_timeout {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_dhcp.defer_timeout)
            ));
        }
        if ipv6_dhcp.recover_lease != ipv6_dhcp_default.recover_lease {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_dhcp.recover_lease)
            ));
        }
        if ipv6_dhcp.refresh_lease != ipv6_dhcp_default.refresh_lease {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_dhcp.refresh_lease)
            ));
        }
    }
    if let Some(ipv6_auto) = &interface.ipv6_auto {
        let ipv6_auto_default = Ipv6Auto::default();
        if ipv6_auto.update != ipv6_auto_default.update {
            warnings.push(anyhow!(
                "Unhandled field in interface {}: {}",
                interface.name,
                stringify!(ipv6_auto.update)
            ));
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn setup_default_migration_settings() {
        let _ = MIGRATION_SETTINGS.set(crate::MigrationSettings::default());
    }

    #[test]
    fn test_static_interface_to_connection() {
        setup_default_migration_settings();
        let static_interface = Interface {
            ipv4: Ipv4::default(),
            ipv4_static: Some(Ipv4Static {
                addresses: Some(vec![Address {
                    local: "127.0.0.1/8".to_string(),
                }]),
                routes: Some(vec![Route {
                    nexthops: Some(vec![Nexthop {
                        gateway: "127.0.0.1".to_string(),
                    }]),
                    ..Default::default()
                }]),
            }),
            ipv6: Ipv6::default(),
            ipv6_static: Some(Ipv6Static {
                addresses: Some(vec![Address {
                    local: "::1/128".to_string(),
                }]),
                routes: Some(vec![Route {
                    nexthops: Some(vec![Nexthop {
                        gateway: "::1".to_string(),
                    }]),
                    ..Default::default()
                }]),
            }),
            ..Default::default()
        };

        let static_connection: model::Connection =
            static_interface.to_connection(&None).unwrap().connections[0].to_owned();
        assert_eq!(static_connection.ip_config.method4, Ipv4Method::Manual);
        assert_eq!(
            static_connection.ip_config.addresses[0].to_string(),
            "127.0.0.1/8"
        );
        assert_eq!(static_connection.ip_config.method6, Ipv6Method::Manual);
        assert_eq!(static_connection.ip_config.addresses[1].to_string(), "::1");
        assert_eq!(
            static_connection.ip_config.addresses[1]
                .network_length()
                .to_string(),
            "128"
        );
        assert!(static_connection.ip_config.routes4.len() == 1);
        assert_eq!(
            static_connection.ip_config.routes4[0]
                .destination
                .to_string(),
            "0.0.0.0/0"
        );
        assert_eq!(
            static_connection.ip_config.routes4[0]
                .next_hop
                .unwrap()
                .to_string(),
            "127.0.0.1"
        );
        assert!(static_connection.ip_config.routes6.len() == 1);
        assert_eq!(
            static_connection.ip_config.routes6[0]
                .destination
                .to_string(),
            "::/0"
        );
        assert_eq!(
            static_connection.ip_config.routes6[0]
                .next_hop
                .unwrap()
                .to_string(),
            "::1"
        );
    }

    #[test]
    fn test_dhcp_interface_to_connection() {
        setup_default_migration_settings();
        let static_interface = Interface {
            ipv4_dhcp: Some(Ipv4Dhcp {
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let static_connection: model::Connection =
            static_interface.to_connection(&None).unwrap().connections[0].to_owned();
        assert_eq!(static_connection.ip_config.method4, Ipv4Method::Auto);
        assert_eq!(static_connection.ip_config.method6, Ipv6Method::Auto);
        assert_eq!(static_connection.ip_config.addresses.len(), 0);
    }

    #[test]
    fn test_dummy_interface_to_connection() {
        setup_default_migration_settings();
        let dummy_interface = Interface {
            dummy: Some(Dummy {
                address: Some("12:34:56:78:9A:BC".to_string()),
            }),
            ..Default::default()
        };

        let connection: &model::Connection =
            &dummy_interface.to_connection(&None).unwrap().connections[0];
        assert!(matches!(connection.config, model::ConnectionConfig::Dummy));
        assert_eq!(connection.mac_address.to_string(), "12:34:56:78:9A:BC");

        let dummy_interface = Interface {
            dummy: Some(Dummy {
                ..Default::default()
            }),
            ..Default::default()
        };

        let connection: &model::Connection =
            &dummy_interface.to_connection(&None).unwrap().connections[0];
        assert!(matches!(connection.config, model::ConnectionConfig::Dummy));
        assert_eq!(dummy_interface.dummy.unwrap().address, None);
        assert!(matches!(connection.mac_address, MacAddress::Unset));
    }

    #[test]
    fn test_firewall_zone_to_connection() {
        setup_default_migration_settings();
        let ifc = Interface {
            firewall: Firewall {
                zone: Some("topsecret".to_string()),
            },
            ..Default::default()
        };

        let con: model::Connection = ifc.to_connection(&None).unwrap().connections[0].to_owned();
        assert_eq!(con.firewall_zone, Some("topsecret".to_string()));
    }

    #[test]
    fn test_startmode_to_connection() {
        setup_default_migration_settings();
        let mut ifc = Interface::default();

        let con: model::Connection = ifc.to_connection(&None).unwrap().connections[0].to_owned();
        assert_eq!(con.autoconnect, false);

        ifc.control.mode = ControlMode::Boot;
        let con: model::Connection = ifc.to_connection(&None).unwrap().connections[0].to_owned();
        assert_eq!(con.autoconnect, true);
    }

    #[test]
    fn test_ignored_default() {
        let ifc = Interface::default();
        assert!(check_ignored(&ifc).len() == 0);

        let ifc = Interface {
            ipv4_dhcp: Some(Ipv4Dhcp {
                flags: String::from("123"),
                update: String::from("456"),
                defer_timeout: 0,
                recover_lease: false,
                ..Default::default()
            }),
            ipv6_dhcp: Some(Ipv6Dhcp {
                flags: String::from("123"),
                update: String::from("456"),
                rapid_commit: false,
                defer_timeout: 0,
                recover_lease: false,
                refresh_lease: true,
                ..Default::default()
            }),
            ipv6_auto: Some(Ipv6Auto {
                update: String::from("123"),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(check_ignored(&ifc).len() == 11);
    }
}
