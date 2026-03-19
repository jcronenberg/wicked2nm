use agama_network::model::{self};
use agama_network::types::BondMode as AgamaBondMode;
use serde::{Deserialize, Serialize};
use serde_with::{skip_serializing_none, DeserializeFromStr, SerializeDisplay};
use std::collections::HashMap;
use strum_macros::{Display, EnumString};

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Team {
    pub runner: Option<Runner>,
    #[serde(rename = "link_watch")]
    pub link_watch: Option<LinkWatch>,
}

#[derive(
    Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display, Default, Clone, Copy,
)]
#[strum(serialize_all = "snake_case")]
pub enum RunnerName {
    #[strum(serialize = "lacp")]
    Lacp,
    #[strum(serialize = "activebackup")]
    ActiveBackup,
    #[strum(serialize = "roundrobin")]
    #[default]
    RoundRobin,
    #[strum(serialize = "broadcast")]
    Broadcast,
    #[strum(serialize = "loadbalance")]
    LoadBalance,
    #[strum(serialize = "random")]
    Random,
}

#[derive(
    Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display, Default, Clone, Copy,
)]
#[strum(serialize_all = "snake_case")]
pub enum SelectPolicy {
    #[strum(serialize = "lacp_prio")]
    #[default]
    LacpPrio,
    #[strum(serialize = "lacp_prio_stable")]
    LacpPrioStable,
    #[strum(serialize = "bandwidth")]
    Bandwidth,
    #[strum(serialize = "count")]
    Count,
}

fn default_true() -> bool {
    true
}

fn default_sys_prio() -> u16 {
    255
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Runner {
    #[serde(rename = "@name", default)]
    pub name: RunnerName,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(rename = "fast_rate", default)]
    pub fast_rate: bool,
    #[serde(rename = "sys_prio", default = "default_sys_prio")]
    pub sys_prio: u16,
    #[serde(rename = "min_ports", default)]
    pub min_ports: u16,
    #[serde(rename = "select_policy", default)]
    pub select_policy: SelectPolicy,
    #[serde(rename = "tx_hash")]
    pub tx_hash: Option<String>,
    #[serde(rename = "tx_balancer")]
    pub tx_balancer: Option<TxBalancer>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TxBalancer {
    pub name: Option<String>,
    #[serde(rename = "balancing_interval")]
    pub balancing_interval: Option<u32>,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct LinkWatch {
    #[serde(rename = "watch", default)]
    pub watches: Vec<Watch>,
}

#[derive(
    Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display, Default, Clone, Copy,
)]
#[strum(serialize_all = "snake_case")]
pub enum WatchName {
    #[strum(serialize = "ethtool")]
    #[default]
    Ethtool,
    #[strum(serialize = "arp_ping")]
    ArpPing,
    #[strum(serialize = "nsna_ping")]
    NsnaPing,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Watch {
    #[serde(rename = "@name", default)]
    pub name: WatchName,
    #[serde(rename = "delay_up", default)]
    pub delay_up: u32,
    #[serde(rename = "delay_down", default)]
    pub delay_down: u32,
    #[serde(rename = "interval", default)]
    pub interval: u32,
    #[serde(rename = "target_host")]
    pub target_host: Option<String>,
}

impl From<&Team> for model::ConnectionConfig {
    fn from(team: &Team) -> model::ConnectionConfig {
        let mut bond_options: HashMap<String, String> = HashMap::new();
        let mut mode = AgamaBondMode::RoundRobin; // Default fallback

        if let Some(runner) = &team.runner {
            match runner.name {
                RunnerName::Lacp => {
                    mode = AgamaBondMode::LACP;
                    bond_options.insert(
                        String::from("lacp_rate"),
                        if runner.fast_rate { "fast" } else { "slow" }.to_string(),
                    );
                    bond_options
                        .insert(String::from("ad_actor_sys_prio"), runner.sys_prio.to_string());
                    bond_options.insert(String::from("min_links"), runner.min_ports.to_string());

                    let val = match runner.select_policy {
                        SelectPolicy::LacpPrio => "stable",
                        SelectPolicy::LacpPrioStable => "stable",
                        SelectPolicy::Bandwidth => "bandwidth",
                        SelectPolicy::Count => "count",
                    };
                    bond_options.insert(String::from("ad_select"), val.to_string());
                }
                RunnerName::ActiveBackup => {
                    mode = AgamaBondMode::ActiveBackup;
                }
                RunnerName::RoundRobin => {
                    mode = AgamaBondMode::RoundRobin;
                }
                RunnerName::Broadcast => {
                    mode = AgamaBondMode::Broadcast;
                }
                RunnerName::LoadBalance => {
                    mode = AgamaBondMode::BalanceXOR;
                }
                RunnerName::Random => {
                    log::warn!("Team runner 'random' is not directly supported by NetworkManager bond mode, defaulting to round-robin");
                    mode = AgamaBondMode::RoundRobin;
                }
            }

            if let Some(tx_hash) = &runner.tx_hash {
                let val = if tx_hash.contains("l4")
                    || (tx_hash.contains("tcp") && tx_hash.contains("udp"))
                {
                    "layer3+4"
                } else if tx_hash.contains("ipv4") || tx_hash.contains("ipv6") {
                    "layer2+3"
                } else {
                    "layer2"
                };
                bond_options.insert(String::from("xmit_hash_policy"), val.to_string());
            } else if let Some(tx_balancer) = &runner.tx_balancer {
                if let Some(name) = &tx_balancer.name {
                    let val = if name.contains("basic") {
                        "layer2+3"
                    } else {
                        "layer2"
                    };
                    bond_options.insert(String::from("xmit_hash_policy"), val.to_string());
                }
            }
        }

        if let Some(lw_container) = &team.link_watch {
            for watch in &lw_container.watches {
                match watch.name {
                    WatchName::Ethtool => {
                        bond_options.insert(String::from("miimon"), "100".to_string());

                        if watch.delay_up > 0 {
                            bond_options
                                .insert(String::from("updelay"), watch.delay_up.to_string());
                        }
                        if watch.delay_down > 0 {
                            bond_options
                                .insert(String::from("downdelay"), watch.delay_down.to_string());
                        }
                    }
                    WatchName::ArpPing => {
                        if watch.interval > 0 {
                            bond_options
                                .insert(String::from("arp_interval"), watch.interval.to_string());
                        }
                        if let Some(target) = &watch.target_host {
                            bond_options.insert(String::from("arp_ip_target"), target.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        model::ConnectionConfig::Bond(model::BondConfig {
            options: model::BondOptions(bond_options),
            mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agama_network::model::ConnectionConfig;
    use agama_network::types::BondMode as AgamaBondMode;

    #[test]
    fn test_runner_name_serialization() {
        assert_eq!(RunnerName::Lacp.to_string(), "lacp");
        assert_eq!(RunnerName::ActiveBackup.to_string(), "activebackup");
        assert_eq!(RunnerName::RoundRobin.to_string(), "roundrobin");
        assert_eq!(RunnerName::Broadcast.to_string(), "broadcast");
        assert_eq!(RunnerName::LoadBalance.to_string(), "loadbalance");
        assert_eq!(RunnerName::Random.to_string(), "random");
    }

    #[test]
    fn test_runner_name_deserialization() {
        use std::str::FromStr;
        assert_eq!(RunnerName::from_str("lacp").unwrap(), RunnerName::Lacp);
        assert_eq!(RunnerName::from_str("activebackup").unwrap(), RunnerName::ActiveBackup);
        assert_eq!(RunnerName::from_str("roundrobin").unwrap(), RunnerName::RoundRobin);
        assert_eq!(RunnerName::from_str("broadcast").unwrap(), RunnerName::Broadcast);
        assert_eq!(RunnerName::from_str("loadbalance").unwrap(), RunnerName::LoadBalance);
        assert_eq!(RunnerName::from_str("random").unwrap(), RunnerName::Random);
    }

    #[test]
    fn test_team_deserialization() {
        let xml = r#"
            <team>
                <runner name="lacp">
                    <fast_rate>true</fast_rate>
                    <sys_prio>100</sys_prio>
                    <min_ports>2</min_ports>
                    <select_policy>bandwidth</select_policy>
                    <tx_hash>ipv4,ipv6,l4</tx_hash>
                </runner>
                <link_watch>
                    <watch name="ethtool">
                        <delay_up>10</delay_up>
                        <delay_down>20</delay_down>
                    </watch>
                    <watch name="arp_ping">
                        <interval>100</interval>
                        <target_host>1.2.3.4</target_host>
                    </watch>
                </link_watch>
            </team>
        "#;
        let mut deserializer = quick_xml::de::Deserializer::from_str(xml);
        let team: Team = Team::deserialize(&mut deserializer).unwrap();

        let runner = team.runner.as_ref().unwrap();
        assert_eq!(runner.name, RunnerName::Lacp);
        assert!(runner.fast_rate);
        assert_eq!(runner.sys_prio, 100);
        assert_eq!(runner.min_ports, 2);
        assert_eq!(runner.select_policy, SelectPolicy::Bandwidth);
        assert_eq!(runner.tx_hash.as_ref().unwrap(), "ipv4,ipv6,l4");

        let link_watch = team.link_watch.as_ref().unwrap();
        assert_eq!(link_watch.watches.len(), 2);
        assert_eq!(link_watch.watches[0].name, WatchName::Ethtool);
        assert_eq!(link_watch.watches[0].delay_up, 10);
        assert_eq!(link_watch.watches[0].delay_down, 20);
        assert_eq!(link_watch.watches[1].name, WatchName::ArpPing);
        assert_eq!(link_watch.watches[1].interval, 100);
        assert_eq!(link_watch.watches[1].target_host.as_ref().unwrap(), "1.2.3.4");
    }

    #[test]
    fn test_team_to_connection_config_lacp() {
        let team = Team {
            runner: Some(Runner {
                name: RunnerName::Lacp,
                active: true,
                fast_rate: true,
                sys_prio: 100,
                min_ports: 2,
                select_policy: SelectPolicy::Bandwidth,
                tx_hash: Some("ipv4,ipv6,l4".to_string()),
                tx_balancer: None,
            }),
            link_watch: Some(LinkWatch {
                watches: vec![
                    Watch {
                        name: WatchName::Ethtool,
                        delay_up: 10,
                        delay_down: 20,
                        interval: 0,
                        target_host: None,
                    },
                    Watch {
                        name: WatchName::ArpPing,
                        delay_up: 0,
                        delay_down: 0,
                        interval: 100,
                        target_host: Some("1.2.3.4".to_string()),
                    },
                ],
            }),
        };

        let config: ConnectionConfig = (&team).into();
        if let ConnectionConfig::Bond(bond) = config {
            assert_eq!(bond.mode, AgamaBondMode::LACP);
            let options = bond.options.0;
            assert_eq!(options.get("lacp_rate").unwrap(), "fast");
            assert_eq!(options.get("ad_actor_sys_prio").unwrap(), "100");
            assert_eq!(options.get("min_links").unwrap(), "2");
            assert_eq!(options.get("ad_select").unwrap(), "bandwidth");
            assert_eq!(options.get("xmit_hash_policy").unwrap(), "layer3+4");
            assert_eq!(options.get("miimon").unwrap(), "100");
            assert_eq!(options.get("updelay").unwrap(), "10");
            assert_eq!(options.get("downdelay").unwrap(), "20");
            assert_eq!(options.get("arp_interval").unwrap(), "100");
            assert_eq!(options.get("arp_ip_target").unwrap(), "1.2.3.4");
        } else {
            panic!("Expected Bond config");
        }
    }

    #[test]
    fn test_team_to_connection_config_tx_hash() {
        let cases = vec![
            (Some("ipv4,ipv6,l4".to_string()), "layer3+4"),
            (Some("tcp,udp".to_string()), "layer3+4"),
            (Some("ipv4,ipv6".to_string()), "layer2+3"),
            (Some("ipv4".to_string()), "layer2+3"),
            (Some("l2".to_string()), "layer2"),
            (None, ""), // won't be in hashmap if None
        ];

        for (tx_hash, expected) in cases {
            let team = Team {
                runner: Some(Runner {
                    name: RunnerName::RoundRobin,
                    tx_hash: tx_hash.clone(),
                    ..Default::default()
                }),
                link_watch: None,
            };

            let config: ConnectionConfig = (&team).into();
            if let ConnectionConfig::Bond(bond) = config {
                if tx_hash.is_some() {
                    assert_eq!(bond.options.0.get("xmit_hash_policy").unwrap(), expected);
                } else {
                    assert!(bond.options.0.get("xmit_hash_policy").is_none());
                }
            }
        }
    }

    #[test]
    fn test_team_to_connection_config_tx_balancer() {
        let team = Team {
            runner: Some(Runner {
                name: RunnerName::LoadBalance,
                tx_balancer: Some(TxBalancer {
                    name: Some("basic".to_string()),
                    balancing_interval: Some(100),
                }),
                ..Default::default()
            }),
            link_watch: None,
        };

        let config: ConnectionConfig = (&team).into();
        if let ConnectionConfig::Bond(bond) = config {
            assert_eq!(bond.options.0.get("xmit_hash_policy").unwrap(), "layer2+3");
        }
    }

    #[test]
    fn test_runner_name_mapping() {
        let cases = vec![
            (RunnerName::Lacp, AgamaBondMode::LACP),
            (RunnerName::ActiveBackup, AgamaBondMode::ActiveBackup),
            (RunnerName::RoundRobin, AgamaBondMode::RoundRobin),
            (RunnerName::Broadcast, AgamaBondMode::Broadcast),
            (RunnerName::LoadBalance, AgamaBondMode::BalanceXOR),
            (RunnerName::Random, AgamaBondMode::RoundRobin),
        ];

        for (name, expected_mode) in cases {
            let team = Team {
                runner: Some(Runner {
                    name,
                    ..Default::default()
                }),
                link_watch: None,
            };

            let config: ConnectionConfig = (&team).into();
            if let ConnectionConfig::Bond(bond) = config {
                assert_eq!(bond.mode, expected_mode);
            }
        }
    }

    #[test]
    fn test_select_policy_mapping() {
        let policies = vec![
            (SelectPolicy::LacpPrio, "stable"),
            (SelectPolicy::LacpPrioStable, "stable"),
            (SelectPolicy::Bandwidth, "bandwidth"),
            (SelectPolicy::Count, "count"),
        ];

        for (policy, expected) in policies {
            let team = Team {
                runner: Some(Runner {
                    name: RunnerName::Lacp,
                    select_policy: policy,
                    ..Default::default()
                }),
                link_watch: None,
            };

            let config: ConnectionConfig = (&team).into();
            if let ConnectionConfig::Bond(bond) = config {
                assert_eq!(bond.options.0.get("ad_select").unwrap(), expected);
            }
        }
    }

    #[test]
    fn test_nsna_ping_ignored() {
        let team = Team {
            runner: None,
            link_watch: Some(LinkWatch {
                watches: vec![Watch {
                    name: WatchName::NsnaPing,
                    interval: 100,
                    ..Default::default()
                }],
            }),
        };

        let config: ConnectionConfig = (&team).into();
        if let ConnectionConfig::Bond(bond) = config {
            assert!(bond.options.0.is_empty());
        }
    }
}

