use agama_network::model::{self};
use agama_network::types::BondMode as AgamaBondMode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{skip_serializing_none, DeserializeFromStr, SerializeDisplay};
use std::collections::HashMap;
use strum_macros::{Display, EnumString};

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum FailOverMac {
    None,
    Active,
    Follow,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum XmitHashPolicy {
    Layer2,
    Layer23,
    Layer34,
    Encap23,
    Encap34,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum LacpRate {
    Slow,
    Fast,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum AdSelect {
    Stable,
    Bandwidth,
    Count,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum PrimaryReselect {
    Always,
    Better,
    Failure,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum WickedBondMode {
    BalanceRr = 0,
    ActiveBackup,
    BalanceXor,
    Broadcast,
    #[strum(serialize = "ieee802-3ad")]
    IEEE8023ad,
    BalanceTlb,
    BalanceAlb,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Bond {
    pub mode: WickedBondMode,
    pub miimon: Option<Miimon>,
    pub arpmon: Option<ArpMon>,
    /* only on mode=[802.3ad, balance_xor] */
    pub xmit_hash_policy: Option<XmitHashPolicy>,
    /* only on mode=balance_rr */
    pub packets_per_slave: Option<u32>,
    /* only on mode=balance_tlb */
    pub tlb_dynamic_lb: Option<bool>,
    /* only on mode=802.3ad */
    pub lacp_rate: Option<LacpRate>,
    /* only on mode=802.3ad */
    pub ad_select: Option<AdSelect>,
    /* only on mode=802.3ad */
    pub ad_user_port_key: Option<u32>,
    /* only on mode=802.3ad */
    pub ad_actor_sys_prio: Option<u32>,
    /* only on mode=802.3ad */
    pub ad_actor_system: Option<String>,
    /* only on mode=802.3ad */
    pub min_links: Option<u32>,
    /* only on mode=active-backup */
    pub primary_reselect: Option<PrimaryReselect>,
    /* only on mode=active-backup */
    pub fail_over_mac: Option<FailOverMac>,
    /* only on mode=active-backup */
    pub num_grat_arp: Option<u32>,
    /* only on mode=active-backup */
    pub num_unsol_na: Option<u32>,
    /* only on mode=[balance_tlb|balance_alb] */
    pub lp_interval: Option<u32>,
    /* only on mode=[active-backup|balance_tlb|balance_alb] */
    pub primary: Option<String>,
    /* only on mode=[balance_tlb|balance_alb|balance_RR|active-backup] */
    pub resend_igmp: Option<u32>,
    pub all_slaves_active: Option<bool>,
    pub address: Option<String>,
}

#[derive(Debug, PartialEq, Default, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum CarrierDetect {
    Ioctl = 0,
    #[default]
    Netif = 1,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Miimon {
    pub frequency: u32,
    #[serde(rename = "carrier-detect")]
    pub carrier_detect: CarrierDetect,
    pub downdelay: Option<u32>,
    pub updelay: Option<u32>,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum ArpValidateTargets {
    Any = 0,
    All = 1,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ArpValidate {
    None = 0,
    Active = 1,
    Backup = 2,
    All = 3,
    Filter = 4,
    FilterActive = 5,
    FilterBackup = 6,
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ArpMon {
    pub interval: u32,
    pub validate: ArpValidate,
    #[serde(rename = "validate-targets")]
    pub validate_targets: Option<ArpValidateTargets>,
    #[serde(deserialize_with = "unwrap_arpmon_targets")]
    pub targets: Vec<String>,
}

fn unwrap_arpmon_targets<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
    pub struct ArpMonTargetAddressV4 {
        #[serde(rename = "ipv4-address")]
        pub ipv4_address: Vec<String>,
    }
    Ok(ArpMonTargetAddressV4::deserialize(deserializer)?.ipv4_address)
}

impl From<&WickedBondMode> for AgamaBondMode {
    fn from(bondmode: &WickedBondMode) -> AgamaBondMode {
        match bondmode {
            WickedBondMode::BalanceRr => AgamaBondMode::RoundRobin,
            WickedBondMode::ActiveBackup => AgamaBondMode::ActiveBackup,
            WickedBondMode::BalanceXor => AgamaBondMode::BalanceXOR,
            WickedBondMode::Broadcast => AgamaBondMode::Broadcast,
            WickedBondMode::IEEE8023ad => AgamaBondMode::LACP,
            WickedBondMode::BalanceTlb => AgamaBondMode::BalanceTLB,
            WickedBondMode::BalanceAlb => AgamaBondMode::BalanceALB,
        }
    }
}

impl XmitHashPolicy {
    fn to_agama(&self) -> String {
        match self {
            XmitHashPolicy::Layer2 => String::from("layer2"),
            XmitHashPolicy::Layer23 => String::from("layer2+3"),
            XmitHashPolicy::Layer34 => String::from("layer3+4"),
            XmitHashPolicy::Encap23 => String::from("encap2+3"),
            XmitHashPolicy::Encap34 => String::from("encap3+4"),
        }
    }
}

impl From<&Bond> for model::ConnectionConfig {
    fn from(bond: &Bond) -> model::ConnectionConfig {
        let mut h: HashMap<String, String> = HashMap::new();

        if let Some(p) = &bond.primary {
            h.insert(String::from("primary"), p.clone());
        }

        if let Some(m) = &bond.miimon {
            h.insert(String::from("miimon"), format!("{}", m.frequency));
            h.insert(
                String::from("use_carrier"),
                match m.carrier_detect {
                    CarrierDetect::Ioctl => 0,
                    CarrierDetect::Netif => 1,
                }
                .to_string(),
            );
            if let Some(v) = m.downdelay {
                h.insert(String::from("downdelay"), v.to_string());
            }
            if let Some(v) = m.updelay {
                h.insert(String::from("updelay"), v.to_string());
            }
        }

        if let Some(a) = &bond.arpmon {
            h.insert(String::from("arp_interval"), format!("{}", a.interval));
            h.insert(String::from("arp_validate"), a.validate.to_string());

            if !a.targets.is_empty() {
                let sv = a
                    .targets
                    .iter()
                    .map(|c| c.as_ref())
                    .collect::<Vec<&str>>()
                    .join(",");
                h.insert(String::from("arp_ip_target"), sv);
            }

            if let Some(v) = &a.validate_targets {
                h.insert(String::from("arp_all_targets"), v.to_string());
            }
        }

        if let Some(fom) = &bond.fail_over_mac {
            h.insert(String::from("fail_over_mac"), fom.to_string());
        }

        if let Some(v) = &bond.xmit_hash_policy {
            h.insert(String::from("xmit_hash_policy"), v.to_agama());
        }

        if let Some(v) = &bond.packets_per_slave {
            h.insert(String::from("packets_per_slave"), v.to_string());
        }

        if let Some(v) = &bond.tlb_dynamic_lb {
            h.insert(
                String::from("tlb_dynamic_lb"),
                if *v { 1.to_string() } else { 0.to_string() },
            );
        }

        if let Some(v) = &bond.lacp_rate {
            h.insert(String::from("lacp_rate"), v.to_string());
        }

        if let Some(v) = &bond.ad_select {
            h.insert(String::from("ad_select"), v.to_string());
        }
        if let Some(v) = &bond.ad_user_port_key {
            h.insert(String::from("ad_user_port_key"), v.to_string());
        }
        if let Some(v) = &bond.ad_actor_sys_prio {
            h.insert(String::from("ad_actor_sys_prio"), v.to_string());
        }
        if let Some(v) = &bond.ad_actor_system {
            h.insert(String::from("ad_actor_system"), v.clone());
        }
        if let Some(v) = &bond.min_links {
            h.insert(String::from("min_links"), v.to_string());
        }
        if let Some(v) = &bond.primary_reselect {
            h.insert(String::from("primary_reselect"), v.to_string());
        }
        if let Some(v) = &bond.num_grat_arp {
            h.insert(String::from("num_grat_arp"), v.to_string());
        }
        if let Some(v) = &bond.num_unsol_na {
            h.insert(String::from("num_unsol_na"), v.to_string());
        }
        if let Some(v) = &bond.lp_interval {
            h.insert(String::from("lp_interval"), v.to_string());
        }
        if let Some(v) = &bond.resend_igmp {
            h.insert(String::from("resend_igmp"), v.to_string());
        }
        if let Some(v) = &bond.all_slaves_active {
            h.insert(
                String::from("all_slaves_active"),
                if *v { 1.to_string() } else { 0.to_string() },
            );
        }

        model::ConnectionConfig::Bond(model::BondConfig {
            options: model::BondOptions(h),
            mode: AgamaBondMode::from(&bond.mode),
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
    fn test_bond_options() {
        setup_default_migration_settings();
        let bond_interface = Interface {
            bond: Some(Bond {
                mode: WickedBondMode::IEEE8023ad,
                xmit_hash_policy: Some(XmitHashPolicy::Encap34),
                fail_over_mac: Some(FailOverMac::Active),
                packets_per_slave: Some(23),
                tlb_dynamic_lb: Some(true),
                lacp_rate: Some(LacpRate::Slow),
                ad_select: Some(AdSelect::Bandwidth),
                ad_user_port_key: Some(42),
                ad_actor_sys_prio: Some(5),
                ad_actor_system: Some(String::from("00:de:ad:be:ef:00")),
                min_links: Some(3),
                primary_reselect: Some(PrimaryReselect::Better),
                num_grat_arp: Some(7),
                num_unsol_na: Some(13),
                lp_interval: Some(17),
                resend_igmp: Some(19),
                all_slaves_active: Some(true),
                miimon: Some(Miimon {
                    frequency: 42,
                    carrier_detect: CarrierDetect::Netif,
                    downdelay: Some(23),
                    updelay: Some(5),
                }),
                arpmon: Some(ArpMon {
                    interval: 23,
                    validate: ArpValidate::FilterBackup,
                    validate_targets: Some(ArpValidateTargets::Any),
                    targets: vec![String::from("1.2.3.4"), String::from("4.3.2.1")],
                }),
                address: Some(String::from("02:11:22:33:44:55")),
                primary: Some(String::from("en0")),
            }),
            ..Default::default()
        };

        let connection: &model::Connection =
            &bond_interface.to_connection(&None).unwrap().connections[0];
        assert!(matches!(
            connection.config,
            model::ConnectionConfig::Bond(_)
        ));
        assert_eq!(connection.mac_address.to_string(), "02:11:22:33:44:55");

        if let model::ConnectionConfig::Bond(bond) = &connection.config {
            assert_eq!(bond.mode, AgamaBondMode::LACP);
            let s = HashMap::from([
                ("xmit_hash_policy", String::from("encap3+4")),
                ("packets_per_slave", 23.to_string()),
                ("tlb_dynamic_lb", 1.to_string()),
                ("lacp_rate", String::from("slow")),
                ("ad_select", String::from("bandwidth")),
                ("ad_user_port_key", 42.to_string()),
                ("ad_actor_sys_prio", 5.to_string()),
                ("ad_actor_system", String::from("00:de:ad:be:ef:00")),
                ("min_links", 3.to_string()),
                ("primary_reselect", String::from("better")),
                ("fail_over_mac", String::from("active")),
                ("num_grat_arp", 7.to_string()),
                ("num_unsol_na", 13.to_string()),
                ("lp_interval", 17.to_string()),
                ("resend_igmp", 19.to_string()),
                ("all_slaves_active", 1.to_string()),
                // miimon
                ("miimon", 42.to_string()),
                ("use_carrier", 1.to_string()),
                ("downdelay", 23.to_string()),
                ("updelay", 5.to_string()),
                // arpmon
                ("arp_validate", String::from("filter_backup")),
                ("arp_all_targets", String::from("any")),
                ("arp_ip_target", String::from("1.2.3.4,4.3.2.1")),
                ("arp_interval", 23.to_string()),
                ("primary", String::from("en0")),
            ]);

            for (k, v) in s.iter() {
                assert!(
                    bond.options.0.contains_key(*k),
                    "Missing key '{}' in bond hash {:?}",
                    *k,
                    bond.options.0
                );
                assert_eq!(
                    bond.options.0.get(*k).unwrap(),
                    v,
                    "Unexpected value '{}' in key '{}'",
                    *k,
                    v
                );
            }
        }
    }
}
