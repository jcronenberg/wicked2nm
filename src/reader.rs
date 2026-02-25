use crate::interface::Interface;
use crate::netconfig::{read_netconfig, Netconfig};
use crate::netconfig_dhcp::{read_netconfig_dhcp, NetconfigDhcp};
use crate::MIGRATION_SETTINGS;

use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;
use std::fs::{self, read_dir};
use std::io::{self};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct InterfacesResult {
    pub interfaces: Vec<Interface>,
    pub netconfig: Option<Netconfig>,
    pub netconfig_dhcp: Option<NetconfigDhcp>,
    pub has_warnings: bool,
}

fn validate_xml(xml: &str) -> Result<(), anyhow::Error> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    let mut root_found = false;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = e.local_name();
                let name_bytes = name.as_ref();
                if name_bytes != b"interface" {
                    anyhow::bail!(
                        "The provided file is not a valid Wicked XML configuration (unexpected element: <{}>).",
                        String::from_utf8_lossy(name_bytes)
                    );
                }
                root_found = true;
                break;
            }
            Ok(_) => (),
            Err(e) => {
                anyhow::bail!("Invalid XML configuration: {}", e);
            }
        }
    }

    if !root_found {
        anyhow::bail!("The provided file is not a valid Wicked XML configuration (no <interface> element found).");
    }

    Ok(())
}

// Define a list of fields that are ignored if present.
// The list must be in alphabetical order.
pub const IGNORED_FIELDS: &[&str] = &[
    "ipv4.arp-notify",
    "ipv4.forwarding",
    "ipv6.accept-dad",
    "ipv6.accept-ra",
    "ipv6.addr-gen-mode",
    "ipv6.autoconf",
    "ipv6.forwarding",
    "ipv6.stable-secret",
];

pub fn read_xml_file(path: PathBuf) -> Result<InterfacesResult, anyhow::Error> {
    let contents = match fs::read_to_string(path.clone()) {
        Ok(contents) => contents,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Couldn't read {}: {}",
                path.as_path().display(),
                e
            ))
        }
    };
    deserialize_xml(contents)
}

pub fn deserialize_xml(contents: String) -> Result<InterfacesResult, anyhow::Error> {
    validate_xml(contents.as_str())?;
    let replaced_string = replace_colons(contents.as_str());
    let deserializer = &mut quick_xml::de::Deserializer::from_str(replaced_string.as_str());
    let mut unhandled_fields = vec![];
    let interfaces: Vec<Interface> = match serde_ignored::deserialize(deserializer, |path| {
        unhandled_fields.push(path.to_string())
    }) {
        Ok(interfaces) => interfaces,
        Err(e) => {
            let deserializer2 =
                &mut quick_xml::de::Deserializer::from_str(replaced_string.as_str());
            let res: Result<Vec<Interface>, _> = serde_path_to_error::deserialize(deserializer2);
            if let Err(path_error) = res {
                log::error!("Error at {}: {}", path_error.path(), e);
            }
            return Err(e.into());
        }
    };
    let mut result = InterfacesResult {
        interfaces,
        netconfig: None,
        netconfig_dhcp: None,
        has_warnings: false,
    };

    for e in unhandled_fields {
        let split_str = e.split_once('.').unwrap();
        let ifc_name = &result.interfaces[split_str.0.parse::<usize>().unwrap()].name;
        let field = split_str.1;

        if IGNORED_FIELDS.binary_search(&field).is_ok() {
            log::debug!("Ingnore field in interface {ifc_name}: {field}");
        } else {
            log::warn!("Unhandled field in interface {ifc_name}: {field}");
            result.has_warnings = true;
        }
    }

    Ok(result)
}

fn replace_colons(colon_string: &str) -> String {
    let re = Regex::new(r"<([\/]?)(\w+):(\w+)\b").unwrap();
    let replaced = re.replace_all(colon_string, "<$1$2-$3").to_string();
    replaced
}

// https://stackoverflow.com/a/76820878
fn list_files(path: impl AsRef<Path>, recursive: bool) -> std::io::Result<Vec<PathBuf>> {
    let mut buf = vec![];
    let entries = read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;

        if meta.is_dir() && recursive {
            let mut subdir = list_files(entry.path(), recursive)?;
            buf.append(&mut subdir);
        }

        if meta.is_file() {
            buf.push(entry.path());
        }
    }

    Ok(buf)
}

fn is_ifsysctl(path: &Path) -> bool {
    let invalid_suffix = [
        "~",
        ".old",
        ".bak",
        ".orig",
        ".scpmbackup",
        ".rpmnew",
        ".rpmsave",
        ".rpmorig",
    ];

    path.file_name()
        .and_then(|name| name.to_str())
        .map(|filename| {
            filename.starts_with("ifsysctl")
                && !invalid_suffix.iter().any(|e| filename.ends_with(e))
        })
        .unwrap_or(false)
}

fn warn_on_deprecated_ifsysctl() -> Result<bool, anyhow::Error> {
    let settings = MIGRATION_SETTINGS.get().unwrap();
    let mut has_warning = false;

    let files = list_files(&settings.netconfig_base_dir, false)?;
    for file in files {
        if is_ifsysctl(&file) {
            log::warn!(
                "ifsysctl file \"{}\" is deprecated and will not be migrated",
                file.display()
            );
            has_warning = true;
        }
    }

    Ok(has_warning)
}

pub fn read(paths: Vec<String>) -> Result<InterfacesResult, anyhow::Error> {
    let settings = MIGRATION_SETTINGS.get().unwrap();

    let mut result = if paths.len() == 1 && paths[0] == "-" {
        deserialize_xml(io::read_to_string(io::stdin())?)?
    } else {
        read_files(paths)?
    };

    if settings.with_netconfig {
        match read_netconfig(settings.netconfig_path.clone()) {
            Ok(netconfig) => {
                result.has_warnings |= netconfig.has_warning;
                result.netconfig = Some(netconfig);
            }
            Err(e) => {
                anyhow::bail!(
                    "Failed to read netconfig at {}: {}",
                    settings.netconfig_path.display(),
                    e
                );
            }
        };

        match read_netconfig_dhcp(&settings.netconfig_dhcp_path) {
            Ok(netconfig_dhcp) => {
                result.has_warnings |= netconfig_dhcp.has_warning;
                result.netconfig_dhcp = Some(netconfig_dhcp);
            }
            Err(e) => {
                anyhow::bail!(
                    "Failed to read netconfig_dhcp at {}: {}",
                    settings.netconfig_dhcp_path.display(),
                    e
                )
            }
        };

        match warn_on_deprecated_ifsysctl() {
            Err(e) => anyhow::bail!("Unexpected error, while searching ifsysctl files: {}", e),
            Ok(has_warnings) => result.has_warnings |= has_warnings,
        };
    }

    // Filter loopback as it doesn't need to be migrated
    result.interfaces.retain(|interface| interface.name != "lo");

    Ok(result)
}

fn read_files(file_paths: Vec<String>) -> Result<InterfacesResult, anyhow::Error> {
    let mut result = InterfacesResult {
        interfaces: vec![],
        netconfig: None,
        netconfig_dhcp: None,
        has_warnings: false,
    };

    for path in file_paths {
        let path: PathBuf = path.into();
        if path.is_dir() {
            let files = list_files(path, true)?;
            for file in files {
                match file.extension() {
                    None => continue,
                    Some(ext) => {
                        if !ext.eq("xml") {
                            continue;
                        }
                    }
                }
                let mut read_xml = read_xml_file(file)?;
                result.has_warnings |= read_xml.has_warnings;
                result.interfaces.append(&mut read_xml.interfaces);
            }
        } else {
            let mut read_xml = read_xml_file(path)?;
            result.has_warnings |= read_xml.has_warnings;
            result.interfaces.append(&mut read_xml.interfaces);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond::*;

    #[test]
    fn test_bond_options_from_xml() {
        let xml = r##"
            <interface>
                <name>bond0</name>
                <bond>
                    <mode>active-backup</mode>
                    <xmit-hash-policy>layer34</xmit-hash-policy>
                    <fail-over-mac>none</fail-over-mac>
                    <packets-per-slave>1</packets-per-slave>
                    <tlb-dynamic-lb>true</tlb-dynamic-lb>
                    <lacp-rate>slow</lacp-rate>
                    <ad-select>bandwidth</ad-select>
                    <ad-user-port-key>5</ad-user-port-key>
                    <ad-actor-sys-prio>7</ad-actor-sys-prio>
                    <ad-actor-system>00:de:ad:be:ef:00</ad-actor-system>
                    <min-links>11</min-links>
                    <primary-reselect>better</primary-reselect>
                    <num-grat-arp>13</num-grat-arp>
                    <num-unsol-na>17</num-unsol-na>
                    <lp-interval>19</lp-interval>
                    <resend-igmp>23</resend-igmp>
                    <all-slaves-active>true</all-slaves-active>
                    <miimon>
                        <frequency>23</frequency>
                        <updelay>27</updelay>
                        <downdelay>31</downdelay>
                        <carrier-detect>ioctl</carrier-detect>
                    </miimon>
                    <arpmon>
                        <interval>23</interval>
                        <validate>filter_backup</validate>
                        <validate-targets>any</validate-targets>
                        <targets>
                            <ipv4-address>1.2.3.4</ipv4-address>
                            <ipv4-address>4.3.2.1</ipv4-address>
                        </targets>
                    </arpmon>
                    <address>02:11:22:33:44:55</address>
                    <primary>en0</primary>
                </bond>
            </interface>
            "##;
        let ifc = deserialize_xml(xml.to_string())
            .unwrap()
            .interfaces
            .pop()
            .unwrap();
        assert!(ifc.bond.is_some());
        let bond = ifc.bond.unwrap();

        assert_eq!(
            bond,
            Bond {
                mode: WickedBondMode::ActiveBackup,
                xmit_hash_policy: Some(XmitHashPolicy::Layer34),
                fail_over_mac: Some(FailOverMac::None),
                packets_per_slave: Some(1),
                tlb_dynamic_lb: Some(true),
                lacp_rate: Some(LacpRate::Slow),
                ad_select: Some(AdSelect::Bandwidth),
                ad_user_port_key: Some(5),
                ad_actor_sys_prio: Some(7),
                ad_actor_system: Some(String::from("00:de:ad:be:ef:00")),
                min_links: Some(11),
                primary_reselect: Some(PrimaryReselect::Better),
                num_grat_arp: Some(13),
                num_unsol_na: Some(17),
                lp_interval: Some(19),
                resend_igmp: Some(23),
                all_slaves_active: Some(true),
                miimon: Some(Miimon {
                    frequency: 23,
                    carrier_detect: CarrierDetect::Ioctl,
                    downdelay: Some(31),
                    updelay: Some(27),
                }),
                arpmon: Some(ArpMon {
                    interval: 23,
                    validate: ArpValidate::FilterBackup,
                    validate_targets: Some(ArpValidateTargets::Any),
                    targets: vec![String::from("1.2.3.4"), String::from("4.3.2.1")]
                }),
                address: Some(String::from("02:11:22:33:44:55")),
                primary: Some(String::from("en0")),
            }
        );
    }

    /// This test check that the default for stp from wicked is False.
    #[test]
    fn test_bridge_default_stp() {
        let xml = r##"
            <interface>
              <name>br0</name>
              <bridge>
                <ports>
                  <port>
                    <device>en0</device>
                  </port>
                </ports>
              </bridge>
            </interface>
            "##;
        let ifc = deserialize_xml(xml.to_string())
            .unwrap()
            .interfaces
            .pop()
            .unwrap();
        assert!(ifc.bridge.is_some());
        assert!(!ifc.bridge.unwrap().stp);
    }

    #[test]
    fn test_broken_xml() {
        let xml = r##"
            <interface>
                <name>eth1</name>
                <ipv4:static>
                  <address>127.0.0.1</>
                </ipv4:static>
            </interface>
            "##;
        let err = deserialize_xml(xml.to_string());
        assert!(err.is_err());
    }

    #[test]
    fn test_non_xml() {
        let content = "This is just some random text, not XML at all.";
        let err = deserialize_xml(content.to_string());
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("no <interface> element found"));
    }

    #[test]
    fn test_empty_xml() {
        let content = "  ";
        let err = deserialize_xml(content.to_string());
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("no <interface> element found"));
    }

    #[test]
    fn test_unexpected_root() {
        let content = "<unexpected><foo>bar</foo></unexpected>";
        let err = deserialize_xml(content.to_string());
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("unexpected element: <unexpected>"));
    }

    #[test]
    fn test_xml_firewall_zone() {
        let xml = r##"
            <interface>
                <name>eth1</name>
                <firewall>
                    <zone>foo</zone>
                </firewall>
            </interface>
            "##;

        let ifc = deserialize_xml(xml.to_string())
            .unwrap()
            .interfaces
            .pop()
            .unwrap();
        assert_eq!(ifc.firewall.zone, Some("foo".to_string()));
    }

    #[test]
    fn check_sort_of_ignored_fields() {
        let mut i = 1;

        while i < IGNORED_FIELDS.len() {
            let a = IGNORED_FIELDS[i - 1].as_bytes();
            let b = IGNORED_FIELDS[i].as_bytes();
            assert!(a <= b);
            i += 1;
        }
    }
}
