use crate::MIGRATION_SETTINGS;
use agama_network::model::{self, WEPAuthAlg, WEPKeyType, WEPSecurity};
use agama_network::types::SSID;
use anyhow::anyhow;
use macaddr::MacAddr6;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::formats::CommaSeparator;
use serde_with::StringWithSeparator;
use serde_with::{serde_as, skip_serializing_none, DeserializeFromStr, SerializeDisplay};
use std::str::FromStr;
use strum_macros::{Display, EnumString};

#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Wireless {
    #[serde(rename = "ap-scan")]
    pub ap_scan: u32,
    #[serde(default)]
    #[serde(deserialize_with = "unwrap_wireless_networks")]
    pub networks: Option<Vec<Network>>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Network {
    pub essid: String,
    #[serde(rename = "scan-ssid")]
    pub scan_ssid: bool,
    pub mode: WickedWirelessMode,
    #[serde(rename = "wpa-psk")]
    pub wpa_psk: Option<WpaPsk>,
    #[serde(default)]
    #[serde(rename = "key-management")]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    pub key_management: Vec<String>,
    pub channel: Option<u32>,
    #[serde(rename = "access-point")]
    pub access_point: Option<String>,
    pub wep: Option<Wep>,
    #[serde(rename = "wpa-eap")]
    pub wpa_eap: Option<WpaEap>,
}

#[derive(Default, Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum WickedWirelessMode {
    AdHoc = 0,
    #[default]
    Infrastructure = 1,
    AP = 2,
}

impl From<&WickedWirelessMode> for model::WirelessMode {
    fn from(value: &WickedWirelessMode) -> Self {
        match value {
            WickedWirelessMode::AdHoc => model::WirelessMode::AdHoc,
            WickedWirelessMode::Infrastructure => model::WirelessMode::Infra,
            WickedWirelessMode::AP => model::WirelessMode::AP,
        }
    }
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct WpaPsk {
    pub passphrase: String,
    #[serde(rename = "auth-proto", skip_serializing_if = "Vec::is_empty", default)]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, EapAuthProto>")]
    pub auth_proto: Vec<EapAuthProto>,
    #[serde(
        rename = "pairwise-cipher",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, EapPairwiseCipher>")]
    pub pairwise_cipher: Vec<EapPairwiseCipher>,
    #[serde(
        rename = "group-cipher",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, EapGroupCipher>")]
    pub group_cipher: Vec<EapGroupCipher>,
    pub pmf: Option<Pmf>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Wep {
    #[serde(rename = "auth-algo")]
    pub auth_algo: String,
    #[serde(rename = "default-key")]
    pub default_key: u32,
    pub key: Vec<String>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct WpaEap {
    pub method: WickedEapMethods,
    pub identity: Option<String>,
    pub phase1: Option<Phase1>,
    pub phase2: Option<Phase2>,
    pub anonid: Option<String>,
    pub tls: Option<EapTLS>,
    #[serde(rename = "auth-proto", skip_serializing_if = "Vec::is_empty", default)]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, EapAuthProto>")]
    pub auth_proto: Vec<EapAuthProto>,
    #[serde(
        rename = "pairwise-cipher",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, EapPairwiseCipher>")]
    pub pairwise_cipher: Vec<EapPairwiseCipher>,
    #[serde(
        rename = "group-cipher",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, EapGroupCipher>")]
    pub group_cipher: Vec<EapGroupCipher>,
    pub pmf: Option<Pmf>,
}

impl TryFrom<&WpaEap> for model::IEEE8021XConfig {
    type Error = anyhow::Error;

    fn try_from(value: &WpaEap) -> Result<Self, Self::Error> {
        let eap: Vec<model::EAPMethod> = vec![value.method.try_into()?];
        let mut config = model::IEEE8021XConfig {
            eap,
            identity: value.identity.clone(),
            anonymous_identity: value.anonid.clone(),
            ..Default::default()
        };

        if let Some(phase1) = &value.phase1 {
            if let Some(peap_label) = phase1.peap_label {
                config.peap_label = peap_label;
            }
            if let Some(peap_version) = phase1.peap_version {
                config.peap_version = Some(peap_version.to_string());
            }
        }

        if let Some(phase2) = &value.phase2 {
            if let Some(method) = phase2.method {
                config.phase2_auth = Some(method.try_into()?);
            }
            if let Some(password) = &phase2.password {
                config.password = Some(password.to_string());
            }
        }

        if let Some(tls) = &value.tls {
            if let Some(ca_cert) = &tls.ca_cert {
                config.ca_cert = Some(wicked_cert_to_path(ca_cert)?);
            }
            if let Some(client_cert) = &tls.client_cert {
                config.client_cert = Some(wicked_cert_to_path(client_cert)?);
            }
            if let Some(client_key) = &tls.client_key {
                config.private_key = Some(wicked_cert_to_path(client_key)?);
            }
            config.private_key_password = tls.client_key_passwd.clone();
        }

        Ok(config)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase1 {
    #[serde(rename = "peap-version")]
    pub peap_version: Option<u32>,
    #[serde(rename = "peap-label")]
    pub peap_label: Option<bool>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase2 {
    pub method: Option<WickedEapMethods>,
    pub password: Option<String>,
}

#[derive(
    Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display, Clone, Copy,
)]
#[strum(serialize_all = "lowercase")]
pub enum Pmf {
    Disabled = 1,
    Optional = 2,
    Required = 3,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
pub enum EapAuthProto {
    Wpa,
    Rsn,
}

impl From<&EapAuthProto> for model::WPAProtocolVersion {
    fn from(value: &EapAuthProto) -> Self {
        match value {
            EapAuthProto::Wpa => Self::Wpa,
            EapAuthProto::Rsn => Self::Rsn,
        }
    }
}

#[derive(
    Debug,
    PartialEq,
    SerializeDisplay,
    DeserializeFromStr,
    EnumString,
    Display,
    Clone,
    Copy,
    Default,
)]
#[strum(serialize_all = "snake_case")]
pub enum WickedEapMethods {
    Wpa,
    #[default]
    None,
    Md5,
    Tls,
    Pap,
    Chap,
    Mschap,
    Mschapv2,
    Peap,
    Ttls,
    Gtc,
    Otp,
    Leap,
    Psk,
    Pax,
    Sake,
    Gpsk,
    Wsc,
    Ikev2,
    Tnc,
    Fast,
    Aka,
    AkaPrime,
    Sim,
}

impl TryFrom<WickedEapMethods> for model::EAPMethod {
    type Error = anyhow::Error;

    fn try_from(value: WickedEapMethods) -> Result<Self, Self::Error> {
        match value {
            WickedEapMethods::Leap => Ok(Self::LEAP),
            WickedEapMethods::Md5 => Ok(Self::MD5),
            WickedEapMethods::Tls => Ok(Self::TLS),
            WickedEapMethods::Peap => Ok(Self::PEAP),
            WickedEapMethods::Ttls => Ok(Self::TTLS),
            WickedEapMethods::Fast => Ok(Self::FAST),
            _ => Err(anyhow!("Invalid EAP (outer) method")),
        }
    }
}

impl TryFrom<WickedEapMethods> for model::Phase2AuthMethod {
    type Error = anyhow::Error;

    fn try_from(value: WickedEapMethods) -> Result<Self, Self::Error> {
        match value {
            WickedEapMethods::Pap => Ok(Self::PAP),
            WickedEapMethods::Chap => Ok(Self::CHAP),
            WickedEapMethods::Mschap => Ok(Self::MSCHAP),
            WickedEapMethods::Mschapv2 => Ok(Self::MSCHAPV2),
            WickedEapMethods::Gtc => Ok(Self::GTC),
            WickedEapMethods::Otp => Ok(Self::OTP),
            WickedEapMethods::Md5 => Ok(Self::MD5),
            WickedEapMethods::Tls => Ok(Self::TLS),
            _ => Err(anyhow!("Invalid phase 2 (inner) method")),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "SCREAMING-KEBAB-CASE")]
pub enum EapPairwiseCipher {
    Tkip,
    Ccmp,
    Ccmp_256,
    Gcmp,
    Gcmp_256,
}

impl TryFrom<&EapPairwiseCipher> for model::PairwiseAlgorithm {
    type Error = anyhow::Error;

    fn try_from(value: &EapPairwiseCipher) -> Result<Self, Self::Error> {
        match value {
            EapPairwiseCipher::Ccmp => Ok(Self::Ccmp),
            EapPairwiseCipher::Tkip => Ok(Self::Tkip),
            _ => Err(anyhow!("EAP pairwise chipher not supported, leaving empty")),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "SCREAMING-KEBAB-CASE")]
pub enum EapGroupCipher {
    Tkip,
    Ccmp,
    Ccmp_256,
    Gcmp,
    Gcmp_256,
    Wep104,
    Wep40,
}

impl TryFrom<&EapGroupCipher> for model::GroupAlgorithm {
    type Error = anyhow::Error;

    fn try_from(value: &EapGroupCipher) -> Result<Self, Self::Error> {
        match value {
            EapGroupCipher::Ccmp => Ok(Self::Ccmp),
            EapGroupCipher::Tkip => Ok(Self::Tkip),
            EapGroupCipher::Wep104 => Ok(Self::Wep104),
            EapGroupCipher::Wep40 => Ok(Self::Wep40),
            _ => Err(anyhow!("EAP group cipher not supported, leaving empty")),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EapTLS {
    #[serde(rename = "ca-cert")]
    pub ca_cert: Option<WickedCertificate>,
    #[serde(rename = "client-cert")]
    pub client_cert: Option<WickedCertificate>,
    #[serde(rename = "client-key")]
    pub client_key: Option<WickedCertificate>,
    #[serde(rename = "client-key-passwd")]
    pub client_key_passwd: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WickedCertificate {
    #[serde(rename = "$value")]
    pub cert: String,
    #[serde(rename = "@type")]
    pub cert_type: WickedCertType,
}

#[derive(Debug, PartialEq, SerializeDisplay, DeserializeFromStr, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum WickedCertType {
    Path,
    File,
    Hex,
}

fn wicked_cert_to_path(wicked_cert: &WickedCertificate) -> Result<String, anyhow::Error> {
    if wicked_cert.cert_type == WickedCertType::Hex {
        return Err(anyhow!("Hex certificate type is currently not supported"));
    } else if wicked_cert.cert_type == WickedCertType::File {
        log::info!("Certificate type 'file' may not work as intended");
    }
    Ok(wicked_cert.cert.clone())
}

fn common_settings_to_config(
    auth_protos: &[EapAuthProto],
    pairwise_ciphers: &[EapPairwiseCipher],
    group_ciphers: &[EapGroupCipher],
    pmf: &Option<Pmf>,
    config: &mut model::WirelessConfig,
) {
    config.wpa_protocol_versions = auth_protos
        .iter()
        .map(|x| x.into())
        .collect::<Vec<model::WPAProtocolVersion>>();

    let mut pairwise_algorithms: Vec<model::PairwiseAlgorithm> = vec![];
    for pairwise_cipher in pairwise_ciphers {
        match model::PairwiseAlgorithm::try_from(pairwise_cipher) {
            Ok(algo) => pairwise_algorithms.push(algo),
            Err(e) => {
                log::info!("{e}");
                pairwise_algorithms = vec![];
                break;
            }
        }
    }
    config.pairwise_algorithms = pairwise_algorithms;

    let mut group_algorithms: Vec<model::GroupAlgorithm> = vec![];
    for group_cipher in group_ciphers {
        match model::GroupAlgorithm::try_from(group_cipher) {
            Ok(algo) => group_algorithms.push(algo),
            Err(e) => {
                log::info!("{e}");
                group_algorithms = vec![];
                break;
            }
        }
    }
    config.group_algorithms = group_algorithms;

    if let Some(pmf) = pmf {
        config.pmf = *pmf as i32;
    }
}

fn unwrap_wireless_networks<'de, D>(deserializer: D) -> Result<Option<Vec<Network>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
    struct Networks {
        network: Vec<Network>,
    }
    Ok(Some(Networks::deserialize(deserializer)?.network))
}

fn all(array: &[String], needle: &[&str]) -> bool {
    if array.is_empty() {
        return false;
    }

    array.iter().all(|x| needle.iter().any(|&y| x == y))
}

fn any(array: &[String], needle: &[&str]) -> bool {
    if array.is_empty() {
        return false;
    }

    array.iter().any(|x| needle.iter().any(|&y| x == y))
}

fn guess_wireless_security_protocol(
    network: &Network,
) -> Result<model::SecurityProtocol, anyhow::Error> {
    let mgmt = &network.key_management;

    let result = if any(mgmt, &["wpa-eap", "wpa-eap-sha256"]) {
        model::SecurityProtocol::WPA2Enterprise
    } else if any(mgmt, &["wpa-eap-suite-b-192", "wpa-eap-suite-b"]) {
        model::SecurityProtocol::WPA3Only
    } else if any(mgmt, &["wpa-psk", "wpa-psk-sha256"]) {
        model::SecurityProtocol::WPA2
    } else if any(mgmt, &["sae", "ft-sae"]) {
        model::SecurityProtocol::WPA3Personal
    } else if any(mgmt, &["owe"]) {
        model::SecurityProtocol::OWE
    } else if any(mgmt, &["none"]) {
        model::SecurityProtocol::WEP
    } else if network.wpa_eap.is_some() {
        model::SecurityProtocol::WPA2Enterprise
    } else if network.wpa_psk.is_some() {
        model::SecurityProtocol::WPA2
    } else {
        model::SecurityProtocol::WEP
    };
    log::warn!(
        "Unsupported key-management protocol(s) '{}' guessing '{}'",
        mgmt.join(","),
        result
    );
    Ok(result)
}

fn wireless_security_protocol(network: &Network) -> Result<model::SecurityProtocol, anyhow::Error> {
    let mgmt = &network.key_management;

    if all(mgmt, &["sae", "ft-sae"]) {
        Ok(model::SecurityProtocol::WPA3Personal)
    } else if all(mgmt, &["wpa-psk", "wpa-psk-sha256", "sae", "ft-sae"]) {
        Ok(model::SecurityProtocol::WPA2)
    } else if all(mgmt, &["wpa-eap-suite-b-192", "wpa-eap-suite-b"]) {
        Ok(model::SecurityProtocol::WPA3Only)
    } else if all(
        mgmt,
        &[
            "wpa-eap",
            "wpa-eap-sha256",
            "wpa-eap-suite-b-192",
            "wpa-eap-suite-b",
        ],
    ) {
        Ok(model::SecurityProtocol::WPA2Enterprise)
    } else if all(mgmt, &["owe"]) {
        Ok(model::SecurityProtocol::OWE)
    } else if all(mgmt, &["none"]) {
        Ok(model::SecurityProtocol::WEP)
    } else if mgmt.is_empty() {
        if network.wpa_eap.is_some() {
            Ok(model::SecurityProtocol::WPA2Enterprise)
        } else if network.wpa_psk.is_some() {
            Ok(model::SecurityProtocol::WPA2)
        } else {
            Ok(model::SecurityProtocol::WEP)
        }
    } else {
        Err(anyhow!(
            "Unrecognized key-management protocol(s): {}",
            mgmt.join(",")
        ))
    }
}

impl TryFrom<&Network> for model::ConnectionConfig {
    type Error = anyhow::Error;

    fn try_from(network: &Network) -> Result<Self, Self::Error> {
        let settings = MIGRATION_SETTINGS.get().unwrap();
        let mut config = model::WirelessConfig {
            ssid: SSID(network.essid.as_bytes().to_vec()),
            hidden: network.scan_ssid,
            ..Default::default()
        };

        let mut sec = wireless_security_protocol(network);
        if sec.is_err() && settings.continue_migration {
            sec = guess_wireless_security_protocol(network);
        }
        config.security = sec?;

        if let Some(wpa_psk) = &network.wpa_psk {
            config.password = Some(wpa_psk.passphrase.clone());

            common_settings_to_config(
                &wpa_psk.auth_proto,
                &wpa_psk.pairwise_cipher,
                &wpa_psk.group_cipher,
                &wpa_psk.pmf,
                &mut config,
            );
        }
        if let Some(channel) = network.channel {
            config.channel = channel;
            if channel <= 14 {
                config.band = Some(model::WirelessBand::BG);
            } else {
                config.band = Some(model::WirelessBand::A);
            }
            log::warn!(
                "NetworkManager requires setting a band for wireless when a channel is set. The band has been set to \"{}\". This may in certain regions be incorrect.",
                config.band.unwrap()
            );
        }
        if let Some(access_point) = &network.access_point {
            config.bssid = Some(MacAddr6::from_str(access_point)?);
        }

        if let Some(wep) = &network.wep {
            // filter out `s:`, `h:`, `:`, and `-` of wep keys
            let keys: Vec<String> = wep
                .key
                .clone()
                .into_iter()
                .map(|mut x| {
                    x = x.replace("s:", "");
                    x = x.replace("h:", "");
                    x = x.replace(':', "");
                    x.replace('-', "")
                })
                .collect();
            let wep_security = WEPSecurity {
                auth_alg: WEPAuthAlg::try_from(wep.auth_algo.as_str())?,
                wep_key_type: WEPKeyType::Key,
                keys,
                wep_key_index: wep.default_key,
            };
            config.wep_security = Some(wep_security);
        }

        if let Some(wpa_eap) = &network.wpa_eap {
            common_settings_to_config(
                &wpa_eap.auth_proto,
                &wpa_eap.pairwise_cipher,
                &wpa_eap.group_cipher,
                &wpa_eap.pmf,
                &mut config,
            );
        }

        config.mode = (&network.mode).into();
        Ok(model::ConnectionConfig::Wireless(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::*;
    use crate::MIGRATION_SETTINGS;

    #[allow(dead_code)]
    fn setup_default_migration_settings() {
        let _ = MIGRATION_SETTINGS.set(crate::MigrationSettings {
            continue_migration: false,
            dry_run: false,
            activate_connections: true,
            with_netconfig: false,
            netconfig_path: "".to_string(),
            netconfig_dhcp_path: "".to_string(),
        });
    }

    #[test]
    fn test_wireless_bands() {
        setup_default_migration_settings();
        let mut wireless_interface = Interface {
            wireless: Some(Wireless {
                networks: Some(vec![Network {
                    channel: Some(0),
                    essid: "testssid".to_string(),
                    scan_ssid: false,
                    mode: WickedWirelessMode::AP,
                    wpa_psk: None,
                    key_management: vec!["wpa-psk".to_string()],
                    access_point: None,
                    wep: None,
                    wpa_eap: None,
                }]),
                ap_scan: 0,
            }),
            ..Default::default()
        };
        let connections = wireless_interface.to_connection(&None);
        assert!(connections.is_ok());
        let connection = &connections.unwrap().connections[0];
        let model::ConnectionConfig::Wireless(wireless) = &connection.config else {
            panic!()
        };
        assert_eq!(wireless.band, Some("bg".try_into().unwrap()));

        wireless_interface
            .wireless
            .as_mut()
            .unwrap()
            .networks
            .as_mut()
            .unwrap()[0]
            .channel = Some(32);
        let ifc = wireless_interface.to_connection(&None);
        assert!(ifc.is_ok());
        let ifc = &ifc.unwrap().connections[0];
        let model::ConnectionConfig::Wireless(wireless) = &ifc.config else {
            panic!()
        };
        assert_eq!(wireless.band, Some("a".try_into().unwrap()));
    }

    #[test]
    fn test_wireless_migration() {
        setup_default_migration_settings();
        let wireless_interface = Interface {
            wireless: Some(Wireless {
                networks: Some(vec![Network {
                    essid: "testssid".to_string(),
                    scan_ssid: true,
                    mode: WickedWirelessMode::Infrastructure,
                    wpa_psk: Some(WpaPsk {
                        passphrase: "testpassword".to_string(),
                        ..Default::default()
                    }),
                    key_management: vec!["wpa-psk".to_string()],
                    channel: Some(14),
                    access_point: Some("12:34:56:78:9A:BC".to_string()),
                    wep: Some(Wep {
                        auth_algo: "open".to_string(),
                        default_key: 1,
                        key: vec!["01020304ff".to_string(), "s:hello".to_string()],
                    }),
                    wpa_eap: None,
                }]),
                ap_scan: 0,
            }),
            ..Default::default()
        };
        let connections = wireless_interface.to_connection(&None);
        assert!(connections.is_ok());
        let connection = &connections.unwrap().connections[0];
        let model::ConnectionConfig::Wireless(wireless) = &connection.config else {
            panic!()
        };
        assert_eq!(wireless.ssid, SSID("testssid".as_bytes().to_vec()));
        assert!(wireless.hidden);
        assert_eq!(wireless.mode, model::WirelessMode::Infra);
        assert_eq!(wireless.password, Some("testpassword".to_string()));
        assert_eq!(wireless.security, model::SecurityProtocol::WPA2);
        assert_eq!(
            wireless.bssid,
            Some(MacAddr6::from_str("12:34:56:78:9A:BC").unwrap())
        );
        assert_eq!(
            wireless.wep_security,
            Some(WEPSecurity {
                auth_alg: WEPAuthAlg::Open,
                wep_key_type: WEPKeyType::Key,
                keys: vec!["01020304ff".to_string(), "hello".to_string()],
                wep_key_index: 1,
            })
        );
        assert_eq!(wireless.band, Some("bg".try_into().unwrap()));
    }

    #[test]
    fn wireless_security_protocol_strict() {
        setup_default_migration_settings();

        let mut net = Network {
            ..Default::default()
        };

        net.key_management = vec![];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WEP
        );

        net.key_management = vec![];
        net.wpa_eap = Some(WpaEap {
            ..Default::default()
        });

        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2Enterprise
        );

        net.wpa_eap = None;
        net.wpa_psk = Some(WpaPsk {
            ..Default::default()
        });
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2
        );

        net.wpa_psk = None;
        net.key_management = vec!["wpa-psk".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2
        );
        net.key_management = vec!["sae".to_string(), "wpa-psk".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2
        );
        net.key_management = vec!["sae".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA3Personal
        );

        net.key_management = vec!["wpa-eap".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2Enterprise
        );
        net.key_management = vec!["wpa-eap".to_string(), "wpa-eap-suite-b".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2Enterprise
        );
        net.key_management = vec!["wpa-eap-suite-b".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA3Only
        );

        net.key_management = vec!["owe".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::OWE
        );

        net.key_management = vec!["none".to_string()];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WEP
        );

        net.key_management = vec!["none".to_string(), "wpa-psk".to_string()];
        assert!(wireless_security_protocol(&net).is_err());
        net.key_management = vec!["wpa-eap".to_string(), "wpa-psk".to_string()];
        assert!(wireless_security_protocol(&net).is_err());
        net.key_management = vec!["wpa-eap".to_string(), "sae".to_string()];
        assert!(wireless_security_protocol(&net).is_err());
        net.key_management = vec!["wpa-eap-suite-b".to_string(), "sae".to_string()];
        assert!(wireless_security_protocol(&net).is_err());
        net.key_management = vec!["wpa-eap-suite-b".to_string(), "owe".to_string()];
        assert!(wireless_security_protocol(&net).is_err());
        net.key_management = vec!["wpa-psk".to_string(), "owe".to_string()];
        assert!(wireless_security_protocol(&net).is_err());
    }

    #[test]
    fn wireless_security_protocol_continue_migration() {
        setup_default_migration_settings();

        let mut net = Network {
            ..Default::default()
        };

        net.key_management = vec![];
        assert_eq!(
            wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WEP
        );

        net.key_management = vec![];
        net.wpa_eap = Some(WpaEap {
            ..Default::default()
        });

        net.key_management = vec!["none".to_string(), "wpa-psk".to_string()];
        assert_eq!(
            guess_wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2
        );
        net.key_management = vec!["wpa-eap".to_string(), "wpa-psk".to_string()];
        assert_eq!(
            guess_wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2Enterprise
        );
        net.key_management = vec!["wpa-eap".to_string(), "sae".to_string()];
        assert_eq!(
            guess_wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2Enterprise
        );
        net.key_management = vec!["wpa-eap-suite-b".to_string(), "sae".to_string()];
        assert_eq!(
            guess_wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA3Only
        );
        net.key_management = vec!["wpa-eap-suite-b".to_string(), "owe".to_string()];
        assert_eq!(
            guess_wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA3Only
        );
        net.key_management = vec!["wpa-psk".to_string(), "owe".to_string()];
        assert_eq!(
            guess_wireless_security_protocol(&net).unwrap(),
            model::SecurityProtocol::WPA2
        );
    }
}
