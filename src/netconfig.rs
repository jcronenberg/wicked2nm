use agama_network::NetworkState;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::Path, str::FromStr};

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Netconfig {
    pub static_dns_servers: Option<Vec<String>>,
    pub static_dns_searchlist: Option<Vec<String>>,
    pub dns_policy: Vec<String>,
}

impl Netconfig {
    pub fn static_dns_servers(&self) -> Result<Vec<IpAddr>, std::net::AddrParseError> {
        if let Some(static_dns_servers) = &self.static_dns_servers {
            static_dns_servers
                .iter()
                .map(|x| IpAddr::from_str(x))
                .collect()
        } else {
            Ok(vec![])
        }
    }
}

pub fn read_netconfig(path: impl AsRef<Path>) -> Result<Option<Netconfig>, anyhow::Error> {
    if let Err(e) = dotenv::from_filename(path) {
        return Err(e.into());
    };
    handle_netconfig_values()
}

fn handle_netconfig_values() -> Result<Option<Netconfig>, anyhow::Error> {
    let mut netconfig = Netconfig::default();
    if let Ok(dns_policy) = dotenv::var("NETCONFIG_DNS_POLICY") {
        if dns_policy == "auto" {
            netconfig.dns_policy = vec!["STATIC".to_string(), ".*".to_string()];
        } else if !dns_policy.is_empty() {
            let dns_policy = dns_policy.replace("?", "[0-9]");
            let dns_policy = dns_policy.replace("*", ".*");
            netconfig.dns_policy = dns_policy.split(' ').map(|s| s.to_string()).collect();
            if netconfig
                .dns_policy
                .contains(&"STATIC_FALLBACK".to_string())
            {
                anyhow::bail!("NETCONFIG_DNS_POLICY \"STATIC_FALLBACK\" is not supported");
            }
        }
    }
    if let Ok(static_dns_servers) = dotenv::var("NETCONFIG_DNS_STATIC_SERVERS") {
        if !static_dns_servers.is_empty() {
            netconfig.static_dns_servers = Some(
                static_dns_servers
                    .split(' ')
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            );
        }
    }
    if let Ok(static_dns_searchlist) = dotenv::var("NETCONFIG_DNS_STATIC_SEARCHLIST") {
        if !static_dns_searchlist.is_empty() {
            netconfig.static_dns_searchlist = Some(
                static_dns_searchlist
                    .split(' ')
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            );
        }
    }
    Ok(Some(netconfig))
}

pub fn apply_dns_policy(
    netconfig: &Netconfig,
    nm_state: &mut NetworkState,
) -> Result<(), anyhow::Error> {
    // Start at 1 because 0 is special global default in NM
    let mut i: i32 = 1;
    for policy in &netconfig.dns_policy {
        match policy.as_str() {
            "" => continue,
            "STATIC" => {
                let mut loopback = match nm_state.get_connection("lo") {
                    Some(lo) => lo.clone(),
                    None => anyhow::bail!("Failed to get loopback connection"),
                };
                loopback.ip_config.dns_priority4 = Some(i);
                loopback.ip_config.dns_priority6 = Some(i);
                nm_state.update_connection(loopback)?;
            }
            _ => {
                let re = Regex::new(&format!("^{policy}$"))?;
                for con in nm_state
                    .connections
                    .iter()
                    .map(|c| c.id.clone())
                    .filter(|c_id| re.is_match(c_id))
                    .collect::<Vec<String>>()
                {
                    let mut con = match nm_state.get_connection(&con) {
                        Some(con) => con.clone(),
                        None => anyhow::bail!("Failed to get connection from state: {}", con),
                    };
                    // If con was already matched its priority should not be overwritten
                    if con.ip_config.dns_priority4.is_some()
                        && con.ip_config.dns_priority6.is_some()
                    {
                        continue;
                    }
                    con.ip_config.dns_priority4 = Some(i);
                    con.ip_config.dns_priority6 = Some(i);
                    nm_state.update_connection(con)?;
                }
            }
        }

        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_handle_netconfig_values() {
        env::set_var("NETCONFIG_DNS_POLICY", "STATIC_FALLBACK NetworkManager");
        assert!(handle_netconfig_values().is_err());

        env::set_var("NETCONFIG_DNS_POLICY", "STATIC_FALLBACK");
        assert!(handle_netconfig_values().is_err());

        env::set_var("NETCONFIG_DNS_POLICY", "");
        env::set_var(
            "NETCONFIG_DNS_STATIC_SERVERS",
            "192.168.0.10 192.168.1.10 2001:db8::10",
        );
        env::set_var("NETCONFIG_DNS_STATIC_SEARCHLIST", "suse.com suse.de");
        assert!(handle_netconfig_values()
            .unwrap()
            .unwrap()
            .dns_policy
            .is_empty());

        env::set_var("NETCONFIG_DNS_POLICY", "STATIC");
        assert_eq!(
            handle_netconfig_values().unwrap(),
            Some(Netconfig {
                static_dns_servers: Some(vec![
                    "192.168.0.10".to_string(),
                    "192.168.1.10".to_string(),
                    "2001:db8::10".to_string()
                ]),
                static_dns_searchlist: Some(vec!["suse.com".to_string(), "suse.de".to_string()]),
                dns_policy: vec!["STATIC".to_string()]
            })
        );

        env::set_var("NETCONFIG_DNS_POLICY", "");
        env::set_var("NETCONFIG_DNS_STATIC_SERVERS", "");
        env::set_var("NETCONFIG_DNS_STATIC_SEARCHLIST", "");
        assert_eq!(
            handle_netconfig_values().unwrap(),
            Some(Netconfig {
                static_dns_servers: None,
                static_dns_searchlist: None,
                ..Default::default()
            })
        );

        env::set_var("NETCONFIG_DNS_POLICY", "auto");
        assert_eq!(
            handle_netconfig_values().unwrap().unwrap().dns_policy,
            vec!["STATIC".to_string(), ".*".to_string(),]
        );

        env::set_var("NETCONFIG_DNS_POLICY", "STATIC eth* ppp?");
        assert_eq!(
            handle_netconfig_values().unwrap().unwrap().dns_policy,
            vec![
                "STATIC".to_string(),
                "eth.*".to_string(),
                "ppp[0-9]".to_string()
            ]
        );
    }
}
