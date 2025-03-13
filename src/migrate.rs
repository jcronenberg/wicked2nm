use crate::interface::Interface;
use crate::netconfig::Netconfig;
use crate::MIGRATION_SETTINGS;
use agama_server::network::model::{Connection, GeneralState, IpConfig, MatchConfig, StateConfig};
use agama_server::network::{model, Adapter, NetworkManagerAdapter, NetworkState};
use cidr::IpInet;
use std::str::FromStr;
use std::{collections::HashMap, error::Error};
use uuid::Uuid;

fn update_parent_connection(
    connections: &mut [Connection],
    parents: HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    let settings = MIGRATION_SETTINGS.get().unwrap();
    let mut parent_uuid: HashMap<String, Uuid> = HashMap::new();

    for (id, parent) in parents {
        if let Some(parent_con) = connections
            .iter()
            .find(|c| c.interface.as_deref() == Some(&parent))
        {
            parent_uuid.insert(id, parent_con.uuid);
        } else {
            log::warn!("Missing parent {} connection for {}", parent, id);
            if !settings.continue_migration {
                return Err(anyhow::anyhow!("Migration of {} failed", id));
            }
        }
    }

    for (id, uuid) in parent_uuid {
        if let Some(connection) = connections
            .iter_mut()
            .find(|c| c.interface.as_deref() == Some(&id))
        {
            connection.controller = Some(uuid);
        } else {
            return Err(anyhow::anyhow!(
                "Unexpected failure - missing connection {}",
                id
            ));
        }
    }

    Ok(())
}

fn create_lo_connection() -> Connection {
    Connection {
        id: "lo".to_string(),
        ip_config: IpConfig {
            method4: model::Ipv4Method::Manual,
            method6: model::Ipv6Method::Manual,
            addresses: vec![
                IpInet::from_str("127.0.0.1/8").unwrap(),
                IpInet::from_str("::1/128").unwrap(),
            ],
            ..Default::default()
        },
        interface: Some("lo".to_string()),
        match_config: MatchConfig::default(),
        config: model::ConnectionConfig::Loopback,
        ..Default::default()
    }
}

pub async fn migrate(
    interfaces: Vec<Interface>,
    netconfig: Option<Netconfig>,
) -> Result<(), Box<dyn Error>> {
    let settings = MIGRATION_SETTINGS.get().unwrap();
    let mut parents: HashMap<String, String> = HashMap::new();
    let mut connections: Vec<Connection> = vec![];

    for interface in interfaces {
        let connection_result = interface.to_connection()?;
        if !connection_result.warnings.is_empty() {
            for connection_error in &connection_result.warnings {
                log::warn!("{}", connection_error);
            }
            if !settings.continue_migration {
                return Err(anyhow::anyhow!(
                    "Migration of {} failed",
                    connection_result.connections[0].id
                )
                .into());
            }
        }

        for connection in connection_result.connections {
            if let Some(parent) = &interface.link.master {
                parents.insert(connection.id.clone(), parent.clone());
            }
            connections.push(connection);
        }
    }

    update_parent_connection(&mut connections, parents)?;

    let mut state = NetworkState::new(GeneralState::default(), vec![], vec![], vec![]);
    for connection in &connections {
        state.add_connection(connection.clone())?;
    }

    if settings.dry_run {
        for connection in state.connections {
            log::debug!("{:#?}", connection);
        }
        return Ok(());
    }
    let nm = NetworkManagerAdapter::from_system().await?;

    if let Some(netconfig) = netconfig {
        let current_state = nm.read(StateConfig::default()).await?;
        let mut loopback = match current_state.get_connection("lo") {
            Some(lo) => lo.clone(),
            None => create_lo_connection(),
        };
        loopback.ip_config.nameservers = match netconfig.static_dns_servers() {
            Ok(nameservers) => nameservers,
            Err(e) => {
                let error = anyhow::anyhow!("Error when parsing static DNS servers: {}", e);
                if !settings.continue_migration {
                    return Err(error.into());
                } else {
                    log::warn!("{}", error);
                    vec![]
                }
            }
        };
        if let Some(static_dns_searchlist) = netconfig.static_dns_searchlist {
            loopback.ip_config.dns_searchlist = static_dns_searchlist;
        }

        for con in state.connections.iter_mut() {
            con.ip_config.ignore_auto_dns = true;
        }

        state.add_connection(loopback)?;
    }

    nm.write(&state).await?;
    Ok(())
}
