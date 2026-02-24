mod bond;
mod bridge;
mod infiniband;
mod interface;
mod migrate;
mod netconfig;
mod netconfig_dhcp;
mod ovs;
mod reader;
mod tuntap;
mod vlan;
mod wireless;

use clap::builder::TypedValueParser;
use clap::{Args, Parser, Subcommand};
use log::*;
use migrate::{apply_networkstate, to_networkstate};
use reader::read as wicked_read;
use serde::Serialize;
use simplelog::ConfigBuilder;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};
use thiserror::Error;
use tokio::sync::OnceCell;

use crate::interface::Interface;
use crate::netconfig::Netconfig;

#[derive(Parser, Clone, Debug)]
#[command(name = "wicked2nm", version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Args, Clone)]
struct GlobalOpts {
    #[arg(long, global = true, default_value_t = LevelFilter::Info, value_parser = clap::builder::PossibleValuesParser::new(["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]).map(|s| s.parse::<LevelFilter>().unwrap()),)]
    pub log_level: LevelFilter,

    #[arg(long, global = true, env = "W2NM_WITHOUT_NETCONFIG")]
    pub without_netconfig: bool,

    /// Base directory for ifcfg, ifsysctl and netconfig configuration files.
    #[arg(
        long,
        global = true,
        default_value = "/etc/sysconfig/network/",
        env = "W2NM_NETCONFIG_BASE_DIR"
    )]
    pub netconfig_base_dir: PathBuf,

    /// Specify the path to the netconfig config file.
    /// If not set, defaults to $W2NM_NETCONFIG_BASE_DIR/config
    #[arg(long, global = true, env = "W2NM_NETCONFIG_PATH")]
    pub netconfig_path: Option<PathBuf>,

    /// Specify the path to the netconfig dhcp config file.
    /// If not set, defaults to $W2NM_NETCONFIG_BASE_DIR/dhcp
    #[arg(long, global = true, env = "W2NM_NETCONFIG_DHCP_PATH")]
    pub netconfig_dhcp_path: Option<PathBuf>,

    /// Disable user hints.
    #[arg(long, global = true, env = "W2NM_DISABLE_HINTS")]
    pub disable_hints: bool,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Shows the current xml wicked configuration
    Show {
        /// Format output
        #[arg(value_enum, short, long, default_value_t = Format::Json)]
        format: Format,

        /// Wicked XML files or directories where the wicked xml configs are located.
        /// Can also be "-" to read from stdin
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Migrate wicked state at path
    Migrate {
        /// Wicked XML files or directories where the wicked xml configs are located.
        /// Can also be "-" to read from stdin
        #[arg(required = true)]
        paths: Vec<String>,

        /// Continue migration if warnings are encountered
        #[arg(short, long, global = true, env = "W2NM_CONTINUE_MIGRATION")]
        continue_migration: bool,

        /// Run migration without sending connections to NetworkManager (can be run without NetworkManager installed)
        #[arg(long, global = true, env = "W2NM_DRY_RUN")]
        dry_run: bool,

        /// Activate connections that are marked as autostart immediately
        #[arg(long, global = true, env = "W2NM_ACTIVATE_CONNECTIONS")]
        activate_connections: bool,
    },
}

/// Supported output formats
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Format {
    Json,
    PrettyJson,
    Yaml,
    Xml,
    Text,
}

#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("Migration failed because of warnings")]
    Warnings,
    #[error("Show failed: {0}")]
    ShowError(anyhow::Error),
    #[error("Migration failed: {0}")]
    MigrationError(anyhow::Error),
}

async fn run_command(cli: Cli) -> Result<(), MigrationError> {
    let mut migration_settings = MigrationSettings {
        continue_migration: true,
        activate_connections: true,
        with_netconfig: !cli.global_opts.without_netconfig,
        netconfig_path: cli
            .global_opts
            .netconfig_path
            .unwrap_or_else(|| cli.global_opts.netconfig_base_dir.join("config")),
        netconfig_dhcp_path: cli
            .global_opts
            .netconfig_dhcp_path
            .unwrap_or_else(|| cli.global_opts.netconfig_base_dir.join("dhcp")),
        netconfig_base_dir: cli.global_opts.netconfig_base_dir,
    };

    match cli.command {
        Commands::Show { paths, format } => {
            MIGRATION_SETTINGS
                .set(migration_settings)
                .expect("MIGRATION_SETTINGS was set too early");
            show_command(paths, format).map_err(MigrationError::ShowError)
        }
        Commands::Migrate {
            paths,
            continue_migration,
            dry_run,
            activate_connections,
        } => {
            migration_settings.continue_migration = continue_migration;
            migration_settings.activate_connections = activate_connections;
            MIGRATION_SETTINGS
                .set(migration_settings)
                .expect("MIGRATION_SETTINGS was set too early");

            log::debug!(
                "Running migration with MigrationSettings: {:#?}",
                MIGRATION_SETTINGS.get().unwrap()
            );

            let interfaces_result = wicked_read(paths).map_err(MigrationError::MigrationError)?;
            let mut network_state_result =
                to_networkstate(&interfaces_result).map_err(MigrationError::MigrationError)?;

            if !continue_migration && network_state_result.has_warnings {
                return Err(MigrationError::Warnings);
            }

            if dry_run {
                for connection in network_state_result.network_state.connections {
                    log::debug!("{connection:#?}");
                }
                return Ok(());
            }

            match apply_networkstate(
                &mut network_state_result.network_state,
                interfaces_result.netconfig,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(e) => Err(MigrationError::MigrationError(e)),
            }
        }
    }
}

fn show_command(paths: Vec<String>, format: Format) -> anyhow::Result<()> {
    let interfaces_result = wicked_read(paths)?;

    #[derive(Debug, Serialize)]
    struct WickedConfig {
        interface: Vec<Interface>,
        netconfig: Option<Netconfig>,
    }
    let show_output = WickedConfig {
        interface: interfaces_result.interfaces,
        netconfig: interfaces_result.netconfig,
    };

    let output = match format {
        Format::Json => serde_json::to_string(&show_output)?,
        Format::PrettyJson => serde_json::to_string_pretty(&show_output)?,
        Format::Yaml => serde_yaml::to_string(&show_output)?,
        Format::Xml => quick_xml::se::to_string_with_root("wicked-config", &show_output)?,
        Format::Text => format!("{show_output:?}"),
    };
    println!("{output}");
    Ok(())
}

/// Represents the result of execution.
pub enum CliResult {
    /// Successful execution.
    Ok = 0,
    /// Something went wrong.
    Error = 1,
    /// Failed due to warnings.
    Warnings = 3,
}

impl Termination for CliResult {
    fn report(self) -> ExitCode {
        ExitCode::from(self as u8)
    }
}

#[derive(Debug)]
struct MigrationSettings {
    continue_migration: bool,
    activate_connections: bool,
    with_netconfig: bool,
    netconfig_base_dir: PathBuf,
    netconfig_path: PathBuf,
    netconfig_dhcp_path: PathBuf,
}

impl Default for MigrationSettings {
    fn default() -> Self {
        MigrationSettings {
            continue_migration: false,
            activate_connections: true,
            with_netconfig: false,
            netconfig_base_dir: PathBuf::default(),
            netconfig_path: PathBuf::default(),
            netconfig_dhcp_path: PathBuf::default(),
        }
    }
}

static MIGRATION_SETTINGS: OnceCell<MigrationSettings> = OnceCell::const_new();

#[tokio::main]
async fn main() -> CliResult {
    let cli = Cli::parse();

    let config = ConfigBuilder::new()
        .set_time_level(LevelFilter::Off)
        .add_filter_allow("wicked2nm".to_string())
        .build();

    simplelog::TermLogger::init(
        cli.global_opts.log_level,
        config,
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();

    if let Err(error) = run_command(cli.clone()).await {
        log::error!("{error}");
        match error {
            MigrationError::Warnings => {
                if !cli.global_opts.disable_hints {
                    log::info!("Use the `--continue-migration` flag to ignore warnings");
                }
                return CliResult::Warnings;
            }
            _ => {
                return CliResult::Error;
            }
        }
    }

    CliResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn test_show_without_paths_fails() {
        let result = Cli::try_parse_from(&["wicked2nm", "show"]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn test_migrate_without_paths_fails() {
        let result = Cli::try_parse_from(&["wicked2nm", "migrate"]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn test_show_with_paths_passes() {
        let result = Cli::try_parse_from(&["wicked2nm", "show", "some_file.xml"]);
        assert!(result.is_ok());
    }
}
