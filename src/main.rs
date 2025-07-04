mod bond;
mod bridge;
mod infiniband;
mod interface;
mod migrate;
mod netconfig;
mod netconfig_dhcp;
mod reader;
mod tuntap;
mod vlan;
mod wireless;

use clap::builder::TypedValueParser;
use clap::{Args, Parser, Subcommand};
use log::*;
use migrate::migrate;
use reader::read as wicked_read;
use serde::Serialize;
use simplelog::ConfigBuilder;
use std::process::{ExitCode, Termination};
use tokio::sync::OnceCell;

use crate::interface::Interface;
use crate::netconfig::Netconfig;

#[derive(Parser)]
#[command(name = "wicked2nm", version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Args)]
struct GlobalOpts {
    #[arg(long, global = true, default_value_t = LevelFilter::Info, value_parser = clap::builder::PossibleValuesParser::new(["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]).map(|s| s.parse::<LevelFilter>().unwrap()),)]
    pub log_level: LevelFilter,

    #[arg(long, global = true, env = "W2NM_WITHOUT_NETCONFIG")]
    pub without_netconfig: bool,

    #[arg(long, global = true, default_value_t = String::from("/etc/sysconfig/network/config"), env = "W2NM_NETCONFIG_PATH")]
    pub netconfig_path: String,

    #[arg(long, global = true, default_value_t = String::from("/etc/sysconfig/network/dhcp"), env = "W2NM_NETCONFIG_DHCP_PATH")]
    pub netconfig_dhcp_path: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Shows the current xml wicked configuration
    Show {
        /// Format output
        #[arg(value_enum, short, long, default_value_t = Format::Json)]
        format: Format,

        /// Wicked XML files or directories where the wicked xml configs are located.
        /// Can also be "-" to read from stdin
        paths: Vec<String>,
    },
    /// Migrate wicked state at path
    Migrate {
        /// Wicked XML files or directories where the wicked xml configs are located.
        /// Can also be "-" to read from stdin
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
#[derive(clap::ValueEnum, Clone)]
pub enum Format {
    Json,
    PrettyJson,
    Yaml,
    Xml,
    Text,
}

async fn run_command(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Show { paths, format } => {
            MIGRATION_SETTINGS
                .set(MigrationSettings {
                    continue_migration: true,
                    dry_run: false,
                    activate_connections: true,
                    with_netconfig: !cli.global_opts.without_netconfig,
                    netconfig_path: cli.global_opts.netconfig_path,
                    netconfig_dhcp_path: cli.global_opts.netconfig_dhcp_path,
                })
                .expect("MIGRATION_SETTINGS was set too early");

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
        Commands::Migrate {
            paths,
            continue_migration,
            dry_run,
            activate_connections,
        } => {
            MIGRATION_SETTINGS
                .set(MigrationSettings {
                    continue_migration,
                    dry_run,
                    activate_connections,
                    with_netconfig: !cli.global_opts.without_netconfig,
                    netconfig_path: cli.global_opts.netconfig_path,
                    netconfig_dhcp_path: cli.global_opts.netconfig_dhcp_path,
                })
                .expect("MIGRATION_SETTINGS was set too early");

            log::debug!(
                "Running migration with MigrationSettings: {:#?}",
                MIGRATION_SETTINGS.get().unwrap()
            );

            let interfaces_result = wicked_read(paths)?;

            if !continue_migration && interfaces_result.warning.is_some() {
                return Err(interfaces_result.warning.unwrap());
            }

            match migrate(
                interfaces_result.interfaces,
                interfaces_result.netconfig,
                interfaces_result.netconfig_dhcp,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("Migration failed: {}", e)),
            }
        }
    }
}

/// Represents the result of execution.
pub enum CliResult {
    /// Successful execution.
    Ok = 0,
    /// Something went wrong.
    Error = 1,
}

impl Termination for CliResult {
    fn report(self) -> ExitCode {
        ExitCode::from(self as u8)
    }
}

#[derive(Debug)]
struct MigrationSettings {
    continue_migration: bool,
    dry_run: bool,
    activate_connections: bool,
    with_netconfig: bool,
    netconfig_path: String,
    netconfig_dhcp_path: String,
}

impl Default for MigrationSettings {
    fn default() -> Self {
        MigrationSettings {
            continue_migration: false,
            dry_run: false,
            activate_connections: true,
            with_netconfig: false,
            netconfig_path: "".to_string(),
            netconfig_dhcp_path: "".to_string(),
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

    if let Err(error) = run_command(cli).await {
        log::error!("{error}");
        return CliResult::Error;
    }

    CliResult::Ok
}
