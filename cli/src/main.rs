use clap::{Parser, Subcommand};

mod cert;
mod der;
mod error;
mod format;
mod utils;

use error::Result;

use cert::CertCommands;
use der::DerCommands;

#[derive(Parser)]
#[command(name = "tsumiki")]
#[command(about = "X.509 certificate and ASN.1 toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Certificate operations
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },
    /// DER encoding operations
    Der {
        #[command(subcommand)]
        command: DerCommands,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Cert { command } => match command {
            CertCommands::Decode { config } => {
                cert::decode::execute(config)?;
            }
        },
        Commands::Der { command } => match command {
            DerCommands::Decode { config } => {
                der::decode::execute(config)?;
            }
        },
    }

    Ok(())
}
