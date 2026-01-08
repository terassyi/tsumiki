use clap::{Parser, Subcommand};

mod asn1;
mod cert;
mod decode;
mod der;
mod error;
mod output;
mod pkcs;
mod utils;

use error::Result;

use asn1::Asn1Commands;
use cert::CertCommands;
use der::DerCommands;
use pkcs::PkcsCommands;

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
    /// ASN.1 operations
    Asn1 {
        #[command(subcommand)]
        command: Asn1Commands,
    },
    /// PKCS operations
    Pkcs {
        #[command(subcommand)]
        command: PkcsCommands,
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
            DerCommands::Dump { config } => {
                der::dump::execute(config)?;
            }
            DerCommands::Encode { config } => {
                der::encode::execute(config)?;
            }
        },
        Commands::Asn1 { command } => match command {
            Asn1Commands::Decode { config } => {
                asn1::decode::execute(config)?;
            }
        },
        Commands::Pkcs { command } => match command {
            PkcsCommands::Decode { config } => {
                pkcs::decode::execute(config)?;
            }
        },
    }

    Ok(())
}
