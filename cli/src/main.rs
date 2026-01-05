use clap::{Parser, Subcommand};

mod cert;
mod error;
mod format;

use error::Result;

use cert::CertCommands;

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Cert { command } => match command {
            CertCommands::Decode { config } => {
                cert::decode::execute(config)?;
            }
        },
    }

    Ok(())
}
