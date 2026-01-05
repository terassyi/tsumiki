pub mod decode;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum CertCommands {
    /// Decode and display a certificate
    Decode {
        #[command(flatten)]
        config: decode::Config,
    },
}
