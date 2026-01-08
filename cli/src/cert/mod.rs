pub(crate) mod decode;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum CertCommands {
    /// Decode and display a certificate
    Decode {
        #[command(flatten)]
        config: decode::Config,
    },
}
