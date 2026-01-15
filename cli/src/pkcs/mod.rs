pub(crate) mod decode;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum PkcsCommands {
    /// Decode PKCS key from PEM file
    Decode {
        #[command(flatten)]
        config: decode::Config,
    },
}
