pub(crate) mod inspect;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum PkcsCommands {
    /// Inspect PKCS key from PEM file
    Inspect {
        #[command(flatten)]
        config: inspect::Config,
    },
}
