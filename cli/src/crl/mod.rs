pub(crate) mod inspect;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum CrlCommands {
    /// Inspect and display a Certificate Revocation List (CRL)
    Inspect {
        #[command(flatten)]
        config: inspect::Config,
    },
}
