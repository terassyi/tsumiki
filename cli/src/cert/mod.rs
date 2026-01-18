pub(crate) mod inspect;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum CertCommands {
    /// Inspect and display a certificate
    Inspect {
        #[command(flatten)]
        config: inspect::Config,
    },
}
