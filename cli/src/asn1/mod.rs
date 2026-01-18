mod format;
pub(crate) mod inspect;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Asn1Commands {
    /// Inspect DER to ASN.1 structure
    Inspect {
        #[command(flatten)]
        config: inspect::Config,
    },
}
