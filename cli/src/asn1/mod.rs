pub(crate) mod decode;
mod format;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Asn1Commands {
    /// Decode DER to ASN.1 structure
    Decode {
        #[command(flatten)]
        config: decode::Config,
    },
}
