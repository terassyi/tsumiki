pub(crate) mod dump;
pub(crate) mod encode;
pub(crate) mod inspect;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum DerCommands {
    /// Inspect PEM to DER format (output binary)
    Inspect {
        #[command(flatten)]
        config: inspect::Config,
    },
    /// Display hexadecimal dump of DER file
    Dump {
        #[command(flatten)]
        config: dump::Config,
    },
    /// Encode DER to PEM format (output text)
    Encode {
        #[command(flatten)]
        config: encode::Config,
    },
}
