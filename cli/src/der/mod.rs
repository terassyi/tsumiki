pub(crate) mod decode;
pub(crate) mod dump;
pub(crate) mod encode;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum DerCommands {
    /// Decode PEM to DER format (output binary)
    Decode {
        #[command(flatten)]
        config: decode::Config,
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
