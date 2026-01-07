pub mod decode;
pub mod encode;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum DerCommands {
    /// Decode PEM to DER format (output binary)
    Decode {
        #[command(flatten)]
        config: decode::Config,
    },
    /// Encode DER to PEM format (output text)
    Encode {
        #[command(flatten)]
        config: encode::Config,
    },
}
