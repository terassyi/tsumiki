pub mod decode;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum DerCommands {
    /// Decode and display DER-encoded data
    Decode {
        #[command(flatten)]
        config: decode::Config,
    },
}
