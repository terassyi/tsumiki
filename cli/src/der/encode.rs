use clap::Args;
use pem::{Label, Pem};

use crate::error::Result;
use crate::utils::read_input;

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the DER file. If not specified, reads from stdin
    file: Option<String>,

    /// PEM label type (possible values: certificate, private-key, public-key)
    #[arg(short = 't', long, value_enum)]
    label_type: LabelType,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LabelType {
    Certificate,
    PrivateKey,
    PublicKey,
}

impl From<LabelType> for Label {
    fn from(label_type: LabelType) -> Self {
        match label_type {
            LabelType::Certificate => Label::Certificate,
            LabelType::PrivateKey => Label::PrivateKey,
            LabelType::PublicKey => Label::PublicKey,
        }
    }
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read DER bytes from input
    let der_bytes = read_input(config.file.as_deref())?;

    // Create PEM from DER bytes
    let label = Label::from(config.label_type);
    let pem = Pem::from_bytes(label, &der_bytes);

    // Output the PEM to stdout
    print!("{pem}");

    Ok(())
}
