pub(crate) mod pkcs1;
pub(crate) mod pkcs8;

use clap::Args;
use pem::Pem;
use std::str::FromStr;

use crate::error::Result;
use crate::inspect::decode;
use crate::output::OutputFormat;
use crate::utils::read_input;

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the PEM file. If not specified, reads from stdin
    file: Option<String>,

    /// Output format (json, yaml, text)
    #[arg(short, long, default_value = "text")]
    output: OutputFormat,
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read input to determine PEM label
    let input_bytes = read_input(config.file.as_deref())?;
    let contents = String::from_utf8(input_bytes)?;

    // Parse PEM to check label
    let pem = Pem::from_str(&contents)?;

    // Dispatch based on PEM label
    match pem.label() {
        pem::Label::RSAPrivateKey => {
            let key = decode(pem)?;
            pkcs1::output_rsa_private_key(&key, config.output)
        }
        pem::Label::RSAPublicKey => {
            let key = decode(pem)?;
            pkcs1::output_rsa_public_key(&key, config.output)
        }
        pem::Label::PrivateKey => {
            let key = decode(pem)?;
            pkcs8::output_private_key_info(&key, config.output)
        }
        pem::Label::EncryptedPrivateKey => {
            let key = decode(pem)?;
            pkcs8::output_encrypted_private_key_info(&key, config.output)
        }
        _ => Err(format!("Unsupported PEM label: {}", pem.label()).into()),
    }
}
