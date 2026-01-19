pub(crate) mod pkcs1;
pub(crate) mod pkcs8;

use clap::Args;
use pem::Pem;
use std::str::FromStr;

use crate::error::Result;
use crate::inspect::decode;
use crate::output::OutputFormat;
use crate::utils::{FingerprintAlgorithm, read_input};

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the PEM file. If not specified, reads from stdin
    pub(crate) file: Option<String>,

    /// Output format (json, yaml, text)
    #[arg(short, long, default_value = "text")]
    pub(crate) output: OutputFormat,

    /// Show OID instead of name
    #[arg(long)]
    pub(crate) show_oid: bool,

    /// Show fingerprint
    #[arg(long)]
    pub(crate) show_fingerprint: bool,

    /// Fingerprint algorithm (SHA1, SHA256, SHA512)
    #[arg(long, value_enum, default_value = "sha256")]
    pub(crate) fingerprint_alg: FingerprintAlgorithm,

    /// Show detailed information
    #[arg(long)]
    pub(crate) detailed: bool,

    /// Show HEX dump of the key data
    #[arg(long)]
    pub(crate) hex: bool,
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read input to determine PEM label
    let input_bytes = read_input(config.file.as_deref())?;
    let contents = String::from_utf8(input_bytes)?;

    // Parse PEM to check label
    let pem = Pem::from_str(&contents)?;

    // If show_fingerprint is set, only display fingerprint
    if config.show_fingerprint {
        return match pem.label() {
            pem::Label::RSAPrivateKey => {
                let key = decode(pem)?;
                pkcs1::output_rsa_private_key_fingerprint(&key, &config)
            }
            pem::Label::RSAPublicKey => {
                let key = decode(pem)?;
                pkcs1::output_rsa_public_key_fingerprint(&key, &config)
            }
            pem::Label::PrivateKey => {
                let key = decode(pem)?;
                pkcs8::output_private_key_info_fingerprint(&key, &config)
            }
            pem::Label::EncryptedPrivateKey => {
                let key = decode(pem)?;
                pkcs8::output_encrypted_private_key_info_fingerprint(&key, &config)
            }
            pem::Label::PublicKey => {
                let key: pkcs::pkcs8::PublicKey = decode(pem)?;
                pkcs8::output_public_key_fingerprint(&key, &config)
            }
            _ => Err(format!("Unsupported PEM label: {}", pem.label()).into()),
        };
    }

    // Dispatch based on PEM label
    match pem.label() {
        pem::Label::RSAPrivateKey => {
            let key = decode(pem)?;
            pkcs1::output_rsa_private_key(&key, &config)
        }
        pem::Label::RSAPublicKey => {
            let key = decode(pem)?;
            pkcs1::output_rsa_public_key(&key, &config)
        }
        pem::Label::PrivateKey => {
            let key = decode(pem)?;
            pkcs8::output_private_key_info(&key, &config)
        }
        pem::Label::EncryptedPrivateKey => {
            let key = decode(pem)?;
            pkcs8::output_encrypted_private_key_info(&key, &config)
        }
        pem::Label::PublicKey => {
            let key: pkcs::pkcs8::PublicKey = decode(pem)?;
            pkcs8::output_public_key(&key, &config)
        }
        _ => Err(format!("Unsupported PEM label: {}", pem.label()).into()),
    }
}
