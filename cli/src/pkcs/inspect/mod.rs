pub(crate) mod pkcs1;
pub(crate) mod pkcs8;
pub(crate) mod sec1;

use clap::Args;
use pem::Label;
use pem::Pem;
use pem::ToPem;
use std::str::FromStr;

use crate::error::Result;
use crate::inspect::decode;
use crate::output::OutputFormat;
use crate::utils::{FingerprintAlgorithm, read_input};
use pkcs::PrivateKeyExt;
use pkcs::pkcs1::RSAPrivateKey;
use pkcs::pkcs8::OneAsymmetricKey;
use pkcs::pkcs8::PublicKey;
use pkcs::sec1::ECPrivateKey;

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

    /// Show public key from private key (PEM format)
    #[arg(long)]
    pub(crate) show_pubkey: bool,

    /// Show key size information (RSA bit length, EC curve, etc.)
    #[arg(long)]
    pub(crate) show_key_size: bool,
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read input to determine PEM label
    let input_bytes = read_input(config.file.as_deref())?;
    let contents = String::from_utf8(input_bytes)?;

    // Parse PEM to check label
    let pem = Pem::from_str(&contents)?;

    // If show_pubkey is set, show and output public key
    if config.show_pubkey {
        return match pem.label() {
            Label::RSAPrivateKey => {
                let key: RSAPrivateKey = decode(pem)?;
                let pub_key = key.public_key().ok_or_else(|| {
                    crate::error::Error::PublicKeyExtraction("RSA private key".to_string())
                })?;
                let pem = pub_key.to_pem()?;
                print!("{}", pem);
                Ok(())
            }
            Label::PrivateKey => {
                let key: OneAsymmetricKey = decode(pem)?;
                let pub_key = key.public_key().ok_or_else(|| {
                    crate::error::Error::PublicKeyExtraction(
                        "v1 PKCS#8 key (no public key field)".to_string(),
                    )
                })?;
                let pem = pub_key.to_pem()?;
                print!("{}", pem);
                Ok(())
            }
            Label::ECPrivateKey => {
                let key: ECPrivateKey = decode(pem)?;
                let pub_key = key.public_key().ok_or_else(|| {
                    crate::error::Error::PublicKeyExtraction(
                        "SEC1 key (missing public key or curve parameters)".to_string(),
                    )
                })?;
                let pem = pub_key.to_pem()?;
                print!("{}", pem);
                Ok(())
            }
            _ => Err(crate::error::Error::PublicKeyExtraction(
                "unsupported key format (only RSA-PKCS#1, PKCS#8, or SEC1)".to_string(),
            )),
        };
    }

    // If show_fingerprint is set, only display fingerprint
    if config.show_fingerprint {
        return match pem.label() {
            Label::RSAPrivateKey => {
                let key = decode(pem)?;
                pkcs1::output_rsa_private_key_fingerprint(&key, &config)
            }
            Label::RSAPublicKey => {
                let key = decode(pem)?;
                pkcs1::output_rsa_public_key_fingerprint(&key, &config)
            }
            Label::PrivateKey => {
                let key = decode(pem)?;
                pkcs8::output_private_key_info_fingerprint(&key, &config)
            }
            Label::EncryptedPrivateKey => {
                let key = decode(pem)?;
                pkcs8::output_encrypted_private_key_info_fingerprint(&key, &config)
            }
            Label::PublicKey => {
                let key: PublicKey = decode(pem)?;
                pkcs8::output_public_key_fingerprint(&key, &config)
            }
            Label::ECPrivateKey => {
                let key = decode(pem)?;
                sec1::output_ec_private_key_fingerprint(&key, &config)
            }
            _ => Err(format!("Unsupported PEM label: {}", pem.label()).into()),
        };
    }

    // If show_key_size is set, display key size information
    if config.show_key_size {
        return match pem.label() {
            Label::RSAPrivateKey => {
                let key: RSAPrivateKey = decode(pem)?;
                let output = pkcs1::output_rsa_key_size(&key);
                println!("{}", output);
                Ok(())
            }
            Label::RSAPublicKey => {
                let key: pkcs::pkcs1::RSAPublicKey = decode(pem)?;
                let output = pkcs1::output_rsa_public_key_size(&key);
                println!("{}", output);
                Ok(())
            }
            Label::PrivateKey => {
                let key: OneAsymmetricKey = decode(pem)?;
                let output = pkcs8::output_private_key_size(&key);
                println!("{}", output);
                Ok(())
            }
            Label::PublicKey => {
                let key: PublicKey = decode(pem)?;
                let output = pkcs8::output_public_key_size(&key);
                println!("{}", output);
                Ok(())
            }
            Label::ECPrivateKey => {
                let key: ECPrivateKey = decode(pem)?;
                let output = sec1::output_ec_key_size(&key);
                println!("{}", output);
                Ok(())
            }
            _ => Err(format!("Cannot determine key size for: {}", pem.label()).into()),
        };
    }

    // Dispatch based on PEM label
    match pem.label() {
        Label::RSAPrivateKey => {
            let key = decode(pem)?;
            pkcs1::output_rsa_private_key(&key, &config)
        }
        Label::RSAPublicKey => {
            let key = decode(pem)?;
            pkcs1::output_rsa_public_key(&key, &config)
        }
        Label::PrivateKey => {
            let key = decode(pem)?;
            pkcs8::output_private_key_info(&key, &config)
        }
        Label::EncryptedPrivateKey => {
            let key = decode(pem)?;
            pkcs8::output_encrypted_private_key_info(&key, &config)
        }
        Label::PublicKey => {
            let key: PublicKey = decode(pem)?;
            pkcs8::output_public_key(&key, &config)
        }
        Label::ECPrivateKey => {
            let key = decode(pem)?;
            sec1::output_ec_private_key(&key, &config)
        }
        _ => Err(format!("Unsupported PEM label: {}", pem.label()).into()),
    }
}
