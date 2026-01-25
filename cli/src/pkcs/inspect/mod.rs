pub(crate) mod pkcs1;
pub(crate) mod pkcs8;
pub(crate) mod sec1;

use clap::Args;
use std::str::FromStr;
use tsumiki_pem::Label;
use tsumiki_pem::Pem;
use tsumiki_pem::ToPem;

use crate::error::Result;
use crate::inspect::decode;
use crate::output::OutputFormat;
use crate::utils::{FingerprintAlgorithm, read_input};
use tsumiki::decoder::Decoder;
use tsumiki_pkcs::PrivateKey;
use tsumiki_pkcs::PublicKey;

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
        let key: PrivateKey = pem
            .decode()
            .map_err(|_| crate::error::Error::UnsupportedKeyFormat)?;
        let pub_key = key.public_key().ok_or_else(|| {
            crate::error::Error::PublicKeyExtractionFailed(key.algorithm().to_string())
        })?;
        let pem = pub_key.to_pem()?;
        print!("{}", pem);
        return Ok(());
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
                let key: tsumiki_pkcs::pkcs8::PublicKey = decode(pem)?;
                pkcs8::output_public_key_fingerprint(&key, &config)
            }
            Label::ECPrivateKey => {
                let key = decode(pem)?;
                sec1::output_ec_private_key_fingerprint(&key, &config)
            }
            _ => Err(crate::error::Error::UnsupportedPemLabel(
                pem.label().to_string(),
            )),
        };
    }

    // If show_key_size is set, display key size information
    if config.show_key_size {
        return match pem.label() {
            Label::RSAPrivateKey | Label::PrivateKey | Label::ECPrivateKey => {
                let key: PrivateKey = pem.decode().map_err(|e: tsumiki_pkcs::Error| {
                    crate::error::Error::PrivateKeyDecodeFailed(e.to_string())
                })?;
                let key_size = key.key_size();
                if key_size == 0 {
                    println!("Key Size: unknown (v1 PKCS#8 key)");
                } else {
                    println!("Key Size: {} bits", key_size);
                }
                Ok(())
            }
            Label::RSAPublicKey | Label::PublicKey => {
                let key: PublicKey = pem.decode().map_err(|e: tsumiki_pkcs::Error| {
                    crate::error::Error::PublicKeyDecodeFailed(e.to_string())
                })?;
                println!("Key Size: {} bits", key.key_size());
                Ok(())
            }
            _ => Err(crate::error::Error::CannotDetermineKeySize(
                pem.label().to_string(),
            )),
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
            let key: tsumiki_pkcs::pkcs8::PublicKey = decode(pem)?;
            pkcs8::output_public_key(&key, &config)
        }
        Label::ECPrivateKey => {
            let key = decode(pem)?;
            sec1::output_ec_private_key(&key, &config)
        }
        _ => Err(crate::error::Error::UnsupportedPemLabel(
            pem.label().to_string(),
        )),
    }
}
