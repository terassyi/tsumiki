use super::Config;
use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::{calculate_fingerprint, format_hex_dump};
use pkix_types::OidName;
use std::fmt::Write;

pub(crate) fn output_ec_private_key(
    private_key: &pkcs::sec1::ECPrivateKey,
    config: &Config,
) -> Result<()> {
    // If --hex flag is set, output only HEX dump of raw private key bytes
    if config.hex {
        print!("{}", format_hex_dump(private_key.private_key.as_bytes()));
        return Ok(());
    }

    // Output based on format
    match config.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&private_key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&private_key)?);
        }
        OutputFormat::Text => {
            let mut output = String::new();

            writeln!(output, "EC Private Key (SEC1)")?;
            writeln!(output, "Version: {}", private_key.version as u8)?;

            if let Some(curve) = private_key.parameters {
                let curve_name = curve.oid_name().unwrap_or("unknown");
                if config.show_oid {
                    writeln!(output, "Curve: {} ({})", curve_name, curve.oid())?;
                } else {
                    writeln!(output, "Curve: {}", curve_name)?;
                }
            } else {
                writeln!(output, "Curve: (not specified)")?;
            }

            writeln!(
                output,
                "Private Key: {} bytes",
                private_key.private_key.as_bytes().len()
            )?;

            if let Some(ref pubkey) = private_key.public_key {
                writeln!(output, "Public Key: {} bits", pubkey.as_bytes().len() * 8)?;
            }

            if config.detailed {
                writeln!(output)?;
                writeln!(output, "Detailed Information:")?;
                writeln!(output, "---------------------")?;

                // Show curve OID if not already showing it
                if !config.show_oid {
                    if let Some(curve) = private_key.parameters {
                        writeln!(output, "Curve OID: {}", curve.oid())?;
                    }
                }

                // Show private key data preview (first 64 bytes)
                let key_data = private_key.private_key.as_bytes();
                writeln!(output, "Private Key Data Preview (first 64 bytes):")?;
                let preview_len = std::cmp::min(64, key_data.len());
                for (i, byte) in key_data[..preview_len].iter().enumerate() {
                    if i % 16 == 0 {
                        if i > 0 {
                            writeln!(output)?;
                        }
                        write!(output, "  {:04x}: ", i)?;
                    }
                    write!(output, "{:02x} ", byte)?;
                }
                if key_data.len() > 64 {
                    writeln!(output, "\n  ... ({} more bytes)", key_data.len() - 64)?;
                } else {
                    writeln!(output)?;
                }
            }

            print!("{}", output);
        }
        OutputFormat::Brief => {
            let curve_name = private_key
                .parameters
                .and_then(|c| c.oid_name())
                .unwrap_or("unknown");
            println!("EC Private Key | {}", curve_name);
        }
    }

    Ok(())
}

pub(crate) fn output_ec_private_key_fingerprint(
    private_key: &pkcs::sec1::ECPrivateKey,
    config: &Config,
) -> Result<()> {
    let fingerprint =
        calculate_fingerprint(private_key.private_key.as_bytes(), config.fingerprint_alg);
    println!("{}", fingerprint);
    Ok(())
}

pub(crate) fn output_ec_key_size(private_key: &pkcs::sec1::ECPrivateKey) -> String {
    let key_bits = private_key.private_key.as_bytes().len() * 8;
    format!("Key Size: {} bits", key_bits)
}
