use super::Config;
use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::{calculate_fingerprint, format_hex_dump};
use pkcs::pkcs9::ParsedAttributes;
use pkcs::{KeyAlgorithm, PrivateKeyExt, PublicKeyExt};
use pkix_types::OidName;
use pkix_types::algorithm::parameters::DsaParameters;
use std::fmt::Write;

fn write_algorithm_parameters(
    output: &mut String,
    elem: &asn1::Element,
    indent: usize,
) -> Result<()> {
    let prefix = " ".repeat(indent);
    match elem {
        asn1::Element::ObjectIdentifier(oid) => {
            writeln!(output, "{}OID: {}", prefix, oid)?;
        }
        asn1::Element::Sequence(elems) => {
            writeln!(output, "{}Sequence: {} elements", prefix, elems.len())?;
            for (i, e) in elems.iter().enumerate() {
                writeln!(output, "{}  [{}]:", prefix, i)?;
                write_algorithm_parameters(output, e, indent + 4)?;
            }
        }
        asn1::Element::Integer(int) => {
            writeln!(output, "{}Integer: {}", prefix, int.as_ref())?;
        }
        asn1::Element::OctetString(oct) => {
            writeln!(
                output,
                "{}OctetString: {} bytes",
                prefix,
                oct.as_ref().len()
            )?;
        }
        asn1::Element::BitString(bits) => {
            writeln!(
                output,
                "{}BitString: {} bits ({} unused)",
                prefix,
                bits.as_ref().len() * 8 - bits.unused_bits() as usize,
                bits.unused_bits()
            )?;
        }
        _ => {
            writeln!(output, "{}{:?}", prefix, elem)?;
        }
    }
    Ok(())
}

pub(crate) fn output_private_key_info(
    key: &pkcs::pkcs8::OneAsymmetricKey,
    config: &Config,
) -> Result<()> {
    // If --hex flag is set, output only HEX dump
    if config.hex {
        print!("{}", format_hex_dump(key.private_key.as_ref()));
        return Ok(());
    }

    let key_algorithm = key.algorithm();

    match config.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&key)?);
        }
        OutputFormat::Text => {
            let mut output = String::new();

            writeln!(output, "PKCS#8 Private Key (OneAsymmetricKey)")?;
            writeln!(output, "Version: {:?}", key.version)?;
            let alg_oid_str = key.private_key_algorithm.algorithm.to_string();
            let alg_name = key.private_key_algorithm.oid_name().unwrap_or(&alg_oid_str);
            let algorithm_display = if config.show_oid {
                &alg_oid_str
            } else {
                alg_name
            };
            writeln!(
                output,
                "Algorithm: {} ({})",
                algorithm_display,
                key_algorithm.name()
            )?;
            if let Some(params) = &key.private_key_algorithm.parameters {
                match params {
                    pkcs::pkcs8::AlgorithmParameters::Null => {
                        writeln!(output, "Algorithm Parameters: NULL")?;
                    }
                    pkcs::pkcs8::AlgorithmParameters::Other(raw) => {
                        writeln!(output, "Algorithm Parameters:")?;
                        write_algorithm_parameters(&mut output, raw.element(), 2)?;
                    }
                }
            }
            writeln!(
                output,
                "Private Key: {} bytes",
                key.private_key.as_ref().len()
            )?;
            if let Some(attributes) = &key.attributes {
                writeln!(output, "Attributes: {} items", attributes.len())?;
                let parsed = ParsedAttributes::from(attributes.attributes().as_ref());
                write!(output, "{}", parsed)?;
            }
            if let Some(public_key) = &key.public_key {
                writeln!(output, "Public Key: {} bits", public_key.as_ref().len() * 8)?;
            }

            if config.detailed {
                writeln!(output)?;
                writeln!(output, "Detailed Information:")?;
                writeln!(output, "---------------------")?;

                // Show algorithm OID if not already showing it
                if !config.show_oid {
                    writeln!(
                        output,
                        "Algorithm OID: {}",
                        key.private_key_algorithm.algorithm
                    )?;
                }

                // Show private key data preview (first 64 bytes)
                let key_data = key.private_key.as_ref();
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
            // Brief format for PKCS#8 private key
            let alg_oid_str = key.private_key_algorithm.algorithm.to_string();
            let alg_name = key.private_key_algorithm.oid_name().unwrap_or(&alg_oid_str);
            let algorithm_display = if config.show_oid {
                &alg_oid_str
            } else {
                alg_name
            };
            println!("PKCS#8 Private Key | {}", algorithm_display);
        }
    }

    Ok(())
}

pub(crate) fn output_encrypted_private_key_info(
    key: &pkcs::pkcs8::EncryptedPrivateKeyInfo,
    config: &Config,
) -> Result<()> {
    // If --hex flag is set, output only HEX dump
    if config.hex {
        print!("{}", format_hex_dump(key.encrypted_data.as_ref()));
        return Ok(());
    }

    match config.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&key)?);
        }
        OutputFormat::Text => {
            let mut output = String::new();
            writeln!(output, "PKCS#8 Encrypted Private Key")?;
            let enc_alg_oid_str = key.encryption_algorithm.algorithm.to_string();
            let alg_name = key
                .encryption_algorithm
                .oid_name()
                .unwrap_or(&enc_alg_oid_str);
            let algorithm_display = if config.show_oid {
                &enc_alg_oid_str
            } else {
                alg_name
            };
            writeln!(output, "Encryption Algorithm: {}", algorithm_display)?;
            if let Some(params) = &key.encryption_algorithm.parameters {
                match params {
                    pkcs::pkcs8::AlgorithmParameters::Null => {
                        writeln!(output, "Encryption Parameters: NULL")?;
                    }
                    pkcs::pkcs8::AlgorithmParameters::Other(_) => {
                        writeln!(output, "Encryption Parameters: Present (PBES2 scheme)")?;
                    }
                }
            }
            writeln!(
                output,
                "Encrypted Data: {} bytes",
                key.encrypted_data.as_ref().len()
            )?;

            if config.detailed {
                writeln!(output)?;
                writeln!(output, "Detailed Information:")?;
                writeln!(output, "---------------------")?;

                // Show encryption algorithm OID if not already showing it
                if !config.show_oid {
                    writeln!(
                        output,
                        "Encryption Algorithm OID: {}",
                        key.encryption_algorithm.algorithm
                    )?;
                }

                // Show encrypted data preview (first 64 bytes)
                let enc_data = key.encrypted_data.as_ref();
                writeln!(output, "Encrypted Data Preview (first 64 bytes):")?;
                let preview_len = std::cmp::min(64, enc_data.len());
                for (i, byte) in enc_data[..preview_len].iter().enumerate() {
                    if i % 16 == 0 {
                        if i > 0 {
                            writeln!(output)?;
                        }
                        write!(output, "  {:04x}: ", i)?;
                    }
                    write!(output, "{:02x} ", byte)?;
                }
                if enc_data.len() > 64 {
                    writeln!(output, "\n  ... ({} more bytes)", enc_data.len() - 64)?;
                } else {
                    writeln!(output)?;
                }
            }

            writeln!(output)?;
            writeln!(
                output,
                "Note: Decryption is not yet implemented. Use OpenSSL to decrypt:"
            )?;
            writeln!(output, "  openssl pkcs8 -in key.pem -out decrypted.pem")?;
            print!("{}", output);
        }
        OutputFormat::Brief => {
            // Brief format for encrypted PKCS#8 key
            let enc_alg_oid_str = key.encryption_algorithm.algorithm.to_string();
            if config.show_oid {
                println!("PKCS#8 Encrypted Private Key | {}", enc_alg_oid_str);
            } else {
                println!("PKCS#8 Encrypted Private Key");
            }
        }
    }

    Ok(())
}

fn output_dsa_parameters_to_string(
    key: &pkcs::pkcs8::PublicKey,
    output: &mut String,
) -> Result<()> {
    // Access SubjectPublicKeyInfo::algorithm() via AsRef to avoid conflict with PublicKeyExt::algorithm()
    let spki: &pkix_types::SubjectPublicKeyInfo = key.as_ref();
    if let Some(pkcs::pkcs8::AlgorithmParameters::Other(raw)) = spki.algorithm().parameters.as_ref()
    {
        if let Ok(dsa_params) = DsaParameters::try_from(raw) {
            writeln!(output, "  Prime (p): {} bits", dsa_params.p.bits())?;
            writeln!(output, "  Subprime (q): {} bits", dsa_params.q.bits())?;
            writeln!(output, "  Generator (g): {} bits", dsa_params.g.bits())?;
        }
    }
    Ok(())
}

pub(crate) fn output_public_key(key: &pkcs::pkcs8::PublicKey, config: &Config) -> Result<()> {
    let algorithm_oid = key.algorithm_oid().to_string();
    let algorithm_name = key.oid_name().unwrap_or("Unknown");
    let key_bits = key.key_bits();
    let key_algorithm = key.algorithm();
    let algorithm_display = if config.show_oid {
        &algorithm_oid
    } else {
        algorithm_name
    };

    // If --hex flag is set, output only HEX dump
    if config.hex {
        print!("{}", format_hex_dump(key.subject_public_key().as_ref()));
        return Ok(());
    }

    match config.output {
        OutputFormat::Json => {
            let json_obj = serde_json::json!({
                "algorithm": algorithm_display,
                "algorithm_type": key_algorithm.name(),
                "key_bits": key_bits,
            });
            println!("{}", serde_json::to_string_pretty(&json_obj)?);
        }
        OutputFormat::Yaml => {
            println!("algorithm: {}", algorithm_display);
            println!("algorithm_type: {}", key_algorithm.name());
            println!("key_bits: {}", key_bits);
        }
        OutputFormat::Text => {
            let mut output = String::new();
            writeln!(output, "Public Key Information")?;
            writeln!(output, "======================")?;
            writeln!(output, "Algorithm: {}", algorithm_display)?;
            writeln!(output, "Key Size: {} bits", key_bits)?;
            writeln!(output)?;

            writeln!(output, "Algorithm Details:")?;
            writeln!(output, "  Type: {}", key_algorithm.name())?;

            match key_algorithm {
                KeyAlgorithm::Rsa => {
                    writeln!(output, "  Key Size: {} bits", key.key_bits())?;
                }
                KeyAlgorithm::Ec => {
                    if let Ok(Some(curve_name)) = key.ec_curve_name() {
                        writeln!(output, "  Curve: {}", curve_name)?;
                    }
                }
                KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => {
                    // No additional details needed
                }
                KeyAlgorithm::Unknown | _ => {
                    // Check if DSA
                    if algorithm_oid == pkix_types::AlgorithmIdentifier::OID_ID_DSA {
                        output_dsa_parameters_to_string(key, &mut output)?;
                    }
                }
            }

            writeln!(output)?;
            writeln!(
                output,
                "Raw Key Data: {} bytes",
                key.subject_public_key().as_ref().len()
            )?;

            if config.detailed {
                writeln!(output)?;
                writeln!(output, "Detailed Information:")?;
                writeln!(output, "---------------------")?;

                // Show algorithm OID if not already showing it
                if !config.show_oid {
                    writeln!(output, "Algorithm OID: {}", algorithm_oid)?;
                }

                // Show raw key data in hex (limited to first 64 bytes for readability)
                let key_data = key.subject_public_key().as_ref();
                writeln!(output, "Key Data Preview (first 64 bytes):")?;
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
            println!(
                "Subject Public Key | {} | {} bits",
                algorithm_display, key_bits
            );
        }
    }

    Ok(())
}

pub(crate) fn output_public_key_fingerprint(
    key: &pkcs::pkcs8::PublicKey,
    config: &Config,
) -> Result<()> {
    let fingerprint =
        calculate_fingerprint(key.subject_public_key().as_ref(), config.fingerprint_alg);
    println!("{}", fingerprint);
    Ok(())
}

pub(crate) fn output_private_key_info_fingerprint(
    key: &pkcs::pkcs8::OneAsymmetricKey,
    config: &Config,
) -> Result<()> {
    let fingerprint = calculate_fingerprint(key.private_key.as_ref(), config.fingerprint_alg);
    println!("{}", fingerprint);
    Ok(())
}

pub(crate) fn output_encrypted_private_key_info_fingerprint(
    key: &pkcs::pkcs8::EncryptedPrivateKeyInfo,
    config: &Config,
) -> Result<()> {
    let fingerprint = calculate_fingerprint(key.encrypted_data.as_ref(), config.fingerprint_alg);
    println!("{}", fingerprint);
    Ok(())
}

pub(crate) fn output_private_key_size(key: &pkcs::pkcs8::OneAsymmetricKey) -> String {
    let key_size = key.key_size();
    if key_size == 0 {
        "Key (v1 key - size not available)".to_string()
    } else {
        format!("Key Size: {} bits", key_size)
    }
}

pub(crate) fn output_public_key_size(key: &pkcs::pkcs8::PublicKey) -> String {
    format!("Key Size: {} bits", key.key_size())
}
