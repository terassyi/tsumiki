use crate::error::Result;
use crate::output::OutputFormat;
use pkcs::pkcs8::{OID_ED25519, OID_ED448};
use pkcs::pkcs9::ParsedAttributes;
use pkix_types::algorithm::parameters::DsaParameters;
use pkix_types::OidName;

fn print_algorithm_parameters(elem: &asn1::Element, indent: usize) {
    let prefix = " ".repeat(indent);
    match elem {
        asn1::Element::ObjectIdentifier(oid) => {
            println!("{}OID: {}", prefix, oid);
        }
        asn1::Element::Sequence(elems) => {
            println!("{}Sequence: {} elements", prefix, elems.len());
            for (i, e) in elems.iter().enumerate() {
                println!("{}  [{}]:", prefix, i);
                print_algorithm_parameters(e, indent + 4);
            }
        }
        asn1::Element::Integer(int) => {
            // BigInt doesn't have a simple byte length, so just display it
            println!("{}Integer: {}", prefix, int.as_ref());
        }
        asn1::Element::OctetString(oct) => {
            println!("{}OctetString: {} bytes", prefix, oct.as_ref().len());
        }
        asn1::Element::BitString(bits) => {
            println!(
                "{}BitString: {} bits ({} unused)",
                prefix,
                bits.as_ref().len() * 8 - bits.unused_bits() as usize,
                bits.unused_bits()
            );
        }
        _ => {
            println!("{}{:?}", prefix, elem);
        }
    }
}

pub(crate) fn output_private_key_info(
    key: &pkcs::pkcs8::OneAsymmetricKey,
    format: OutputFormat,
    show_oid: bool,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&key)?);
        }
        OutputFormat::Text => {
            println!("PKCS#8 Private Key (OneAsymmetricKey)");
            println!("Version: {:?}", key.version);
            let alg_oid_str = key.private_key_algorithm.algorithm.to_string();
            let alg_name = key.private_key_algorithm.oid_name().unwrap_or(&alg_oid_str);
            println!(
                "Algorithm: {} ({})",
                alg_name, key.private_key_algorithm.algorithm
            );
            if let Some(params) = &key.private_key_algorithm.parameters {
                match params {
                    pkcs::pkcs8::AlgorithmParameters::Null => {
                        println!("Algorithm Parameters: NULL");
                    }
                    pkcs::pkcs8::AlgorithmParameters::Other(raw) => {
                        println!("Algorithm Parameters:");
                        print_algorithm_parameters(raw.element(), 2);
                    }
                }
            }
            println!("Private Key: {} bytes", key.private_key.as_ref().len());
            if let Some(attributes) = &key.attributes {
                println!("Attributes: {} items", attributes.len());
                let parsed = ParsedAttributes::from(attributes.attributes().as_ref());
                print!("{}", parsed);
            }
            if let Some(public_key) = &key.public_key {
                println!("Public Key: {} bits", public_key.as_ref().len() * 8);
            }
        }
        OutputFormat::Brief => {
            // Brief format for PKCS#8 private key
            let alg_oid_str = key.private_key_algorithm.algorithm.to_string();
            let alg_name = key.private_key_algorithm.oid_name().unwrap_or(&alg_oid_str);
            println!("PKCS#8 Private Key | {}", alg_name);
        }
    }

    Ok(())
}

pub(crate) fn output_encrypted_private_key_info(
    key: &pkcs::pkcs8::EncryptedPrivateKeyInfo,
    format: OutputFormat,
    show_oid: bool,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&key)?);
        }
        OutputFormat::Text => {
            println!("PKCS#8 Encrypted Private Key");
            let enc_alg_oid_str = key.encryption_algorithm.algorithm.to_string();
            let alg_name = key
                .encryption_algorithm
                .oid_name()
                .unwrap_or(&enc_alg_oid_str);
            println!(
                "Encryption Algorithm: {} ({})",
                alg_name, key.encryption_algorithm.algorithm
            );
            if let Some(params) = &key.encryption_algorithm.parameters {
                match params {
                    pkcs::pkcs8::AlgorithmParameters::Null => {
                        println!("Encryption Parameters: NULL");
                    }
                    pkcs::pkcs8::AlgorithmParameters::Other(_) => {
                        println!("Encryption Parameters: Present (PBES2 scheme)");
                    }
                }
            }
            println!(
                "Encrypted Data: {} bytes",
                key.encrypted_data.as_ref().len()
            );
            println!("\nNote: Decryption is not yet implemented. Use OpenSSL to decrypt:");
            println!("  openssl pkcs8 -in key.pem -out decrypted.pem");
        }
        OutputFormat::Brief => {
            // Brief format for encrypted PKCS#8 key
            println!("PKCS#8 Encrypted Private Key");
        }
    }

    Ok(())
}

fn output_algorithm_details(key: &pkcs::pkcs8::PublicKey, algorithm_oid: &str) -> Result<()> {
    match algorithm_oid {
        pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION => {
            println!("Algorithm Details:");
            println!("  Type: RSA");
            println!("  Key Size: {} bits", key.key_bits());
        }
        pkix_types::AlgorithmIdentifier::OID_ID_DSA => {
            println!("Algorithm Details:");
            println!("  Type: DSA");
            output_dsa_parameters(key)?;
        }
        pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY => {
            println!("Algorithm Details:");
            println!("  Type: EC");
            if let Ok(Some(curve_name)) = key.ec_curve_name() {
                println!("  Curve: {}", curve_name);
            }
        }
        OID_ED25519 => {
            println!("Algorithm Details:");
            println!("  Type: Ed25519");
        }
        OID_ED448 => {
            println!("Algorithm Details:");
            println!("  Type: Ed448");
        }
        _ => {
            println!("Algorithm Details: Unknown algorithm");
        }
    }
    Ok(())
}

fn output_dsa_parameters(key: &pkcs::pkcs8::PublicKey) -> Result<()> {
    if let Some(params) = key.algorithm().parameters.as_ref() {
        if let pkcs::pkcs8::AlgorithmParameters::Other(raw) = params {
            if let Ok(dsa_params) = DsaParameters::try_from(raw) {
                println!("  Prime (p): {} bits", dsa_params.p.bits());
                println!("  Subprime (q): {} bits", dsa_params.q.bits());
                println!("  Generator (g): {} bits", dsa_params.g.bits());
            }
        }
    }
    Ok(())
}

pub(crate) fn output_public_key(
    key: &pkcs::pkcs8::PublicKey,
    format: OutputFormat,
    show_oid: bool,
) -> Result<()> {
    let algorithm_oid = key.algorithm_oid().to_string();
    let algorithm_name = key.oid_name().unwrap_or("Unknown");
    let key_bits = key.key_bits();
    let algorithm_display = if show_oid { &algorithm_oid } else { algorithm_name };

    match format {
        OutputFormat::Json => {
            let json_obj = serde_json::json!({
                "algorithm": algorithm_display,
                "key_bits": key_bits,
            });
            println!("{}", serde_json::to_string_pretty(&json_obj)?);
        }
        OutputFormat::Yaml => {
            if show_oid {
                println!("algorithm: {}", algorithm_oid);
            } else {
                println!("algorithm: {}", algorithm_name);
                println!("algorithm_oid: {}", algorithm_oid);
            }
            println!("key_bits: {}", key_bits);
        }
        OutputFormat::Text => {
            println!("Public Key Information");
            println!("======================");
            println!("Algorithm: {}", algorithm_display);
            println!("Key Size: {} bits", key_bits);
            println!();

            output_algorithm_details(key, &algorithm_oid)?;

            println!();
            println!("Raw Key Data: {} bytes", key.subject_public_key().as_ref().len());
        }
        OutputFormat::Brief => {
            println!("Subject Public Key | {} | {} bits", algorithm_display, key_bits);
        }
    }

    Ok(())
}

