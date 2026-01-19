use crate::error::Result;
use crate::output::OutputFormat;
use pkcs::pkcs9::ParsedAttributes;
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
