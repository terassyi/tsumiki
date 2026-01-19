use super::Config;
use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::{calculate_fingerprint, format_hex_dump};
use std::fmt::Write;
use tsumiki::encoder::Encoder;

pub(crate) fn output_rsa_private_key(
    private_key: &pkcs::pkcs1::RSAPrivateKey,
    config: &Config,
) -> Result<()> {
    // If --hex flag is set, output only HEX dump
    if config.hex {
        if let Ok(asn1_obj) = private_key.encode() {
            if let Ok(der) = asn1_obj.encode() {
                if let Ok(der_bytes) = der.encode() {
                    print!("{}", format_hex_dump(&der_bytes));
                }
            }
        }
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

            writeln!(output, "RSA Private Key (PKCS#1)")?;
            writeln!(output, "Version: {:?}", private_key.version)?;
            writeln!(output, "Modulus (n): {} bits", private_key.modulus.bits())?;
            writeln!(
                output,
                "Public Exponent (e): {}",
                private_key
                    .public_exponent
                    .to_u64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| format!("{} bits", private_key.public_exponent.bits()))
            )?;
            writeln!(
                output,
                "Private Exponent (d): {} bits",
                private_key.private_exponent.bits()
            )?;
            writeln!(output, "Prime 1 (p): {} bits", private_key.prime1.bits())?;
            writeln!(output, "Prime 2 (q): {} bits", private_key.prime2.bits())?;
            writeln!(
                output,
                "Exponent 1 (d mod (p-1)): {} bits",
                private_key.exponent1.bits()
            )?;
            writeln!(
                output,
                "Exponent 2 (d mod (q-1)): {} bits",
                private_key.exponent2.bits()
            )?;
            writeln!(
                output,
                "Coefficient (q^-1 mod p): {} bits",
                private_key.coefficient.bits()
            )?;

            if config.detailed {
                writeln!(output)?;
                writeln!(output, "Detailed Information:")?;
                writeln!(output, "---------------------")?;

                writeln!(output, "Component Sizes:")?;
                writeln!(
                    output,
                    "  Modulus (n): {} bytes",
                    private_key.modulus.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Public Exponent (e): {} bytes",
                    private_key.public_exponent.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Private Exponent (d): {} bytes",
                    private_key.private_exponent.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Prime 1 (p): {} bytes",
                    private_key.prime1.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Prime 2 (q): {} bytes",
                    private_key.prime2.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Exponent 1: {} bytes",
                    private_key.exponent1.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Exponent 2: {} bytes",
                    private_key.exponent2.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Coefficient: {} bytes",
                    private_key.coefficient.bits().div_ceil(8)
                )?;
            }

            print!("{}", output);
        }
        OutputFormat::Brief => {
            println!("RSA Private Key | {} bits", private_key.modulus.bits());
        }
    }

    Ok(())
}

pub(crate) fn output_rsa_public_key(
    public_key: &pkcs::pkcs1::RSAPublicKey,
    config: &Config,
) -> Result<()> {
    // If --hex flag is set, output only HEX dump
    if config.hex {
        if let Ok(asn1_obj) = public_key.encode() {
            if let Ok(der) = asn1_obj.encode() {
                if let Ok(der_bytes) = der.encode() {
                    print!("{}", format_hex_dump(&der_bytes));
                }
            }
        }
        return Ok(());
    }

    // Output based on format
    match config.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&public_key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&public_key)?);
        }
        OutputFormat::Text => {
            let mut output = String::new();

            writeln!(output, "RSA Public Key (PKCS#1)")?;
            writeln!(output, "Modulus (n): {} bits", public_key.modulus.bits())?;
            writeln!(
                output,
                "Public Exponent (e): {}",
                public_key
                    .public_exponent
                    .to_u64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| format!("{} bits", public_key.public_exponent.bits()))
            )?;

            if config.detailed {
                writeln!(output)?;
                writeln!(output, "Detailed Information:")?;
                writeln!(output, "---------------------")?;

                writeln!(output, "Component Sizes:")?;
                writeln!(
                    output,
                    "  Modulus (n): {} bytes",
                    public_key.modulus.bits().div_ceil(8)
                )?;
                writeln!(
                    output,
                    "  Public Exponent (e): {} bytes",
                    public_key.public_exponent.bits().div_ceil(8)
                )?;
            }

            print!("{}", output);
        }
        OutputFormat::Brief => {
            // Brief format for RSA public key
            println!("RSA Public Key | {} bits", public_key.modulus.bits());
        }
    }

    Ok(())
}

pub(crate) fn output_rsa_private_key_fingerprint(
    private_key: &pkcs::pkcs1::RSAPrivateKey,
    config: &Config,
) -> Result<()> {
    if let Ok(asn1_obj) = private_key.encode() {
        if let Ok(der) = asn1_obj.encode() {
            if let Ok(der_bytes) = der.encode() {
                let fingerprint = calculate_fingerprint(&der_bytes, config.fingerprint_alg);
                println!("{}", fingerprint);
            }
        }
    }
    Ok(())
}

pub(crate) fn output_rsa_public_key_fingerprint(
    public_key: &pkcs::pkcs1::RSAPublicKey,
    config: &Config,
) -> Result<()> {
    if let Ok(asn1_obj) = public_key.encode() {
        if let Ok(der) = asn1_obj.encode() {
            if let Ok(der_bytes) = der.encode() {
                let fingerprint = calculate_fingerprint(&der_bytes, config.fingerprint_alg);
                println!("{}", fingerprint);
            }
        }
    }
    Ok(())
}
