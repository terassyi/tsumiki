use crate::error::Result;
use crate::output::OutputFormat;

pub(crate) fn output_rsa_private_key(
    private_key: &pkcs::pkcs1::RSAPrivateKey,
    format: OutputFormat,
    show_oid: bool,
) -> Result<()> {
    // Output based on format
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&private_key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&private_key)?);
        }
        OutputFormat::Text => {
            println!("RSA Private Key (PKCS#1)");
            println!("Version: {:?}", private_key.version);
            println!("Modulus (n): {} bits", private_key.modulus.bits());
            println!(
                "Public Exponent (e): {}",
                private_key
                    .public_exponent
                    .to_u64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| format!("{} bits", private_key.public_exponent.bits()))
            );
            println!(
                "Private Exponent (d): {} bits",
                private_key.private_exponent.bits()
            );
            println!("Prime 1 (p): {} bits", private_key.prime1.bits());
            println!("Prime 2 (q): {} bits", private_key.prime2.bits());
            println!(
                "Exponent 1 (d mod (p-1)): {} bits",
                private_key.exponent1.bits()
            );
            println!(
                "Exponent 2 (d mod (q-1)): {} bits",
                private_key.exponent2.bits()
            );
            println!(
                "Coefficient (q^-1 mod p): {} bits",
                private_key.coefficient.bits()
            );
        }
        OutputFormat::Brief => {
            // Brief format for RSA private key
            println!("RSA Private Key | {} bits", private_key.modulus.bits());
        }
    }

    Ok(())
}

pub(crate) fn output_rsa_public_key(
    public_key: &pkcs::pkcs1::RSAPublicKey,
    format: OutputFormat,
    show_oid: bool,
) -> Result<()> {
    // Output based on format
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&public_key)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&public_key)?);
        }
        OutputFormat::Text => {
            println!("RSA Public Key (PKCS#1)");
            println!("Modulus (n): {} bits", public_key.modulus.bits());
            println!(
                "Public Exponent (e): {}",
                public_key
                    .public_exponent
                    .to_u64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| format!("{} bits", public_key.public_exponent.bits()))
            );
        }
        OutputFormat::Brief => {
            // Brief format for RSA public key
            println!("RSA Public Key | {} bits", public_key.modulus.bits());
        }
    }

    Ok(())
}
