use std::str::FromStr;

use asn1::ASN1Object;
use clap::Args;
use der::Der;
use pem::Pem;
use pkix_types::OidName;
use tsumiki::decoder::Decoder;

use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::read_input;

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the certificate file (PEM or DER format). If not specified, reads from stdin
    file: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    output: OutputFormat,

    /// Show only subject
    #[arg(long)]
    show_subject: bool,

    /// Show only issuer
    #[arg(long)]
    show_issuer: bool,

    /// Show only validity dates
    #[arg(long)]
    show_dates: bool,

    /// Show only serial number
    #[arg(long)]
    show_serial: bool,

    /// List all extensions
    #[arg(long)]
    list_extensions: bool,

    /// Show algorithm information
    #[arg(long)]
    show_algorithms: bool,

    /// Show OID values instead of human-readable names
    #[arg(long)]
    show_oid: bool,
}

impl Config {
    fn should_show_specific_fields(&self) -> bool {
        self.show_subject
            || self.show_issuer
            || self.show_dates
            || self.show_serial
            || self.list_extensions
            || self.show_algorithms
    }
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read input
    let input_bytes = read_input(config.file.as_deref())?;

    // Try to parse as PEM first, fallback to DER
    let cert: x509::Certificate = if let Ok(contents) = String::from_utf8(input_bytes.clone()) {
        // Text data - try PEM first
        if let Ok(pem) = Pem::from_str(&contents) {
            // PEM format - decode directly
            pem.decode()?
        } else {
            // Not PEM, maybe UTF-8 encoded DER (unlikely but possible)
            // Try to parse as DER
            let der: Der = input_bytes.decode()?;
            let asn1_obj: ASN1Object = der.decode()?;
            asn1_obj.decode()?
        }
    } else {
        // Binary data - treat as DER
        let der: Der = input_bytes.decode()?;
        let asn1_obj: ASN1Object = der.decode()?;
        asn1_obj.decode()?
    };

    // Show specific fields if requested
    if config.should_show_specific_fields() {
        let tbs = cert.tbs_certificate();

        if config.show_subject {
            println!("Subject: {}", tbs.subject());
        }
        if config.show_issuer {
            println!("Issuer: {}", tbs.issuer());
        }
        if config.show_dates {
            let validity = tbs.validity();
            println!(
                "Not Before: {}",
                validity.not_before().format("%b %d %H:%M:%S %Y GMT")
            );
            println!(
                "Not After:  {}",
                validity.not_after().format("%b %d %H:%M:%S %Y GMT")
            );
        }
        if config.show_serial {
            println!("Serial Number: {}", tbs.serial_number().format_hex());
        }
        if config.list_extensions {
            if let Some(exts) = tbs.extensions() {
                println!("Extensions:");
                for ext in exts.extensions() {
                    let oid_str = ext.oid().to_string();
                    let name = ext.oid_name().unwrap_or(&oid_str);
                    let critical = if ext.critical() { " (critical)" } else { "" };
                    println!("  {} [{}]{}", name, ext.oid(), critical);
                }
            } else {
                println!("No extensions");
            }
        }
        if config.show_algorithms {
            let sig_alg = &tbs.signature();
            let sig_oid_str = sig_alg.algorithm.to_string();
            let sig_name = sig_alg.oid_name().unwrap_or(&sig_oid_str);
            println!("Signature Algorithm: {} ({})", sig_name, sig_alg.algorithm);

            let pubkey_alg = tbs.subject_public_key_info().algorithm();
            let pubkey_oid_str = pubkey_alg.algorithm.to_string();
            let pubkey_name = pubkey_alg.oid_name().unwrap_or(&pubkey_oid_str);
            println!(
                "Public Key Algorithm: {} ({})",
                pubkey_name, pubkey_alg.algorithm
            );
        }
        return Ok(());
    }

    // Full output

    // Set the OID display mode
    pkix_types::set_use_oid_values(config.show_oid);
    match config.output {
        OutputFormat::Text => {
            println!("{}", cert);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&cert)?;
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            // Convert to JSON value first, then to YAML
            let json_value = serde_json::to_value(&cert)?;
            let yaml = serde_yml::to_string(&json_value)?;
            print!("{}", yaml);
        }
    }

    Ok(())
}
