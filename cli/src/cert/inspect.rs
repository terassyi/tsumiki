use std::fmt::Write;
use std::str::FromStr;

use asn1::ASN1Object;
use chrono::Utc;
use clap::Args;
use der::Der;
use pem::Pem;
use pkix_types::OidName;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;
use x509::extensions::Extension;

use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::read_input;

#[derive(Clone, Copy, clap::ValueEnum, Debug)]
pub(crate) enum FingerprintAlgorithm {
    /// SHA1 fingerprint
    Sha1,
    /// SHA256 fingerprint (default)
    Sha256,
    /// SHA512 fingerprint
    Sha512,
}

impl std::fmt::Display for FingerprintAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FingerprintAlgorithm::Sha1 => write!(f, "SHA1"),
            FingerprintAlgorithm::Sha256 => write!(f, "SHA256"),
            FingerprintAlgorithm::Sha512 => write!(f, "SHA512"),
        }
    }
}

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

    /// Show SHA256 fingerprint
    #[arg(long)]
    show_fingerprint: bool,

    /// Check certificate expiry
    #[arg(long)]
    check_expiry: bool,

    /// Fingerprint algorithm (SHA1, SHA256, SHA512)
    #[arg(long, value_enum, default_value = "sha256")]
    fingerprint_alg: FingerprintAlgorithm,

    /// Show public key in PEM format
    #[arg(long)]
    show_pubkey: bool,

    /// Show certificate purposes (from Extended Key Usage extension)
    #[arg(long)]
    show_purposes: bool,
}

impl Config {
    fn should_show_specific_fields(&self) -> bool {
        self.show_subject
            || self.show_issuer
            || self.show_dates
            || self.show_serial
            || self.list_extensions
            || self.show_algorithms
            || self.show_fingerprint
            || self.check_expiry
            || self.show_pubkey
            || self.show_purposes
    }
}

fn calculate_fingerprint(data: &[u8], alg: FingerprintAlgorithm) -> String {
    let format_digest = |digest: &[u8]| {
        digest
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    };

    match alg {
        FingerprintAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            format_digest(&hasher.finalize())
        }
        FingerprintAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format_digest(&hasher.finalize())
        }
        FingerprintAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            format_digest(&hasher.finalize())
        }
    }
}

fn get_purpose_name(oid_str: &str) -> &'static str {
    match oid_str {
        x509::extensions::ExtendedKeyUsage::SERVER_AUTH => "Server Authentication",
        x509::extensions::ExtendedKeyUsage::CLIENT_AUTH => "Client Authentication",
        x509::extensions::ExtendedKeyUsage::CODE_SIGNING => "Code Signing",
        x509::extensions::ExtendedKeyUsage::EMAIL_PROTECTION => "Email Protection",
        x509::extensions::ExtendedKeyUsage::TIME_STAMPING => "Time Stamping",
        x509::extensions::ExtendedKeyUsage::OCSP_SIGNING => "OCSP Signing",
        _ => "Unknown",
    }
}

fn show_certificate_purposes(tbs: &x509::TBSCertificate) -> Result<()> {
    let mut output = String::new();

    if let Some(extensions) = tbs.extensions() {
        for ext in extensions.extensions() {
            if *ext.oid() == x509::extensions::ExtendedKeyUsage::OID {
                if let Ok(eku) = ext.parse::<x509::extensions::ExtendedKeyUsage>() {
                    writeln!(output, "Certificate Purposes:")?;
                    for purpose_oid in &eku.purposes {
                        let oid_str = purpose_oid.to_string();
                        let purpose_name = get_purpose_name(&oid_str);
                        writeln!(output, "  - {}", purpose_name)?;
                    }
                    print!("{}", output);
                    return Ok(());
                }
            }
        }
        writeln!(output, "No Extended Key Usage extension found")?;
    } else {
        writeln!(output, "No extensions in certificate")?;
    }
    print!("{}", output);
    Ok(())
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
        let mut output = String::new();

        if config.show_subject {
            writeln!(output, "Subject: {}", tbs.subject())?;
        }
        if config.show_issuer {
            writeln!(output, "Issuer: {}", tbs.issuer())?;
        }
        if config.show_dates {
            let validity = tbs.validity();
            writeln!(
                output,
                "Not Before: {}",
                validity.not_before().format("%b %d %H:%M:%S %Y GMT")
            )?;
            writeln!(
                output,
                "Not After: {}",
                validity.not_after().format("%b %d %H:%M:%S %Y GMT")
            )?;
        }
        if config.show_serial {
            writeln!(
                output,
                "Serial Number: {}",
                tbs.serial_number().format_hex()
            )?;
        }
        if config.list_extensions {
            if let Some(exts) = tbs.extensions() {
                writeln!(output, "Extensions:")?;
                for ext in exts.extensions() {
                    let oid_str = ext.oid().to_string();
                    let name = ext.oid_name().unwrap_or(&oid_str);
                    let critical = if ext.critical() { " (critical)" } else { "" };
                    writeln!(output, "  {} [{}]{}", name, ext.oid(), critical)?;
                }
            } else {
                writeln!(output, "No extensions")?;
            }
        }
        if config.show_algorithms {
            let sig_alg = &tbs.signature();
            let sig_oid_str = sig_alg.algorithm.to_string();
            let sig_name = sig_alg.oid_name().unwrap_or(&sig_oid_str);
            writeln!(
                output,
                "Signature Algorithm: {} ({})",
                sig_name, sig_alg.algorithm
            )?;

            let pubkey_alg = tbs.subject_public_key_info().algorithm();
            let pubkey_oid_str = pubkey_alg.algorithm.to_string();
            let pubkey_name = pubkey_alg.oid_name().unwrap_or(&pubkey_oid_str);
            writeln!(
                output,
                "Public Key Algorithm: {} ({})",
                pubkey_name, pubkey_alg.algorithm
            )?;
        }
        if config.show_fingerprint {
            // Get the original DER bytes and calculate fingerprint
            let asn1_obj: asn1::ASN1Object = cert.encode()?;
            let der: Der = asn1_obj.encode()?;
            let cert_der = der.encode()?;
            let fingerprint = calculate_fingerprint(&cert_der, config.fingerprint_alg);
            writeln!(
                output,
                "{} Fingerprint: {}",
                config.fingerprint_alg, fingerprint
            )?;
        }
        if config.check_expiry {
            let validity = tbs.validity();
            let not_after = validity.not_after();
            let now = Utc::now().naive_utc();

            if now > *not_after {
                writeln!(
                    output,
                    "Certificate is EXPIRED (expired on {})",
                    not_after.format("%Y-%m-%d %H:%M:%S UTC")
                )?;
                print!("{}", output);
                std::process::exit(1);
            } else {
                writeln!(
                    output,
                    "Certificate is VALID (expires on {})",
                    not_after.format("%Y-%m-%d %H:%M:%S UTC")
                )?;
            }
        }
        if config.show_pubkey {
            // Output public key in PEM format
            let spki = tbs.subject_public_key_info();
            let pubkey_bytes = spki.subject_public_key().as_bytes();

            // Create PEM from public key bytes
            let pem = Pem::from_bytes(pem::Label::PublicKey, pubkey_bytes);
            write!(output, "{}", pem)?;
        }
        if config.show_purposes {
            print!("{}", output);
            show_certificate_purposes(tbs)?;
            return Ok(());
        }
        print!("{}", output);
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
        OutputFormat::Brief => {
            // Brief one-line format: CN=example.com | Valid: 2024-01-01 to 2025-01-01
            let tbs = cert.tbs_certificate();
            let subject = tbs.subject();
            let validity = tbs.validity();
            let not_before = validity.not_before().format("%Y-%m-%d").to_string();
            let not_after = validity.not_after().format("%Y-%m-%d").to_string();
            println!("{} | Valid: {} to {}", subject, not_before, not_after);
        }
    }

    Ok(())
}
