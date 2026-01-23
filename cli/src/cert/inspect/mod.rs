mod tls;
mod verifier;

use std::fmt::Write;

use asn1::ASN1Object;
use chrono::Utc;
use clap::Args;
use pem::ToPem;
use pkcs::pkcs8::PublicKey;
use pkix_types::OidName;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;
use x509::extensions::{Extension, GeneralName, IpAddressOrRange, SubjectAltName};
use x509::{Certificate, CertificateChain};

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

    /// Fetch certificate from remote TLS server (e.g., "example.com" or "example.com:443")
    #[arg(long)]
    remote: Option<String>,

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

    /// Show Subject Alternative Names (SAN)
    #[arg(long)]
    show_san: bool,

    /// Check if certificate is self-signed
    #[arg(long)]
    check_self_signed: bool,

    /// Show only the first certificate in the chain
    #[arg(long, short = '1', conflicts_with_all = ["index", "depth"])]
    first: bool,

    /// Show only the certificate at the specified index (0-indexed)
    #[arg(long, conflicts_with_all = ["first", "depth"])]
    index: Option<usize>,

    /// Show only the first N certificates in the chain
    #[arg(long, conflicts_with_all = ["first", "index"])]
    depth: Option<usize>,

    /// Show only the root certificate (self-signed) if present
    #[arg(long, conflicts_with_all = ["first", "index", "depth"])]
    root: bool,

    /// Hide certificate index headers (--- Certificate N ---)
    #[arg(long)]
    no_header: bool,
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
            || self.show_san
            || self.check_self_signed
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

fn extract_san(tbs: &x509::TBSCertificate) -> Result<Vec<String>> {
    let mut san_list = Vec::new();

    if let Some(exts) = tbs.extensions() {
        for raw_ext in exts.extensions() {
            // Parse to SubjectAltName first to check if it's the right extension
            if let Ok(san) = raw_ext.parse::<SubjectAltName>() {
                for name in &san.names {
                    match name {
                        GeneralName::DnsName(dns) => {
                            san_list.push(format!("DNS:{}", dns));
                        }
                        GeneralName::Rfc822Name(email) => {
                            san_list.push(format!("Email:{}", email));
                        }
                        GeneralName::Uri(uri) => {
                            san_list.push(format!("URI:{}", uri));
                        }
                        GeneralName::IpAddress(ip_range) => match ip_range {
                            IpAddressOrRange::Address(addr) => {
                                san_list.push(format!("IP:{}", addr));
                            }
                            _ => {
                                san_list.push("IP:Other".to_string());
                            }
                        },
                        _ => {
                            // Skip other types
                        }
                    }
                }
                // Found SAN, no need to check other extensions
                break;
            }
        }
    }

    Ok(san_list)
}

fn check_self_signed(tbs: &x509::TBSCertificate) -> bool {
    tbs.subject() == tbs.issuer()
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

fn parse_remote_address(remote: &str) -> (&str, u16) {
    if let Some((host, port_str)) = remote.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host, port);
        }
    }
    (remote, 443)
}

fn parse_certificate_from_der(input_bytes: Vec<u8>) -> Result<Certificate> {
    let der = input_bytes.decode()?;
    let asn1_obj = der.decode()?;
    Ok(asn1_obj.decode()?)
}

fn load_certificate_chain(file: Option<&str>) -> Result<CertificateChain> {
    let input_bytes = read_input(file)?;

    // Try to parse as PEM first, fallback to DER
    if let Ok(contents) = String::from_utf8(input_bytes.clone()) {
        // Text data - try PEM first (using FromStr)
        if let Ok(chain) = contents.parse::<CertificateChain>() {
            return Ok(chain);
        }
        // Not PEM, try to parse as DER (single certificate)
        let cert = parse_certificate_from_der(input_bytes)?;
        Ok(CertificateChain::from(cert))
    } else {
        // Binary data - treat as DER (single certificate)
        let cert = parse_certificate_from_der(input_bytes)?;
        Ok(CertificateChain::from(cert))
    }
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Validate that --remote is not used with file input
    if config.remote.is_some() && config.file.is_some() {
        return Err(crate::error::Error::InvalidInput(
            "--remote cannot be used with file input".to_string(),
        ));
    }

    // Fetch certificate chain from remote server or read from file/stdin
    let chain = if let Some(ref remote) = config.remote {
        let (host, port) = parse_remote_address(remote);
        tls::fetch_certificate_chain(host, port)?
    } else {
        load_certificate_chain(config.file.as_deref())?
    };

    if chain.is_empty() {
        return Err(crate::error::Error::Certificate(
            "no certificates found".to_string(),
        ));
    }

    // Filter chain based on selection flags
    let chain = filter_chain(&chain, &config)?;

    // Empty chain after filtering (e.g., --root with no root cert)
    if chain.is_empty() {
        return Ok(());
    }

    // Show specific fields if requested
    if config.should_show_specific_fields() {
        for (i, cert) in chain.iter().enumerate() {
            if chain.len() > 1 && !config.no_header {
                println!("--- Certificate {} ---", i);
            }
            show_specific_fields(cert, &config)?;
        }
        return Ok(());
    }

    // Full output
    pkix_types::set_use_oid_values(config.show_oid);
    output_certificate_chain(&chain, &config)?;

    Ok(())
}

fn filter_chain(chain: &CertificateChain, config: &Config) -> Result<CertificateChain> {
    if config.first {
        return chain
            .first()
            .cloned()
            .map(CertificateChain::from)
            .ok_or_else(|| crate::error::Error::Certificate("no certificates found".to_string()));
    }

    if let Some(index) = config.index {
        return chain
            .get(index)
            .cloned()
            .map(CertificateChain::from)
            .ok_or_else(|| {
                crate::error::Error::Certificate(format!(
                    "certificate index {} out of range (chain has {} certificates)",
                    index,
                    chain.len()
                ))
            });
    }

    if let Some(depth) = config.depth {
        let certs: Vec<_> = chain.iter().take(depth).cloned().collect();
        if certs.is_empty() {
            return Err(crate::error::Error::Certificate(
                "no certificates found".to_string(),
            ));
        }
        return Ok(CertificateChain::new(certs));
    }

    if config.root {
        // Find self-signed certificate
        for cert in chain.iter() {
            if cert.is_self_signed() {
                return Ok(CertificateChain::from(cert.clone()));
            }
        }
        // No root found, return empty chain
        return Ok(CertificateChain::new(vec![]));
    }

    Ok(chain.clone())
}

fn show_specific_fields(cert: &Certificate, config: &Config) -> Result<()> {
    let tbs = cert.tbs_certificate();
    let mut output = String::new();

    if config.show_subject {
        format_subject(&mut output, tbs)?;
    }
    if config.show_issuer {
        format_issuer(&mut output, tbs)?;
    }
    if config.show_dates {
        format_dates(&mut output, tbs)?;
    }
    if config.show_serial {
        format_serial(&mut output, tbs)?;
    }
    if config.list_extensions {
        format_extensions(&mut output, tbs)?;
    }
    if config.show_algorithms {
        format_algorithms(&mut output, tbs)?;
    }
    if config.show_fingerprint {
        format_fingerprint(&mut output, cert, config.fingerprint_alg)?;
    }
    if config.check_expiry {
        format_expiry(&mut output, tbs)?;
    }
    if config.show_pubkey {
        format_pubkey(&mut output, tbs)?;
    }
    if config.show_purposes {
        print!("{}", output);
        show_certificate_purposes(tbs)?;
        return Ok(());
    }
    if config.show_san {
        format_san(&mut output, tbs)?;
    }
    if config.check_self_signed {
        format_self_signed(&mut output, tbs)?;
    }
    print!("{}", output);
    Ok(())
}

fn format_subject(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
    writeln!(output, "Subject: {}", tbs.subject())?;
    Ok(())
}

fn format_issuer(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
    writeln!(output, "Issuer: {}", tbs.issuer())?;
    Ok(())
}

fn format_dates(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
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
    Ok(())
}

fn format_serial(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
    writeln!(
        output,
        "Serial Number: {}",
        tbs.serial_number().format_hex()
    )?;
    Ok(())
}

fn format_extensions(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
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
    Ok(())
}

fn format_algorithms(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
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
    Ok(())
}

fn format_fingerprint(
    output: &mut String,
    cert: &Certificate,
    alg: FingerprintAlgorithm,
) -> Result<()> {
    let asn1_obj: ASN1Object = cert.encode()?;
    let der = asn1_obj.encode()?;
    let cert_der = der.encode()?;
    let fingerprint = calculate_fingerprint(&cert_der, alg);
    writeln!(output, "{} Fingerprint: {}", alg, fingerprint)?;
    Ok(())
}

fn format_expiry(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
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
    Ok(())
}

fn format_pubkey(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
    let spki = tbs.subject_public_key_info().clone();
    let pubkey = PublicKey::new(spki);
    let pem = pubkey.to_pem()?;
    write!(output, "{}", pem)?;
    Ok(())
}

fn format_san(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
    let san_list = extract_san(tbs)?;
    if san_list.is_empty() {
        writeln!(output, "Subject Alternative Names: (none)")?;
    } else {
        writeln!(output, "Subject Alternative Names:")?;
        for san in san_list {
            writeln!(output, "  {}", san)?;
        }
    }
    Ok(())
}

fn format_self_signed(output: &mut String, tbs: &x509::TBSCertificate) -> Result<()> {
    let is_self_signed = check_self_signed(tbs);
    if is_self_signed {
        writeln!(output, "Self-Signed: Yes")?;
    } else {
        writeln!(output, "Self-Signed: No")?;
    }
    Ok(())
}

fn output_certificate_chain(chain: &CertificateChain, config: &Config) -> Result<()> {
    match config.output {
        OutputFormat::Text => {
            for (i, cert) in chain.iter().enumerate() {
                if chain.len() > 1 && !config.no_header {
                    println!("--- Certificate {} ---", i);
                }
                println!("{}", cert);
            }
        }
        OutputFormat::Json => {
            if chain.len() == 1 {
                let json = serde_json::to_string_pretty(chain.end_entity().unwrap())?;
                println!("{}", json);
            } else {
                let json = serde_json::to_string_pretty(&chain)?;
                println!("{}", json);
            }
        }
        OutputFormat::Yaml => {
            if chain.len() == 1 {
                let json_value = serde_json::to_value(chain.end_entity().unwrap())?;
                let yaml = serde_yml::to_string(&json_value)?;
                print!("{}", yaml);
            } else {
                let json_value = serde_json::to_value(chain)?;
                let yaml = serde_yml::to_string(&json_value)?;
                print!("{}", yaml);
            }
        }
        OutputFormat::Brief => {
            for (i, cert) in chain.iter().enumerate() {
                let tbs = cert.tbs_certificate();
                let subject = tbs.subject();
                let validity = tbs.validity();
                let not_before = validity.not_before().format("%Y-%m-%d").to_string();
                let not_after = validity.not_after().format("%Y-%m-%d").to_string();
                if chain.len() > 1 && !config.no_header {
                    println!(
                        "[{}] {} | Valid: {} to {}",
                        i, subject, not_before, not_after
                    );
                } else {
                    println!("{} | Valid: {} to {}", subject, not_before, not_after);
                }
            }
        }
    }
    Ok(())
}
