mod tls;
mod verifier;

use chrono::Utc;
use clap::Args;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;
use tsumiki_asn1::ASN1Object;
use tsumiki_pem::ToPem;
use tsumiki_pkcs::pkcs8::PublicKey;
use tsumiki_pkix_types::OidName;
use tsumiki_x509::extensions::{Extension, GeneralName, IpAddressOrRange, SubjectAltName};
use tsumiki_x509::{Certificate, CertificateChain};

use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::{FingerprintAlgorithm, calculate_fingerprint, read_input};

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
        [
            self.show_subject,
            self.show_issuer,
            self.show_dates,
            self.show_serial,
            self.list_extensions,
            self.show_algorithms,
            self.show_fingerprint,
            self.check_expiry,
            self.show_pubkey,
            self.show_purposes,
            self.show_san,
            self.check_self_signed,
        ]
        .iter()
        .any(|&flag| flag)
    }
}

fn get_purpose_name(oid_str: &str) -> &'static str {
    match oid_str {
        tsumiki_x509::extensions::ExtendedKeyUsage::SERVER_AUTH => "Server Authentication",
        tsumiki_x509::extensions::ExtendedKeyUsage::CLIENT_AUTH => "Client Authentication",
        tsumiki_x509::extensions::ExtendedKeyUsage::CODE_SIGNING => "Code Signing",
        tsumiki_x509::extensions::ExtendedKeyUsage::EMAIL_PROTECTION => "Email Protection",
        tsumiki_x509::extensions::ExtendedKeyUsage::TIME_STAMPING => "Time Stamping",
        tsumiki_x509::extensions::ExtendedKeyUsage::OCSP_SIGNING => "OCSP Signing",
        _ => "Unknown",
    }
}

fn extract_san(tbs: &tsumiki_x509::TBSCertificate) -> Result<Vec<String>> {
    let exts = match tbs.extensions() {
        Some(e) => e,
        None => return Ok(Vec::new()),
    };

    let san = match exts
        .extensions()
        .iter()
        .find_map(|ext| ext.parse::<SubjectAltName>().ok())
    {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };

    let san_list = san
        .names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DnsName(dns) => Some(format!("DNS:{}", dns)),
            GeneralName::Rfc822Name(email) => Some(format!("Email:{}", email)),
            GeneralName::Uri(uri) => Some(format!("URI:{}", uri)),
            GeneralName::IpAddress(IpAddressOrRange::Address(addr)) => Some(format!("IP:{}", addr)),
            GeneralName::IpAddress(_) => Some("IP:Other".to_string()),
            _ => None,
        })
        .collect();

    Ok(san_list)
}

fn check_self_signed(tbs: &tsumiki_x509::TBSCertificate) -> bool {
    tbs.subject() == tbs.issuer()
}

fn show_certificate_purposes(tbs: &tsumiki_x509::TBSCertificate) -> Result<()> {
    let extensions = match tbs.extensions() {
        Some(e) => e,
        None => {
            println!("No extensions in certificate");
            return Ok(());
        }
    };

    let eku = extensions
        .extensions()
        .iter()
        .find(|ext| *ext.oid() == tsumiki_x509::extensions::ExtendedKeyUsage::OID)
        .and_then(|ext| {
            ext.parse::<tsumiki_x509::extensions::ExtendedKeyUsage>()
                .ok()
        });

    match eku {
        Some(eku) => {
            println!("Certificate Purposes:");
            eku.purposes
                .iter()
                .map(|purpose_oid| {
                    let oid_str = purpose_oid.to_string();
                    get_purpose_name(&oid_str)
                })
                .for_each(|purpose_name| println!("  - {}", purpose_name));
        }
        None => println!("No Extended Key Usage extension found"),
    }

    Ok(())
}

fn parse_remote_address(remote: &str) -> (&str, u16) {
    remote
        .rsplit_once(':')
        .and_then(|(host, port_str)| port_str.parse::<u16>().ok().map(|port| (host, port)))
        .unwrap_or((remote, 443))
}

fn parse_certificate_from_der(input_bytes: Vec<u8>) -> Result<Certificate> {
    let der = input_bytes.decode()?;
    let asn1_obj = der.decode()?;
    Ok(asn1_obj.decode()?)
}

fn load_certificate_chain(file: Option<&str>) -> Result<CertificateChain> {
    let input_bytes = read_input(file)?;

    // Try to parse as PEM first, fallback to DER
    String::from_utf8(input_bytes.clone())
        .ok()
        .and_then(|contents| contents.parse::<CertificateChain>().ok())
        .map(Ok)
        .unwrap_or_else(|| parse_certificate_from_der(input_bytes).map(CertificateChain::from))
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Validate that --remote is not used with file input
    if config.remote.is_some() && config.file.is_some() {
        return Err(crate::error::Error::RemoteWithFileInput);
    }

    // Fetch certificate chain from remote server or read from file/stdin
    let chain = match &config.remote {
        Some(remote) => {
            let (host, port) = parse_remote_address(remote);
            tls::fetch_certificate_chain(host, port)?
        }
        None => load_certificate_chain(config.file.as_deref())?,
    };

    if chain.is_empty() {
        return Err(crate::error::Error::NoCertificatesFound);
    }

    // Filter chain based on selection flags
    let chain = filter_chain(&chain, &config)?;

    // Empty chain after filtering (e.g., --root with no root cert)
    if chain.is_empty() {
        return Ok(());
    }

    // Show specific fields if requested
    if config.should_show_specific_fields() {
        chain.iter().enumerate().try_for_each(|(i, cert)| {
            if chain.len() > 1 && !config.no_header {
                println!("--- Certificate {} ---", i);
            }
            show_specific_fields(cert, &config)
        })?;
        return Ok(());
    }

    // Full output
    tsumiki_pkix_types::set_use_oid_values(config.show_oid);
    output_certificate_chain(&chain, &config)?;

    Ok(())
}

fn filter_chain(chain: &CertificateChain, config: &Config) -> Result<CertificateChain> {
    if config.first {
        return chain
            .first()
            .cloned()
            .map(CertificateChain::from)
            .ok_or(crate::error::Error::NoCertificatesFound);
    }

    if let Some(index) = config.index {
        return chain.get(index).cloned().map(CertificateChain::from).ok_or(
            crate::error::Error::CertificateIndexOutOfRange {
                index,
                total: chain.len(),
            },
        );
    }

    if let Some(depth) = config.depth {
        let certs: Vec<_> = chain.iter().take(depth).cloned().collect();
        if certs.is_empty() {
            return Err(crate::error::Error::NoCertificatesFound);
        }
        return Ok(CertificateChain::new(certs));
    }

    if config.root {
        // Find self-signed certificate
        return chain
            .iter()
            .find(|cert| cert.is_self_signed())
            .cloned()
            .map(CertificateChain::from)
            .map(Ok)
            .unwrap_or_else(|| Ok(CertificateChain::new(vec![])));
    }

    Ok(chain.clone())
}

fn show_specific_fields(cert: &Certificate, config: &Config) -> Result<()> {
    let tbs = cert.tbs_certificate();

    let parts = [
        config.show_subject.then(|| format_subject(tbs)),
        config.show_issuer.then(|| format_issuer(tbs)),
        config.show_dates.then(|| format_dates(tbs)),
        config.show_serial.then(|| format_serial(tbs)),
        config.list_extensions.then(|| format_extensions(tbs)),
        config.show_algorithms.then(|| format_algorithms(tbs)),
        config
            .show_fingerprint
            .then(|| format_fingerprint(cert, config.fingerprint_alg)),
        config.check_expiry.then(|| format_expiry(tbs)),
        config.show_pubkey.then(|| format_pubkey(tbs)),
        config.show_san.then(|| format_san(tbs)),
        config.check_self_signed.then(|| format_self_signed(tbs)),
    ];

    let output = parts
        .into_iter()
        .flatten()
        .collect::<Result<Vec<_>>>()?
        .join("");

    print!("{}", output);

    if config.show_purposes {
        show_certificate_purposes(tbs)?;
    }

    Ok(())
}

fn format_subject(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    Ok(format!("Subject: {}\n", tbs.subject()))
}

fn format_issuer(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    Ok(format!("Issuer: {}\n", tbs.issuer()))
}

fn format_dates(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    let validity = tbs.validity();
    Ok(format!(
        "Not Before: {}\nNot After: {}\n",
        validity.not_before().format("%b %d %H:%M:%S %Y GMT"),
        validity.not_after().format("%b %d %H:%M:%S %Y GMT")
    ))
}

fn format_serial(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    Ok(format!(
        "Serial Number: {}\n",
        tbs.serial_number().format_hex()
    ))
}

fn format_extensions(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    match tbs.extensions() {
        Some(exts) => {
            let lines = exts
                .extensions()
                .iter()
                .map(|ext| {
                    let oid_str = ext.oid().to_string();
                    let name = ext.oid_name().unwrap_or(&oid_str);
                    let critical = if ext.critical() { " (critical)" } else { "" };
                    format!("  {} [{}]{}", name, ext.oid(), critical)
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(format!("Extensions:\n{}\n", lines))
        }
        None => Ok("No extensions\n".to_string()),
    }
}

fn format_algorithms(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    let sig_alg = tbs.signature();
    let sig_oid_str = sig_alg.algorithm.to_string();
    let sig_name = sig_alg.oid_name().unwrap_or(&sig_oid_str);

    let pubkey_alg = tbs.subject_public_key_info().algorithm();
    let pubkey_oid_str = pubkey_alg.algorithm.to_string();
    let pubkey_name = pubkey_alg.oid_name().unwrap_or(&pubkey_oid_str);

    Ok(format!(
        "Signature Algorithm: {} ({})\nPublic Key Algorithm: {} ({})\n",
        sig_name, sig_alg.algorithm, pubkey_name, pubkey_alg.algorithm
    ))
}

fn format_fingerprint(cert: &Certificate, alg: FingerprintAlgorithm) -> Result<String> {
    let asn1_obj: ASN1Object = cert.encode()?;
    let der = asn1_obj.encode()?;
    let cert_der = der.encode()?;
    let fingerprint = calculate_fingerprint(&cert_der, alg);
    Ok(format!("{} Fingerprint: {}\n", alg, fingerprint))
}

fn format_expiry(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    let validity = tbs.validity();
    let not_after = validity.not_after();
    let now = Utc::now().naive_utc();

    if now > *not_after {
        let output = format!(
            "Certificate is EXPIRED (expired on {})\n",
            not_after.format("%Y-%m-%d %H:%M:%S UTC")
        );
        print!("{}", output);
        std::process::exit(1);
    } else {
        Ok(format!(
            "Certificate is VALID (expires on {})\n",
            not_after.format("%Y-%m-%d %H:%M:%S UTC")
        ))
    }
}

fn format_pubkey(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    let spki = tbs.subject_public_key_info().clone();
    let pubkey = PublicKey::new(spki);
    let pem = pubkey.to_pem()?;
    Ok(pem.to_string())
}

fn format_san(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    let san_list = extract_san(tbs)?;
    if san_list.is_empty() {
        Ok("Subject Alternative Names: (none)\n".to_string())
    } else {
        let sans = san_list
            .iter()
            .map(|san| format!("  {}", san))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(format!("Subject Alternative Names:\n{}\n", sans))
    }
}

fn format_self_signed(tbs: &tsumiki_x509::TBSCertificate) -> Result<String> {
    let is_self_signed = check_self_signed(tbs);
    Ok(format!(
        "Self-Signed: {}\n",
        if is_self_signed { "Yes" } else { "No" }
    ))
}

fn output_certificate_chain(chain: &CertificateChain, config: &Config) -> Result<()> {
    match config.output {
        OutputFormat::Text => {
            chain.iter().enumerate().for_each(|(i, cert)| {
                if chain.len() > 1 && !config.no_header {
                    println!("--- Certificate {} ---", i);
                }
                println!("{}", cert);
            });
        }
        OutputFormat::Json => {
            let json = if chain.len() == 1 {
                serde_json::to_string_pretty(
                    chain
                        .end_entity()
                        .ok_or(crate::error::Error::NoCertificatesFound)?,
                )?
            } else {
                serde_json::to_string_pretty(&chain)?
            };
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            let json_value = if chain.len() == 1 {
                serde_json::to_value(
                    chain
                        .end_entity()
                        .ok_or(crate::error::Error::NoCertificatesFound)?,
                )?
            } else {
                serde_json::to_value(chain)?
            };
            let yaml = serde_yml::to_string(&json_value)?;
            print!("{}", yaml);
        }
        OutputFormat::Brief => {
            chain.iter().enumerate().for_each(|(i, cert)| {
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
            });
        }
    }
    Ok(())
}
