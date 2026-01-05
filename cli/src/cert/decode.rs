use std::fs;
use std::io::{self, Read};

use clap::Args;

use crate::error::Result;
use crate::format::OutputFormat;

#[derive(Args)]
pub struct Config {
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
}

impl Config {
    fn should_show_specific_fields(&self) -> bool {
        self.show_subject || self.show_issuer || self.show_dates || self.show_serial
    }
}

fn read_input(file: Option<&str>) -> Result<Vec<u8>> {
    match file {
        Some(path) => {
            // Read from file
            Ok(fs::read(path)?)
        }
        None => {
            // Read from stdin
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            Ok(buffer)
        }
    }
}

pub fn execute(config: Config) -> Result<()> {
    use asn1::ASN1Object;
    use der::Der;
    use pem::Pem;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use x509::Certificate;

    // Read input
    let input_bytes = read_input(config.file.as_deref())?;

    // Try to parse as PEM first, fallback to DER
    let cert: Certificate = if let Ok(contents) = String::from_utf8(input_bytes.clone()) {
        if let Ok(pem) = Pem::from_str(&contents) {
            // PEM format
            let der: Der = pem.decode()?;
            let asn1_obj: ASN1Object = der.decode()?;
            asn1_obj.decode()?
        } else {
            // Try DER format
            let der: Der = input_bytes.decode()?;
            let asn1_obj: ASN1Object = der.decode()?;
            asn1_obj.decode()?
        }
    } else {
        // Binary data, treat as DER
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
        return Ok(());
    }

    // Full output
    match config.output {
        OutputFormat::Text => {
            println!("{}", cert);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&cert)?;
            println!("{}", json);
        }
    }

    Ok(())
}
