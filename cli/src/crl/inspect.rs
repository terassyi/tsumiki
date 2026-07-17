use std::str::FromStr;

use clap::Args;
use tsumiki::decoder::Decoder;
use tsumiki_asn1::ASN1Object;
use tsumiki_der::Der;
use tsumiki_x509::crl::CertificateList;

use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::read_input;

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the CRL file (PEM or DER format). If not specified, reads from stdin
    file: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    output: OutputFormat,
}

pub(crate) fn execute(config: Config) -> Result<()> {
    let input_bytes = read_input(config.file.as_deref())?;

    // Parse as PEM first (via `FromStr`), falling back to DER
    // (`Vec<u8>` -> `Der` -> `ASN1Object` -> `CertificateList` via `Decoder`).
    let crl = match String::from_utf8(input_bytes.clone())
        .ok()
        .and_then(|contents| CertificateList::from_str(&contents).ok())
    {
        Some(crl) => crl,
        None => {
            let der: Der = input_bytes.decode()?;
            let asn1_obj: ASN1Object = der.decode()?;
            asn1_obj.decode()?
        }
    };

    match config.output {
        OutputFormat::Text => println!("{}", crl),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&crl)?),
        OutputFormat::Yaml => {
            let value = serde_json::to_value(&crl)?;
            println!("{}", serde_yml::to_string(&value)?);
        }
        OutputFormat::Brief => {
            let tbs = crl.tbs_cert_list();
            println!(
                "Issuer: {} | Revoked: {}",
                tbs.issuer(),
                tbs.revoked_certificates().len()
            );
        }
    }

    Ok(())
}
