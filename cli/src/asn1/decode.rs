use std::str::FromStr;

use asn1::ASN1Object;
use clap::Args;
use der::Der;
use pem::Pem;
use tsumiki::decoder::Decoder;

use crate::error::Result;
use crate::utils::read_input;

use super::format::format_asn1;

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the DER or PEM file. If not specified, reads from stdin
    file: Option<String>,

    /// Try to parse implicit-tagged OCTET STRING content as ASN.1
    #[arg(long)]
    parse_implicit: bool,
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read input
    let input_bytes = read_input(config.file.as_deref())?;

    // Try to parse as PEM first, fallback to DER
    let asn1_obj: ASN1Object = if let Ok(contents) = String::from_utf8(input_bytes.clone()) {
        // Text data - try PEM first
        if let Ok(pem) = Pem::from_str(&contents) {
            // PEM format
            let der: Der = pem.decode()?;
            der.decode()?
        } else {
            // Not PEM, try to parse as DER
            let der: Der = input_bytes.decode()?;
            der.decode()?
        }
    } else {
        // Binary data - treat as DER
        let der: Der = input_bytes.decode()?;
        der.decode()?
    };

    // Output ASN.1 structure in readable format
    print!("{}", format_asn1(&asn1_obj, config.parse_implicit));

    Ok(())
}
