use std::io::{self, Write};
use std::str::FromStr;

use clap::Args;
use pem::Pem;
use tsumiki::decoder::Decoder;

use crate::error::Result;
use crate::utils::read_input;

#[derive(Args)]
pub struct Config {
    /// Path to the PEM file. If not specified, reads from stdin
    file: Option<String>,
}

pub fn execute(config: Config) -> Result<()> {
    // Read input
    let input_bytes = read_input(config.file.as_deref())?;

    // Parse as PEM and decode to DER
    let contents = String::from_utf8(input_bytes)?;
    let pem = Pem::from_str(&contents)?;
    let der_bytes: Vec<u8> = pem.decode()?;

    // Output the DER binary to stdout
    io::stdout().write_all(&der_bytes)?;

    Ok(())
}
