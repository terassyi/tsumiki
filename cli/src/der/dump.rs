use clap::Args;

use crate::error::Result;
use crate::utils::{format_hex_dump, read_input};

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the DER file. If not specified, reads from stdin
    file: Option<String>,
}

pub(crate) fn execute(config: Config) -> Result<()> {
    // Read DER bytes from input
    let der_bytes = read_input(config.file.as_deref())?;

    // Output hexadecimal dump
    let hex_dump = format_hex_dump(&der_bytes);
    print!("{hex_dump}");

    Ok(())
}
