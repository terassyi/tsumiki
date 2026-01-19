use std::fs;
use std::io::{self, Read};

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::error::Result;

/// Fingerprint algorithm
#[derive(Clone, Copy, clap::ValueEnum, Debug, Default)]
pub(crate) enum FingerprintAlgorithm {
    /// SHA1 fingerprint
    Sha1,
    /// SHA256 fingerprint (default)
    #[default]
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

/// Calculate fingerprint of data
pub(crate) fn calculate_fingerprint(data: &[u8], alg: FingerprintAlgorithm) -> String {
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

/// Read input from a file or stdin
///
/// If `file` is `Some`, reads from the specified file path.
/// If `file` is `None`, reads from stdin.
pub(crate) fn read_input(file: Option<&str>) -> Result<Vec<u8>> {
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

/// Format binary data as hexadecimal dump
///
/// Returns a string formatted in hexdump style (similar to `xxd` command):
/// - 16 bytes per line
/// - Offset in hexadecimal
/// - Hex bytes with space separator
/// - ASCII representation on the right
pub(crate) fn format_hex_dump(data: &[u8]) -> String {
    const BYTES_PER_LINE: usize = 16;
    let mut output = String::new();

    for (offset, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        // Offset
        output.push_str(&format!("{:08x}  ", offset * BYTES_PER_LINE));

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if i == 7 {
                output.push(' ');
            }
        }

        // Padding for incomplete lines
        if chunk.len() < BYTES_PER_LINE {
            for i in chunk.len()..BYTES_PER_LINE {
                output.push_str("   ");
                if i == 7 {
                    output.push(' ');
                }
            }
        }

        // ASCII representation
        output.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }

    output
}
