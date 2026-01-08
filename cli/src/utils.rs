use std::fs;
use std::io::{self, Read};

use crate::error::Result;

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
