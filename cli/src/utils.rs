use std::fs;
use std::io::{self, Read};

use crate::error::Result;

/// Read input from a file or stdin
///
/// If `file` is `Some`, reads from the specified file path.
/// If `file` is `None`, reads from stdin.
pub fn read_input(file: Option<&str>) -> Result<Vec<u8>> {
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
