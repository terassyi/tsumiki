//! Error types for DER parsing and encoding operations.

use thiserror::Error;

/// Errors that can occur during DER parsing or encoding.
#[derive(Debug, Error)]
pub enum Error {
    /// Parser encountered an error while processing DER data.
    #[error("parser error {0:?}")]
    Parser(nom::error::ErrorKind),
    /// Parser needs more data to complete parsing.
    #[error("parser incomplete: {0:?}")]
    ParserIncomplete(nom::Needed),
    /// Error occurred while processing PEM data.
    #[error("pem: {0}")]
    Pem(tsumiki_pem::error::Error),
}
