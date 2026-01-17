//! Algorithm Error Types

use thiserror::Error;

/// Algorithm Error
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid algorithm identifier
    #[error("Invalid algorithm identifier: {0}")]
    InvalidAlgorithmIdentifier(String),

    /// Algorithm parameter error
    #[error(transparent)]
    ParameterError(#[from] super::parameters::Error),

    /// ASN.1 error
    #[error(transparent)]
    ASN1Error(#[from] asn1::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
