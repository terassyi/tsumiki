use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] asn1::error::Error),

    #[error("Invalid PKCS#1 structure: {0}")]
    InvalidStructure(String),

    #[error("Invalid version: {0} (must be 0 for two-prime or 1 for multi-prime)")]
    InvalidVersion(i64),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid integer value: {0}")]
    InvalidInteger(String),
}

pub type Result<T> = std::result::Result<T, Error>;
