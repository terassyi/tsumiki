use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] tsumiki_asn1::error::Error),

    #[error("expected SEQUENCE")]
    ExpectedSequence,

    #[error("expected {expected} elements, got {actual}")]
    InvalidElementCount {
        expected: &'static str,
        actual: usize,
    },

    #[error("expected INTEGER for {field}")]
    ExpectedInteger { field: &'static str },

    #[error("empty ASN1Object")]
    EmptyAsn1Object,

    #[error("unexpected key format: expected {expected}")]
    UnexpectedKeyFormat { expected: &'static str },

    #[error("Invalid version: {0} (must be 0 for two-prime or 1 for multi-prime)")]
    InvalidVersion(i64),

    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("version out of range for i64")]
    VersionOutOfRange,

    #[error("Invalid PEM: {0}")]
    InvalidPem(#[from] tsumiki_pem::error::Error),

    #[error("Invalid DER: {0}")]
    InvalidDer(#[from] tsumiki_der::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
