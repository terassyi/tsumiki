//! Algorithm Error Types

use thiserror::Error;

/// Algorithm Error
#[derive(Debug, Error)]
pub enum Error {
    /// NULL parameter cannot be converted to a typed parameter
    #[error("cannot convert NULL to typed parameter")]
    NullParameterNotSupported,

    /// AlgorithmIdentifier algorithm field must be an OID
    #[error("AlgorithmIdentifier algorithm must be OBJECT IDENTIFIER")]
    ExpectedOidForAlgorithm,

    /// AlgorithmIdentifier is empty (must have at least algorithm OID)
    #[error("AlgorithmIdentifier must have at least 1 element")]
    EmptyAlgorithmIdentifier,

    /// AlgorithmIdentifier has too many elements
    #[error("AlgorithmIdentifier must have at most 2 elements")]
    TooManyElements,

    /// AlgorithmIdentifier must be a SEQUENCE
    #[error("AlgorithmIdentifier must be a SEQUENCE")]
    ExpectedSequence,

    /// Algorithm parameter error
    #[error(transparent)]
    ParameterError(#[from] super::parameters::Error),

    /// ASN.1 error
    #[error(transparent)]
    ASN1Error(#[from] tsumiki_asn1::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
