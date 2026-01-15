//! Error types for PKCS#9

use thiserror::Error;

/// Result type for PKCS#9 operations
pub type Result<T> = std::result::Result<T, Error>;

/// PKCS#9 error types
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid PKCS#9 attribute structure
    #[error("Invalid PKCS#9 attribute: {0}")]
    InvalidAttribute(String),

    /// Invalid contentType attribute
    #[error("Invalid contentType: {0}")]
    InvalidContentType(String),

    /// Invalid messageDigest attribute
    #[error("Invalid messageDigest: {0}")]
    InvalidMessageDigest(String),

    /// Invalid signingTime attribute
    #[error("Invalid signingTime: {0}")]
    InvalidSigningTime(String),

    /// Invalid challengePassword attribute
    #[error("Invalid challengePassword: {0}")]
    InvalidChallengePassword(String),

    /// Invalid unstructuredName attribute
    #[error("Invalid unstructuredName: {0}")]
    InvalidUnstructuredName(String),

    /// Invalid unstructuredAddress attribute
    #[error("Invalid unstructuredAddress: {0}")]
    InvalidUnstructuredAddress(String),

    /// Invalid smimeCapabilities attribute
    #[error("Invalid smimeCapabilities: {0}")]
    InvalidSmimeCapabilities(String),

    /// Invalid countersignature attribute
    #[error("Invalid countersignature: {0}")]
    InvalidCountersignature(String),

    /// Invalid extensionRequest attribute
    #[error("Invalid extensionRequest: {0}")]
    InvalidExtensionRequest(String),

    /// Invalid friendlyName attribute
    #[error("Invalid friendlyName: {0}")]
    InvalidFriendlyName(String),

    /// Invalid localKeyId attribute
    #[error("Invalid localKeyId: {0}")]
    InvalidLocalKeyId(String),

    /// Empty attribute name or value
    #[error("{0} cannot be empty")]
    EmptyValue(String),

    /// Value exceeds maximum length
    #[error("Value too long: {actual} characters (max: {max})")]
    ValueTooLong { max: usize, actual: usize },

    /// OID mismatch between expected and actual
    #[error("OID mismatch: expected {expected}, got {actual}")]
    OidMismatch { expected: String, actual: String },

    /// Failed to parse ASN.1 structure
    #[error("ASN.1 error: {0}")]
    ASN1Error(#[from] asn1::error::Error),

    /// Failed to encode/decode DER
    #[error("DER encoding/decoding error: {0}")]
    DerError(#[from] der::error::Error),

    /// PKIX types error
    #[error("PKIX types error: {0}")]
    PkixTypesError(#[from] pkix_types::Error),

    /// Unsupported attribute type
    #[error("Unsupported attribute type: {0}")]
    UnsupportedAttribute(String),
}
