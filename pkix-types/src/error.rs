//! Error types for PKIX types

use thiserror::Error;

/// Result type for PKIX types operations
pub type Result<T> = std::result::Result<T, Error>;

/// PKIX types error types
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid DirectoryString
    #[error("Invalid DirectoryString: {0}")]
    InvalidDirectoryString(String),

    /// Invalid AlgorithmIdentifier
    #[error("Invalid AlgorithmIdentifier: {0}")]
    InvalidAlgorithmIdentifier(String),

    /// Invalid Extension
    #[error("Invalid Extension: {0}")]
    InvalidExtension(String),

    /// Invalid Name
    #[error("Invalid Name: {0}")]
    InvalidName(String),

    /// Invalid RelativeDistinguishedName
    #[error("Invalid RelativeDistinguishedName: {0}")]
    InvalidRelativeDistinguishedName(String),

    /// Invalid AttributeTypeAndValue
    #[error("Invalid AttributeTypeAndValue: {0}")]
    InvalidAttributeTypeAndValue(String),

    /// Invalid CertificateSerialNumber
    #[error("Invalid CertificateSerialNumber: {0}")]
    InvalidCertificateSerialNumber(String),

    /// Invalid KeyIdentifier
    #[error("Invalid KeyIdentifier: {0}")]
    InvalidKeyIdentifier(String),

    /// Invalid SubjectPublicKeyInfo
    #[error("Invalid SubjectPublicKeyInfo: {0}")]
    InvalidSubjectPublicKeyInfo(String),

    /// Invalid encoding
    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Algorithm error
    #[error(transparent)]
    AlgorithmError(#[from] crate::algorithm::Error),

    /// ASN.1 encoding/decoding error
    #[error("ASN.1 error: {0}")]
    ASN1Error(#[from] asn1::error::Error),
}
