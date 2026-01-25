//! Error types for PKIX types

use thiserror::Error;

/// Result type for PKIX types operations
pub type Result<T> = std::result::Result<T, Error>;

/// PKIX types error types
#[derive(Debug, Error)]
pub enum Error {
    // DirectoryString errors
    #[error("DirectoryString: invalid UTF-8 in OctetString")]
    DirectoryStringInvalidUtf8,
    #[error("DirectoryString: expected string type")]
    DirectoryStringExpectedStringType,

    // Extension errors
    #[error("Extension: expected SEQUENCE")]
    ExtensionExpectedSequence,
    #[error("Extension: expected 2 or 3 elements, got {0}")]
    ExtensionInvalidElementCount(usize),
    #[error("Extension: expected OCTET STRING for extnValue")]
    ExtensionExpectedOctetString,
    #[error("Extension: expected BOOLEAN for critical or OCTET STRING for extnValue")]
    ExtensionInvalidCriticalOrValue,
    #[error("Extension: expected OBJECT IDENTIFIER for extnID")]
    ExtensionExpectedOidForExtnId,

    // Name errors
    #[error("Name: expected SEQUENCE")]
    NameExpectedSequence,

    // RelativeDistinguishedName errors
    #[error("RelativeDistinguishedName: expected SET")]
    RdnExpectedSet,

    // AttributeTypeAndValue errors
    #[error("AttributeTypeAndValue: expected SEQUENCE")]
    AttributeTypeAndValueExpectedSequence,
    #[error("AttributeTypeAndValue: expected OBJECT IDENTIFIER for attribute type")]
    AttributeTypeAndValueExpectedOid,
    #[error("AttributeTypeAndValue: expected 2 elements")]
    AttributeTypeAndValueInvalidElementCount,

    // CertificateSerialNumber errors
    #[error("CertificateSerialNumber: expected INTEGER")]
    CertificateSerialNumberExpectedInteger,

    // SubjectPublicKeyInfo errors
    #[error("SubjectPublicKeyInfo: expected SEQUENCE")]
    SubjectPublicKeyInfoExpectedSequence,
    #[error("SubjectPublicKeyInfo: expected BIT STRING for subject public key")]
    SubjectPublicKeyInfoExpectedBitString,
    #[error("SubjectPublicKeyInfo: expected 2 elements, got {0}")]
    SubjectPublicKeyInfoInvalidElementCount(usize),

    /// Algorithm error
    #[error(transparent)]
    AlgorithmError(#[from] crate::algorithm::Error),

    /// ASN.1 encoding/decoding error
    #[error("ASN.1 error: {0}")]
    ASN1Error(#[from] asn1::error::Error),
}
