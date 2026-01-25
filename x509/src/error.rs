use thiserror::Error;

use crate::extensions::error;

/// Context for certificate-level errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateField {
    Certificate,
    TBSCertificate,
    Version,
    SerialNumber,
    Signature,
    Issuer,
    Validity,
    Subject,
    SubjectPublicKeyInfo,
    IssuerUniqueID,
    SubjectUniqueID,
    Extensions,
    SignatureAlgorithm,
    SignatureValue,
}

impl std::fmt::Display for CertificateField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate => write!(f, "Certificate"),
            Self::TBSCertificate => write!(f, "TBSCertificate"),
            Self::Version => write!(f, "version"),
            Self::SerialNumber => write!(f, "serialNumber"),
            Self::Signature => write!(f, "signature"),
            Self::Issuer => write!(f, "issuer"),
            Self::Validity => write!(f, "validity"),
            Self::Subject => write!(f, "subject"),
            Self::SubjectPublicKeyInfo => write!(f, "subjectPublicKeyInfo"),
            Self::IssuerUniqueID => write!(f, "issuerUniqueID"),
            Self::SubjectUniqueID => write!(f, "subjectUniqueID"),
            Self::Extensions => write!(f, "extensions"),
            Self::SignatureAlgorithm => write!(f, "signatureAlgorithm"),
            Self::SignatureValue => write!(f, "signatureValue"),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    // Structured certificate errors
    #[error("{0}: expected SEQUENCE")]
    ExpectedSequence(CertificateField),
    #[error("{0}: missing required field")]
    MissingField(CertificateField),
    #[error("{context}: expected {expected} elements, got {actual}")]
    InvalidElementCount {
        context: CertificateField,
        expected: &'static str,
        actual: usize,
    },
    #[error("Certificate: no elements in ASN1Object")]
    EmptyCertificate,
    #[error("Certificate: failed to decode DER")]
    CertificateDerDecodeFailed,
    #[error("{0}: unexpected element")]
    UnexpectedElement(CertificateField),
    #[error("{0}: expected BIT STRING")]
    ExpectedBitString(CertificateField),

    // Validity errors
    #[error("Validity: expected 2 elements in SEQUENCE")]
    ValidityInvalidElementCount,
    #[error("Validity: expected SEQUENCE")]
    ValidityExpectedSequence,
    #[error("Validity: notBefore must be UTCTime or GeneralizedTime")]
    ValidityInvalidNotBefore,
    #[error("Validity: notAfter must be UTCTime or GeneralizedTime")]
    ValidityInvalidNotAfter,

    // UniqueIdentifier errors
    #[error("UniqueIdentifier: expected context-specific tag [1] or [2], got [{0}]")]
    UniqueIdentifierInvalidTag(u8),
    #[error("UniqueIdentifier: expected BIT STRING inside context-specific tag")]
    UniqueIdentifierExpectedBitString,
    #[error("UniqueIdentifier: expected context-specific tag [1] or [2] or BIT STRING")]
    UniqueIdentifierInvalidElement,

    // Extension errors
    #[error("Extension: OID {0} is not recognized")]
    UnknownExtensionOid(String),
    #[error("Extension: failed to parse OID {oid}: {error}")]
    ExtensionParseOidFailed { oid: String, error: String },
    #[error("Extensions: expected SEQUENCE")]
    ExtensionsExpectedSequence,
    #[error("Extensions: at least one extension required")]
    ExtensionsEmpty,
    #[error("Extensions: expected context-specific tag [3]")]
    ExtensionsExpectedTag3,
    #[error("Extensions: duplicate extension OID {0}")]
    ExtensionsDuplicateOid(String),
    #[error("Extension: OID mismatch - expected {expected}, got {actual}")]
    OidMismatch { expected: String, actual: String },
    #[error("Extension: invalid OID string '{oid}': {message}")]
    InvalidOidString { oid: String, message: String },
    #[error("Extensions: expected context-specific tag [3], got [{actual}]")]
    UnexpectedContextTag { expected: u8, actual: u8 },
    #[error("Extensions: expected SEQUENCE inside context-specific tag [3]")]
    ExpectedSequenceInExtensions,
    #[error("Extensions: invalid structure - expected context-specific tag [3] or SEQUENCE")]
    InvalidExtensionsStructure,

    // Version errors
    #[error("Version: invalid value {0}")]
    InvalidVersion(String),

    // Certificate errors (used by rustls integration)
    #[error("Certificate: {0}")]
    InvalidCertificate(String),
    #[error("DER encoding: {0}")]
    DerEncodingError(String),

    // External error conversions
    #[error("invalid ASN.1: {0}")]
    InvalidASN1(#[source] asn1::error::Error),
    #[error("PKIX types error: {0}")]
    PKIXTypesError(#[from] pkix_types::Error),
    #[error("PEM error: {0}")]
    PemError(#[from] pem::error::Error),
    #[error("DER error: {0}")]
    DerError(#[from] der::error::Error),
    #[error("unexpected PEM label: expected {expected}, got {got}")]
    UnexpectedPemLabel { expected: String, got: String },
    #[error("extension error: {0}")]
    ExtensionError(#[from] error::Error),
}
