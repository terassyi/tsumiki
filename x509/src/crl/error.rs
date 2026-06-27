use thiserror::Error;

/// Context identifying which CRL field caused an error.
///
/// Used in error messages to provide specific context about where
/// parsing or validation failed within a `CertificateList` structure
/// (RFC 5280 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CRLField {
    CertificateList,
    TBSCertList,
    Version,
    Signature,
    Issuer,
    ThisUpdate,
    NextUpdate,
    RevokedCertificates,
    RevokedCertificate,
    UserCertificate,
    RevocationDate,
    CRLEntryExtensions,
    CRLExtensions,
    SignatureAlgorithm,
    SignatureValue,
}

impl std::fmt::Display for CRLField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateList => write!(f, "CertificateList"),
            Self::TBSCertList => write!(f, "TBSCertList"),
            Self::Version => write!(f, "version"),
            Self::Signature => write!(f, "signature"),
            Self::Issuer => write!(f, "issuer"),
            Self::ThisUpdate => write!(f, "thisUpdate"),
            Self::NextUpdate => write!(f, "nextUpdate"),
            Self::RevokedCertificates => write!(f, "revokedCertificates"),
            Self::RevokedCertificate => write!(f, "revokedCertificate"),
            Self::UserCertificate => write!(f, "userCertificate"),
            Self::RevocationDate => write!(f, "revocationDate"),
            Self::CRLEntryExtensions => write!(f, "crlEntryExtensions"),
            Self::CRLExtensions => write!(f, "crlExtensions"),
            Self::SignatureAlgorithm => write!(f, "signatureAlgorithm"),
            Self::SignatureValue => write!(f, "signatureValue"),
        }
    }
}

/// Errors that can occur during CRL parsing and validation.
///
/// This type covers structural errors (invalid ASN.1, missing fields) and
/// validation errors (invalid formats, out-of-range values). Conversions
/// from underlying library errors (PKIX types, X.509) are added alongside the
/// parsing code that produces them.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}: expected SEQUENCE")]
    ExpectedSequence(CRLField),
    #[error("{0}: missing required field")]
    MissingField(CRLField),
    #[error("{context}: expected {expected} elements, got {actual}")]
    InvalidElementCount {
        context: CRLField,
        expected: &'static str,
        actual: usize,
    },
    #[error("CertificateList: no elements in ASN1Object")]
    EmptyCertificateList,
    #[error("{0}: unexpected element")]
    UnexpectedElement(CRLField),
    #[error("{0}: expected BIT STRING")]
    ExpectedBitString(CRLField),

    // Version errors (CRL version MUST be v2 if present, RFC 5280 §5.1.2.1)
    #[error("version: invalid value {0} (CRL version must be v2)")]
    InvalidVersion(String),

    // Time errors
    #[error("{0}: must be UTCTime or GeneralizedTime")]
    InvalidTime(CRLField),

    // External error conversions
    #[error("PKIX types error: {0}")]
    PKIXTypesError(#[from] tsumiki_pkix_types::Error),
    #[error("X.509 error: {0}")]
    X509Error(#[from] crate::error::Error),
}
