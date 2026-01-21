//! SEC1 (RFC 5915) error types

use thiserror::Error;

/// Errors that can occur when parsing or encoding SEC1 structures.
#[derive(Debug, Error)]
pub enum Error {
    /// ASN.1 parsing error
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] asn1::error::Error),

    /// PEM parsing error
    #[error("PEM error: {0}")]
    Pem(#[from] pem::error::Error),

    /// DER parsing error
    #[error("DER error: {0}")]
    Der(#[from] der::error::Error),

    /// PKIX types error
    #[error("PKIX types error: {0}")]
    PkixTypes(#[from] pkix_types::Error),

    /// Expected a SEQUENCE element but got something else
    #[error("expected SEQUENCE")]
    ExpectedSequence,

    /// Expected an INTEGER element but got something else
    #[error("expected INTEGER for {0}")]
    ExpectedInteger(&'static str),

    /// Expected an OCTET STRING element but got something else
    #[error("expected OCTET STRING")]
    ExpectedOctetString,

    /// The sequence has fewer elements than required
    #[error("insufficient elements: {0}")]
    InsufficientElements(String),

    /// The ASN.1 object contains no elements
    #[error("empty ASN.1 object")]
    EmptyAsn1Object,

    /// Invalid version number (must be 1 for ecPrivkeyVer1)
    #[error("invalid version: expected 1 (ecPrivkeyVer1), got {0}")]
    InvalidVersion(i64),

    /// Version integer value is out of range for i64
    #[error("version integer out of range")]
    VersionOutOfRange,

    /// Unknown or unsupported elliptic curve OID
    #[error("unknown curve OID: {0}")]
    UnknownCurve(String),
}

pub type Result<T> = std::result::Result<T, Error>;
