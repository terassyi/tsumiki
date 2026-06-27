//! Error types for the CRL-specific extensions.

use thiserror::Error;

/// Context for where a CRL extension error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CRLNumber,
    DeltaCRLIndicator,
    IssuingDistributionPoint,
    CRLReason,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CRLNumber => write!(f, "cRLNumber"),
            Self::DeltaCRLIndicator => write!(f, "deltaCRLIndicator"),
            Self::IssuingDistributionPoint => write!(f, "issuingDistributionPoint"),
            Self::CRLReason => write!(f, "cRLReason"),
        }
    }
}

/// CRL extension parsing errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}: empty content")]
    EmptyContent(Kind),

    #[error("{0}: expected INTEGER")]
    ExpectedInteger(Kind),

    #[error("{0}: expected SEQUENCE")]
    ExpectedSequence(Kind),

    #[error("{0}: expected BOOLEAN")]
    ExpectedBoolean(Kind),

    #[error("{0}: expected BIT STRING")]
    ExpectedBitString(Kind),

    #[error("{0}: unexpected element type")]
    UnexpectedElementType(Kind),

    #[error("{kind}: unknown context-specific tag [{slot}]")]
    UnknownContextTag { kind: Kind, slot: u8 },

    #[error("{0}: expected ENUMERATED")]
    ExpectedEnumerated(Kind),

    #[error("cRLReason: unknown reason code")]
    UnknownReasonCode,

    /// Invalid ASN.1 structure
    #[error("invalid ASN.1: {0}")]
    InvalidAsn1(#[source] tsumiki_asn1::error::Error),
}

/// Result type for CRL extension operations
pub type Result<T> = std::result::Result<T, Error>;
