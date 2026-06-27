//! Error types for the CRL-specific extensions.

use thiserror::Error;

/// Context for where a CRL extension error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CrlNumber,
    DeltaCrlIndicator,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrlNumber => write!(f, "cRLNumber"),
            Self::DeltaCrlIndicator => write!(f, "deltaCRLIndicator"),
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

    /// Invalid ASN.1 structure
    #[error("invalid ASN.1: {0}")]
    InvalidAsn1(#[source] tsumiki_asn1::error::Error),
}

/// Result type for CRL extension operations
pub type Result<T> = std::result::Result<T, Error>;
