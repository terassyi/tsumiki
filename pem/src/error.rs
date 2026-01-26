use base64::DecodeError;
use thiserror::Error;

/// Errors that can occur when parsing or decoding PEM data.
///
/// PEM parsing follows RFC 7468 and requires proper boundary markers,
/// valid base64 encoding, and matching labels.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Missing the opening boundary marker (e.g., `-----BEGIN CERTIFICATE-----`)
    #[error("missing a pre encapsulation boundary")]
    MissingPreEncapsulationBoundary,

    /// Missing the closing boundary marker (e.g., `-----END CERTIFICATE-----`)
    #[error("missing a post encapsulation boundary")]
    MissingPostEncapsulationBoundary,

    /// No data found between boundary markers
    #[error("missing PEM data")]
    MissingData,

    /// The label in the boundary marker is not recognized
    #[error("invalid label")]
    InvalidLabel,

    /// The BEGIN and END labels do not match (e.g., BEGIN CERTIFICATE, END PRIVATE KEY)
    #[error("label doesn't match")]
    LabelMissMatch,

    /// Malformed boundary marker
    #[error("invalid encapsulation boundary")]
    InvalidEncapsulationBoundary,

    /// Invalid character or format in a base64 data line
    #[error("invalid base64line")]
    InvalidBase64Line,

    /// Invalid final base64 line (the line containing padding characters)
    #[error("invalid base64finl")]
    InvalidBase64Finl,

    /// Failed to decode base64 data
    #[error("base64 decode: {0}")]
    Base64Decode(DecodeError),
}
