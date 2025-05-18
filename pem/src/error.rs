use base64::DecodeError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("missing a pre encapsulation boundary")]
    MissingPreEncapsulationBoundary,
    #[error("missing a post encapsulation boundary")]
    MissingPostEncapsulationBoundary,
    #[error("missing PEM data")]
    MissingData,
    #[error("invalid label")]
    InvalidLabel,
    #[error("label doesn't match")]
    LabelMissMatch,
    #[error("invalid encapsulation boundary")]
    InvalidEncapsulationBoundary,
    #[error("invalid base64line")]
    InvalidBase64Line,
    #[error("invalid base64finl")]
    InvalidBase64Finl,
    #[error("base64 decode: {0}")]
    Base64Decode(DecodeError),
}
