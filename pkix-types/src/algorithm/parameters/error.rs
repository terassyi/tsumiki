//! Algorithm Parameters Error Types

use thiserror::Error;

/// Algorithm Parameters Error
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid parameter format
    #[error("Invalid parameter format: {0}")]
    InvalidFormat(String),

    /// Invalid EC parameter
    #[error("Invalid EC parameter: {0}")]
    InvalidEcParameter(String),

    /// Invalid DSA parameter
    #[error("Invalid DSA parameter: {0}")]
    InvalidDsaParameter(String),

    /// Element type mismatch
    #[error("Expected {expected} but got {actual}")]
    TypeMismatch { expected: String, actual: String },

    /// Invalid element count
    #[error("Expected {expected} elements but got {actual}")]
    InvalidElementCount { expected: usize, actual: usize },

    /// Cannot convert NULL to typed parameter
    #[error("Cannot convert NULL to typed parameter")]
    NullConversion,
}

pub type Result<T> = std::result::Result<T, Error>;
